mod support;

use quant_hft_core::adverse::{AdverseConfig, AdverseError};
use quant_hft_core::control::{ConfigDigest, ControlDecision};
use quant_hft_core::engine::{
    EngineConfig, EngineError, EngineMarketState, ExecutionEngine, OrderApplication,
    TransmissionStatus,
};
use quant_hft_core::event_codec::{decode_control_decision, normalize_control_decision};
use quant_hft_core::events::CaptureOrdinal;
use quant_hft_core::journal::{RECORD_LEN, decode_record, encode_record};
use quant_hft_core::kill::{KillCode, KillSnapshot};
use quant_hft_core::orders::{ExecutionPriceViolation, OrderError};
use quant_hft_core::ownership::OwnershipBindOutcome;
use quant_hft_core::reference_data::{
    InstrumentDefinitionError, InstrumentRuleViolation, ReferenceDataDigest,
};
use quant_hft_core::risk::{
    CurrencyId, InstrumentRiskDefinition, InstrumentValuation, RiskError, RiskLimits, RiskSessionId,
};
use quant_hft_core::strategy::QuotePolicyConfig;
use quant_hft_core::types::{
    InstrumentId, MonotonicTimestampNs, OrderId, PriceTicks, Quantity, Sequence, Side, TimestampNs,
    VenueId,
};
use quant_hft_core::venue::{
    Accepted, BookDelta, Canceled, ClientOrderId, Fill, InboundMessage, InboundPayload,
    LifecycleCorrectionDigest, LifecycleCorrectionId, LifecycleCorrectionKind,
    LifecycleCorrectionObserved, LiquidityFlag, MarketByOrderId, MarketDataMessage,
    MarketDataPayload, OrderCommand, OrderEvent, OwnedMboBinding, OwnedMboBindingMethod,
    SessionEvent, SnapshotMessage, SnapshotOrder, SnapshotPayload, TradeId, VenueOrderId,
};
use quant_hft_core::{ClockSample, ReconciledOrderFaultSummary};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Mutex;

type Engine = ExecutionEngine<64, 16, 8, 16, 16>;

const INSTRUMENT: InstrumentId = InstrumentId(7);
const OFFSET: u64 = 1_000_000_000;
const BID_BOOK_ORDER: MarketByOrderId = MarketByOrderId(11);
const ASK_BOOK_ORDER: MarketByOrderId = MarketByOrderId(12);

struct CountingAllocator;

static TEST_LOCK: Mutex<()> = Mutex::new(());

thread_local! {
    static TRACK_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = TRACK_ALLOCATIONS.try_with(|tracking| {
            if tracking.get() {
                let _ = ALLOCATIONS.try_with(|allocations| {
                    allocations.set(allocations.get().saturating_add(1));
                });
            }
        });
        // SAFETY: Delegates the exact layout to the process system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: `pointer` and `layout` came from the delegated system allocator.
        unsafe { System.dealloc(pointer, layout) }
    }
}

fn config() -> EngineConfig {
    EngineConfig {
        venue: VenueId(1),
        instrument: INSTRUMENT,
        first_market_sequence: Sequence(1),
        first_order_sequence: Sequence(1),
        first_client_order_id: ClientOrderId(1_000),
        first_risk_order_id: OrderId(5_000),
        instrument_definition: support::instrument_definition(VenueId(1), INSTRUMENT),
        max_clock_uncertainty_ns: 1_000,
        max_clock_offset_step_ns: 100,
        max_clock_holdover_ns: 100_000,
        clock_drift_parts_per_billion: 10,
        risk_session: RiskSessionId(1),
        risk_definition: InstrumentRiskDefinition {
            instrument: INSTRUMENT,
            base_currency: CurrencyId(840),
            valuation: InstrumentValuation::Fixed {
                base_units_per_price_tick: 1,
                contract_multiplier: 1,
            },
            position_limit: Quantity(1_000),
        },
        risk: RiskLimits {
            max_order_quantity: Quantity(100),
            max_order_notional: 1_000_000,
            max_gross_notional: 10_000_000,
            max_net_notional: 10_000_000,
            max_daily_loss: 1_000_000,
            max_market_age_ns: 10_000,
        },
        adverse: AdverseConfig {
            markout_horizon_ns: 100,
            rolling_window_ns: 10_000,
            breach_markout_ticks: 1,
            halt_after_consecutive: 2,
            halt_aggregate_loss: 10_000,
            kill_after_consecutive: 3,
            kill_aggregate_loss: 20_000,
        },
        quote: QuotePolicyConfig {
            base_quantity: Quantity(10),
            base_half_spread_ticks: 1,
            max_volatility_spread_ticks: 10,
            max_abs_alpha_ticks: 1,
            inventory_skew_numerator: 0,
            inventory_skew_denominator: 1,
            max_abs_inventory: Quantity(1_000),
        },
    }
}

fn clocked_engine(config: EngineConfig) -> Engine {
    let mut engine = Engine::new(config).unwrap();
    engine
        .observe_clock(quant_hft_core::ClockSample {
            utc: TimestampNs(OFFSET + 1_000),
            monotonic: MonotonicTimestampNs(1_000),
            uncertainty_ns: 10,
        })
        .unwrap();
    let mut output = [None; 2];
    for (monotonic, payload) in [
        (
            1_010,
            SnapshotPayload::Begin {
                snapshot_id: 1,
                last_incremental_sequence: Sequence(0),
            },
        ),
        (
            1_020,
            SnapshotPayload::End {
                snapshot_id: 1,
                last_incremental_sequence: Sequence(0),
            },
        ),
    ] {
        engine
            .on_snapshot(
                snapshot(monotonic, payload),
                MonotonicTimestampNs(monotonic),
                &mut output,
            )
            .unwrap();
    }
    engine
}

fn engine_with(config: EngineConfig) -> Engine {
    engine_with_lease(config, TimestampNs(u64::MAX))
}

fn engine_with_lease(config: EngineConfig, lease_deadline: TimestampNs) -> Engine {
    let mut engine = clocked_engine(config);
    let mut output = [None; 2];
    engine
        .on_order_entry(
            inbound_session(1, 1_030, SessionEvent::LogonAccepted),
            MonotonicTimestampNs(1_030),
            &mut output,
        )
        .unwrap();
    engine
        .apply_control_decision(
            support::authenticated_arm(
                1,
                ConfigDigest([0xA5; 32]),
                Sequence(1),
                TimestampNs(OFFSET + 1_030),
                lease_deadline,
            ),
            &mut output,
        )
        .unwrap();
    assert!(output.iter().all(Option::is_none));
    engine
        .on_market_data(
            market(
                1,
                1_050,
                MarketDataPayload::TradingStatus { status_code: 1 },
            ),
            MonotonicTimestampNs(1_050),
            &mut output,
        )
        .unwrap();
    assert!(engine.control_armed());
    assert!(engine.venue_trading_open());
    engine
}

fn arm_decision(accepted_at: TimestampNs) -> ControlDecision {
    support::authenticated_arm(
        1,
        ConfigDigest([0xA5; 32]),
        Sequence(1),
        accepted_at,
        TimestampNs(u64::MAX),
    )
}

#[test]
fn engine_construction_rejects_missing_reference_provenance_and_lot_drift() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut invalid = config();
    invalid.instrument_definition.reference_data_digest = ReferenceDataDigest([0; 32]);
    assert_eq!(
        Engine::new(invalid).unwrap_err(),
        EngineError::InstrumentDefinition(InstrumentDefinitionError::InvalidReferenceDataDigest)
    );

    let mut lot_drift = config();
    lot_drift.instrument_definition.minimum_quantity = Quantity(3);
    lot_drift.instrument_definition.maximum_quantity = Quantity(999);
    lot_drift.instrument_definition.quantity_increment = Quantity(3);
    assert_eq!(
        Engine::new(lot_drift).unwrap_err(),
        EngineError::InstrumentRule(InstrumentRuleViolation::QuantityIncrementMismatch {
            increment: Quantity(3),
            received: Quantity(10),
        })
    );

    let mut wrong_product_route = config();
    wrong_product_route.instrument_definition.instrument = InstrumentId(INSTRUMENT.0 + 1);
    assert_eq!(
        Engine::new(wrong_product_route).unwrap_err(),
        EngineError::InvalidConfiguration
    );
}

#[test]
fn engine_construction_rejects_risk_economics_not_bound_to_reference_data() {
    let _guard = TEST_LOCK.lock().unwrap();

    let mut currency_drift = config();
    currency_drift.risk_definition.base_currency = CurrencyId(978);
    assert_eq!(
        Engine::new(currency_drift).unwrap_err(),
        EngineError::RiskCurrencyBindingMismatch
    );

    let mut tick_value_drift = config();
    tick_value_drift.risk_definition.valuation = InstrumentValuation::Fixed {
        base_units_per_price_tick: 2,
        contract_multiplier: 1,
    };
    assert_eq!(
        Engine::new(tick_value_drift).unwrap_err(),
        EngineError::RiskValuationBindingMismatch
    );

    let mut multiplier_drift = config();
    multiplier_drift.risk_definition.valuation = InstrumentValuation::Fixed {
        base_units_per_price_tick: 1,
        contract_multiplier: 2,
    };
    assert_eq!(
        Engine::new(multiplier_drift).unwrap_err(),
        EngineError::RiskValuationBindingMismatch
    );

    // Equal products are insufficient: the authenticated contract identity must
    // match each valuation term, not merely their multiplication result.
    let mut compensating_drift = config();
    compensating_drift
        .instrument_definition
        .fixed_value
        .settlement_units_per_price_tick = 2;
    compensating_drift
        .instrument_definition
        .fixed_value
        .contract_multiplier = 5;
    compensating_drift.risk_definition.valuation = InstrumentValuation::Fixed {
        base_units_per_price_tick: 1,
        contract_multiplier: 10,
    };
    assert_eq!(
        Engine::new(compensating_drift).unwrap_err(),
        EngineError::RiskValuationBindingMismatch
    );
}

#[test]
fn freshly_received_exchange_stale_mark_fails_risk_freshness() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut stale_config = config();
    stale_config.risk.max_market_age_ns = 50;
    let mut engine = engine_with(stale_config);
    let mut output = [None; 2];

    engine
        .on_market_data(
            market(
                2,
                1_100,
                MarketDataPayload::Book(BookDelta::Add {
                    order_id: BID_BOOK_ORDER,
                    side: Side::Buy,
                    price: PriceTicks(99),
                    quantity: Quantity(100),
                }),
            ),
            MonotonicTimestampNs(1_100),
            &mut output,
        )
        .expect("one-sided book has no valuation mark");
    let risk_before = engine.risk().instrument(INSTRUMENT);
    let adverse_before = engine.adverse().instrument(INSTRUMENT);

    let freshly_received_stale = MarketDataMessage {
        instrument: INSTRUMENT,
        sequence: Sequence(3),
        exchange_timestamp: TimestampNs(OFFSET + 1_100),
        hardware_receive_timestamp: TimestampNs(OFFSET + 1_200),
        payload: MarketDataPayload::Book(BookDelta::Add {
            order_id: ASK_BOOK_ORDER,
            side: Side::Sell,
            price: PriceTicks(101),
            quantity: Quantity(100),
        }),
    };
    assert_eq!(
        engine.on_market_data(
            freshly_received_stale,
            MonotonicTimestampNs(1_200),
            &mut output,
        ),
        Err(EngineError::Risk(RiskError::StaleMarket {
            age_ns: 100,
            max_age_ns: 50,
        }))
    );
    assert_eq!(engine.risk().instrument(INSTRUMENT), risk_before);
    assert_eq!(engine.adverse().instrument(INSTRUMENT), adverse_before);
    assert!(output.iter().all(Option::is_none));
    assert_eq!(
        engine.kill_snapshot(),
        Some(KillSnapshot {
            code: KillCode::MarketDataGap,
            triggered_at: TimestampNs(OFFSET + 1_200),
        })
    );
}

#[test]
fn live_exchange_timestamp_regression_is_rejected_like_journal_replay() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut engine = engine_with(config());
    let mut output = [None; 2];
    engine
        .on_market_data(
            market(
                2,
                1_100,
                MarketDataPayload::Trade {
                    trade_id: TradeId(90),
                    side: Side::Buy,
                    price: PriceTicks(100),
                    quantity: Quantity(1),
                },
            ),
            MonotonicTimestampNs(1_100),
            &mut output,
        )
        .expect("first market timestamp");

    let regressing = MarketDataMessage {
        instrument: INSTRUMENT,
        sequence: Sequence(3),
        exchange_timestamp: TimestampNs(OFFSET + 1_089),
        hardware_receive_timestamp: TimestampNs(OFFSET + 1_200),
        payload: MarketDataPayload::Trade {
            trade_id: TradeId(91),
            side: Side::Buy,
            price: PriceTicks(100),
            quantity: Quantity(1),
        },
    };
    assert_eq!(
        engine.on_market_data(regressing, MonotonicTimestampNs(1_200), &mut output,),
        Err(EngineError::EventTimestampRegression {
            prior: TimestampNs(OFFSET + 1_090),
            received: TimestampNs(OFFSET + 1_089),
        })
    );
    assert_eq!(engine.expected_market_sequence(), Sequence(3));
    assert!(output.iter().all(Option::is_none));
    assert_eq!(engine.kill_snapshot().unwrap().code, KillCode::ClockUnsafe);
}

fn market(sequence: u64, monotonic: u64, payload: MarketDataPayload) -> MarketDataMessage {
    MarketDataMessage {
        instrument: INSTRUMENT,
        sequence: Sequence(sequence),
        exchange_timestamp: TimestampNs(OFFSET + monotonic - 10),
        hardware_receive_timestamp: TimestampNs(OFFSET + monotonic),
        payload,
    }
}

fn snapshot(monotonic: u64, payload: SnapshotPayload) -> SnapshotMessage {
    SnapshotMessage {
        exchange_timestamp: TimestampNs(OFFSET + monotonic - 10),
        hardware_receive_timestamp: TimestampNs(OFFSET + monotonic),
        payload,
    }
}

fn inbound(sequence: u64, monotonic: u64, event: OrderEvent) -> InboundMessage {
    InboundMessage {
        sequence: Sequence(sequence),
        exchange_timestamp: TimestampNs(OFFSET + monotonic - 10),
        hardware_receive_timestamp: TimestampNs(OFFSET + monotonic),
        payload: InboundPayload::Order(event),
    }
}

fn inbound_session(sequence: u64, monotonic: u64, event: SessionEvent) -> InboundMessage {
    InboundMessage {
        sequence: Sequence(sequence),
        exchange_timestamp: TimestampNs(OFFSET + monotonic - 10),
        hardware_receive_timestamp: TimestampNs(OFFSET + monotonic),
        payload: InboundPayload::Session(event),
    }
}

fn seed_two_sided(engine: &mut Engine) -> [OrderCommand; 2] {
    let mut output = [None; 2];
    engine
        .on_market_data(
            market(
                2,
                1_100,
                MarketDataPayload::Book(BookDelta::Add {
                    order_id: BID_BOOK_ORDER,
                    side: Side::Buy,
                    price: PriceTicks(99),
                    quantity: Quantity(100),
                }),
            ),
            MonotonicTimestampNs(1_100),
            &mut output,
        )
        .unwrap();
    assert!(output.iter().all(Option::is_none));
    assert_eq!(engine.book().expected_sequence(), Sequence(2));

    engine
        .on_market_data(
            market(
                3,
                1_200,
                MarketDataPayload::Trade {
                    trade_id: TradeId(90),
                    side: Side::Buy,
                    price: PriceTicks(100),
                    quantity: Quantity(1),
                },
            ),
            MonotonicTimestampNs(1_200),
            &mut output,
        )
        .unwrap();
    assert!(output.iter().all(Option::is_none));
    assert_eq!(engine.book().expected_sequence(), Sequence(2));

    let outcome = engine
        .on_market_data(
            market(
                4,
                1_300,
                MarketDataPayload::Book(BookDelta::Add {
                    order_id: ASK_BOOK_ORDER,
                    side: Side::Sell,
                    price: PriceTicks(101),
                    quantity: Quantity(100),
                }),
            ),
            MonotonicTimestampNs(1_300),
            &mut output,
        )
        .unwrap();
    assert_eq!(outcome.output.commands, 2);
    assert_eq!(engine.book().expected_sequence(), Sequence(3));
    assert_eq!(engine.expected_market_sequence(), Sequence(5));
    [output[0].unwrap(), output[1].unwrap()]
}

fn split_new(commands: [OrderCommand; 2]) -> (OrderCommand, OrderCommand) {
    let mut bid = None;
    let mut ask = None;
    for command in commands {
        match command {
            OrderCommand::New(order) if order.side == Side::Buy => bid = Some(command),
            OrderCommand::New(order) if order.side == Side::Sell => ask = Some(command),
            _ => panic!("expected two post-only new commands"),
        }
    }
    (bid.unwrap(), ask.unwrap())
}

fn new_fields(command: OrderCommand) -> quant_hft_core::venue::NewOrder {
    match command {
        OrderCommand::New(order) => order,
        _ => panic!("expected new order"),
    }
}

fn cancel_fields(command: OrderCommand) -> quant_hft_core::venue::CancelOrder {
    match command {
        OrderCommand::Cancel(order) => order,
        _ => panic!("expected cancel order"),
    }
}

fn accept(
    engine: &mut Engine,
    sequence: u64,
    monotonic: u64,
    new: quant_hft_core::venue::NewOrder,
    venue_order_id: VenueOrderId,
) {
    let mut output = [None; 2];
    engine
        .on_order_entry(
            inbound(
                sequence,
                monotonic,
                OrderEvent::Accepted(Accepted {
                    client_order_id: new.client_order_id,
                    venue_order_id,
                    price: new.price,
                    quantity: new.quantity,
                }),
            ),
            MonotonicTimestampNs(monotonic),
            &mut output,
        )
        .unwrap();
}

fn live_two_sided(
    engine: &mut Engine,
) -> (
    quant_hft_core::venue::NewOrder,
    quant_hft_core::venue::NewOrder,
) {
    let (bid_command, ask_command) = split_new(seed_two_sided(engine));
    let bid = new_fields(bid_command);
    let ask = new_fields(ask_command);
    engine
        .on_transmission(
            bid_command,
            TransmissionStatus::Sent,
            MonotonicTimestampNs(1_400),
        )
        .unwrap();
    engine
        .on_transmission(
            ask_command,
            TransmissionStatus::Sent,
            MonotonicTimestampNs(1_401),
        )
        .unwrap();
    accept(engine, 2, 1_500, bid, VenueOrderId(7_000));
    accept(engine, 3, 1_501, ask, VenueOrderId(7_001));
    (bid, ask)
}

#[test]
fn normalized_market_lot_violation_fails_before_sequence_or_book_mutation() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut configured = config();
    configured.instrument_definition.minimum_quantity = Quantity(10);
    configured.instrument_definition.maximum_quantity = Quantity(1_000);
    configured.instrument_definition.quantity_increment = Quantity(10);
    let mut engine = engine_with(configured);
    let mut output = [Some(OrderCommand::CancelAll(quant_hft_core::venue::CancelAll {
        scope: quant_hft_core::venue::CancelScope::Session,
        created_at: TimestampNs(1),
    })); 2];

    assert_eq!(
        engine.on_market_data(
            market(
                2,
                1_100,
                MarketDataPayload::Book(BookDelta::Add {
                    order_id: BID_BOOK_ORDER,
                    side: Side::Buy,
                    price: PriceTicks(100),
                    quantity: Quantity(11),
                }),
            ),
            MonotonicTimestampNs(1_100),
            &mut output,
        ),
        Err(EngineError::InstrumentRule(
            InstrumentRuleViolation::QuantityIncrementMismatch {
                increment: Quantity(10),
                received: Quantity(11),
            },
        ))
    );
    assert_eq!(engine.expected_market_sequence(), Sequence(2));
    assert_eq!(engine.book().order_count(), 0);
    assert_eq!(engine.market_state(), EngineMarketState::SnapshotRequired);
    assert_eq!(
        engine.kill_snapshot().unwrap().code,
        KillCode::MarketDataGap
    );
    assert!(output.iter().all(Option::is_none));
}

#[test]
fn reference_data_expiry_timer_cancels_live_quotes_without_permitting_new_orders() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut configured = config();
    configured.instrument_definition.valid_until = TimestampNs(OFFSET + 1_550);
    let mut engine = engine_with(configured);
    let _ = live_two_sided(&mut engine);
    let mut output = [None; 2];

    let batch = engine
        .check_control_liveness(MonotonicTimestampNs(1_600), &mut output)
        .unwrap();
    assert_eq!(batch.commands, 2);
    assert!(!engine.trading_eligible());
    assert!(engine.kill_snapshot().is_none());
    assert!(
        output
            .iter()
            .flatten()
            .all(|command| matches!(command, OrderCommand::Cancel(_)))
    );
}

#[test]
fn application_clock_never_regresses_when_feedback_overtakes_a_queued_source() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut engine = engine_with(config());
    let commands = seed_two_sided(&mut engine);
    assert_eq!(
        engine.last_applied_monotonic(),
        Some(MonotonicTimestampNs(1_300))
    );

    for (index, command) in commands.into_iter().enumerate() {
        engine
            .on_transmission(
                command,
                TransmissionStatus::Sent,
                MonotonicTimestampNs(1_500 + u64::try_from(index).unwrap()),
            )
            .unwrap();
    }
    assert_eq!(
        engine.last_applied_monotonic(),
        Some(MonotonicTimestampNs(1_501))
    );
    assert_eq!(engine.last_applied_utc(), Some(TimestampNs(OFFSET + 1_501)));

    // This market event was captured before the priority feedback above, but is
    // applied afterward. Its raw timestamps remain unchanged while engine time stays
    // at the application-order floor.
    let mut output = [None; 2];
    engine
        .on_market_data(
            market(
                5,
                1_400,
                MarketDataPayload::Trade {
                    trade_id: TradeId(91),
                    side: Side::Buy,
                    price: PriceTicks(100),
                    quantity: Quantity(1),
                },
            ),
            MonotonicTimestampNs(1_400),
            &mut output,
        )
        .unwrap();
    assert_eq!(
        engine.last_applied_monotonic(),
        Some(MonotonicTimestampNs(1_501))
    );
    assert_eq!(engine.last_applied_utc(), Some(TimestampNs(OFFSET + 1_501)));

    // A later clock observation is itself an applied input. A queued market event
    // captured before it is applied at the clock input's monotonic floor.
    engine
        .observe_clock(ClockSample {
            utc: TimestampNs(OFFSET + 1_700),
            monotonic: MonotonicTimestampNs(1_700),
            uncertainty_ns: 10,
        })
        .unwrap();
    engine
        .on_market_data(
            market(
                6,
                1_600,
                MarketDataPayload::Trade {
                    trade_id: TradeId(92),
                    side: Side::Sell,
                    price: PriceTicks(100),
                    quantity: Quantity(1),
                },
            ),
            MonotonicTimestampNs(1_600),
            &mut output,
        )
        .unwrap();
    assert_eq!(
        engine.last_applied_monotonic(),
        Some(MonotonicTimestampNs(1_700))
    );
    assert_eq!(engine.last_applied_utc(), Some(TimestampNs(OFFSET + 1_700)));

    // Control carries authenticated UTC but no monotonic timestamp. It advances the
    // UTC causal floor. A subsequent clock-derived input below that floor fails
    // closed instead of fabricating a UTC value outside the disciplined mapping.
    engine
        .apply_control_decision(
            support::authenticated_disarm(
                1,
                ConfigDigest([0xA5; 32]),
                Sequence(2),
                TimestampNs(OFFSET + 2_000),
            ),
            &mut output,
        )
        .unwrap();
    assert!(matches!(
        engine.on_market_data(
            market(
                7,
                1_800,
                MarketDataPayload::Trade {
                    trade_id: TradeId(93),
                    side: Side::Buy,
                    price: PriceTicks(100),
                    quantity: Quantity(1),
                },
            ),
            MonotonicTimestampNs(1_800),
            &mut output,
        ),
        Err(EngineError::EventTimestampRegression {
            prior: TimestampNs(1_000_002_000),
            received: TimestampNs(1_000_001_800),
        })
    ));
    assert_eq!(
        engine.last_applied_monotonic(),
        Some(MonotonicTimestampNs(1_800))
    );
    assert_eq!(engine.last_applied_utc(), Some(TimestampNs(OFFSET + 2_000)));
    assert_eq!(engine.kill_snapshot().unwrap().code, KillCode::ClockUnsafe);
}

#[test]
fn rejected_control_and_clock_times_use_the_last_safe_causal_kill_time() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut output = [None; 2];

    let mut control = engine_with(config());
    let control_floor = control.last_applied_utc().expect("control causal floor");
    let regressing_at = TimestampNs(control_floor.0 - 1);
    assert_eq!(
        control.apply_control_decision(
            support::authenticated_disarm(1, ConfigDigest([0xA5; 32]), Sequence(2), regressing_at,),
            &mut output,
        ),
        Err(EngineError::EventTimestampRegression {
            prior: control_floor,
            received: regressing_at,
        })
    );
    assert_eq!(control.last_applied_utc(), Some(control_floor));
    assert_eq!(
        control.kill_snapshot(),
        Some(KillSnapshot {
            code: KillCode::ClockUnsafe,
            triggered_at: control_floor,
        })
    );

    let mut clock = clocked_engine(config());
    let clock_floor = clock.last_applied_utc().expect("clock causal floor");
    assert_eq!(
        clock.observe_clock(ClockSample {
            utc: TimestampNs::ZERO,
            monotonic: MonotonicTimestampNs(2_000),
            uncertainty_ns: 10,
        }),
        Err(EngineError::Clock(
            quant_hft_core::ClockError::InvalidUtcTimestamp
        ))
    );
    assert_eq!(clock.last_applied_utc(), Some(clock_floor));
    assert_eq!(
        clock.kill_snapshot(),
        Some(KillSnapshot {
            code: KillCode::ClockUnsafe,
            triggered_at: clock_floor,
        })
    );
}

#[test]
fn explicit_owned_mbo_binding_drives_exact_queue_without_id_inference() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut engine = engine_with(config());
    let (bid, _ask) = live_two_sided(&mut engine);
    let public_id = MarketByOrderId(70_000);
    assert_eq!(engine.owned_mbo_registry().by_market_order(public_id), None);
    assert!(engine.exact_queue(Side::Buy).is_none());

    let binding = OwnedMboBinding {
        venue: VenueId(1),
        client_order_id: bid.client_order_id,
        venue_order_id: VenueOrderId(7_000),
        market_by_order_id: public_id,
        order_entry_sequence: Sequence(2),
        method: OwnedMboBindingMethod::CertifiedDeterministicRule { rule_id: 91 },
    };
    ALLOCATIONS.set(0);
    TRACK_ALLOCATIONS.set(true);
    let bind_result = engine.on_owned_mbo_binding(binding, MonotonicTimestampNs(1_550));
    TRACK_ALLOCATIONS.set(false);
    assert_eq!(bind_result, Ok(OwnershipBindOutcome::Inserted));
    assert_eq!(ALLOCATIONS.get(), 0);
    let queue = engine.exact_queue(Side::Buy).unwrap();
    assert!(!queue.own_visible());
    assert_eq!(queue.queue_ahead(), Quantity(100));
    assert_eq!(
        engine.owned_mbo_registry().by_client(bid.client_order_id),
        Some(binding)
    );

    let mut output = [None; 2];
    engine
        .on_market_data(
            market(
                5,
                1_600,
                MarketDataPayload::Book(BookDelta::Add {
                    order_id: public_id,
                    side: bid.side,
                    price: bid.price,
                    quantity: bid.quantity,
                }),
            ),
            MonotonicTimestampNs(1_600),
            &mut output,
        )
        .unwrap();
    for (index, command) in output.iter().flatten().copied().enumerate() {
        engine
            .on_transmission(
                command,
                TransmissionStatus::Sent,
                MonotonicTimestampNs(1_601 + u64::try_from(index).unwrap()),
            )
            .unwrap();
    }
    let queue = engine.exact_queue(Side::Buy).unwrap();
    assert!(queue.own_visible());
    assert_eq!(queue.queue_ahead(), Quantity(100));

    engine
        .on_market_data(
            market(
                6,
                1_700,
                MarketDataPayload::Book(BookDelta::Cancel {
                    order_id: BID_BOOK_ORDER,
                }),
            ),
            MonotonicTimestampNs(1_700),
            &mut output,
        )
        .unwrap();
    for (index, command) in output.iter().flatten().copied().enumerate() {
        engine
            .on_transmission(
                command,
                TransmissionStatus::Sent,
                MonotonicTimestampNs(1_701 + u64::try_from(index).unwrap()),
            )
            .unwrap();
    }
    assert_eq!(
        engine.exact_queue(Side::Buy).unwrap().queue_ahead(),
        Quantity::ZERO
    );

    engine
        .on_market_data(
            market(
                7,
                1_800,
                MarketDataPayload::Book(BookDelta::Execute {
                    order_id: public_id,
                    price: bid.price,
                    quantity: bid.quantity,
                }),
            ),
            MonotonicTimestampNs(1_800),
            &mut output,
        )
        .unwrap();
    for (index, command) in output.iter().flatten().copied().enumerate() {
        engine
            .on_transmission(
                command,
                TransmissionStatus::Sent,
                MonotonicTimestampNs(1_801 + u64::try_from(index).unwrap()),
            )
            .unwrap();
    }
    assert_eq!(
        engine.exact_queue(Side::Buy).unwrap().status(),
        quant_hft_core::queue::QueueStatus::Filled
    );

    engine
        .on_order_entry(
            inbound(
                4,
                1_900,
                OrderEvent::Fill(Fill {
                    client_order_id: bid.client_order_id,
                    venue_order_id: VenueOrderId(7_000),
                    trade_id: TradeId(900),
                    price: bid.price,
                    quantity: bid.quantity,
                    leaves_quantity: Quantity::ZERO,
                    liquidity: LiquidityFlag::Added,
                }),
            ),
            MonotonicTimestampNs(1_900),
            &mut output,
        )
        .unwrap();
    assert!(engine.exact_queue(Side::Buy).is_some());
    engine
        .on_order_entry(
            inbound(
                5,
                1_950,
                OrderEvent::Canceled(Canceled {
                    client_order_id: bid.client_order_id,
                    venue_order_id: VenueOrderId(7_000),
                    canceled_quantity: Quantity::ZERO,
                    leaves_quantity: Quantity::ZERO,
                }),
            ),
            MonotonicTimestampNs(1_950),
            &mut output,
        )
        .unwrap();
    assert!(engine.exact_queue(Side::Buy).is_none());
    assert_eq!(
        engine.owned_mbo_registry().by_client(bid.client_order_id),
        None
    );
}

#[test]
fn incrementals_are_rejected_until_a_complete_snapshot_exists() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut engine = Engine::new(config()).unwrap();
    engine
        .observe_clock(ClockSample {
            utc: TimestampNs(OFFSET + 1_000),
            monotonic: MonotonicTimestampNs(1_000),
            uncertainty_ns: 10,
        })
        .unwrap();
    let mut output = [None; 2];

    assert_eq!(engine.market_state(), EngineMarketState::SnapshotRequired);
    assert_eq!(
        engine.on_market_data(
            market(
                1,
                1_010,
                MarketDataPayload::TradingStatus { status_code: 1 },
            ),
            MonotonicTimestampNs(1_010),
            &mut output,
        ),
        Err(EngineError::SnapshotRequired)
    );
    assert_eq!(
        engine.kill_snapshot().unwrap().code,
        KillCode::MarketDataGap
    );
    assert!(!engine.trading_eligible());
}

#[test]
fn snapshot_rebuild_sets_exact_incremental_cursor_and_boundary_fault_discards_image() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut engine = Engine::new(config()).unwrap();
    engine
        .observe_clock(ClockSample {
            utc: TimestampNs(OFFSET + 1_000),
            monotonic: MonotonicTimestampNs(1_000),
            uncertainty_ns: 10,
        })
        .unwrap();
    let mut output = [None; 2];
    let begin = SnapshotPayload::Begin {
        snapshot_id: 77,
        last_incremental_sequence: Sequence(10),
    };
    engine
        .on_snapshot(
            snapshot(1_010, begin),
            MonotonicTimestampNs(1_010),
            &mut output,
        )
        .unwrap();
    for (monotonic, order) in [
        (
            1_020,
            SnapshotOrder {
                instrument: INSTRUMENT,
                order_id: BID_BOOK_ORDER,
                side: Side::Buy,
                price: PriceTicks(99),
                quantity: Quantity(100),
            },
        ),
        (
            1_030,
            SnapshotOrder {
                instrument: INSTRUMENT,
                order_id: ASK_BOOK_ORDER,
                side: Side::Sell,
                price: PriceTicks(101),
                quantity: Quantity(100),
            },
        ),
    ] {
        engine
            .on_snapshot(
                snapshot(monotonic, SnapshotPayload::Order(order)),
                MonotonicTimestampNs(monotonic),
                &mut output,
            )
            .unwrap();
    }
    let completed = engine
        .on_snapshot(
            snapshot(
                1_040,
                SnapshotPayload::End {
                    snapshot_id: 77,
                    last_incremental_sequence: Sequence(10),
                },
            ),
            MonotonicTimestampNs(1_040),
            &mut output,
        )
        .unwrap();
    assert!(completed.completed);
    assert_eq!(engine.market_state(), EngineMarketState::Live);
    assert_eq!(engine.expected_market_sequence(), Sequence(11));
    assert_eq!(engine.book().order_count(), 2);
    assert!(!engine.venue_trading_open());

    engine
        .on_order_entry(
            inbound_session(1, 1_050, SessionEvent::LogonAccepted),
            MonotonicTimestampNs(1_050),
            &mut output,
        )
        .unwrap();
    engine
        .apply_control_decision(arm_decision(TimestampNs(OFFSET + 1_050)), &mut output)
        .unwrap();
    let opened = engine
        .on_market_data(
            market(
                11,
                1_100,
                MarketDataPayload::TradingStatus { status_code: 1 },
            ),
            MonotonicTimestampNs(1_100),
            &mut output,
        )
        .unwrap();
    assert_eq!(opened.output.commands, 2);
    assert!(engine.trading_eligible());

    let mut malformed = Engine::new(config()).unwrap();
    malformed
        .observe_clock(ClockSample {
            utc: TimestampNs(OFFSET + 2_000),
            monotonic: MonotonicTimestampNs(2_000),
            uncertainty_ns: 10,
        })
        .unwrap();
    malformed
        .on_snapshot(
            snapshot(2_010, begin),
            MonotonicTimestampNs(2_010),
            &mut output,
        )
        .unwrap();
    malformed
        .on_snapshot(
            snapshot(
                2_020,
                SnapshotPayload::Order(SnapshotOrder {
                    instrument: INSTRUMENT,
                    order_id: BID_BOOK_ORDER,
                    side: Side::Buy,
                    price: PriceTicks(99),
                    quantity: Quantity(1),
                }),
            ),
            MonotonicTimestampNs(2_020),
            &mut output,
        )
        .unwrap();
    assert_eq!(
        malformed.on_snapshot(
            snapshot(
                2_030,
                SnapshotPayload::End {
                    snapshot_id: 78,
                    last_incremental_sequence: Sequence(10),
                },
            ),
            MonotonicTimestampNs(2_030),
            &mut output,
        ),
        Err(EngineError::SnapshotBoundaryMismatch)
    );
    assert_eq!(
        malformed.market_state(),
        EngineMarketState::SnapshotRequired
    );
    assert_eq!(malformed.book().order_count(), 0);
    assert_eq!(
        malformed.kill_snapshot().unwrap().code,
        KillCode::MarketDataGap
    );
}

#[test]
fn engine_requires_snapshot_control_market_and_order_session_gates() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut engine = clocked_engine(config());
    let mut output = [None; 2];

    assert!(!engine.control_armed());
    assert!(!engine.venue_trading_open());
    assert!(!engine.order_session_live());
    assert!(!engine.trading_eligible());

    engine
        .on_market_data(
            market(
                1,
                1_050,
                MarketDataPayload::TradingStatus { status_code: 1 },
            ),
            MonotonicTimestampNs(1_050),
            &mut output,
        )
        .unwrap();
    assert!(!engine.control_armed());
    assert!(engine.venue_trading_open());
    assert!(!engine.order_session_live());
    assert!(!engine.trading_eligible());

    for (sequence, monotonic, payload) in [
        (
            2,
            1_100,
            MarketDataPayload::Book(BookDelta::Add {
                order_id: BID_BOOK_ORDER,
                side: Side::Buy,
                price: PriceTicks(99),
                quantity: Quantity(100),
            }),
        ),
        (
            3,
            1_200,
            MarketDataPayload::Trade {
                trade_id: TradeId(89),
                side: Side::Buy,
                price: PriceTicks(100),
                quantity: Quantity(1),
            },
        ),
        (
            4,
            1_300,
            MarketDataPayload::Book(BookDelta::Add {
                order_id: ASK_BOOK_ORDER,
                side: Side::Sell,
                price: PriceTicks(101),
                quantity: Quantity(100),
            }),
        ),
    ] {
        let outcome = engine
            .on_market_data(
                market(sequence, monotonic, payload),
                MonotonicTimestampNs(monotonic),
                &mut output,
            )
            .unwrap();
        assert_eq!(outcome.output.commands, 0);
        assert!(output.iter().all(Option::is_none));
    }

    assert!(!engine.control_armed());
    assert!(engine.venue_trading_open());

    engine
        .on_order_entry(
            inbound_session(1, 1_360, SessionEvent::LogonAccepted),
            MonotonicTimestampNs(1_360),
            &mut output,
        )
        .unwrap();
    assert!(engine.order_session_live());
    assert!(!engine.trading_eligible());

    engine
        .apply_control_decision(arm_decision(TimestampNs(OFFSET + 1_400)), &mut output)
        .unwrap();
    assert!(engine.control_armed());
    assert!(engine.venue_trading_open());
    assert!(engine.trading_eligible());
    assert!(output.iter().all(Option::is_none));

    let activated = engine
        .on_market_data(
            market(
                5,
                1_500,
                MarketDataPayload::Trade {
                    trade_id: TradeId(90),
                    side: Side::Sell,
                    price: PriceTicks(100),
                    quantity: Quantity(1),
                },
            ),
            MonotonicTimestampNs(1_500),
            &mut output,
        )
        .unwrap();
    assert_eq!(activated.output.commands, 2);
    assert!(
        output
            .iter()
            .flatten()
            .all(|command| matches!(command, OrderCommand::New(_)))
    );

    let mut control_only = clocked_engine(config());
    control_only
        .apply_control_decision(arm_decision(TimestampNs(OFFSET + 1_050)), &mut output)
        .unwrap();
    assert!(control_only.control_armed());
    assert!(!control_only.venue_trading_open());
    assert!(!control_only.trading_eligible());
}

#[test]
fn disarm_and_control_kill_clear_intent_and_emit_only_cancels() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut output = [None; 2];

    let mut disarmed = engine_with(config());
    let _ = live_two_sided(&mut disarmed);
    let batch = disarmed
        .apply_control_decision(
            support::authenticated_disarm(
                1,
                ConfigDigest([0xA5; 32]),
                Sequence(2),
                TimestampNs(OFFSET + 1_600),
            ),
            &mut output,
        )
        .unwrap();
    assert_eq!(batch.commands, 2);
    assert!(!disarmed.control_armed());
    assert!(disarmed.venue_trading_open());
    assert!(!disarmed.trading_eligible());
    assert!(disarmed.kill_snapshot().is_none());
    assert!(
        output
            .iter()
            .flatten()
            .all(|command| matches!(command, OrderCommand::Cancel(_)))
    );

    let mut killed = engine_with(config());
    let _ = live_two_sided(&mut killed);
    let batch = killed
        .apply_control_decision(
            support::authenticated_kill(
                1,
                ConfigDigest([0xA5; 32]),
                Sequence(1),
                TimestampNs(OFFSET + 1_600),
            ),
            &mut output,
        )
        .unwrap();
    assert_eq!(batch.commands, 2);
    assert!(!killed.control_armed());
    assert!(killed.venue_trading_open());
    assert!(!killed.trading_eligible());
    assert_eq!(killed.kill_snapshot().unwrap().code, KillCode::Manual);
    assert!(
        output
            .iter()
            .flatten()
            .all(|command| matches!(command, OrderCommand::Cancel(_)))
    );
}

#[test]
fn control_lease_exact_boundary_survives_then_expiry_kills_and_cancels() {
    let _guard = TEST_LOCK.lock().unwrap();
    let deadline = TimestampNs(OFFSET + 1_600);
    let mut engine = engine_with_lease(config(), deadline);
    let _ = live_two_sided(&mut engine);
    let mut output = [None; 2];

    let exact = engine
        .check_control_liveness(MonotonicTimestampNs(1_600), &mut output)
        .unwrap();
    assert_eq!(exact.commands, 0);
    assert!(engine.control_armed());
    assert_eq!(engine.control_lease_deadline(), Some(deadline));
    assert!(engine.kill_snapshot().is_none());

    let expired = engine
        .check_control_liveness(MonotonicTimestampNs(1_601), &mut output)
        .unwrap();
    assert_eq!(expired.commands, 2);
    assert!(!engine.control_armed());
    assert_eq!(engine.control_lease_deadline(), None);
    assert_eq!(
        engine.kill_snapshot(),
        Some(KillSnapshot {
            code: KillCode::VenueDisconnect,
            triggered_at: TimestampNs(OFFSET + 1_601),
        })
    );
    assert!(
        output
            .iter()
            .flatten()
            .all(|command| matches!(command, OrderCommand::Cancel(_)))
    );

    let repeated = engine
        .check_control_liveness(MonotonicTimestampNs(1_602), &mut output)
        .unwrap();
    assert_eq!(repeated.commands, 0);
    assert_eq!(
        engine.kill_snapshot().unwrap().triggered_at,
        TimestampNs(OFFSET + 1_601)
    );
}

#[test]
fn market_event_cannot_quote_after_a_missed_control_lease_timer() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut engine = engine_with_lease(config(), TimestampNs(OFFSET + 1_550));
    let _ = live_two_sided(&mut engine);
    let mut output = [None; 2];

    let outcome = engine
        .on_market_data(
            market(
                5,
                1_600,
                MarketDataPayload::Trade {
                    trade_id: TradeId(91),
                    side: Side::Buy,
                    price: PriceTicks(100),
                    quantity: Quantity(1),
                },
            ),
            MonotonicTimestampNs(1_600),
            &mut output,
        )
        .unwrap();

    assert_eq!(outcome.output.commands, 2);
    assert_eq!(engine.expected_market_sequence(), Sequence(6));
    assert!(!engine.control_armed());
    assert_eq!(
        engine.kill_snapshot().unwrap().code,
        KillCode::VenueDisconnect
    );
    assert!(
        output
            .iter()
            .flatten()
            .all(|command| matches!(command, OrderCommand::Cancel(_)))
    );
}

#[test]
fn heartbeat_extends_control_lease_but_rollback_fails_closed() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut output = [None; 2];
    let mut engine = engine_with_lease(config(), TimestampNs(OFFSET + 1_600));

    engine
        .apply_control_decision(
            support::authenticated_heartbeat(
                1,
                ConfigDigest([0xA5; 32]),
                Sequence(2),
                TimestampNs(OFFSET + 1_550),
                TimestampNs(OFFSET + 1_700),
            ),
            &mut output,
        )
        .unwrap();
    assert_eq!(
        engine.control_lease_deadline(),
        Some(TimestampNs(OFFSET + 1_700))
    );

    let error = engine
        .apply_control_decision(
            support::authenticated_heartbeat(
                1,
                ConfigDigest([0xA5; 32]),
                Sequence(2),
                TimestampNs(OFFSET + 1_560),
                TimestampNs(OFFSET + 1_699),
            ),
            &mut output,
        )
        .expect_err("lease rollback must fail closed");
    assert_eq!(
        error,
        EngineError::ControlLeaseRollback {
            current: TimestampNs(OFFSET + 1_700),
            received: TimestampNs(OFFSET + 1_699),
        }
    );
    assert!(!engine.control_armed());
    assert_eq!(engine.control_lease_deadline(), None);
    assert_eq!(
        engine.kill_snapshot().unwrap().code,
        KillCode::InternalInvariant
    );
}

#[test]
fn venue_close_and_session_fault_clear_only_the_venue_gate() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut output = [None; 2];

    let mut closed = engine_with(config());
    let _ = live_two_sided(&mut closed);
    let outcome = closed
        .on_market_data(
            market(
                5,
                1_600,
                MarketDataPayload::TradingStatus { status_code: 0 },
            ),
            MonotonicTimestampNs(1_600),
            &mut output,
        )
        .unwrap();
    assert_eq!(outcome.output.commands, 2);
    assert!(closed.control_armed());
    assert!(!closed.venue_trading_open());
    assert!(!closed.trading_eligible());
    assert!(closed.kill_snapshot().is_none());
    assert!(
        output
            .iter()
            .flatten()
            .all(|command| matches!(command, OrderCommand::Cancel(_)))
    );

    let mut faulted = engine_with(config());
    assert_eq!(
        faulted.on_order_entry(
            inbound_session(2, 1_100, SessionEvent::SnapshotRequired),
            MonotonicTimestampNs(1_100),
            &mut output,
        ),
        Err(EngineError::VenueUnavailable(
            SessionEvent::SnapshotRequired
        ))
    );
    assert!(faulted.control_armed());
    assert!(!faulted.venue_trading_open());
    assert!(!faulted.trading_eligible());
    assert_eq!(
        faulted.kill_snapshot().unwrap().code,
        KillCode::VenueDisconnect
    );
    assert!(output.iter().all(Option::is_none));
}

#[test]
fn fatal_session_fact_advances_order_cursor_and_keeps_later_fill_visible() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut engine = engine_with(config());
    let (bid, _ask) = live_two_sided(&mut engine);
    let mut output = [None; 2];

    assert_eq!(
        engine.on_order_entry(
            inbound_session(4, 1_600, SessionEvent::SnapshotRequired),
            MonotonicTimestampNs(1_600),
            &mut output,
        ),
        Err(EngineError::VenueUnavailable(
            SessionEvent::SnapshotRequired
        ))
    );
    assert_eq!(engine.expected_order_sequence(), Sequence(5));
    assert_eq!(output.iter().flatten().count(), 2);
    for (index, command) in output.iter().flatten().copied().enumerate() {
        engine
            .on_transmission(
                command,
                TransmissionStatus::Sent,
                MonotonicTimestampNs(1_601 + u64::try_from(index).unwrap()),
            )
            .expect("session-fault cancel transmission");
    }

    let fill_outcome = engine
        .on_order_entry(
            inbound(
                5,
                1_700,
                OrderEvent::Fill(Fill {
                    client_order_id: bid.client_order_id,
                    venue_order_id: VenueOrderId(7_000),
                    trade_id: TradeId(701),
                    price: bid.price,
                    quantity: bid.quantity,
                    leaves_quantity: Quantity::ZERO,
                    liquidity: LiquidityFlag::Added,
                }),
            ),
            MonotonicTimestampNs(1_700),
            &mut output,
        )
        .expect("next sequenced fill remains reconcilable while killed");
    assert!(matches!(
        fill_outcome.application,
        OrderApplication::Fill(_)
    ));
    assert_eq!(engine.expected_order_sequence(), Sequence(6));
    assert_eq!(
        engine.risk().instrument(INSTRUMENT).unwrap().position,
        bid.quantity
    );
}

#[test]
fn identical_traces_are_deterministic_and_trade_does_not_advance_book_sequence() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut first = engine_with(config());
    let mut second = engine_with(config());

    let first_commands = seed_two_sided(&mut first);
    let second_commands = seed_two_sided(&mut second);
    assert_eq!(first_commands, second_commands);
    assert!(
        first_commands
            .iter()
            .all(|command| !matches!(command, OrderCommand::Replace(_)))
    );

    for (index, (left, right)) in first_commands.into_iter().zip(second_commands).enumerate() {
        let monotonic = 1_400 + u64::try_from(index).unwrap();
        first
            .on_transmission(
                left,
                TransmissionStatus::Sent,
                MonotonicTimestampNs(monotonic),
            )
            .unwrap();
        second
            .on_transmission(
                right,
                TransmissionStatus::Sent,
                MonotonicTimestampNs(monotonic),
            )
            .unwrap();
    }
    assert_eq!(first.orders().order_count(), second.orders().order_count());
    assert_eq!(first.risk().exposure(), second.risk().exposure());
}

#[test]
fn market_gap_clock_fault_risk_breach_and_unknown_order_each_fail_closed() {
    let _guard = TEST_LOCK.lock().unwrap();

    let mut gap = engine_with(config());
    let mut output = [None; 2];
    gap.on_market_data(
        market(
            2,
            1_100,
            MarketDataPayload::Book(BookDelta::Add {
                order_id: BID_BOOK_ORDER,
                side: Side::Buy,
                price: PriceTicks(99),
                quantity: Quantity(100),
            }),
        ),
        MonotonicTimestampNs(1_100),
        &mut output,
    )
    .unwrap();
    assert!(matches!(
        gap.on_market_data(
            market(
                4,
                1_200,
                MarketDataPayload::Trade {
                    trade_id: TradeId(91),
                    side: Side::Buy,
                    price: PriceTicks(100),
                    quantity: Quantity(1),
                },
            ),
            MonotonicTimestampNs(1_200),
            &mut output,
        ),
        Err(EngineError::MarketSequenceMismatch { .. })
    ));
    assert_eq!(gap.kill_snapshot().unwrap().code, KillCode::MarketDataGap);

    let mut clock = Engine::new(config()).unwrap();
    assert_eq!(
        clock.on_market_data(
            market(
                2,
                1_100,
                MarketDataPayload::Book(BookDelta::Add {
                    order_id: BID_BOOK_ORDER,
                    side: Side::Buy,
                    price: PriceTicks(99),
                    quantity: Quantity(100),
                }),
            ),
            MonotonicTimestampNs(1_100),
            &mut output,
        ),
        Err(EngineError::Clock(
            quant_hft_core::ClockError::Uninitialized
        ))
    );
    assert_eq!(clock.kill_snapshot().unwrap().code, KillCode::ClockUnsafe);

    let mut tight = config();
    tight.risk.max_order_quantity = Quantity(5);
    let mut risk = engine_with(tight);
    risk.on_market_data(
        market(
            2,
            1_100,
            MarketDataPayload::Book(BookDelta::Add {
                order_id: BID_BOOK_ORDER,
                side: Side::Buy,
                price: PriceTicks(99),
                quantity: Quantity(100),
            }),
        ),
        MonotonicTimestampNs(1_100),
        &mut output,
    )
    .unwrap();
    risk.on_market_data(
        market(
            3,
            1_200,
            MarketDataPayload::Trade {
                trade_id: TradeId(92),
                side: Side::Buy,
                price: PriceTicks(100),
                quantity: Quantity(1),
            },
        ),
        MonotonicTimestampNs(1_200),
        &mut output,
    )
    .unwrap();
    assert!(matches!(
        risk.on_market_data(
            market(
                4,
                1_300,
                MarketDataPayload::Book(BookDelta::Add {
                    order_id: ASK_BOOK_ORDER,
                    side: Side::Sell,
                    price: PriceTicks(101),
                    quantity: Quantity(100),
                }),
            ),
            MonotonicTimestampNs(1_300),
            &mut output,
        ),
        Err(EngineError::Order(OrderError::Risk(
            RiskError::OrderQuantityLimit { .. }
        )))
    ));
    assert_eq!(risk.kill_snapshot().unwrap().code, KillCode::RiskLimit);

    let mut unknown = engine_with(config());
    assert!(matches!(
        unknown.on_order_entry(
            inbound(
                2,
                1_100,
                OrderEvent::Accepted(Accepted {
                    client_order_id: ClientOrderId(999),
                    venue_order_id: VenueOrderId(8_000),
                    price: PriceTicks(99),
                    quantity: Quantity(10),
                }),
            ),
            MonotonicTimestampNs(1_100),
            &mut output,
        ),
        Err(EngineError::UnknownManagedOrder(ClientOrderId(999)))
    ));
    assert_eq!(
        unknown.kill_snapshot().unwrap().code,
        KillCode::InternalInvariant
    );
}

#[test]
fn adverse_markout_from_authenticated_fill_latches_global_kill() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut cfg = config();
    cfg.adverse.halt_after_consecutive = 1;
    cfg.adverse.kill_after_consecutive = 1;
    let mut engine = engine_with(cfg);
    let (bid_command, ask_command) = split_new(seed_two_sided(&mut engine));
    let bid = new_fields(bid_command);
    engine
        .on_transmission(
            bid_command,
            TransmissionStatus::Sent,
            MonotonicTimestampNs(1_400),
        )
        .unwrap();
    engine
        .on_transmission(
            ask_command,
            TransmissionStatus::ProvenUnsent,
            MonotonicTimestampNs(1_401),
        )
        .unwrap();

    let mut output = [None; 2];
    let fill_outcome = engine
        .on_order_entry(
            inbound(
                2,
                1_500,
                OrderEvent::Fill(Fill {
                    client_order_id: bid.client_order_id,
                    venue_order_id: VenueOrderId(7_000),
                    trade_id: TradeId(500),
                    price: bid.price,
                    quantity: bid.quantity,
                    leaves_quantity: Quantity::ZERO,
                    liquidity: LiquidityFlag::Added,
                }),
            ),
            MonotonicTimestampNs(1_500),
            &mut output,
        )
        .unwrap();
    assert!(matches!(
        fill_outcome.application,
        OrderApplication::Fill(_)
    ));
    assert_eq!(fill_outcome.output.commands, 0);

    let marked = engine
        .on_market_data(
            market(
                5,
                1_700,
                MarketDataPayload::Book(BookDelta::Modify {
                    order_id: BID_BOOK_ORDER,
                    price: PriceTicks(90),
                    quantity: Quantity(100),
                }),
            ),
            MonotonicTimestampNs(1_700),
            &mut output,
        )
        .unwrap();
    assert!(marked.adverse.unwrap().global_kill_triggered);
    assert_eq!(
        engine.kill_snapshot().unwrap().code,
        KillCode::AdverseSelection
    );
}

#[test]
fn short_market_output_fails_before_source_book_or_clock_mutation() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut engine = engine_with(config());
    let expected_sequence = engine.expected_market_sequence();
    let book_count = engine.book().order_count();
    let monotonic_before = engine.last_applied_monotonic();
    let utc_before = engine.last_applied_utc();
    let mut output: [Option<OrderCommand>; 0] = [];

    assert_eq!(
        engine.on_market_data(
            market(
                2,
                1_100,
                MarketDataPayload::Book(BookDelta::Add {
                    order_id: BID_BOOK_ORDER,
                    side: Side::Buy,
                    price: PriceTicks(99),
                    quantity: Quantity(100),
                }),
            ),
            MonotonicTimestampNs(1_100),
            &mut output,
        ),
        Err(EngineError::OutputCapacity {
            required: 2,
            provided: 0,
        })
    );
    assert_eq!(engine.expected_market_sequence(), expected_sequence);
    assert_eq!(engine.book().order_count(), book_count);
    assert_eq!(engine.last_applied_monotonic(), monotonic_before);
    assert_eq!(engine.last_applied_utc(), utc_before);
}

#[test]
fn short_snapshot_output_fails_before_snapshot_or_clock_mutation() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut engine = Engine::new(config()).unwrap();
    engine
        .observe_clock(ClockSample {
            utc: TimestampNs(OFFSET + 1_000),
            monotonic: MonotonicTimestampNs(1_000),
            uncertainty_ns: 10,
        })
        .unwrap();
    let market_state = engine.market_state();
    let expected_sequence = engine.expected_market_sequence();
    let monotonic_before = engine.last_applied_monotonic();
    let utc_before = engine.last_applied_utc();
    let mut output: [Option<OrderCommand>; 0] = [];

    assert_eq!(
        engine.on_snapshot(
            snapshot(
                1_010,
                SnapshotPayload::Begin {
                    snapshot_id: 77,
                    last_incremental_sequence: Sequence(10),
                },
            ),
            MonotonicTimestampNs(1_010),
            &mut output,
        ),
        Err(EngineError::OutputCapacity {
            required: 2,
            provided: 0,
        })
    );
    assert_eq!(engine.market_state(), market_state);
    assert_eq!(engine.expected_market_sequence(), expected_sequence);
    assert_eq!(engine.book().order_count(), 0);
    assert_eq!(engine.last_applied_monotonic(), monotonic_before);
    assert_eq!(engine.last_applied_utc(), utc_before);
}

#[test]
fn short_control_output_fails_before_timestamp_or_control_mutation() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut engine = clocked_engine(config());
    let monotonic_before = engine.last_applied_monotonic();
    let utc_before = engine.last_applied_utc();
    let mut output: [Option<OrderCommand>; 0] = [];

    assert_eq!(
        engine.apply_control_decision(arm_decision(TimestampNs(OFFSET + 1_030)), &mut output,),
        Err(EngineError::OutputCapacity {
            required: 2,
            provided: 0,
        })
    );
    assert!(!engine.control_armed());
    assert_eq!(engine.control_lease_deadline(), None);
    assert_eq!(engine.last_applied_monotonic(), monotonic_before);
    assert_eq!(engine.last_applied_utc(), utc_before);
}

#[test]
fn short_output_preflights_before_replay_provenance_rejection_mutates_control() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut engine = engine_with(config());
    let lease_before = engine.control_lease_deadline();
    let authenticated = arm_decision(TimestampNs(OFFSET + 1_060));
    let event = normalize_control_decision(CaptureOrdinal(1), authenticated).unwrap();
    let mut record = [0_u8; RECORD_LEN];
    encode_record(event, &mut record).unwrap();
    let replayed_event = decode_record(&record).unwrap().0;
    let replayed_decision = decode_control_decision(replayed_event).unwrap();
    let mut output: [Option<OrderCommand>; 0] = [];

    assert_eq!(
        engine.apply_control_decision(replayed_decision, &mut output),
        Err(EngineError::OutputCapacity {
            required: 2,
            provided: 0,
        })
    );
    assert!(engine.control_armed());
    assert_eq!(engine.control_lease_deadline(), lease_before);
}

#[test]
fn short_timer_output_fails_before_clock_or_lease_mutation() {
    let _guard = TEST_LOCK.lock().unwrap();
    let deadline = TimestampNs(OFFSET + 1_600);
    let mut engine = engine_with_lease(config(), deadline);
    let monotonic_before = engine.last_applied_monotonic();
    let utc_before = engine.last_applied_utc();
    let mut output: [Option<OrderCommand>; 0] = [];

    assert_eq!(
        engine.check_control_liveness(MonotonicTimestampNs(1_601), &mut output),
        Err(EngineError::OutputCapacity {
            required: 2,
            provided: 0,
        })
    );
    assert!(engine.control_armed());
    assert_eq!(engine.control_lease_deadline(), Some(deadline));
    assert_eq!(engine.last_applied_monotonic(), monotonic_before);
    assert_eq!(engine.last_applied_utc(), utc_before);
}

#[test]
fn short_order_output_fails_before_consuming_fill_or_clock() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut engine = engine_with(config());
    let (bid, _) = live_two_sided(&mut engine);
    let order_before = engine.orders().order(bid.client_order_id);
    let risk_before = engine.risk().instrument(INSTRUMENT);
    let adverse_before = engine.adverse().fill(500);
    let monotonic_before = engine.last_applied_monotonic();
    let utc_before = engine.last_applied_utc();
    let fill = inbound(
        4,
        1_600,
        OrderEvent::Fill(Fill {
            client_order_id: bid.client_order_id,
            venue_order_id: VenueOrderId(7_000),
            trade_id: TradeId(500),
            price: bid.price,
            quantity: bid.quantity,
            leaves_quantity: Quantity::ZERO,
            liquidity: LiquidityFlag::Added,
        }),
    );
    let mut output: [Option<OrderCommand>; 0] = [];

    assert_eq!(
        engine.on_order_entry(fill, MonotonicTimestampNs(1_600), &mut output),
        Err(EngineError::OutputCapacity {
            required: 2,
            provided: 0,
        })
    );
    assert_eq!(engine.expected_order_sequence(), Sequence(4));
    assert_eq!(engine.orders().order(bid.client_order_id), order_before);
    assert_eq!(engine.risk().instrument(INSTRUMENT), risk_before);
    assert!(!engine.orders().has_recent_trade(TradeId(500)));
    assert_eq!(engine.adverse().fill(500), adverse_before);
    assert_eq!(engine.last_applied_monotonic(), monotonic_before);
    assert_eq!(engine.last_applied_utc(), utc_before);
    assert_eq!(
        engine.kill_snapshot().unwrap().code,
        KillCode::InternalInvariant
    );
}

#[test]
fn route_sync_failure_after_fill_remains_consumed_and_advances_source() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut engine = engine_with(config());
    let (bid, _) = live_two_sided(&mut engine);
    let mut output = [None; 2];

    let prepared = engine
        .fail_closed(KillCode::Manual, &mut output)
        .expect("prepare bounded kill cancels");
    assert_eq!(prepared.commands, 2);
    assert!(
        output
            .iter()
            .all(|slot| matches!(slot, Some(OrderCommand::Cancel(_))))
    );

    let fill = inbound(
        4,
        1_600,
        OrderEvent::Fill(Fill {
            client_order_id: bid.client_order_id,
            venue_order_id: VenueOrderId(7_000),
            trade_id: TradeId(500),
            price: bid.price,
            quantity: bid.quantity,
            leaves_quantity: Quantity::ZERO,
            liquidity: LiquidityFlag::Added,
        }),
    );
    assert_eq!(
        engine.on_order_entry(fill, MonotonicTimestampNs(1_600), &mut output),
        Err(EngineError::OrderRouteAfterReconciled {
            client_order_id: bid.client_order_id,
            order_fault: None,
            instrument_rule_violation: None,
        })
    );

    assert_eq!(engine.expected_order_sequence(), Sequence(5));
    assert!(engine.orders().has_recent_trade(TradeId(500)));
    assert_eq!(
        engine.risk().instrument(INSTRUMENT).unwrap().position,
        bid.quantity
    );
    assert_eq!(
        engine
            .orders()
            .order(bid.client_order_id)
            .unwrap()
            .remaining_quantity,
        Quantity::ZERO
    );
}

#[test]
fn reconciled_late_fill_error_commits_order_source_progress_exactly_once() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut engine = engine_with(config());
    let (bid, ask) = live_two_sided(&mut engine);
    let venue_order_id = VenueOrderId(7_000);

    let mut output = [None; 2];
    engine
        .on_market_data(
            market(
                5,
                1_700,
                MarketDataPayload::Trade {
                    trade_id: TradeId(499),
                    side: Side::Buy,
                    price: PriceTicks(100),
                    quantity: Quantity(1),
                },
            ),
            MonotonicTimestampNs(1_700),
            &mut output,
        )
        .expect("advance the retained adverse mark frontier");
    assert!(output.iter().all(Option::is_none));

    let fill = InboundMessage {
        sequence: Sequence(4),
        exchange_timestamp: TimestampNs(OFFSET + 1_590),
        hardware_receive_timestamp: TimestampNs(OFFSET + 1_600),
        payload: InboundPayload::Order(OrderEvent::Fill(Fill {
            client_order_id: bid.client_order_id,
            venue_order_id,
            trade_id: TradeId(500),
            price: bid.price,
            quantity: bid.quantity,
            leaves_quantity: Quantity::ZERO,
            liquidity: LiquidityFlag::Added,
        })),
    };
    assert_eq!(
        engine.on_order_entry(fill, MonotonicTimestampNs(1_800), &mut output),
        Err(EngineError::Order(OrderError::AdverseAfterReconciled(
            AdverseError::LateFillBeyondMarkFrontier {
                fill: TimestampNs(OFFSET + 1_590),
                frontier: TimestampNs(OFFSET + 1_690),
            }
        )))
    );
    assert_eq!(engine.expected_order_sequence(), Sequence(5));
    assert!(engine.orders().order(bid.client_order_id).is_none());
    assert_eq!(
        engine.risk().instrument(INSTRUMENT).unwrap().position,
        bid.quantity
    );
    assert!(engine.orders().has_recent_trade(TradeId(500)));
    assert_eq!(output.iter().flatten().count(), 1);
    assert_eq!(
        cancel_fields(output.iter().flatten().copied().next().unwrap()).client_order_id,
        ask.client_order_id
    );

    let position_after_fill = engine.risk().instrument(INSTRUMENT).unwrap().position;
    assert_eq!(
        engine.on_order_entry(fill, MonotonicTimestampNs(1_801), &mut output),
        Err(EngineError::OrderSequenceMismatch {
            expected: Sequence(5),
            received: Sequence(4),
        })
    );
    assert_eq!(
        engine.risk().instrument(INSTRUMENT).unwrap().position,
        position_after_fill
    );

    let regressing_cursor = InboundMessage {
        sequence: Sequence(5),
        exchange_timestamp: TimestampNs(OFFSET + 1_589),
        hardware_receive_timestamp: TimestampNs(OFFSET + 1_900),
        payload: InboundPayload::Session(SessionEvent::Heartbeat),
    };
    assert_eq!(
        engine.on_order_entry(regressing_cursor, MonotonicTimestampNs(1_900), &mut output,),
        Err(EngineError::EventTimestampRegression {
            prior: TimestampNs(OFFSET + 1_590),
            received: TimestampNs(OFFSET + 1_589),
        })
    );
    assert_eq!(engine.expected_order_sequence(), Sequence(5));

    engine
        .on_order_entry(
            inbound_session(5, 1_900, SessionEvent::Heartbeat),
            MonotonicTimestampNs(1_900),
            &mut output,
        )
        .expect("the next valid venue sequence remains consumable");
    assert_eq!(engine.expected_order_sequence(), Sequence(6));
}

#[test]
fn worse_than_limit_fill_commits_cursor_and_prepares_cancel_first_output() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut engine = engine_with(config());
    let (bid, ask) = live_two_sided(&mut engine);
    let violating_price = PriceTicks(bid.price.0 + 1);
    let fill = inbound(
        4,
        1_600,
        OrderEvent::Fill(Fill {
            client_order_id: bid.client_order_id,
            venue_order_id: VenueOrderId(7_000),
            trade_id: TradeId(702),
            price: violating_price,
            quantity: bid.quantity,
            leaves_quantity: Quantity::ZERO,
            liquidity: LiquidityFlag::Added,
        }),
    );
    let mut output = [None; 2];

    assert_eq!(
        engine.on_order_entry(fill, MonotonicTimestampNs(1_600), &mut output),
        Err(EngineError::Order(
            OrderError::ExecutionPriceAfterReconciled {
                violation: ExecutionPriceViolation {
                    side: Side::Buy,
                    limit_price: bid.price,
                    fill_price: violating_price,
                },
                risk: None,
                adverse: None,
            }
        ))
    );
    assert_eq!(engine.expected_order_sequence(), Sequence(5));
    assert_eq!(
        engine.risk().instrument(INSTRUMENT).unwrap().position,
        bid.quantity
    );
    assert!(engine.orders().has_recent_trade(TradeId(702)));
    assert_eq!(output.iter().flatten().count(), 1);
    assert_eq!(
        cancel_fields(output.iter().flatten().copied().next().unwrap()).client_order_id,
        ask.client_order_id
    );
}

#[test]
fn reconciled_order_fault_summary_retains_simultaneous_fault_evidence() {
    let violation = ExecutionPriceViolation {
        side: Side::Sell,
        limit_price: PriceTicks(101),
        fill_price: PriceTicks(100),
    };

    assert_eq!(
        ReconciledOrderFaultSummary::from_order_error(OrderError::ExecutionPriceAfterReconciled {
            violation,
            risk: Some(RiskError::ArithmeticOverflow),
            adverse: Some(AdverseError::ArithmeticOverflow),
        },),
        Some(ReconciledOrderFaultSummary {
            risk_fault: true,
            adverse_fault: true,
            execution_price: Some(violation),
        })
    );
}

#[test]
fn invalid_fill_instrument_economics_are_applied_and_preserve_order_fault() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut configured = config();
    configured.instrument_definition.maximum_price = PriceTicks(101);
    let mut engine = engine_with(configured);
    let (bid, ask) = live_two_sided(&mut engine);
    let invalid_price = PriceTicks(102);
    let fill = inbound(
        4,
        1_600,
        OrderEvent::Fill(Fill {
            client_order_id: bid.client_order_id,
            venue_order_id: VenueOrderId(7_000),
            trade_id: TradeId(703),
            price: invalid_price,
            quantity: bid.quantity,
            leaves_quantity: Quantity::ZERO,
            liquidity: LiquidityFlag::Added,
        }),
    );
    let mut output = [None; 2];

    assert_eq!(
        engine.on_order_entry(fill, MonotonicTimestampNs(1_600), &mut output),
        Err(EngineError::OrderInstrumentRuleAfterReconciled {
            violation: InstrumentRuleViolation::PriceOutOfBounds {
                minimum: PriceTicks(1),
                maximum: PriceTicks(101),
                received: invalid_price,
            },
            order_fault: Some(ReconciledOrderFaultSummary {
                risk_fault: false,
                adverse_fault: false,
                execution_price: Some(ExecutionPriceViolation {
                    side: Side::Buy,
                    limit_price: bid.price,
                    fill_price: invalid_price,
                }),
            }),
        })
    );
    assert_eq!(engine.expected_order_sequence(), Sequence(5));
    assert_eq!(
        engine.risk().instrument(INSTRUMENT).unwrap().position,
        bid.quantity
    );
    assert!(engine.orders().has_recent_trade(TradeId(703)));
    assert_eq!(output.iter().flatten().count(), 1);
    assert_eq!(
        cancel_fields(output.iter().flatten().copied().next().unwrap()).client_order_id,
        ask.client_order_id
    );
}

#[test]
fn lifecycle_correction_quarantines_idempotently_without_reversing_financial_state() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut engine = engine_with(config());
    let (bid_command, ask_command) = split_new(seed_two_sided(&mut engine));
    let bid = new_fields(bid_command);
    engine
        .on_transmission(
            bid_command,
            TransmissionStatus::Sent,
            MonotonicTimestampNs(1_400),
        )
        .unwrap();
    engine
        .on_transmission(
            ask_command,
            TransmissionStatus::ProvenUnsent,
            MonotonicTimestampNs(1_401),
        )
        .unwrap();

    let mut output = [None; 2];
    engine
        .on_order_entry(
            inbound(
                2,
                1_500,
                OrderEvent::Fill(Fill {
                    client_order_id: bid.client_order_id,
                    venue_order_id: VenueOrderId(7_000),
                    trade_id: TradeId(500),
                    price: bid.price,
                    quantity: bid.quantity,
                    leaves_quantity: Quantity::ZERO,
                    liquidity: LiquidityFlag::Added,
                }),
            ),
            MonotonicTimestampNs(1_500),
            &mut output,
        )
        .unwrap();
    let risk_before = engine.risk().instrument(INSTRUMENT);
    let realized_before = engine.risk().lifetime_realized_pnl();
    let adverse_before = engine.adverse().fill(500);
    let adverse_count_before = engine.adverse().tracked_fill_count();
    let order_count_before = engine.orders().order_count();

    let correction = LifecycleCorrectionObserved {
        correction_id: LifecycleCorrectionId(700),
        target_trade_id: TradeId(500),
        kind: LifecycleCorrectionKind::Bust,
        canonical_payload_digest: LifecycleCorrectionDigest([0xD4; 32]),
    };
    let quarantined = engine
        .on_order_entry(
            inbound(
                3,
                1_600,
                OrderEvent::LifecycleCorrectionObserved(correction),
            ),
            MonotonicTimestampNs(1_600),
            &mut output,
        )
        .unwrap();
    assert_eq!(
        quarantined.application,
        OrderApplication::LifecycleCorrectionQuarantined(correction)
    );
    assert_eq!(quarantined.output.commands, 0);
    let first_kill = engine.kill_snapshot().unwrap();
    assert_eq!(first_kill.code, KillCode::LifecycleCorrection);
    assert_eq!(engine.expected_order_sequence(), Sequence(4));
    assert_eq!(engine.risk().instrument(INSTRUMENT), risk_before);
    assert_eq!(engine.risk().lifetime_realized_pnl(), realized_before);
    assert_eq!(engine.adverse().fill(500), adverse_before);
    assert_eq!(engine.adverse().tracked_fill_count(), adverse_count_before);
    assert_eq!(engine.orders().order_count(), order_count_before);
    assert!(engine.orders().has_recent_trade(TradeId(500)));

    let repeated = engine
        .on_order_entry(
            inbound(
                4,
                1_700,
                OrderEvent::LifecycleCorrectionObserved(correction),
            ),
            MonotonicTimestampNs(1_700),
            &mut output,
        )
        .unwrap();
    assert_eq!(
        repeated.application,
        OrderApplication::LifecycleCorrectionQuarantined(correction)
    );
    assert_eq!(engine.kill_snapshot(), Some(first_kill));
    assert_eq!(engine.risk().instrument(INSTRUMENT), risk_before);
    assert_eq!(engine.adverse().fill(500), adverse_before);
}

fn live_bid_with_cancel_pending(
    engine: &mut Engine,
) -> (quant_hft_core::venue::NewOrder, VenueOrderId) {
    let (bid_command, ask_command) = split_new(seed_two_sided(engine));
    let bid = new_fields(bid_command);
    let venue_order_id = VenueOrderId(7_000);
    engine
        .on_transmission(
            bid_command,
            TransmissionStatus::Sent,
            MonotonicTimestampNs(1_400),
        )
        .unwrap();
    engine
        .on_transmission(
            ask_command,
            TransmissionStatus::ProvenUnsent,
            MonotonicTimestampNs(1_401),
        )
        .unwrap();
    accept(engine, 2, 1_500, bid, venue_order_id);

    let mut output = [None; 2];
    engine
        .on_market_data(
            market(
                5,
                1_600,
                MarketDataPayload::Book(BookDelta::Modify {
                    order_id: BID_BOOK_ORDER,
                    price: PriceTicks(98),
                    quantity: Quantity(100),
                }),
            ),
            MonotonicTimestampNs(1_600),
            &mut output,
        )
        .unwrap();
    let cancel_command = output
        .iter()
        .flatten()
        .copied()
        .find(|command| matches!(command, OrderCommand::Cancel(_)))
        .unwrap();
    for command in output.iter().flatten().copied() {
        if matches!(command, OrderCommand::New(_)) {
            engine
                .on_transmission(
                    command,
                    TransmissionStatus::ProvenUnsent,
                    MonotonicTimestampNs(1_601),
                )
                .unwrap();
        }
    }
    assert_eq!(
        cancel_fields(cancel_command).client_order_id,
        bid.client_order_id
    );
    engine
        .on_transmission(
            cancel_command,
            TransmissionStatus::Sent,
            MonotonicTimestampNs(1_602),
        )
        .unwrap();
    (bid, venue_order_id)
}

#[test]
fn partial_fill_then_cancel_is_reconciled_before_any_replacement_new() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut engine = engine_with(config());
    let (bid, venue_order_id) = live_bid_with_cancel_pending(&mut engine);
    let mut output = [None; 2];

    let partial = engine
        .on_order_entry(
            inbound(
                3,
                1_700,
                OrderEvent::Fill(Fill {
                    client_order_id: bid.client_order_id,
                    venue_order_id,
                    trade_id: TradeId(600),
                    price: bid.price,
                    quantity: Quantity(4),
                    leaves_quantity: Quantity(6),
                    liquidity: LiquidityFlag::Added,
                }),
            ),
            MonotonicTimestampNs(1_700),
            &mut output,
        )
        .unwrap();
    assert_eq!(partial.output.commands, 0);
    assert!(output.iter().all(Option::is_none));

    let canceled = engine
        .on_order_entry(
            inbound(
                4,
                1_800,
                OrderEvent::Canceled(Canceled {
                    client_order_id: bid.client_order_id,
                    venue_order_id,
                    canceled_quantity: Quantity(6),
                    leaves_quantity: Quantity::ZERO,
                }),
            ),
            MonotonicTimestampNs(1_800),
            &mut output,
        )
        .unwrap();
    assert!(matches!(
        canceled.application,
        OrderApplication::Canceled(_)
    ));
    assert!(canceled.output.commands > 0);
    assert!(output.iter().flatten().all(|command| {
        matches!(command, OrderCommand::New(_)) && !matches!(command, OrderCommand::Replace(_))
    }));
}

#[test]
fn full_fill_cancel_race_accepts_only_terminal_zero_cancel_resolution() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut engine = engine_with(config());
    let (bid, venue_order_id) = live_bid_with_cancel_pending(&mut engine);
    let mut output = [None; 2];

    let filled = engine
        .on_order_entry(
            inbound(
                3,
                1_700,
                OrderEvent::Fill(Fill {
                    client_order_id: bid.client_order_id,
                    venue_order_id,
                    trade_id: TradeId(601),
                    price: bid.price,
                    quantity: bid.quantity,
                    leaves_quantity: Quantity::ZERO,
                    liquidity: LiquidityFlag::Added,
                }),
            ),
            MonotonicTimestampNs(1_700),
            &mut output,
        )
        .unwrap();
    assert_eq!(filled.output.commands, 0);

    let resolved = engine
        .on_order_entry(
            inbound(
                4,
                1_800,
                OrderEvent::Canceled(Canceled {
                    client_order_id: bid.client_order_id,
                    venue_order_id,
                    canceled_quantity: Quantity::ZERO,
                    leaves_quantity: Quantity::ZERO,
                }),
            ),
            MonotonicTimestampNs(1_800),
            &mut output,
        )
        .unwrap();
    assert!(matches!(
        resolved.application,
        OrderApplication::Canceled(_)
    ));
    assert!(resolved.output.commands > 0);
    assert!(
        output
            .iter()
            .flatten()
            .all(|command| matches!(command, OrderCommand::New(_)))
    );
}

#[test]
fn steady_state_event_path_performs_no_heap_allocation() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut engine = engine_with(config());
    let _commands = seed_two_sided(&mut engine);
    let mut output = [None; 2];

    ALLOCATIONS.set(0);
    TRACK_ALLOCATIONS.set(true);
    let result = engine.on_market_data(
        market(
            5,
            1_400,
            MarketDataPayload::Trade {
                trade_id: TradeId(700),
                side: Side::Sell,
                price: PriceTicks(100),
                quantity: Quantity(3),
            },
        ),
        MonotonicTimestampNs(1_400),
        &mut output,
    );
    TRACK_ALLOCATIONS.set(false);
    let allocations = ALLOCATIONS.get();

    assert!(result.is_ok());
    assert_eq!(allocations, 0);
}

#[test]
fn control_disarm_cancel_path_performs_no_heap_allocation() {
    let _guard = TEST_LOCK.lock().unwrap();
    let mut engine = engine_with(config());
    let _ = live_two_sided(&mut engine);
    let mut output = [None; 2];

    ALLOCATIONS.set(0);
    TRACK_ALLOCATIONS.set(true);
    let result = engine.apply_control_decision(
        support::authenticated_disarm(
            1,
            ConfigDigest([0xA5; 32]),
            Sequence(2),
            TimestampNs(OFFSET + 1_600),
        ),
        &mut output,
    );
    TRACK_ALLOCATIONS.set(false);
    let allocations = ALLOCATIONS.get();

    assert_eq!(result.unwrap().commands, 2);
    assert_eq!(allocations, 0);
    assert!(
        output
            .iter()
            .flatten()
            .all(|command| matches!(command, OrderCommand::Cancel(_)))
    );
}
