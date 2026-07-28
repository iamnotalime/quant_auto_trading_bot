mod support;

use quant_hft_core::adverse::{AdverseConfig, AdverseError};
use quant_hft_core::clock::ClockError;
use quant_hft_core::control::ConfigDigest;
use quant_hft_core::engine::{EngineConfig, EngineError, ExecutionEngine, TransmissionStatus};
use quant_hft_core::kill::KillCode;
use quant_hft_core::orders::OrderError;
use quant_hft_core::reactor::{
    ClockInput, HotPathReactor, MarketDataInput, OrderEntryInput, ReactorBudget, ReactorError,
    ReactorInput, ReactorInputKind, ReactorStop, SnapshotInput, TimerAction, TimerId, TimerInput,
    TransmissionInput,
};
use quant_hft_core::risk::{
    CurrencyId, InstrumentRiskDefinition, InstrumentValuation, RiskLimits, RiskSessionId,
};
use quant_hft_core::strategy::QuotePolicyConfig;
use quant_hft_core::types::{
    InstrumentId, MonotonicTimestampNs, OrderId, PriceTicks, Quantity, Sequence, Side, TimestampNs,
    VenueId,
};
use quant_hft_core::venue::{
    Accepted, BookDelta, ClientOrderId, Fill, InboundMessage, InboundPayload, LiquidityFlag,
    MarketByOrderId, MarketDataMessage, MarketDataPayload, OrderCommand, OrderEvent, SessionEvent,
    SnapshotMessage, SnapshotPayload, TradeId, VenueOrderId,
};
use quant_hft_core::{ClockSample, SpscRing};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

type Engine = ExecutionEngine<64, 16, 8, 16, 16>;
type Reactor = HotPathReactor<64, 16, 8, 16, 16>;

const INSTRUMENT: InstrumentId = InstrumentId(7);
const OFFSET: u64 = 1_000_000_000;

struct CountingAllocator;

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
        // SAFETY: The exact allocation contract is forwarded to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: `pointer` and `layout` originated from the delegated allocator.
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

fn market(sequence: u64, monotonic: u64, payload: MarketDataPayload) -> MarketDataMessage {
    MarketDataMessage {
        instrument: INSTRUMENT,
        sequence: Sequence(sequence),
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

fn snapshot(monotonic: u64, payload: SnapshotPayload) -> SnapshotMessage {
    SnapshotMessage {
        exchange_timestamp: TimestampNs(OFFSET + monotonic - 10),
        hardware_receive_timestamp: TimestampNs(OFFSET + monotonic),
        payload,
    }
}

fn ready_engine() -> Engine {
    ready_engine_with_lease(TimestampNs(u64::MAX))
}

fn ready_engine_with_lease(lease_deadline: TimestampNs) -> Engine {
    let mut engine = Engine::new(config()).expect("engine configuration");
    engine
        .observe_clock(ClockSample {
            utc: TimestampNs(OFFSET + 1_000),
            monotonic: MonotonicTimestampNs(1_000),
            uncertainty_ns: 10,
        })
        .expect("initial clock sample");
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
            .expect("startup snapshot");
    }
    engine
        .on_order_entry(
            inbound_session(1, 1_030, SessionEvent::LogonAccepted),
            MonotonicTimestampNs(1_030),
            &mut output,
        )
        .expect("order-entry logon");
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
        .expect("arm");
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
        .expect("open venue");
    engine
}

fn seed_live_orders(engine: &mut Engine) -> [OrderCommand; 2] {
    let mut output = [None; 2];
    engine
        .on_market_data(
            market(
                2,
                1_100,
                MarketDataPayload::Book(BookDelta::Add {
                    order_id: MarketByOrderId(11),
                    side: Side::Buy,
                    price: PriceTicks(99),
                    quantity: Quantity(100),
                }),
            ),
            MonotonicTimestampNs(1_100),
            &mut output,
        )
        .expect("bid");
    engine
        .on_market_data(
            market(
                3,
                1_200,
                MarketDataPayload::Book(BookDelta::Add {
                    order_id: MarketByOrderId(12),
                    side: Side::Sell,
                    price: PriceTicks(101),
                    quantity: Quantity(100),
                }),
            ),
            MonotonicTimestampNs(1_200),
            &mut output,
        )
        .expect("ask");
    let commands = [output[0].expect("bid new"), output[1].expect("ask new")];
    for (index, command) in commands.iter().copied().enumerate() {
        engine
            .on_transmission(
                command,
                TransmissionStatus::Sent,
                MonotonicTimestampNs(1_300 + u64::try_from(index).expect("bounded index")),
            )
            .expect("new sent");
        let OrderCommand::New(new) = command else {
            panic!("expected new command");
        };
        engine
            .on_order_entry(
                inbound(
                    u64::try_from(index + 2).expect("bounded sequence"),
                    1_400 + u64::try_from(index).expect("bounded index"),
                    OrderEvent::Accepted(Accepted {
                        client_order_id: new.client_order_id,
                        venue_order_id: VenueOrderId(
                            7_000 + u64::try_from(index).expect("bounded index"),
                        ),
                        price: new.price,
                        quantity: new.quantity,
                    }),
                ),
                MonotonicTimestampNs(1_400 + u64::try_from(index).expect("bounded index")),
                &mut output,
            )
            .expect("new accepted");
    }
    commands
}

fn live_engine() -> Engine {
    let mut engine = ready_engine();
    seed_live_orders(&mut engine);
    engine
}

#[test]
fn priority_transmission_lane_cannot_be_blocked_by_queued_market_data() {
    let mut reactor = Reactor::new(live_engine());
    let mut event_ring = SpscRing::<ReactorInput, 16>::new();
    let mut transmission_ring = SpscRing::<TransmissionInput, 16>::new();
    let (mut event_producer, mut event_consumer) = event_ring.split();
    let (mut transmission_producer, mut transmission_consumer) = transmission_ring.split();
    let mut egress = [None; 2];

    event_producer
        .try_push(ReactorInput::MarketData(MarketDataInput {
            message: market(
                4,
                1_500,
                MarketDataPayload::TradingStatus { status_code: 0 },
            ),
            monotonic_now: MonotonicTimestampNs(1_500),
        }))
        .expect("close event");
    let first = reactor
        .run(
            &mut event_consumer,
            &mut transmission_consumer,
            ReactorBudget {
                max_events: 8,
                max_transmissions: 8,
            },
            &mut egress,
        )
        .expect("publish cancels");
    assert_eq!(first.commands_published, 2);
    assert!(matches!(
        first.stop,
        ReactorStop::TransmissionBoundary {
            published: 2,
            outstanding: 2
        }
    ));
    let cancels = [
        egress[0].take().expect("first cancel").command,
        egress[1].take().expect("second cancel").command,
    ];
    assert!(
        cancels
            .iter()
            .all(|command| matches!(command, OrderCommand::Cancel(_)))
    );

    // This normal event is deliberately queued before transport feedback. The
    // separate priority lane must still resolve both commands first.
    event_producer
        .try_push(ReactorInput::MarketData(MarketDataInput {
            message: market(
                5,
                1_600,
                MarketDataPayload::Trade {
                    trade_id: TradeId(99),
                    side: Side::Sell,
                    price: PriceTicks(100),
                    quantity: Quantity(1),
                },
            ),
            monotonic_now: MonotonicTimestampNs(1_600),
        }))
        .expect("queued market event");
    for (index, command) in cancels.into_iter().enumerate() {
        transmission_producer
            .try_push(TransmissionInput {
                command,
                status: TransmissionStatus::Sent,
                monotonic_now: MonotonicTimestampNs(
                    1_550 + u64::try_from(index).expect("bounded index"),
                ),
            })
            .expect("transport feedback");
    }

    let second = reactor
        .run(
            &mut event_consumer,
            &mut transmission_consumer,
            ReactorBudget {
                max_events: 8,
                max_transmissions: 8,
            },
            &mut egress,
        )
        .expect("priority feedback and market event");
    assert_eq!(second.transmissions_processed, 2);
    assert_eq!(second.events_processed, 1);
    assert_eq!(second.outstanding_transmissions, 0);
    assert_eq!(second.stop, ReactorStop::InputDrained);
    assert_eq!(reactor.counters().transmissions_sent, 2);
}

#[test]
fn reconciled_order_error_publishes_cancel_egress_before_reactor_failure() {
    let mut engine = ready_engine();
    let live_commands = seed_live_orders(&mut engine);
    let bid = live_commands
        .iter()
        .find_map(|command| match command {
            OrderCommand::New(order) if order.side == Side::Buy => Some(*order),
            _ => None,
        })
        .expect("live bid");
    let ask = live_commands
        .iter()
        .find_map(|command| match command {
            OrderCommand::New(order) if order.side == Side::Sell => Some(*order),
            _ => None,
        })
        .expect("live ask");
    let mut engine_output = [None; 2];
    engine
        .on_market_data(
            market(
                4,
                1_700,
                MarketDataPayload::Trade {
                    trade_id: TradeId(499),
                    side: Side::Buy,
                    price: PriceTicks(100),
                    quantity: Quantity(1),
                },
            ),
            MonotonicTimestampNs(1_700),
            &mut engine_output,
        )
        .expect("advance adverse mark frontier");
    assert!(engine_output.iter().all(Option::is_none));

    let late_fill = InboundMessage {
        sequence: Sequence(4),
        exchange_timestamp: TimestampNs(OFFSET + 1_590),
        hardware_receive_timestamp: TimestampNs(OFFSET + 1_600),
        payload: InboundPayload::Order(OrderEvent::Fill(Fill {
            client_order_id: bid.client_order_id,
            venue_order_id: VenueOrderId(7_000),
            trade_id: TradeId(500),
            price: bid.price,
            quantity: bid.quantity,
            leaves_quantity: Quantity::ZERO,
            liquidity: LiquidityFlag::Added,
        })),
    };
    let mut reactor = Reactor::new(engine);
    let mut event_ring = SpscRing::<ReactorInput, 4>::new();
    let mut transmission_ring = SpscRing::<TransmissionInput, 4>::new();
    let (mut event_producer, mut event_consumer) = event_ring.split();
    let (_transmission_producer, mut transmission_consumer) = transmission_ring.split();
    event_producer
        .try_push(ReactorInput::OrderEntry(OrderEntryInput {
            message: late_fill,
            monotonic_now: MonotonicTimestampNs(1_800),
        }))
        .expect("late fill input");
    let mut egress = [None; 2];

    let failure = reactor
        .run(
            &mut event_consumer,
            &mut transmission_consumer,
            ReactorBudget {
                max_events: 1,
                max_transmissions: 1,
            },
            &mut egress,
        )
        .expect_err("typed reconciled error");

    assert_eq!(
        failure.error,
        ReactorError::Engine {
            input: ReactorInputKind::OrderEntry,
            source: EngineError::Order(OrderError::AdverseAfterReconciled(
                AdverseError::LateFillBeyondMarkFrontier {
                    fill: TimestampNs(OFFSET + 1_590),
                    frontier: TimestampNs(OFFSET + 1_690),
                }
            )),
        }
    );
    assert_eq!(failure.report.events_processed, 1);
    assert_eq!(failure.report.commands_published, 1);
    assert_eq!(reactor.outstanding_transmissions(), 1);
    assert_eq!(reactor.engine().expected_order_sequence(), Sequence(5));
    let published = egress[0].take().expect("cancel-first egress");
    let OrderCommand::Cancel(cancel) = published.command else {
        panic!("expected remaining ask cancel");
    };
    assert_eq!(cancel.client_order_id, ask.client_order_id);
    assert!(egress[1].is_none());
}

#[test]
fn clock_failure_publishes_kill_cancels_before_preserving_primary_error() {
    let mut reactor = Reactor::new(live_engine());
    let mut event_ring = SpscRing::<ReactorInput, 4>::new();
    let mut transmission_ring = SpscRing::<TransmissionInput, 4>::new();
    let (mut event_producer, mut event_consumer) = event_ring.split();
    let (_transmission_producer, mut transmission_consumer) = transmission_ring.split();
    event_producer
        .try_push(ReactorInput::Clock(ClockInput {
            sample: ClockSample {
                utc: TimestampNs(OFFSET + 1_001),
                monotonic: MonotonicTimestampNs(1_000),
                uncertainty_ns: 10,
            },
        }))
        .expect("rejected clock sample");
    let mut egress = [None; 2];

    let failure = reactor
        .run(
            &mut event_consumer,
            &mut transmission_consumer,
            ReactorBudget {
                max_events: 1,
                max_transmissions: 1,
            },
            &mut egress,
        )
        .expect_err("clock error remains primary");

    assert_eq!(
        failure.error,
        ReactorError::Engine {
            input: ReactorInputKind::Clock,
            source: EngineError::Clock(ClockError::MonotonicRegression),
        }
    );
    assert_eq!(failure.report.events_processed, 1);
    assert_eq!(failure.report.commands_published, 2);
    assert_eq!(reactor.outstanding_transmissions(), 2);
    assert!(egress.iter().all(
        |slot| matches!(slot, Some(value) if matches!(value.command, OrderCommand::Cancel(_)))
    ));
}

#[test]
fn reactor_routes_clock_and_snapshot_before_incremental_eligibility() {
    let engine = Engine::new(config()).unwrap();
    let mut reactor = Reactor::new(engine);
    let mut event_ring = SpscRing::<ReactorInput, 8>::new();
    let mut transmission_ring = SpscRing::<TransmissionInput, 4>::new();
    let (mut event_producer, mut event_consumer) = event_ring.split();
    let (_transmission_producer, mut transmission_consumer) = transmission_ring.split();
    event_producer
        .try_push(ReactorInput::Clock(ClockInput {
            sample: ClockSample {
                utc: TimestampNs(OFFSET + 1_000),
                monotonic: MonotonicTimestampNs(1_000),
                uncertainty_ns: 10,
            },
        }))
        .unwrap();
    for (monotonic, payload) in [
        (
            1_010,
            SnapshotPayload::Begin {
                snapshot_id: 9,
                last_incremental_sequence: Sequence(0),
            },
        ),
        (
            1_020,
            SnapshotPayload::End {
                snapshot_id: 9,
                last_incremental_sequence: Sequence(0),
            },
        ),
    ] {
        event_producer
            .try_push(ReactorInput::Snapshot(SnapshotInput {
                message: snapshot(monotonic, payload),
                monotonic_now: MonotonicTimestampNs(monotonic),
            }))
            .unwrap();
    }
    let mut egress = [None; 2];
    let report = reactor
        .run(
            &mut event_consumer,
            &mut transmission_consumer,
            ReactorBudget {
                max_events: 3,
                max_transmissions: 1,
            },
            &mut egress,
        )
        .unwrap();
    assert_eq!(report.events_processed, 3);
    assert_eq!(report.stop, ReactorStop::EventBudgetExhausted);
    assert_eq!(
        reactor.engine().market_state(),
        quant_hft_core::engine::EngineMarketState::Live
    );
    assert_eq!(reactor.engine().expected_market_sequence(), Sequence(1));
    assert_eq!(reactor.counters().snapshot_inputs, 2);
}

#[test]
fn egress_shortage_retains_event_and_applies_mandatory_kill_before_mutation() {
    let mut reactor = Reactor::new(live_engine());
    let mut event_ring = SpscRing::<ReactorInput, 8>::new();
    let mut transmission_ring = SpscRing::<TransmissionInput, 8>::new();
    let (mut event_producer, mut event_consumer) = event_ring.split();
    let (_transmission_producer, mut transmission_consumer) = transmission_ring.split();
    event_producer
        .try_push(ReactorInput::MarketData(MarketDataInput {
            message: market(
                4,
                1_500,
                MarketDataPayload::Trade {
                    trade_id: TradeId(100),
                    side: Side::Buy,
                    price: PriceTicks(100),
                    quantity: Quantity(1),
                },
            ),
            monotonic_now: MonotonicTimestampNs(1_500),
        }))
        .expect("market event");

    let mut undersized = [None; 1];
    let first = reactor
        .run(
            &mut event_consumer,
            &mut transmission_consumer,
            ReactorBudget {
                max_events: 8,
                max_transmissions: 8,
            },
            &mut undersized,
        )
        .expect("typed mandatory-kill stop");
    assert_eq!(first.events_processed, 0);
    assert!(first.event_retained);
    assert!(first.mandatory_kill_pending);
    assert_eq!(
        first.stop,
        ReactorStop::MandatoryKillRequired {
            required_egress: 2,
            available_egress: 1,
        }
    );
    assert!(reactor.engine().kill_snapshot().is_none());
    assert_eq!(reactor.engine().expected_market_sequence(), Sequence(4));

    let mut emergency = [None; 2];
    let second = reactor
        .run(
            &mut event_consumer,
            &mut transmission_consumer,
            ReactorBudget {
                max_events: 8,
                max_transmissions: 8,
            },
            &mut emergency,
        )
        .expect("apply mandatory kill");
    assert_eq!(second.commands_published, 2);
    assert!(second.event_retained);
    assert!(!second.mandatory_kill_pending);
    assert!(
        emergency
            .iter()
            .flatten()
            .all(|item| matches!(item.command, OrderCommand::Cancel(_)))
    );
    assert_eq!(
        reactor.engine().kill_snapshot().expect("kill").code,
        KillCode::InternalInvariant
    );
    assert!(!reactor.engine().control_armed());
}

#[test]
fn stray_and_mismatched_transmission_feedback_are_contract_errors() {
    let reactor = Reactor::new(ready_engine());
    let mut event_ring = SpscRing::<ReactorInput, 4>::new();
    let mut transmission_ring = SpscRing::<TransmissionInput, 4>::new();
    let (_event_producer, mut event_consumer) = event_ring.split();
    let (mut transmission_producer, mut transmission_consumer) = transmission_ring.split();
    let command = OrderCommand::New(quant_hft_core::venue::NewOrder {
        client_order_id: ClientOrderId(44),
        instrument: INSTRUMENT,
        side: Side::Buy,
        price: PriceTicks(99),
        quantity: Quantity(1),
        time_in_force: quant_hft_core::venue::TimeInForce::PostOnly,
        created_at: TimestampNs(OFFSET + 1_100),
    });
    transmission_producer
        .try_push(TransmissionInput {
            command,
            status: TransmissionStatus::Sent,
            monotonic_now: MonotonicTimestampNs(1_100),
        })
        .expect("stray feedback");
    let mut reactor = reactor;
    let mut egress = [None; 2];
    let failure = reactor
        .run(
            &mut event_consumer,
            &mut transmission_consumer,
            ReactorBudget {
                max_events: 1,
                max_transmissions: 1,
            },
            &mut egress,
        )
        .expect_err("stray feedback must fail");
    assert_eq!(failure.error, ReactorError::UnexpectedTransmission(command));
    assert!(failure.report.mandatory_kill_pending);
    assert!(reactor.mandatory_kill_pending());
    assert!(reactor.engine().kill_snapshot().is_none());
}

#[test]
fn exact_feedback_clock_fault_retains_fifo_and_sets_mandatory_safety() {
    let mut reactor = Reactor::new(ready_engine());
    let mut event_ring = SpscRing::<ReactorInput, 4>::new();
    let mut transmission_ring = SpscRing::<TransmissionInput, 4>::new();
    let (mut event_producer, mut event_consumer) = event_ring.split();
    let (mut transmission_producer, mut transmission_consumer) = transmission_ring.split();
    for (sequence, monotonic, payload) in [
        (
            2,
            1_100,
            MarketDataPayload::Book(BookDelta::Add {
                order_id: MarketByOrderId(11),
                side: Side::Buy,
                price: PriceTicks(99),
                quantity: Quantity(100),
            }),
        ),
        (
            3,
            1_200,
            MarketDataPayload::Book(BookDelta::Add {
                order_id: MarketByOrderId(12),
                side: Side::Sell,
                price: PriceTicks(101),
                quantity: Quantity(100),
            }),
        ),
    ] {
        event_producer
            .try_push(ReactorInput::MarketData(MarketDataInput {
                message: market(sequence, monotonic, payload),
                monotonic_now: MonotonicTimestampNs(monotonic),
            }))
            .expect("quote input");
    }
    let mut egress = [None; 2];
    let quoted = reactor
        .run(
            &mut event_consumer,
            &mut transmission_consumer,
            ReactorBudget {
                max_events: 2,
                max_transmissions: 1,
            },
            &mut egress,
        )
        .expect("publish new orders");
    assert_eq!(quoted.commands_published, 2);
    let first = egress[0].take().expect("first new order").command;
    let _second = egress[1].take().expect("second new order").command;
    transmission_producer
        .try_push(TransmissionInput {
            command: first,
            status: TransmissionStatus::Sent,
            monotonic_now: MonotonicTimestampNs(u64::MAX),
        })
        .expect("exact feedback");

    let failure = reactor
        .run(
            &mut event_consumer,
            &mut transmission_consumer,
            ReactorBudget {
                max_events: 0,
                max_transmissions: 1,
            },
            &mut egress,
        )
        .expect_err("expired clock holdover must fail closed");

    assert_eq!(
        failure.error,
        ReactorError::Engine {
            input: ReactorInputKind::Transmission,
            source: EngineError::Clock(ClockError::HoldoverExpired),
        }
    );
    assert_eq!(failure.report.transmissions_processed, 1);
    assert_eq!(failure.report.commands_published, 0);
    assert_eq!(failure.report.outstanding_transmissions, 2);
    assert!(failure.report.mandatory_kill_pending);
    assert!(egress.iter().all(Option::is_none));
    assert_eq!(reactor.outstanding_transmissions(), 2);
    assert!(reactor.mandatory_kill_pending());
    assert_eq!(
        reactor.engine().kill_snapshot().expect("clock kill").code,
        KillCode::ClockUnsafe
    );
}

#[test]
fn wrong_feedback_command_cannot_resolve_an_outstanding_transport_barrier() {
    let mut reactor = Reactor::new(live_engine());
    let mut event_ring = SpscRing::<ReactorInput, 8>::new();
    let mut transmission_ring = SpscRing::<TransmissionInput, 8>::new();
    let (mut event_producer, mut event_consumer) = event_ring.split();
    let (mut transmission_producer, mut transmission_consumer) = transmission_ring.split();
    event_producer
        .try_push(ReactorInput::MarketData(MarketDataInput {
            message: market(
                4,
                1_500,
                MarketDataPayload::TradingStatus { status_code: 0 },
            ),
            monotonic_now: MonotonicTimestampNs(1_500),
        }))
        .unwrap();
    let mut egress = [None; 2];
    reactor
        .run(
            &mut event_consumer,
            &mut transmission_consumer,
            ReactorBudget {
                max_events: 1,
                max_transmissions: 1,
            },
            &mut egress,
        )
        .unwrap();
    let expected = egress[0].take().unwrap().command;
    let received = egress[1].take().unwrap().command;
    assert_ne!(expected, received);
    transmission_producer
        .try_push(TransmissionInput {
            command: received,
            status: TransmissionStatus::Sent,
            monotonic_now: MonotonicTimestampNs(1_510),
        })
        .unwrap();
    let failure = reactor
        .run(
            &mut event_consumer,
            &mut transmission_consumer,
            ReactorBudget {
                max_events: 1,
                max_transmissions: 1,
            },
            &mut egress,
        )
        .expect_err("out-of-order feedback");
    assert_eq!(
        failure.error,
        ReactorError::TransmissionMismatch { expected, received }
    );
    assert!(failure.report.mandatory_kill_pending);
    assert_eq!(reactor.outstanding_transmissions(), 2);
    assert!(reactor.mandatory_kill_pending());
}

#[test]
fn invalid_timer_is_rejected_without_engine_dispatch() {
    let mut reactor = Reactor::new(ready_engine());
    let mut event_ring = SpscRing::<ReactorInput, 4>::new();
    let mut transmission_ring = SpscRing::<TransmissionInput, 4>::new();
    let (mut event_producer, mut event_consumer) = event_ring.split();
    let (_transmission_producer, mut transmission_consumer) = transmission_ring.split();
    let timer = TimerInput {
        timer_id: TimerId(0),
        action: TimerAction::KillCancelSweep,
        scheduled_at: MonotonicTimestampNs(2_000),
        fired_at: MonotonicTimestampNs(1_999),
    };
    event_producer
        .try_push(ReactorInput::Timer(timer))
        .expect("timer");
    let mut egress = [None; 2];
    let failure = reactor
        .run(
            &mut event_consumer,
            &mut transmission_consumer,
            ReactorBudget {
                max_events: 1,
                max_transmissions: 1,
            },
            &mut egress,
        )
        .expect_err("invalid timer");
    assert_eq!(failure.error, ReactorError::InvalidTimer(timer));
    assert_eq!(reactor.engine().expected_market_sequence(), Sequence(2));
}

#[test]
fn control_liveness_timer_expires_lease_and_publishes_cancel_first_egress() {
    let mut engine = ready_engine_with_lease(TimestampNs(OFFSET + 1_600));
    seed_live_orders(&mut engine);
    let mut reactor = Reactor::new(engine);
    let mut event_ring = SpscRing::<ReactorInput, 4>::new();
    let mut transmission_ring = SpscRing::<TransmissionInput, 4>::new();
    let (mut event_producer, mut event_consumer) = event_ring.split();
    let (_transmission_producer, mut transmission_consumer) = transmission_ring.split();
    event_producer
        .try_push(ReactorInput::Timer(TimerInput {
            timer_id: TimerId(77),
            action: TimerAction::ControlLivenessCheck,
            scheduled_at: MonotonicTimestampNs(1_600),
            fired_at: MonotonicTimestampNs(1_601),
        }))
        .expect("control lease timer");
    let mut egress = [None; 2];

    ALLOCATIONS.with(|allocations| allocations.set(0));
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(true));
    let result = reactor.run(
        &mut event_consumer,
        &mut transmission_consumer,
        ReactorBudget {
            max_events: 1,
            max_transmissions: 1,
        },
        &mut egress,
    );
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(false));
    let allocations = ALLOCATIONS.with(Cell::get);
    let report = result.expect("control lease expiry");

    assert_eq!(report.commands_published, 2);
    assert_eq!(allocations, 0);
    assert!(!reactor.engine().control_armed());
    assert_eq!(
        reactor.engine().kill_snapshot().unwrap().code,
        KillCode::VenueDisconnect
    );
    assert!(
        egress
            .iter()
            .flatten()
            .all(|item| matches!(item.command, OrderCommand::Cancel(_)))
    );
}

#[test]
fn initialized_reactor_run_performs_no_heap_allocation() {
    let mut reactor = Reactor::new(ready_engine());
    let mut event_ring = SpscRing::<ReactorInput, 4>::new();
    let mut transmission_ring = SpscRing::<TransmissionInput, 4>::new();
    let (mut event_producer, mut event_consumer) = event_ring.split();
    let (_transmission_producer, mut transmission_consumer) = transmission_ring.split();
    event_producer
        .try_push(ReactorInput::Clock(ClockInput {
            sample: ClockSample {
                utc: TimestampNs(OFFSET + 2_000),
                monotonic: MonotonicTimestampNs(2_000),
                uncertainty_ns: 10,
            },
        }))
        .expect("clock input");
    let mut egress = [None; 2];

    ALLOCATIONS.with(|allocations| allocations.set(0));
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(true));
    let result = reactor.run(
        &mut event_consumer,
        &mut transmission_consumer,
        ReactorBudget {
            max_events: 1,
            max_transmissions: 1,
        },
        &mut egress,
    );
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(false));
    let allocations = ALLOCATIONS.with(Cell::get);

    assert!(result.is_ok());
    assert_eq!(allocations, 0);
}
