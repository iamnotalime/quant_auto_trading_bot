mod support;

use quant_hft_core::adverse::AdverseConfig;
use quant_hft_core::control::ConfigDigest;
use quant_hft_core::drop_copy::{DropCopyConfig, DropCopyError, DropCopyReportIdentity};
use quant_hft_core::engine::{
    EngineConfig, EngineError, ExecutionEngine, OrderApplication, TransmissionStatus,
};
use quant_hft_core::event_codec::{
    ReplayInput, VenueCaptureMetadata, decode_drop_copy, decode_replay_input, decode_timer,
    normalize_drop_copy, normalize_order_entry, normalize_timer,
};
use quant_hft_core::events::{CaptureOrdinal, EventSource, SequenceDomain, SessionEpoch, SourceId};
use quant_hft_core::journal::{RECORD_LEN, decode_record, encode_record};
use quant_hft_core::kill::KillCode;
use quant_hft_core::native_live::{NativeLiveCoordinator, NativeLiveError};
use quant_hft_core::orders::OrderError;
use quant_hft_core::reactor::{
    DropCopyInput, HotPathReactor, MAX_REACTOR_COMMANDS_PER_INPUT, ReactorBudget, ReactorError,
    ReactorInput, ReactorInputKind, TimerAction, TimerId, TimerInput, TransmissionInput,
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
    Accepted, BookDelta, ClientOrderId, Fill, InboundMessage, InboundPayload,
    LifecycleCorrectionDigest, LifecycleCorrectionId, LifecycleCorrectionKind,
    LifecycleCorrectionObserved, LiquidityFlag, MarketByOrderId, MarketDataMessage,
    MarketDataPayload, OrderCommand, OrderEvent, ProtocolId, RejectCode, Rejected, SessionEvent,
    SessionId, SnapshotMessage, SnapshotPayload, TradeId, VenueIdentity, VenueOrderId,
};
use quant_hft_core::{EngineReplayError, SpscRing, dispatch_engine_replay_event};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

type Engine = ExecutionEngine<64, 16, 8, 16, 16>;

const VENUE: VenueId = VenueId(1);
const INSTRUMENT: InstrumentId = InstrumentId(7);
const OFFSET: u64 = 1_000_000_000;
const ORDER_ENTRY_SOURCE: EventSource = EventSource::new(
    SourceId::new(20, 2),
    SequenceDomain::OrderEntry,
    SessionEpoch(11),
);
const DROP_COPY_SOURCE: EventSource = EventSource::new(
    SourceId::new(77, 8),
    SequenceDomain::DropCopy,
    SessionEpoch(29),
);

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
        // SAFETY: Delegates the exact layout to the process system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: `pointer` and `layout` came from the delegated system allocator.
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[test]
fn canonical_drop_copy_domain_round_trips_to_its_own_reactor_lane() {
    let message = inbound(
        1,
        1_030,
        InboundPayload::Session(SessionEvent::LogonAccepted),
    );
    let event = normalize_drop_copy(metadata(DROP_COPY_SOURCE, 1, 1_030), message).unwrap();
    assert_eq!(decode_drop_copy(event), Ok(message));
    let mut record = [0_u8; RECORD_LEN];
    assert_eq!(encode_record(event, &mut record).unwrap(), RECORD_LEN);
    assert_eq!(decode_record(&record).unwrap(), (event, RECORD_LEN));
    assert_eq!(
        decode_replay_input(event),
        Ok(ReplayInput::Reactor(ReactorInput::DropCopy(
            DropCopyInput {
                message,
                monotonic_now: MonotonicTimestampNs(1_030),
            }
        )))
    );
    assert!(normalize_order_entry(metadata(DROP_COPY_SOURCE, 1, 1_030), message).is_err());
    assert!(normalize_drop_copy(metadata(ORDER_ENTRY_SOURCE, 1, 1_030), message).is_err());
}

#[test]
fn live_coordinator_persists_exact_drop_copy_source_domain_and_session() {
    let identity = VenueIdentity {
        venue: VENUE,
        market_data_protocol: ProtocolId(10),
        order_entry_protocol: ProtocolId(20),
        session: SessionId(30),
    };
    let market_data_source = EventSource::new(
        SourceId::new(10, 1),
        SequenceDomain::MarketData,
        SessionEpoch(7),
    );
    let coordinator = NativeLiveCoordinator::new_with_drop_copy(
        identity,
        support::instrument_definition(VENUE, INSTRUMENT),
        market_data_source,
        ORDER_ENTRY_SOURCE,
        DROP_COPY_SOURCE,
        41,
        CaptureOrdinal(1),
        1,
    )
    .unwrap();
    assert_eq!(
        coordinator.expected_drop_copy_source(),
        Some(DROP_COPY_SOURCE)
    );
    assert_eq!(
        coordinator.checkpoint().expected_drop_copy_source,
        Some(DROP_COPY_SOURCE)
    );

    for invalid in [
        EventSource::new(
            DROP_COPY_SOURCE.id,
            SequenceDomain::OrderEntry,
            DROP_COPY_SOURCE.session_epoch,
        ),
        EventSource::new(
            DROP_COPY_SOURCE.id,
            SequenceDomain::DropCopy,
            SessionEpoch(0),
        ),
        EventSource::new(
            SourceId::new(0, DROP_COPY_SOURCE.id.channel),
            SequenceDomain::DropCopy,
            DROP_COPY_SOURCE.session_epoch,
        ),
    ] {
        assert_eq!(
            NativeLiveCoordinator::new_with_drop_copy(
                identity,
                support::instrument_definition(VENUE, INSTRUMENT),
                market_data_source,
                ORDER_ENTRY_SOURCE,
                invalid,
                41,
                CaptureOrdinal(1),
                1,
            ),
            Err(NativeLiveError::InvalidDropCopySource(invalid))
        );
    }
}

#[test]
fn economic_mismatch_kills_and_publishes_only_cancels_before_new_risk() {
    let (mut engine, orders) = reconciled_live_orders();
    let bid = accepted_for(orders[0], VenueOrderId(7_001));
    let bid_price = match bid {
        OrderEvent::Accepted(value) => value.price,
        _ => unreachable!(),
    };
    let fill = fill_for(bid, TradeId(9_001), bid_price, Quantity(1));
    let mut output = [None; MAX_REACTOR_COMMANDS_PER_INPUT];

    engine
        .on_order_entry(
            inbound(4, 1_070, InboundPayload::Order(fill)),
            MonotonicTimestampNs(1_070),
            &mut output,
        )
        .unwrap();
    assert_eq!(output, [None; MAX_REACTOR_COMMANDS_PER_INPUT]);
    assert!(!engine.trading_eligible());
    assert_eq!(engine.drop_copy_status().unwrap().pending_order_entry, 1);

    let mismatched = match fill {
        OrderEvent::Fill(value) => OrderEvent::Fill(Fill {
            price: PriceTicks(value.price.0 + 1),
            ..value
        }),
        _ => unreachable!(),
    };
    assert_eq!(
        engine.on_drop_copy(
            inbound(4, 1_071, InboundPayload::Order(mismatched)),
            MonotonicTimestampNs(1_071),
            &mut output,
        ),
        Err(EngineError::DropCopy(DropCopyError::ReportMismatch {
            order_entry: DropCopyReportIdentity::from_report(fill),
            drop_copy: DropCopyReportIdentity::from_report(mismatched),
        }))
    );
    assert_eq!(
        engine.kill_snapshot().unwrap().code,
        KillCode::DropCopyMismatch
    );
    assert!(
        output
            .iter()
            .all(|slot| matches!(slot, Some(OrderCommand::Cancel(_))))
    );
    assert_eq!(output.iter().flatten().count(), 2);
    assert_eq!(
        engine.risk().instrument(INSTRUMENT).unwrap().position,
        Quantity(1),
        "drop copy must not apply the fill to risk a second time"
    );
}

#[test]
fn cross_variant_divergence_for_one_client_kills_before_new_risk() {
    let (mut engine, orders) = prepared_sent_orders();
    let accepted = accepted_for(orders[0], VenueOrderId(7_001));
    let client_order_id = match accepted {
        OrderEvent::Accepted(value) => value.client_order_id,
        _ => unreachable!(),
    };
    let rejected = OrderEvent::Rejected(Rejected {
        client_order_id,
        code: RejectCode(41),
    });
    let mut output = [None; MAX_REACTOR_COMMANDS_PER_INPUT];
    engine
        .on_order_entry(
            inbound(2, 1_060, InboundPayload::Order(accepted)),
            MonotonicTimestampNs(1_060),
            &mut output,
        )
        .unwrap();
    assert_eq!(output, [None; MAX_REACTOR_COMMANDS_PER_INPUT]);
    assert!(!engine.trading_eligible());

    assert_eq!(
        engine.on_drop_copy(
            inbound(2, 1_061, InboundPayload::Order(rejected)),
            MonotonicTimestampNs(1_061),
            &mut output,
        ),
        Err(EngineError::DropCopy(DropCopyError::ReportMismatch {
            order_entry: DropCopyReportIdentity::from_report(accepted),
            drop_copy: DropCopyReportIdentity::from_report(rejected),
        }))
    );
    assert_eq!(
        engine.kill_snapshot().unwrap().code,
        KillCode::DropCopyMismatch
    );
    assert_eq!(output.iter().flatten().count(), 1);
    assert!(
        output
            .iter()
            .all(|slot| slot.is_none() || matches!(slot, Some(OrderCommand::Cancel(_))))
    );
}

#[test]
fn drop_copy_sequence_gap_kills_and_cancels_live_quotes() {
    let (mut engine, _) = reconciled_live_orders();
    let mut output = [None; MAX_REACTOR_COMMANDS_PER_INPUT];
    let heartbeat = inbound(5, 1_070, InboundPayload::Session(SessionEvent::Heartbeat));
    assert_eq!(
        engine.on_drop_copy(heartbeat, MonotonicTimestampNs(1_070), &mut output,),
        Err(EngineError::DropCopy(DropCopyError::SequenceMismatch {
            expected: Sequence(4),
            received: Sequence(5),
        }))
    );
    assert_eq!(
        engine.kill_snapshot().unwrap().code,
        KillCode::DropCopyMismatch
    );
    assert_eq!(output.iter().flatten().count(), 2);
    assert!(
        output
            .iter()
            .all(|slot| matches!(slot, Some(OrderCommand::Cancel(_))))
    );
}

#[test]
fn short_drop_copy_output_fails_before_clock_or_gate_consumption() {
    let (mut engine, _) = reconciled_live_orders();
    let monotonic_before = engine.last_applied_monotonic();
    let utc_before = engine.last_applied_utc();
    let replay = SessionEvent::ReplayComplete {
        through: Sequence(3),
    };
    let message = inbound(4, 1_070, InboundPayload::Session(replay));
    let mut short_output: [Option<OrderCommand>; 0] = [];

    assert_eq!(
        engine.on_drop_copy(message, MonotonicTimestampNs(1_070), &mut short_output),
        Err(EngineError::OutputCapacity {
            required: 2,
            provided: 0,
        })
    );
    assert_eq!(
        engine.drop_copy_status().unwrap().expected_sequence,
        Sequence(4)
    );
    assert_eq!(engine.last_applied_monotonic(), monotonic_before);
    assert_eq!(engine.last_applied_utc(), utc_before);

    let mut output = [None; MAX_REACTOR_COMMANDS_PER_INPUT];
    assert_eq!(
        engine.on_drop_copy(message, MonotonicTimestampNs(1_070), &mut output),
        Err(EngineError::DropCopy(DropCopyError::SessionUnavailable(
            replay
        )))
    );
    assert_eq!(
        engine.drop_copy_status().unwrap().expected_sequence,
        Sequence(5)
    );
}

#[test]
fn replay_complete_without_recovery_state_kills_and_cancels() {
    let (mut engine, orders) = reconciled_live_orders();
    let mut output = [None; MAX_REACTOR_COMMANDS_PER_INPUT];
    let replay = SessionEvent::ReplayComplete {
        through: Sequence(3),
    };
    assert_eq!(
        engine.on_drop_copy(
            inbound(4, 1_070, InboundPayload::Session(replay)),
            MonotonicTimestampNs(1_070),
            &mut output,
        ),
        Err(EngineError::DropCopy(DropCopyError::SessionUnavailable(
            replay
        )))
    );
    assert_eq!(
        engine.kill_snapshot().unwrap().code,
        KillCode::DropCopyMismatch
    );
    assert_eq!(output.iter().flatten().count(), 2);
    assert!(
        output
            .iter()
            .all(|slot| matches!(slot, Some(OrderCommand::Cancel(_))))
    );

    let report = accepted_for(orders[0], VenueOrderId(7_001));
    assert_eq!(
        engine.on_drop_copy(
            inbound(5, 1_080, InboundPayload::Order(report)),
            MonotonicTimestampNs(1_080),
            &mut output,
        ),
        Err(EngineError::DropCopy(DropCopyError::SessionNotLive))
    );
    assert_eq!(
        engine.drop_copy_status().unwrap().expected_sequence,
        Sequence(6)
    );

    let regressing = InboundMessage {
        sequence: Sequence(6),
        exchange_timestamp: TimestampNs(OFFSET + 1_077),
        hardware_receive_timestamp: TimestampNs(OFFSET + 1_080),
        payload: InboundPayload::Session(SessionEvent::LogonAccepted),
    };
    assert_eq!(
        engine.on_drop_copy(regressing, MonotonicTimestampNs(1_081), &mut output,),
        Err(EngineError::EventTimestampRegression {
            prior: TimestampNs(OFFSET + 1_078),
            received: TimestampNs(OFFSET + 1_077),
        })
    );
    assert_eq!(
        engine.drop_copy_status().unwrap().expected_sequence,
        Sequence(6)
    );

    assert_eq!(
        engine
            .on_drop_copy(
                inbound(
                    6,
                    1_082,
                    InboundPayload::Session(SessionEvent::LogonAccepted),
                ),
                MonotonicTimestampNs(1_082),
                &mut output,
            )
            .unwrap()
            .commands,
        0
    );
    assert_eq!(
        engine.drop_copy_status().unwrap().expected_sequence,
        Sequence(7)
    );
}

#[test]
fn nonreconciled_fill_restores_drop_copy_gate_for_exact_retry() {
    let base_units_per_price_tick = i128::MAX / 10_000;
    let mut overflow_config = config();
    overflow_config
        .instrument_definition
        .fixed_value
        .settlement_units_per_price_tick = base_units_per_price_tick;
    overflow_config.risk_definition.valuation = InstrumentValuation::Fixed {
        base_units_per_price_tick,
        contract_multiplier: 1,
    };
    overflow_config.risk.max_order_notional = i128::MAX;
    overflow_config.risk.max_gross_notional = i128::MAX;
    overflow_config.risk.max_net_notional = i128::MAX;
    overflow_config.risk.max_daily_loss = i128::MAX;

    let (mut engine, orders) = reconciled_live_orders_with(overflow_config);
    let (index, bid) = orders
        .iter()
        .copied()
        .enumerate()
        .find(|(_, command)| matches!(command, OrderCommand::New(order) if order.side == Side::Buy))
        .expect("prepared bid");
    let accepted = accepted_for(
        bid,
        VenueOrderId(7_001 + u64::try_from(index).expect("bounded order index")),
    );
    let report = fill_for(accepted, TradeId(900), PriceTicks(i64::MAX), Quantity(1));
    let message = inbound(4, 1_070, InboundPayload::Order(report));
    let expected = Err(EngineError::Order(OrderError::Risk(
        RiskError::ArithmeticOverflow,
    )));
    let mut output = [None; MAX_REACTOR_COMMANDS_PER_INPUT];

    assert_eq!(
        engine.on_order_entry(message, MonotonicTimestampNs(1_070), &mut output),
        expected
    );
    assert!(engine.drop_copy_status().unwrap().synchronized());
    assert_eq!(engine.expected_order_sequence(), Sequence(4));
    assert!(!engine.orders().has_recent_trade(TradeId(900)));

    assert_eq!(
        engine.on_order_entry(message, MonotonicTimestampNs(1_070), &mut output),
        expected
    );
    assert!(engine.drop_copy_status().unwrap().synchronized());
    assert_eq!(engine.expected_order_sequence(), Sequence(4));
    assert!(!engine.orders().has_recent_trade(TradeId(900)));
}

#[test]
fn direct_and_journal_dispatch_reconcile_to_exact_state_without_allocating() {
    let (mut direct, orders) = prepared_sent_orders();
    let (mut replayed, replay_orders) = prepared_sent_orders();
    assert_eq!(orders, replay_orders);
    let accepted = accepted_for(orders[0], VenueOrderId(7_001));
    let drop_copy_message = inbound(2, 1_060, InboundPayload::Order(accepted));
    let order_entry_message = inbound(2, 1_061, InboundPayload::Order(accepted));
    let drop_copy_event =
        normalize_drop_copy(metadata(DROP_COPY_SOURCE, 1, 1_060), drop_copy_message).unwrap();
    let order_entry_event =
        normalize_order_entry(metadata(ORDER_ENTRY_SOURCE, 2, 1_061), order_entry_message).unwrap();
    let mut direct_output = [None; MAX_REACTOR_COMMANDS_PER_INPUT];
    direct
        .on_drop_copy(
            drop_copy_message,
            MonotonicTimestampNs(1_060),
            &mut direct_output,
        )
        .unwrap();
    direct
        .on_order_entry(
            order_entry_message,
            MonotonicTimestampNs(1_061),
            &mut direct_output,
        )
        .unwrap();

    let mut replay_output = [None; MAX_REACTOR_COMMANDS_PER_INPUT];
    dispatch_engine_replay_event(&mut replayed, drop_copy_event, &mut replay_output).unwrap();
    dispatch_engine_replay_event(&mut replayed, order_entry_event, &mut replay_output).unwrap();
    assert!(direct.deterministic_state_eq(&replayed));

    let second = accepted_for(orders[1], VenueOrderId(7_002));
    let message = inbound(3, 1_062, InboundPayload::Order(second));
    ALLOCATIONS.with(|allocations| allocations.set(0));
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(true));
    let result = direct.on_drop_copy(message, MonotonicTimestampNs(1_062), &mut direct_output);
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(false));
    assert_eq!(result.unwrap().commands, 0);
    assert_eq!(ALLOCATIONS.with(Cell::get), 0);
}

#[test]
fn drop_copy_first_lifecycle_correction_immediately_quarantines_then_pairs_exactly() {
    let (mut engine, _) = reconciled_live_orders();
    let (mut replayed, _) = reconciled_live_orders();
    let risk_before = engine.risk().instrument(INSTRUMENT);
    let realized_before = engine.risk().lifetime_realized_pnl();
    let adverse_count_before = engine.adverse().tracked_fill_count();
    let correction = OrderEvent::LifecycleCorrectionObserved(LifecycleCorrectionObserved {
        correction_id: LifecycleCorrectionId(8_001),
        target_trade_id: TradeId(7_001),
        kind: LifecycleCorrectionKind::Correct,
        canonical_payload_digest: LifecycleCorrectionDigest([0xE5; 32]),
    });
    let mut output = [None; MAX_REACTOR_COMMANDS_PER_INPUT];
    let mut replay_output = [None; MAX_REACTOR_COMMANDS_PER_INPUT];
    let drop_copy_message = inbound(4, 1_070, InboundPayload::Order(correction));

    ALLOCATIONS.with(|allocations| allocations.set(0));
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(true));
    let result = engine.on_drop_copy(drop_copy_message, MonotonicTimestampNs(1_070), &mut output);
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(false));
    let drop_copy_batch = result.unwrap();
    assert_eq!(ALLOCATIONS.with(Cell::get), 0);
    dispatch_engine_replay_event(
        &mut replayed,
        normalize_drop_copy(metadata(DROP_COPY_SOURCE, 80, 1_070), drop_copy_message).unwrap(),
        &mut replay_output,
    )
    .unwrap();
    assert_eq!(replay_output, output);
    assert_eq!(drop_copy_batch.commands, 2);
    assert!(
        output
            .iter()
            .all(|slot| matches!(slot, Some(OrderCommand::Cancel(_))))
    );
    assert_eq!(
        engine.kill_snapshot().unwrap().code,
        KillCode::LifecycleCorrection
    );
    assert_eq!(engine.drop_copy_status().unwrap().pending_drop_copy, 1);
    assert_eq!(engine.risk().instrument(INSTRUMENT), risk_before);
    assert_eq!(engine.risk().lifetime_realized_pnl(), realized_before);
    assert_eq!(engine.adverse().tracked_fill_count(), adverse_count_before);

    let order_entry_message = inbound(4, 1_071, InboundPayload::Order(correction));
    let order_entry = engine
        .on_order_entry(
            order_entry_message,
            MonotonicTimestampNs(1_071),
            &mut output,
        )
        .unwrap();
    dispatch_engine_replay_event(
        &mut replayed,
        normalize_order_entry(metadata(ORDER_ENTRY_SOURCE, 81, 1_071), order_entry_message)
            .unwrap(),
        &mut replay_output,
    )
    .unwrap();
    assert_eq!(replay_output, output);
    assert!(matches!(
        order_entry.application,
        OrderApplication::LifecycleCorrectionQuarantined(value)
            if OrderEvent::LifecycleCorrectionObserved(value) == correction
    ));
    assert_eq!(order_entry.output.commands, 0);
    assert!(engine.drop_copy_status().unwrap().synchronized());
    assert_eq!(engine.risk().instrument(INSTRUMENT), risk_before);
    assert_eq!(engine.adverse().tracked_fill_count(), adverse_count_before);
    assert!(engine.deterministic_state_eq(&replayed));
}

#[test]
fn pending_timer_accepts_exact_boundary_then_expires_cancel_only_without_allocating() {
    let (mut engine, orders) = reconciled_live_orders();
    leave_fill_pending(&mut engine, orders[0], 1_070);
    let deadline = TimestampNs(OFFSET + 1_080);
    assert_eq!(
        engine.drop_copy_status().unwrap().pending_deadline,
        Some(deadline)
    );
    let mut output = [None; MAX_REACTOR_COMMANDS_PER_INPUT];
    assert_eq!(
        engine
            .check_drop_copy_liveness(MonotonicTimestampNs(1_080), &mut output)
            .unwrap()
            .commands,
        0
    );
    assert_eq!(output, [None; MAX_REACTOR_COMMANDS_PER_INPUT]);
    assert!(engine.kill_snapshot().is_none());

    ALLOCATIONS.with(|allocations| allocations.set(0));
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(true));
    let result = engine.check_drop_copy_liveness(MonotonicTimestampNs(1_081), &mut output);
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(false));
    assert_eq!(
        result,
        Err(EngineError::DropCopy(DropCopyError::PendingExpired {
            deadline,
            observed: TimestampNs(OFFSET + 1_081),
        }))
    );
    assert_eq!(ALLOCATIONS.with(Cell::get), 0);
    assert_eq!(
        engine.kill_snapshot().unwrap().code,
        KillCode::DropCopyMismatch
    );
    assert_eq!(output.iter().flatten().count(), 2);
    assert!(
        output
            .iter()
            .flatten()
            .all(|command| matches!(command, OrderCommand::Cancel(_)))
    );
}

#[test]
fn exact_peer_survives_but_first_later_market_event_expires_a_missed_timer() {
    let (mut exact, exact_orders) = reconciled_live_orders();
    let exact_fill = leave_fill_pending(&mut exact, exact_orders[0], 1_070);
    let mut output = [None; MAX_REACTOR_COMMANDS_PER_INPUT];
    assert_eq!(
        exact
            .on_drop_copy(
                inbound(4, 1_080, InboundPayload::Order(exact_fill)),
                MonotonicTimestampNs(1_080),
                &mut output,
            )
            .unwrap()
            .commands,
        0
    );
    assert!(exact.drop_copy_status().unwrap().synchronized());
    assert!(exact.kill_snapshot().is_none());

    let (mut missed, missed_orders) = reconciled_live_orders();
    leave_fill_pending(&mut missed, missed_orders[0], 1_070);
    assert_eq!(
        missed.on_market_data(
            market(
                4,
                1_081,
                MarketDataPayload::Trade {
                    trade_id: TradeId(9_099),
                    side: Side::Buy,
                    price: PriceTicks(101),
                    quantity: Quantity(1),
                },
            ),
            MonotonicTimestampNs(1_081),
            &mut output,
        ),
        Err(EngineError::DropCopy(DropCopyError::PendingExpired {
            deadline: TimestampNs(OFFSET + 1_080),
            observed: TimestampNs(OFFSET + 1_081),
        }))
    );
    assert_eq!(missed.expected_market_sequence(), Sequence(4));
    assert_eq!(
        missed.kill_snapshot().unwrap().code,
        KillCode::DropCopyMismatch
    );
    assert_eq!(output.iter().flatten().count(), 2);
    assert!(
        output
            .iter()
            .flatten()
            .all(|command| matches!(command, OrderCommand::Cancel(_)))
    );
}

#[test]
fn drop_copy_liveness_timer_codec_and_replay_match_direct_failure_state() {
    let (mut direct, direct_orders) = reconciled_live_orders();
    let (mut replayed, replay_orders) = reconciled_live_orders();
    leave_fill_pending(&mut direct, direct_orders[0], 1_070);
    leave_fill_pending(&mut replayed, replay_orders[0], 1_070);
    let timer = TimerInput {
        timer_id: TimerId(91),
        action: TimerAction::DropCopyLivenessCheck,
        scheduled_at: MonotonicTimestampNs(1_080),
        fired_at: MonotonicTimestampNs(1_081),
    };
    let event = normalize_timer(CaptureOrdinal(91), timer).unwrap();
    assert_eq!(event.auxiliary, 3);
    assert_eq!(decode_timer(event), Ok(timer));
    let expected = EngineError::DropCopy(DropCopyError::PendingExpired {
        deadline: TimestampNs(OFFSET + 1_080),
        observed: TimestampNs(OFFSET + 1_081),
    });
    let mut direct_output = [None; MAX_REACTOR_COMMANDS_PER_INPUT];
    let mut replay_output = [None; MAX_REACTOR_COMMANDS_PER_INPUT];
    assert_eq!(
        direct.check_drop_copy_liveness(timer.fired_at, &mut direct_output),
        Err(expected)
    );
    assert_eq!(
        dispatch_engine_replay_event(&mut replayed, event, &mut replay_output),
        Err(EngineReplayError::Engine(expected))
    );
    assert_eq!(direct_output, replay_output);
    assert!(direct.deterministic_state_eq(&replayed));
}

#[test]
fn reactor_drop_copy_timer_publishes_cancel_first_failure_without_allocating() {
    let (mut engine, orders) = reconciled_live_orders();
    leave_fill_pending(&mut engine, orders[0], 1_070);
    let mut reactor = HotPathReactor::new(engine);
    let mut event_ring = SpscRing::<ReactorInput, 4>::new();
    let mut transmission_ring = SpscRing::<TransmissionInput, 4>::new();
    let (mut event_producer, mut event_consumer) = event_ring.split();
    let (_transmission_producer, mut transmission_consumer) = transmission_ring.split();
    let timer = TimerInput {
        timer_id: TimerId(92),
        action: TimerAction::DropCopyLivenessCheck,
        scheduled_at: MonotonicTimestampNs(1_080),
        fired_at: MonotonicTimestampNs(1_081),
    };
    event_producer.try_push(ReactorInput::Timer(timer)).unwrap();
    let mut egress = [None; MAX_REACTOR_COMMANDS_PER_INPUT];

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
    let failure = result.expect_err("expired pending reconciliation must fail closed");
    assert_eq!(ALLOCATIONS.with(Cell::get), 0);
    assert_eq!(
        failure.error,
        ReactorError::Engine {
            input: ReactorInputKind::Timer,
            source: EngineError::DropCopy(DropCopyError::PendingExpired {
                deadline: TimestampNs(OFFSET + 1_080),
                observed: TimestampNs(OFFSET + 1_081),
            }),
        }
    );
    assert_eq!(failure.report.commands_published, 2);
    assert_eq!(
        reactor.engine().kill_snapshot().unwrap().code,
        KillCode::DropCopyMismatch
    );
    assert!(
        egress
            .iter()
            .flatten()
            .all(|item| matches!(item.command, OrderCommand::Cancel(_)))
    );
}

fn leave_fill_pending(engine: &mut Engine, command: OrderCommand, monotonic: u64) -> OrderEvent {
    let accepted = accepted_for(command, VenueOrderId(7_001));
    let price = match accepted {
        OrderEvent::Accepted(value) => value.price,
        _ => unreachable!(),
    };
    let fill = fill_for(accepted, TradeId(9_001), price, Quantity(1));
    let mut output = [None; MAX_REACTOR_COMMANDS_PER_INPUT];
    engine
        .on_order_entry(
            inbound(4, monotonic, InboundPayload::Order(fill)),
            MonotonicTimestampNs(monotonic),
            &mut output,
        )
        .unwrap();
    assert_eq!(output, [None; MAX_REACTOR_COMMANDS_PER_INPUT]);
    fill
}

fn config() -> EngineConfig {
    EngineConfig {
        venue: VENUE,
        instrument: INSTRUMENT,
        first_market_sequence: Sequence(1),
        first_order_sequence: Sequence(1),
        first_client_order_id: ClientOrderId(1_000),
        first_risk_order_id: OrderId(5_000),
        instrument_definition: support::instrument_definition(VENUE, INSTRUMENT),
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

fn prepared_sent_orders() -> (Engine, [OrderCommand; 2]) {
    prepared_sent_orders_with(config())
}

fn prepared_sent_orders_with(engine_config: EngineConfig) -> (Engine, [OrderCommand; 2]) {
    let mut engine = Engine::new_with_drop_copy(
        engine_config,
        DropCopyConfig {
            first_sequence: Sequence(1),
            pending_timeout_ns: 10,
        },
    )
    .unwrap();
    engine
        .observe_clock(quant_hft_core::ClockSample {
            utc: TimestampNs(OFFSET + 1_000),
            monotonic: MonotonicTimestampNs(1_000),
            uncertainty_ns: 10,
        })
        .unwrap();
    let mut output = [None; MAX_REACTOR_COMMANDS_PER_INPUT];
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
        .on_order_entry(
            inbound(
                1,
                1_030,
                InboundPayload::Session(SessionEvent::LogonAccepted),
            ),
            MonotonicTimestampNs(1_030),
            &mut output,
        )
        .unwrap();
    engine
        .on_drop_copy(
            inbound(
                1,
                1_031,
                InboundPayload::Session(SessionEvent::LogonAccepted),
            ),
            MonotonicTimestampNs(1_031),
            &mut output,
        )
        .unwrap();
    engine
        .apply_control_decision(
            support::authenticated_arm(
                1,
                ConfigDigest([3; 32]),
                Sequence(1),
                TimestampNs(OFFSET + 1_040),
                TimestampNs(OFFSET + 50_000),
            ),
            &mut output,
        )
        .unwrap();
    for message in [
        market(
            1,
            1_050,
            MarketDataPayload::TradingStatus { status_code: 1 },
        ),
        market(
            2,
            1_051,
            MarketDataPayload::Book(BookDelta::Add {
                order_id: MarketByOrderId(11),
                side: Side::Buy,
                price: PriceTicks(100),
                quantity: Quantity(100),
            }),
        ),
        market(
            3,
            1_052,
            MarketDataPayload::Book(BookDelta::Add {
                order_id: MarketByOrderId(12),
                side: Side::Sell,
                price: PriceTicks(102),
                quantity: Quantity(100),
            }),
        ),
    ] {
        engine
            .on_market_data(
                message,
                MonotonicTimestampNs(message.hardware_receive_timestamp.0 - OFFSET),
                &mut output,
            )
            .unwrap();
    }
    let orders = [output[0].unwrap(), output[1].unwrap()];
    for (index, command) in orders.into_iter().enumerate() {
        engine
            .on_transmission(
                command,
                TransmissionStatus::Sent,
                MonotonicTimestampNs(1_053 + u64::try_from(index).unwrap()),
            )
            .unwrap();
    }
    (engine, orders)
}

fn reconciled_live_orders() -> (Engine, [OrderCommand; 2]) {
    reconciled_live_orders_with(config())
}

fn reconciled_live_orders_with(engine_config: EngineConfig) -> (Engine, [OrderCommand; 2]) {
    let (mut engine, orders) = prepared_sent_orders_with(engine_config);
    let mut output = [None; MAX_REACTOR_COMMANDS_PER_INPUT];
    for (index, command) in orders.into_iter().enumerate() {
        let sequence = 2 + u64::try_from(index).unwrap();
        let monotonic = 1_060 + (u64::try_from(index).unwrap() * 2);
        let report = accepted_for(command, VenueOrderId(7_001 + u64::try_from(index).unwrap()));
        engine
            .on_drop_copy(
                inbound(sequence, monotonic, InboundPayload::Order(report)),
                MonotonicTimestampNs(monotonic),
                &mut output,
            )
            .unwrap();
        engine
            .on_order_entry(
                inbound(sequence, monotonic + 1, InboundPayload::Order(report)),
                MonotonicTimestampNs(monotonic + 1),
                &mut output,
            )
            .unwrap();
        assert_eq!(output, [None; MAX_REACTOR_COMMANDS_PER_INPUT]);
    }
    assert!(engine.drop_copy_status().unwrap().synchronized());
    assert!(engine.trading_eligible());
    (engine, orders)
}

fn accepted_for(command: OrderCommand, venue_order_id: VenueOrderId) -> OrderEvent {
    let OrderCommand::New(order) = command else {
        panic!("prepared quote must be new")
    };
    OrderEvent::Accepted(Accepted {
        client_order_id: order.client_order_id,
        venue_order_id,
        price: order.price,
        quantity: order.quantity,
    })
}

fn fill_for(
    accepted: OrderEvent,
    trade_id: TradeId,
    price: PriceTicks,
    quantity: Quantity,
) -> OrderEvent {
    let OrderEvent::Accepted(accepted) = accepted else {
        unreachable!()
    };
    OrderEvent::Fill(Fill {
        client_order_id: accepted.client_order_id,
        venue_order_id: accepted.venue_order_id,
        trade_id,
        price,
        quantity,
        leaves_quantity: Quantity(accepted.quantity.0 - quantity.0),
        liquidity: LiquidityFlag::Removed,
    })
}

fn metadata(source: EventSource, capture_ordinal: u64, monotonic: u64) -> VenueCaptureMetadata {
    VenueCaptureMetadata {
        venue: VENUE,
        source,
        capture_ordinal: CaptureOrdinal(capture_ordinal),
        monotonic_timestamp: MonotonicTimestampNs(monotonic),
        recovery: false,
    }
}

fn inbound(sequence: u64, monotonic: u64, payload: InboundPayload) -> InboundMessage {
    InboundMessage {
        sequence: Sequence(sequence),
        exchange_timestamp: TimestampNs(OFFSET + monotonic - 2),
        hardware_receive_timestamp: TimestampNs(OFFSET + monotonic - 1),
        payload,
    }
}

fn market(sequence: u64, monotonic: u64, payload: MarketDataPayload) -> MarketDataMessage {
    MarketDataMessage {
        instrument: INSTRUMENT,
        sequence: Sequence(sequence),
        exchange_timestamp: TimestampNs(OFFSET + monotonic - 2),
        hardware_receive_timestamp: TimestampNs(OFFSET + monotonic - 1),
        payload,
    }
}

fn snapshot(monotonic: u64, payload: SnapshotPayload) -> SnapshotMessage {
    SnapshotMessage {
        exchange_timestamp: TimestampNs(OFFSET + monotonic - 2),
        hardware_receive_timestamp: TimestampNs(OFFSET + monotonic - 1),
        payload,
    }
}
