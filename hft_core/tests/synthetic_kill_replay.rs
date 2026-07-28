mod support;

use quant_hft_core::adverse::AdverseConfig;
use quant_hft_core::clock::ClockSample;
use quant_hft_core::control::ConfigDigest;
use quant_hft_core::engine::{EngineConfig, ExecutionEngine, TransmissionStatus};
use quant_hft_core::engine_replay::EngineReplayRoute;
use quant_hft_core::event_codec::{
    VenueCaptureMetadata, normalize_market_data, normalize_transmission,
};
use quant_hft_core::events::{CaptureOrdinal, EventSource, SequenceDomain, SessionEpoch, SourceId};
use quant_hft_core::reactor::{HotPathReactor, InputOrdinal, TransmissionInput};
use quant_hft_core::reactor_audit::{
    SCHEDULER_COMMIT_RECORD_LEN, SchedulerCommit, SchedulerCommitVerifier, SchedulerReplayError,
    SchedulerRoute, decode_scheduler_commit, encode_scheduler_commit,
};
use quant_hft_core::reactor_replay::{
    dispatch_reactor_replay_event, dispatch_reactor_replay_retention,
    dispatch_reactor_replay_safety_kill,
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
    Accepted, BookDelta, ClientOrderId, InboundMessage, InboundPayload, MarketByOrderId,
    MarketDataMessage, MarketDataPayload, OrderCommand, OrderEvent, SessionEvent, SnapshotMessage,
    SnapshotPayload, VenueOrderId,
};

type Engine = ExecutionEngine<64, 16, 8, 16, 16>;
type Reactor = HotPathReactor<64, 16, 8, 16, 16>;

const VENUE: VenueId = VenueId(1);
const INSTRUMENT: InstrumentId = InstrumentId(7);
const OFFSET: u64 = 1_000_000_000;

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

fn market(sequence: u64, monotonic: u64, payload: MarketDataPayload) -> MarketDataMessage {
    MarketDataMessage {
        instrument: INSTRUMENT,
        sequence: Sequence(sequence),
        exchange_timestamp: TimestampNs(OFFSET + monotonic - 10),
        hardware_receive_timestamp: TimestampNs(OFFSET + monotonic),
        payload,
    }
}

fn inbound(sequence: u64, monotonic: u64, payload: InboundPayload) -> InboundMessage {
    InboundMessage {
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

fn ready_engine() -> Engine {
    let mut engine = Engine::new(config()).expect("engine configuration");
    engine
        .observe_clock(ClockSample {
            utc: TimestampNs(OFFSET + 1_000),
            monotonic: MonotonicTimestampNs(1_000),
            uncertainty_ns: 10,
        })
        .expect("initial clock");

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
            inbound(
                1,
                1_030,
                InboundPayload::Session(SessionEvent::LogonAccepted),
            ),
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
                TimestampNs(OFFSET + 1_040),
                TimestampNs(u64::MAX),
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

fn live_engine() -> Engine {
    let mut engine = ready_engine();
    let mut output = [None; 2];
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
        engine
            .on_market_data(
                market(sequence, monotonic, payload),
                MonotonicTimestampNs(monotonic),
                &mut output,
            )
            .expect("seed book");
    }

    let new_commands = [output[0].expect("bid new"), output[1].expect("ask new")];
    for (index, command) in new_commands.into_iter().enumerate() {
        let offset = u64::try_from(index).expect("bounded command index");
        engine
            .on_transmission(
                command,
                TransmissionStatus::Sent,
                MonotonicTimestampNs(1_300 + offset),
            )
            .expect("new sent");
        let OrderCommand::New(new) = command else {
            panic!("expected new command");
        };
        output.fill(None);
        engine
            .on_order_entry(
                inbound(
                    2 + offset,
                    1_400 + offset,
                    InboundPayload::Order(OrderEvent::Accepted(Accepted {
                        client_order_id: new.client_order_id,
                        venue_order_id: VenueOrderId(7_000 + offset),
                        price: new.price,
                        quantity: new.quantity,
                    })),
                ),
                MonotonicTimestampNs(1_400 + offset),
                &mut output,
            )
            .expect("new accepted");
    }
    engine
}

fn market_source_metadata(ordinal: u64, monotonic: u64) -> VenueCaptureMetadata {
    VenueCaptureMetadata {
        venue: VENUE,
        source: EventSource::new(
            SourceId::new(11, 1),
            SequenceDomain::MarketData,
            SessionEpoch(1),
        ),
        capture_ordinal: CaptureOrdinal(ordinal),
        monotonic_timestamp: MonotonicTimestampNs(monotonic),
        recovery: false,
    }
}

fn round_trip(commit: SchedulerCommit) -> SchedulerCommit {
    let mut encoded = [0_u8; SCHEDULER_COMMIT_RECORD_LEN];
    assert_eq!(
        encode_scheduler_commit(commit, &mut encoded),
        Ok(SCHEDULER_COMMIT_RECORD_LEN)
    );
    let (decoded, consumed) = decode_scheduler_commit(&encoded).expect("scheduler commit decode");
    assert_eq!(consumed, SCHEDULER_COMMIT_RECORD_LEN);
    assert_eq!(decoded, commit);
    decoded
}

#[test]
fn retained_input_synthetic_kill_and_feedback_replay_exactly_through_actual_reactor() {
    let close = market(
        4,
        1_500,
        MarketDataPayload::TradingStatus { status_code: 0 },
    );
    let close_event = normalize_market_data(market_source_metadata(1, 1_500), close)
        .expect("normalize close event");

    let mut recorded = Reactor::new(live_engine());
    let retained_outcome = dispatch_reactor_replay_retention(&mut recorded, close_event)
        .expect("retain undersized-egress input");
    assert_eq!(retained_outcome.route, EngineReplayRoute::RetainedNormal);
    assert!(recorded.has_retained_event());
    assert!(recorded.mandatory_kill_pending());
    let retained_commit = round_trip(
        SchedulerCommit::from_replay_outcome(1, close_event, retained_outcome, &[None; 2])
            .expect("retained scheduler commit"),
    );

    let mut emergency_egress = [None; 2];
    let safety_outcome = dispatch_reactor_replay_safety_kill(&mut recorded, &mut emergency_egress)
        .expect("apply synthetic safety kill");
    assert_eq!(safety_outcome.route, EngineReplayRoute::SafetyKill);
    assert_eq!(safety_outcome.commands, 2);
    assert!(recorded.has_retained_event());
    assert!(!recorded.mandatory_kill_pending());
    for (index, item) in emergency_egress.iter().flatten().enumerate() {
        assert_eq!(item.input_ordinal, InputOrdinal(0));
        assert_eq!(usize::from(item.command_index), index);
        assert!(matches!(item.command, OrderCommand::Cancel(_)));
    }
    let safety_commit = round_trip(
        SchedulerCommit::from_safety_outcome(2, safety_outcome, &emergency_egress)
            .expect("source-less safety scheduler commit"),
    );

    let cancel_commands = emergency_egress.map(|slot| slot.expect("cancel egress").command);
    let feedback_events = [
        normalize_transmission(
            CaptureOrdinal(2),
            TransmissionInput {
                command: cancel_commands[0],
                status: TransmissionStatus::Sent,
                monotonic_now: MonotonicTimestampNs(1_501),
            },
        )
        .expect("first cancel feedback"),
        normalize_transmission(
            CaptureOrdinal(3),
            TransmissionInput {
                command: cancel_commands[1],
                status: TransmissionStatus::Sent,
                monotonic_now: MonotonicTimestampNs(1_502),
            },
        )
        .expect("second cancel feedback"),
    ];

    let mut feedback_commits = [None; 2];
    for (index, event) in feedback_events.into_iter().enumerate() {
        let mut egress = [None; 2];
        let outcome = dispatch_reactor_replay_event(&mut recorded, event, &mut egress)
            .expect("record exact cancel feedback");
        assert_eq!(outcome.route, EngineReplayRoute::PriorityTransmission);
        assert_eq!(outcome.commands, 0);
        feedback_commits[index] = Some(round_trip(
            SchedulerCommit::from_replay_outcome(
                3 + u64::try_from(index).expect("bounded commit index"),
                event,
                outcome,
                &egress,
            )
            .expect("feedback scheduler commit"),
        ));
    }
    assert_eq!(recorded.outstanding_transmissions(), 0);
    assert!(recorded.has_retained_event());

    let mut final_egress = [None; 2];
    let final_outcome =
        dispatch_reactor_replay_event(&mut recorded, close_event, &mut final_egress)
            .expect("process retained close event exactly once");
    assert_eq!(final_outcome.route, EngineReplayRoute::Normal);
    assert_eq!(final_outcome.commands, 0);
    assert!(!recorded.has_retained_event());
    let final_commit = round_trip(
        SchedulerCommit::from_replay_outcome(5, close_event, final_outcome, &final_egress)
            .expect("retained application scheduler commit"),
    );

    let mut replayed = Reactor::new(live_engine());
    let mut verifier = SchedulerCommitVerifier::new(1).expect("commit verifier");
    verifier
        .verify_and_dispatch(&mut replayed, close_event, retained_commit, &mut [None; 2])
        .expect("verify retained-input preflight");
    let mut replay_safety_egress = [None; 2];
    verifier
        .verify_and_dispatch_safety(&mut replayed, safety_commit, &mut replay_safety_egress)
        .expect("verify source-less safety run");
    assert_eq!(replay_safety_egress, emergency_egress);

    for (index, event) in feedback_events.into_iter().enumerate() {
        verifier
            .verify_and_dispatch(
                &mut replayed,
                event,
                feedback_commits[index].expect("feedback commit"),
                &mut [None; 2],
            )
            .expect("verify exact cancel feedback");
    }
    verifier
        .verify_and_dispatch(&mut replayed, close_event, final_commit, &mut [None; 2])
        .expect("verify retained input application");

    assert_eq!(verifier.next_commit_ordinal(), 6);
    assert!(!verifier.is_failed());
    assert_eq!(replayed.outstanding_transmissions(), 0);
    assert!(!replayed.has_retained_event());
    assert!(recorded.deterministic_state_eq(&replayed));

    final_commit
        .verify_source(close_event)
        .expect("final commit binds the original retained source");
    let substituted_close_event = normalize_market_data(market_source_metadata(99, 1_500), close)
        .expect("normalize substituted close event");
    let substituted_final_commit = round_trip(
        SchedulerCommit::from_replay_outcome(
            5,
            substituted_close_event,
            final_outcome,
            &final_egress,
        )
        .expect("internally consistent substituted-source commit"),
    );
    substituted_final_commit
        .verify_source(substituted_close_event)
        .expect("substituted commit binds its substituted source");
    let mut rejected = Reactor::new(live_engine());
    let mut rejected_verifier = SchedulerCommitVerifier::new(1).expect("commit verifier");
    rejected_verifier
        .verify_and_dispatch(&mut rejected, close_event, retained_commit, &mut [None; 2])
        .expect("verify retained-input preflight");
    rejected_verifier
        .verify_and_dispatch_safety(&mut rejected, safety_commit, &mut [None; 2])
        .expect("verify source-less safety run");
    for (index, event) in feedback_events.into_iter().enumerate() {
        rejected_verifier
            .verify_and_dispatch(
                &mut rejected,
                event,
                feedback_commits[index].expect("feedback commit"),
                &mut [None; 2],
            )
            .expect("verify exact cancel feedback");
    }
    assert_eq!(
        rejected_verifier.verify_and_dispatch(
            &mut rejected,
            substituted_close_event,
            substituted_final_commit,
            &mut [None; 2],
        ),
        Err(SchedulerReplayError::RetainedSourceMismatch)
    );
    assert!(rejected_verifier.is_failed());
}

#[test]
fn infrastructure_trip_is_idempotent_and_replays_exact_cancel_fifo() {
    let mut recorded = Reactor::new(live_engine());
    let requests_before = recorded.counters().mandatory_kill_requests;
    assert!(recorded.trip_internal_safety());
    assert!(!recorded.trip_internal_safety());
    assert_eq!(
        recorded.counters().mandatory_kill_requests,
        requests_before + 1
    );
    assert!(recorded.mandatory_kill_pending());
    assert!(!recorded.has_retained_event());

    let mut emergency_egress = [None; 2];
    let safety_outcome = dispatch_reactor_replay_safety_kill(&mut recorded, &mut emergency_egress)
        .expect("apply infrastructure safety kill");
    assert_eq!(safety_outcome.route, EngineReplayRoute::SafetyKill);
    assert_eq!(safety_outcome.commands, 2);
    let safety_report = safety_outcome.report.expect("safety report");
    assert!(!safety_report.event_retained);
    assert!(!safety_report.mandatory_kill_pending);

    let safety_commit = round_trip(
        SchedulerCommit::from_safety_outcome(1, safety_outcome, &emergency_egress)
            .expect("infrastructure safety scheduler commit"),
    );
    assert_eq!(safety_commit.route, SchedulerRoute::SafetyKill);
    assert_eq!(safety_commit.capture_ordinal, CaptureOrdinal(0));
    assert_eq!(safety_commit.source_event_crc32c, 0);
    assert!(!safety_commit.event_retained);

    let cancel_commands = emergency_egress.map(|slot| slot.expect("cancel egress").command);
    for (index, slot) in emergency_egress.iter().enumerate() {
        let item = slot.expect("populated cancel slot");
        assert_eq!(item.input_ordinal, InputOrdinal(0));
        assert_eq!(usize::from(item.command_index), index);
        assert_eq!(item.command, cancel_commands[index]);
        assert!(matches!(item.command, OrderCommand::Cancel(_)));
    }

    let feedback_events = [
        normalize_transmission(
            CaptureOrdinal(1),
            TransmissionInput {
                command: cancel_commands[0],
                status: TransmissionStatus::Sent,
                monotonic_now: MonotonicTimestampNs(1_501),
            },
        )
        .expect("first infrastructure cancel feedback"),
        normalize_transmission(
            CaptureOrdinal(2),
            TransmissionInput {
                command: cancel_commands[1],
                status: TransmissionStatus::Sent,
                monotonic_now: MonotonicTimestampNs(1_502),
            },
        )
        .expect("second infrastructure cancel feedback"),
    ];
    let mut feedback_commits = [None; 2];
    for (index, event) in feedback_events.into_iter().enumerate() {
        let mut egress = [None; 2];
        let outcome = dispatch_reactor_replay_event(&mut recorded, event, &mut egress)
            .expect("record infrastructure cancel feedback");
        assert_eq!(outcome.route, EngineReplayRoute::PriorityTransmission);
        feedback_commits[index] = Some(round_trip(
            SchedulerCommit::from_replay_outcome(
                2 + u64::try_from(index).expect("bounded feedback index"),
                event,
                outcome,
                &egress,
            )
            .expect("feedback scheduler commit"),
        ));
    }
    assert_eq!(recorded.outstanding_transmissions(), 0);
    assert!(!recorded.has_retained_event());

    let mut replayed = Reactor::new(live_engine());
    let mut verifier = SchedulerCommitVerifier::new(1).expect("commit verifier");
    let mut replay_egress = [None; 2];
    verifier
        .verify_and_dispatch_safety(&mut replayed, safety_commit, &mut replay_egress)
        .expect("replay infrastructure trip");
    assert_eq!(replay_egress, emergency_egress);
    for (index, event) in feedback_events.into_iter().enumerate() {
        verifier
            .verify_and_dispatch(
                &mut replayed,
                event,
                feedback_commits[index].expect("feedback commit"),
                &mut [None; 2],
            )
            .expect("replay infrastructure cancel feedback");
    }

    assert_eq!(verifier.next_commit_ordinal(), 4);
    assert!(!verifier.is_failed());
    assert_eq!(
        replayed.counters().mandatory_kill_requests,
        requests_before + 1
    );
    assert!(recorded.deterministic_state_eq(&replayed));
}

#[test]
fn safety_replay_rejects_both_retained_binding_mismatches_and_fail_latches() {
    let close = market(
        4,
        1_500,
        MarketDataPayload::TradingStatus { status_code: 0 },
    );
    let close_event = normalize_market_data(market_source_metadata(1, 1_500), close)
        .expect("normalize close event");
    let mut retained_recording = Reactor::new(live_engine());
    let retained_outcome = dispatch_reactor_replay_retention(&mut retained_recording, close_event)
        .expect("record retained source");
    let retained_commit =
        SchedulerCommit::from_replay_outcome(1, close_event, retained_outcome, &[None; 2])
            .expect("retained commit");

    let mut infrastructure_recording = Reactor::new(live_engine());
    assert!(infrastructure_recording.trip_internal_safety());
    let mut infrastructure_egress = [None; 2];
    let infrastructure_outcome = dispatch_reactor_replay_safety_kill(
        &mut infrastructure_recording,
        &mut infrastructure_egress,
    )
    .expect("record infrastructure safety run");
    let infrastructure_commit =
        SchedulerCommit::from_safety_outcome(2, infrastructure_outcome, &infrastructure_egress)
            .expect("infrastructure commit");
    assert!(!infrastructure_commit.event_retained);

    let mut replay_with_binding = Reactor::new(live_engine());
    let mut verifier_with_binding = SchedulerCommitVerifier::new(1).expect("commit verifier");
    verifier_with_binding
        .verify_and_dispatch(
            &mut replay_with_binding,
            close_event,
            retained_commit,
            &mut [None; 2],
        )
        .expect("establish retained binding");
    assert_eq!(
        verifier_with_binding.verify_and_dispatch_safety(
            &mut replay_with_binding,
            infrastructure_commit,
            &mut [None; 2],
        ),
        Err(SchedulerReplayError::RetainedBindingUnexpected)
    );
    assert!(verifier_with_binding.is_failed());
    assert_eq!(
        verifier_with_binding.verify_and_dispatch_safety(
            &mut replay_with_binding,
            infrastructure_commit,
            &mut [None; 2],
        ),
        Err(SchedulerReplayError::ReplayFailed)
    );

    let mut retained_without_binding = infrastructure_commit;
    retained_without_binding.commit_ordinal = 1;
    retained_without_binding.event_retained = true;
    let retained_without_binding = round_trip(retained_without_binding);
    let mut fresh_reactor = Reactor::new(live_engine());
    let mut verifier_without_binding = SchedulerCommitVerifier::new(1).expect("commit verifier");
    assert_eq!(
        verifier_without_binding.verify_and_dispatch_safety(
            &mut fresh_reactor,
            retained_without_binding,
            &mut [None; 2],
        ),
        Err(SchedulerReplayError::RetainedBindingMissing)
    );
    assert!(verifier_without_binding.is_failed());
    assert_eq!(
        verifier_without_binding.verify_and_dispatch_safety(
            &mut fresh_reactor,
            retained_without_binding,
            &mut [None; 2],
        ),
        Err(SchedulerReplayError::ReplayFailed)
    );
}
