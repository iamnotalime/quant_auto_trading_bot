mod support;

use quant_hft_core::adverse::AdverseConfig;
use quant_hft_core::clock::ClockSample;
use quant_hft_core::control::ConfigDigest;
use quant_hft_core::engine::{EngineConfig, EngineError, ExecutionEngine, TransmissionStatus};
use quant_hft_core::engine_replay::dispatch_engine_replay_event;
use quant_hft_core::event_codec::{
    SnapshotCaptureMetadata, VenueCaptureMetadata, decode_control_decision, normalize_clock,
    normalize_control_decision, normalize_market_data, normalize_order_entry,
    normalize_owned_mbo_binding, normalize_snapshot, normalize_timer, normalize_transmission,
};
use quant_hft_core::events::{CaptureOrdinal, EventSource, SequenceDomain, SessionEpoch, SourceId};
use quant_hft_core::journal::{RECORD_LEN, decode_record, encode_record, replay_bytes};
use quant_hft_core::kill::KillCode;
use quant_hft_core::reactor::{
    HotPathReactor, OwnedMboBindingInput, ReactorError, TimerAction, TimerId, TimerInput,
    TransmissionInput,
};
use quant_hft_core::reactor_audit::{
    SCHEDULER_COMMIT_RECORD_LEN, SchedulerCommit, SchedulerCommitError, SchedulerCommitVerifier,
    SchedulerReplayError, decode_scheduler_commit, encode_scheduler_commit,
};
use quant_hft_core::reactor_replay::{ReactorReplayError, dispatch_reactor_replay_event};
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
    MarketDataMessage, MarketDataPayload, NewOrder, OrderCommand, OrderEvent, OwnedMboBinding,
    OwnedMboBindingMethod, SessionEvent, SnapshotMessage, SnapshotOrder, SnapshotPayload,
    VenueOrderId,
};

type Engine = ExecutionEngine<64, 16, 8, 16, 16>;
type Reactor = HotPathReactor<64, 16, 8, 16, 16>;

const VENUE: VenueId = VenueId(1);
const INSTRUMENT: InstrumentId = InstrumentId(7);
const OFFSET: u64 = 1_000_000_000;
const BID_BOOK_ORDER: MarketByOrderId = MarketByOrderId(11);
const ASK_BOOK_ORDER: MarketByOrderId = MarketByOrderId(12);

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

fn source(domain: SequenceDomain) -> EventSource {
    EventSource::new(
        SourceId::new(
            if domain == SequenceDomain::MarketData {
                11
            } else {
                12
            },
            1,
        ),
        domain,
        SessionEpoch(1),
    )
}

fn venue_metadata(domain: SequenceDomain, ordinal: u64, monotonic: u64) -> VenueCaptureMetadata {
    VenueCaptureMetadata {
        venue: VENUE,
        source: source(domain),
        capture_ordinal: CaptureOrdinal(ordinal),
        monotonic_timestamp: MonotonicTimestampNs(monotonic),
        recovery: false,
    }
}

fn snapshot(monotonic: u64, payload: SnapshotPayload) -> SnapshotMessage {
    SnapshotMessage {
        exchange_timestamp: TimestampNs(OFFSET + monotonic - 10),
        hardware_receive_timestamp: TimestampNs(OFFSET + monotonic),
        payload,
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

fn append_record(
    journal: &mut Vec<u8>,
    expected_outputs: &mut Vec<[Option<OrderCommand>; 2]>,
    event: quant_hft_core::events::NormalizedEvent,
    output: [Option<OrderCommand>; 2],
) {
    let mut record = [0_u8; RECORD_LEN];
    assert_eq!(encode_record(event, &mut record), Ok(RECORD_LEN));
    journal.extend_from_slice(&record);
    expected_outputs.push(output);
}

fn split_new_orders(commands: [Option<OrderCommand>; 2]) -> (NewOrder, NewOrder) {
    let mut bid = None;
    let mut ask = None;
    for command in commands.into_iter().flatten() {
        match command {
            OrderCommand::New(order) if order.side == Side::Buy => bid = Some(order),
            OrderCommand::New(order) if order.side == Side::Sell => ask = Some(order),
            _ => panic!("expected two new-order decisions"),
        }
    }
    (bid.unwrap(), ask.unwrap())
}

#[test]
fn decoded_journal_control_decision_cannot_arm_a_live_engine_api() {
    let authenticated = support::authenticated_arm(
        1,
        ConfigDigest([0xA5; 32]),
        Sequence(1),
        TimestampNs(OFFSET + 1_010),
        TimestampNs(OFFSET + 1_110),
    );
    let event = normalize_control_decision(CaptureOrdinal(1), authenticated).unwrap();
    let mut record = [0_u8; RECORD_LEN];
    encode_record(event, &mut record).unwrap();
    let (decoded, _) = decode_record(&record).unwrap();
    let replay_decision = decode_control_decision(decoded).unwrap();
    let mut engine = Engine::new(config()).unwrap();
    let mut output = [None; 2];

    assert_eq!(
        engine.apply_control_decision(replay_decision, &mut output),
        Err(EngineError::ControlProvenance)
    );
    assert!(!engine.control_armed());
    assert_eq!(
        engine.kill_snapshot().unwrap().code,
        KillCode::InternalInvariant
    );
    assert!(output.iter().all(Option::is_none));
}

#[test]
fn journal_replay_matches_live_engine_commands_and_complete_state() {
    let mut live = Engine::new(config()).unwrap();
    let mut journal = Vec::new();
    let mut expected_outputs = Vec::new();
    let mut output = [None; 2];

    let clock = ClockSample {
        utc: TimestampNs(OFFSET + 1_000),
        monotonic: MonotonicTimestampNs(1_000),
        uncertainty_ns: 10,
    };
    live.observe_clock(clock).unwrap();
    append_record(
        &mut journal,
        &mut expected_outputs,
        normalize_clock(CaptureOrdinal(1), clock).unwrap(),
        output,
    );

    for (ordinal, monotonic, payload) in [
        (
            2,
            1_010,
            SnapshotPayload::Begin {
                snapshot_id: 1,
                last_incremental_sequence: Sequence(0),
            },
        ),
        (
            3,
            1_020,
            SnapshotPayload::Order(SnapshotOrder {
                instrument: INSTRUMENT,
                order_id: BID_BOOK_ORDER,
                side: Side::Buy,
                price: PriceTicks(99),
                quantity: Quantity(100),
            }),
        ),
        (
            4,
            1_030,
            SnapshotPayload::Order(SnapshotOrder {
                instrument: INSTRUMENT,
                order_id: ASK_BOOK_ORDER,
                side: Side::Sell,
                price: PriceTicks(101),
                quantity: Quantity(100),
            }),
        ),
        (
            5,
            1_040,
            SnapshotPayload::End {
                snapshot_id: 1,
                last_incremental_sequence: Sequence(0),
            },
        ),
    ] {
        output.fill(None);
        let message = snapshot(monotonic, payload);
        live.on_snapshot(message, MonotonicTimestampNs(monotonic), &mut output)
            .unwrap();
        append_record(
            &mut journal,
            &mut expected_outputs,
            normalize_snapshot(
                SnapshotCaptureMetadata {
                    venue: venue_metadata(SequenceDomain::MarketData, ordinal, monotonic),
                    snapshot_id: 1,
                    last_incremental_sequence: Sequence(0),
                },
                message,
            )
            .unwrap(),
            output,
        );
    }

    output.fill(None);
    let logon = inbound(
        1,
        1_050,
        InboundPayload::Session(SessionEvent::LogonAccepted),
    );
    live.on_order_entry(logon, MonotonicTimestampNs(1_050), &mut output)
        .unwrap();
    append_record(
        &mut journal,
        &mut expected_outputs,
        normalize_order_entry(venue_metadata(SequenceDomain::OrderEntry, 6, 1_050), logon).unwrap(),
        output,
    );

    output.fill(None);
    let accepted_at = TimestampNs(OFFSET + 1_060);
    let arm = support::authenticated_arm(
        1,
        ConfigDigest([0xA5; 32]),
        Sequence(1),
        accepted_at,
        TimestampNs(OFFSET + 1_150),
    );
    live.apply_control_decision(arm, &mut output).unwrap();
    append_record(
        &mut journal,
        &mut expected_outputs,
        normalize_control_decision(CaptureOrdinal(7), arm).unwrap(),
        output,
    );

    output.fill(None);
    let trading_open = market(
        1,
        1_070,
        MarketDataPayload::TradingStatus { status_code: 1 },
    );
    let open_outcome = live
        .on_market_data(trading_open, MonotonicTimestampNs(1_070), &mut output)
        .unwrap();
    assert_eq!(open_outcome.output.commands, 2);
    append_record(
        &mut journal,
        &mut expected_outputs,
        normalize_market_data(
            venue_metadata(SequenceDomain::MarketData, 8, 1_070),
            trading_open,
        )
        .unwrap(),
        output,
    );
    let quoted = output;
    let (bid, ask) = split_new_orders(quoted);

    for (ordinal, monotonic, command) in [
        (9, 1_080, quoted[0].unwrap()),
        (10, 1_081, quoted[1].unwrap()),
    ] {
        live.on_transmission(
            command,
            TransmissionStatus::Sent,
            MonotonicTimestampNs(monotonic),
        )
        .unwrap();
        append_record(
            &mut journal,
            &mut expected_outputs,
            normalize_transmission(
                CaptureOrdinal(ordinal),
                TransmissionInput {
                    command,
                    status: TransmissionStatus::Sent,
                    monotonic_now: MonotonicTimestampNs(monotonic),
                },
            )
            .unwrap(),
            [None; 2],
        );
    }

    for (ordinal, sequence, monotonic, new_order, venue_order_id) in [
        (11, 2, 1_090, bid, VenueOrderId(7_000)),
        (12, 3, 1_100, ask, VenueOrderId(7_001)),
    ] {
        output.fill(None);
        let accepted = inbound(
            sequence,
            monotonic,
            InboundPayload::Order(OrderEvent::Accepted(Accepted {
                client_order_id: new_order.client_order_id,
                venue_order_id,
                price: new_order.price,
                quantity: new_order.quantity,
            })),
        );
        live.on_order_entry(accepted, MonotonicTimestampNs(monotonic), &mut output)
            .unwrap();
        append_record(
            &mut journal,
            &mut expected_outputs,
            normalize_order_entry(
                venue_metadata(SequenceDomain::OrderEntry, ordinal, monotonic),
                accepted,
            )
            .unwrap(),
            output,
        );
    }

    let binding = OwnedMboBinding {
        venue: VENUE,
        client_order_id: bid.client_order_id,
        venue_order_id: VenueOrderId(7_000),
        market_by_order_id: MarketByOrderId(70_000),
        order_entry_sequence: Sequence(2),
        method: OwnedMboBindingMethod::CertifiedDeterministicRule { rule_id: 91 },
    };
    live.on_owned_mbo_binding(binding, MonotonicTimestampNs(1_110))
        .unwrap();
    append_record(
        &mut journal,
        &mut expected_outputs,
        normalize_owned_mbo_binding(
            CaptureOrdinal(13),
            OwnedMboBindingInput {
                binding,
                monotonic_now: MonotonicTimestampNs(1_110),
            },
        )
        .unwrap(),
        [None; 2],
    );

    output.fill(None);
    let public_add = market(
        2,
        1_120,
        MarketDataPayload::Book(BookDelta::Add {
            order_id: binding.market_by_order_id,
            side: bid.side,
            price: bid.price,
            quantity: bid.quantity,
        }),
    );
    live.on_market_data(public_add, MonotonicTimestampNs(1_120), &mut output)
        .unwrap();
    append_record(
        &mut journal,
        &mut expected_outputs,
        normalize_market_data(
            venue_metadata(SequenceDomain::MarketData, 14, 1_120),
            public_add,
        )
        .unwrap(),
        output,
    );

    let mut next_capture_ordinal = 15_u64;
    for (index, command) in output.into_iter().flatten().enumerate() {
        let monotonic = 1_130 + u64::try_from(index).unwrap();
        live.on_transmission(
            command,
            TransmissionStatus::Sent,
            MonotonicTimestampNs(monotonic),
        )
        .unwrap();
        append_record(
            &mut journal,
            &mut expected_outputs,
            normalize_transmission(
                CaptureOrdinal(next_capture_ordinal),
                TransmissionInput {
                    command,
                    status: TransmissionStatus::Sent,
                    monotonic_now: MonotonicTimestampNs(monotonic),
                },
            )
            .unwrap(),
            [None; 2],
        );
        next_capture_ordinal += 1;
    }

    let live_queue = live.exact_queue(Side::Buy).unwrap();
    assert!(live_queue.own_visible());
    assert_eq!(live_queue.queue_ahead(), Quantity(100));

    output.fill(None);
    let lease_timer = TimerInput {
        timer_id: TimerId(1),
        action: TimerAction::ControlLivenessCheck,
        scheduled_at: MonotonicTimestampNs(1_150),
        fired_at: MonotonicTimestampNs(1_151),
    };
    live.check_control_liveness(lease_timer.fired_at, &mut output)
        .unwrap();
    assert!(
        output
            .iter()
            .flatten()
            .all(|command| matches!(command, OrderCommand::Cancel(_)))
    );
    append_record(
        &mut journal,
        &mut expected_outputs,
        normalize_timer(CaptureOrdinal(next_capture_ordinal), lease_timer).unwrap(),
        output,
    );

    let summary = replay_bytes::<4>(&journal, Sequence(1)).unwrap();
    assert_eq!(summary.records, next_capture_ordinal);
    assert_eq!(
        summary.last_capture_ordinal,
        CaptureOrdinal(next_capture_ordinal)
    );

    let mut replayed = Engine::new(config()).unwrap();
    let mut offset = 0;
    for (event_index, expected) in expected_outputs.iter().copied().enumerate() {
        let (event, consumed) = decode_record(&journal[offset..]).unwrap();
        let mut replay_output = [None; 2];
        let outcome =
            dispatch_engine_replay_event(&mut replayed, event, &mut replay_output).unwrap();
        assert_eq!(
            replay_output,
            expected,
            "outbound decisions diverged at event {}",
            event_index + 1
        );
        assert_eq!(
            outcome.commands,
            replay_output.iter().flatten().count(),
            "dispatcher output count diverged at event {}",
            event_index + 1
        );
        offset += consumed;
    }
    assert_eq!(offset, journal.len());
    assert!(live.deterministic_state_eq(&replayed));
    assert_eq!(live.exact_queue(Side::Buy), replayed.exact_queue(Side::Buy));

    let mut reactor_replayed = Reactor::new(Engine::new(config()).unwrap());
    let mut scheduler_journal = Vec::new();
    offset = 0;
    for (event_index, expected) in expected_outputs.iter().copied().enumerate() {
        let (event, consumed) = decode_record(&journal[offset..]).unwrap();
        let mut egress = [None; 2];
        let outcome =
            dispatch_reactor_replay_event(&mut reactor_replayed, event, &mut egress).unwrap();
        let actual = egress.map(|slot| slot.map(|item| item.command));
        assert_eq!(
            actual,
            expected,
            "reactor replay diverged at event {}",
            event_index + 1
        );
        assert_eq!(outcome.commands, actual.iter().flatten().count());
        let commit = SchedulerCommit::from_replay_outcome(
            u64::try_from(event_index + 1).unwrap(),
            event,
            outcome,
            &egress,
        )
        .unwrap();
        let mut encoded_commit = [0_u8; SCHEDULER_COMMIT_RECORD_LEN];
        assert_eq!(
            encode_scheduler_commit(commit, &mut encoded_commit),
            Ok(SCHEDULER_COMMIT_RECORD_LEN)
        );
        scheduler_journal.extend_from_slice(&encoded_commit);
        offset += consumed;
    }
    assert!(live.deterministic_state_eq(reactor_replayed.engine()));

    let mut committed_replay = Reactor::new(Engine::new(config()).unwrap());
    let mut commit_verifier = SchedulerCommitVerifier::new(1).unwrap();
    let mut event_offset = 0;
    let mut commit_offset = 0;
    for expected_commit_ordinal in 1..=expected_outputs.len() {
        let (event, event_consumed) = decode_record(&journal[event_offset..]).unwrap();
        let (expected_commit, commit_consumed) =
            decode_scheduler_commit(&scheduler_journal[commit_offset..]).unwrap();
        assert_eq!(
            expected_commit.commit_ordinal,
            u64::try_from(expected_commit_ordinal).unwrap()
        );
        expected_commit.verify_source(event).unwrap();

        let mut egress = [None; 2];
        commit_verifier
            .verify_and_dispatch(&mut committed_replay, event, expected_commit, &mut egress)
            .unwrap();
        event_offset += event_consumed;
        commit_offset += commit_consumed;
    }
    assert_eq!(event_offset, journal.len());
    assert_eq!(commit_offset, scheduler_journal.len());
    assert_eq!(
        commit_verifier.next_commit_ordinal(),
        u64::try_from(expected_outputs.len()).unwrap() + 1
    );
    assert!(!commit_verifier.is_failed());
    assert!(reactor_replayed.deterministic_state_eq(&committed_replay));

    let mut corrupted_commit = scheduler_journal[..SCHEDULER_COMMIT_RECORD_LEN].to_vec();
    corrupted_commit[20] ^= 1;
    assert!(matches!(
        decode_scheduler_commit(&corrupted_commit),
        Err(SchedulerCommitError::ChecksumMismatch { .. })
    ));
    let (first_commit, _) = decode_scheduler_commit(&scheduler_journal).unwrap();
    let (second_event, _) = decode_record(&journal[RECORD_LEN..]).unwrap();
    assert_eq!(
        first_commit.verify_source(second_event),
        Err(SchedulerCommitError::SourceMismatch)
    );

    let (first_event, _) = decode_record(&journal).unwrap();
    let (second_commit, _) =
        decode_scheduler_commit(&scheduler_journal[SCHEDULER_COMMIT_RECORD_LEN..]).unwrap();
    let mut failed_verifier = SchedulerCommitVerifier::new(1).unwrap();
    let mut untouched_reactor = Reactor::new(Engine::new(config()).unwrap());
    assert_eq!(
        failed_verifier.verify_and_dispatch(
            &mut untouched_reactor,
            first_event,
            second_commit,
            &mut [None; 2],
        ),
        Err(SchedulerReplayError::CommitOrdinalMismatch {
            expected: 1,
            actual: 2,
        })
    );
    assert!(failed_verifier.is_failed());
    assert_eq!(
        failed_verifier.verify_and_dispatch(
            &mut untouched_reactor,
            first_event,
            first_commit,
            &mut [None; 2],
        ),
        Err(SchedulerReplayError::ReplayFailed)
    );

    let mut barrier_reactor = Reactor::new(Engine::new(config()).unwrap());
    for event_index in 0..8 {
        let offset = event_index * RECORD_LEN;
        let (event, _) = decode_record(&journal[offset..]).unwrap();
        let mut egress = [None; 2];
        dispatch_reactor_replay_event(&mut barrier_reactor, event, &mut egress).unwrap();
    }
    assert_eq!(barrier_reactor.outstanding_transmissions(), 2);

    let (premature_normal, _) = decode_record(&journal[10 * RECORD_LEN..]).unwrap();
    let barrier_error =
        dispatch_reactor_replay_event(&mut barrier_reactor, premature_normal, &mut [None; 2])
            .unwrap_err();
    assert_eq!(
        barrier_error,
        ReactorReplayError::OutstandingTransmission { outstanding: 2 }
    );

    let (reversed_feedback, _) = decode_record(&journal[9 * RECORD_LEN..]).unwrap();
    let feedback_error =
        dispatch_reactor_replay_event(&mut barrier_reactor, reversed_feedback, &mut [None; 2])
            .unwrap_err();
    let ReactorReplayError::Reactor(failure) = feedback_error else {
        panic!("expected reactor transmission-order failure");
    };
    assert_eq!(
        failure.error,
        ReactorError::TransmissionMismatch {
            expected: quoted[0].unwrap(),
            received: quoted[1].unwrap(),
        }
    );
    assert_eq!(barrier_reactor.outstanding_transmissions(), 2);
}
