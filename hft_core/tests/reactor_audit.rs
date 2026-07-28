mod support;

use quant_hft_core::adverse::AdverseConfig;
use quant_hft_core::engine::{EngineConfig, ExecutionEngine};
use quant_hft_core::events::CaptureOrdinal;
use quant_hft_core::journal::crc32c;
use quant_hft_core::reactor::{
    HotPathReactor, InputOrdinal, ReactorInputKind, ReactorStop, RunOrdinal,
};
use quant_hft_core::reactor_audit::{
    SCHEDULER_COMMIT_HEADER_LEN, SCHEDULER_COMMIT_RECORD_LEN, SchedulerCommit,
    SchedulerCommitError, SchedulerCommitVerifier, SchedulerReplayError, SchedulerRoute,
    decode_scheduler_commit, encode_scheduler_commit,
};
use quant_hft_core::risk::{
    CurrencyId, InstrumentRiskDefinition, InstrumentValuation, RiskLimits, RiskSessionId,
};
use quant_hft_core::strategy::QuotePolicyConfig;
use quant_hft_core::types::{
    InstrumentId, OrderId, PriceTicks, Quantity, Sequence, Side, TimestampNs, VenueId,
};
use quant_hft_core::venue::{
    CancelAll, CancelOrder, CancelScope, ClientOrderId, NewOrder, OrderCommand, ReplaceOrder,
    TimeInForce, VenueOrderId,
};

type AuditEngine = ExecutionEngine<64, 16, 8, 16, 16>;
type AuditReactor = HotPathReactor<64, 16, 8, 16, 16>;

const FLAGS_OFFSET: usize = 16;
const STOP_ARG0_OFFSET: usize = 18;
const STOP_ARG1_OFFSET: usize = 19;
const SOURCE_CRC_OFFSET: usize = 20;
const EGRESS_INPUT_ORDINAL_OFFSET: usize = 48;
const CAPTURE_ORDINAL_OFFSET: usize = 56;

fn rewrite_record_crc(record: &mut [u8; SCHEDULER_COMMIT_RECORD_LEN]) {
    let checksum_offset = SCHEDULER_COMMIT_RECORD_LEN - 4;
    let checksum = crc32c(&record[..checksum_offset]);
    record[checksum_offset..].copy_from_slice(&checksum.to_le_bytes());
}

fn commit(command: OrderCommand) -> SchedulerCommit {
    SchedulerCommit {
        commit_ordinal: 1,
        route: SchedulerRoute::Normal,
        input_kind: Some(ReactorInputKind::MarketData),
        run_ordinal: Some(RunOrdinal(1)),
        input_ordinal: Some(InputOrdinal(1)),
        egress_input_ordinal: Some(InputOrdinal(1)),
        capture_ordinal: CaptureOrdinal(7),
        source_event_crc32c: 0x1234_5678,
        commands: [Some(command), None],
        outstanding_transmissions: 1,
        event_retained: false,
        mandatory_kill_pending: false,
        stop: Some(ReactorStop::TransmissionBoundary {
            published: 1,
            outstanding: 1,
        }),
    }
}

fn commands() -> [OrderCommand; 5] {
    [
        OrderCommand::New(NewOrder {
            client_order_id: ClientOrderId(10),
            instrument: InstrumentId(7),
            side: Side::Buy,
            price: PriceTicks(100),
            quantity: Quantity(3),
            time_in_force: TimeInForce::PostOnly,
            created_at: TimestampNs(1_000),
        }),
        OrderCommand::Cancel(CancelOrder {
            client_order_id: ClientOrderId(11),
            venue_order_id: VenueOrderId(21),
            created_at: TimestampNs(1_001),
        }),
        OrderCommand::Replace(ReplaceOrder {
            current_client_order_id: ClientOrderId(12),
            replacement_client_order_id: ClientOrderId(13),
            venue_order_id: VenueOrderId(22),
            new_price: PriceTicks(101),
            new_quantity: Quantity(4),
            created_at: TimestampNs(1_002),
        }),
        OrderCommand::CancelAll(CancelAll {
            scope: CancelScope::Session,
            created_at: TimestampNs(1_003),
        }),
        OrderCommand::CancelAll(CancelAll {
            scope: CancelScope::Instrument(InstrumentId(7)),
            created_at: TimestampNs(1_004),
        }),
    ]
}

fn retained_commit() -> SchedulerCommit {
    SchedulerCommit {
        commit_ordinal: 2,
        route: SchedulerRoute::RetainedNormal,
        input_kind: Some(ReactorInputKind::MarketData),
        run_ordinal: Some(RunOrdinal(2)),
        input_ordinal: None,
        egress_input_ordinal: None,
        capture_ordinal: CaptureOrdinal(8),
        source_event_crc32c: 0x8765_4321,
        commands: [None; 2],
        outstanding_transmissions: 0,
        event_retained: true,
        mandatory_kill_pending: true,
        stop: Some(ReactorStop::MandatoryKillRequired {
            required_egress: 2,
            available_egress: 1,
        }),
    }
}

fn safety_commit() -> SchedulerCommit {
    SchedulerCommit {
        commit_ordinal: 3,
        route: SchedulerRoute::SafetyKill,
        input_kind: Some(ReactorInputKind::SafetyKill),
        run_ordinal: Some(RunOrdinal(3)),
        input_ordinal: None,
        egress_input_ordinal: Some(InputOrdinal(0)),
        capture_ordinal: CaptureOrdinal(0),
        source_event_crc32c: 0,
        commands: [Some(commands()[1]), None],
        outstanding_transmissions: 1,
        event_retained: true,
        mandatory_kill_pending: false,
        stop: Some(ReactorStop::TransmissionBoundary {
            published: 1,
            outstanding: 1,
        }),
    }
}

fn engine_config() -> EngineConfig {
    EngineConfig {
        venue: VenueId(1),
        instrument: InstrumentId(7),
        first_market_sequence: Sequence(1),
        first_order_sequence: Sequence(1),
        first_client_order_id: ClientOrderId(1_000),
        first_risk_order_id: OrderId(5_000),
        instrument_definition: support::instrument_definition(VenueId(1), InstrumentId(7)),
        max_clock_uncertainty_ns: 1_000,
        max_clock_offset_step_ns: 100,
        max_clock_holdover_ns: 100_000,
        clock_drift_parts_per_billion: 10,
        risk_session: RiskSessionId(1),
        risk_definition: InstrumentRiskDefinition {
            instrument: InstrumentId(7),
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

#[test]
fn every_order_command_has_one_canonical_fixed_scheduler_encoding() {
    for command in commands() {
        let expected = commit(command);
        let mut record = [0xA5_u8; SCHEDULER_COMMIT_RECORD_LEN + 8];
        assert_eq!(
            encode_scheduler_commit(expected, &mut record),
            Ok(SCHEDULER_COMMIT_RECORD_LEN)
        );
        assert_eq!(
            &record[SCHEDULER_COMMIT_RECORD_LEN..],
            &[0xA5; 8],
            "encoder modified caller tail"
        );
        let (decoded, consumed) = decode_scheduler_commit(&record).unwrap();
        assert_eq!(consumed, SCHEDULER_COMMIT_RECORD_LEN);
        assert_eq!(decoded, expected);
    }

    let no_engine = SchedulerCommit {
        commit_ordinal: 2,
        route: SchedulerRoute::NoEngineInput,
        input_kind: None,
        run_ordinal: None,
        input_ordinal: None,
        egress_input_ordinal: None,
        capture_ordinal: CaptureOrdinal(8),
        source_event_crc32c: 0x8765_4321,
        commands: [None; 2],
        outstanding_transmissions: 0,
        event_retained: false,
        mandatory_kill_pending: false,
        stop: None,
    };
    let mut record = [0_u8; SCHEDULER_COMMIT_RECORD_LEN];
    encode_scheduler_commit(no_engine, &mut record).unwrap();
    assert_eq!(decode_scheduler_commit(&record).unwrap().0, no_engine);
}

#[test]
fn noncanonical_or_invalid_commands_are_rejected_even_with_a_valid_crc() {
    let mut record = [0_u8; SCHEDULER_COMMIT_RECORD_LEN];
    encode_scheduler_commit(commit(commands()[0]), &mut record).unwrap();
    record[SCHEDULER_COMMIT_HEADER_LEN + 3] = 1;
    let checksum = crc32c(&record[..SCHEDULER_COMMIT_RECORD_LEN - 4]);
    record[SCHEDULER_COMMIT_RECORD_LEN - 4..].copy_from_slice(&checksum.to_le_bytes());
    assert_eq!(
        decode_scheduler_commit(&record),
        Err(SchedulerCommitError::InvalidCommand)
    );

    let invalid_replace = OrderCommand::Replace(ReplaceOrder {
        current_client_order_id: ClientOrderId(14),
        replacement_client_order_id: ClientOrderId(14),
        venue_order_id: VenueOrderId(23),
        new_price: PriceTicks(102),
        new_quantity: Quantity(5),
        created_at: TimestampNs(1_005),
    });
    assert_eq!(
        encode_scheduler_commit(commit(invalid_replace), &mut record),
        Err(SchedulerCommitError::InvalidCommand)
    );
}

#[test]
fn safety_egress_presence_round_trips_some_zero_ordinal() {
    let expected = safety_commit();
    let mut record = [0_u8; SCHEDULER_COMMIT_RECORD_LEN];
    encode_scheduler_commit(expected, &mut record).unwrap();

    assert_ne!(record[FLAGS_OFFSET] & 0b100, 0);
    assert_eq!(
        &record[EGRESS_INPUT_ORDINAL_OFFSET..EGRESS_INPUT_ORDINAL_OFFSET + 8],
        &[0; 8]
    );
    assert_eq!(decode_scheduler_commit(&record).unwrap().0, expected);
}

#[test]
fn inconsistent_egress_presence_is_rejected_after_crc_recalculation() {
    let mut safety_record = [0_u8; SCHEDULER_COMMIT_RECORD_LEN];
    encode_scheduler_commit(safety_commit(), &mut safety_record).unwrap();
    safety_record[FLAGS_OFFSET] &= !0b100;
    rewrite_record_crc(&mut safety_record);
    assert_eq!(
        decode_scheduler_commit(&safety_record),
        Err(SchedulerCommitError::InvalidRecord)
    );

    let mut retained_record = [0_u8; SCHEDULER_COMMIT_RECORD_LEN];
    encode_scheduler_commit(retained_commit(), &mut retained_record).unwrap();
    retained_record[FLAGS_OFFSET] |= 0b100;
    rewrite_record_crc(&mut retained_record);
    assert_eq!(
        decode_scheduler_commit(&retained_record),
        Err(SchedulerCommitError::InvalidRecord)
    );
}

#[test]
fn safety_commit_rejects_any_source_binding_after_crc_recalculation() {
    let mut source_crc_record = [0_u8; SCHEDULER_COMMIT_RECORD_LEN];
    encode_scheduler_commit(safety_commit(), &mut source_crc_record).unwrap();
    source_crc_record[SOURCE_CRC_OFFSET..SOURCE_CRC_OFFSET + 4]
        .copy_from_slice(&1_u32.to_le_bytes());
    rewrite_record_crc(&mut source_crc_record);
    assert_eq!(
        decode_scheduler_commit(&source_crc_record),
        Err(SchedulerCommitError::InvalidRecord)
    );

    let mut capture_record = [0_u8; SCHEDULER_COMMIT_RECORD_LEN];
    encode_scheduler_commit(safety_commit(), &mut capture_record).unwrap();
    capture_record[CAPTURE_ORDINAL_OFFSET..CAPTURE_ORDINAL_OFFSET + 8]
        .copy_from_slice(&1_u64.to_le_bytes());
    rewrite_record_crc(&mut capture_record);
    assert_eq!(
        decode_scheduler_commit(&capture_record),
        Err(SchedulerCommitError::InvalidRecord)
    );
}

#[test]
fn retained_commit_requires_exact_mandatory_kill_stop_arguments() {
    for (offset, value) in [(STOP_ARG0_OFFSET, 1_u8), (STOP_ARG1_OFFSET, 0_u8)] {
        let mut record = [0_u8; SCHEDULER_COMMIT_RECORD_LEN];
        encode_scheduler_commit(retained_commit(), &mut record).unwrap();
        record[offset] = value;
        rewrite_record_crc(&mut record);
        assert_eq!(
            decode_scheduler_commit(&record),
            Err(SchedulerCommitError::InvalidRecord)
        );
    }
}

#[test]
fn verifier_ordinal_overflow_is_preflighted_without_reactor_mutation() {
    let mut reactor = AuditReactor::new(AuditEngine::new(engine_config()).unwrap());
    let baseline = AuditReactor::new(AuditEngine::new(engine_config()).unwrap());
    let mut verifier = SchedulerCommitVerifier::new(u64::MAX).unwrap();
    let mut expected = safety_commit();
    expected.commit_ordinal = u64::MAX;
    let mut egress = [None; 2];

    let result = verifier.verify_and_dispatch_safety(&mut reactor, expected, &mut egress);

    assert!(matches!(
        result,
        Err(SchedulerReplayError::CommitOrdinalExhausted)
    ));
    assert!(verifier.is_failed());
    assert_eq!(verifier.next_commit_ordinal(), u64::MAX);
    assert!(reactor.deterministic_state_eq(&baseline));
    assert!(egress.iter().all(Option::is_none));
}
