use quant_hft_core::book::{BookEvent, L3Book};
use quant_hft_core::events::{
    CanonicalField, CaptureOrdinal, EVENT_FLAG_RECOVERY, EVENT_FLAG_SNAPSHOT, EventError,
    EventKind, EventSide, EventSource, NormalizedEvent, SequenceDomain, SessionEpoch, SourceId,
};
use quant_hft_core::journal::{
    BoundaryState, BoundaryViolation, EncodeError, JOURNAL_MAGIC, JOURNAL_VERSION,
    RECORD_HEADER_LEN, RECORD_LEN, RecordError, ReplayConsumer, ReplayConsumerError,
    ReplayContribution, ReplayDigest, ReplayError, ReplayState, crc32c, decode_record,
    encode_record, replay_bytes, replay_bytes_with_consumer,
};
use quant_hft_core::strategy::{InventoryAwareQuoter, MarketFeatures, QuotePolicyConfig};
use quant_hft_core::{
    EventHeader, InstrumentId, MonotonicTimestampNs, OrderId, PriceTicks, Quantity, Sequence,
    TimestampNs, VenueId,
};

const VENUE: VenueId = VenueId(7);
const INSTRUMENT_A: InstrumentId = InstrumentId(42);
const INSTRUMENT_B: InstrumentId = InstrumentId(43);
const SOURCE: EventSource = EventSource::new(
    SourceId::new(11, 21),
    SequenceDomain::MarketData,
    SessionEpoch(1),
);

#[allow(clippy::too_many_arguments)]
fn event(
    source: EventSource,
    instrument: InstrumentId,
    sequence: u64,
    ordinal: u64,
    kind: EventKind,
    side: EventSide,
    flags: u16,
    order_id: u64,
    price: i64,
    quantity: i64,
    reference: u64,
) -> NormalizedEvent {
    NormalizedEvent::new(
        EventHeader {
            venue: VENUE,
            instrument,
            sequence: Sequence(sequence),
            exchange_timestamp: TimestampNs(1_000 + ordinal),
            hardware_receive_timestamp: TimestampNs(2_000 + ordinal),
        },
        source,
        CaptureOrdinal(ordinal),
        kind,
        side,
        flags,
        OrderId(order_id),
        PriceTicks(price),
        Quantity(quantity),
        reference,
    )
}

fn book_add(sequence: u64, ordinal: u64, instrument: InstrumentId) -> NormalizedEvent {
    event(
        SOURCE,
        instrument,
        sequence,
        ordinal,
        EventKind::BookAdd,
        EventSide::Buy,
        0,
        10_000 + sequence,
        25_000 - i64::try_from(sequence).unwrap(),
        100,
        0,
    )
}

fn boundary(
    kind: EventKind,
    sequence: u64,
    ordinal: u64,
    flags: u16,
    reference: u64,
) -> NormalizedEvent {
    event(
        SOURCE,
        InstrumentId(0),
        sequence,
        ordinal,
        kind,
        EventSide::None,
        flags,
        0,
        0,
        0,
        reference,
    )
}

fn append(journal: &mut Vec<u8>, event: NormalizedEvent) {
    let mut record = [0_u8; RECORD_LEN];
    assert_eq!(encode_record(event, &mut record), Ok(RECORD_LEN));
    journal.extend_from_slice(&record);
}

fn rewrite_checksum(record: &mut [u8]) {
    let checksum_offset = RECORD_LEN - 4;
    let checksum = crc32c(&record[..checksum_offset]);
    record[checksum_offset..RECORD_LEN].copy_from_slice(&checksum.to_le_bytes());
}

#[test]
fn v5_encoding_is_canonical_little_endian_and_preserves_caller_tail() {
    let mut event = book_add(1, 9, INSTRUMENT_A);
    event.header.sequence = Sequence(0x0102_0304_0506_0708);
    let mut first = [0xaa_u8; RECORD_LEN + 8];
    let mut second = [0x55_u8; RECORD_LEN + 8];

    assert_eq!(encode_record(event, &mut first), Ok(RECORD_LEN));
    assert_eq!(encode_record(event, &mut second), Ok(RECORD_LEN));
    assert_eq!(first[..RECORD_LEN], second[..RECORD_LEN]);
    assert_eq!(first[RECORD_LEN..], [0xaa; 8]);
    assert_eq!(second[RECORD_LEN..], [0x55; 8]);
    assert_eq!(first[0..4], JOURNAL_MAGIC);
    assert_eq!(first[4..6], JOURNAL_VERSION.to_le_bytes());
    assert_eq!(
        first[6..8],
        u16::try_from(RECORD_HEADER_LEN).unwrap().to_le_bytes()
    );
    assert_eq!(
        first[8..12],
        u32::try_from(RECORD_LEN).unwrap().to_le_bytes()
    );
    assert_eq!(first[18], EventSide::Buy as u8);
    assert_eq!(first[19], SequenceDomain::MarketData as u8);
    assert_eq!(first[24..28], SOURCE.id.protocol.to_le_bytes());
    assert_eq!(first[28..32], SOURCE.id.channel.to_le_bytes());
    assert_eq!(first[32..40], SOURCE.session_epoch.0.to_le_bytes());
    assert_eq!(first[40..48], event.header.sequence.0.to_le_bytes());
    assert_eq!(first[48..56], event.capture_ordinal.0.to_le_bytes());

    let (decoded, consumed) = decode_record(&first).unwrap();
    assert_eq!(decoded, event);
    assert_eq!(consumed, RECORD_LEN);
}

#[test]
fn source_cursor_is_channel_global_not_instrument_local() {
    let mut journal = Vec::new();
    append(&mut journal, book_add(1, 1, INSTRUMENT_A));
    append(&mut journal, book_add(2, 2, INSTRUMENT_B));
    let second_source = EventSource::new(
        SourceId::new(11, 22),
        SequenceDomain::MarketData,
        SessionEpoch(1),
    );
    append(
        &mut journal,
        event(
            second_source,
            INSTRUMENT_A,
            1,
            3,
            EventKind::BookAdd,
            EventSide::Buy,
            0,
            20_001,
            24_000,
            20,
            0,
        ),
    );

    let summary = replay_bytes::<4>(&journal, Sequence(1)).unwrap();
    assert_eq!(summary.records, 3);
    assert_eq!(summary.streams, 2);
    assert_eq!(summary.last_capture_ordinal, CaptureOrdinal(3));
}

#[test]
fn capture_ordinal_and_source_sequence_detect_omission_and_reordering() {
    let mut capture_gap = Vec::new();
    append(&mut capture_gap, book_add(1, 1, INSTRUMENT_A));
    let mut skipped_ordinal = book_add(2, 3, INSTRUMENT_B);
    skipped_ordinal.header.exchange_timestamp = TimestampNs(1_003);
    skipped_ordinal.header.hardware_receive_timestamp = TimestampNs(2_003);
    append(&mut capture_gap, skipped_ordinal);
    assert_eq!(
        replay_bytes::<2>(&capture_gap, Sequence(1)),
        Err(ReplayError::CaptureGap {
            expected: CaptureOrdinal(2),
            actual: CaptureOrdinal(3),
        })
    );

    let mut source_gap = Vec::new();
    append(&mut source_gap, book_add(1, 1, INSTRUMENT_A));
    append(&mut source_gap, book_add(3, 2, INSTRUMENT_B));
    assert!(matches!(
        replay_bytes::<2>(&source_gap, Sequence(1)),
        Err(ReplayError::SequenceGap {
            expected: Sequence(2),
            actual: Sequence(3),
            ..
        })
    ));

    let mut duplicate = Vec::new();
    append(&mut duplicate, book_add(1, 1, INSTRUMENT_A));
    append(&mut duplicate, book_add(1, 2, INSTRUMENT_B));
    assert!(matches!(
        replay_bytes::<2>(&duplicate, Sequence(1)),
        Err(ReplayError::SequenceRegression {
            expected: Sequence(2),
            actual: Sequence(1),
            ..
        })
    ));
}

#[test]
fn replay_rejects_global_monotonic_clock_regression() {
    let mut journal = Vec::new();
    append(&mut journal, book_add(1, 1, INSTRUMENT_A));
    let mut regressed = book_add(2, 2, INSTRUMENT_A);
    regressed.monotonic_timestamp = MonotonicTimestampNs(2_000);
    append(&mut journal, regressed);
    assert_eq!(
        replay_bytes::<1>(&journal, Sequence(1)),
        Err(ReplayError::GlobalMonotonicTimestampRegression {
            previous: MonotonicTimestampNs(2_001),
            actual: MonotonicTimestampNs(2_000),
        })
    );
}

#[test]
fn session_epoch_resets_sequence_but_old_epoch_cannot_reappear() {
    let epoch_two = EventSource::new(SOURCE.id, SequenceDomain::MarketData, SessionEpoch(2));
    let mut valid = Vec::new();
    append(&mut valid, book_add(1, 1, INSTRUMENT_A));
    append(
        &mut valid,
        event(
            epoch_two,
            INSTRUMENT_A,
            1,
            2,
            EventKind::BookAdd,
            EventSide::Buy,
            0,
            30_001,
            23_000,
            10,
            0,
        ),
    );
    assert_eq!(replay_bytes::<2>(&valid, Sequence(1)).unwrap().streams, 2);

    append(&mut valid, book_add(2, 3, INSTRUMENT_B));
    assert!(matches!(
        replay_bytes::<3>(&valid, Sequence(1)),
        Err(ReplayError::SessionEpochRegression {
            highest: SessionEpoch(2),
            actual: SessionEpoch(1),
            ..
        })
    ));
}

#[test]
fn initial_and_explicit_recovery_snapshots_are_atomic_and_cannot_bless_silent_gaps() {
    let snapshot_id = 77;
    let mut initial = Vec::new();
    append(
        &mut initial,
        boundary(
            EventKind::SnapshotStart,
            100,
            1,
            EVENT_FLAG_SNAPSHOT,
            snapshot_id,
        ),
    );
    append(
        &mut initial,
        event(
            SOURCE,
            INSTRUMENT_A,
            100,
            2,
            EventKind::BookAdd,
            EventSide::Buy,
            EVENT_FLAG_SNAPSHOT,
            40_001,
            99,
            10,
            snapshot_id,
        ),
    );
    append(
        &mut initial,
        boundary(
            EventKind::SnapshotEnd,
            100,
            3,
            EVENT_FLAG_SNAPSHOT,
            snapshot_id,
        ),
    );
    append(
        &mut initial,
        event(
            SOURCE,
            INSTRUMENT_B,
            101,
            4,
            EventKind::BookAdd,
            EventSide::Sell,
            0,
            40_002,
            101,
            10,
            0,
        ),
    );
    assert_eq!(replay_bytes::<1>(&initial, Sequence(1)).unwrap().records, 4);

    let mut silent = Vec::new();
    append(&mut silent, book_add(1, 1, INSTRUMENT_A));
    append(
        &mut silent,
        boundary(
            EventKind::SnapshotStart,
            5,
            2,
            EVENT_FLAG_SNAPSHOT | EVENT_FLAG_RECOVERY,
            88,
        ),
    );
    assert!(matches!(
        replay_bytes::<1>(&silent, Sequence(1)),
        Err(ReplayError::Boundary {
            violation: BoundaryViolation::SnapshotWouldBlessGap,
            ..
        })
    ));

    let mut explicit = Vec::new();
    append(&mut explicit, book_add(1, 1, INSTRUMENT_A));
    append(
        &mut explicit,
        boundary(EventKind::RecoveryStart, 2, 2, EVENT_FLAG_RECOVERY, 4),
    );
    append(
        &mut explicit,
        boundary(
            EventKind::SnapshotStart,
            5,
            3,
            EVENT_FLAG_SNAPSHOT | EVENT_FLAG_RECOVERY,
            88,
        ),
    );
    append(
        &mut explicit,
        event(
            SOURCE,
            INSTRUMENT_A,
            5,
            4,
            EventKind::BookAdd,
            EventSide::Buy,
            EVENT_FLAG_SNAPSHOT | EVENT_FLAG_RECOVERY,
            41_001,
            98,
            20,
            88,
        ),
    );
    append(
        &mut explicit,
        boundary(
            EventKind::SnapshotEnd,
            5,
            5,
            EVENT_FLAG_SNAPSHOT | EVENT_FLAG_RECOVERY,
            88,
        ),
    );
    append(
        &mut explicit,
        event(
            SOURCE,
            INSTRUMENT_B,
            6,
            6,
            EventKind::BookAdd,
            EventSide::Sell,
            0,
            41_002,
            102,
            20,
            0,
        ),
    );
    assert_eq!(
        replay_bytes::<1>(&explicit, Sequence(1)).unwrap().records,
        6
    );
}

#[test]
fn incremental_recovery_preserves_exact_source_sequences_and_requires_end_boundary() {
    let mut recovered = Vec::new();
    append(&mut recovered, book_add(1, 1, INSTRUMENT_A));
    append(
        &mut recovered,
        boundary(EventKind::RecoveryStart, 2, 2, EVENT_FLAG_RECOVERY, 3),
    );
    let mut sequence_two = book_add(2, 3, INSTRUMENT_B);
    sequence_two.flags = EVENT_FLAG_RECOVERY;
    append(&mut recovered, sequence_two);
    let mut sequence_three = book_add(3, 4, INSTRUMENT_A);
    sequence_three.flags = EVENT_FLAG_RECOVERY;
    append(&mut recovered, sequence_three);
    append(
        &mut recovered,
        boundary(EventKind::RecoveryEnd, 4, 5, EVENT_FLAG_RECOVERY, 3),
    );
    append(&mut recovered, book_add(4, 6, INSTRUMENT_B));
    assert_eq!(
        replay_bytes::<1>(&recovered, Sequence(1)).unwrap().records,
        6
    );

    let mut wrong_order = Vec::new();
    append(&mut wrong_order, book_add(1, 1, INSTRUMENT_A));
    append(
        &mut wrong_order,
        boundary(EventKind::RecoveryStart, 2, 2, EVENT_FLAG_RECOVERY, 3),
    );
    let mut sequence_three_first = book_add(3, 3, INSTRUMENT_A);
    sequence_three_first.flags = EVENT_FLAG_RECOVERY;
    append(&mut wrong_order, sequence_three_first);
    assert!(matches!(
        replay_bytes::<1>(&wrong_order, Sequence(1)),
        Err(ReplayError::SequenceGap {
            expected: Sequence(2),
            actual: Sequence(3),
            ..
        })
    ));

    let mut state = ReplayState::<1>::new(Sequence(1));
    state.apply(book_add(1, 1, INSTRUMENT_A)).unwrap();
    state
        .apply(boundary(
            EventKind::RecoveryStart,
            2,
            2,
            EVENT_FLAG_RECOVERY,
            3,
        ))
        .unwrap();
    assert!(matches!(
        state.finish(),
        Err(ReplayError::IncompleteBoundary {
            state: BoundaryState::Recovery,
            ..
        })
    ));
}

#[test]
fn invalid_source_domain_timestamps_and_irrelevant_fields_fail_before_encoding() {
    let mut invalid_source = book_add(1, 1, INSTRUMENT_A);
    invalid_source.source.id.protocol = 0;
    let mut record = [0_u8; RECORD_LEN];
    assert!(matches!(
        encode_record(invalid_source, &mut record),
        Err(EncodeError::InvalidEvent(EventError::InvalidSource(_)))
    ));

    let mut wrong_domain = book_add(1, 1, INSTRUMENT_A);
    wrong_domain.source.sequence_domain = SequenceDomain::OrderEntry;
    assert!(matches!(
        encode_record(wrong_domain, &mut record),
        Err(EncodeError::InvalidEvent(
            EventError::SequenceDomainMismatch { .. }
        ))
    ));

    let mut time_travel = book_add(1, 1, INSTRUMENT_A);
    time_travel.header.hardware_receive_timestamp = TimestampNs(999);
    assert!(matches!(
        encode_record(time_travel, &mut record),
        Err(EncodeError::InvalidEvent(
            EventError::ReceiveBeforeExchange { .. }
        ))
    ));

    let cancel = event(
        SOURCE,
        INSTRUMENT_A,
        1,
        1,
        EventKind::BookCancel,
        EventSide::None,
        0,
        50_001,
        99,
        0,
        0,
    );
    assert_eq!(
        encode_record(cancel, &mut record),
        Err(EncodeError::InvalidEvent(
            EventError::CanonicalZeroRequired {
                kind: EventKind::BookCancel,
                field: CanonicalField::Price,
            }
        ))
    );
}

#[test]
fn corruption_truncation_unknown_version_type_and_domain_fail_closed() {
    let mut record = [0_u8; RECORD_LEN];
    encode_record(book_add(1, 1, INSTRUMENT_A), &mut record).unwrap();

    let mut corrupted = record;
    corrupted[80] ^= 0x40;
    assert!(matches!(
        decode_record(&corrupted),
        Err(RecordError::ChecksumMismatch { .. })
    ));
    assert!(matches!(
        decode_record(&record[..RECORD_LEN - 1]),
        Err(RecordError::Truncated {
            required: RECORD_LEN,
            ..
        })
    ));

    let mut version = record;
    version[4..6].copy_from_slice(&4_u16.to_le_bytes());
    assert_eq!(
        decode_record(&version),
        Err(RecordError::UnsupportedVersion(4))
    );

    let mut kind = record;
    kind[12..14].copy_from_slice(&999_u16.to_le_bytes());
    rewrite_checksum(&mut kind);
    assert_eq!(
        decode_record(&kind),
        Err(RecordError::UnknownEventType(999))
    );

    let mut domain = record;
    domain[19] = 99;
    rewrite_checksum(&mut domain);
    assert_eq!(
        decode_record(&domain),
        Err(RecordError::InvalidSequenceDomain(99))
    );
}

#[derive(Debug)]
struct DecisionConsumer {
    book: L3Book<16, 8>,
    quoter: InventoryAwareQuoter,
    state: ReplayDigest,
    outbound: ReplayDigest,
    decisions: u64,
}

impl DecisionConsumer {
    fn new() -> Self {
        Self {
            book: L3Book::new(Sequence(1)),
            quoter: InventoryAwareQuoter::new(QuotePolicyConfig {
                base_quantity: Quantity(10),
                base_half_spread_ticks: 1,
                max_volatility_spread_ticks: 0,
                max_abs_alpha_ticks: 0,
                inventory_skew_numerator: 0,
                inventory_skew_denominator: 1,
                max_abs_inventory: Quantity(100),
            })
            .unwrap(),
            state: ReplayDigest::default(),
            outbound: ReplayDigest::default(),
            decisions: 0,
        }
    }

    fn apply_book(&mut self, event: NormalizedEvent) -> Result<(), ReplayConsumerError> {
        let book_event = match event.kind {
            EventKind::BookAdd => BookEvent::Add {
                order_id: event.order_id,
                side: event.side.as_side().ok_or(ReplayConsumerError(10))?,
                price: event.price,
                quantity: event.quantity,
            },
            EventKind::BookModify => BookEvent::Modify {
                order_id: event.order_id,
                price: event.price,
                quantity: event.quantity,
            },
            EventKind::BookCancel => BookEvent::Cancel {
                order_id: event.order_id,
            },
            EventKind::BookExecute => BookEvent::Execute {
                order_id: event.order_id,
                quantity: event.quantity,
            },
            _ => return Ok(()),
        };
        self.book
            .apply(self.book.expected_sequence(), book_event)
            .map(|_| ())
            .map_err(|_| ReplayConsumerError(11))
    }

    fn update_digests(&mut self) -> Result<(), ReplayConsumerError> {
        let bid = self.book.best_bid();
        let ask = self.book.best_ask();
        self.state = ReplayDigest {
            lane0: u64::try_from(self.book.order_count()).map_err(|_| ReplayConsumerError(12))?
                ^ bid.map_or(0, |level| level.price.0.unsigned_abs().rotate_left(7)),
            lane1: ask.map_or(0, |level| level.price.0.unsigned_abs().rotate_left(17)),
        };
        let (Some(bid), Some(ask)) = (bid, ask) else {
            return Ok(());
        };
        let decision = self
            .quoter
            .decide(MarketFeatures {
                best_bid: bid.price,
                best_bid_quantity: bid.total_quantity,
                best_ask: ask.price,
                best_ask_quantity: ask.total_quantity,
                short_horizon_alpha_ticks: 0,
                volatility_spread_ticks: 0,
                inventory: Quantity::ZERO,
                instrument_halted: false,
            })
            .map_err(|_| ReplayConsumerError(13))?;
        self.decisions = self
            .decisions
            .checked_add(1)
            .ok_or(ReplayConsumerError(14))?;
        self.outbound.lane0 = self
            .outbound
            .lane0
            .rotate_left(9)
            .wrapping_add(decision.bid.map_or(0, |leg| leg.price.0.unsigned_abs()));
        self.outbound.lane1 = self
            .outbound
            .lane1
            .rotate_left(13)
            .wrapping_add(decision.ask.map_or(0, |leg| leg.price.0.unsigned_abs()));
        Ok(())
    }
}

impl ReplayConsumer for DecisionConsumer {
    fn on_event(
        &mut self,
        event: NormalizedEvent,
    ) -> Result<ReplayContribution, ReplayConsumerError> {
        self.apply_book(event)?;
        self.update_digests()?;
        Ok(ReplayContribution {
            state_digest: self.state,
            outbound_decision_digest: self.outbound,
        })
    }
}

fn decision_trace() -> [NormalizedEvent; 4] {
    [
        event(
            SOURCE,
            INSTRUMENT_A,
            1,
            1,
            EventKind::BookAdd,
            EventSide::Buy,
            0,
            60_001,
            99,
            100,
            0,
        ),
        event(
            SOURCE,
            INSTRUMENT_A,
            2,
            2,
            EventKind::Trade,
            EventSide::Buy,
            0,
            0,
            100,
            2,
            70_001,
        ),
        event(
            SOURCE,
            INSTRUMENT_A,
            3,
            3,
            EventKind::BookAdd,
            EventSide::Sell,
            0,
            60_002,
            101,
            100,
            0,
        ),
        event(
            SOURCE,
            INSTRUMENT_A,
            4,
            4,
            EventKind::BookModify,
            EventSide::None,
            0,
            60_001,
            98,
            80,
            0,
        ),
    ]
}

#[test]
fn allocation_free_consumer_replay_matches_live_state_and_outbound_decisions() {
    let trace = decision_trace();
    let mut live = DecisionConsumer::new();
    let mut journal = Vec::new();
    for event in trace {
        live.on_event(event).unwrap();
        append(&mut journal, event);
    }

    let mut replayed = DecisionConsumer::new();
    let summary =
        replay_bytes_with_consumer::<2, _>(&journal, CaptureOrdinal(1), &mut replayed).unwrap();
    assert_eq!(replayed.state, live.state);
    assert_eq!(replayed.outbound, live.outbound);
    assert_eq!(replayed.decisions, live.decisions);
    assert_eq!(replayed.book.best_bid(), live.book.best_bid());
    assert_eq!(replayed.book.best_ask(), live.book.best_ask());
    assert_ne!(summary.consumer_state_digest, ReplayDigest::default());
    assert_ne!(summary.outbound_decision_digest, ReplayDigest::default());

    let mut repeated = DecisionConsumer::new();
    let repeated_summary =
        replay_bytes_with_consumer::<2, _>(&journal, CaptureOrdinal(1), &mut repeated).unwrap();
    assert_eq!(summary, repeated_summary);
}

#[test]
fn failed_replay_is_permanently_latched() {
    let mut state = ReplayState::<1>::new(Sequence(1));
    let bad = book_add(2, 1, INSTRUMENT_A);
    assert!(matches!(
        state.apply(bad),
        Err(ReplayError::SequenceGap { .. })
    ));
    assert!(state.is_failed());
    assert_eq!(state.apply(bad), Err(ReplayError::ReplayFailed));
    assert_eq!(state.finish(), Err(ReplayError::ReplayFailed));
}
