//! Fixed-width capture format and allocation-free deterministic replay.
//!
//! CRC32C detects accidental record corruption only. It provides no authenticity,
//! tamper resistance, or cryptographic integrity. Likewise, replay digests are stable
//! non-cryptographic regression fingerprints; security decisions require a separately
//! authenticated journal/container and trusted key management. Retained deployments
//! can wrap these records with [`crate::audit_container`], but still require a reviewed
//! authenticator and an externally retained latest anchor.

use crate::events::{
    CaptureOrdinal, ControlEventOrigin, EVENT_FLAG_RECOVERY, EVENT_FLAG_SNAPSHOT, EventError,
    EventKind, EventSide, EventSource, NormalizedEvent, SequenceDomain, SessionEpoch, SourceId,
};
use crate::types::{
    EventHeader, InstrumentId, MonotonicTimestampNs, OrderId, PriceTicks, Quantity, Sequence,
    TimestampNs, VenueId,
};

pub const JOURNAL_MAGIC: [u8; 4] = *b"QHFT";
pub const JOURNAL_VERSION: u16 = 5;
pub const RECORD_HEADER_LEN: usize = 16;
pub const RECORD_LEN: usize = 180;

const CHECKSUM_OFFSET: usize = 176;
const RECORD_HEADER_LEN_WIRE: u16 = 16;
const RECORD_LEN_WIRE: u32 = 180;
const CRC32C_REVERSED_POLYNOMIAL: u32 = 0x82f6_3b78;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    BufferTooSmall { required: usize, available: usize },
    InvalidEvent(EventError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordError {
    Truncated { required: usize, available: usize },
    InvalidMagic,
    UnsupportedVersion(u16),
    InvalidHeaderLength(u16),
    InvalidRecordLength(u32),
    ChecksumMismatch { recorded: u32, calculated: u32 },
    UnknownEventType(u16),
    InvalidSide(u8),
    InvalidSequenceDomain(u8),
    InvalidEvent(EventError),
}

/// Compute CRC32C (Castagnoli) with conventional initial/final inversion.
///
/// This checksum detects accidental corruption. It is not a MAC, signature, or proof
/// that a record came from an authenticated source.
#[must_use]
pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (CRC32C_REVERSED_POLYNOMIAL & mask);
        }
    }
    !crc
}

/// Encode one version-5 record into caller-owned storage without allocating.
///
/// Every integer is little-endian. CRC32C covers bytes `0..176`; bytes `176..180`
/// hold the checksum. Bytes beyond the record remain untouched.
///
/// # Errors
///
/// Returns [`EncodeError::InvalidEvent`] for a non-canonical event or
/// [`EncodeError::BufferTooSmall`] when `output` cannot hold one record.
pub fn encode_record(event: NormalizedEvent, output: &mut [u8]) -> Result<usize, EncodeError> {
    event.validate().map_err(EncodeError::InvalidEvent)?;
    if output.len() < RECORD_LEN {
        return Err(EncodeError::BufferTooSmall {
            required: RECORD_LEN,
            available: output.len(),
        });
    }

    let record = &mut output[..RECORD_LEN];
    record.fill(0);
    record[0..4].copy_from_slice(&JOURNAL_MAGIC);
    write_u16(record, 4, JOURNAL_VERSION);
    write_u16(record, 6, RECORD_HEADER_LEN_WIRE);
    write_u32(record, 8, RECORD_LEN_WIRE);
    write_u16(record, 12, event.kind as u16);
    write_u16(record, 14, event.flags);
    write_u16(record, 16, event.header.venue.0);
    record[18] = event.side as u8;
    record[19] = event.source.sequence_domain as u8;
    write_u32(record, 20, event.header.instrument.0);
    write_u32(record, 24, event.source.id.protocol);
    write_u32(record, 28, event.source.id.channel);
    write_u64(record, 32, event.source.session_epoch.0);
    write_u64(record, 40, event.header.sequence.0);
    write_u64(record, 48, event.capture_ordinal.0);
    write_u64(record, 56, event.header.exchange_timestamp.0);
    write_u64(record, 64, event.header.hardware_receive_timestamp.0);
    write_u64(record, 72, event.monotonic_timestamp.0);
    write_u64(record, 80, event.order_id.0);
    write_u64(record, 88, event.secondary_id);
    write_u64(record, 96, event.tertiary_id);
    write_i64(record, 104, event.price.0);
    write_i64(record, 112, event.quantity.0);
    write_i64(record, 120, event.leaves_quantity.0);
    write_u64(record, 128, event.reference);
    write_u64(record, 136, event.auxiliary);
    record[144..176].copy_from_slice(&event.blob);
    let checksum = crc32c(&record[..CHECKSUM_OFFSET]);
    write_u32(record, CHECKSUM_OFFSET, checksum);
    Ok(RECORD_LEN)
}

/// Decode and validate one version-5 record from `input` without allocating.
///
/// # Errors
///
/// Returns a [`RecordError`] for framing, corruption, unknown wire codes, or any
/// non-canonical event field.
pub fn decode_record(input: &[u8]) -> Result<(NormalizedEvent, usize), RecordError> {
    if input.len() < RECORD_HEADER_LEN {
        return Err(RecordError::Truncated {
            required: RECORD_HEADER_LEN,
            available: input.len(),
        });
    }
    if input[0..4] != JOURNAL_MAGIC {
        return Err(RecordError::InvalidMagic);
    }
    let version = read_u16(input, 4);
    if version != JOURNAL_VERSION {
        return Err(RecordError::UnsupportedVersion(version));
    }
    let header_len = read_u16(input, 6);
    if usize::from(header_len) != RECORD_HEADER_LEN {
        return Err(RecordError::InvalidHeaderLength(header_len));
    }
    let record_len = read_u32(input, 8);
    if record_len != RECORD_LEN_WIRE {
        return Err(RecordError::InvalidRecordLength(record_len));
    }
    if input.len() < RECORD_LEN {
        return Err(RecordError::Truncated {
            required: RECORD_LEN,
            available: input.len(),
        });
    }

    let record = &input[..RECORD_LEN];
    let recorded_checksum = read_u32(record, CHECKSUM_OFFSET);
    let calculated_checksum = crc32c(&record[..CHECKSUM_OFFSET]);
    if recorded_checksum != calculated_checksum {
        return Err(RecordError::ChecksumMismatch {
            recorded: recorded_checksum,
            calculated: calculated_checksum,
        });
    }
    let kind_code = read_u16(record, 12);
    let kind = EventKind::from_wire(kind_code).ok_or(RecordError::UnknownEventType(kind_code))?;
    let side_code = record[18];
    let side = EventSide::from_wire(side_code).ok_or(RecordError::InvalidSide(side_code))?;
    let domain_code = record[19];
    let sequence_domain = SequenceDomain::from_wire(domain_code)
        .ok_or(RecordError::InvalidSequenceDomain(domain_code))?;
    let mut blob = [0_u8; 32];
    blob.copy_from_slice(&record[144..176]);
    let mut event = NormalizedEvent::new_full(
        EventHeader {
            venue: VenueId(read_u16(record, 16)),
            instrument: InstrumentId(read_u32(record, 20)),
            sequence: Sequence(read_u64(record, 40)),
            exchange_timestamp: TimestampNs(read_u64(record, 56)),
            hardware_receive_timestamp: TimestampNs(read_u64(record, 64)),
        },
        EventSource::new(
            SourceId::new(read_u32(record, 24), read_u32(record, 28)),
            sequence_domain,
            SessionEpoch(read_u64(record, 32)),
        ),
        CaptureOrdinal(read_u64(record, 48)),
        MonotonicTimestampNs(read_u64(record, 72)),
        kind,
        side,
        read_u16(record, 14),
        OrderId(read_u64(record, 80)),
        read_u64(record, 88),
        read_u64(record, 96),
        PriceTicks(read_i64(record, 104)),
        Quantity(read_i64(record, 112)),
        Quantity(read_i64(record, 120)),
        read_u64(record, 128),
        read_u64(record, 136),
        blob,
    );
    if matches!(
        event.kind,
        EventKind::ControlArm
            | EventKind::ControlDisarm
            | EventKind::ControlHeartbeat
            | EventKind::ControlKill
    ) {
        event = event.with_control_origin(ControlEventOrigin::JournalReplay);
    }
    event.validate().map_err(RecordError::InvalidEvent)?;
    Ok((event, RECORD_LEN))
}

/// Stable non-cryptographic replay fingerprint.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReplayDigest {
    pub lane0: u64,
    pub lane1: u64,
}

/// Canonical caller contribution after consuming one event.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReplayContribution {
    pub state_digest: ReplayDigest,
    pub outbound_decision_digest: ReplayDigest,
}

/// Allocation-free callback failure code owned by the consumer implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayConsumerError(pub u32);

/// Caller-owned deterministic event consumer.
///
/// Implementations may update fixed-capacity book/strategy/order state and return
/// canonical non-cryptographic fingerprints of resulting state and outbound decisions.
pub trait ReplayConsumer {
    /// Consume one fully validated event.
    ///
    /// # Errors
    ///
    /// Return a stable nonzero error code when the caller state machine rejects it.
    fn on_event(
        &mut self,
        event: NormalizedEvent,
    ) -> Result<ReplayContribution, ReplayConsumerError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplaySummary {
    pub records: u64,
    pub streams: u32,
    pub last_capture_ordinal: CaptureOrdinal,
    pub last_receive_timestamp: TimestampNs,
    pub last_monotonic_timestamp: MonotonicTimestampNs,
    /// Fingerprint of normalized capture records, not a cryptographic digest.
    pub digest: ReplayDigest,
    /// Fingerprint of consumer-supplied state contributions.
    pub consumer_state_digest: ReplayDigest,
    /// Fingerprint of consumer-supplied outbound-decision contributions.
    pub outbound_decision_digest: ReplayDigest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundaryState {
    Recovery,
    Snapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundaryViolation {
    UnexpectedEvent,
    UnexpectedRecovery,
    InvalidRecoveryTarget,
    RecoveryIncomplete,
    SnapshotMismatch,
    SnapshotWouldBlessGap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayError {
    Record(RecordError),
    InvalidEvent(EventError),
    CaptureGap {
        expected: CaptureOrdinal,
        actual: CaptureOrdinal,
    },
    CaptureRegression {
        expected: CaptureOrdinal,
        actual: CaptureOrdinal,
    },
    SequenceGap {
        venue: VenueId,
        source: EventSource,
        expected: Sequence,
        actual: Sequence,
    },
    SequenceRegression {
        venue: VenueId,
        source: EventSource,
        expected: Sequence,
        actual: Sequence,
    },
    SequenceOverflow {
        venue: VenueId,
        source: EventSource,
    },
    SessionEpochRegression {
        venue: VenueId,
        source_id: SourceId,
        domain: SequenceDomain,
        highest: SessionEpoch,
        actual: SessionEpoch,
    },
    ExchangeTimestampRegression {
        venue: VenueId,
        source: EventSource,
        previous: TimestampNs,
        actual: TimestampNs,
    },
    ReceiveTimestampRegression {
        venue: VenueId,
        source: EventSource,
        previous: TimestampNs,
        actual: TimestampNs,
    },
    GlobalReceiveTimestampRegression {
        previous: TimestampNs,
        actual: TimestampNs,
    },
    GlobalMonotonicTimestampRegression {
        previous: MonotonicTimestampNs,
        actual: MonotonicTimestampNs,
    },
    Boundary {
        venue: VenueId,
        source: EventSource,
        kind: EventKind,
        violation: BoundaryViolation,
    },
    IncompleteBoundary {
        venue: VenueId,
        source: EventSource,
        state: BoundaryState,
    },
    StreamCapacity {
        capacity: usize,
    },
    Consumer(ReplayConsumerError),
    CounterOverflow,
    ReplayFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CursorPhase {
    Live,
    Recovering {
        through: Sequence,
    },
    Snapshot {
        snapshot_id: u64,
        anchor: Sequence,
        recovery: bool,
    },
}

#[derive(Clone, Copy, Debug)]
struct StreamCursor {
    occupied: bool,
    venue: VenueId,
    source: EventSource,
    last_sequence: Sequence,
    last_exchange_timestamp: TimestampNs,
    last_receive_timestamp: TimestampNs,
    phase: CursorPhase,
}

impl StreamCursor {
    const EMPTY: Self = Self {
        occupied: false,
        venue: VenueId(0),
        source: EventSource::new(
            SourceId::new(0, 0),
            SequenceDomain::MarketData,
            SessionEpoch(0),
        ),
        last_sequence: Sequence(0),
        last_exchange_timestamp: TimestampNs::ZERO,
        last_receive_timestamp: TimestampNs::ZERO,
        phase: CursorPhase::Live,
    };

    fn exact_source(self, event: NormalizedEvent) -> bool {
        self.occupied && self.venue == event.header.venue && self.source == event.source
    }

    fn same_base_source(self, event: NormalizedEvent) -> bool {
        self.occupied
            && self.venue == event.header.venue
            && self.source.id.protocol == event.source.id.protocol
            && self.source.id.channel == event.source.id.channel
            && self.source.sequence_domain == event.source.sequence_domain
    }
}

#[derive(Clone, Copy, Debug)]
struct ReplayPlan {
    cursor_update: Option<(usize, StreamCursor)>,
    records: u64,
    streams: u32,
}

#[derive(Clone, Copy, Debug)]
struct StableDigest {
    lane0: u64,
    lane1: u64,
}

impl StableDigest {
    const fn new(seed0: u64, seed1: u64) -> Self {
        Self {
            lane0: seed0,
            lane1: seed1,
        }
    }

    fn absorb(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.lane0 ^= u64::from(byte);
            self.lane0 = self.lane0.wrapping_mul(0x0000_0100_0000_01b3);
            self.lane1 ^= u64::from(byte).wrapping_add(0x9d);
            self.lane1 = self
                .lane1
                .rotate_left(11)
                .wrapping_mul(0x9e37_79b1_85eb_ca87)
                .wrapping_add(0x1656_67b1_9e37_79f9);
        }
    }

    fn absorb_event(&mut self, event: NormalizedEvent) {
        self.absorb(&(event.kind as u16).to_le_bytes());
        self.absorb(&event.flags.to_le_bytes());
        self.absorb(&event.header.venue.0.to_le_bytes());
        self.absorb(&[event.side as u8, event.source.sequence_domain as u8]);
        self.absorb(&event.header.instrument.0.to_le_bytes());
        self.absorb(&event.source.id.protocol.to_le_bytes());
        self.absorb(&event.source.id.channel.to_le_bytes());
        self.absorb(&event.source.session_epoch.0.to_le_bytes());
        self.absorb(&event.header.sequence.0.to_le_bytes());
        self.absorb(&event.capture_ordinal.0.to_le_bytes());
        self.absorb(&event.header.exchange_timestamp.0.to_le_bytes());
        self.absorb(&event.header.hardware_receive_timestamp.0.to_le_bytes());
        self.absorb(&event.monotonic_timestamp.0.to_le_bytes());
        self.absorb(&event.order_id.0.to_le_bytes());
        self.absorb(&event.secondary_id.to_le_bytes());
        self.absorb(&event.tertiary_id.to_le_bytes());
        self.absorb(&event.price.0.to_le_bytes());
        self.absorb(&event.quantity.0.to_le_bytes());
        self.absorb(&event.leaves_quantity.0.to_le_bytes());
        self.absorb(&event.reference.to_le_bytes());
        self.absorb(&event.auxiliary.to_le_bytes());
        self.absorb(&event.blob);
    }

    fn absorb_replay_digest(&mut self, digest: ReplayDigest) {
        self.absorb(&digest.lane0.to_le_bytes());
        self.absorb(&digest.lane1.to_le_bytes());
    }

    const fn finish(self, records: u64) -> ReplayDigest {
        ReplayDigest {
            lane0: avalanche(self.lane0 ^ records),
            lane1: avalanche(self.lane1 ^ records.rotate_left(29)),
        }
    }
}

#[derive(Debug)]
struct NoopConsumer;

impl ReplayConsumer for NoopConsumer {
    fn on_event(
        &mut self,
        _event: NormalizedEvent,
    ) -> Result<ReplayContribution, ReplayConsumerError> {
        Ok(ReplayContribution::default())
    }
}

/// Fixed-capacity validator keyed by actual `(venue, protocol, channel, domain, epoch)`
/// source. Instrument is intentionally absent from cursor identity.
#[derive(Debug)]
pub struct ReplayState<const MAX_STREAMS: usize> {
    cursors: [StreamCursor; MAX_STREAMS],
    expected_first_capture_ordinal: CaptureOrdinal,
    digest: StableDigest,
    consumer_state_digest: StableDigest,
    outbound_decision_digest: StableDigest,
    records: u64,
    streams: u32,
    last_capture_ordinal: CaptureOrdinal,
    last_global_receive_timestamp: TimestampNs,
    last_global_monotonic_timestamp: MonotonicTimestampNs,
    has_records: bool,
    failed: bool,
}

impl<const MAX_STREAMS: usize> ReplayState<MAX_STREAMS> {
    /// Backward-compatible constructor. The argument is the expected first global
    /// capture ordinal, not a per-source venue sequence.
    #[must_use]
    pub fn new(expected_first_capture_ordinal: Sequence) -> Self {
        Self::new_at(CaptureOrdinal(expected_first_capture_ordinal.0))
    }

    #[must_use]
    pub fn new_at(expected_first_capture_ordinal: CaptureOrdinal) -> Self {
        let mut digest = StableDigest::new(0xcbf2_9ce4_8422_2325, 0x6c62_272e_07bb_0142);
        digest.absorb(&JOURNAL_VERSION.to_le_bytes());
        let mut consumer_state_digest =
            StableDigest::new(0x243f_6a88_85a3_08d3, 0x1319_8a2e_0370_7344);
        consumer_state_digest.absorb(b"consumer-state-v5");
        let mut outbound_decision_digest =
            StableDigest::new(0xa409_3822_299f_31d0, 0x082e_fa98_ec4e_6c89);
        outbound_decision_digest.absorb(b"outbound-decision-v5");
        Self {
            cursors: [StreamCursor::EMPTY; MAX_STREAMS],
            expected_first_capture_ordinal,
            digest,
            consumer_state_digest,
            outbound_decision_digest,
            records: 0,
            streams: 0,
            last_capture_ordinal: CaptureOrdinal(0),
            last_global_receive_timestamp: TimestampNs::ZERO,
            last_global_monotonic_timestamp: MonotonicTimestampNs::ZERO,
            has_records: false,
            failed: false,
        }
    }

    #[must_use]
    pub const fn is_failed(&self) -> bool {
        self.failed
    }

    /// Decode, validate, and apply one record without a caller state machine.
    ///
    /// # Errors
    ///
    /// Any failure permanently latches the replay state.
    pub fn push_record(&mut self, input: &[u8]) -> Result<usize, ReplayError> {
        let mut consumer = NoopConsumer;
        self.push_record_with_consumer(input, &mut consumer)
    }

    /// Decode and apply one record through an allocation-free caller callback.
    ///
    /// # Errors
    ///
    /// Framing, semantic, or consumer errors permanently latch this replay state.
    pub fn push_record_with_consumer<C: ReplayConsumer>(
        &mut self,
        input: &[u8],
        consumer: &mut C,
    ) -> Result<usize, ReplayError> {
        if self.failed {
            return Err(ReplayError::ReplayFailed);
        }
        let (event, bytes_read) = match decode_record(input) {
            Ok(value) => value,
            Err(error) => return self.latch(ReplayError::Record(error)),
        };
        self.apply_with_consumer(event, consumer)?;
        Ok(bytes_read)
    }

    /// Apply one decoded event without a caller state machine.
    ///
    /// # Errors
    ///
    /// Any event, sequence, capture-order, timestamp, boundary, or capacity failure
    /// permanently latches this replay state.
    pub fn apply(&mut self, event: NormalizedEvent) -> Result<(), ReplayError> {
        let mut consumer = NoopConsumer;
        self.apply_with_consumer(event, &mut consumer)
    }

    /// Validate then deliver one event to `consumer` and commit replay metadata.
    /// Replay metadata is not committed if the consumer rejects the event.
    ///
    /// # Errors
    ///
    /// Returns and latches a replay or consumer failure.
    pub fn apply_with_consumer<C: ReplayConsumer>(
        &mut self,
        event: NormalizedEvent,
        consumer: &mut C,
    ) -> Result<(), ReplayError> {
        if self.failed {
            return Err(ReplayError::ReplayFailed);
        }
        if let Err(error) = event.validate() {
            return self.latch(ReplayError::InvalidEvent(error));
        }
        let plan = match self.plan_event(event) {
            Ok(plan) => plan,
            Err(error) => return self.latch(error),
        };
        let contribution = match consumer.on_event(event) {
            Ok(contribution) => contribution,
            Err(error) => return self.latch(ReplayError::Consumer(error)),
        };

        if let Some((cursor_index, cursor)) = plan.cursor_update {
            self.cursors[cursor_index] = cursor;
        }
        self.records = plan.records;
        self.streams = plan.streams;
        self.last_capture_ordinal = event.capture_ordinal;
        if !event.kind.is_local() {
            self.last_global_receive_timestamp = event.header.hardware_receive_timestamp;
        }
        if event.monotonic_timestamp != MonotonicTimestampNs::ZERO {
            self.last_global_monotonic_timestamp = event.monotonic_timestamp;
        }
        self.has_records = true;
        self.digest.absorb_event(event);
        self.consumer_state_digest
            .absorb_replay_digest(contribution.state_digest);
        self.outbound_decision_digest
            .absorb_replay_digest(contribution.outbound_decision_digest);
        Ok(())
    }

    /// Produce a summary only after every recovery/snapshot boundary is closed.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayError::ReplayFailed`] after a prior failure or
    /// [`ReplayError::IncompleteBoundary`] for a truncated semantic transaction.
    pub fn finish(&self) -> Result<ReplaySummary, ReplayError> {
        if self.failed {
            return Err(ReplayError::ReplayFailed);
        }
        for cursor in self.cursors.iter().filter(|cursor| cursor.occupied) {
            let state = match cursor.phase {
                CursorPhase::Live => continue,
                CursorPhase::Recovering { .. } => BoundaryState::Recovery,
                CursorPhase::Snapshot { .. } => BoundaryState::Snapshot,
            };
            return Err(ReplayError::IncompleteBoundary {
                venue: cursor.venue,
                source: cursor.source,
                state,
            });
        }
        Ok(ReplaySummary {
            records: self.records,
            streams: self.streams,
            last_capture_ordinal: self.last_capture_ordinal,
            last_receive_timestamp: self.last_global_receive_timestamp,
            last_monotonic_timestamp: self.last_global_monotonic_timestamp,
            digest: self.digest.finish(self.records),
            consumer_state_digest: self.consumer_state_digest.finish(self.records),
            outbound_decision_digest: self.outbound_decision_digest.finish(self.records),
        })
    }

    fn plan_event(&self, event: NormalizedEvent) -> Result<ReplayPlan, ReplayError> {
        self.check_capture_ordinal(event)?;
        if event.monotonic_timestamp != MonotonicTimestampNs::ZERO
            && self.last_global_monotonic_timestamp != MonotonicTimestampNs::ZERO
            && event.monotonic_timestamp < self.last_global_monotonic_timestamp
        {
            return Err(ReplayError::GlobalMonotonicTimestampRegression {
                previous: self.last_global_monotonic_timestamp,
                actual: event.monotonic_timestamp,
            });
        }
        let records = self
            .records
            .checked_add(1)
            .ok_or(ReplayError::CounterOverflow)?;
        if event.kind.is_local() {
            return Ok(ReplayPlan {
                cursor_update: None,
                records,
                streams: self.streams,
            });
        }
        if self.has_records
            && self.last_global_receive_timestamp != TimestampNs::ZERO
            && event.header.hardware_receive_timestamp < self.last_global_receive_timestamp
        {
            return Err(ReplayError::GlobalReceiveTimestampRegression {
                previous: self.last_global_receive_timestamp,
                actual: event.header.hardware_receive_timestamp,
            });
        }
        self.check_session_epoch(event)?;
        let existing = self
            .cursors
            .iter()
            .position(|cursor| cursor.exact_source(event));
        let (cursor_index, prior, new_stream) = if let Some(index) = existing {
            (index, self.cursors[index], false)
        } else {
            let Some(index) = self.cursors.iter().position(|cursor| !cursor.occupied) else {
                return Err(ReplayError::StreamCapacity {
                    capacity: MAX_STREAMS,
                });
            };
            (
                index,
                StreamCursor {
                    occupied: true,
                    venue: event.header.venue,
                    source: event.source,
                    ..StreamCursor::EMPTY
                },
                true,
            )
        };
        if !new_stream {
            Self::check_source_timestamps(prior, event)?;
        }
        let cursor = Self::transition_cursor(prior, event, new_stream)?;
        let streams = if new_stream {
            self.streams
                .checked_add(1)
                .ok_or(ReplayError::CounterOverflow)?
        } else {
            self.streams
        };
        Ok(ReplayPlan {
            cursor_update: Some((
                cursor_index,
                StreamCursor {
                    last_exchange_timestamp: event.header.exchange_timestamp,
                    last_receive_timestamp: event.header.hardware_receive_timestamp,
                    ..cursor
                },
            )),
            records,
            streams,
        })
    }

    fn check_capture_ordinal(&self, event: NormalizedEvent) -> Result<(), ReplayError> {
        let expected = if self.has_records {
            CaptureOrdinal(
                self.last_capture_ordinal
                    .0
                    .checked_add(1)
                    .ok_or(ReplayError::CounterOverflow)?,
            )
        } else {
            self.expected_first_capture_ordinal
        };
        if event.capture_ordinal == expected {
            return Ok(());
        }
        if event.capture_ordinal < expected {
            Err(ReplayError::CaptureRegression {
                expected,
                actual: event.capture_ordinal,
            })
        } else {
            Err(ReplayError::CaptureGap {
                expected,
                actual: event.capture_ordinal,
            })
        }
    }

    fn check_session_epoch(&self, event: NormalizedEvent) -> Result<(), ReplayError> {
        let highest = self
            .cursors
            .iter()
            .filter(|cursor| cursor.same_base_source(event))
            .map(|cursor| cursor.source.session_epoch)
            .max();
        if let Some(highest) = highest
            && event.source.session_epoch < highest
        {
            return Err(ReplayError::SessionEpochRegression {
                venue: event.header.venue,
                source_id: event.source.id,
                domain: event.source.sequence_domain,
                highest,
                actual: event.source.session_epoch,
            });
        }
        Ok(())
    }

    fn check_source_timestamps(
        cursor: StreamCursor,
        event: NormalizedEvent,
    ) -> Result<(), ReplayError> {
        if event.header.exchange_timestamp < cursor.last_exchange_timestamp {
            return Err(ReplayError::ExchangeTimestampRegression {
                venue: event.header.venue,
                source: event.source,
                previous: cursor.last_exchange_timestamp,
                actual: event.header.exchange_timestamp,
            });
        }
        if event.header.hardware_receive_timestamp < cursor.last_receive_timestamp {
            return Err(ReplayError::ReceiveTimestampRegression {
                venue: event.header.venue,
                source: event.source,
                previous: cursor.last_receive_timestamp,
                actual: event.header.hardware_receive_timestamp,
            });
        }
        Ok(())
    }

    fn transition_cursor(
        cursor: StreamCursor,
        event: NormalizedEvent,
        new_stream: bool,
    ) -> Result<StreamCursor, ReplayError> {
        if new_stream {
            return Self::start_cursor(cursor, event);
        }
        match cursor.phase {
            CursorPhase::Live => Self::transition_live(cursor, event),
            CursorPhase::Recovering { through } => {
                Self::transition_recovery(cursor, event, through)
            }
            CursorPhase::Snapshot {
                snapshot_id,
                anchor,
                recovery,
            } => Self::transition_snapshot(cursor, event, snapshot_id, anchor, recovery),
        }
    }

    fn start_cursor(
        mut cursor: StreamCursor,
        event: NormalizedEvent,
    ) -> Result<StreamCursor, ReplayError> {
        if event.kind == EventKind::SnapshotStart && !event.is_recovery() {
            cursor.phase = CursorPhase::Snapshot {
                snapshot_id: event.reference,
                anchor: event.header.sequence,
                recovery: false,
            };
            return Ok(cursor);
        }
        if event.kind.is_boundary() || event.is_snapshot() || event.is_recovery() {
            return Err(Self::boundary_error(
                event,
                BoundaryViolation::UnexpectedEvent,
            ));
        }
        Self::check_sequence(event, Sequence(1))?;
        cursor.last_sequence = event.header.sequence;
        Ok(cursor)
    }

    fn transition_live(
        mut cursor: StreamCursor,
        event: NormalizedEvent,
    ) -> Result<StreamCursor, ReplayError> {
        let expected = Self::next_source_sequence(cursor, event)?;
        match event.kind {
            EventKind::RecoveryStart => {
                Self::check_sequence(event, expected)?;
                let through = Sequence(event.reference);
                if through < expected {
                    return Err(Self::boundary_error(
                        event,
                        BoundaryViolation::InvalidRecoveryTarget,
                    ));
                }
                cursor.phase = CursorPhase::Recovering { through };
                Ok(cursor)
            }
            EventKind::SnapshotStart => {
                if event.is_recovery() {
                    return Err(Self::boundary_error(
                        event,
                        BoundaryViolation::SnapshotWouldBlessGap,
                    ));
                }
                Self::check_sequence(event, expected)?;
                cursor.phase = CursorPhase::Snapshot {
                    snapshot_id: event.reference,
                    anchor: event.header.sequence,
                    recovery: false,
                };
                Ok(cursor)
            }
            EventKind::RecoveryEnd | EventKind::SnapshotEnd => Err(Self::boundary_error(
                event,
                BoundaryViolation::UnexpectedEvent,
            )),
            _ if event.is_snapshot() || event.is_recovery() => Err(Self::boundary_error(
                event,
                BoundaryViolation::UnexpectedRecovery,
            )),
            _ => {
                Self::check_sequence(event, expected)?;
                cursor.last_sequence = event.header.sequence;
                Ok(cursor)
            }
        }
    }

    fn transition_recovery(
        mut cursor: StreamCursor,
        event: NormalizedEvent,
        through: Sequence,
    ) -> Result<StreamCursor, ReplayError> {
        let expected = Self::next_source_sequence(cursor, event)?;
        match event.kind {
            EventKind::RecoveryEnd => {
                if cursor.last_sequence != through
                    || event.reference != through.0
                    || event.header.sequence != expected
                {
                    return Err(Self::boundary_error(
                        event,
                        BoundaryViolation::RecoveryIncomplete,
                    ));
                }
                cursor.phase = CursorPhase::Live;
                Ok(cursor)
            }
            EventKind::SnapshotStart => {
                if !event.is_snapshot() || !event.is_recovery() || event.header.sequence < through {
                    return Err(Self::boundary_error(
                        event,
                        BoundaryViolation::SnapshotWouldBlessGap,
                    ));
                }
                cursor.phase = CursorPhase::Snapshot {
                    snapshot_id: event.reference,
                    anchor: event.header.sequence,
                    recovery: true,
                };
                Ok(cursor)
            }
            EventKind::RecoveryStart | EventKind::SnapshotEnd => Err(Self::boundary_error(
                event,
                BoundaryViolation::UnexpectedEvent,
            )),
            _ => {
                if event.flags != EVENT_FLAG_RECOVERY || event.header.sequence > through {
                    return Err(Self::boundary_error(
                        event,
                        BoundaryViolation::UnexpectedRecovery,
                    ));
                }
                Self::check_sequence(event, expected)?;
                cursor.last_sequence = event.header.sequence;
                Ok(cursor)
            }
        }
    }

    fn transition_snapshot(
        mut cursor: StreamCursor,
        event: NormalizedEvent,
        snapshot_id: u64,
        anchor: Sequence,
        recovery: bool,
    ) -> Result<StreamCursor, ReplayError> {
        let expected_flags = if recovery {
            EVENT_FLAG_SNAPSHOT | EVENT_FLAG_RECOVERY
        } else {
            EVENT_FLAG_SNAPSHOT
        };
        if event.kind == EventKind::SnapshotEnd {
            if event.flags != expected_flags
                || event.header.sequence != anchor
                || event.reference != snapshot_id
            {
                return Err(Self::boundary_error(
                    event,
                    BoundaryViolation::SnapshotMismatch,
                ));
            }
            cursor.last_sequence = anchor;
            cursor.phase = CursorPhase::Live;
            return Ok(cursor);
        }
        if event.kind != EventKind::BookAdd
            || event.flags != expected_flags
            || event.header.sequence != anchor
            || event.reference != snapshot_id
        {
            return Err(Self::boundary_error(
                event,
                BoundaryViolation::SnapshotMismatch,
            ));
        }
        Ok(cursor)
    }

    fn next_source_sequence(
        cursor: StreamCursor,
        event: NormalizedEvent,
    ) -> Result<Sequence, ReplayError> {
        cursor
            .last_sequence
            .0
            .checked_add(1)
            .map(Sequence)
            .ok_or(ReplayError::SequenceOverflow {
                venue: event.header.venue,
                source: event.source,
            })
    }

    fn check_sequence(event: NormalizedEvent, expected: Sequence) -> Result<(), ReplayError> {
        if event.header.sequence == expected {
            return Ok(());
        }
        if event.header.sequence < expected {
            Err(ReplayError::SequenceRegression {
                venue: event.header.venue,
                source: event.source,
                expected,
                actual: event.header.sequence,
            })
        } else {
            Err(ReplayError::SequenceGap {
                venue: event.header.venue,
                source: event.source,
                expected,
                actual: event.header.sequence,
            })
        }
    }

    const fn boundary_error(event: NormalizedEvent, violation: BoundaryViolation) -> ReplayError {
        ReplayError::Boundary {
            venue: event.header.venue,
            source: event.source,
            kind: event.kind,
            violation,
        }
    }

    fn latch<T>(&mut self, error: ReplayError) -> Result<T, ReplayError> {
        self.failed = true;
        Err(error)
    }
}

/// Validate a contiguous journal and return its deterministic summary.
///
/// The `Sequence` argument is retained for API compatibility but denotes the expected
/// first global capture ordinal in v5.
///
/// # Errors
///
/// Returns the first framing, corruption, sequence, timestamp, boundary, capacity, or
/// counter error. No summary is returned for partially valid input.
pub fn replay_bytes<const MAX_STREAMS: usize>(
    input: &[u8],
    expected_first_capture_ordinal: Sequence,
) -> Result<ReplaySummary, ReplayError> {
    let mut state = ReplayState::<MAX_STREAMS>::new(expected_first_capture_ordinal);
    let mut offset = 0_usize;
    while offset < input.len() {
        let consumed = state.push_record(&input[offset..])?;
        offset = offset
            .checked_add(consumed)
            .ok_or(ReplayError::CounterOverflow)?;
    }
    state.finish()
}

/// Replay a contiguous journal through a caller-owned allocation-free consumer.
///
/// # Errors
///
/// Returns the first journal, semantic, or consumer failure.
pub fn replay_bytes_with_consumer<const MAX_STREAMS: usize, C: ReplayConsumer>(
    input: &[u8],
    expected_first_capture_ordinal: CaptureOrdinal,
    consumer: &mut C,
) -> Result<ReplaySummary, ReplayError> {
    let mut state = ReplayState::<MAX_STREAMS>::new_at(expected_first_capture_ordinal);
    let mut offset = 0_usize;
    while offset < input.len() {
        let bytes_read = state.push_record_with_consumer(&input[offset..], consumer)?;
        offset = offset
            .checked_add(bytes_read)
            .ok_or(ReplayError::CounterOverflow)?;
    }
    state.finish()
}

const fn avalanche(mut value: u64) -> u64 {
    value ^= value >> 33;
    value = value.wrapping_mul(0xff51_afd7_ed55_8ccd);
    value ^= value >> 33;
    value = value.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    value ^ (value >> 33)
}

fn write_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_i64(output: &mut [u8], offset: usize, value: i64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn read_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([input[offset], input[offset + 1]])
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ])
}

fn read_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
        input[offset + 4],
        input[offset + 5],
        input[offset + 6],
        input[offset + 7],
    ])
}

fn read_i64(input: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
        input[offset + 4],
        input[offset + 5],
        input[offset + 6],
        input[offset + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::crc32c;

    #[test]
    fn crc32c_matches_standard_check_value() {
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    }
}
