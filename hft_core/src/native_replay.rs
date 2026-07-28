//! Allocation-free verification at the venue-native capture boundary.
//!
//! This module binds caller-owned native packet bytes to the normalized events
//! consumed by the deterministic core. It deliberately defines neither a disk
//! format nor a packet-capture transport. Capture-metadata and journal authenticity,
//! plus the concrete transport-proof implementation, remain external certification
//! inputs. Successful verification is not proof of NIC, kernel-bypass, clock,
//! exchange, or colocation certification.

use crate::engine::TransmissionStatus;
use crate::event_codec::{
    EventCodecError, SnapshotCaptureMetadata, VenueCaptureMetadata, decode_owned_mbo_binding,
    decode_transmission, normalize_market_data, normalize_order_entry, normalize_owned_mbo_binding,
    normalize_snapshot, normalize_transmission,
};
use crate::events::{CaptureOrdinal, EventSource, NormalizedEvent, SequenceDomain};
use crate::reactor::{
    MAX_REACTOR_COMMANDS_PER_INPUT, OwnedMboBindingInput, ReactorEgress, TransmissionInput,
};
use crate::reactor_audit::{
    SCHEDULER_COMMIT_RECORD_LEN, SchedulerCommit, SchedulerCommitError, SchedulerRoute,
    encode_scheduler_commit,
};
use crate::types::{MonotonicTimestampNs, Sequence, TimestampNs};
use crate::venue::{
    CorrelationResult, DirectExactMboVenueAdapter, DirectMarketDataDecoder, InboundMessage,
    MarketDataFeed, MarketDataMessage, NativeOrderEntryDecoder, NativeOrderEntryEncoder,
    OrderCommand, OwnedMboBinding, SnapshotMessage, SnapshotPayload, VenueError, VenueIdentity,
    VenueSession, validate_exact_mbo_adapter,
};

/// Native ingress protocol lane represented by one captured frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeIngressLane {
    MarketData,
    Snapshot,
    OrderEntry,
}

/// Capture metadata supplied by the native packet acquisition layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativePacketMetadata {
    /// Gapless ordinal shared by ingress and encoded-order capture records.
    pub frame_ordinal: u64,
    /// Exact protocol and session descriptor under which `packet` is interpreted.
    pub adapter_identity: VenueIdentity,
    pub source: EventSource,
    pub hardware_receive_timestamp: TimestampNs,
    pub monotonic_timestamp: MonotonicTimestampNs,
    pub recovery: bool,
}

/// Borrowed native packet and the exact normalized events attributed to it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeIngressCapture<'a> {
    pub metadata: NativePacketMetadata,
    pub lane: NativeIngressLane,
    pub packet: &'a [u8],
    pub expected_events: &'a [NormalizedEvent],
}

/// Native ingress plus the exact local owned-MBO events derived by the adapter.
///
/// `ingress.expected_events` remains venue-only. `expected_bindings` contains only
/// canonical local [`crate::events::EventKind::OwnedMboBinding`] events. Logical
/// capture order is, for each decoded message, its venue event followed by every
/// binding returned for that message in correlation-slot order. Ordinal gaps in the
/// venue-only slice therefore bind local events to the exact message that proved
/// them without an allocation or a parallel count table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeOwnedMboIngressCapture<'a> {
    pub ingress: NativeIngressCapture<'a>,
    pub expected_bindings: &'a [NormalizedEvent],
}

/// Exact totals committed by one correlated native ingress frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeOwnedMboReplayResult {
    pub messages: usize,
    pub bindings: usize,
}

/// Caller-owned snapshot transaction context for one [`MarketDataFeed`].
///
/// Snapshot orders do not carry their transaction identity or incremental anchor,
/// so native verification must retain the matching begin values across packet
/// boundaries. Keep one context per feed; it is deliberately not global verifier
/// state because a capture stream may interleave independent feeds.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeSnapshotContext {
    active_snapshot_id: Option<u64>,
    last_incremental_sequence: Option<Sequence>,
}

impl NativeSnapshotContext {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            active_snapshot_id: None,
            last_incremental_sequence: None,
        }
    }

    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(
            (self.active_snapshot_id, self.last_incremental_sequence),
            (Some(_), Some(_))
        )
    }

    #[must_use]
    pub const fn active_snapshot_id(self) -> Option<u64> {
        self.active_snapshot_id
    }

    #[must_use]
    pub const fn last_incremental_sequence(self) -> Option<Sequence> {
        self.last_incremental_sequence
    }
}

/// Borrowed proof material for one encoded order frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeOrderEgressCapture<'a> {
    pub frame_ordinal: u64,
    pub scheduler_commit_ordinal: u64,
    /// Exact canonical source event named by the scheduler commit. Safety-kill
    /// commits are source-less and must carry `None` here.
    pub scheduler_source_event: Option<NormalizedEvent>,
    pub egress: ReactorEgress,
    /// Exact protocol and session descriptor under which `encoded_bytes` was formed.
    pub adapter_identity: VenueIdentity,
    pub venue_sequence: Sequence,
    pub encoded_bytes: &'a [u8],
    /// Audited causal lower bound used when constructing the canonical
    /// transmission event. It equals the raw transport timestamp on the ordinary
    /// path, but may be higher after a zero/regressing transport-clock fallback.
    /// The authoritative global event sequencer may raise the event timestamp
    /// again to preserve capture-order monotonicity.
    pub transmission_minimum_monotonic: MonotonicTimestampNs,
    /// Canonical local event recording the transport disposition of `egress`.
    pub transmission_event: NormalizedEvent,
}

/// Exact fixed context a transport-owned verifier must bind to its opaque proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeTransmissionContext<'a> {
    pub frame_ordinal: u64,
    pub adapter_identity: VenueIdentity,
    pub venue_sequence: Sequence,
    pub scheduler_commit_ordinal: u64,
    pub scheduler_capture_ordinal: CaptureOrdinal,
    pub scheduler_source_event_crc32c: u32,
    pub egress: ReactorEgress,
    /// Exact successfully encoded prefix. No uninitialized or trailing capacity is
    /// exposed to the proof verifier.
    pub encoded_bytes: &'a [u8],
}

/// Transport-owned result used to construct canonical transmission feedback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeTransmissionDisposition {
    pub status: TransmissionStatus,
    pub monotonic_now: MonotonicTimestampNs,
}

/// Fixed proof failure classes. Ambiguity is never converted into `ProvenUnsent`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeTransmissionProofError {
    Rejected,
    Ambiguous,
}

/// Transactional, transport-owned verification of an opaque send-disposition proof.
///
/// The checkpoint must cover every mutable transport counter, descriptor, completion,
/// and anti-replay datum consulted by [`Self::verify`]. A returned
/// [`TransmissionStatus::ProvenUnsent`] is an irrevocable guarantee that no byte of
/// `context.encoded_bytes` was submitted to, consumed by, or made observable to the
/// peer. Missing acknowledgements, timeouts, and ambiguous queue ownership do not
/// satisfy that contract and must return [`NativeTransmissionProofError::Ambiguous`].
/// A production implementation and its proof provenance require independent external
/// certification; co-locating submission and verification in one concrete transport
/// object is not evidence of independence, and callers cannot substitute a
/// [`TransmissionInput`] as proof.
/// Live callers checkpoint after submission. Therefore restoring a failed live
/// verification must retain all post-submit descriptor ownership and submission
/// state: it must never erase, rewind, or make a submitted sequence reusable.
pub trait NativeTransmissionProofVerifier {
    type Proof: ?Sized;
    type Checkpoint: Copy;

    fn checkpoint(&self) -> Self::Checkpoint;
    fn restore(&mut self, checkpoint: Self::Checkpoint);
    fn commit(&mut self, _checkpoint: Self::Checkpoint) {}

    /// Verify `proof` against every field and byte in `context`.
    ///
    /// # Errors
    ///
    /// Returns a fixed rejection or ambiguity class without committing verifier
    /// state. The native replay boundary restores the supplied checkpoint after any
    /// later frame error.
    fn verify(
        &mut self,
        context: NativeTransmissionContext<'_>,
        proof: &Self::Proof,
    ) -> Result<NativeTransmissionDisposition, NativeTransmissionProofError>;
}

/// Fail-closed native replay verification error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeReplayError {
    Failed,
    CorpusFinished,
    InvalidInitialFrameOrdinal(u64),
    FrameOrdinalMismatch {
        expected: u64,
        received: u64,
    },
    FrameOrdinalExhausted(u64),
    LaneMismatch {
        expected: NativeIngressLane,
        received: NativeIngressLane,
    },
    AdapterIdentityMismatch {
        expected: VenueIdentity,
        received: VenueIdentity,
    },
    SequenceDomainMismatch {
        lane: NativeIngressLane,
        received: SequenceDomain,
    },
    SourceProtocolMismatch {
        expected: u32,
        received: u32,
    },
    InvalidSource(EventSource),
    InvalidHardwareReceiveTimestamp(TimestampNs),
    InvalidMonotonicTimestamp(MonotonicTimestampNs),
    EmptyPacket,
    EmptyDecodeBuffer,
    EmptyEncodeBuffer,
    DirtyDecodedTail {
        index: usize,
    },
    OwnedMboBufferTooSmall {
        expected: usize,
        provided: usize,
    },
    OwnedMboCorrelationCountOutOfRange {
        reported: usize,
        available: usize,
    },
    EmptyOwnedMboBindingSlot {
        index: usize,
    },
    DirtyOwnedMboBindingTail {
        index: usize,
    },
    DirtyEncodedTail {
        index: usize,
    },
    ByteOffsetOverflow,
    EventCountOverflow,
    EventCountMismatch {
        expected: usize,
        actual: usize,
    },
    ExpectedEventMetadataMismatch {
        index: usize,
    },
    ExpectedOwnedMboEventMismatch {
        index: usize,
    },
    OwnedMboVenueMismatch {
        index: usize,
        expected: crate::types::VenueId,
        received: crate::types::VenueId,
    },
    OwnedMboBindingEventMismatch {
        index: usize,
    },
    OwnedMboEventCountMismatch {
        expected: usize,
        actual: usize,
    },
    SnapshotAlreadyActive {
        active_snapshot_id: u64,
        last_incremental_sequence: Sequence,
    },
    SnapshotContextMissing,
    SnapshotContextMismatch {
        expected_snapshot_id: u64,
        received_snapshot_id: u64,
        expected_last_incremental_sequence: Sequence,
        received_last_incremental_sequence: Sequence,
    },
    NormalizedEventMismatch {
        index: usize,
    },
    InvalidCaptureOrdinal(CaptureOrdinal),
    CaptureOrdinalRegression {
        previous: CaptureOrdinal,
        received: CaptureOrdinal,
    },
    CaptureOrdinalNotContiguous {
        expected: CaptureOrdinal,
        received: CaptureOrdinal,
    },
    CorrelatedCaptureOrdinalMismatch {
        expected: CaptureOrdinal,
        received: CaptureOrdinal,
    },
    CaptureOrdinalExhausted(CaptureOrdinal),
    InvalidSchedulerCommitOrdinal(u64),
    SchedulerCommitOrdinalMismatch {
        expected: u64,
        received: u64,
    },
    EgressMismatch,
    InvalidCommandIndex(u8),
    MissingSchedulerSource,
    UnexpectedSchedulerSource,
    SchedulerSourceNotBeforeTransmission {
        source: CaptureOrdinal,
        transmission: CaptureOrdinal,
    },
    MissingEgressInputOrdinal,
    EgressInputOrdinalMismatch,
    MissingSchedulerCommand(u8),
    SchedulerCommandMismatch(u8),
    OrphanSchedulerCommand {
        commit_ordinal: u64,
        command_index: u8,
    },
    SchedulerCommandIndexMismatch {
        expected: u8,
        received: u8,
    },
    SchedulerCommitRegression {
        previous: u64,
        received: u64,
    },
    SchedulerCommitInProgress {
        expected: u64,
        received: u64,
    },
    SchedulerCommitMutation(u64),
    IncompleteSchedulerCommit {
        commit_ordinal: u64,
        next_command_index: u8,
    },
    InvalidVenueSequence(Sequence),
    VenueSequenceMismatch {
        expected: Sequence,
        received: Sequence,
    },
    EncodedLengthMismatch {
        expected: usize,
        actual: usize,
    },
    EncodedByteMismatch {
        index: usize,
    },
    TransmissionCommandMismatch,
    InvalidTransmissionMinimum(MonotonicTimestampNs),
    TransmissionMinimumBeforeTransport {
        minimum: MonotonicTimestampNs,
        transport: MonotonicTimestampNs,
    },
    TransmissionEventBeforeMinimum {
        minimum: MonotonicTimestampNs,
        event: MonotonicTimestampNs,
    },
    TransmissionEventMismatch,
    TransmissionProof(NativeTransmissionProofError),
    SchedulerCommit(SchedulerCommitError),
    Venue(VenueError),
    EventCodec(EventCodecError),
}

impl From<VenueError> for NativeReplayError {
    fn from(error: VenueError) -> Self {
        Self::Venue(error)
    }
}

impl From<EventCodecError> for NativeReplayError {
    fn from(error: EventCodecError) -> Self {
        Self::EventCodec(error)
    }
}

impl From<NativeTransmissionProofError> for NativeReplayError {
    fn from(error: NativeTransmissionProofError) -> Self {
        Self::TransmissionProof(error)
    }
}

impl From<SchedulerCommitError> for NativeReplayError {
    fn from(error: SchedulerCommitError) -> Self {
        Self::SchedulerCommit(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SchedulerOutputState {
    pending_commit: Option<SchedulerCommit>,
    next_command_index: u8,
    last_completed_commit_ordinal: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CorrelatedOrdinalRange {
    first: Option<CaptureOrdinal>,
    last: Option<CaptureOrdinal>,
}

/// Gapless, fail-latched verifier for native ingress and encoded order frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeReplayVerifier {
    next_frame_ordinal: u64,
    last_capture_ordinal: Option<CaptureOrdinal>,
    scheduler_output: SchedulerOutputState,
    corpus_finished: bool,
    failed: bool,
}

impl NativeReplayVerifier {
    /// Create a verifier at the first frame ordinal in the caller's capture range.
    ///
    /// # Errors
    ///
    /// Returns [`NativeReplayError::InvalidInitialFrameOrdinal`] for zero.
    pub const fn new(first_frame_ordinal: u64) -> Result<Self, NativeReplayError> {
        if first_frame_ordinal == 0 {
            return Err(NativeReplayError::InvalidInitialFrameOrdinal(
                first_frame_ordinal,
            ));
        }
        Ok(Self {
            next_frame_ordinal: first_frame_ordinal,
            last_capture_ordinal: None,
            scheduler_output: SchedulerOutputState {
                pending_commit: None,
                next_command_index: 0,
                last_completed_commit_ordinal: None,
            },
            corpus_finished: false,
            failed: false,
        })
    }

    #[must_use]
    pub const fn next_frame_ordinal(self) -> u64 {
        self.next_frame_ordinal
    }

    #[must_use]
    pub const fn failed(self) -> bool {
        self.failed
    }

    #[must_use]
    pub const fn corpus_finished(self) -> bool {
        self.corpus_finished
    }

    #[must_use]
    pub const fn last_capture_ordinal(self) -> Option<CaptureOrdinal> {
        self.last_capture_ordinal
    }

    /// Verify that the native corpus does not end between command slots of one
    /// scheduler commit.
    ///
    /// This detects only mid-commit truncation after at least one command from a
    /// multi-command commit was accepted. Detecting wholly omitted commits requires
    /// an authenticated corpus manifest and a complete authenticated scheduler-commit
    /// stream, which remain external certification inputs.
    ///
    /// # Errors
    ///
    /// Returns [`NativeReplayError::IncompleteSchedulerCommit`] and permanently
    /// latches failure when another command slot is pending. A previously failed
    /// verifier returns [`NativeReplayError::Failed`].
    pub fn finish_corpus(&mut self) -> Result<(), NativeReplayError> {
        if self.failed {
            return Err(NativeReplayError::Failed);
        }
        if self.corpus_finished {
            return Err(self.latch(NativeReplayError::CorpusFinished));
        }
        if let Some(commit) = self.scheduler_output.pending_commit {
            let error = NativeReplayError::IncompleteSchedulerCommit {
                commit_ordinal: commit.commit_ordinal,
                next_command_index: self.scheduler_output.next_command_index,
            };
            return Err(self.latch(error));
        }
        self.corpus_finished = true;
        Ok(())
    }

    /// Decode every byte in a native incremental frame and compare every
    /// normalization with its exact expected event.
    ///
    /// `decoded` is caller-owned and may be smaller than the number of messages in
    /// the packet. The decoder is called repeatedly until the packet is consumed.
    ///
    /// # Errors
    ///
    /// Any frame, metadata, venue, decoder, normalization, count, or equality fault
    /// permanently latches this verifier.
    pub fn verify_market_data<A: DirectMarketDataDecoder>(
        &mut self,
        feed: &mut MarketDataFeed,
        adapter: &mut A,
        capture: NativeIngressCapture<'_>,
        decoded: &mut [Option<MarketDataMessage>],
    ) -> Result<usize, NativeReplayError> {
        decoded.fill(None);
        let next = self.preflight_frame(capture.metadata.frame_ordinal)?;
        let capture_end = match self.preflight_capture_ordinals(capture.expected_events) {
            Ok(end) => end,
            Err(error) => return Err(self.latch(error)),
        };
        let feed_checkpoint = *feed;
        let adapter_checkpoint = adapter.checkpoint();
        let result = verify_market_data_inner(feed, adapter, capture, decoded);
        match result {
            Ok(events) => {
                adapter.commit(adapter_checkpoint);
                self.commit_frame(next, capture_end);
                Ok(events)
            }
            Err(error) => {
                *feed = feed_checkpoint;
                adapter.restore(adapter_checkpoint);
                decoded.fill(None);
                Err(self.latch(error))
            }
        }
    }

    /// Decode every byte in a native snapshot frame and compare every
    /// normalization with its exact expected event.
    ///
    /// `context` belongs to `feed` and carries a matching begin transaction across
    /// frames until its exact end is verified. It is committed only after the whole
    /// captured frame succeeds. `decoded` is caller-owned and may be smaller than
    /// the number of messages in the packet, so decoding repeats until every byte
    /// is consumed.
    ///
    /// # Errors
    ///
    /// Any frame, metadata, venue, decoder, snapshot-boundary, normalization,
    /// count, or equality fault permanently latches this verifier.
    pub fn verify_snapshot<A: DirectMarketDataDecoder>(
        &mut self,
        feed: &mut MarketDataFeed,
        adapter: &mut A,
        context: &mut NativeSnapshotContext,
        capture: NativeIngressCapture<'_>,
        decoded: &mut [Option<SnapshotMessage>],
    ) -> Result<usize, NativeReplayError> {
        decoded.fill(None);
        let next = self.preflight_frame(capture.metadata.frame_ordinal)?;
        let capture_end = match self.preflight_capture_ordinals(capture.expected_events) {
            Ok(end) => end,
            Err(error) => return Err(self.latch(error)),
        };
        let feed_checkpoint = *feed;
        let adapter_checkpoint = adapter.checkpoint();
        let mut candidate = *context;
        let result = verify_snapshot_inner(feed, adapter, &mut candidate, capture, decoded);
        match result {
            Ok(events) => {
                adapter.commit(adapter_checkpoint);
                *context = candidate;
                self.commit_frame(next, capture_end);
                Ok(events)
            }
            Err(error) => {
                *feed = feed_checkpoint;
                adapter.restore(adapter_checkpoint);
                decoded.fill(None);
                Err(self.latch(error))
            }
        }
    }

    /// Decode every byte in a native order-entry frame and compare every
    /// normalization with its exact expected event.
    ///
    /// # Errors
    ///
    /// Any frame, metadata, venue, decoder, normalization, count, or equality fault
    /// permanently latches this verifier.
    pub fn verify_order_entry<A: NativeOrderEntryDecoder>(
        &mut self,
        session: &mut VenueSession,
        adapter: &mut A,
        capture: NativeIngressCapture<'_>,
        decoded: &mut [Option<InboundMessage>],
    ) -> Result<usize, NativeReplayError> {
        decoded.fill(None);
        let next = self.preflight_frame(capture.metadata.frame_ordinal)?;
        let capture_end = match self.preflight_capture_ordinals(capture.expected_events) {
            Ok(end) => end,
            Err(error) => return Err(self.latch(error)),
        };
        let session_checkpoint = *session;
        let adapter_checkpoint = adapter.checkpoint();
        let result = verify_order_entry_inner(session, adapter, capture, decoded);
        match result {
            Ok(events) => {
                adapter.commit(adapter_checkpoint);
                self.commit_frame(next, capture_end);
                Ok(events)
            }
            Err(error) => {
                *session = session_checkpoint;
                adapter.restore(adapter_checkpoint);
                decoded.fill(None);
                Err(self.latch(error))
            }
        }
    }

    /// Verify native incrementals and every owned-MBO binding derived from them in
    /// one allocation-free transaction.
    ///
    /// A decoder may return a batch before correlation begins. Correlators must
    /// therefore operate only from each supplied typed message plus durable
    /// transactional adapter state; a transient decoder cursor is not a valid input.
    /// `bindings` retains every verified binding from this frame in emission order.
    ///
    /// # Errors
    ///
    /// Any decoder, correlation, metadata, ordering, capacity, normalization, or
    /// equality fault restores feed and adapter state, clears both output slices,
    /// and permanently latches this verifier.
    pub fn verify_market_data_with_owned_mbo<A: DirectExactMboVenueAdapter>(
        &mut self,
        feed: &mut MarketDataFeed,
        adapter: &mut A,
        capture: NativeOwnedMboIngressCapture<'_>,
        decoded: &mut [Option<MarketDataMessage>],
        bindings: &mut [Option<OwnedMboBinding>],
    ) -> Result<NativeOwnedMboReplayResult, NativeReplayError> {
        decoded.fill(None);
        bindings.fill(None);
        let next = self.preflight_frame(capture.ingress.metadata.frame_ordinal)?;
        let ordinals = match self.preflight_owned_mbo_frame::<A>(capture, bindings.len()) {
            Ok(ordinals) => ordinals,
            Err(error) => return Err(self.latch(error)),
        };
        let feed_checkpoint = *feed;
        let adapter_checkpoint = adapter.checkpoint();
        let result = verify_market_data_with_owned_mbo_inner(
            feed,
            adapter,
            capture,
            decoded,
            bindings,
            ordinals.first,
        );
        match result {
            Ok(result) => {
                adapter.commit(adapter_checkpoint);
                self.commit_frame(next, ordinals.last);
                Ok(result)
            }
            Err(error) => {
                *feed = feed_checkpoint;
                adapter.restore(adapter_checkpoint);
                decoded.fill(None);
                bindings.fill(None);
                Err(self.latch(error))
            }
        }
    }

    /// Verify native order-entry messages and their exact owned-MBO correlations in
    /// one allocation-free transaction.
    ///
    /// Correlation for each decoded message is ordered immediately after that
    /// message's venue event. See [`Self::verify_market_data_with_owned_mbo`] for the
    /// durable-state requirement placed on batched decoders and correlators.
    ///
    /// # Errors
    ///
    /// Any decoder, correlation, metadata, ordering, capacity, normalization, or
    /// equality fault restores session and adapter state, clears both output slices,
    /// and permanently latches this verifier.
    pub fn verify_order_entry_with_owned_mbo<A: DirectExactMboVenueAdapter>(
        &mut self,
        session: &mut VenueSession,
        adapter: &mut A,
        capture: NativeOwnedMboIngressCapture<'_>,
        decoded: &mut [Option<InboundMessage>],
        bindings: &mut [Option<OwnedMboBinding>],
    ) -> Result<NativeOwnedMboReplayResult, NativeReplayError> {
        decoded.fill(None);
        bindings.fill(None);
        let next = self.preflight_frame(capture.ingress.metadata.frame_ordinal)?;
        let ordinals = match self.preflight_owned_mbo_frame::<A>(capture, bindings.len()) {
            Ok(ordinals) => ordinals,
            Err(error) => return Err(self.latch(error)),
        };
        let session_checkpoint = *session;
        let adapter_checkpoint = adapter.checkpoint();
        let result = verify_order_entry_with_owned_mbo_inner(
            session,
            adapter,
            capture,
            decoded,
            bindings,
            ordinals.first,
        );
        match result {
            Ok(result) => {
                adapter.commit(adapter_checkpoint);
                self.commit_frame(next, ordinals.last);
                Ok(result)
            }
            Err(error) => {
                *session = session_checkpoint;
                adapter.restore(adapter_checkpoint);
                decoded.fill(None);
                bindings.fill(None);
                Err(self.latch(error))
            }
        }
    }

    /// Verify native snapshot messages and their exact owned-MBO correlations in one
    /// allocation-free transaction.
    ///
    /// Begin, order, and end messages are all presented to the correlator. The
    /// snapshot context candidate, feed, and adapter correlation state commit only
    /// after the complete captured frame succeeds.
    ///
    /// # Errors
    ///
    /// Any decoder, correlation, snapshot-boundary, metadata, ordering, capacity,
    /// normalization, or equality fault restores feed and adapter state, leaves
    /// `context` unchanged, clears both output slices, and permanently latches this
    /// verifier.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_snapshot_with_owned_mbo<A: DirectExactMboVenueAdapter>(
        &mut self,
        feed: &mut MarketDataFeed,
        adapter: &mut A,
        context: &mut NativeSnapshotContext,
        capture: NativeOwnedMboIngressCapture<'_>,
        decoded: &mut [Option<SnapshotMessage>],
        bindings: &mut [Option<OwnedMboBinding>],
    ) -> Result<NativeOwnedMboReplayResult, NativeReplayError> {
        decoded.fill(None);
        bindings.fill(None);
        let next = self.preflight_frame(capture.ingress.metadata.frame_ordinal)?;
        let ordinals = match self.preflight_owned_mbo_frame::<A>(capture, bindings.len()) {
            Ok(ordinals) => ordinals,
            Err(error) => return Err(self.latch(error)),
        };
        let feed_checkpoint = *feed;
        let adapter_checkpoint = adapter.checkpoint();
        let mut candidate = *context;
        let result = verify_snapshot_with_owned_mbo_inner(
            feed,
            adapter,
            &mut candidate,
            capture,
            decoded,
            bindings,
            ordinals.first,
        );
        match result {
            Ok(result) => {
                adapter.commit(adapter_checkpoint);
                *context = candidate;
                self.commit_frame(next, ordinals.last);
                Ok(result)
            }
            Err(error) => {
                *feed = feed_checkpoint;
                adapter.restore(adapter_checkpoint);
                decoded.fill(None);
                bindings.fill(None);
                Err(self.latch(error))
            }
        }
    }

    /// Re-encode a reactor command through the stateful venue session and compare
    /// its sequence and bytes with one captured encoded order frame.
    ///
    /// The transport verifier supplies the raw disposition and clock observation.
    /// Replay separately checks the audited effective lower bound and permits the
    /// authoritative event sequencer to raise the canonical event time. The returned
    /// input is the exact decoded canonical event; caller-supplied transmission input
    /// is never accepted as proof. `ProvenUnsent` restores the encoder/session
    /// sequence and clears `encode_buffer`, while still consuming the proven
    /// scheduler slot and capture frame.
    ///
    /// # Errors
    ///
    /// Any linkage, encoder, byte, sequence, or transmission-event fault permanently
    /// latches this verifier.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_encoded_order<A: NativeOrderEntryEncoder, T: NativeTransmissionProofVerifier>(
        &mut self,
        session: &mut VenueSession,
        adapter: &mut A,
        transport: &mut T,
        scheduler_commit: SchedulerCommit,
        egress: ReactorEgress,
        proof: &T::Proof,
        capture: NativeOrderEgressCapture<'_>,
        encode_buffer: &mut [u8],
    ) -> Result<TransmissionInput, NativeReplayError> {
        encode_buffer.fill(0);
        let next = self.preflight_frame(capture.frame_ordinal)?;
        let capture_end = match self.preflight_capture_ordinals(&[capture.transmission_event]) {
            Ok(end) => end,
            Err(error) => return Err(self.latch(error)),
        };
        let scheduler_output =
            match self.preflight_scheduler_output(scheduler_commit, egress, &capture) {
                Ok(state) => state,
                Err(error) => return Err(self.latch(error)),
            };
        let session_checkpoint = *session;
        let adapter_checkpoint = adapter.checkpoint();
        let transport_checkpoint = transport.checkpoint();
        let result = verify_encoded_order_inner(
            session,
            adapter,
            transport,
            scheduler_commit,
            egress,
            proof,
            &capture,
            encode_buffer,
        );
        match result {
            Ok(transmission) => {
                transport.commit(transport_checkpoint);
                if transmission.status == TransmissionStatus::ProvenUnsent {
                    *session = session_checkpoint;
                    adapter.restore(adapter_checkpoint);
                    encode_buffer.fill(0);
                } else {
                    adapter.commit(adapter_checkpoint);
                }
                self.scheduler_output = scheduler_output;
                self.commit_frame(next, capture_end);
                Ok(transmission)
            }
            Err(error) => {
                *session = session_checkpoint;
                adapter.restore(adapter_checkpoint);
                transport.restore(transport_checkpoint);
                encode_buffer.fill(0);
                Err(self.latch(error))
            }
        }
    }

    fn preflight_frame(&mut self, received: u64) -> Result<u64, NativeReplayError> {
        if self.failed {
            return Err(NativeReplayError::Failed);
        }
        if self.corpus_finished {
            return Err(self.latch(NativeReplayError::CorpusFinished));
        }
        if received != self.next_frame_ordinal {
            return Err(self.latch(NativeReplayError::FrameOrdinalMismatch {
                expected: self.next_frame_ordinal,
                received,
            }));
        }
        let Some(next) = self.next_frame_ordinal.checked_add(1) else {
            return Err(self.latch(NativeReplayError::FrameOrdinalExhausted(received)));
        };
        Ok(next)
    }

    fn preflight_capture_ordinals(
        self,
        events: &[NormalizedEvent],
    ) -> Result<Option<CaptureOrdinal>, NativeReplayError> {
        let Some(first) = events.first().copied() else {
            return Ok(None);
        };
        if first.capture_ordinal.0 == 0 {
            return Err(NativeReplayError::InvalidCaptureOrdinal(
                first.capture_ordinal,
            ));
        }
        if let Some(previous) = self.last_capture_ordinal
            && first.capture_ordinal.0 <= previous.0
        {
            return Err(NativeReplayError::CaptureOrdinalRegression {
                previous,
                received: first.capture_ordinal,
            });
        }
        let mut previous = first.capture_ordinal;
        for event in &events[1..] {
            let Some(expected) = previous.0.checked_add(1).map(CaptureOrdinal) else {
                return Err(NativeReplayError::CaptureOrdinalExhausted(previous));
            };
            if event.capture_ordinal != expected {
                return Err(NativeReplayError::CaptureOrdinalNotContiguous {
                    expected,
                    received: event.capture_ordinal,
                });
            }
            previous = event.capture_ordinal;
        }
        Ok(Some(previous))
    }

    fn preflight_owned_mbo_frame<A: DirectExactMboVenueAdapter>(
        self,
        capture: NativeOwnedMboIngressCapture<'_>,
        binding_slots: usize,
    ) -> Result<CorrelatedOrdinalRange, NativeReplayError> {
        validate_exact_mbo_adapter::<A>()?;
        if binding_slots < capture.expected_bindings.len() {
            return Err(NativeReplayError::OwnedMboBufferTooSmall {
                expected: capture.expected_bindings.len(),
                provided: binding_slots,
            });
        }
        preflight_expected_events(capture.ingress)?;
        preflight_expected_owned_mbo_events(capture)?;
        self.preflight_correlated_capture_ordinals(
            capture.ingress.expected_events,
            capture.expected_bindings,
        )
    }

    fn preflight_correlated_capture_ordinals(
        self,
        venue_events: &[NormalizedEvent],
        binding_events: &[NormalizedEvent],
    ) -> Result<CorrelatedOrdinalRange, NativeReplayError> {
        venue_events
            .len()
            .checked_add(binding_events.len())
            .ok_or(NativeReplayError::EventCountOverflow)?;
        let mut venue_index = 0_usize;
        let mut binding_index = 0_usize;
        let mut first = None;
        let mut previous: Option<CaptureOrdinal> = None;

        while venue_index < venue_events.len() || binding_index < binding_events.len() {
            let venue = venue_events.get(venue_index).copied();
            let binding = binding_events.get(binding_index).copied();
            let received = match (venue, binding) {
                (Some(venue), Some(binding))
                    if binding.capture_ordinal.0 < venue.capture_ordinal.0 =>
                {
                    binding_index = binding_index
                        .checked_add(1)
                        .ok_or(NativeReplayError::EventCountOverflow)?;
                    binding.capture_ordinal
                }
                (Some(venue), _) => {
                    venue_index = venue_index
                        .checked_add(1)
                        .ok_or(NativeReplayError::EventCountOverflow)?;
                    venue.capture_ordinal
                }
                (None, Some(binding)) => {
                    binding_index = binding_index
                        .checked_add(1)
                        .ok_or(NativeReplayError::EventCountOverflow)?;
                    binding.capture_ordinal
                }
                (None, None) => break,
            };
            if received.0 == 0 {
                return Err(NativeReplayError::InvalidCaptureOrdinal(received));
            }
            if let Some(previous) = previous {
                let Some(expected) = previous.0.checked_add(1).map(CaptureOrdinal) else {
                    return Err(NativeReplayError::CaptureOrdinalExhausted(previous));
                };
                if received != expected {
                    return Err(NativeReplayError::CaptureOrdinalNotContiguous {
                        expected,
                        received,
                    });
                }
            } else {
                if let Some(global_previous) = self.last_capture_ordinal
                    && received.0 <= global_previous.0
                {
                    return Err(NativeReplayError::CaptureOrdinalRegression {
                        previous: global_previous,
                        received,
                    });
                }
                first = Some(received);
            }
            previous = Some(received);
        }

        Ok(CorrelatedOrdinalRange {
            first,
            last: previous,
        })
    }

    fn commit_frame(&mut self, next: u64, capture_end: Option<CaptureOrdinal>) {
        self.next_frame_ordinal = next;
        if let Some(capture_end) = capture_end {
            self.last_capture_ordinal = Some(capture_end);
        }
    }

    fn preflight_scheduler_output(
        self,
        commit: SchedulerCommit,
        egress: ReactorEgress,
        capture: &NativeOrderEgressCapture<'_>,
    ) -> Result<SchedulerOutputState, NativeReplayError> {
        let mut encoded_commit = [0_u8; SCHEDULER_COMMIT_RECORD_LEN];
        let encoded = encode_scheduler_commit(commit, &mut encoded_commit)?;
        if encoded != SCHEDULER_COMMIT_RECORD_LEN {
            return Err(NativeReplayError::SchedulerCommit(
                SchedulerCommitError::InvalidRecord,
            ));
        }
        if capture.scheduler_commit_ordinal != commit.commit_ordinal {
            return Err(NativeReplayError::SchedulerCommitOrdinalMismatch {
                expected: capture.scheduler_commit_ordinal,
                received: commit.commit_ordinal,
            });
        }
        verify_scheduler_source(commit, capture)?;
        if capture.egress != egress {
            return Err(NativeReplayError::EgressMismatch);
        }
        let Some(egress_input_ordinal) = commit.egress_input_ordinal else {
            return Err(NativeReplayError::MissingEgressInputOrdinal);
        };
        if egress_input_ordinal != egress.input_ordinal {
            return Err(NativeReplayError::EgressInputOrdinalMismatch);
        }
        let command_index = usize::from(egress.command_index);
        if command_index >= MAX_REACTOR_COMMANDS_PER_INPUT {
            return Err(NativeReplayError::InvalidCommandIndex(egress.command_index));
        }
        let Some(command) = commit.commands[command_index] else {
            return Err(NativeReplayError::MissingSchedulerCommand(
                egress.command_index,
            ));
        };
        if command != egress.command {
            return Err(NativeReplayError::SchedulerCommandMismatch(
                egress.command_index,
            ));
        }
        let command_count = commit.commands.iter().flatten().count();

        let mut candidate = self.scheduler_output;
        if let Some(pending) = candidate.pending_commit {
            if commit.commit_ordinal != pending.commit_ordinal {
                return Err(NativeReplayError::SchedulerCommitInProgress {
                    expected: pending.commit_ordinal,
                    received: commit.commit_ordinal,
                });
            }
            if commit != pending {
                return Err(NativeReplayError::SchedulerCommitMutation(
                    commit.commit_ordinal,
                ));
            }
            if egress.command_index != candidate.next_command_index {
                return Err(NativeReplayError::SchedulerCommandIndexMismatch {
                    expected: candidate.next_command_index,
                    received: egress.command_index,
                });
            }
        } else {
            if let Some(previous) = candidate.last_completed_commit_ordinal
                && commit.commit_ordinal <= previous
            {
                return Err(NativeReplayError::SchedulerCommitRegression {
                    previous,
                    received: commit.commit_ordinal,
                });
            }
            if egress.command_index != 0 {
                return Err(NativeReplayError::OrphanSchedulerCommand {
                    commit_ordinal: commit.commit_ordinal,
                    command_index: egress.command_index,
                });
            }
        }

        let following = egress
            .command_index
            .checked_add(1)
            .ok_or(NativeReplayError::InvalidCommandIndex(egress.command_index))?;
        if usize::from(following) == command_count {
            candidate.pending_commit = None;
            candidate.next_command_index = 0;
            candidate.last_completed_commit_ordinal = Some(commit.commit_ordinal);
        } else {
            candidate.pending_commit = Some(commit);
            candidate.next_command_index = following;
        }
        Ok(candidate)
    }

    fn latch(&mut self, error: NativeReplayError) -> NativeReplayError {
        self.failed = true;
        error
    }
}

fn verify_scheduler_source(
    commit: SchedulerCommit,
    capture: &NativeOrderEgressCapture<'_>,
) -> Result<(), NativeReplayError> {
    match (commit.route, capture.scheduler_source_event) {
        (SchedulerRoute::SafetyKill, None) => Ok(()),
        (SchedulerRoute::SafetyKill, Some(_)) => Err(NativeReplayError::UnexpectedSchedulerSource),
        (_, Some(source)) => {
            commit.verify_source(source)?;
            if source.capture_ordinal.0 >= capture.transmission_event.capture_ordinal.0 {
                return Err(NativeReplayError::SchedulerSourceNotBeforeTransmission {
                    source: source.capture_ordinal,
                    transmission: capture.transmission_event.capture_ordinal,
                });
            }
            Ok(())
        }
        (_, None) => Err(NativeReplayError::MissingSchedulerSource),
    }
}

fn verify_market_data_with_owned_mbo_inner<A: DirectExactMboVenueAdapter>(
    feed: &mut MarketDataFeed,
    adapter: &mut A,
    capture: NativeOwnedMboIngressCapture<'_>,
    decoded: &mut [Option<MarketDataMessage>],
    bindings: &mut [Option<OwnedMboBinding>],
    first_capture_ordinal: Option<CaptureOrdinal>,
) -> Result<NativeOwnedMboReplayResult, NativeReplayError> {
    let ingress = capture.ingress;
    verify_ingress_capture(ingress, NativeIngressLane::MarketData, feed.identity())?;
    preflight_buffers(ingress.packet, decoded.len())?;
    preflight_expected_events(ingress)?;
    preflight_expected_owned_mbo_events(capture)?;

    let mut offset = 0_usize;
    let mut messages = 0_usize;
    let mut binding_count = 0_usize;
    let mut previous_capture_ordinal = None;
    while offset < ingress.packet.len() {
        let result = feed.decode_incrementals(
            adapter,
            &ingress.packet[offset..],
            ingress.metadata.hardware_receive_timestamp,
            decoded,
        )?;
        verify_clean_tail(decoded, result.messages)?;
        for slot in &decoded[..result.messages] {
            let message = slot.ok_or(NativeReplayError::EventCountMismatch {
                expected: ingress.expected_events.len(),
                actual: messages,
            })?;
            let expected = ingress.expected_events.get(messages).copied().ok_or(
                NativeReplayError::EventCountMismatch {
                    expected: ingress.expected_events.len(),
                    actual: messages.saturating_add(1),
                },
            )?;
            verify_correlated_capture_ordinal(
                first_capture_ordinal,
                &mut previous_capture_ordinal,
                expected.capture_ordinal,
            )?;
            let actual = normalize_market_data(capture_metadata(ingress, expected), message)?;
            if actual != expected {
                return Err(NativeReplayError::NormalizedEventMismatch { index: messages });
            }
            messages = messages
                .checked_add(1)
                .ok_or(NativeReplayError::EventCountOverflow)?;

            let available = bindings.get_mut(binding_count..).ok_or(
                NativeReplayError::OwnedMboCorrelationCountOutOfRange {
                    reported: 0,
                    available: 0,
                },
            )?;
            let correlation = adapter
                .correlate_market_data(message, available)
                .map_err(|error| NativeReplayError::Venue(error.into()))?;
            binding_count = verify_owned_mbo_batch(
                ingress.metadata.adapter_identity,
                ingress.metadata.monotonic_timestamp,
                capture.expected_bindings,
                bindings,
                binding_count,
                correlation,
                first_capture_ordinal,
                &mut previous_capture_ordinal,
            )?;
        }
        offset = offset
            .checked_add(result.consumed_bytes)
            .ok_or(NativeReplayError::ByteOffsetOverflow)?;
    }
    verify_event_count(ingress.expected_events.len(), messages)?;
    verify_owned_mbo_event_count(capture.expected_bindings.len(), binding_count)?;
    Ok(NativeOwnedMboReplayResult {
        messages,
        bindings: binding_count,
    })
}

fn verify_order_entry_with_owned_mbo_inner<A: DirectExactMboVenueAdapter>(
    session: &mut VenueSession,
    adapter: &mut A,
    capture: NativeOwnedMboIngressCapture<'_>,
    decoded: &mut [Option<InboundMessage>],
    bindings: &mut [Option<OwnedMboBinding>],
    first_capture_ordinal: Option<CaptureOrdinal>,
) -> Result<NativeOwnedMboReplayResult, NativeReplayError> {
    let ingress = capture.ingress;
    verify_ingress_capture(ingress, NativeIngressLane::OrderEntry, session.identity())?;
    preflight_buffers(ingress.packet, decoded.len())?;
    preflight_expected_events(ingress)?;
    preflight_expected_owned_mbo_events(capture)?;

    let mut offset = 0_usize;
    let mut messages = 0_usize;
    let mut binding_count = 0_usize;
    let mut previous_capture_ordinal = None;
    while offset < ingress.packet.len() {
        let result = session.decode_inbound(
            adapter,
            &ingress.packet[offset..],
            ingress.metadata.hardware_receive_timestamp,
            decoded,
        )?;
        verify_clean_tail(decoded, result.messages)?;
        for slot in &decoded[..result.messages] {
            let message = slot.ok_or(NativeReplayError::EventCountMismatch {
                expected: ingress.expected_events.len(),
                actual: messages,
            })?;
            let expected = ingress.expected_events.get(messages).copied().ok_or(
                NativeReplayError::EventCountMismatch {
                    expected: ingress.expected_events.len(),
                    actual: messages.saturating_add(1),
                },
            )?;
            verify_correlated_capture_ordinal(
                first_capture_ordinal,
                &mut previous_capture_ordinal,
                expected.capture_ordinal,
            )?;
            let actual = normalize_order_entry(capture_metadata(ingress, expected), message)?;
            if actual != expected {
                return Err(NativeReplayError::NormalizedEventMismatch { index: messages });
            }
            messages = messages
                .checked_add(1)
                .ok_or(NativeReplayError::EventCountOverflow)?;

            let available = bindings.get_mut(binding_count..).ok_or(
                NativeReplayError::OwnedMboCorrelationCountOutOfRange {
                    reported: 0,
                    available: 0,
                },
            )?;
            let correlation = adapter
                .correlate_order_entry(message, available)
                .map_err(|error| NativeReplayError::Venue(error.into()))?;
            binding_count = verify_owned_mbo_batch(
                ingress.metadata.adapter_identity,
                ingress.metadata.monotonic_timestamp,
                capture.expected_bindings,
                bindings,
                binding_count,
                correlation,
                first_capture_ordinal,
                &mut previous_capture_ordinal,
            )?;
        }
        offset = offset
            .checked_add(result.consumed_bytes)
            .ok_or(NativeReplayError::ByteOffsetOverflow)?;
    }
    verify_event_count(ingress.expected_events.len(), messages)?;
    verify_owned_mbo_event_count(capture.expected_bindings.len(), binding_count)?;
    Ok(NativeOwnedMboReplayResult {
        messages,
        bindings: binding_count,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_snapshot_with_owned_mbo_inner<A: DirectExactMboVenueAdapter>(
    feed: &mut MarketDataFeed,
    adapter: &mut A,
    context: &mut NativeSnapshotContext,
    capture: NativeOwnedMboIngressCapture<'_>,
    decoded: &mut [Option<SnapshotMessage>],
    bindings: &mut [Option<OwnedMboBinding>],
    first_capture_ordinal: Option<CaptureOrdinal>,
) -> Result<NativeOwnedMboReplayResult, NativeReplayError> {
    let ingress = capture.ingress;
    verify_ingress_capture(ingress, NativeIngressLane::Snapshot, feed.identity())?;
    preflight_buffers(ingress.packet, decoded.len())?;
    preflight_expected_events(ingress)?;
    preflight_expected_owned_mbo_events(capture)?;

    let mut offset = 0_usize;
    let mut messages = 0_usize;
    let mut binding_count = 0_usize;
    let mut previous_capture_ordinal = None;
    while offset < ingress.packet.len() {
        let result = feed.decode_snapshot(
            adapter,
            &ingress.packet[offset..],
            ingress.metadata.hardware_receive_timestamp,
            decoded,
        )?;
        verify_clean_tail(decoded, result.messages)?;
        for slot in &decoded[..result.messages] {
            let message = slot.ok_or(NativeReplayError::EventCountMismatch {
                expected: ingress.expected_events.len(),
                actual: messages,
            })?;
            let expected = ingress.expected_events.get(messages).copied().ok_or(
                NativeReplayError::EventCountMismatch {
                    expected: ingress.expected_events.len(),
                    actual: messages.saturating_add(1),
                },
            )?;
            verify_correlated_capture_ordinal(
                first_capture_ordinal,
                &mut previous_capture_ordinal,
                expected.capture_ordinal,
            )?;
            let (snapshot_id, last_incremental_sequence) =
                apply_snapshot_context(context, message)?;
            let actual = normalize_snapshot(
                SnapshotCaptureMetadata {
                    venue: capture_metadata(ingress, expected),
                    snapshot_id,
                    last_incremental_sequence,
                },
                message,
            )?;
            if actual != expected {
                return Err(NativeReplayError::NormalizedEventMismatch { index: messages });
            }
            messages = messages
                .checked_add(1)
                .ok_or(NativeReplayError::EventCountOverflow)?;

            let available = bindings.get_mut(binding_count..).ok_or(
                NativeReplayError::OwnedMboCorrelationCountOutOfRange {
                    reported: 0,
                    available: 0,
                },
            )?;
            let correlation = adapter
                .correlate_snapshot(message, available)
                .map_err(|error| NativeReplayError::Venue(error.into()))?;
            binding_count = verify_owned_mbo_batch(
                ingress.metadata.adapter_identity,
                ingress.metadata.monotonic_timestamp,
                capture.expected_bindings,
                bindings,
                binding_count,
                correlation,
                first_capture_ordinal,
                &mut previous_capture_ordinal,
            )?;
        }
        offset = offset
            .checked_add(result.consumed_bytes)
            .ok_or(NativeReplayError::ByteOffsetOverflow)?;
    }
    verify_event_count(ingress.expected_events.len(), messages)?;
    verify_owned_mbo_event_count(capture.expected_bindings.len(), binding_count)?;
    Ok(NativeOwnedMboReplayResult {
        messages,
        bindings: binding_count,
    })
}

fn verify_market_data_inner<A: DirectMarketDataDecoder>(
    feed: &mut MarketDataFeed,
    adapter: &mut A,
    capture: NativeIngressCapture<'_>,
    decoded: &mut [Option<MarketDataMessage>],
) -> Result<usize, NativeReplayError> {
    verify_ingress_capture(capture, NativeIngressLane::MarketData, feed.identity())?;
    preflight_buffers(capture.packet, decoded.len())?;
    preflight_expected_events(capture)?;

    let mut offset = 0_usize;
    let mut events = 0_usize;
    while offset < capture.packet.len() {
        let result = feed.decode_incrementals(
            adapter,
            &capture.packet[offset..],
            capture.metadata.hardware_receive_timestamp,
            decoded,
        )?;
        verify_clean_tail(decoded, result.messages)?;
        for slot in &decoded[..result.messages] {
            let message = slot.ok_or(NativeReplayError::EventCountMismatch {
                expected: capture.expected_events.len(),
                actual: events,
            })?;
            let expected = capture.expected_events.get(events).copied().ok_or(
                NativeReplayError::EventCountMismatch {
                    expected: capture.expected_events.len(),
                    actual: events.saturating_add(1),
                },
            )?;
            let actual = normalize_market_data(capture_metadata(capture, expected), message)?;
            if actual != expected {
                return Err(NativeReplayError::NormalizedEventMismatch { index: events });
            }
            events = events
                .checked_add(1)
                .ok_or(NativeReplayError::EventCountOverflow)?;
        }
        offset = offset
            .checked_add(result.consumed_bytes)
            .ok_or(NativeReplayError::ByteOffsetOverflow)?;
    }
    verify_event_count(capture.expected_events.len(), events)?;
    Ok(events)
}

fn verify_snapshot_inner<A: DirectMarketDataDecoder>(
    feed: &mut MarketDataFeed,
    adapter: &mut A,
    context: &mut NativeSnapshotContext,
    capture: NativeIngressCapture<'_>,
    decoded: &mut [Option<SnapshotMessage>],
) -> Result<usize, NativeReplayError> {
    verify_ingress_capture(capture, NativeIngressLane::Snapshot, feed.identity())?;
    preflight_buffers(capture.packet, decoded.len())?;
    preflight_expected_events(capture)?;

    let mut offset = 0_usize;
    let mut events = 0_usize;
    while offset < capture.packet.len() {
        let result = feed.decode_snapshot(
            adapter,
            &capture.packet[offset..],
            capture.metadata.hardware_receive_timestamp,
            decoded,
        )?;
        verify_clean_tail(decoded, result.messages)?;
        for slot in &decoded[..result.messages] {
            let message = slot.ok_or(NativeReplayError::EventCountMismatch {
                expected: capture.expected_events.len(),
                actual: events,
            })?;
            let expected = capture.expected_events.get(events).copied().ok_or(
                NativeReplayError::EventCountMismatch {
                    expected: capture.expected_events.len(),
                    actual: events.saturating_add(1),
                },
            )?;
            let (snapshot_id, last_incremental_sequence) =
                apply_snapshot_context(context, message)?;
            let actual = normalize_snapshot(
                SnapshotCaptureMetadata {
                    venue: capture_metadata(capture, expected),
                    snapshot_id,
                    last_incremental_sequence,
                },
                message,
            )?;
            if actual != expected {
                return Err(NativeReplayError::NormalizedEventMismatch { index: events });
            }
            events = events
                .checked_add(1)
                .ok_or(NativeReplayError::EventCountOverflow)?;
        }
        offset = offset
            .checked_add(result.consumed_bytes)
            .ok_or(NativeReplayError::ByteOffsetOverflow)?;
    }
    verify_event_count(capture.expected_events.len(), events)?;
    Ok(events)
}

fn apply_snapshot_context(
    context: &mut NativeSnapshotContext,
    message: SnapshotMessage,
) -> Result<(u64, Sequence), NativeReplayError> {
    match message.payload {
        SnapshotPayload::Begin {
            snapshot_id,
            last_incremental_sequence,
        } => match (
            context.active_snapshot_id,
            context.last_incremental_sequence,
        ) {
            (None, None) => {
                context.active_snapshot_id = Some(snapshot_id);
                context.last_incremental_sequence = Some(last_incremental_sequence);
                Ok((snapshot_id, last_incremental_sequence))
            }
            (Some(active_snapshot_id), Some(active_last_incremental_sequence)) => {
                Err(NativeReplayError::SnapshotAlreadyActive {
                    active_snapshot_id,
                    last_incremental_sequence: active_last_incremental_sequence,
                })
            }
            _ => Err(NativeReplayError::SnapshotContextMissing),
        },
        SnapshotPayload::Order(_) => active_snapshot_context(*context),
        SnapshotPayload::End {
            snapshot_id,
            last_incremental_sequence,
        } => {
            let (expected_snapshot_id, expected_last_incremental_sequence) =
                active_snapshot_context(*context)?;
            if snapshot_id != expected_snapshot_id
                || last_incremental_sequence != expected_last_incremental_sequence
            {
                return Err(NativeReplayError::SnapshotContextMismatch {
                    expected_snapshot_id,
                    received_snapshot_id: snapshot_id,
                    expected_last_incremental_sequence,
                    received_last_incremental_sequence: last_incremental_sequence,
                });
            }
            *context = NativeSnapshotContext::new();
            Ok((snapshot_id, last_incremental_sequence))
        }
    }
}

fn active_snapshot_context(
    context: NativeSnapshotContext,
) -> Result<(u64, Sequence), NativeReplayError> {
    match (
        context.active_snapshot_id,
        context.last_incremental_sequence,
    ) {
        (Some(snapshot_id), Some(last_incremental_sequence)) => {
            Ok((snapshot_id, last_incremental_sequence))
        }
        _ => Err(NativeReplayError::SnapshotContextMissing),
    }
}

fn verify_order_entry_inner<A: NativeOrderEntryDecoder>(
    session: &mut VenueSession,
    adapter: &mut A,
    capture: NativeIngressCapture<'_>,
    decoded: &mut [Option<InboundMessage>],
) -> Result<usize, NativeReplayError> {
    verify_ingress_capture(capture, NativeIngressLane::OrderEntry, session.identity())?;
    preflight_buffers(capture.packet, decoded.len())?;
    preflight_expected_events(capture)?;

    let mut offset = 0_usize;
    let mut events = 0_usize;
    while offset < capture.packet.len() {
        let result = session.decode_inbound(
            adapter,
            &capture.packet[offset..],
            capture.metadata.hardware_receive_timestamp,
            decoded,
        )?;
        verify_clean_tail(decoded, result.messages)?;
        for slot in &decoded[..result.messages] {
            let message = slot.ok_or(NativeReplayError::EventCountMismatch {
                expected: capture.expected_events.len(),
                actual: events,
            })?;
            let expected = capture.expected_events.get(events).copied().ok_or(
                NativeReplayError::EventCountMismatch {
                    expected: capture.expected_events.len(),
                    actual: events.saturating_add(1),
                },
            )?;
            let actual = normalize_order_entry(capture_metadata(capture, expected), message)?;
            if actual != expected {
                return Err(NativeReplayError::NormalizedEventMismatch { index: events });
            }
            events = events
                .checked_add(1)
                .ok_or(NativeReplayError::EventCountOverflow)?;
        }
        offset = offset
            .checked_add(result.consumed_bytes)
            .ok_or(NativeReplayError::ByteOffsetOverflow)?;
    }
    verify_event_count(capture.expected_events.len(), events)?;
    Ok(events)
}

#[allow(clippy::too_many_arguments)]
fn verify_encoded_order_inner<A: NativeOrderEntryEncoder, T: NativeTransmissionProofVerifier>(
    session: &mut VenueSession,
    adapter: &mut A,
    transport: &mut T,
    scheduler_commit: SchedulerCommit,
    egress: ReactorEgress,
    proof: &T::Proof,
    capture: &NativeOrderEgressCapture<'_>,
    encode_buffer: &mut [u8],
) -> Result<TransmissionInput, NativeReplayError> {
    if capture.adapter_identity != session.identity() {
        return Err(NativeReplayError::AdapterIdentityMismatch {
            expected: session.identity(),
            received: capture.adapter_identity,
        });
    }
    if capture.venue_sequence.0 == 0 {
        return Err(NativeReplayError::InvalidVenueSequence(
            capture.venue_sequence,
        ));
    }
    if encode_buffer.is_empty() {
        return Err(NativeReplayError::EmptyEncodeBuffer);
    }
    let expected_transmission = decode_transmission(capture.transmission_event)?;
    if expected_transmission.command != egress.command {
        return Err(NativeReplayError::TransmissionCommandMismatch);
    }

    let frame = match egress.command {
        OrderCommand::CancelAll(command) => {
            session.encode_cancel_all(adapter, command, encode_buffer)?
        }
        OrderCommand::New(_) | OrderCommand::Cancel(_) | OrderCommand::Replace(_) => {
            session.encode_order(adapter, egress.command, encode_buffer)?
        }
    };
    if frame.sequence != capture.venue_sequence {
        return Err(NativeReplayError::VenueSequenceMismatch {
            expected: capture.venue_sequence,
            received: frame.sequence,
        });
    }
    if frame.bytes != capture.encoded_bytes.len() {
        return Err(NativeReplayError::EncodedLengthMismatch {
            expected: capture.encoded_bytes.len(),
            actual: frame.bytes,
        });
    }
    if let Some(index) = encode_buffer[..frame.bytes]
        .iter()
        .zip(capture.encoded_bytes)
        .position(|(actual, expected)| actual != expected)
    {
        return Err(NativeReplayError::EncodedByteMismatch { index });
    }
    if let Some(relative) = encode_buffer[frame.bytes..]
        .iter()
        .position(|byte| *byte != 0)
    {
        let index = frame
            .bytes
            .checked_add(relative)
            .ok_or(NativeReplayError::ByteOffsetOverflow)?;
        return Err(NativeReplayError::DirtyEncodedTail { index });
    }
    let disposition = transport.verify(
        NativeTransmissionContext {
            frame_ordinal: capture.frame_ordinal,
            adapter_identity: capture.adapter_identity,
            venue_sequence: frame.sequence,
            scheduler_commit_ordinal: scheduler_commit.commit_ordinal,
            scheduler_capture_ordinal: scheduler_commit.capture_ordinal,
            scheduler_source_event_crc32c: scheduler_commit.source_event_crc32c,
            egress,
            encoded_bytes: &encode_buffer[..frame.bytes],
        },
        proof,
    )?;
    let minimum = capture.transmission_minimum_monotonic;
    if minimum == MonotonicTimestampNs::ZERO {
        return Err(NativeReplayError::InvalidTransmissionMinimum(minimum));
    }
    if disposition.monotonic_now != MonotonicTimestampNs::ZERO
        && minimum < disposition.monotonic_now
    {
        return Err(NativeReplayError::TransmissionMinimumBeforeTransport {
            minimum,
            transport: disposition.monotonic_now,
        });
    }
    if expected_transmission.monotonic_now < minimum {
        return Err(NativeReplayError::TransmissionEventBeforeMinimum {
            minimum,
            event: expected_transmission.monotonic_now,
        });
    }
    if expected_transmission.status != disposition.status {
        return Err(NativeReplayError::TransmissionEventMismatch);
    }
    let canonical = normalize_transmission(
        capture.transmission_event.capture_ordinal,
        expected_transmission,
    )?;
    if canonical != capture.transmission_event {
        return Err(NativeReplayError::TransmissionEventMismatch);
    }
    Ok(expected_transmission)
}

fn verify_ingress_capture(
    capture: NativeIngressCapture<'_>,
    expected_lane: NativeIngressLane,
    identity: VenueIdentity,
) -> Result<(), NativeReplayError> {
    if capture.lane != expected_lane {
        return Err(NativeReplayError::LaneMismatch {
            expected: expected_lane,
            received: capture.lane,
        });
    }
    let metadata = capture.metadata;
    if metadata.adapter_identity != identity {
        return Err(NativeReplayError::AdapterIdentityMismatch {
            expected: identity,
            received: metadata.adapter_identity,
        });
    }
    let expected_domain = match expected_lane {
        NativeIngressLane::MarketData | NativeIngressLane::Snapshot => SequenceDomain::MarketData,
        NativeIngressLane::OrderEntry => SequenceDomain::OrderEntry,
    };
    if metadata.source.sequence_domain != expected_domain {
        return Err(NativeReplayError::SequenceDomainMismatch {
            lane: expected_lane,
            received: metadata.source.sequence_domain,
        });
    }
    let expected_protocol = match expected_lane {
        NativeIngressLane::MarketData | NativeIngressLane::Snapshot => {
            identity.market_data_protocol.0
        }
        NativeIngressLane::OrderEntry => identity.order_entry_protocol.0,
    };
    if metadata.source.id.protocol != expected_protocol {
        return Err(NativeReplayError::SourceProtocolMismatch {
            expected: expected_protocol,
            received: metadata.source.id.protocol,
        });
    }
    if !metadata.source.id.is_valid() || metadata.source.session_epoch.0 == 0 {
        return Err(NativeReplayError::InvalidSource(metadata.source));
    }
    if metadata.hardware_receive_timestamp == TimestampNs::ZERO {
        return Err(NativeReplayError::InvalidHardwareReceiveTimestamp(
            metadata.hardware_receive_timestamp,
        ));
    }
    if metadata.monotonic_timestamp == MonotonicTimestampNs::ZERO {
        return Err(NativeReplayError::InvalidMonotonicTimestamp(
            metadata.monotonic_timestamp,
        ));
    }
    Ok(())
}

fn preflight_expected_owned_mbo_events(
    capture: NativeOwnedMboIngressCapture<'_>,
) -> Result<(), NativeReplayError> {
    let metadata = capture.ingress.metadata;
    for (index, event) in capture.expected_bindings.iter().copied().enumerate() {
        let input = decode_owned_mbo_binding(event)
            .map_err(|_| NativeReplayError::ExpectedOwnedMboEventMismatch { index })?;
        if event.source != EventSource::LOCAL || input.monotonic_now != metadata.monotonic_timestamp
        {
            return Err(NativeReplayError::ExpectedOwnedMboEventMismatch { index });
        }
        if input.binding.venue != metadata.adapter_identity.venue {
            return Err(NativeReplayError::OwnedMboVenueMismatch {
                index,
                expected: metadata.adapter_identity.venue,
                received: input.binding.venue,
            });
        }
        let canonical = normalize_owned_mbo_binding(event.capture_ordinal, input)
            .map_err(|_| NativeReplayError::ExpectedOwnedMboEventMismatch { index })?;
        if canonical != event {
            return Err(NativeReplayError::ExpectedOwnedMboEventMismatch { index });
        }
    }
    Ok(())
}

fn verify_correlated_capture_ordinal(
    first: Option<CaptureOrdinal>,
    previous: &mut Option<CaptureOrdinal>,
    received: CaptureOrdinal,
) -> Result<(), NativeReplayError> {
    let expected = match *previous {
        Some(previous) => previous
            .0
            .checked_add(1)
            .map(CaptureOrdinal)
            .ok_or(NativeReplayError::CaptureOrdinalExhausted(previous))?,
        None => first.ok_or(NativeReplayError::InvalidCaptureOrdinal(received))?,
    };
    if received != expected {
        return Err(NativeReplayError::CorrelatedCaptureOrdinalMismatch { expected, received });
    }
    *previous = Some(received);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_owned_mbo_batch(
    identity: VenueIdentity,
    monotonic_now: MonotonicTimestampNs,
    expected_events: &[NormalizedEvent],
    output: &[Option<OwnedMboBinding>],
    start: usize,
    correlation: CorrelationResult,
    first_capture_ordinal: Option<CaptureOrdinal>,
    previous_capture_ordinal: &mut Option<CaptureOrdinal>,
) -> Result<usize, NativeReplayError> {
    let available = output.len().checked_sub(start).ok_or(
        NativeReplayError::OwnedMboCorrelationCountOutOfRange {
            reported: correlation.bindings,
            available: 0,
        },
    )?;
    if correlation.bindings > available {
        return Err(NativeReplayError::OwnedMboCorrelationCountOutOfRange {
            reported: correlation.bindings,
            available,
        });
    }
    let end = start
        .checked_add(correlation.bindings)
        .ok_or(NativeReplayError::EventCountOverflow)?;
    if let Some(relative) = output[end..].iter().position(Option::is_some) {
        let index = end
            .checked_add(relative)
            .ok_or(NativeReplayError::EventCountOverflow)?;
        return Err(NativeReplayError::DirtyOwnedMboBindingTail { index });
    }

    for (relative, slot) in output[start..end].iter().enumerate() {
        let index = start
            .checked_add(relative)
            .ok_or(NativeReplayError::EventCountOverflow)?;
        let binding = (*slot).ok_or(NativeReplayError::EmptyOwnedMboBindingSlot { index })?;
        let expected = expected_events.get(index).copied().ok_or(
            NativeReplayError::OwnedMboEventCountMismatch {
                expected: expected_events.len(),
                actual: end,
            },
        )?;
        if binding.venue != identity.venue {
            return Err(NativeReplayError::OwnedMboVenueMismatch {
                index,
                expected: identity.venue,
                received: binding.venue,
            });
        }
        verify_correlated_capture_ordinal(
            first_capture_ordinal,
            previous_capture_ordinal,
            expected.capture_ordinal,
        )?;
        let actual = normalize_owned_mbo_binding(
            expected.capture_ordinal,
            OwnedMboBindingInput {
                binding,
                monotonic_now,
            },
        )
        .map_err(|_| NativeReplayError::OwnedMboBindingEventMismatch { index })?;
        if actual != expected {
            return Err(NativeReplayError::OwnedMboBindingEventMismatch { index });
        }
    }
    Ok(end)
}

fn verify_owned_mbo_event_count(expected: usize, actual: usize) -> Result<(), NativeReplayError> {
    if expected != actual {
        return Err(NativeReplayError::OwnedMboEventCountMismatch { expected, actual });
    }
    Ok(())
}

fn preflight_buffers(packet: &[u8], slots: usize) -> Result<(), NativeReplayError> {
    if packet.is_empty() {
        return Err(NativeReplayError::EmptyPacket);
    }
    if slots == 0 {
        return Err(NativeReplayError::EmptyDecodeBuffer);
    }
    Ok(())
}

fn preflight_expected_events(capture: NativeIngressCapture<'_>) -> Result<(), NativeReplayError> {
    for (index, event) in capture.expected_events.iter().copied().enumerate() {
        if event.validate().is_err()
            || event.header.venue != capture.metadata.adapter_identity.venue
            || event.source != capture.metadata.source
            || event.header.hardware_receive_timestamp
                != capture.metadata.hardware_receive_timestamp
            || event.monotonic_timestamp != capture.metadata.monotonic_timestamp
            || event.is_recovery() != capture.metadata.recovery
        {
            return Err(NativeReplayError::ExpectedEventMetadataMismatch { index });
        }
    }
    Ok(())
}

fn capture_metadata(
    capture: NativeIngressCapture<'_>,
    expected: NormalizedEvent,
) -> VenueCaptureMetadata {
    VenueCaptureMetadata {
        venue: capture.metadata.adapter_identity.venue,
        source: capture.metadata.source,
        capture_ordinal: expected.capture_ordinal,
        monotonic_timestamp: capture.metadata.monotonic_timestamp,
        recovery: capture.metadata.recovery,
    }
}

fn verify_clean_tail<T>(decoded: &[Option<T>], messages: usize) -> Result<(), NativeReplayError> {
    if let Some(relative) = decoded[messages..].iter().position(Option::is_some) {
        let index = messages
            .checked_add(relative)
            .ok_or(NativeReplayError::EventCountOverflow)?;
        return Err(NativeReplayError::DirtyDecodedTail { index });
    }
    Ok(())
}

fn verify_event_count(expected: usize, actual: usize) -> Result<(), NativeReplayError> {
    if expected != actual {
        return Err(NativeReplayError::EventCountMismatch { expected, actual });
    }
    Ok(())
}
