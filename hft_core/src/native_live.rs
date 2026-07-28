//! Allocation-free coordination of one canonical event through the live hot path.
//!
//! This module starts at an already authenticated, normalized event and ends at a
//! synchronous native order transport disposition. It deliberately does **not** poll
//! a NIC, authenticate packet capture, implement kernel bypass, prove clock quality,
//! or certify a venue adapter or transport proof. Those are deployment-specific
//! external boundaries. The coordinator does bind the real reactor, scheduler
//! commits, venue session encoder, submitted bytes, and priority feedback together.
//! Coordinator-owned work uses no heap allocation or trait objects; concrete adapter,
//! audit, and transport implementations require separate bounded-path certification.

use crate::control::ControlDecisionOrigin;
use crate::engine::TransmissionStatus;
use crate::engine_replay::EngineReplayRoute;
use crate::event_codec::{
    EventCodecError, ReplayInput, decode_replay_input, decode_transmission, normalize_transmission,
};
use crate::events::{CaptureOrdinal, EventSource, NormalizedEvent, SequenceDomain};
use crate::native_replay::{
    NativeTransmissionContext, NativeTransmissionDisposition, NativeTransmissionProofError,
    NativeTransmissionProofVerifier,
};
use crate::reactor::{
    HotPathReactor, MAX_REACTOR_COMMANDS_PER_INPUT, ReactorBudget, ReactorEgress, ReactorFailure,
    ReactorInput, TransmissionInput,
};
use crate::reactor_audit::{SchedulerCommit, SchedulerCommitError, SchedulerRoute};
use crate::reactor_replay::ReactorReplayOutcome;
use crate::reference_data::{
    InstrumentDefinition, InstrumentDefinitionBinding, InstrumentDefinitionError,
};
use crate::spsc::SpscRing;
use crate::types::{MonotonicTimestampNs, Sequence, VenueId};
use crate::venue::{
    NativeOrderEntryEncoder, OrderCommand, VenueError, VenueIdentity, VenueSession,
};

/// Maximum records reserved for one clean-boundary source and its two immediate
/// transmission resolutions.
pub const NATIVE_LIVE_AUDIT_CAPACITY: NativeLiveAuditCapacity = NativeLiveAuditCapacity {
    scheduler_commits: 3,
    native_intents: 2,
    native_egress: 2,
    proof_faults: 1,
    transmission_events: 2,
    encode_faults: 1,
    clock_fallbacks: 1,
    source_events: 1,
    reactor_faults: 2,
    application_faults: 2,
};

/// Worst-case fixed audit reservation for one [`NativeLiveCoordinator::process_event`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeLiveAuditCapacity {
    pub scheduler_commits: u8,
    pub native_intents: u8,
    pub native_egress: u8,
    pub proof_faults: u8,
    pub transmission_events: u8,
    pub encode_faults: u8,
    pub clock_fallbacks: u8,
    pub source_events: u8,
    pub reactor_faults: u8,
    pub application_faults: u8,
}

/// Operation whose ordinary reservation could not be acquired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeLiveOperation {
    ProcessEvent,
    DriveSafety,
}

/// Fixed record written through the independently provisioned emergency seal lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeLiveEmergencySealRecord<AuditError: Copy> {
    pub operation: NativeLiveOperation,
    pub rejected_source: Option<NormalizedEvent>,
    pub local_monotonic_sample: MonotonicTimestampNs,
    pub error: AuditError,
    pub checkpoint: NativeLiveCheckpoint,
}

/// Transport-owned total classification of one synchronous submission attempt.
///
/// `ProvenUnsent` is permitted only when the transport can irrevocably prove that no
/// byte was submitted to, consumed by, or made observable to the peer. Timeouts,
/// missing completions, and uncertain descriptor ownership are `Ambiguous`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeSubmit<Proof: Copy> {
    Sent {
        proof: Proof,
        monotonic_now: MonotonicTimestampNs,
    },
    ProvenUnsent {
        proof: Proof,
        monotonic_now: MonotonicTimestampNs,
    },
    Ambiguous {
        proof: Proof,
        monotonic_now: MonotonicTimestampNs,
    },
}

/// Stable audit classification corresponding to [`NativeSubmit`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeSubmitDisposition {
    Sent,
    ProvenUnsent,
    Ambiguous,
}

/// Synchronous native order transport boundary.
///
/// The returned classification is an untrusted claim until a separate
/// [`NativeTransmissionProofVerifier`] verifies the exact `context`, proof, status,
/// and timestamp. An implementation must never translate an ambiguous I/O outcome
/// into `ProvenUnsent`. Every `Proof` must bind the exact frame, adapter identity,
/// venue sequence, scheduler commit/source checksum, egress slot, and byte prefix in
/// `context`. The submit and verifier traits may share one concrete object for
/// zero-overhead state ownership; that co-location is not evidence of independent
/// proof provenance, which production deployments must certify independently.
/// `quiesce` must be idempotent and must stop further submission without inventing
/// feedback for an in-flight command.
///
/// Production implementations of both methods must be bounded, nonblocking, and
/// allocation-free; this trait's type system cannot prove those deployment facts.
pub trait NativeOrderTransport {
    type Proof: Copy;

    fn submit(&mut self, context: NativeTransmissionContext<'_>) -> NativeSubmit<Self::Proof>;
    fn quiesce(&mut self);
}

/// Local pre-submit fault provenance. No native byte or transport proof exists for
/// this record; the corresponding canonical feedback is always `ProvenUnsent`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeLiveEncodeFaultRecord {
    pub egress: ReactorEgress,
    pub fault: NativeLiveEncodeFault,
    pub local_monotonic_sample: MonotonicTimestampNs,
    pub monotonic_now: MonotonicTimestampNs,
}

/// Provenance for a zero or causally regressing transport timestamp. Canonical
/// feedback uses the separately authenticated effective local observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeLiveClockFallbackRecord {
    pub egress: ReactorEgress,
    pub disposition: NativeSubmitDisposition,
    pub transport_monotonic_now: MonotonicTimestampNs,
    pub local_monotonic_now: MonotonicTimestampNs,
    pub effective_monotonic_now: MonotonicTimestampNs,
}

/// Audited application-ordinal record for a reactor call that failed after it began.
/// `source_event` is `None` only for the source-less `SafetyKill` route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeLiveReactorFaultRecord {
    pub application_ordinal: u64,
    pub route: SchedulerRoute,
    pub source_event: Option<NormalizedEvent>,
    pub failure: ReactorFailure,
    pub egress: [Option<ReactorEgress>; MAX_REACTOR_COMMANDS_PER_INPUT],
    pub outstanding_transmissions: usize,
    pub retained_event: bool,
    pub mandatory_kill_pending: bool,
}

/// Validation fault after a successful reactor application but before a canonical
/// scheduler commit could be persisted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeLivePostRunFault {
    Scheduler(SchedulerCommitError),
    UnexpectedEgress,
}

/// Ordinal-bound evidence replacing a scheduler commit when post-run validation
/// fails. The application ordinal is consumed exactly once by this record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeLiveApplicationFaultRecord {
    pub application_ordinal: u64,
    pub route: SchedulerRoute,
    pub source_event: Option<NormalizedEvent>,
    pub outcome: ReactorReplayOutcome,
    pub egress: [Option<ReactorEgress>; MAX_REACTOR_COMMANDS_PER_INPUT],
    pub outstanding_transmissions: usize,
    pub retained_event: bool,
    pub mandatory_kill_pending: bool,
    pub fault: NativeLivePostRunFault,
}

/// Exact, successfully verified native submission evidence copied by an audit sink
/// while encoded bytes are still borrowed from caller-owned scratch storage.
/// Unverified or contradictory transport claims are recorded separately as
/// [`NativeLiveProofFaultRecord`] and never reach this record type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeLiveEgressRecord<'a, Proof: Copy> {
    pub context: NativeTransmissionContext<'a>,
    pub proof: Proof,
    pub disposition: NativeSubmitDisposition,
    pub monotonic_now: MonotonicTimestampNs,
}

/// Fail-closed reason an untrusted live transport claim was not accepted as evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeLiveProofFault {
    Rejected,
    Ambiguous,
    DispositionMismatch {
        claimed: NativeSubmitDisposition,
        verified: NativeSubmitDisposition,
    },
    TimestampMismatch {
        claimed: MonotonicTimestampNs,
        verified: MonotonicTimestampNs,
    },
}

/// Exact claimed proof and context retained when live verification fails closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeLiveProofFaultRecord<'a, Proof: Copy> {
    pub context: NativeTransmissionContext<'a>,
    pub proof: Proof,
    pub claimed_disposition: NativeSubmitDisposition,
    pub claimed_monotonic_now: MonotonicTimestampNs,
    pub fault: NativeLiveProofFault,
}

/// Exact outbound frame intent before the shared native capture sequencer assigns
/// its process-global RX/TX ordinal. The encoded prefix is borrowed only for this
/// call and must be copied by the audit sink.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeLiveIntent<'a> {
    pub adapter_identity: VenueIdentity,
    pub venue_sequence: Sequence,
    pub scheduler_commit_ordinal: u64,
    pub scheduler_capture_ordinal: CaptureOrdinal,
    pub scheduler_source_event_crc32c: u32,
    pub egress: ReactorEgress,
    pub encoded_bytes: &'a [u8],
}

impl<'a> NativeLiveIntent<'a> {
    #[must_use]
    pub const fn with_frame_ordinal(self, frame_ordinal: u64) -> NativeTransmissionContext<'a> {
        NativeTransmissionContext {
            frame_ordinal,
            adapter_identity: self.adapter_identity,
            venue_sequence: self.venue_sequence,
            scheduler_commit_ordinal: self.scheduler_commit_ordinal,
            scheduler_capture_ordinal: self.scheduler_capture_ordinal,
            scheduler_source_event_crc32c: self.scheduler_source_event_crc32c,
            egress: self.egress,
            encoded_bytes: self.encoded_bytes,
        }
    }
}

/// Reservation-first, allocation-free live audit sink.
///
/// `reserve` must atomically reserve all capacity described by `capacity`. After it
/// succeeds, every `record_*`, `seal`, and `abort` call is infallible by contract.
/// Implementations must copy borrowed bytes during `append_native_intent`.
/// `abort` is only for a call that has not mutated the reactor, codec, or transport;
/// it must retain an explicit aborted-reservation marker rather than silently reusing
/// a ticket. Every record must be synchronously ordered and visible in one recovery
/// domain before its call returns. Recovery must fail-stop an unfinished ticket;
/// specifically, a durable native intent without its disposition is `Ambiguous`,
/// never `ProvenUnsent`. Source events and application records recover in call order.
/// A transport claim rejected by its proof verifier, left ambiguous, or contradicted
/// by the verified disposition/timestamp must be persisted through
/// [`Self::record_proof_fault`] and recovered as ambiguity; it must not be emitted as
/// transmission feedback or used to roll back a venue sequence.
/// If nominally infallible persistence suffers a hardware failure, the sink must
/// fail-stop and invoke certified cancel-on-disconnect/manual reconciliation.
/// Production sinks must additionally be bounded, nonblocking, and allocation-free.
/// `seal_emergency` is backed by an independently pre-reserved slot provisioned at
/// initialization, not by capacity acquired through `reserve`; it must be eligible
/// as the latest authenticated recovery seal. Failure of that lane is an immediate
/// fail-stop plus certified cancel-on-disconnect/disconnect action.
///
/// A production implementation must encode every ticket, record type, borrowed byte
/// prefix, proof, abort marker, and checkpoint unambiguously inside an authenticated
/// append-only container such as [`crate::audit_container`]. Its authenticated header
/// must carry the exact configuration/software digests, venue/session, canonical
/// market-data/order-entry/optional-drop-copy sources, authoritative instrument-definition
/// binding, and clock epoch, and recovery must compare the seal with a latest anchor outside
/// the journal's writable failure domain. Implementing this trait alone does not provide
/// those persistence, cryptographic, or rollback guarantees.
pub trait NativeLiveAudit<Proof: Copy> {
    type Ticket: Copy;
    type Error: Copy;

    /// Atomically acquire the entire fixed reservation.
    ///
    /// # Errors
    ///
    /// Returns the sink's fixed capacity or persistence error without reserving a
    /// partial ticket.
    fn reserve(&mut self, capacity: NativeLiveAuditCapacity) -> Result<Self::Ticket, Self::Error>;
    fn seal_emergency(&mut self, record: NativeLiveEmergencySealRecord<Self::Error>);
    fn record_scheduler_commit(&mut self, ticket: Self::Ticket, commit: SchedulerCommit);
    fn record_source_event(&mut self, ticket: Self::Ticket, event: NormalizedEvent);
    /// Atomically assign a process-global tail ordinal and causally nondecreasing
    /// capture timestamp, persist the canonical transmission event, and return it.
    /// This sink must be the same authoritative sequencer used by raw ingress. The
    /// returned event must preserve `input.command` and `input.status`, may only raise
    /// `input.monotonic_now`, and must never reuse an ordinal after crash.
    fn append_transmission_event(
        &mut self,
        ticket: Self::Ticket,
        input: TransmissionInput,
    ) -> NormalizedEvent;
    /// Atomically assign and durably persist this exact intent with a process-global
    /// native frame ordinal in `1..u64::MAX` before returning. This must use the same
    /// gapless RX/TX frame sequencer as native ingress capture, must never reuse an
    /// ordinal after crash, and must fail-stop on exhaustion or persistence failure.
    /// A persisted intent without a later disposition is recovered as `Ambiguous`.
    fn append_native_intent(&mut self, ticket: Self::Ticket, intent: NativeLiveIntent<'_>) -> u64;
    fn record_native_egress(
        &mut self,
        ticket: Self::Ticket,
        record: NativeLiveEgressRecord<'_, Proof>,
    );
    fn record_proof_fault(
        &mut self,
        ticket: Self::Ticket,
        record: NativeLiveProofFaultRecord<'_, Proof>,
    );
    fn record_encode_fault(&mut self, ticket: Self::Ticket, record: NativeLiveEncodeFaultRecord);
    fn record_clock_fallback(
        &mut self,
        ticket: Self::Ticket,
        record: NativeLiveClockFallbackRecord,
    );
    fn record_reactor_fault(&mut self, ticket: Self::Ticket, record: NativeLiveReactorFaultRecord);
    fn record_application_fault(
        &mut self,
        ticket: Self::Ticket,
        record: NativeLiveApplicationFaultRecord,
    );
    /// Seal the reservation with the exact coordinator metadata reached by this call.
    /// Recovery may expose this metadata only after all preceding records in the
    /// ticket are durable in the same failure domain. It is not a snapshot of the
    /// reactor, venue session, adapter, transport, or authenticated control gate.
    fn seal(&mut self, ticket: Self::Ticket, checkpoint: NativeLiveCheckpoint);
    fn abort(&mut self, ticket: Self::Ticket);
}

/// Persistent coordinator phase. `Ready` and the killed `KilledRecovery` recovery
/// phase accept clean-boundary source events; only `SafetyPending` accepts a safety
/// continuation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeLivePhase {
    Ready,
    SafetyPending,
    KilledRecovery,
    Ambiguous,
    Failed,
}

/// Durable coordinator metadata emitted with every completed audit reservation.
///
/// This value binds identity, audit cursors, and the coordinator phase. It deliberately
/// does not snapshot or commit the full engine/reactor, venue-session/adapter, transport,
/// or authenticated-control state. Consequently, it cannot by itself authorize a
/// runnable restart. Until an in-library recovery session consumes the authenticated
/// native/source/scheduler trace and returns the exact reconstructed owners, only the
/// non-runnable `Ambiguous` and `Failed` phases may be reconstructed from this metadata.
///
/// `monotonic_clock_epoch` is an authenticated deployment identifier for the boot or
/// clock domain in which local monotonic samples are meaningful. It is not a wall
/// clock timestamp and must change whenever that clock domain changes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeLiveCheckpoint {
    pub expected_identity: VenueIdentity,
    pub expected_instrument_binding: InstrumentDefinitionBinding,
    pub expected_market_data_source: EventSource,
    pub expected_order_entry_source: EventSource,
    pub expected_drop_copy_source: Option<EventSource>,
    pub monotonic_clock_epoch: u64,
    pub expected_first_source_capture: CaptureOrdinal,
    pub last_source_capture: Option<CaptureOrdinal>,
    pub last_feedback_capture: Option<CaptureOrdinal>,
    pub last_outbound_frame: Option<u64>,
    pub next_commit_ordinal: u64,
    pub phase: NativeLivePhase,
}

/// Exact rejection reason for a checkpoint supplied after deterministic replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeLiveCheckpointError {
    InvalidVenueIdentity(VenueIdentity),
    InvalidInstrumentBinding,
    InstrumentVenueMismatch {
        identity: VenueId,
        definition: VenueId,
    },
    EngineInstrumentBindingMismatch {
        checkpoint: InstrumentDefinitionBinding,
        engine: InstrumentDefinitionBinding,
    },
    InvalidMarketDataSource(EventSource),
    InvalidOrderEntrySource(EventSource),
    InvalidDropCopySource(EventSource),
    DropCopyConfigurationMismatch {
        checkpoint_enabled: bool,
        engine_enabled: bool,
    },
    EngineVenueMismatch {
        expected: VenueId,
        actual: VenueId,
    },
    InvalidMonotonicClockEpoch(u64),
    MonotonicClockEpochMismatch {
        checkpoint: u64,
        current: u64,
    },
    InvalidExpectedFirstSourceCapture(CaptureOrdinal),
    InvalidLastSourceCapture {
        expected_at_least: CaptureOrdinal,
        actual: CaptureOrdinal,
    },
    InvalidLastFeedbackCapture(CaptureOrdinal),
    InvalidLastOutboundFrame(u64),
    InvalidNextCommitOrdinal(u64),
    ReactorBoundaryMismatch {
        phase: NativeLivePhase,
        engine_killed: bool,
        retained: bool,
        mandatory_kill: bool,
        outstanding: usize,
    },
    /// The authenticated coordinator metadata names a phase that can execute or
    /// continue safety work, but no typed proof binds the supplied reactor/session/
    /// adapter owners to the complete authenticated replay that produced it.
    ReplayStateUnbound {
        phase: NativeLivePhase,
    },
}

/// External authenticity boundary for coordinator metadata. Implementations must
/// verify that `checkpoint` is the latest non-rollback audit seal for this process
/// identity. This trait does not receive or authenticate the complete reconstructed
/// reactor, venue session, adapter, transport, or control gate, so successful metadata
/// verification does not authorize a runnable restart. Merely validating a checksum,
/// MAC without a trusted latest anchor, or caller-selected old anchor is insufficient.
pub trait NativeLiveCheckpointVerifier {
    type Seal: Copy;
    type Error: Copy;

    /// Verify that `seal` authenticates the latest non-rollback checkpoint.
    ///
    /// # Errors
    ///
    /// Returns the implementation's fixed authentication, freshness, or binding
    /// failure without authorizing checkpoint restoration.
    fn verify_latest(
        &mut self,
        checkpoint: NativeLiveCheckpoint,
        seal: Self::Seal,
    ) -> Result<(), Self::Error>;
}

/// Authentication or structural rejection while restoring live coordination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeLiveRecoveryError<VerifyError: Copy> {
    Verification(VerifyError),
    Checkpoint(NativeLiveCheckpointError),
}

/// Successful per-event accounting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeLiveSummary {
    pub source_commit_ordinal: u64,
    pub commands: u8,
    pub sent: u8,
    pub proven_unsent: u8,
}

/// A pre-submit failure for which every reactor command was resolved locally as
/// proven unsent before internal safety was requested.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeLiveEncodeFault {
    Venue(VenueError),
    DirtyEncodedTail { index: usize },
}

/// Exact cause of a safety-pending return. The audit error remains transport/sink
/// specific while retaining a fixed outer classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeLiveSafetyReason<AuditError: Copy> {
    AuditReservation(AuditError),
    Encode(NativeLiveEncodeFault),
    InvalidProvenUnsentTimestamp(MonotonicTimestampNs),
    InvalidSentTimestamp(MonotonicTimestampNs),
    KillCancelProvenUnsent {
        commands: u8,
    },
    ReactorFault {
        route: SchedulerRoute,
    },
    SchedulerFault,
    TransmissionTimestampRegression {
        received: MonotonicTimestampNs,
        causal_floor: MonotonicTimestampNs,
    },
}

/// Non-error terminal status for one call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeLiveStatus<AuditError: Copy> {
    Completed(NativeLiveSummary),
    SafetyPending {
        reason: NativeLiveSafetyReason<AuditError>,
    },
    KilledRecoveryEntered(NativeLiveSummary),
    Ambiguous {
        frame_ordinal: u64,
        egress: ReactorEgress,
    },
}

/// Contract or invariant failure. Operational reservation and pre-submit encoder
/// faults are returned as [`NativeLiveStatus::SafetyPending`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeLiveError {
    InvalidVenueIdentity(VenueIdentity),
    InvalidInstrumentDefinition(InstrumentDefinitionError),
    InstrumentVenueMismatch {
        identity: VenueId,
        definition: VenueId,
    },
    InstrumentDefinitionMismatch {
        expected: InstrumentDefinitionBinding,
        session: InstrumentDefinitionBinding,
        engine: InstrumentDefinitionBinding,
        session_engine_rules_equal: bool,
    },
    InvalidMarketDataSource(EventSource),
    InvalidOrderEntrySource(EventSource),
    InvalidDropCopySource(EventSource),
    DropCopyConfigurationMismatch {
        coordinator_enabled: bool,
        engine_enabled: bool,
    },
    DropCopyNotConfigured,
    VenueIdentityMismatch {
        expected: VenueIdentity,
        session: VenueIdentity,
        adapter: VenueIdentity,
        engine_venue: VenueId,
    },
    SourceRouteMismatch {
        expected_source: EventSource,
        actual_source: EventSource,
        expected_venue: VenueId,
        actual_venue: VenueId,
    },
    InvalidMonotonicClockEpoch(u64),
    InvalidInitialCaptureOrdinal(CaptureOrdinal),
    InvalidInitialCommitOrdinal(u64),
    Phase(NativeLivePhase),
    DirtyScratch,
    EmptyEncodeBuffer,
    DirtyReactorBoundary {
        retained: bool,
        mandatory_kill: bool,
        outstanding: usize,
    },
    SourceCaptureOrdinalMismatch {
        expected: CaptureOrdinal,
        actual: CaptureOrdinal,
    },
    SourceCaptureOrdinalRegression {
        previous: CaptureOrdinal,
        actual: CaptureOrdinal,
    },
    InvalidFeedbackCaptureOrdinal {
        previous_feedback: Option<CaptureOrdinal>,
        last_source: Option<CaptureOrdinal>,
        actual: CaptureOrdinal,
    },
    InvalidAppendedTransmissionEvent,
    InvalidNativeFrameOrdinal {
        previous_outbound: Option<u64>,
        actual: u64,
    },
    SourceMustBeNormal,
    ControlProvenance,
    InvalidFaultTimestamp(MonotonicTimestampNs),
    LocalMonotonicRegression {
        required_at_least: MonotonicTimestampNs,
        received: MonotonicTimestampNs,
    },
    InvalidTransmissionTimestamp(MonotonicTimestampNs),
    EngineKillPhaseMismatch {
        phase: NativeLivePhase,
        engine_killed: bool,
    },
    CommitOrdinalExhausted,
    RingInvariant,
    EgressInvariant,
    KilledModeNonCancelCommand,
    FeedbackProducedCommands,
    Codec(EventCodecError),
    Reactor(ReactorFailure),
    Scheduler(SchedulerCommitError),
}

/// Caller-owned, fixed live scratch. Both SPSC rings have one usable slot (`N = 2`
/// includes the sentinel); no storage grows at runtime. Deployments must certify a
/// finite `ENCODED_BYTES` maximum because tail verification is linear in that bound.
#[derive(Debug)]
pub struct NativeLiveScratch<const ENCODED_BYTES: usize> {
    pending_egress: [Option<ReactorEgress>; MAX_REACTOR_COMMANDS_PER_INPUT],
    reactor_egress: [Option<ReactorEgress>; MAX_REACTOR_COMMANDS_PER_INPUT],
    encoded: [u8; ENCODED_BYTES],
    normal: SpscRing<ReactorInput, 2>,
    feedback: SpscRing<TransmissionInput, 2>,
}

impl<const ENCODED_BYTES: usize> NativeLiveScratch<ENCODED_BYTES> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending_egress: [None; MAX_REACTOR_COMMANDS_PER_INPUT],
            reactor_egress: [None; MAX_REACTOR_COMMANDS_PER_INPUT],
            encoded: [0; ENCODED_BYTES],
            normal: SpscRing::new(),
            feedback: SpscRing::new(),
        }
    }

    #[must_use]
    pub const fn encoded_capacity(&self) -> usize {
        ENCODED_BYTES
    }

    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.pending_egress.iter().all(Option::is_none)
            && self.reactor_egress.iter().all(Option::is_none)
            && self.encoded.iter().all(|byte| *byte == 0)
            && self.normal.is_empty()
            && self.feedback.is_empty()
    }

    fn clear(&mut self) {
        self.pending_egress.fill(None);
        self.reactor_egress.fill(None);
        self.encoded.fill(0);
    }
}

impl<const ENCODED_BYTES: usize> Default for NativeLiveScratch<ENCODED_BYTES> {
    fn default() -> Self {
        Self::new()
    }
}

/// Fixed ordinal and phase owner for the native live execution boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeLiveCoordinator {
    expected_identity: VenueIdentity,
    expected_instrument_binding: InstrumentDefinitionBinding,
    expected_market_data_source: EventSource,
    expected_order_entry_source: EventSource,
    expected_drop_copy_source: Option<EventSource>,
    monotonic_clock_epoch: u64,
    expected_first_source_capture: CaptureOrdinal,
    last_source_capture: Option<CaptureOrdinal>,
    last_feedback_capture: Option<CaptureOrdinal>,
    last_outbound_frame: Option<u64>,
    next_commit_ordinal: u64,
    phase: NativeLivePhase,
}

const fn valid_market_data_source(identity: VenueIdentity, source: EventSource) -> bool {
    source.id.protocol != 0
        && source.id.channel != 0
        && source.id.protocol == identity.market_data_protocol.0
        && matches!(source.sequence_domain, SequenceDomain::MarketData)
        && source.session_epoch.0 != 0
}

const fn valid_order_entry_source(identity: VenueIdentity, source: EventSource) -> bool {
    source.id.protocol != 0
        && source.id.channel != 0
        && source.id.protocol == identity.order_entry_protocol.0
        && matches!(source.sequence_domain, SequenceDomain::OrderEntry)
        && source.session_epoch.0 != 0
}

const fn valid_drop_copy_source(source: EventSource) -> bool {
    source.id.protocol != 0
        && source.id.channel != 0
        && matches!(source.sequence_domain, SequenceDomain::DropCopy)
        && source.session_epoch.0 != 0
}

impl NativeLiveCoordinator {
    /// Construct a coordinator for one exact venue/protocol/session identity and its
    /// authenticated market-data and order-entry sequence namespaces. The coordinator
    /// runs in a nonzero monotonic-clock epoch at exact nonzero source-journal and
    /// scheduler ordinals. Native frame ordinals are owned by the shared RX/TX sequencer.
    ///
    /// # Errors
    ///
    /// Zero is reserved in every identity and ordinal domain.
    #[allow(
        clippy::result_large_err,
        reason = "construction shares the exact fixed hot-path failure type"
    )]
    pub const fn new(
        expected_identity: VenueIdentity,
        expected_instrument_definition: InstrumentDefinition,
        expected_market_data_source: EventSource,
        expected_order_entry_source: EventSource,
        monotonic_clock_epoch: u64,
        first_capture_ordinal: CaptureOrdinal,
        first_commit_ordinal: u64,
    ) -> Result<Self, NativeLiveError> {
        Self::new_configured(
            expected_identity,
            expected_instrument_definition,
            expected_market_data_source,
            expected_order_entry_source,
            None,
            monotonic_clock_epoch,
            first_capture_ordinal,
            first_commit_ordinal,
        )
    }

    /// Construct a coordinator that additionally accepts one exact, independently
    /// sequenced drop-copy source. The paired engine must have drop copy enabled.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid identity, source namespace, epoch, or ordinal.
    #[allow(
        clippy::too_many_arguments,
        clippy::result_large_err,
        reason = "construction binds every authenticated live namespace explicitly"
    )]
    pub const fn new_with_drop_copy(
        expected_identity: VenueIdentity,
        expected_instrument_definition: InstrumentDefinition,
        expected_market_data_source: EventSource,
        expected_order_entry_source: EventSource,
        expected_drop_copy_source: EventSource,
        monotonic_clock_epoch: u64,
        first_capture_ordinal: CaptureOrdinal,
        first_commit_ordinal: u64,
    ) -> Result<Self, NativeLiveError> {
        Self::new_configured(
            expected_identity,
            expected_instrument_definition,
            expected_market_data_source,
            expected_order_entry_source,
            Some(expected_drop_copy_source),
            monotonic_clock_epoch,
            first_capture_ordinal,
            first_commit_ordinal,
        )
    }

    #[allow(clippy::too_many_arguments, clippy::result_large_err)]
    const fn new_configured(
        expected_identity: VenueIdentity,
        expected_instrument_definition: InstrumentDefinition,
        expected_market_data_source: EventSource,
        expected_order_entry_source: EventSource,
        expected_drop_copy_source: Option<EventSource>,
        monotonic_clock_epoch: u64,
        first_capture_ordinal: CaptureOrdinal,
        first_commit_ordinal: u64,
    ) -> Result<Self, NativeLiveError> {
        if !expected_identity.is_valid() {
            return Err(NativeLiveError::InvalidVenueIdentity(expected_identity));
        }
        if let Err(error) = expected_instrument_definition.validate() {
            return Err(NativeLiveError::InvalidInstrumentDefinition(error));
        }
        if expected_instrument_definition.venue.0 != expected_identity.venue.0 {
            return Err(NativeLiveError::InstrumentVenueMismatch {
                identity: expected_identity.venue,
                definition: expected_instrument_definition.venue,
            });
        }
        if !valid_market_data_source(expected_identity, expected_market_data_source) {
            return Err(NativeLiveError::InvalidMarketDataSource(
                expected_market_data_source,
            ));
        }
        if !valid_order_entry_source(expected_identity, expected_order_entry_source) {
            return Err(NativeLiveError::InvalidOrderEntrySource(
                expected_order_entry_source,
            ));
        }
        if let Some(source) = expected_drop_copy_source
            && !valid_drop_copy_source(source)
        {
            return Err(NativeLiveError::InvalidDropCopySource(source));
        }
        if monotonic_clock_epoch == 0 {
            return Err(NativeLiveError::InvalidMonotonicClockEpoch(
                monotonic_clock_epoch,
            ));
        }
        if first_capture_ordinal.0 == 0 {
            return Err(NativeLiveError::InvalidInitialCaptureOrdinal(
                first_capture_ordinal,
            ));
        }
        if first_commit_ordinal == 0 {
            return Err(NativeLiveError::InvalidInitialCommitOrdinal(
                first_commit_ordinal,
            ));
        }
        Ok(Self {
            expected_identity,
            expected_instrument_binding: expected_instrument_definition.binding(),
            expected_market_data_source,
            expected_order_entry_source,
            expected_drop_copy_source,
            monotonic_clock_epoch,
            expected_first_source_capture: first_capture_ordinal,
            last_source_capture: None,
            last_feedback_capture: None,
            last_outbound_frame: None,
            next_commit_ordinal: first_commit_ordinal,
            phase: NativeLivePhase::Ready,
        })
    }

    #[must_use]
    pub const fn phase(self) -> NativeLivePhase {
        self.phase
    }

    #[must_use]
    pub const fn expected_identity(self) -> VenueIdentity {
        self.expected_identity
    }

    #[must_use]
    pub const fn expected_instrument_binding(self) -> InstrumentDefinitionBinding {
        self.expected_instrument_binding
    }

    #[must_use]
    pub const fn expected_market_data_source(self) -> EventSource {
        self.expected_market_data_source
    }

    #[must_use]
    pub const fn expected_order_entry_source(self) -> EventSource {
        self.expected_order_entry_source
    }

    #[must_use]
    pub const fn expected_drop_copy_source(self) -> Option<EventSource> {
        self.expected_drop_copy_source
    }

    #[must_use]
    pub const fn checkpoint(self) -> NativeLiveCheckpoint {
        NativeLiveCheckpoint {
            expected_identity: self.expected_identity,
            expected_instrument_binding: self.expected_instrument_binding,
            expected_market_data_source: self.expected_market_data_source,
            expected_order_entry_source: self.expected_order_entry_source,
            expected_drop_copy_source: self.expected_drop_copy_source,
            monotonic_clock_epoch: self.monotonic_clock_epoch,
            expected_first_source_capture: self.expected_first_source_capture,
            last_source_capture: self.last_source_capture,
            last_feedback_capture: self.last_feedback_capture,
            last_outbound_frame: self.last_outbound_frame,
            next_commit_ordinal: self.next_commit_ordinal,
            phase: self.phase,
        }
    }

    /// Reconstruct non-runnable coordinator metadata from the latest authenticated
    /// audit seal. Native capture and canonical-event appenders retain their own
    /// authoritative tails; this method never restores or rewinds them.
    ///
    /// `Ready`, `SafetyPending`, and `KilledRecovery` are rejected even when the
    /// supplied reactor satisfies the shallow structural boundary checks. Those
    /// phases require a future typed recovery session that owns the complete
    /// authenticated replay and returns the exact reactor, venue session, adapter,
    /// transport, and control state. `Ambiguous` and `Failed` remain non-runnable and
    /// may be reconstructed for fail-stop reconciliation.
    ///
    /// A prior boot's numeric monotonic timestamps must not be reused: an epoch
    /// mismatch is rejected and requires replay/reconciliation in the current epoch.
    ///
    /// # Errors
    ///
    /// Returns the verifier's rejection, invalid metadata/boundary state, or
    /// [`NativeLiveCheckpointError::ReplayStateUnbound`] for a runnable phase.
    #[allow(clippy::too_many_arguments, clippy::result_large_err)]
    pub fn from_checkpoint<
        const MAX_BOOK_ORDERS: usize,
        const MAX_BOOK_LEVELS: usize,
        const MAX_ORDERS: usize,
        const MAX_RECENT_TRADES: usize,
        const MAX_FILLS: usize,
        V,
    >(
        checkpoint: NativeLiveCheckpoint,
        seal: V::Seal,
        current_monotonic_clock_epoch: u64,
        reactor: &HotPathReactor<
            MAX_BOOK_ORDERS,
            MAX_BOOK_LEVELS,
            MAX_ORDERS,
            MAX_RECENT_TRADES,
            MAX_FILLS,
        >,
        verifier: &mut V,
    ) -> Result<Self, NativeLiveRecoveryError<V::Error>>
    where
        V: NativeLiveCheckpointVerifier,
    {
        verifier
            .verify_latest(checkpoint, seal)
            .map_err(NativeLiveRecoveryError::Verification)?;
        Self::validate_checkpoint(checkpoint, current_monotonic_clock_epoch, reactor)
            .map_err(NativeLiveRecoveryError::Checkpoint)?;
        Ok(Self {
            expected_identity: checkpoint.expected_identity,
            expected_instrument_binding: checkpoint.expected_instrument_binding,
            expected_market_data_source: checkpoint.expected_market_data_source,
            expected_order_entry_source: checkpoint.expected_order_entry_source,
            expected_drop_copy_source: checkpoint.expected_drop_copy_source,
            monotonic_clock_epoch: checkpoint.monotonic_clock_epoch,
            expected_first_source_capture: checkpoint.expected_first_source_capture,
            last_source_capture: checkpoint.last_source_capture,
            last_feedback_capture: checkpoint.last_feedback_capture,
            last_outbound_frame: checkpoint.last_outbound_frame,
            next_commit_ordinal: checkpoint.next_commit_ordinal,
            phase: checkpoint.phase,
        })
    }

    #[must_use]
    pub const fn last_source_capture_ordinal(self) -> Option<CaptureOrdinal> {
        self.last_source_capture
    }

    #[must_use]
    pub const fn last_feedback_capture_ordinal(self) -> Option<CaptureOrdinal> {
        self.last_feedback_capture
    }

    #[must_use]
    pub const fn last_outbound_frame_ordinal(self) -> Option<u64> {
        self.last_outbound_frame
    }

    #[must_use]
    pub const fn next_commit_ordinal(self) -> u64 {
        self.next_commit_ordinal
    }

    #[allow(
        clippy::result_large_err,
        clippy::too_many_lines,
        reason = "checkpoint validation preserves fixed, allocation-free typed failures"
    )]
    fn validate_checkpoint<
        const MAX_BOOK_ORDERS: usize,
        const MAX_BOOK_LEVELS: usize,
        const MAX_ORDERS: usize,
        const MAX_RECENT_TRADES: usize,
        const MAX_FILLS: usize,
    >(
        checkpoint: NativeLiveCheckpoint,
        current_monotonic_clock_epoch: u64,
        reactor: &HotPathReactor<
            MAX_BOOK_ORDERS,
            MAX_BOOK_LEVELS,
            MAX_ORDERS,
            MAX_RECENT_TRADES,
            MAX_FILLS,
        >,
    ) -> Result<(), NativeLiveCheckpointError> {
        if !checkpoint.expected_identity.is_valid() {
            return Err(NativeLiveCheckpointError::InvalidVenueIdentity(
                checkpoint.expected_identity,
            ));
        }
        if !checkpoint.expected_instrument_binding.is_valid() {
            return Err(NativeLiveCheckpointError::InvalidInstrumentBinding);
        }
        if checkpoint.expected_instrument_binding.venue != checkpoint.expected_identity.venue {
            return Err(NativeLiveCheckpointError::InstrumentVenueMismatch {
                identity: checkpoint.expected_identity.venue,
                definition: checkpoint.expected_instrument_binding.venue,
            });
        }
        if !valid_market_data_source(
            checkpoint.expected_identity,
            checkpoint.expected_market_data_source,
        ) {
            return Err(NativeLiveCheckpointError::InvalidMarketDataSource(
                checkpoint.expected_market_data_source,
            ));
        }
        if !valid_order_entry_source(
            checkpoint.expected_identity,
            checkpoint.expected_order_entry_source,
        ) {
            return Err(NativeLiveCheckpointError::InvalidOrderEntrySource(
                checkpoint.expected_order_entry_source,
            ));
        }
        if let Some(source) = checkpoint.expected_drop_copy_source
            && !valid_drop_copy_source(source)
        {
            return Err(NativeLiveCheckpointError::InvalidDropCopySource(source));
        }
        let checkpoint_enabled = checkpoint.expected_drop_copy_source.is_some();
        let engine_enabled = reactor.engine().drop_copy_enabled();
        if checkpoint_enabled != engine_enabled {
            return Err(NativeLiveCheckpointError::DropCopyConfigurationMismatch {
                checkpoint_enabled,
                engine_enabled,
            });
        }
        let engine_venue = reactor.engine().config().venue;
        if checkpoint.expected_identity.venue != engine_venue {
            return Err(NativeLiveCheckpointError::EngineVenueMismatch {
                expected: checkpoint.expected_identity.venue,
                actual: engine_venue,
            });
        }
        let engine_binding = reactor.engine().config().instrument_definition.binding();
        if checkpoint.expected_instrument_binding != engine_binding {
            return Err(NativeLiveCheckpointError::EngineInstrumentBindingMismatch {
                checkpoint: checkpoint.expected_instrument_binding,
                engine: engine_binding,
            });
        }
        if current_monotonic_clock_epoch == 0 {
            return Err(NativeLiveCheckpointError::InvalidMonotonicClockEpoch(
                current_monotonic_clock_epoch,
            ));
        }
        if checkpoint.monotonic_clock_epoch == 0 {
            return Err(NativeLiveCheckpointError::InvalidMonotonicClockEpoch(
                checkpoint.monotonic_clock_epoch,
            ));
        }
        if checkpoint.monotonic_clock_epoch != current_monotonic_clock_epoch {
            return Err(NativeLiveCheckpointError::MonotonicClockEpochMismatch {
                checkpoint: checkpoint.monotonic_clock_epoch,
                current: current_monotonic_clock_epoch,
            });
        }
        if checkpoint.expected_first_source_capture.0 == 0 {
            return Err(
                NativeLiveCheckpointError::InvalidExpectedFirstSourceCapture(
                    checkpoint.expected_first_source_capture,
                ),
            );
        }
        if let Some(actual) = checkpoint.last_source_capture
            && (actual.0 == 0 || actual < checkpoint.expected_first_source_capture)
        {
            return Err(NativeLiveCheckpointError::InvalidLastSourceCapture {
                expected_at_least: checkpoint.expected_first_source_capture,
                actual,
            });
        }
        if let Some(actual) = checkpoint.last_feedback_capture
            && actual.0 == 0
        {
            return Err(NativeLiveCheckpointError::InvalidLastFeedbackCapture(
                actual,
            ));
        }
        if let Some(actual) = checkpoint.last_outbound_frame
            && (actual == 0 || actual == u64::MAX)
        {
            return Err(NativeLiveCheckpointError::InvalidLastOutboundFrame(actual));
        }
        if checkpoint.next_commit_ordinal == 0 {
            return Err(NativeLiveCheckpointError::InvalidNextCommitOrdinal(
                checkpoint.next_commit_ordinal,
            ));
        }

        let engine_killed = reactor.engine().kill_snapshot().is_some();
        let retained = reactor.has_retained_event();
        let mandatory_kill = reactor.mandatory_kill_pending();
        let outstanding = reactor.outstanding_transmissions();
        let boundary_matches = match checkpoint.phase {
            NativeLivePhase::Ready => {
                !engine_killed && !mandatory_kill && !retained && outstanding == 0
            }
            NativeLivePhase::SafetyPending => mandatory_kill && !retained && outstanding == 0,
            NativeLivePhase::KilledRecovery => {
                engine_killed && !mandatory_kill && !retained && outstanding == 0
            }
            // Both phases are deliberately non-runnable. Their exact dirty state is
            // retained by deterministic replay for external ownership reconciliation.
            NativeLivePhase::Ambiguous | NativeLivePhase::Failed => mandatory_kill,
        };
        if !boundary_matches {
            return Err(NativeLiveCheckpointError::ReactorBoundaryMismatch {
                phase: checkpoint.phase,
                engine_killed,
                retained,
                mandatory_kill,
                outstanding,
            });
        }
        if matches!(
            checkpoint.phase,
            NativeLivePhase::Ready
                | NativeLivePhase::SafetyPending
                | NativeLivePhase::KilledRecovery
        ) {
            return Err(NativeLiveCheckpointError::ReplayStateUnbound {
                phase: checkpoint.phase,
            });
        }
        Ok(())
    }

    /// Process one canonical normal-lane event from a clean reactor boundary.
    ///
    /// Audit capacity is reserved before the source reactor mutation. Each source or
    /// feedback scheduler commit is persisted before a later command can be submitted.
    /// At most two source commands are encoded and submitted in reactor FIFO order.
    ///
    /// `local_monotonic_now` must be a nonzero, authenticated coordinator-clock
    /// observation sampled immediately around this call. It timestamps definitely
    /// local encoder failures and is the explicitly audited fallback only when a
    /// non-ambiguous transport result violates its contract by returning zero.
    ///
    /// # Errors
    ///
    /// Returns a fixed contract/invariant failure. A return after source mutation
    /// fail-latches this coordinator; callers must not infer venue readiness from this
    /// boundary alone.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        clippy::result_large_err,
        reason = "the hot-path boundary uses explicit fixed owners and exact failures"
    )]
    pub fn process_event<
        const MAX_BOOK_ORDERS: usize,
        const MAX_BOOK_LEVELS: usize,
        const MAX_ORDERS: usize,
        const MAX_RECENT_TRADES: usize,
        const MAX_FILLS: usize,
        const ENCODED_BYTES: usize,
        A,
        T,
        L,
    >(
        &mut self,
        source_event: NormalizedEvent,
        local_monotonic_now: MonotonicTimestampNs,
        reactor: &mut HotPathReactor<
            MAX_BOOK_ORDERS,
            MAX_BOOK_LEVELS,
            MAX_ORDERS,
            MAX_RECENT_TRADES,
            MAX_FILLS,
        >,
        session: &mut VenueSession,
        adapter: &mut A,
        transport: &mut T,
        audit: &mut L,
        scratch: &mut NativeLiveScratch<ENCODED_BYTES>,
    ) -> Result<NativeLiveStatus<L::Error>, NativeLiveError>
    where
        A: NativeOrderEntryEncoder,
        T: NativeOrderTransport
            + NativeTransmissionProofVerifier<Proof = <T as NativeOrderTransport>::Proof>,
        L: NativeLiveAudit<<T as NativeOrderTransport>::Proof>,
    {
        self.validate_venue_binding(
            session.identity(),
            session.instrument_definition(),
            A::IDENTITY,
            reactor.engine().config().venue,
            reactor.engine().config().instrument_definition,
            reactor.engine().drop_copy_enabled(),
        )?;
        let entry_phase = self.phase;
        let fault_monotonic_now = local_monotonic_now;
        let input = self.preflight(source_event, local_monotonic_now, reactor, scratch)?;
        let ticket = match audit.reserve(NATIVE_LIVE_AUDIT_CAPACITY) {
            Ok(ticket) => ticket,
            Err(error) => {
                let _new_request = reactor.trip_internal_safety();
                scratch.clear();
                self.phase = NativeLivePhase::SafetyPending;
                audit.seal_emergency(NativeLiveEmergencySealRecord {
                    operation: NativeLiveOperation::ProcessEvent,
                    rejected_source: Some(source_event),
                    local_monotonic_sample: local_monotonic_now,
                    error,
                    checkpoint: self.checkpoint(),
                });
                return Ok(NativeLiveStatus::SafetyPending {
                    reason: NativeLiveSafetyReason::AuditReservation(error),
                });
            }
        };
        let source_commit_ordinal = self.next_commit_ordinal;
        audit.record_source_event(ticket, source_event);
        let source_outcome = match run_source(reactor, input, scratch) {
            Ok(outcome) => outcome,
            Err(NativeLiveError::Reactor(failure)) => {
                if let Err(error) = self.record_reactor_fault(
                    SchedulerRoute::Normal,
                    Some(source_event),
                    failure,
                    reactor,
                    audit,
                    ticket,
                    scratch,
                ) {
                    self.seal_failed(reactor, transport, audit, ticket, scratch);
                    return Err(error);
                }
                if failure.report.run_ordinal.is_none()
                    || failure.report.events_processed != 1
                    || failure.report.transmissions_processed != 0
                {
                    self.seal_failed(reactor, transport, audit, ticket, scratch);
                    return Err(NativeLiveError::Reactor(failure));
                }
                self.last_source_capture = Some(source_event.capture_ordinal);
                scratch.pending_egress = scratch.reactor_egress;
                scratch.reactor_egress.fill(None);
                if let Err(error) = self.resolve_published_unsent(
                    failure.report.commands_published,
                    local_monotonic_now,
                    reactor,
                    audit,
                    ticket,
                    scratch,
                ) {
                    self.seal_failed(reactor, transport, audit, ticket, scratch);
                    return Err(error);
                }
                let _new_request = reactor.trip_internal_safety();
                scratch.clear();
                self.phase = NativeLivePhase::SafetyPending;
                audit.seal(ticket, self.checkpoint());
                return Ok(NativeLiveStatus::SafetyPending {
                    reason: NativeLiveSafetyReason::ReactorFault {
                        route: SchedulerRoute::Normal,
                    },
                });
            }
            Err(error) => {
                audit.abort(ticket);
                return Err(error);
            }
        };
        self.last_source_capture = Some(source_event.capture_ordinal);
        scratch.pending_egress = scratch.reactor_egress;
        scratch.reactor_egress.fill(None);
        let source_commit = match SchedulerCommit::from_replay_outcome(
            self.next_commit_ordinal,
            source_event,
            source_outcome,
            &scratch.pending_egress,
        ) {
            Ok(commit) => commit,
            Err(error) => {
                self.record_application_fault(
                    SchedulerRoute::Normal,
                    Some(source_event),
                    source_outcome,
                    scratch.pending_egress,
                    NativeLivePostRunFault::Scheduler(error),
                    reactor,
                    audit,
                    ticket,
                )?;
                if let Err(cleanup_error) = self.resolve_published_unsent(
                    source_outcome.commands,
                    local_monotonic_now,
                    reactor,
                    audit,
                    ticket,
                    scratch,
                ) {
                    self.seal_failed(reactor, transport, audit, ticket, scratch);
                    return Err(cleanup_error);
                }
                let _new_request = reactor.trip_internal_safety();
                scratch.clear();
                self.phase = NativeLivePhase::SafetyPending;
                audit.seal(ticket, self.checkpoint());
                return Ok(NativeLiveStatus::SafetyPending {
                    reason: NativeLiveSafetyReason::SchedulerFault,
                });
            }
        };
        audit.record_scheduler_commit(ticket, source_commit);
        self.next_commit_ordinal += 1;

        let commands = source_outcome.commands;
        let source_engine_killed = reactor.engine().kill_snapshot().is_some();
        if source_engine_killed
            && source_commit
                .commands
                .iter()
                .flatten()
                .any(|command| !matches!(command, OrderCommand::Cancel(_)))
        {
            let Some(first) = scratch.pending_egress[0].take() else {
                self.seal_failed(reactor, transport, audit, ticket, scratch);
                return Err(NativeLiveError::EgressInvariant);
            };
            if let Err(error) = self.resolve_local_unsent_from(
                0,
                commands,
                first,
                fault_monotonic_now,
                reactor,
                audit,
                ticket,
                scratch,
            ) {
                self.seal_failed(reactor, transport, audit, ticket, scratch);
                return Err(error);
            }
            let _new_request = reactor.trip_internal_safety();
            scratch.clear();
            self.phase = NativeLivePhase::SafetyPending;
            audit.seal(ticket, self.checkpoint());
            return Err(NativeLiveError::KilledModeNonCancelCommand);
        }
        let mut sent = 0_u8;
        let mut proven_unsent = 0_u8;
        for index in 0..commands {
            let Some(egress) = scratch.pending_egress[index].take() else {
                self.seal_failed(reactor, transport, audit, ticket, scratch);
                return Err(NativeLiveError::EgressInvariant);
            };
            let session_checkpoint = *session;
            let adapter_checkpoint = adapter.checkpoint();
            let frame = match encode_egress(session, adapter, egress, &mut scratch.encoded) {
                Ok(frame) => frame,
                Err(fault) => {
                    *session = session_checkpoint;
                    adapter.restore(adapter_checkpoint);
                    scratch.encoded.fill(0);
                    let effective_now = causal_timestamp(reactor, local_monotonic_now);
                    audit.record_encode_fault(
                        ticket,
                        NativeLiveEncodeFaultRecord {
                            egress,
                            fault,
                            local_monotonic_sample: local_monotonic_now,
                            monotonic_now: effective_now,
                        },
                    );
                    if let Err(error) = self.resolve_local_unsent_from(
                        index,
                        commands,
                        egress,
                        effective_now,
                        reactor,
                        audit,
                        ticket,
                        scratch,
                    ) {
                        self.seal_failed(reactor, transport, audit, ticket, scratch);
                        return Err(error);
                    }
                    let _new_request = reactor.trip_internal_safety();
                    scratch.clear();
                    self.phase = NativeLivePhase::SafetyPending;
                    audit.seal(ticket, self.checkpoint());
                    return Ok(NativeLiveStatus::SafetyPending {
                        reason: NativeLiveSafetyReason::Encode(fault),
                    });
                }
            };
            let intent = NativeLiveIntent {
                adapter_identity: session.identity(),
                venue_sequence: frame.sequence,
                scheduler_commit_ordinal: source_commit.commit_ordinal,
                scheduler_capture_ordinal: source_commit.capture_ordinal,
                scheduler_source_event_crc32c: source_commit.source_event_crc32c,
                egress,
                encoded_bytes: &scratch.encoded[..frame.bytes],
            };
            let frame_ordinal = audit.append_native_intent(ticket, intent);
            if frame_ordinal == 0
                || frame_ordinal == u64::MAX
                || self
                    .last_outbound_frame
                    .is_some_and(|previous| frame_ordinal <= previous)
            {
                *session = session_checkpoint;
                adapter.restore(adapter_checkpoint);
                let _new_request = reactor.trip_internal_safety();
                scratch.clear();
                transport.quiesce();
                self.phase = NativeLivePhase::Ambiguous;
                audit.seal(ticket, self.checkpoint());
                return Err(NativeLiveError::InvalidNativeFrameOrdinal {
                    previous_outbound: self.last_outbound_frame,
                    actual: frame_ordinal,
                });
            }
            self.last_outbound_frame = Some(frame_ordinal);
            let context = intent.with_frame_ordinal(frame_ordinal);
            let submit = transport.submit(context);
            let claim = submit_parts(submit);
            let verified = match verify_live_submit(transport, context, claim) {
                Ok(verified) => verified,
                Err(fault) => {
                    let ambiguous_frame_ordinal = context.frame_ordinal;
                    transport.quiesce();
                    audit.record_proof_fault(
                        ticket,
                        NativeLiveProofFaultRecord {
                            context,
                            proof: claim.proof,
                            claimed_disposition: claim.disposition,
                            claimed_monotonic_now: claim.monotonic_now,
                            fault,
                        },
                    );
                    adapter.commit(adapter_checkpoint);
                    let _new_request = reactor.trip_internal_safety();
                    scratch.clear();
                    self.phase = NativeLivePhase::Ambiguous;
                    audit.seal(ticket, self.checkpoint());
                    return Ok(NativeLiveStatus::Ambiguous {
                        frame_ordinal: ambiguous_frame_ordinal,
                        egress,
                    });
                }
            };
            let NativeSubmitClaim {
                proof,
                disposition,
                monotonic_now,
            } = verified;
            audit.record_native_egress(
                ticket,
                NativeLiveEgressRecord {
                    context,
                    proof,
                    disposition,
                    monotonic_now,
                },
            );
            match disposition {
                NativeSubmitDisposition::Sent => {
                    adapter.commit(adapter_checkpoint);
                    sent += 1;
                }
                NativeSubmitDisposition::ProvenUnsent => {
                    *session = session_checkpoint;
                    adapter.restore(adapter_checkpoint);
                    proven_unsent += 1;
                }
                NativeSubmitDisposition::Ambiguous => {
                    let frame_ordinal = context.frame_ordinal;
                    adapter.commit(adapter_checkpoint);
                    let _new_request = reactor.trip_internal_safety();
                    scratch.clear();
                    self.phase = NativeLivePhase::Ambiguous;
                    audit.seal(ticket, self.checkpoint());
                    return Ok(NativeLiveStatus::Ambiguous {
                        frame_ordinal,
                        egress,
                    });
                }
            }
            scratch.encoded.fill(0);
            if monotonic_now < causal_timestamp(reactor, local_monotonic_now) {
                let effective_now = causal_timestamp(reactor, local_monotonic_now);
                audit.record_clock_fallback(
                    ticket,
                    NativeLiveClockFallbackRecord {
                        egress,
                        disposition,
                        transport_monotonic_now: monotonic_now,
                        local_monotonic_now,
                        effective_monotonic_now: effective_now,
                    },
                );
                let (status, reason) = match disposition {
                    NativeSubmitDisposition::Sent => {
                        let reason = if monotonic_now == MonotonicTimestampNs::ZERO {
                            NativeLiveSafetyReason::InvalidSentTimestamp(monotonic_now)
                        } else {
                            NativeLiveSafetyReason::TransmissionTimestampRegression {
                                received: monotonic_now,
                                causal_floor: effective_now,
                            }
                        };
                        (TransmissionStatus::Sent, reason)
                    }
                    NativeSubmitDisposition::ProvenUnsent => {
                        let reason = if monotonic_now == MonotonicTimestampNs::ZERO {
                            NativeLiveSafetyReason::InvalidProvenUnsentTimestamp(monotonic_now)
                        } else {
                            NativeLiveSafetyReason::TransmissionTimestampRegression {
                                received: monotonic_now,
                                causal_floor: effective_now,
                            }
                        };
                        (TransmissionStatus::ProvenUnsent, reason)
                    }
                    NativeSubmitDisposition::Ambiguous => {
                        self.seal_failed(reactor, transport, audit, ticket, scratch);
                        return Err(NativeLiveError::EgressInvariant);
                    }
                };
                let feedback = TransmissionInput {
                    command: egress.command,
                    status,
                    monotonic_now: effective_now,
                };
                if let Err(error) =
                    self.record_and_dispatch_feedback(feedback, reactor, audit, ticket, scratch)
                {
                    self.seal_failed(reactor, transport, audit, ticket, scratch);
                    return Err(error);
                }
                for later in (index + 1)..commands {
                    let Some(later_egress) = scratch.pending_egress[later].take() else {
                        self.seal_failed(reactor, transport, audit, ticket, scratch);
                        return Err(NativeLiveError::EgressInvariant);
                    };
                    let feedback = TransmissionInput {
                        command: later_egress.command,
                        status: TransmissionStatus::ProvenUnsent,
                        monotonic_now: effective_now,
                    };
                    if let Err(error) =
                        self.record_and_dispatch_feedback(feedback, reactor, audit, ticket, scratch)
                    {
                        self.seal_failed(reactor, transport, audit, ticket, scratch);
                        return Err(error);
                    }
                }
                let _new_request = reactor.trip_internal_safety();
                scratch.clear();
                self.phase = NativeLivePhase::SafetyPending;
                audit.seal(ticket, self.checkpoint());
                return Ok(NativeLiveStatus::SafetyPending { reason });
            }
            let status = match disposition {
                NativeSubmitDisposition::Sent => TransmissionStatus::Sent,
                NativeSubmitDisposition::ProvenUnsent => TransmissionStatus::ProvenUnsent,
                NativeSubmitDisposition::Ambiguous => {
                    self.seal_failed(reactor, transport, audit, ticket, scratch);
                    return Err(NativeLiveError::EgressInvariant);
                }
            };
            let feedback = TransmissionInput {
                command: egress.command,
                status,
                monotonic_now,
            };
            if let Err(error) =
                self.record_and_dispatch_feedback(feedback, reactor, audit, ticket, scratch)
            {
                self.seal_failed(reactor, transport, audit, ticket, scratch);
                return Err(error);
            }
        }
        if scratch.pending_egress.iter().any(Option::is_some)
            || reactor.outstanding_transmissions() != 0
        {
            self.seal_failed(reactor, transport, audit, ticket, scratch);
            return Err(NativeLiveError::EgressInvariant);
        }
        let engine_killed = reactor.engine().kill_snapshot().is_some();
        if engine_killed {
            if proven_unsent != 0 {
                let _new_request = reactor.trip_internal_safety();
                scratch.clear();
                self.phase = NativeLivePhase::SafetyPending;
                audit.seal(ticket, self.checkpoint());
                return Ok(NativeLiveStatus::SafetyPending {
                    reason: NativeLiveSafetyReason::KillCancelProvenUnsent {
                        commands: proven_unsent,
                    },
                });
            }
            self.phase = NativeLivePhase::KilledRecovery;
        } else if entry_phase != NativeLivePhase::Ready {
            self.seal_failed(reactor, transport, audit, ticket, scratch);
            return Err(NativeLiveError::EngineKillPhaseMismatch {
                phase: entry_phase,
                engine_killed,
            });
        }
        let command_count = u8::try_from(commands).map_err(|_| NativeLiveError::EgressInvariant)?;
        scratch.clear();
        audit.seal(ticket, self.checkpoint());
        Ok(NativeLiveStatus::Completed(NativeLiveSummary {
            source_commit_ordinal,
            commands: command_count,
            sent,
            proven_unsent,
        }))
    }

    /// Apply one pending source-less internal safety kill, submit its bounded cancel
    /// commands, and synchronously drain their priority feedback.
    ///
    /// This is the only continuation accepted from [`NativeLivePhase::SafetyPending`].
    /// It acquires a fresh worst-case audit reservation before the reactor applies the
    /// kill. A pre-submit failure resolves every published cancel as locally proven
    /// unsent and schedules another bounded safety attempt. An ambiguous submission
    /// remains terminal until external transport ownership reconciliation or certified
    /// cancel-on-disconnect handling.
    /// `local_monotonic_now` has the same authenticated local-clock contract as in
    /// [`Self::process_event`].
    ///
    /// # Errors
    ///
    /// Returns a fixed phase, boundary, ordinal, reactor, scheduler, or egress
    /// contract failure. Any error after mutation seals the audit reservation,
    /// quiesces external submission when necessary, and fail-latches the coordinator.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        clippy::result_large_err,
        reason = "the safety hot path uses explicit fixed owners and exact failures"
    )]
    pub fn drive_safety<
        const MAX_BOOK_ORDERS: usize,
        const MAX_BOOK_LEVELS: usize,
        const MAX_ORDERS: usize,
        const MAX_RECENT_TRADES: usize,
        const MAX_FILLS: usize,
        const ENCODED_BYTES: usize,
        A,
        T,
        L,
    >(
        &mut self,
        local_monotonic_now: MonotonicTimestampNs,
        reactor: &mut HotPathReactor<
            MAX_BOOK_ORDERS,
            MAX_BOOK_LEVELS,
            MAX_ORDERS,
            MAX_RECENT_TRADES,
            MAX_FILLS,
        >,
        session: &mut VenueSession,
        adapter: &mut A,
        transport: &mut T,
        audit: &mut L,
        scratch: &mut NativeLiveScratch<ENCODED_BYTES>,
    ) -> Result<NativeLiveStatus<L::Error>, NativeLiveError>
    where
        A: NativeOrderEntryEncoder,
        T: NativeOrderTransport
            + NativeTransmissionProofVerifier<Proof = <T as NativeOrderTransport>::Proof>,
        L: NativeLiveAudit<<T as NativeOrderTransport>::Proof>,
    {
        self.validate_venue_binding(
            session.identity(),
            session.instrument_definition(),
            A::IDENTITY,
            reactor.engine().config().venue,
            reactor.engine().config().instrument_definition,
            reactor.engine().drop_copy_enabled(),
        )?;
        let fault_monotonic_now = local_monotonic_now;
        if self.phase != NativeLivePhase::SafetyPending {
            return Err(NativeLiveError::Phase(self.phase));
        }
        if ENCODED_BYTES == 0 {
            return Err(NativeLiveError::EmptyEncodeBuffer);
        }
        if !scratch.is_clean() {
            return Err(NativeLiveError::DirtyScratch);
        }
        let retained = reactor.has_retained_event();
        let mandatory_kill = reactor.mandatory_kill_pending();
        let outstanding = reactor.outstanding_transmissions();
        if retained || !mandatory_kill || outstanding != 0 {
            return Err(NativeLiveError::DirtyReactorBoundary {
                retained,
                mandatory_kill,
                outstanding,
            });
        }
        if fault_monotonic_now == MonotonicTimestampNs::ZERO {
            return Err(NativeLiveError::InvalidFaultTimestamp(fault_monotonic_now));
        }
        let engine_floor = reactor
            .engine()
            .last_applied_monotonic()
            .unwrap_or(MonotonicTimestampNs::ZERO);
        if fault_monotonic_now < engine_floor {
            return Err(NativeLiveError::LocalMonotonicRegression {
                required_at_least: engine_floor,
                received: fault_monotonic_now,
            });
        }
        if self.next_commit_ordinal.checked_add(3).is_none() {
            return Err(NativeLiveError::CommitOrdinalExhausted);
        }
        let ticket = match audit.reserve(NATIVE_LIVE_AUDIT_CAPACITY) {
            Ok(ticket) => ticket,
            Err(error) => {
                let _new_request = reactor.trip_internal_safety();
                scratch.clear();
                self.phase = NativeLivePhase::SafetyPending;
                audit.seal_emergency(NativeLiveEmergencySealRecord {
                    operation: NativeLiveOperation::DriveSafety,
                    rejected_source: None,
                    local_monotonic_sample: local_monotonic_now,
                    error,
                    checkpoint: self.checkpoint(),
                });
                return Ok(NativeLiveStatus::SafetyPending {
                    reason: NativeLiveSafetyReason::AuditReservation(error),
                });
            }
        };
        let safety_commit_ordinal = self.next_commit_ordinal;
        let outcome = match run_safety(reactor, scratch) {
            Ok(outcome) => outcome,
            Err(NativeLiveError::Reactor(failure)) => {
                if let Err(error) = self.record_reactor_fault(
                    SchedulerRoute::SafetyKill,
                    None,
                    failure,
                    reactor,
                    audit,
                    ticket,
                    scratch,
                ) {
                    self.seal_failed(reactor, transport, audit, ticket, scratch);
                    return Err(error);
                }
                if failure.report.run_ordinal.is_none()
                    || failure.report.events_processed != 0
                    || failure.report.transmissions_processed != 0
                {
                    self.seal_failed(reactor, transport, audit, ticket, scratch);
                    return Err(NativeLiveError::Reactor(failure));
                }
                scratch.pending_egress = scratch.reactor_egress;
                scratch.reactor_egress.fill(None);
                if failure.report.commands_published != 0 {
                    if reactor.mandatory_kill_pending() {
                        self.seal_failed(reactor, transport, audit, ticket, scratch);
                        return Err(NativeLiveError::Reactor(failure));
                    }
                    if let Err(error) = self.resolve_published_unsent(
                        failure.report.commands_published,
                        local_monotonic_now,
                        reactor,
                        audit,
                        ticket,
                        scratch,
                    ) {
                        self.seal_failed(reactor, transport, audit, ticket, scratch);
                        return Err(error);
                    }
                } else if reactor.outstanding_transmissions() != 0 {
                    self.seal_failed(reactor, transport, audit, ticket, scratch);
                    return Err(NativeLiveError::Reactor(failure));
                }
                let _new_request = reactor.trip_internal_safety();
                scratch.clear();
                self.phase = NativeLivePhase::SafetyPending;
                audit.seal(ticket, self.checkpoint());
                return Ok(NativeLiveStatus::SafetyPending {
                    reason: NativeLiveSafetyReason::ReactorFault {
                        route: SchedulerRoute::SafetyKill,
                    },
                });
            }
            Err(error) => {
                audit.abort(ticket);
                return Err(error);
            }
        };
        scratch.pending_egress = scratch.reactor_egress;
        scratch.reactor_egress.fill(None);
        let safety_commit = match SchedulerCommit::from_safety_outcome(
            self.next_commit_ordinal,
            outcome,
            &scratch.pending_egress,
        ) {
            Ok(commit) => commit,
            Err(error) => {
                self.record_application_fault(
                    SchedulerRoute::SafetyKill,
                    None,
                    outcome,
                    scratch.pending_egress,
                    NativeLivePostRunFault::Scheduler(error),
                    reactor,
                    audit,
                    ticket,
                )?;
                if let Err(cleanup_error) = self.resolve_published_unsent(
                    outcome.commands,
                    local_monotonic_now,
                    reactor,
                    audit,
                    ticket,
                    scratch,
                ) {
                    self.seal_failed(reactor, transport, audit, ticket, scratch);
                    return Err(cleanup_error);
                }
                let _new_request = reactor.trip_internal_safety();
                scratch.clear();
                self.phase = NativeLivePhase::SafetyPending;
                audit.seal(ticket, self.checkpoint());
                return Ok(NativeLiveStatus::SafetyPending {
                    reason: NativeLiveSafetyReason::SchedulerFault,
                });
            }
        };
        audit.record_scheduler_commit(ticket, safety_commit);
        self.next_commit_ordinal += 1;

        let commands = outcome.commands;
        let mut sent = 0_u8;
        let mut proven_unsent = 0_u8;
        for index in 0..commands {
            let Some(egress) = scratch.pending_egress[index].take() else {
                self.seal_failed(reactor, transport, audit, ticket, scratch);
                return Err(NativeLiveError::EgressInvariant);
            };
            let session_checkpoint = *session;
            let adapter_checkpoint = adapter.checkpoint();
            let frame = match encode_egress(session, adapter, egress, &mut scratch.encoded) {
                Ok(frame) => frame,
                Err(fault) => {
                    *session = session_checkpoint;
                    adapter.restore(adapter_checkpoint);
                    scratch.encoded.fill(0);
                    let effective_now = causal_timestamp(reactor, local_monotonic_now);
                    audit.record_encode_fault(
                        ticket,
                        NativeLiveEncodeFaultRecord {
                            egress,
                            fault,
                            local_monotonic_sample: local_monotonic_now,
                            monotonic_now: effective_now,
                        },
                    );
                    if let Err(error) = self.resolve_local_unsent_from(
                        index,
                        commands,
                        egress,
                        effective_now,
                        reactor,
                        audit,
                        ticket,
                        scratch,
                    ) {
                        self.seal_failed(reactor, transport, audit, ticket, scratch);
                        return Err(error);
                    }
                    let _new_request = reactor.trip_internal_safety();
                    scratch.clear();
                    self.phase = NativeLivePhase::SafetyPending;
                    audit.seal(ticket, self.checkpoint());
                    return Ok(NativeLiveStatus::SafetyPending {
                        reason: NativeLiveSafetyReason::Encode(fault),
                    });
                }
            };
            let intent = NativeLiveIntent {
                adapter_identity: session.identity(),
                venue_sequence: frame.sequence,
                scheduler_commit_ordinal: safety_commit.commit_ordinal,
                scheduler_capture_ordinal: safety_commit.capture_ordinal,
                scheduler_source_event_crc32c: safety_commit.source_event_crc32c,
                egress,
                encoded_bytes: &scratch.encoded[..frame.bytes],
            };
            let frame_ordinal = audit.append_native_intent(ticket, intent);
            if frame_ordinal == 0
                || frame_ordinal == u64::MAX
                || self
                    .last_outbound_frame
                    .is_some_and(|previous| frame_ordinal <= previous)
            {
                *session = session_checkpoint;
                adapter.restore(adapter_checkpoint);
                let _new_request = reactor.trip_internal_safety();
                scratch.clear();
                transport.quiesce();
                self.phase = NativeLivePhase::Ambiguous;
                audit.seal(ticket, self.checkpoint());
                return Err(NativeLiveError::InvalidNativeFrameOrdinal {
                    previous_outbound: self.last_outbound_frame,
                    actual: frame_ordinal,
                });
            }
            self.last_outbound_frame = Some(frame_ordinal);
            let context = intent.with_frame_ordinal(frame_ordinal);
            let submit = transport.submit(context);
            let claim = submit_parts(submit);
            let verified = match verify_live_submit(transport, context, claim) {
                Ok(verified) => verified,
                Err(fault) => {
                    let ambiguous_frame_ordinal = context.frame_ordinal;
                    transport.quiesce();
                    audit.record_proof_fault(
                        ticket,
                        NativeLiveProofFaultRecord {
                            context,
                            proof: claim.proof,
                            claimed_disposition: claim.disposition,
                            claimed_monotonic_now: claim.monotonic_now,
                            fault,
                        },
                    );
                    adapter.commit(adapter_checkpoint);
                    let _new_request = reactor.trip_internal_safety();
                    scratch.clear();
                    self.phase = NativeLivePhase::Ambiguous;
                    audit.seal(ticket, self.checkpoint());
                    return Ok(NativeLiveStatus::Ambiguous {
                        frame_ordinal: ambiguous_frame_ordinal,
                        egress,
                    });
                }
            };
            let NativeSubmitClaim {
                proof,
                disposition,
                monotonic_now,
            } = verified;
            audit.record_native_egress(
                ticket,
                NativeLiveEgressRecord {
                    context,
                    proof,
                    disposition,
                    monotonic_now,
                },
            );
            match disposition {
                NativeSubmitDisposition::Sent => {
                    adapter.commit(adapter_checkpoint);
                    sent += 1;
                }
                NativeSubmitDisposition::ProvenUnsent => {
                    *session = session_checkpoint;
                    adapter.restore(adapter_checkpoint);
                    proven_unsent += 1;
                }
                NativeSubmitDisposition::Ambiguous => {
                    let frame_ordinal = context.frame_ordinal;
                    adapter.commit(adapter_checkpoint);
                    let _new_request = reactor.trip_internal_safety();
                    scratch.clear();
                    self.phase = NativeLivePhase::Ambiguous;
                    audit.seal(ticket, self.checkpoint());
                    return Ok(NativeLiveStatus::Ambiguous {
                        frame_ordinal,
                        egress,
                    });
                }
            }
            scratch.encoded.fill(0);
            let timestamp_anomaly = monotonic_now < causal_timestamp(reactor, local_monotonic_now);
            let effective_now = causal_timestamp(reactor, local_monotonic_now);
            if timestamp_anomaly {
                audit.record_clock_fallback(
                    ticket,
                    NativeLiveClockFallbackRecord {
                        egress,
                        disposition,
                        transport_monotonic_now: monotonic_now,
                        local_monotonic_now,
                        effective_monotonic_now: effective_now,
                    },
                );
            }
            let feedback_now = if timestamp_anomaly {
                effective_now
            } else {
                monotonic_now
            };
            if feedback_now == MonotonicTimestampNs::ZERO {
                self.seal_failed(reactor, transport, audit, ticket, scratch);
                return Err(NativeLiveError::InvalidTransmissionTimestamp(monotonic_now));
            }
            let status = match disposition {
                NativeSubmitDisposition::Sent => TransmissionStatus::Sent,
                NativeSubmitDisposition::ProvenUnsent => TransmissionStatus::ProvenUnsent,
                NativeSubmitDisposition::Ambiguous => {
                    self.seal_failed(reactor, transport, audit, ticket, scratch);
                    return Err(NativeLiveError::EgressInvariant);
                }
            };
            let feedback = TransmissionInput {
                command: egress.command,
                status,
                monotonic_now: feedback_now,
            };
            if let Err(error) =
                self.record_and_dispatch_feedback(feedback, reactor, audit, ticket, scratch)
            {
                self.seal_failed(reactor, transport, audit, ticket, scratch);
                return Err(error);
            }
            if timestamp_anomaly {
                for later in (index + 1)..commands {
                    let Some(later_egress) = scratch.pending_egress[later].take() else {
                        self.seal_failed(reactor, transport, audit, ticket, scratch);
                        return Err(NativeLiveError::EgressInvariant);
                    };
                    let feedback = TransmissionInput {
                        command: later_egress.command,
                        status: TransmissionStatus::ProvenUnsent,
                        monotonic_now: effective_now,
                    };
                    if let Err(error) =
                        self.record_and_dispatch_feedback(feedback, reactor, audit, ticket, scratch)
                    {
                        self.seal_failed(reactor, transport, audit, ticket, scratch);
                        return Err(error);
                    }
                }
                let _new_request = reactor.trip_internal_safety();
                scratch.clear();
                self.phase = NativeLivePhase::SafetyPending;
                audit.seal(ticket, self.checkpoint());
                let reason = match disposition {
                    NativeSubmitDisposition::Sent => {
                        if monotonic_now == MonotonicTimestampNs::ZERO {
                            NativeLiveSafetyReason::InvalidSentTimestamp(monotonic_now)
                        } else {
                            NativeLiveSafetyReason::TransmissionTimestampRegression {
                                received: monotonic_now,
                                causal_floor: effective_now,
                            }
                        }
                    }
                    NativeSubmitDisposition::ProvenUnsent => {
                        if monotonic_now == MonotonicTimestampNs::ZERO {
                            NativeLiveSafetyReason::InvalidProvenUnsentTimestamp(monotonic_now)
                        } else {
                            NativeLiveSafetyReason::TransmissionTimestampRegression {
                                received: monotonic_now,
                                causal_floor: effective_now,
                            }
                        }
                    }
                    NativeSubmitDisposition::Ambiguous => {
                        return Err(NativeLiveError::EgressInvariant);
                    }
                };
                return Ok(NativeLiveStatus::SafetyPending { reason });
            }
        }
        if scratch.pending_egress.iter().any(Option::is_some)
            || reactor.outstanding_transmissions() != 0
        {
            self.seal_failed(reactor, transport, audit, ticket, scratch);
            return Err(NativeLiveError::EgressInvariant);
        }
        if proven_unsent != 0 {
            let _new_request = reactor.trip_internal_safety();
            scratch.clear();
            self.phase = NativeLivePhase::SafetyPending;
            audit.seal(ticket, self.checkpoint());
            return Ok(NativeLiveStatus::SafetyPending {
                reason: NativeLiveSafetyReason::KillCancelProvenUnsent {
                    commands: proven_unsent,
                },
            });
        }
        let command_count = u8::try_from(commands).map_err(|_| NativeLiveError::EgressInvariant)?;
        scratch.clear();
        self.phase = NativeLivePhase::KilledRecovery;
        audit.seal(ticket, self.checkpoint());
        Ok(NativeLiveStatus::KilledRecoveryEntered(NativeLiveSummary {
            source_commit_ordinal: safety_commit_ordinal,
            commands: command_count,
            sent,
            proven_unsent,
        }))
    }

    #[allow(clippy::result_large_err)]
    fn validate_venue_binding(
        &self,
        session: VenueIdentity,
        session_definition: InstrumentDefinition,
        adapter: VenueIdentity,
        engine_venue: VenueId,
        engine_definition: InstrumentDefinition,
        engine_drop_copy_enabled: bool,
    ) -> Result<(), NativeLiveError> {
        if self.expected_identity != session
            || self.expected_identity != adapter
            || self.expected_identity.venue != engine_venue
        {
            return Err(NativeLiveError::VenueIdentityMismatch {
                expected: self.expected_identity,
                session,
                adapter,
                engine_venue,
            });
        }
        let session_binding = session_definition.binding();
        let engine_binding = engine_definition.binding();
        let session_engine_rules_equal = session_definition == engine_definition;
        if self.expected_instrument_binding != session_binding
            || self.expected_instrument_binding != engine_binding
            || !session_engine_rules_equal
        {
            return Err(NativeLiveError::InstrumentDefinitionMismatch {
                expected: self.expected_instrument_binding,
                session: session_binding,
                engine: engine_binding,
                session_engine_rules_equal,
            });
        }
        let coordinator_enabled = self.expected_drop_copy_source.is_some();
        if coordinator_enabled != engine_drop_copy_enabled {
            return Err(NativeLiveError::DropCopyConfigurationMismatch {
                coordinator_enabled,
                engine_enabled: engine_drop_copy_enabled,
            });
        }
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn validate_source_route(&self, source_event: NormalizedEvent) -> Result<(), NativeLiveError> {
        let (expected_source, expected_venue) = match source_event.source.sequence_domain {
            SequenceDomain::Local => (EventSource::LOCAL, VenueId(0)),
            SequenceDomain::MarketData => (
                self.expected_market_data_source,
                self.expected_identity.venue,
            ),
            SequenceDomain::OrderEntry => (
                self.expected_order_entry_source,
                self.expected_identity.venue,
            ),
            SequenceDomain::DropCopy => (
                self.expected_drop_copy_source
                    .ok_or(NativeLiveError::DropCopyNotConfigured)?,
                self.expected_identity.venue,
            ),
        };
        if source_event.source != expected_source || source_event.header.venue != expected_venue {
            return Err(NativeLiveError::SourceRouteMismatch {
                expected_source,
                actual_source: source_event.source,
                expected_venue,
                actual_venue: source_event.header.venue,
            });
        }
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn preflight<
        const MAX_BOOK_ORDERS: usize,
        const MAX_BOOK_LEVELS: usize,
        const MAX_ORDERS: usize,
        const MAX_RECENT_TRADES: usize,
        const MAX_FILLS: usize,
        const ENCODED_BYTES: usize,
    >(
        &self,
        source_event: NormalizedEvent,
        fault_monotonic_now: MonotonicTimestampNs,
        reactor: &HotPathReactor<
            MAX_BOOK_ORDERS,
            MAX_BOOK_LEVELS,
            MAX_ORDERS,
            MAX_RECENT_TRADES,
            MAX_FILLS,
        >,
        scratch: &NativeLiveScratch<ENCODED_BYTES>,
    ) -> Result<ReactorInput, NativeLiveError> {
        if !matches!(
            self.phase,
            NativeLivePhase::Ready | NativeLivePhase::KilledRecovery
        ) {
            return Err(NativeLiveError::Phase(self.phase));
        }
        let engine_killed = reactor.engine().kill_snapshot().is_some();
        if (self.phase == NativeLivePhase::Ready && engine_killed)
            || (self.phase == NativeLivePhase::KilledRecovery && !engine_killed)
        {
            return Err(NativeLiveError::EngineKillPhaseMismatch {
                phase: self.phase,
                engine_killed,
            });
        }
        if ENCODED_BYTES == 0 {
            return Err(NativeLiveError::EmptyEncodeBuffer);
        }
        if !scratch.is_clean() {
            return Err(NativeLiveError::DirtyScratch);
        }
        let retained = reactor.has_retained_event();
        let mandatory_kill = reactor.mandatory_kill_pending();
        let outstanding = reactor.outstanding_transmissions();
        if retained || mandatory_kill || outstanding != 0 {
            return Err(NativeLiveError::DirtyReactorBoundary {
                retained,
                mandatory_kill,
                outstanding,
            });
        }
        match self.last_source_capture {
            None if source_event.capture_ordinal != self.expected_first_source_capture => {
                return Err(NativeLiveError::SourceCaptureOrdinalMismatch {
                    expected: self.expected_first_source_capture,
                    actual: source_event.capture_ordinal,
                });
            }
            Some(previous) if source_event.capture_ordinal <= previous => {
                return Err(NativeLiveError::SourceCaptureOrdinalRegression {
                    previous,
                    actual: source_event.capture_ordinal,
                });
            }
            None | Some(_) => {}
        }
        if fault_monotonic_now == MonotonicTimestampNs::ZERO {
            return Err(NativeLiveError::InvalidFaultTimestamp(fault_monotonic_now));
        }
        let required_at_least = reactor
            .engine()
            .last_applied_monotonic()
            .unwrap_or(MonotonicTimestampNs::ZERO)
            .max(source_event.monotonic_timestamp);
        if fault_monotonic_now < required_at_least {
            return Err(NativeLiveError::LocalMonotonicRegression {
                required_at_least,
                received: fault_monotonic_now,
            });
        }
        if self.next_commit_ordinal.checked_add(3).is_none() {
            return Err(NativeLiveError::CommitOrdinalExhausted);
        }
        self.validate_source_route(source_event)?;
        match decode_replay_input(source_event).map_err(NativeLiveError::Codec)? {
            ReplayInput::Reactor(ReactorInput::Control(control))
                if control.decision().origin() != ControlDecisionOrigin::AuthenticatedGate =>
            {
                Err(NativeLiveError::ControlProvenance)
            }
            ReplayInput::Reactor(input) => Ok(input),
            ReplayInput::Transmission(_) | ReplayInput::NoEngineInput => {
                Err(NativeLiveError::SourceMustBeNormal)
            }
        }
    }

    #[allow(clippy::too_many_arguments, clippy::result_large_err)]
    fn resolve_local_unsent_from<
        const MAX_BOOK_ORDERS: usize,
        const MAX_BOOK_LEVELS: usize,
        const MAX_ORDERS: usize,
        const MAX_RECENT_TRADES: usize,
        const MAX_FILLS: usize,
        const ENCODED_BYTES: usize,
        Proof: Copy,
        L: NativeLiveAudit<Proof>,
    >(
        &mut self,
        failed_index: usize,
        commands: usize,
        failed_egress: ReactorEgress,
        fault_monotonic_now: MonotonicTimestampNs,
        reactor: &mut HotPathReactor<
            MAX_BOOK_ORDERS,
            MAX_BOOK_LEVELS,
            MAX_ORDERS,
            MAX_RECENT_TRADES,
            MAX_FILLS,
        >,
        audit: &mut L,
        ticket: L::Ticket,
        scratch: &mut NativeLiveScratch<ENCODED_BYTES>,
    ) -> Result<(), NativeLiveError> {
        for index in failed_index..commands {
            let egress = if index == failed_index {
                failed_egress
            } else {
                scratch.pending_egress[index]
                    .take()
                    .ok_or(NativeLiveError::EgressInvariant)?
            };
            let feedback = TransmissionInput {
                command: egress.command,
                status: TransmissionStatus::ProvenUnsent,
                monotonic_now: fault_monotonic_now,
            };
            self.record_and_dispatch_feedback(feedback, reactor, audit, ticket, scratch)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments, clippy::result_large_err)]
    fn record_and_dispatch_feedback<
        const MAX_BOOK_ORDERS: usize,
        const MAX_BOOK_LEVELS: usize,
        const MAX_ORDERS: usize,
        const MAX_RECENT_TRADES: usize,
        const MAX_FILLS: usize,
        const ENCODED_BYTES: usize,
        Proof: Copy,
        L: NativeLiveAudit<Proof>,
    >(
        &mut self,
        feedback: TransmissionInput,
        reactor: &mut HotPathReactor<
            MAX_BOOK_ORDERS,
            MAX_BOOK_LEVELS,
            MAX_ORDERS,
            MAX_RECENT_TRADES,
            MAX_FILLS,
        >,
        audit: &mut L,
        ticket: L::Ticket,
        scratch: &mut NativeLiveScratch<ENCODED_BYTES>,
    ) -> Result<(), NativeLiveError> {
        // Validate caller-owned content before the infallible durable append mutates
        // the journal. The authoritative appender may then raise only the timestamp.
        normalize_transmission(CaptureOrdinal(1), feedback).map_err(NativeLiveError::Codec)?;
        let event = audit.append_transmission_event(ticket, feedback);
        if event.capture_ordinal.0 == 0
            || self
                .last_feedback_capture
                .is_some_and(|previous| event.capture_ordinal <= previous)
            || self
                .last_source_capture
                .is_some_and(|source| event.capture_ordinal <= source)
        {
            return Err(NativeLiveError::InvalidFeedbackCaptureOrdinal {
                previous_feedback: self.last_feedback_capture,
                last_source: self.last_source_capture,
                actual: event.capture_ordinal,
            });
        }
        let appended = decode_transmission(event)
            .map_err(|_| NativeLiveError::InvalidAppendedTransmissionEvent)?;
        let reconstructed = normalize_transmission(event.capture_ordinal, appended)
            .map_err(|_| NativeLiveError::InvalidAppendedTransmissionEvent)?;
        if reconstructed != event
            || appended.command != feedback.command
            || appended.status != feedback.status
            || appended.monotonic_now < feedback.monotonic_now
        {
            return Err(NativeLiveError::InvalidAppendedTransmissionEvent);
        }
        self.last_feedback_capture = Some(event.capture_ordinal);
        let outcome = match run_feedback(reactor, appended, scratch) {
            Ok(outcome) => outcome,
            Err(NativeLiveError::Reactor(failure)) => {
                self.record_reactor_fault(
                    SchedulerRoute::PriorityTransmission,
                    Some(event),
                    failure,
                    reactor,
                    audit,
                    ticket,
                    scratch,
                )?;
                return Err(NativeLiveError::Reactor(failure));
            }
            Err(error) => return Err(error),
        };
        if outcome.commands != 0 || scratch.reactor_egress.iter().any(Option::is_some) {
            self.record_application_fault(
                SchedulerRoute::PriorityTransmission,
                Some(event),
                outcome,
                scratch.reactor_egress,
                NativeLivePostRunFault::UnexpectedEgress,
                reactor,
                audit,
                ticket,
            )?;
            return Err(NativeLiveError::FeedbackProducedCommands);
        }
        let commit = match SchedulerCommit::from_replay_outcome(
            self.next_commit_ordinal,
            event,
            outcome,
            &scratch.reactor_egress,
        ) {
            Ok(commit) => commit,
            Err(error) => {
                self.record_application_fault(
                    SchedulerRoute::PriorityTransmission,
                    Some(event),
                    outcome,
                    scratch.reactor_egress,
                    NativeLivePostRunFault::Scheduler(error),
                    reactor,
                    audit,
                    ticket,
                )?;
                return Err(NativeLiveError::Scheduler(error));
            }
        };
        audit.record_scheduler_commit(ticket, commit);
        self.next_commit_ordinal += 1;
        Ok(())
    }

    #[allow(clippy::too_many_arguments, clippy::result_large_err)]
    fn record_reactor_fault<
        const MAX_BOOK_ORDERS: usize,
        const MAX_BOOK_LEVELS: usize,
        const MAX_ORDERS: usize,
        const MAX_RECENT_TRADES: usize,
        const MAX_FILLS: usize,
        const ENCODED_BYTES: usize,
        Proof: Copy,
        L: NativeLiveAudit<Proof>,
    >(
        &mut self,
        route: SchedulerRoute,
        source_event: Option<NormalizedEvent>,
        failure: ReactorFailure,
        reactor: &HotPathReactor<
            MAX_BOOK_ORDERS,
            MAX_BOOK_LEVELS,
            MAX_ORDERS,
            MAX_RECENT_TRADES,
            MAX_FILLS,
        >,
        audit: &mut L,
        ticket: L::Ticket,
        scratch: &NativeLiveScratch<ENCODED_BYTES>,
    ) -> Result<(), NativeLiveError> {
        let next = self
            .next_commit_ordinal
            .checked_add(1)
            .ok_or(NativeLiveError::CommitOrdinalExhausted)?;
        audit.record_reactor_fault(
            ticket,
            NativeLiveReactorFaultRecord {
                application_ordinal: self.next_commit_ordinal,
                route,
                source_event,
                failure,
                egress: scratch.reactor_egress,
                outstanding_transmissions: reactor.outstanding_transmissions(),
                retained_event: reactor.has_retained_event(),
                mandatory_kill_pending: reactor.mandatory_kill_pending(),
            },
        );
        self.next_commit_ordinal = next;
        Ok(())
    }

    #[allow(clippy::too_many_arguments, clippy::result_large_err)]
    fn record_application_fault<
        const MAX_BOOK_ORDERS: usize,
        const MAX_BOOK_LEVELS: usize,
        const MAX_ORDERS: usize,
        const MAX_RECENT_TRADES: usize,
        const MAX_FILLS: usize,
        Proof: Copy,
        L: NativeLiveAudit<Proof>,
    >(
        &mut self,
        route: SchedulerRoute,
        source_event: Option<NormalizedEvent>,
        outcome: ReactorReplayOutcome,
        egress: [Option<ReactorEgress>; MAX_REACTOR_COMMANDS_PER_INPUT],
        fault: NativeLivePostRunFault,
        reactor: &HotPathReactor<
            MAX_BOOK_ORDERS,
            MAX_BOOK_LEVELS,
            MAX_ORDERS,
            MAX_RECENT_TRADES,
            MAX_FILLS,
        >,
        audit: &mut L,
        ticket: L::Ticket,
    ) -> Result<(), NativeLiveError> {
        let next = self
            .next_commit_ordinal
            .checked_add(1)
            .ok_or(NativeLiveError::CommitOrdinalExhausted)?;
        audit.record_application_fault(
            ticket,
            NativeLiveApplicationFaultRecord {
                application_ordinal: self.next_commit_ordinal,
                route,
                source_event,
                outcome,
                egress,
                outstanding_transmissions: reactor.outstanding_transmissions(),
                retained_event: reactor.has_retained_event(),
                mandatory_kill_pending: reactor.mandatory_kill_pending(),
                fault,
            },
        );
        self.next_commit_ordinal = next;
        Ok(())
    }

    #[allow(clippy::too_many_arguments, clippy::result_large_err)]
    fn resolve_published_unsent<
        const MAX_BOOK_ORDERS: usize,
        const MAX_BOOK_LEVELS: usize,
        const MAX_ORDERS: usize,
        const MAX_RECENT_TRADES: usize,
        const MAX_FILLS: usize,
        const ENCODED_BYTES: usize,
        Proof: Copy,
        L: NativeLiveAudit<Proof>,
    >(
        &mut self,
        expected_commands: usize,
        local_monotonic_now: MonotonicTimestampNs,
        reactor: &mut HotPathReactor<
            MAX_BOOK_ORDERS,
            MAX_BOOK_LEVELS,
            MAX_ORDERS,
            MAX_RECENT_TRADES,
            MAX_FILLS,
        >,
        audit: &mut L,
        ticket: L::Ticket,
        scratch: &mut NativeLiveScratch<ENCODED_BYTES>,
    ) -> Result<(), NativeLiveError> {
        if expected_commands > MAX_REACTOR_COMMANDS_PER_INPUT
            || reactor.outstanding_transmissions() != expected_commands
            || scratch
                .pending_egress
                .iter()
                .take(expected_commands)
                .any(Option::is_none)
            || scratch
                .pending_egress
                .iter()
                .skip(expected_commands)
                .any(Option::is_some)
        {
            return Err(NativeLiveError::EgressInvariant);
        }
        for index in 0..expected_commands {
            let egress = scratch.pending_egress[index]
                .take()
                .ok_or(NativeLiveError::EgressInvariant)?;
            if usize::from(egress.command_index) != index {
                return Err(NativeLiveError::EgressInvariant);
            }
            let feedback = TransmissionInput {
                command: egress.command,
                status: TransmissionStatus::ProvenUnsent,
                monotonic_now: local_monotonic_now,
            };
            self.record_and_dispatch_feedback(feedback, reactor, audit, ticket, scratch)?;
        }
        if reactor.outstanding_transmissions() != 0 {
            return Err(NativeLiveError::EgressInvariant);
        }
        Ok(())
    }

    fn fail_after_mutation<
        const MAX_BOOK_ORDERS: usize,
        const MAX_BOOK_LEVELS: usize,
        const MAX_ORDERS: usize,
        const MAX_RECENT_TRADES: usize,
        const MAX_FILLS: usize,
        const ENCODED_BYTES: usize,
    >(
        &mut self,
        reactor: &mut HotPathReactor<
            MAX_BOOK_ORDERS,
            MAX_BOOK_LEVELS,
            MAX_ORDERS,
            MAX_RECENT_TRADES,
            MAX_FILLS,
        >,
        scratch: &mut NativeLiveScratch<ENCODED_BYTES>,
    ) {
        let _new_request = reactor.trip_internal_safety();
        scratch.clear();
        self.phase = NativeLivePhase::Failed;
    }

    /// Seal a post-mutation fatal path in crash-safe order. All exact evidence must
    /// already have been appended before this call; submission is quiesced before
    /// the reservation is marked complete.
    fn seal_failed<
        const MAX_BOOK_ORDERS: usize,
        const MAX_BOOK_LEVELS: usize,
        const MAX_ORDERS: usize,
        const MAX_RECENT_TRADES: usize,
        const MAX_FILLS: usize,
        const ENCODED_BYTES: usize,
        T,
        L,
    >(
        &mut self,
        reactor: &mut HotPathReactor<
            MAX_BOOK_ORDERS,
            MAX_BOOK_LEVELS,
            MAX_ORDERS,
            MAX_RECENT_TRADES,
            MAX_FILLS,
        >,
        transport: &mut T,
        audit: &mut L,
        ticket: L::Ticket,
        scratch: &mut NativeLiveScratch<ENCODED_BYTES>,
    ) where
        T: NativeOrderTransport,
        L: NativeLiveAudit<T::Proof>,
    {
        self.fail_after_mutation(reactor, scratch);
        transport.quiesce();
        audit.seal(ticket, self.checkpoint());
    }
}

fn causal_timestamp<
    const MAX_BOOK_ORDERS: usize,
    const MAX_BOOK_LEVELS: usize,
    const MAX_ORDERS: usize,
    const MAX_RECENT_TRADES: usize,
    const MAX_FILLS: usize,
>(
    reactor: &HotPathReactor<
        MAX_BOOK_ORDERS,
        MAX_BOOK_LEVELS,
        MAX_ORDERS,
        MAX_RECENT_TRADES,
        MAX_FILLS,
    >,
    local_sample: MonotonicTimestampNs,
) -> MonotonicTimestampNs {
    reactor
        .engine()
        .last_applied_monotonic()
        .unwrap_or(MonotonicTimestampNs::ZERO)
        .max(local_sample)
}

#[allow(clippy::result_large_err)]
fn run_source<
    const MAX_BOOK_ORDERS: usize,
    const MAX_BOOK_LEVELS: usize,
    const MAX_ORDERS: usize,
    const MAX_RECENT_TRADES: usize,
    const MAX_FILLS: usize,
    const ENCODED_BYTES: usize,
>(
    reactor: &mut HotPathReactor<
        MAX_BOOK_ORDERS,
        MAX_BOOK_LEVELS,
        MAX_ORDERS,
        MAX_RECENT_TRADES,
        MAX_FILLS,
    >,
    input: ReactorInput,
    scratch: &mut NativeLiveScratch<ENCODED_BYTES>,
) -> Result<ReactorReplayOutcome, NativeLiveError> {
    let (mut normal_producer, mut normal_consumer) = scratch.normal.split();
    let (_feedback_producer, mut feedback_consumer) = scratch.feedback.split();
    normal_producer
        .try_push(input)
        .map_err(|_| NativeLiveError::RingInvariant)?;
    let report = reactor
        .run(
            &mut normal_consumer,
            &mut feedback_consumer,
            ReactorBudget {
                max_events: 1,
                max_transmissions: 1,
            },
            &mut scratch.reactor_egress,
        )
        .map_err(NativeLiveError::Reactor)?;
    Ok(ReactorReplayOutcome {
        route: EngineReplayRoute::Normal,
        commands: report.commands_published,
        report: Some(report),
    })
}

#[allow(clippy::result_large_err)]
fn run_feedback<
    const MAX_BOOK_ORDERS: usize,
    const MAX_BOOK_LEVELS: usize,
    const MAX_ORDERS: usize,
    const MAX_RECENT_TRADES: usize,
    const MAX_FILLS: usize,
    const ENCODED_BYTES: usize,
>(
    reactor: &mut HotPathReactor<
        MAX_BOOK_ORDERS,
        MAX_BOOK_LEVELS,
        MAX_ORDERS,
        MAX_RECENT_TRADES,
        MAX_FILLS,
    >,
    feedback: TransmissionInput,
    scratch: &mut NativeLiveScratch<ENCODED_BYTES>,
) -> Result<ReactorReplayOutcome, NativeLiveError> {
    let (_normal_producer, mut normal_consumer) = scratch.normal.split();
    let (mut feedback_producer, mut feedback_consumer) = scratch.feedback.split();
    feedback_producer
        .try_push(feedback)
        .map_err(|_| NativeLiveError::RingInvariant)?;
    let report = reactor
        .run(
            &mut normal_consumer,
            &mut feedback_consumer,
            ReactorBudget {
                max_events: 0,
                max_transmissions: 1,
            },
            &mut scratch.reactor_egress,
        )
        .map_err(NativeLiveError::Reactor)?;
    Ok(ReactorReplayOutcome {
        route: EngineReplayRoute::PriorityTransmission,
        commands: report.commands_published,
        report: Some(report),
    })
}

#[allow(clippy::result_large_err)]
fn run_safety<
    const MAX_BOOK_ORDERS: usize,
    const MAX_BOOK_LEVELS: usize,
    const MAX_ORDERS: usize,
    const MAX_RECENT_TRADES: usize,
    const MAX_FILLS: usize,
    const ENCODED_BYTES: usize,
>(
    reactor: &mut HotPathReactor<
        MAX_BOOK_ORDERS,
        MAX_BOOK_LEVELS,
        MAX_ORDERS,
        MAX_RECENT_TRADES,
        MAX_FILLS,
    >,
    scratch: &mut NativeLiveScratch<ENCODED_BYTES>,
) -> Result<ReactorReplayOutcome, NativeLiveError> {
    let (_normal_producer, mut normal_consumer) = scratch.normal.split();
    let (_feedback_producer, mut feedback_consumer) = scratch.feedback.split();
    let report = reactor
        .run(
            &mut normal_consumer,
            &mut feedback_consumer,
            ReactorBudget {
                max_events: 1,
                max_transmissions: 1,
            },
            &mut scratch.reactor_egress,
        )
        .map_err(NativeLiveError::Reactor)?;
    Ok(ReactorReplayOutcome {
        route: EngineReplayRoute::SafetyKill,
        commands: report.commands_published,
        report: Some(report),
    })
}

fn encode_egress<A: NativeOrderEntryEncoder>(
    session: &mut VenueSession,
    adapter: &mut A,
    egress: ReactorEgress,
    output: &mut [u8],
) -> Result<crate::venue::EncodedFrame, NativeLiveEncodeFault> {
    let frame = match egress.command {
        OrderCommand::CancelAll(command) => session.encode_cancel_all(adapter, command, output),
        OrderCommand::New(_) | OrderCommand::Cancel(_) | OrderCommand::Replace(_) => {
            session.encode_order(adapter, egress.command, output)
        }
    }
    .map_err(NativeLiveEncodeFault::Venue)?;
    if let Some(relative) = output[frame.bytes..].iter().position(|byte| *byte != 0) {
        return Err(NativeLiveEncodeFault::DirtyEncodedTail {
            index: frame.bytes + relative,
        });
    }
    Ok(frame)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativeSubmitClaim<Proof: Copy> {
    proof: Proof,
    disposition: NativeSubmitDisposition,
    monotonic_now: MonotonicTimestampNs,
}

fn submit_parts<Proof: Copy>(submit: NativeSubmit<Proof>) -> NativeSubmitClaim<Proof> {
    match submit {
        NativeSubmit::Sent {
            proof,
            monotonic_now,
        } => NativeSubmitClaim {
            proof,
            disposition: NativeSubmitDisposition::Sent,
            monotonic_now,
        },
        NativeSubmit::ProvenUnsent {
            proof,
            monotonic_now,
        } => NativeSubmitClaim {
            proof,
            disposition: NativeSubmitDisposition::ProvenUnsent,
            monotonic_now,
        },
        NativeSubmit::Ambiguous {
            proof,
            monotonic_now,
        } => NativeSubmitClaim {
            proof,
            disposition: NativeSubmitDisposition::Ambiguous,
            monotonic_now,
        },
    }
}

fn verify_live_submit<T>(
    transport: &mut T,
    context: NativeTransmissionContext<'_>,
    claim: NativeSubmitClaim<<T as NativeOrderTransport>::Proof>,
) -> Result<NativeSubmitClaim<<T as NativeOrderTransport>::Proof>, NativeLiveProofFault>
where
    T: NativeOrderTransport
        + NativeTransmissionProofVerifier<Proof = <T as NativeOrderTransport>::Proof>,
{
    let checkpoint = <T as NativeTransmissionProofVerifier>::checkpoint(transport);
    let verified = <T as NativeTransmissionProofVerifier>::verify(transport, context, &claim.proof);
    let verified = match verified {
        Ok(verified) => verified,
        Err(error) => {
            <T as NativeTransmissionProofVerifier>::restore(transport, checkpoint);
            return Err(match error {
                NativeTransmissionProofError::Rejected => NativeLiveProofFault::Rejected,
                NativeTransmissionProofError::Ambiguous => NativeLiveProofFault::Ambiguous,
            });
        }
    };
    let verified_disposition = NativeSubmitDisposition::from(verified);
    if verified_disposition != claim.disposition {
        <T as NativeTransmissionProofVerifier>::restore(transport, checkpoint);
        return Err(NativeLiveProofFault::DispositionMismatch {
            claimed: claim.disposition,
            verified: verified_disposition,
        });
    }
    if verified.monotonic_now != claim.monotonic_now {
        <T as NativeTransmissionProofVerifier>::restore(transport, checkpoint);
        return Err(NativeLiveProofFault::TimestampMismatch {
            claimed: claim.monotonic_now,
            verified: verified.monotonic_now,
        });
    }
    <T as NativeTransmissionProofVerifier>::commit(transport, checkpoint);
    Ok(claim)
}

impl From<NativeTransmissionDisposition> for NativeSubmitDisposition {
    fn from(value: NativeTransmissionDisposition) -> Self {
        match value.status {
            TransmissionStatus::Sent => Self::Sent,
            TransmissionStatus::ProvenUnsent => Self::ProvenUnsent,
        }
    }
}
