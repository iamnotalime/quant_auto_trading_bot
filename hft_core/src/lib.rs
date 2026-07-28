//! Fixed-capacity, deterministic execution primitives for a true low-latency hot path.
//!
//! This crate deliberately contains no Python runtime, REST client, dynamic strategy
//! loading, or venue-specific guesswork. Venue wire adapters translate authenticated
//! native packets into these normalized events. Research and orchestration remain
//! outside the process boundary.

#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(
    clippy::all,
    clippy::pedantic,
    missing_debug_implementations,
    unreachable_pub
)]

#[cfg(not(target_pointer_width = "64"))]
compile_error!("quant-hft-core requires a 64-bit target");
#[cfg(not(target_has_atomic = "64"))]
compile_error!("quant-hft-core requires lock-free 64-bit atomics");

pub mod adverse;
pub mod audit_container;
pub mod audit_prefix;
pub mod book;
pub mod clock;
pub mod control;
pub mod drop_copy;
pub mod engine;
pub mod engine_replay;
pub mod event_codec;
pub mod events;
pub mod fixed;
pub mod journal;
pub mod kill;
pub mod native_audit_codec;
pub mod native_live;
pub mod native_recovery;
pub mod native_replay;
mod order_command_codec;
pub mod orders;
pub mod ownership;
pub mod queue;
pub mod reactor;
pub mod reactor_audit;
pub mod reactor_replay;
pub mod reference_data;
pub mod risk;
pub mod spsc;
pub mod strategy;
pub mod telemetry;
pub mod types;
pub mod venue;

pub use audit_container::{
    AUDIT_CONTAINER_HEADER_LEN, AUDIT_CONTAINER_MAGIC, AUDIT_CONTAINER_SEAL_LEN,
    AUDIT_CONTAINER_VERSION, AUDIT_RECORD_MAGIC, AUDIT_RECORD_PREFIX_LEN, AUDIT_SEAL_MAGIC,
    AUDIT_TAG_LEN, AuditAnchor, AuditAuthenticator, AuditContainerError, AuditContainerHeader,
    AuditContainerId, AuditContainerWriter, AuditHeaderError, AuditPredecessor, AuditRecordKind,
    AuditRecordView, AuditTag, VerifiedAuditContainer, VerifiedAuditRecords, audit_record_len,
    verify_audit_container,
};
pub use audit_prefix::{
    AUDIT_PREFIX_AUTHENTICATED_LEN, AUDIT_PREFIX_MAGIC, AUDIT_PREFIX_RECORD_LEN,
    AUDIT_PREFIX_TAG_LEN, AUDIT_PREFIX_VERSION, AuditPrefixAnchor, AuditPrefixCursor,
    AuditPrefixError, AuditPrefixFlags, AuditPrefixHeaderField, AuditPrefixRecordVariant,
    AuditPrefixTicketState, TaggedAuditPrefixAnchor, decode_audit_prefix_anchor,
    encode_audit_prefix_anchor, encode_audit_prefix_authenticated,
};
pub use book::{ApplyOutcome, BookError, BookEvent, BookOrder, L3Book, PriceLevel};
pub use clock::{ClockDiscipline, ClockError, ClockSample, DisciplinedTimestamp};
pub use drop_copy::{
    DropCopyChannel, DropCopyConfig, DropCopyError, DropCopyReportIdentity, DropCopyReportKind,
    DropCopyStatus,
};
pub use engine::ReconciledOrderFaultSummary;
pub use engine_replay::{
    EngineReplayError, EngineReplayOutcome, EngineReplayRoute, dispatch_engine_replay_event,
};
pub use event_codec::{
    EventCodecError, ReplayInput, SnapshotCaptureMetadata, VenueCaptureMetadata, decode_clock,
    decode_control_decision, decode_drop_copy, decode_market_data, decode_order_entry,
    decode_owned_mbo_binding, decode_replay_input, decode_snapshot, decode_timer,
    decode_transmission, normalize_clock, normalize_control_decision, normalize_drop_copy,
    normalize_market_data, normalize_order_entry, normalize_owned_mbo_binding, normalize_snapshot,
    normalize_timer, normalize_transmission,
};
pub use events::{
    CanonicalField, CaptureOrdinal, EVENT_FLAG_RECOVERY, EVENT_FLAG_SNAPSHOT, EventError,
    EventKind, EventSide, EventSource, NormalizedEvent, SequenceDomain, SessionEpoch, SourceId,
};
pub use fixed::{CapacityError, FixedIndexMap, FixedVec};
pub use journal::{
    BoundaryState, BoundaryViolation, EncodeError, RecordError, ReplayConsumer,
    ReplayConsumerError, ReplayContribution, ReplayDigest, ReplayError, ReplayState, ReplaySummary,
    decode_record, encode_record, replay_bytes, replay_bytes_with_consumer,
};
pub use kill::{KillCode, KillLatch, KillSnapshot, KillState};
pub use native_audit_codec::{
    NATIVE_AUDIT_RECORD_CHECKSUM_LEN, NATIVE_AUDIT_RECORD_HEADER_LEN, NATIVE_AUDIT_RECORD_MAGIC,
    NATIVE_AUDIT_RECORD_VERSION, NATIVE_LIVE_CHECKPOINT_BODY_LEN,
    NATIVE_LIVE_CHECKPOINT_RECORD_LEN, NativeAuditCodecError, NativeAuditRecordVariant,
    NativeAuditRecordView, NativeCheckpointOptionField, NativeCheckpointSourceField,
    decode_native_audit_record, decode_native_live_checkpoint_record, encode_native_audit_record,
    encode_native_live_checkpoint_record,
};
pub use native_live::{
    NATIVE_LIVE_AUDIT_CAPACITY, NativeLiveApplicationFaultRecord, NativeLiveAudit,
    NativeLiveAuditCapacity, NativeLiveCheckpoint, NativeLiveCheckpointError,
    NativeLiveCheckpointVerifier, NativeLiveClockFallbackRecord, NativeLiveCoordinator,
    NativeLiveEgressRecord, NativeLiveEmergencySealRecord, NativeLiveEncodeFault,
    NativeLiveEncodeFaultRecord, NativeLiveError, NativeLiveIntent, NativeLiveOperation,
    NativeLivePhase, NativeLivePostRunFault, NativeLiveProofFault, NativeLiveProofFaultRecord,
    NativeLiveReactorFaultRecord, NativeLiveRecoveryError, NativeLiveSafetyReason,
    NativeLiveScratch, NativeLiveStatus, NativeLiveSummary, NativeOrderTransport, NativeSubmit,
    NativeSubmitDisposition,
};
pub use native_recovery::{
    NativeLiveCheckpointHeaderField, NativeLiveRecordedNonRunnablePhase,
    NativeLiveRecordedRunnablePhase, NativeLiveRecoveryCheckpointError, NativeLiveRecoveryEvidence,
    NativeLiveRecoveryRequirement, NativeLiveRecoveryScanError, NativeLiveTrailingRecordKind,
    scan_native_live_recovery,
};
pub use native_replay::{
    NativeIngressCapture, NativeIngressLane, NativeOrderEgressCapture,
    NativeOwnedMboIngressCapture, NativeOwnedMboReplayResult, NativePacketMetadata,
    NativeReplayError, NativeReplayVerifier, NativeSnapshotContext, NativeTransmissionContext,
    NativeTransmissionDisposition, NativeTransmissionProofError, NativeTransmissionProofVerifier,
};
pub use orders::{
    CancelApplyOutcome, CancelConfirmed, CancelReason, CancelRejected, ExecutionPriceViolation,
    FillApplyOutcome, FillReport, LifecycleEvent, ManagedOrderSnapshot, ManagedOrderState,
    NewAccepted, NewOrderRequest, NewRejected, OrderEconomics, OrderError, OrderManager,
    VenueOrderIdentity,
};
pub use ownership::{OwnedMboRegistry, OwnershipBindOutcome, OwnershipError};
pub use queue::{
    ExactQueuePosition, QueueAction, QueueError, QueuePolicy, QueuePosition, QueueStatus,
    QueueUpdate,
};
pub use reactor_audit::{
    SCHEDULER_COMMIT_HEADER_LEN, SCHEDULER_COMMIT_MAGIC, SCHEDULER_COMMIT_RECORD_LEN,
    SCHEDULER_COMMIT_VERSION, SchedulerCommit, SchedulerCommitError, SchedulerCommitVerifier,
    SchedulerReplayError, SchedulerRoute, decode_scheduler_commit, encode_scheduler_commit,
};
pub use reactor_replay::{
    ReactorReplayError, ReactorReplayOutcome, dispatch_reactor_replay_event,
    dispatch_reactor_replay_retention, dispatch_reactor_replay_safety_kill,
};
pub use reference_data::{
    FixedInstrumentValue, InstrumentDefinition, InstrumentDefinitionBinding,
    InstrumentDefinitionError, InstrumentRuleViolation, NativeProductId, RationalScale,
    ReferenceDataAuthorityId, ReferenceDataDigest, SelfTradePreventionInstruction,
};
pub use spsc::{Consumer, Producer, SpscRing};
pub use strategy::{
    InventoryAwareQuoter, MarketFeatures, QuoteDecision, QuoteLeg, QuotePolicyConfig, StrategyError,
};
pub use telemetry::{LatencyHistogram, LatencyStage, PipelineLatency};
pub use types::{
    CurrencyId, EventHeader, InstrumentId, MonotonicTimestampNs, OrderId, PriceTicks, Quantity,
    Sequence, Side, TimestampNs, VenueId,
};
pub use venue::{
    ClientOrderId, LifecycleCorrectionDigest, LifecycleCorrectionId, LifecycleCorrectionKind,
    LifecycleCorrectionObserved, MarketByOrderId, OwnedMboBinding, OwnedMboBindingMethod, TradeId,
    VenueOrderId,
};
