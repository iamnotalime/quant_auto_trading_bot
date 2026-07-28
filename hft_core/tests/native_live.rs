mod support;

use core::cell::Cell;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;

use quant_hft_core::adverse::AdverseConfig;
use quant_hft_core::clock::ClockSample;
use quant_hft_core::control::ConfigDigest;
use quant_hft_core::engine::{EngineConfig, ExecutionEngine, TransmissionStatus};
use quant_hft_core::journal::{RECORD_LEN, decode_record};
use quant_hft_core::native_live::{
    NATIVE_LIVE_AUDIT_CAPACITY, NativeLiveApplicationFaultRecord, NativeLiveAudit,
    NativeLiveAuditCapacity, NativeLiveCheckpoint, NativeLiveCheckpointError,
    NativeLiveCheckpointVerifier, NativeLiveClockFallbackRecord, NativeLiveCoordinator,
    NativeLiveEgressRecord, NativeLiveEmergencySealRecord, NativeLiveEncodeFault,
    NativeLiveEncodeFaultRecord, NativeLiveError, NativeLiveIntent, NativeLiveOperation,
    NativeLivePhase, NativeLiveProofFault, NativeLiveProofFaultRecord,
    NativeLiveReactorFaultRecord, NativeLiveRecoveryError, NativeLiveSafetyReason,
    NativeLiveScratch, NativeLiveStatus, NativeOrderTransport, NativeSubmit,
    NativeSubmitDisposition,
};
use quant_hft_core::native_replay::{
    NativeTransmissionContext, NativeTransmissionDisposition, NativeTransmissionProofError,
    NativeTransmissionProofVerifier,
};
use quant_hft_core::reactor::{
    HotPathReactor, InputOrdinal, ReactorEgress, ReactorInputKind, TimerAction, TimerId,
    TimerInput, TransmissionInput,
};
use quant_hft_core::reactor_audit::{SchedulerCommit, SchedulerRoute};
use quant_hft_core::reactor_replay::dispatch_reactor_replay_event;
use quant_hft_core::risk::{
    CurrencyId, InstrumentRiskDefinition, InstrumentValuation, RiskLimits, RiskSessionId,
};
use quant_hft_core::strategy::QuotePolicyConfig;
use quant_hft_core::venue::{
    Accepted, BookDelta, CancelOrder, Canceled, ClientOrderId, DecodeResult, InboundMessage,
    InboundPayload, MarketDataMessage, MarketDataPayload, NativeOrderEntryDecoder,
    NativeOrderEntryEncoder, NewOrder, OrderCommand, OrderEvent, ProtocolId, SessionCommand,
    SessionEvent, SessionId, SnapshotMessage, SnapshotOrder, SnapshotPayload, TimeInForce,
    TransactionalCodec, VenueCapabilities, VenueDescriptor, VenueError, VenueIdentity,
    VenueOrderId, VenueSession, WireError,
};
use quant_hft_core::{
    CaptureOrdinal, EventSource, InstrumentId, MonotonicTimestampNs, NormalizedEvent, OrderId,
    PriceTicks, Quantity, Sequence, SequenceDomain, SessionEpoch, Side, SourceId, TimestampNs,
    VenueCaptureMetadata, VenueId, encode_record, normalize_control_decision,
    normalize_market_data, normalize_order_entry, normalize_timer, normalize_transmission,
    replay_bytes,
};

const IDENTITY: VenueIdentity = VenueIdentity {
    venue: VenueId(7),
    market_data_protocol: ProtocolId(101),
    order_entry_protocol: ProtocolId(202),
    session: SessionId(303),
};
const OTHER_IDENTITY: VenueIdentity = VenueIdentity {
    venue: VenueId(7),
    market_data_protocol: ProtocolId(111),
    order_entry_protocol: ProtocolId(222),
    session: SessionId(333),
};
const OTHER_VENUE_IDENTITY: VenueIdentity = VenueIdentity {
    venue: VenueId(8),
    market_data_protocol: ProtocolId(101),
    order_entry_protocol: ProtocolId(202),
    session: SessionId(303),
};
const INVALID_IDENTITY: VenueIdentity = VenueIdentity {
    venue: VenueId(0),
    market_data_protocol: ProtocolId(101),
    order_entry_protocol: ProtocolId(202),
    session: SessionId(303),
};
const INSTRUMENT: InstrumentId = InstrumentId(9);

const fn instrument_definition() -> quant_hft_core::InstrumentDefinition {
    support::instrument_definition(IDENTITY.venue, INSTRUMENT)
}

const fn other_venue_instrument_definition() -> quant_hft_core::InstrumentDefinition {
    support::instrument_definition(OTHER_VENUE_IDENTITY.venue, INSTRUMENT)
}
const MARKET_DATA_SOURCE: EventSource = EventSource::new(
    SourceId::new(IDENTITY.market_data_protocol.0, 1),
    SequenceDomain::MarketData,
    SessionEpoch(1),
);
const ORDER_ENTRY_SOURCE: EventSource = EventSource::new(
    SourceId::new(IDENTITY.order_entry_protocol.0, 1),
    SequenceDomain::OrderEntry,
    SessionEpoch(1),
);
const OTHER_MARKET_DATA_SOURCE: EventSource = EventSource::new(
    SourceId::new(OTHER_IDENTITY.market_data_protocol.0, 1),
    SequenceDomain::MarketData,
    SessionEpoch(1),
);
const OTHER_ORDER_ENTRY_SOURCE: EventSource = EventSource::new(
    SourceId::new(OTHER_IDENTITY.order_entry_protocol.0, 1),
    SequenceDomain::OrderEntry,
    SessionEpoch(1),
);
const CAPABILITIES: VenueCapabilities =
    VenueCapabilities::NEW_ORDER.union(VenueCapabilities::CANCEL_ORDER);
const WIRE_LEN: usize = 47;
const CANCEL_WIRE_LEN: usize = 33;
const FIRST_CAPTURE_ORDINAL: CaptureOrdinal = CaptureOrdinal(2);
const FIRST_FRAME_ORDINAL: u64 = 90;
const FIRST_COMMIT_ORDINAL: u64 = 50;
const MONOTONIC_CLOCK_EPOCH: u64 = 1;

const OP_RESERVE: u8 = 1;
const OP_COMMIT: u8 = 2;
const OP_INTENT: u8 = 3;
const OP_SUBMIT: u8 = 4;
const OP_EGRESS: u8 = 5;
const OP_TRANSMISSION: u8 = 6;
const OP_ENCODE_FAULT: u8 = 7;
const OP_FINISH: u8 = 8;
const OP_ABORT: u8 = 9;
const OP_QUIESCE: u8 = 10;
const OP_CLOCK_FALLBACK: u8 = 11;
const OP_SOURCE: u8 = 12;
const OP_REACTOR_FAULT: u8 = 14;
const OP_APPLICATION_FAULT: u8 = 15;
const OP_EMERGENCY_SEAL: u8 = 16;
const OP_PROOF_FAULT: u8 = 17;

#[derive(Debug)]
struct CountingAllocator;

static ALLOCATION_TEST_LOCK: Mutex<()> = Mutex::new(());

thread_local! {
    static TRACK_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

fn count_allocation() {
    let _ = TRACK_ALLOCATIONS.try_with(|tracking| {
        if tracking.get() {
            let _ = ALLOCATIONS.try_with(|allocations| {
                allocations.set(allocations.get().saturating_add(1));
            });
        }
    });
}

// SAFETY: every operation is forwarded unchanged to `System`; the counter is
// observational and does not alter pointer, layout, or lifetime semantics.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_allocation();
        // SAFETY: the caller provides the `GlobalAlloc` contract and `layout` is
        // forwarded unchanged to the system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: `pointer` and `layout` came from the forwarded system allocation.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_allocation();
        // SAFETY: the caller provides the `GlobalAlloc` contract and `layout` is
        // forwarded unchanged to the system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count_allocation();
        // SAFETY: all arguments are forwarded unchanged to the system allocator.
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn tracked_allocations(operation: impl FnOnce()) -> usize {
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(false));
    ALLOCATIONS.with(|allocations| allocations.set(0));
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(true));
    operation();
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(false));
    ALLOCATIONS.with(Cell::get)
}

type TestEngine = ExecutionEngine<64, 16, 8, 16, 16>;
type TestReactor = HotPathReactor<64, 16, 8, 16, 16>;

#[derive(Debug)]
struct FixedOperationLog {
    entries: [Cell<u8>; 32],
    len: Cell<usize>,
}

impl FixedOperationLog {
    fn new() -> Self {
        Self {
            entries: core::array::from_fn(|_| Cell::new(0)),
            len: Cell::new(0),
        }
    }

    fn push(&self, operation: u8) {
        let index = self.len.get();
        assert!(index < self.entries.len(), "fixed operation log overflow");
        self.entries[index].set(operation);
        self.len.set(index + 1);
    }

    fn assert_exact(&self, expected: &[u8]) {
        assert_eq!(self.len.get(), expected.len());
        for (index, operation) in expected.iter().copied().enumerate() {
            assert_eq!(self.entries[index].get(), operation, "operation {index}");
        }
        assert!(
            self.entries[expected.len()..]
                .iter()
                .all(|entry| entry.get() == 0)
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CapturedContext {
    frame_ordinal: u64,
    adapter_identity: VenueIdentity,
    venue_sequence: Sequence,
    scheduler_commit_ordinal: u64,
    scheduler_capture_ordinal: CaptureOrdinal,
    scheduler_source_event_crc32c: u32,
    egress: ReactorEgress,
    encoded_bytes: [u8; 64],
    encoded_len: usize,
}

impl CapturedContext {
    fn copy_from(context: NativeTransmissionContext<'_>) -> Self {
        assert!(context.encoded_bytes.len() <= 64);
        let mut encoded_bytes = [0_u8; 64];
        encoded_bytes[..context.encoded_bytes.len()].copy_from_slice(context.encoded_bytes);
        Self {
            frame_ordinal: context.frame_ordinal,
            adapter_identity: context.adapter_identity,
            venue_sequence: context.venue_sequence,
            scheduler_commit_ordinal: context.scheduler_commit_ordinal,
            scheduler_capture_ordinal: context.scheduler_capture_ordinal,
            scheduler_source_event_crc32c: context.scheduler_source_event_crc32c,
            egress: context.egress,
            encoded_bytes,
            encoded_len: context.encoded_bytes.len(),
        }
    }

    fn encoded(&self) -> &[u8] {
        &self.encoded_bytes[..self.encoded_len]
    }
}

#[derive(Debug)]
struct FixedTransport<'a> {
    operations: &'a FixedOperationLog,
    submissions: [NativeSubmit<u64>; 2],
    contexts: [Option<CapturedContext>; 2],
    submit_count: usize,
    quiesce_count: usize,
    proof_mode: ProofMode,
    verifier_state: usize,
    verify_attempts: usize,
    verifier_commits: usize,
    verifier_restores: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProofMode {
    MatchClaim,
    Rejected,
    Ambiguous,
    Verified(NativeTransmissionDisposition),
}

impl<'a> FixedTransport<'a> {
    fn new(operations: &'a FixedOperationLog, submissions: [NativeSubmit<u64>; 2]) -> Self {
        Self {
            operations,
            submissions,
            contexts: [None; 2],
            submit_count: 0,
            quiesce_count: 0,
            proof_mode: ProofMode::MatchClaim,
            verifier_state: 0,
            verify_attempts: 0,
            verifier_commits: 0,
            verifier_restores: 0,
        }
    }

    fn with_proof_mode(mut self, proof_mode: ProofMode) -> Self {
        self.proof_mode = proof_mode;
        self
    }
}

impl NativeOrderTransport for FixedTransport<'_> {
    type Proof = u64;

    fn submit(&mut self, context: NativeTransmissionContext<'_>) -> NativeSubmit<Self::Proof> {
        self.operations.push(OP_SUBMIT);
        assert!(self.submit_count < self.submissions.len());
        self.contexts[self.submit_count] = Some(CapturedContext::copy_from(context));
        let result = self.submissions[self.submit_count];
        self.submit_count += 1;
        result
    }

    fn quiesce(&mut self) {
        self.operations.push(OP_QUIESCE);
        self.quiesce_count += 1;
    }
}

impl NativeTransmissionProofVerifier for FixedTransport<'_> {
    type Proof = u64;
    type Checkpoint = usize;

    fn checkpoint(&self) -> Self::Checkpoint {
        self.verifier_state
    }

    fn restore(&mut self, checkpoint: Self::Checkpoint) {
        self.verifier_state = checkpoint;
        self.verifier_restores += 1;
    }

    fn commit(&mut self, _checkpoint: Self::Checkpoint) {
        self.verifier_commits += 1;
    }

    fn verify(
        &mut self,
        context: NativeTransmissionContext<'_>,
        proof: &Self::Proof,
    ) -> Result<NativeTransmissionDisposition, NativeTransmissionProofError> {
        self.verify_attempts += 1;
        let Some(index) = self.submit_count.checked_sub(1) else {
            return Err(NativeTransmissionProofError::Rejected);
        };
        let (expected_proof, disposition, monotonic_now) =
            submission_parts(self.submissions[index]);
        if *proof != expected_proof
            || self.contexts[index] != Some(CapturedContext::copy_from(context))
        {
            return Err(NativeTransmissionProofError::Rejected);
        }
        self.verifier_state += 1;
        match self.proof_mode {
            ProofMode::MatchClaim => match disposition {
                NativeSubmitDisposition::Sent => Ok(NativeTransmissionDisposition {
                    status: TransmissionStatus::Sent,
                    monotonic_now,
                }),
                NativeSubmitDisposition::ProvenUnsent => Ok(NativeTransmissionDisposition {
                    status: TransmissionStatus::ProvenUnsent,
                    monotonic_now,
                }),
                NativeSubmitDisposition::Ambiguous => Err(NativeTransmissionProofError::Ambiguous),
            },
            ProofMode::Rejected => Err(NativeTransmissionProofError::Rejected),
            ProofMode::Ambiguous => Err(NativeTransmissionProofError::Ambiguous),
            ProofMode::Verified(disposition) => Ok(disposition),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CapturedEgress {
    context: CapturedContext,
    proof: u64,
    disposition: NativeSubmitDisposition,
    monotonic_now: MonotonicTimestampNs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CapturedProofFault {
    context: CapturedContext,
    proof: u64,
    claimed_disposition: NativeSubmitDisposition,
    claimed_monotonic_now: MonotonicTimestampNs,
    fault: NativeLiveProofFault,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuditFailure {
    Capacity,
}

#[derive(Debug)]
struct FixedAudit<'a> {
    operations: &'a FixedOperationLog,
    fail_reserve: bool,
    next_appended_capture: CaptureOrdinal,
    sequencer_monotonic: MonotonicTimestampNs,
    next_frame_ordinal: u64,
    frame_step: u64,
    reserve_calls: usize,
    reserved: Option<NativeLiveAuditCapacity>,
    source_events: [Option<NormalizedEvent>; 1],
    source_event_count: usize,
    commits: [Option<SchedulerCommit>; 3],
    commit_count: usize,
    intents: [Option<CapturedContext>; 2],
    intent_count: usize,
    egress: [Option<CapturedEgress>; 2],
    egress_count: usize,
    proof_faults: [Option<CapturedProofFault>; 1],
    proof_fault_count: usize,
    transmissions: [Option<NormalizedEvent>; 2],
    transmission_count: usize,
    encode_faults: [Option<NativeLiveEncodeFaultRecord>; 1],
    encode_fault_count: usize,
    clock_fallbacks: [Option<NativeLiveClockFallbackRecord>; 1],
    clock_fallback_count: usize,
    reactor_faults: [Option<NativeLiveReactorFaultRecord>; 2],
    reactor_fault_count: usize,
    application_faults: [Option<NativeLiveApplicationFaultRecord>; 2],
    application_fault_count: usize,
    emergency_seals: [Option<NativeLiveEmergencySealRecord<AuditFailure>>; 1],
    emergency_seal_count: usize,
    sealed_checkpoints: [Option<NativeLiveCheckpoint>; 1],
    finish_count: usize,
    abort_count: usize,
}

impl<'a> FixedAudit<'a> {
    fn new(operations: &'a FixedOperationLog) -> Self {
        Self::new_at(operations, CaptureOrdinal(3), FIRST_FRAME_ORDINAL)
    }

    fn new_at(
        operations: &'a FixedOperationLog,
        next_appended_capture: CaptureOrdinal,
        next_frame_ordinal: u64,
    ) -> Self {
        assert_ne!(next_appended_capture, CaptureOrdinal(0));
        assert_ne!(next_frame_ordinal, 0);
        Self {
            operations,
            fail_reserve: false,
            next_appended_capture,
            sequencer_monotonic: MonotonicTimestampNs::ZERO,
            next_frame_ordinal,
            frame_step: 1,
            reserve_calls: 0,
            reserved: None,
            source_events: [None; 1],
            source_event_count: 0,
            commits: [None; 3],
            commit_count: 0,
            intents: [None; 2],
            intent_count: 0,
            egress: [None; 2],
            egress_count: 0,
            proof_faults: [None; 1],
            proof_fault_count: 0,
            transmissions: [None; 2],
            transmission_count: 0,
            encode_faults: [None; 1],
            encode_fault_count: 0,
            clock_fallbacks: [None; 1],
            clock_fallback_count: 0,
            reactor_faults: [None; 2],
            reactor_fault_count: 0,
            application_faults: [None; 2],
            application_fault_count: 0,
            emergency_seals: [None; 1],
            emergency_seal_count: 0,
            sealed_checkpoints: [None; 1],
            finish_count: 0,
            abort_count: 0,
        }
    }

    fn rejecting(operations: &'a FixedOperationLog) -> Self {
        let mut audit = Self::new(operations);
        audit.fail_reserve = true;
        audit
    }

    fn assert_untouched(&self) {
        self.operations.assert_exact(&[]);
        assert_eq!(self.reserve_calls, 0);
        assert_eq!(self.reserved, None);
        assert_eq!(self.source_event_count, 0);
        assert_eq!(self.commit_count, 0);
        assert_eq!(self.intent_count, 0);
        assert_eq!(self.egress_count, 0);
        assert_eq!(self.proof_fault_count, 0);
        assert_eq!(self.transmission_count, 0);
        assert_eq!(self.encode_fault_count, 0);
        assert_eq!(self.clock_fallback_count, 0);
        assert_eq!(self.reactor_fault_count, 0);
        assert_eq!(self.application_fault_count, 0);
        assert_eq!(self.emergency_seal_count, 0);
        assert_eq!(self.finish_count, 0);
        assert_eq!(self.abort_count, 0);
    }
}

#[derive(Debug, Default)]
struct AcceptCheckpointVerifier {
    calls: u64,
}

impl NativeLiveCheckpointVerifier for AcceptCheckpointVerifier {
    type Seal = u64;
    type Error = u8;

    fn verify_latest(
        &mut self,
        _checkpoint: NativeLiveCheckpoint,
        _seal: Self::Seal,
    ) -> Result<(), Self::Error> {
        self.calls += 1;
        Ok(())
    }
}

impl NativeLiveAudit<u64> for FixedAudit<'_> {
    type Ticket = u8;
    type Error = AuditFailure;

    fn reserve(&mut self, capacity: NativeLiveAuditCapacity) -> Result<Self::Ticket, Self::Error> {
        self.operations.push(OP_RESERVE);
        self.reserve_calls += 1;
        if self.fail_reserve {
            return Err(AuditFailure::Capacity);
        }
        assert_eq!(capacity, NATIVE_LIVE_AUDIT_CAPACITY);
        self.reserved = Some(capacity);
        Ok(1)
    }

    fn seal_emergency(&mut self, record: NativeLiveEmergencySealRecord<Self::Error>) {
        self.operations.push(OP_EMERGENCY_SEAL);
        assert!(self.emergency_seal_count < self.emergency_seals.len());
        self.emergency_seals[self.emergency_seal_count] = Some(record);
        self.emergency_seal_count += 1;
    }

    fn record_scheduler_commit(&mut self, ticket: Self::Ticket, commit: SchedulerCommit) {
        assert_eq!(ticket, 1);
        self.operations.push(OP_COMMIT);
        assert!(self.commit_count < self.commits.len());
        self.commits[self.commit_count] = Some(commit);
        self.commit_count += 1;
    }

    fn record_source_event(&mut self, ticket: Self::Ticket, event: NormalizedEvent) {
        assert_eq!(ticket, 1);
        self.operations.push(OP_SOURCE);
        assert!(self.source_event_count < self.source_events.len());
        self.source_events[self.source_event_count] = Some(event);
        self.source_event_count += 1;
    }

    fn append_native_intent(&mut self, ticket: Self::Ticket, intent: NativeLiveIntent<'_>) -> u64 {
        assert_eq!(ticket, 1);
        self.operations.push(OP_INTENT);
        assert!(self.intent_count < self.intents.len());
        let frame_ordinal = self.next_frame_ordinal;
        self.next_frame_ordinal = self.next_frame_ordinal.wrapping_add(self.frame_step);
        let context = intent.with_frame_ordinal(frame_ordinal);
        self.intents[self.intent_count] = Some(CapturedContext::copy_from(context));
        self.intent_count += 1;
        frame_ordinal
    }

    fn record_native_egress(
        &mut self,
        ticket: Self::Ticket,
        record: NativeLiveEgressRecord<'_, u64>,
    ) {
        assert_eq!(ticket, 1);
        self.operations.push(OP_EGRESS);
        assert!(self.egress_count < self.egress.len());
        self.egress[self.egress_count] = Some(CapturedEgress {
            context: CapturedContext::copy_from(record.context),
            proof: record.proof,
            disposition: record.disposition,
            monotonic_now: record.monotonic_now,
        });
        self.egress_count += 1;
    }

    fn record_proof_fault(
        &mut self,
        ticket: Self::Ticket,
        record: NativeLiveProofFaultRecord<'_, u64>,
    ) {
        assert_eq!(ticket, 1);
        self.operations.push(OP_PROOF_FAULT);
        assert!(self.proof_fault_count < self.proof_faults.len());
        self.proof_faults[self.proof_fault_count] = Some(CapturedProofFault {
            context: CapturedContext::copy_from(record.context),
            proof: record.proof,
            claimed_disposition: record.claimed_disposition,
            claimed_monotonic_now: record.claimed_monotonic_now,
            fault: record.fault,
        });
        self.proof_fault_count += 1;
    }

    fn append_transmission_event(
        &mut self,
        ticket: Self::Ticket,
        minimum: TransmissionInput,
    ) -> NormalizedEvent {
        assert_eq!(ticket, 1);
        self.operations.push(OP_TRANSMISSION);
        assert!(self.transmission_count < self.transmissions.len());
        let monotonic_now = self.sequencer_monotonic.max(minimum.monotonic_now);
        let event = normalize_transmission(
            self.next_appended_capture,
            TransmissionInput {
                command: minimum.command,
                status: minimum.status,
                monotonic_now,
            },
        )
        .unwrap();
        self.next_appended_capture.0 = self
            .next_appended_capture
            .0
            .checked_add(1)
            .expect("fixed audit capture ordinal exhaustion");
        self.sequencer_monotonic = monotonic_now;
        self.transmissions[self.transmission_count] = Some(event);
        self.transmission_count += 1;
        event
    }

    fn record_encode_fault(&mut self, ticket: Self::Ticket, record: NativeLiveEncodeFaultRecord) {
        assert_eq!(ticket, 1);
        self.operations.push(OP_ENCODE_FAULT);
        assert!(self.encode_fault_count < self.encode_faults.len());
        self.encode_faults[self.encode_fault_count] = Some(record);
        self.encode_fault_count += 1;
    }

    fn record_clock_fallback(
        &mut self,
        ticket: Self::Ticket,
        record: NativeLiveClockFallbackRecord,
    ) {
        assert_eq!(ticket, 1);
        self.operations.push(OP_CLOCK_FALLBACK);
        assert!(self.clock_fallback_count < self.clock_fallbacks.len());
        self.clock_fallbacks[self.clock_fallback_count] = Some(record);
        self.clock_fallback_count += 1;
    }

    fn record_reactor_fault(&mut self, ticket: Self::Ticket, record: NativeLiveReactorFaultRecord) {
        assert_eq!(ticket, 1);
        self.operations.push(OP_REACTOR_FAULT);
        assert!(self.reactor_fault_count < self.reactor_faults.len());
        self.reactor_faults[self.reactor_fault_count] = Some(record);
        self.reactor_fault_count += 1;
    }

    fn record_application_fault(
        &mut self,
        ticket: Self::Ticket,
        record: NativeLiveApplicationFaultRecord,
    ) {
        assert_eq!(ticket, 1);
        self.operations.push(OP_APPLICATION_FAULT);
        assert!(self.application_fault_count < self.application_faults.len());
        self.application_faults[self.application_fault_count] = Some(record);
        self.application_fault_count += 1;
    }

    fn seal(&mut self, ticket: Self::Ticket, checkpoint: NativeLiveCheckpoint) {
        assert_eq!(ticket, 1);
        self.operations.push(OP_FINISH);
        assert!(self.finish_count < self.sealed_checkpoints.len());
        self.sealed_checkpoints[self.finish_count] = Some(checkpoint);
        self.finish_count += 1;
    }

    fn abort(&mut self, ticket: Self::Ticket) {
        assert_eq!(ticket, 1);
        self.operations.push(OP_ABORT);
        self.abort_count += 1;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AdapterCheckpoint {
    codec_state: u64,
    durable_commits: u64,
    dirty_input_seen: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct FixedVenueAdapter {
    codec_state: u64,
    durable_commits: u64,
    dirty_input_seen: bool,
    dirty_tail: bool,
}

impl VenueDescriptor for FixedVenueAdapter {
    const IDENTITY: VenueIdentity = IDENTITY;
    const CAPABILITIES: VenueCapabilities = CAPABILITIES;
}

impl TransactionalCodec for FixedVenueAdapter {
    type Checkpoint = AdapterCheckpoint;

    fn checkpoint(&self) -> Self::Checkpoint {
        AdapterCheckpoint {
            codec_state: self.codec_state,
            durable_commits: self.durable_commits,
            dirty_input_seen: self.dirty_input_seen,
        }
    }

    fn restore(&mut self, checkpoint: Self::Checkpoint) {
        self.codec_state = checkpoint.codec_state;
        self.durable_commits = checkpoint.durable_commits;
        self.dirty_input_seen = checkpoint.dirty_input_seen;
    }

    fn commit(&mut self, _checkpoint: Self::Checkpoint) {
        self.durable_commits += 1;
    }
}

impl NativeOrderEntryDecoder for FixedVenueAdapter {
    fn decode_order_entry(
        &mut self,
        packet: &[u8],
        hardware_receive_timestamp: TimestampNs,
        output: &mut [Option<InboundMessage>],
    ) -> Result<DecodeResult, WireError> {
        if packet != [0x01] {
            return Err(WireError::MalformedPacket);
        }
        let Some(slot) = output.first_mut() else {
            return Err(WireError::BufferTooSmall {
                required: 1,
                provided: 0,
            });
        };
        self.codec_state += 1;
        *slot = Some(InboundMessage {
            sequence: Sequence(1),
            exchange_timestamp: TimestampNs(20),
            hardware_receive_timestamp,
            payload: InboundPayload::Session(SessionEvent::LogonAccepted),
        });
        Ok(DecodeResult {
            messages: 1,
            consumed_bytes: 1,
        })
    }
}

impl NativeOrderEntryEncoder for FixedVenueAdapter {
    fn encode_session(
        &mut self,
        _sequence: Sequence,
        _command: SessionCommand,
        _output: &mut [u8],
    ) -> Result<usize, WireError> {
        Err(WireError::UnsupportedMessage { message_type: 0 })
    }

    fn encode_order(
        &mut self,
        sequence: Sequence,
        command: OrderCommand,
        _instrument: quant_hft_core::InstrumentDefinition,
        output: &mut [u8],
    ) -> Result<usize, WireError> {
        if output.iter().any(|byte| *byte != 0) {
            self.dirty_input_seen = true;
        }
        self.codec_state += 1;
        let bytes = match command {
            OrderCommand::New(order) => {
                if output.len() < WIRE_LEN {
                    return Err(WireError::BufferTooSmall {
                        required: WIRE_LEN,
                        provided: output.len(),
                    });
                }
                write_new_order(output, sequence, order);
                WIRE_LEN
            }
            OrderCommand::Cancel(cancel) => {
                if output.len() < CANCEL_WIRE_LEN {
                    return Err(WireError::BufferTooSmall {
                        required: CANCEL_WIRE_LEN,
                        provided: output.len(),
                    });
                }
                write_cancel(output, sequence, cancel);
                CANCEL_WIRE_LEN
            }
            OrderCommand::Replace(_) | OrderCommand::CancelAll(_) => {
                return Err(WireError::UnsupportedMessage { message_type: 0 });
            }
        };
        if self.dirty_tail {
            let Some(tail) = output.get_mut(bytes) else {
                return Err(WireError::BufferTooSmall {
                    required: bytes + 1,
                    provided: output.len(),
                });
            };
            *tail = 0xD1;
        }
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct MismatchedVenueAdapter {
    inner: FixedVenueAdapter,
}

impl VenueDescriptor for MismatchedVenueAdapter {
    const IDENTITY: VenueIdentity = OTHER_IDENTITY;
    const CAPABILITIES: VenueCapabilities = CAPABILITIES;
}

impl TransactionalCodec for MismatchedVenueAdapter {
    type Checkpoint = AdapterCheckpoint;

    fn checkpoint(&self) -> Self::Checkpoint {
        self.inner.checkpoint()
    }

    fn restore(&mut self, checkpoint: Self::Checkpoint) {
        self.inner.restore(checkpoint);
    }

    fn commit(&mut self, checkpoint: Self::Checkpoint) {
        self.inner.commit(checkpoint);
    }
}

impl NativeOrderEntryEncoder for MismatchedVenueAdapter {
    fn encode_session(
        &mut self,
        sequence: Sequence,
        command: SessionCommand,
        output: &mut [u8],
    ) -> Result<usize, WireError> {
        self.inner.encode_session(sequence, command, output)
    }

    fn encode_order(
        &mut self,
        sequence: Sequence,
        command: OrderCommand,
        instrument: quant_hft_core::InstrumentDefinition,
        output: &mut [u8],
    ) -> Result<usize, WireError> {
        self.inner
            .encode_order(sequence, command, instrument, output)
    }
}

#[test]
fn coordinator_identity_is_validated_and_authenticated_in_checkpoint() {
    assert_eq!(
        NativeLiveCoordinator::new(
            INVALID_IDENTITY,
            instrument_definition(),
            MARKET_DATA_SOURCE,
            ORDER_ENTRY_SOURCE,
            MONOTONIC_CLOCK_EPOCH,
            FIRST_CAPTURE_ORDINAL,
            FIRST_COMMIT_ORDINAL,
        ),
        Err(NativeLiveError::InvalidVenueIdentity(INVALID_IDENTITY))
    );

    let mut invalid_definition = instrument_definition();
    invalid_definition.reference_data_digest = quant_hft_core::ReferenceDataDigest([0; 32]);
    assert_eq!(
        NativeLiveCoordinator::new(
            IDENTITY,
            invalid_definition,
            MARKET_DATA_SOURCE,
            ORDER_ENTRY_SOURCE,
            MONOTONIC_CLOCK_EPOCH,
            FIRST_CAPTURE_ORDINAL,
            FIRST_COMMIT_ORDINAL,
        ),
        Err(NativeLiveError::InvalidInstrumentDefinition(
            quant_hft_core::InstrumentDefinitionError::InvalidReferenceDataDigest,
        ))
    );

    assert_eq!(
        NativeLiveCoordinator::new(
            IDENTITY,
            other_venue_instrument_definition(),
            MARKET_DATA_SOURCE,
            ORDER_ENTRY_SOURCE,
            MONOTONIC_CLOCK_EPOCH,
            FIRST_CAPTURE_ORDINAL,
            FIRST_COMMIT_ORDINAL,
        ),
        Err(NativeLiveError::InstrumentVenueMismatch {
            identity: IDENTITY.venue,
            definition: OTHER_VENUE_IDENTITY.venue,
        })
    );

    for source in [
        EventSource::new(
            SourceId::new(0, MARKET_DATA_SOURCE.id.channel),
            SequenceDomain::MarketData,
            SessionEpoch(1),
        ),
        EventSource::new(
            SourceId::new(MARKET_DATA_SOURCE.id.protocol, 0),
            SequenceDomain::MarketData,
            SessionEpoch(1),
        ),
        EventSource::new(
            SourceId::new(999, MARKET_DATA_SOURCE.id.channel),
            SequenceDomain::MarketData,
            SessionEpoch(1),
        ),
        EventSource::new(
            MARKET_DATA_SOURCE.id,
            SequenceDomain::OrderEntry,
            SessionEpoch(1),
        ),
        EventSource::new(
            MARKET_DATA_SOURCE.id,
            SequenceDomain::MarketData,
            SessionEpoch(0),
        ),
    ] {
        assert_eq!(
            NativeLiveCoordinator::new(
                IDENTITY,
                instrument_definition(),
                source,
                ORDER_ENTRY_SOURCE,
                MONOTONIC_CLOCK_EPOCH,
                FIRST_CAPTURE_ORDINAL,
                FIRST_COMMIT_ORDINAL,
            ),
            Err(NativeLiveError::InvalidMarketDataSource(source))
        );
    }
    for source in [
        EventSource::new(
            SourceId::new(0, ORDER_ENTRY_SOURCE.id.channel),
            SequenceDomain::OrderEntry,
            SessionEpoch(1),
        ),
        EventSource::new(
            SourceId::new(ORDER_ENTRY_SOURCE.id.protocol, 0),
            SequenceDomain::OrderEntry,
            SessionEpoch(1),
        ),
        EventSource::new(
            SourceId::new(999, ORDER_ENTRY_SOURCE.id.channel),
            SequenceDomain::OrderEntry,
            SessionEpoch(1),
        ),
        EventSource::new(
            ORDER_ENTRY_SOURCE.id,
            SequenceDomain::MarketData,
            SessionEpoch(1),
        ),
        EventSource::new(
            ORDER_ENTRY_SOURCE.id,
            SequenceDomain::OrderEntry,
            SessionEpoch(0),
        ),
    ] {
        assert_eq!(
            NativeLiveCoordinator::new(
                IDENTITY,
                instrument_definition(),
                MARKET_DATA_SOURCE,
                source,
                MONOTONIC_CLOCK_EPOCH,
                FIRST_CAPTURE_ORDINAL,
                FIRST_COMMIT_ORDINAL,
            ),
            Err(NativeLiveError::InvalidOrderEntrySource(source))
        );
    }

    let reactor = TestReactor::new(ready_engine());
    let coordinator = coordinator();
    let checkpoint = coordinator.checkpoint();
    assert_eq!(coordinator.expected_identity(), IDENTITY);
    assert_eq!(
        coordinator.expected_instrument_binding(),
        instrument_definition().binding()
    );
    assert_eq!(
        coordinator.expected_market_data_source(),
        MARKET_DATA_SOURCE
    );
    assert_eq!(
        coordinator.expected_order_entry_source(),
        ORDER_ENTRY_SOURCE
    );
    assert_eq!(checkpoint.expected_identity, IDENTITY);
    assert_eq!(
        checkpoint.expected_instrument_binding,
        instrument_definition().binding()
    );
    assert_eq!(checkpoint.expected_market_data_source, MARKET_DATA_SOURCE);
    assert_eq!(checkpoint.expected_order_entry_source, ORDER_ENTRY_SOURCE);

    let mut verifier = AcceptCheckpointVerifier::default();
    assert_eq!(
        NativeLiveCoordinator::from_checkpoint(
            checkpoint,
            1,
            MONOTONIC_CLOCK_EPOCH,
            &reactor,
            &mut verifier,
        ),
        Err(NativeLiveRecoveryError::Checkpoint(
            NativeLiveCheckpointError::ReplayStateUnbound {
                phase: NativeLivePhase::Ready,
            }
        ))
    );

    let invalid_market_data_source = EventSource::new(
        SourceId::new(MARKET_DATA_SOURCE.id.protocol, 0),
        SequenceDomain::MarketData,
        SessionEpoch(1),
    );
    let invalid_market_data_checkpoint = NativeLiveCheckpoint {
        expected_market_data_source: invalid_market_data_source,
        ..checkpoint
    };
    assert_eq!(
        NativeLiveCoordinator::from_checkpoint(
            invalid_market_data_checkpoint,
            2,
            MONOTONIC_CLOCK_EPOCH,
            &reactor,
            &mut verifier,
        ),
        Err(NativeLiveRecoveryError::Checkpoint(
            NativeLiveCheckpointError::InvalidMarketDataSource(invalid_market_data_source)
        ))
    );

    let invalid_order_entry_source = EventSource::new(
        ORDER_ENTRY_SOURCE.id,
        SequenceDomain::OrderEntry,
        SessionEpoch(0),
    );
    let invalid_order_entry_checkpoint = NativeLiveCheckpoint {
        expected_order_entry_source: invalid_order_entry_source,
        ..checkpoint
    };
    assert_eq!(
        NativeLiveCoordinator::from_checkpoint(
            invalid_order_entry_checkpoint,
            3,
            MONOTONIC_CLOCK_EPOCH,
            &reactor,
            &mut verifier,
        ),
        Err(NativeLiveRecoveryError::Checkpoint(
            NativeLiveCheckpointError::InvalidOrderEntrySource(invalid_order_entry_source)
        ))
    );

    let invalid_checkpoint = NativeLiveCheckpoint {
        expected_identity: INVALID_IDENTITY,
        ..checkpoint
    };
    assert_eq!(
        NativeLiveCoordinator::from_checkpoint(
            invalid_checkpoint,
            4,
            MONOTONIC_CLOCK_EPOCH,
            &reactor,
            &mut verifier,
        ),
        Err(NativeLiveRecoveryError::Checkpoint(
            NativeLiveCheckpointError::InvalidVenueIdentity(INVALID_IDENTITY)
        ))
    );

    let mut invalid_definition = instrument_definition();
    invalid_definition.reference_data_digest = quant_hft_core::ReferenceDataDigest([0; 32]);
    let invalid_definition_checkpoint = NativeLiveCheckpoint {
        expected_instrument_binding: invalid_definition.binding(),
        ..checkpoint
    };
    assert_eq!(
        NativeLiveCoordinator::from_checkpoint(
            invalid_definition_checkpoint,
            5,
            MONOTONIC_CLOCK_EPOCH,
            &reactor,
            &mut verifier,
        ),
        Err(NativeLiveRecoveryError::Checkpoint(
            NativeLiveCheckpointError::InvalidInstrumentBinding
        ))
    );

    let mut changed_definition = instrument_definition();
    changed_definition.reference_data_digest = quant_hft_core::ReferenceDataDigest([0x6B; 32]);
    let changed_definition_checkpoint = NativeLiveCheckpoint {
        expected_instrument_binding: changed_definition.binding(),
        ..checkpoint
    };
    assert_eq!(
        NativeLiveCoordinator::from_checkpoint(
            changed_definition_checkpoint,
            6,
            MONOTONIC_CLOCK_EPOCH,
            &reactor,
            &mut verifier,
        ),
        Err(NativeLiveRecoveryError::Checkpoint(
            NativeLiveCheckpointError::EngineInstrumentBindingMismatch {
                checkpoint: changed_definition.binding(),
                engine: instrument_definition().binding(),
            }
        ))
    );

    let wrong_venue_checkpoint = NativeLiveCheckpoint {
        expected_identity: OTHER_VENUE_IDENTITY,
        expected_instrument_binding: other_venue_instrument_definition().binding(),
        ..checkpoint
    };
    assert_eq!(
        NativeLiveCoordinator::from_checkpoint(
            wrong_venue_checkpoint,
            7,
            MONOTONIC_CLOCK_EPOCH,
            &reactor,
            &mut verifier,
        ),
        Err(NativeLiveRecoveryError::Checkpoint(
            NativeLiveCheckpointError::EngineVenueMismatch {
                expected: OTHER_VENUE_IDENTITY.venue,
                actual: IDENTITY.venue,
            }
        ))
    );
    assert_eq!(verifier.calls, 7);
}

#[test]
fn progressed_ready_metadata_cannot_authorize_a_fresh_same_config_reactor() {
    let (recorded_reactor, _session, _adapter, coordinator) = prepared_live_orders_ready();
    let fresh_reactor = TestReactor::new(ready_engine());
    assert_eq!(coordinator.phase(), NativeLivePhase::Ready);
    assert!(!recorded_reactor.deterministic_state_eq(&fresh_reactor));

    let mut verifier = AcceptCheckpointVerifier::default();
    assert_eq!(
        NativeLiveCoordinator::from_checkpoint(
            coordinator.checkpoint(),
            1,
            MONOTONIC_CLOCK_EPOCH,
            &fresh_reactor,
            &mut verifier,
        ),
        Err(NativeLiveRecoveryError::Checkpoint(
            NativeLiveCheckpointError::ReplayStateUnbound {
                phase: NativeLivePhase::Ready,
            }
        ))
    );
    assert_eq!(verifier.calls, 1);
}

#[test]
fn only_non_runnable_checkpoint_metadata_can_be_reconstructed() {
    let mut reactor = TestReactor::new(ready_engine());
    assert!(reactor.trip_internal_safety());
    let base = coordinator().checkpoint();
    let mut verifier = AcceptCheckpointVerifier::default();

    let safety_pending = NativeLiveCheckpoint {
        phase: NativeLivePhase::SafetyPending,
        ..base
    };
    assert_eq!(
        NativeLiveCoordinator::from_checkpoint(
            safety_pending,
            1,
            MONOTONIC_CLOCK_EPOCH,
            &reactor,
            &mut verifier,
        ),
        Err(NativeLiveRecoveryError::Checkpoint(
            NativeLiveCheckpointError::ReplayStateUnbound {
                phase: NativeLivePhase::SafetyPending,
            }
        ))
    );

    for (seal, phase) in [
        (2, NativeLivePhase::Ambiguous),
        (3, NativeLivePhase::Failed),
    ] {
        let checkpoint = NativeLiveCheckpoint { phase, ..base };
        let restored = NativeLiveCoordinator::from_checkpoint(
            checkpoint,
            seal,
            MONOTONIC_CLOCK_EPOCH,
            &reactor,
            &mut verifier,
        )
        .unwrap();
        assert_eq!(restored.phase(), phase);
    }

    let mut killed_engine = ready_engine();
    killed_engine
        .apply_control_decision(
            support::authenticated_kill(
                1,
                ConfigDigest([0xA5; 32]),
                Sequence(1),
                TimestampNs(1_100),
            ),
            &mut [None; 2],
        )
        .unwrap();
    let killed_reactor = TestReactor::new(killed_engine);
    let killed_recovery = NativeLiveCheckpoint {
        phase: NativeLivePhase::KilledRecovery,
        ..base
    };
    assert_eq!(
        NativeLiveCoordinator::from_checkpoint(
            killed_recovery,
            4,
            MONOTONIC_CLOCK_EPOCH,
            &killed_reactor,
            &mut verifier,
        ),
        Err(NativeLiveRecoveryError::Checkpoint(
            NativeLiveCheckpointError::ReplayStateUnbound {
                phase: NativeLivePhase::KilledRecovery,
            }
        ))
    );
    assert_eq!(verifier.calls, 4);
}

#[test]
fn process_event_identity_mismatch_preserves_every_owner_and_ordinal() {
    let (mut reactor, source_event) = prepared_quote_reactor();
    let (reactor_before, expected_source_event) = prepared_quote_reactor();
    assert_eq!(source_event, expected_source_event);
    let (mut session, mut adapter) = live_session();
    let session_before = session;
    let adapter_before = adapter;
    let operations = FixedOperationLog::new();
    let mut transport = FixedTransport::new(&operations, [sent(9_001, 2_010), sent(9_002, 2_020)]);
    let mut audit = FixedAudit::new(&operations);
    let audit_capture_before = audit.next_appended_capture;
    let audit_frame_before = audit.next_frame_ordinal;
    let mut scratch = NativeLiveScratch::<64>::new();
    let mut coordinator = NativeLiveCoordinator::new(
        OTHER_IDENTITY,
        instrument_definition(),
        OTHER_MARKET_DATA_SOURCE,
        OTHER_ORDER_ENTRY_SOURCE,
        MONOTONIC_CLOCK_EPOCH,
        FIRST_CAPTURE_ORDINAL,
        FIRST_COMMIT_ORDINAL,
    )
    .unwrap();
    let coordinator_before = coordinator;

    assert_eq!(
        coordinator.process_event(
            source_event,
            MonotonicTimestampNs(2_000),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        ),
        Err(NativeLiveError::VenueIdentityMismatch {
            expected: OTHER_IDENTITY,
            session: IDENTITY,
            adapter: IDENTITY,
            engine_venue: IDENTITY.venue,
        })
    );

    assert_eq!(coordinator, coordinator_before);
    assert!(reactor.deterministic_state_eq(&reactor_before));
    assert_eq!(session, session_before);
    assert_eq!(adapter, adapter_before);
    assert_eq!(audit.next_appended_capture, audit_capture_before);
    assert_eq!(audit.next_frame_ordinal, audit_frame_before);
    audit.assert_untouched();
    assert_eq!(transport.submit_count, 0);
    assert_eq!(transport.quiesce_count, 0);
    assert!(transport.contexts.iter().all(Option::is_none));
    assert!(scratch.is_clean());
}

#[test]
fn process_event_reference_data_mismatch_precedes_reservation_and_mutation() {
    let (mut reactor, source_event) = prepared_quote_reactor();
    let (reactor_before, expected_source_event) = prepared_quote_reactor();
    assert_eq!(source_event, expected_source_event);
    let mut changed_definition = instrument_definition();
    changed_definition.maximum_price = PriceTicks(i64::MAX - 1);
    let (mut session, mut adapter) = live_session_with_definition(changed_definition);
    let session_before = session;
    let adapter_before = adapter;
    let operations = FixedOperationLog::new();
    let mut transport = FixedTransport::new(&operations, [sent(9_001, 2_010), sent(9_002, 2_020)]);
    let mut audit = FixedAudit::new(&operations);
    let audit_capture_before = audit.next_appended_capture;
    let audit_frame_before = audit.next_frame_ordinal;
    let mut scratch = NativeLiveScratch::<64>::new();
    let mut coordinator = coordinator();
    let coordinator_before = coordinator;

    assert_eq!(
        coordinator.process_event(
            source_event,
            MonotonicTimestampNs(2_000),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        ),
        Err(NativeLiveError::InstrumentDefinitionMismatch {
            expected: instrument_definition().binding(),
            session: changed_definition.binding(),
            engine: instrument_definition().binding(),
            session_engine_rules_equal: false,
        })
    );

    assert_eq!(coordinator, coordinator_before);
    assert!(reactor.deterministic_state_eq(&reactor_before));
    assert_eq!(session, session_before);
    assert_eq!(adapter, adapter_before);
    assert_eq!(audit.next_appended_capture, audit_capture_before);
    assert_eq!(audit.next_frame_ordinal, audit_frame_before);
    audit.assert_untouched();
    assert_eq!(transport.submit_count, 0);
    assert_eq!(transport.quiesce_count, 0);
    assert!(transport.contexts.iter().all(Option::is_none));
    assert!(scratch.is_clean());
}

#[test]
fn process_event_source_route_mismatches_precede_reservation_and_mutation() {
    let (_, valid_event) = prepared_quote_reactor();

    let mut wrong_venue = valid_event;
    wrong_venue.header.venue = OTHER_VENUE_IDENTITY.venue;
    assert_source_route_rejected(
        wrong_venue,
        NativeLiveError::SourceRouteMismatch {
            expected_source: MARKET_DATA_SOURCE,
            actual_source: MARKET_DATA_SOURCE,
            expected_venue: IDENTITY.venue,
            actual_venue: OTHER_VENUE_IDENTITY.venue,
        },
    );

    let mut wrong_protocol = valid_event;
    wrong_protocol.source.id.protocol = 999;
    assert_source_route_rejected(
        wrong_protocol,
        NativeLiveError::SourceRouteMismatch {
            expected_source: MARKET_DATA_SOURCE,
            actual_source: wrong_protocol.source,
            expected_venue: IDENTITY.venue,
            actual_venue: IDENTITY.venue,
        },
    );

    let mut wrong_domain = valid_event;
    wrong_domain.source.sequence_domain = SequenceDomain::OrderEntry;
    assert_source_route_rejected(
        wrong_domain,
        NativeLiveError::SourceRouteMismatch {
            expected_source: ORDER_ENTRY_SOURCE,
            actual_source: wrong_domain.source,
            expected_venue: IDENTITY.venue,
            actual_venue: IDENTITY.venue,
        },
    );

    let mut wrong_channel = valid_event;
    wrong_channel.source.id.channel = 2;
    assert_source_route_rejected(
        wrong_channel,
        NativeLiveError::SourceRouteMismatch {
            expected_source: MARKET_DATA_SOURCE,
            actual_source: wrong_channel.source,
            expected_venue: IDENTITY.venue,
            actual_venue: IDENTITY.venue,
        },
    );

    let mut wrong_epoch = valid_event;
    wrong_epoch.source.session_epoch = SessionEpoch(2);
    assert_source_route_rejected(
        wrong_epoch,
        NativeLiveError::SourceRouteMismatch {
            expected_source: MARKET_DATA_SOURCE,
            actual_source: wrong_epoch.source,
            expected_venue: IDENTITY.venue,
            actual_venue: IDENTITY.venue,
        },
    );
}

#[test]
fn configured_market_data_order_entry_and_local_routes_are_accepted() {
    let market_event = market_event(
        FIRST_CAPTURE_ORDINAL,
        MarketDataMessage {
            sequence: Sequence(100),
            exchange_timestamp: TimestampNs(1_080),
            hardware_receive_timestamp: TimestampNs(1_090),
            instrument: InstrumentId(9),
            payload: MarketDataPayload::Book(BookDelta::Add {
                order_id: quant_hft_core::MarketByOrderId(9_000),
                side: Side::Buy,
                price: PriceTicks(99),
                quantity: Quantity(100),
            }),
        },
    );
    assert_valid_source_route(TestReactor::new(ready_engine()), market_event);

    let order_entry_event = normalize_order_entry(
        VenueCaptureMetadata {
            venue: IDENTITY.venue,
            source: ORDER_ENTRY_SOURCE,
            capture_ordinal: FIRST_CAPTURE_ORDINAL,
            monotonic_timestamp: MonotonicTimestampNs(1_100),
            recovery: false,
        },
        InboundMessage {
            sequence: Sequence(2),
            exchange_timestamp: TimestampNs(1_080),
            hardware_receive_timestamp: TimestampNs(1_090),
            payload: InboundPayload::Session(SessionEvent::Heartbeat),
        },
    )
    .unwrap();
    assert_valid_source_route(TestReactor::new(ready_engine()), order_entry_event);

    let local_event = normalize_timer(
        FIRST_CAPTURE_ORDINAL,
        TimerInput {
            timer_id: TimerId(1),
            action: TimerAction::ControlLivenessCheck,
            scheduled_at: MonotonicTimestampNs(1_050),
            fired_at: MonotonicTimestampNs(1_100),
        },
    )
    .unwrap();
    assert_valid_source_route(TestReactor::new(ready_engine()), local_event);
}

#[test]
fn process_event_engine_venue_mismatch_precedes_reservation_and_mutation() {
    let (mut reactor, source_event) =
        prepared_quote_reactor_for_engine_venue(OTHER_VENUE_IDENTITY.venue);
    let (reactor_before, expected_source_event) =
        prepared_quote_reactor_for_engine_venue(OTHER_VENUE_IDENTITY.venue);
    assert_eq!(source_event, expected_source_event);
    let (mut session, mut adapter) = live_session();
    let session_before = session;
    let adapter_before = adapter;
    let operations = FixedOperationLog::new();
    let mut transport = FixedTransport::new(&operations, [sent(9_011, 2_010), sent(9_012, 2_020)]);
    let mut audit = FixedAudit::new(&operations);
    let mut scratch = NativeLiveScratch::<64>::new();
    let mut coordinator = coordinator();
    let coordinator_before = coordinator;

    assert_eq!(
        coordinator.process_event(
            source_event,
            MonotonicTimestampNs(2_000),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        ),
        Err(NativeLiveError::VenueIdentityMismatch {
            expected: IDENTITY,
            session: IDENTITY,
            adapter: IDENTITY,
            engine_venue: OTHER_VENUE_IDENTITY.venue,
        })
    );

    assert_eq!(coordinator, coordinator_before);
    assert!(reactor.deterministic_state_eq(&reactor_before));
    assert_eq!(session, session_before);
    assert_eq!(adapter, adapter_before);
    audit.assert_untouched();
    assert_eq!(transport.submit_count, 0);
    assert_eq!(transport.quiesce_count, 0);
    assert!(transport.contexts.iter().all(Option::is_none));
    assert!(scratch.is_clean());
}

#[test]
fn drive_safety_adapter_mismatch_never_routes_cancels_to_wrong_identity() {
    let (mut reactor, mut session, adapter, mut coordinator) = prepared_safety_pending();
    let (reactor_before, session_before, adapter_before, coordinator_before) =
        prepared_safety_pending();
    assert_eq!(session, session_before);
    assert_eq!(adapter, adapter_before);
    assert_eq!(coordinator, coordinator_before);
    let mut adapter = MismatchedVenueAdapter { inner: adapter };
    let mismatched_adapter_before = adapter;
    let operations = FixedOperationLog::new();
    let mut transport = FixedTransport::new(&operations, [sent(9_021, 3_010), sent(9_022, 3_020)]);
    let mut audit = FixedAudit::new_at(&operations, CaptureOrdinal(7), 92);
    let audit_capture_before = audit.next_appended_capture;
    let audit_frame_before = audit.next_frame_ordinal;
    let mut scratch = NativeLiveScratch::<64>::new();

    assert_eq!(
        coordinator.drive_safety(
            MonotonicTimestampNs(3_000),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        ),
        Err(NativeLiveError::VenueIdentityMismatch {
            expected: IDENTITY,
            session: IDENTITY,
            adapter: OTHER_IDENTITY,
            engine_venue: IDENTITY.venue,
        })
    );

    assert_eq!(coordinator, coordinator_before);
    assert!(reactor.deterministic_state_eq(&reactor_before));
    assert!(reactor.mandatory_kill_pending());
    assert_eq!(session, session_before);
    assert_eq!(adapter, mismatched_adapter_before);
    assert_eq!(audit.next_appended_capture, audit_capture_before);
    assert_eq!(audit.next_frame_ordinal, audit_frame_before);
    audit.assert_untouched();
    assert_eq!(transport.submit_count, 0);
    assert_eq!(transport.quiesce_count, 0);
    assert!(transport.contexts.iter().all(Option::is_none));
    assert!(scratch.is_clean());
}

#[test]
fn composed_native_live_paths_perform_no_heap_allocations() {
    let _guard = ALLOCATION_TEST_LOCK
        .lock()
        .expect("native-live allocation test lock");
    assert_eq!(tracked_allocations(|| {}), 0, "allocation tracker warmup");

    let (mut sent_reactor, sent_event) = prepared_quote_reactor();
    let (mut sent_session, mut sent_adapter) = live_session();
    let sent_operations = FixedOperationLog::new();
    let mut sent_transport =
        FixedTransport::new(&sent_operations, [sent(1_001, 2_010), sent(1_002, 2_020)]);
    let mut sent_audit = FixedAudit::new(&sent_operations);
    let mut sent_scratch = NativeLiveScratch::<64>::new();
    let mut sent_coordinator = coordinator();

    let (mut unsent_reactor, unsent_event) = prepared_quote_reactor();
    let (mut unsent_session, mut unsent_adapter) = live_session();
    let unsent_operations = FixedOperationLog::new();
    let mut unsent_transport = FixedTransport::new(
        &unsent_operations,
        [proven_unsent(1_003, 2_010), sent(1_004, 2_020)],
    );
    let mut unsent_audit = FixedAudit::new(&unsent_operations);
    let mut unsent_scratch = NativeLiveScratch::<64>::new();
    let mut unsent_coordinator = coordinator();

    let (mut encode_reactor, encode_event) = prepared_quote_reactor();
    let (mut encode_session, mut encode_adapter) = live_session();
    let encode_operations = FixedOperationLog::new();
    let mut encode_transport =
        FixedTransport::new(&encode_operations, [sent(1_005, 2_010), sent(1_006, 2_020)]);
    let mut encode_audit = FixedAudit::new(&encode_operations);
    let mut encode_scratch = NativeLiveScratch::<8>::new();
    let mut encode_coordinator = coordinator();

    let mut sent_result = None;
    let sent_allocations = tracked_allocations(|| {
        sent_result = Some(sent_coordinator.process_event(
            sent_event,
            MonotonicTimestampNs(2_000),
            &mut sent_reactor,
            &mut sent_session,
            &mut sent_adapter,
            &mut sent_transport,
            &mut sent_audit,
            &mut sent_scratch,
        ));
    });

    let mut unsent_result = None;
    let unsent_allocations = tracked_allocations(|| {
        unsent_result = Some(unsent_coordinator.process_event(
            unsent_event,
            MonotonicTimestampNs(2_000),
            &mut unsent_reactor,
            &mut unsent_session,
            &mut unsent_adapter,
            &mut unsent_transport,
            &mut unsent_audit,
            &mut unsent_scratch,
        ));
    });

    let mut encode_result = None;
    let encode_allocations = tracked_allocations(|| {
        encode_result = Some(encode_coordinator.process_event(
            encode_event,
            MonotonicTimestampNs(2_000),
            &mut encode_reactor,
            &mut encode_session,
            &mut encode_adapter,
            &mut encode_transport,
            &mut encode_audit,
            &mut encode_scratch,
        ));
    });

    assert!(matches!(
        sent_result.unwrap().unwrap(),
        NativeLiveStatus::Completed(quant_hft_core::NativeLiveSummary {
            commands: 2,
            sent: 2,
            proven_unsent: 0,
            ..
        })
    ));
    assert!(matches!(
        unsent_result.unwrap().unwrap(),
        NativeLiveStatus::Completed(quant_hft_core::NativeLiveSummary {
            commands: 2,
            sent: 1,
            proven_unsent: 1,
            ..
        })
    ));
    assert!(matches!(
        encode_result.unwrap().unwrap(),
        NativeLiveStatus::SafetyPending {
            reason: NativeLiveSafetyReason::Encode(_),
        }
    ));
    assert_eq!(sent_allocations, 0, "all-Sent coordinator path allocated");
    assert_eq!(
        unsent_allocations, 0,
        "ProvenUnsent coordinator path allocated"
    );
    assert_eq!(
        encode_allocations, 0,
        "local encode-fault coordinator path allocated"
    );
    assert!(sent_scratch.is_clean());
    assert!(unsent_scratch.is_clean());
    assert!(encode_scratch.is_clean());
}

#[test]
fn two_command_sent_is_fifo_audited_and_feedback_is_immediate_priority() {
    let (mut reactor, source_event) = prepared_quote_reactor();
    let (mut session, mut adapter) = live_session();
    let operations = FixedOperationLog::new();
    let submissions = [sent(11, 2_010), sent(12, 2_020)];
    let mut transport = FixedTransport::new(&operations, submissions);
    let mut audit = FixedAudit::new(&operations);
    let mut scratch = NativeLiveScratch::<64>::new();
    let mut coordinator = coordinator();

    let status = coordinator
        .process_event(
            source_event,
            MonotonicTimestampNs(2_000),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        )
        .unwrap();

    assert_eq!(
        status,
        NativeLiveStatus::Completed(quant_hft_core::NativeLiveSummary {
            source_commit_ordinal: FIRST_COMMIT_ORDINAL,
            commands: 2,
            sent: 2,
            proven_unsent: 0,
        })
    );
    assert_eq!(coordinator.phase(), NativeLivePhase::Ready);
    assert_eq!(coordinator.expected_identity(), IDENTITY);
    assert_eq!(coordinator.checkpoint().expected_identity, IDENTITY);
    assert_eq!(
        coordinator.last_source_capture_ordinal(),
        Some(CaptureOrdinal(2))
    );
    assert_eq!(
        coordinator.last_feedback_capture_ordinal(),
        Some(CaptureOrdinal(4))
    );
    assert_eq!(coordinator.last_outbound_frame_ordinal(), Some(91));
    assert_eq!(coordinator.next_commit_ordinal(), 53);
    assert_eq!(reactor.outstanding_transmissions(), 0);
    assert_eq!(reactor.counters().transmissions_processed, 2);
    assert_eq!(reactor.counters().transmissions_sent, 2);
    assert_eq!(reactor.counters().transmissions_proven_unsent, 0);
    assert_eq!(session.next_outbound(), Sequence(702));
    assert!(!adapter.dirty_input_seen);
    assert!(scratch.is_clean());
    assert_eq!(transport.submit_count, 2);
    assert_eq!(transport.quiesce_count, 0);
    assert_eq!(audit.commit_count, 3);
    assert_eq!(audit.intent_count, 2);
    assert_eq!(audit.egress_count, 2);
    assert_eq!(audit.transmission_count, 2);
    assert_eq!(audit.finish_count, 1);
    assert_eq!(audit.abort_count, 0);

    let source_commit = audit.commits[0].unwrap();
    source_commit.verify_source(source_event).unwrap();
    assert_eq!(source_commit.commit_ordinal, FIRST_COMMIT_ORDINAL);
    assert_eq!(source_commit.route, SchedulerRoute::Normal);
    assert_eq!(source_commit.capture_ordinal, FIRST_CAPTURE_ORDINAL);
    assert_eq!(source_commit.egress_input_ordinal, Some(InputOrdinal(2)));
    assert_eq!(source_commit.commands.iter().flatten().count(), 2);

    for index in 0..2 {
        let context = transport.contexts[index].unwrap();
        let command = source_commit.commands[index].unwrap();
        assert_eq!(context.frame_ordinal, FIRST_FRAME_ORDINAL + index as u64);
        assert_eq!(context.adapter_identity, IDENTITY);
        assert_eq!(context.venue_sequence, Sequence(700 + index as u64));
        assert_eq!(context.scheduler_commit_ordinal, FIRST_COMMIT_ORDINAL);
        assert_eq!(context.scheduler_capture_ordinal, FIRST_CAPTURE_ORDINAL);
        assert_eq!(
            context.scheduler_source_event_crc32c,
            source_commit.source_event_crc32c
        );
        assert_eq!(context.egress.input_ordinal, InputOrdinal(2));
        assert_eq!(usize::from(context.egress.command_index), index);
        assert_eq!(context.egress.command, command);
        assert_eq!(context.encoded_len, WIRE_LEN);
        assert_eq!(read_u64(context.encoded(), 1), 700 + index as u64);
        assert_eq!(audit.intents[index], Some(context));
        assert_eq!(audit.egress[index].unwrap().context, context);
        assert_eq!(audit.egress[index].unwrap().proof, 11 + index as u64);
        assert_eq!(
            audit.egress[index].unwrap().disposition,
            NativeSubmitDisposition::Sent
        );
    }

    assert_feedback(
        &audit,
        0,
        CaptureOrdinal(3),
        source_commit.commands[0].unwrap(),
        TransmissionStatus::Sent,
        MonotonicTimestampNs(2_010),
        51,
    );
    assert_feedback(
        &audit,
        1,
        CaptureOrdinal(4),
        source_commit.commands[1].unwrap(),
        TransmissionStatus::Sent,
        MonotonicTimestampNs(2_020),
        52,
    );
    operations.assert_exact(&[
        OP_RESERVE,
        OP_SOURCE,
        OP_COMMIT,
        OP_INTENT,
        OP_SUBMIT,
        OP_EGRESS,
        OP_TRANSMISSION,
        OP_COMMIT,
        OP_INTENT,
        OP_SUBMIT,
        OP_EGRESS,
        OP_TRANSMISSION,
        OP_COMMIT,
        OP_FINISH,
    ]);
}

#[test]
fn native_frame_ordinal_gaps_are_accepted_and_preserved_in_fifo_order() {
    let (mut reactor, source_event) = prepared_quote_reactor();
    let (mut session, mut adapter) = live_session();
    let operations = FixedOperationLog::new();
    let mut transport = FixedTransport::new(&operations, [sent(13, 2_010), sent(14, 2_020)]);
    let mut audit = FixedAudit::new(&operations);
    audit.frame_step = 2;
    let mut scratch = NativeLiveScratch::<64>::new();
    let mut coordinator = coordinator();

    let status = coordinator
        .process_event(
            source_event,
            MonotonicTimestampNs(2_000),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        )
        .unwrap();

    assert!(matches!(
        status,
        NativeLiveStatus::Completed(quant_hft_core::NativeLiveSummary {
            commands: 2,
            sent: 2,
            proven_unsent: 0,
            ..
        })
    ));
    assert_eq!(
        transport
            .contexts
            .map(|context| context.unwrap().frame_ordinal),
        [90, 92]
    );
    assert_eq!(audit.intents, transport.contexts);
    assert_eq!(coordinator.last_outbound_frame_ordinal(), Some(92));
    assert_eq!(transport.submit_count, 2);
    assert_eq!(transport.quiesce_count, 0);
    assert_eq!(reactor.outstanding_transmissions(), 0);
    assert!(scratch.is_clean());
}

#[test]
fn invalid_first_native_frame_ordinal_fails_closed_before_submit() {
    for invalid in [0, u64::MAX] {
        let (mut reactor, source_event) = prepared_quote_reactor();
        let (mut session, mut adapter) = live_session();
        let session_before = session;
        let adapter_before = adapter;
        let operations = FixedOperationLog::new();
        let mut transport = FixedTransport::new(&operations, [sent(13, 2_010), sent(14, 2_020)]);
        let mut audit = FixedAudit::new(&operations);
        audit.next_frame_ordinal = invalid;
        let mut scratch = NativeLiveScratch::<64>::new();
        let mut coordinator = coordinator();

        assert_eq!(
            coordinator.process_event(
                source_event,
                MonotonicTimestampNs(2_000),
                &mut reactor,
                &mut session,
                &mut adapter,
                &mut transport,
                &mut audit,
                &mut scratch,
            ),
            Err(NativeLiveError::InvalidNativeFrameOrdinal {
                previous_outbound: None,
                actual: invalid,
            })
        );

        assert_eq!(coordinator.phase(), NativeLivePhase::Ambiguous);
        assert_eq!(coordinator.last_outbound_frame_ordinal(), None);
        assert_eq!(audit.sealed_checkpoints[0], Some(coordinator.checkpoint()));
        assert_eq!(session, session_before);
        assert_eq!(adapter, adapter_before);
        assert_eq!(transport.submit_count, 0);
        assert_eq!(transport.quiesce_count, 1);
        assert_eq!(audit.intent_count, 1);
        assert_eq!(audit.egress_count, 0);
        assert_eq!(audit.transmission_count, 0);
        assert_eq!(audit.commit_count, 1);
        assert_eq!(reactor.outstanding_transmissions(), 2);
        assert!(reactor.mandatory_kill_pending());
        assert!(scratch.is_clean());
        operations.assert_exact(&[
            OP_RESERVE, OP_SOURCE, OP_COMMIT, OP_INTENT, OP_QUIESCE, OP_FINISH,
        ]);
    }
}

#[test]
fn regressed_native_frame_ordinal_fails_closed_without_second_submit() {
    let (mut reactor, source_event) = prepared_quote_reactor();
    let (mut session, mut adapter) = live_session();
    let operations = FixedOperationLog::new();
    let mut transport = FixedTransport::new(&operations, [sent(13, 2_010), sent(14, 2_020)]);
    let mut audit = FixedAudit::new(&operations);
    audit.frame_step = 0;
    let mut scratch = NativeLiveScratch::<64>::new();
    let mut coordinator = coordinator();

    assert_eq!(
        coordinator.process_event(
            source_event,
            MonotonicTimestampNs(2_000),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        ),
        Err(NativeLiveError::InvalidNativeFrameOrdinal {
            previous_outbound: Some(FIRST_FRAME_ORDINAL),
            actual: FIRST_FRAME_ORDINAL,
        })
    );

    assert_eq!(coordinator.phase(), NativeLivePhase::Ambiguous);
    assert_eq!(
        coordinator.last_outbound_frame_ordinal(),
        Some(FIRST_FRAME_ORDINAL)
    );
    assert_eq!(
        coordinator.last_feedback_capture_ordinal(),
        Some(CaptureOrdinal(3))
    );
    assert_eq!(audit.sealed_checkpoints[0], Some(coordinator.checkpoint()));
    assert_eq!(session.next_outbound(), Sequence(701));
    assert_eq!(adapter.codec_state, 2);
    assert_eq!(transport.submit_count, 1);
    assert_eq!(transport.quiesce_count, 1);
    assert_eq!(audit.intent_count, 2);
    assert_eq!(audit.egress_count, 1);
    assert_eq!(audit.transmission_count, 1);
    assert_eq!(audit.commit_count, 2);
    assert_eq!(reactor.outstanding_transmissions(), 1);
    assert!(reactor.mandatory_kill_pending());
    assert!(scratch.is_clean());
    operations.assert_exact(&[
        OP_RESERVE,
        OP_SOURCE,
        OP_COMMIT,
        OP_INTENT,
        OP_SUBMIT,
        OP_EGRESS,
        OP_TRANSMISSION,
        OP_COMMIT,
        OP_INTENT,
        OP_QUIESCE,
        OP_FINISH,
    ]);
}

#[test]
fn queued_source_can_follow_overtaking_feedback_while_raw_journal_stays_capture_sorted() {
    let mut reactor = prepared_live_orders_reactor_for_control();
    let source_two = normalize_control_decision(
        CaptureOrdinal(2),
        support::authenticated_kill(1, ConfigDigest([0xA5; 32]), Sequence(1), TimestampNs(1_100)),
    )
    .unwrap();
    let source_three = normalize_timer(
        CaptureOrdinal(3),
        TimerInput {
            timer_id: TimerId(1),
            action: TimerAction::KillCancelSweep,
            scheduled_at: MonotonicTimestampNs(1_100),
            fired_at: MonotonicTimestampNs(2_015),
        },
    )
    .unwrap();
    let (mut session, mut adapter) = live_session();
    let first_operations = FixedOperationLog::new();
    let mut first_transport =
        FixedTransport::new(&first_operations, [sent(15, 2_010), sent(16, 2_015)]);
    // Source three already owns global capture ordinal 3 before source two is
    // applied, so immediate feedback is sequenced at the authoritative tail 4/5.
    let mut first_audit =
        FixedAudit::new_at(&first_operations, CaptureOrdinal(4), FIRST_FRAME_ORDINAL);
    first_audit.sequencer_monotonic = MonotonicTimestampNs(2_015);
    let mut scratch = NativeLiveScratch::<64>::new();
    let mut coordinator = coordinator();

    let first = coordinator
        .process_event(
            source_two,
            MonotonicTimestampNs(2_000),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut first_transport,
            &mut first_audit,
            &mut scratch,
        )
        .unwrap();
    assert!(matches!(
        first,
        NativeLiveStatus::Completed(quant_hft_core::NativeLiveSummary {
            commands: 2,
            sent: 2,
            proven_unsent: 0,
            ..
        })
    ));
    assert_eq!(
        first_audit
            .transmissions
            .map(|event| event.unwrap().capture_ordinal),
        [CaptureOrdinal(4), CaptureOrdinal(5)]
    );
    assert_eq!(
        first_audit
            .transmissions
            .map(|event| event.unwrap().monotonic_timestamp),
        [MonotonicTimestampNs(2_015); 2]
    );
    assert_eq!(
        reactor.engine().last_applied_monotonic(),
        Some(MonotonicTimestampNs(2_015))
    );

    let second_operations = FixedOperationLog::new();
    let mut second_transport =
        FixedTransport::new(&second_operations, [sent(17, 2_040), sent(18, 2_050)]);
    let mut second_audit = FixedAudit::new_at(&second_operations, CaptureOrdinal(6), 92);
    let second = coordinator
        .process_event(
            source_three,
            MonotonicTimestampNs(2_020),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut second_transport,
            &mut second_audit,
            &mut scratch,
        )
        .unwrap();
    assert_eq!(
        second,
        NativeLiveStatus::Completed(quant_hft_core::NativeLiveSummary {
            source_commit_ordinal: 53,
            commands: 0,
            sent: 0,
            proven_unsent: 0,
        })
    );
    assert_eq!(second_transport.submit_count, 0);
    assert_eq!(
        reactor.engine().last_applied_monotonic(),
        Some(MonotonicTimestampNs(2_015))
    );
    assert_eq!(
        [
            first_audit.commits[0].unwrap().capture_ordinal,
            first_audit.commits[1].unwrap().capture_ordinal,
            first_audit.commits[2].unwrap().capture_ordinal,
            second_audit.commits[0].unwrap().capture_ordinal,
        ],
        [
            CaptureOrdinal(2),
            CaptureOrdinal(4),
            CaptureOrdinal(5),
            CaptureOrdinal(3),
        ]
    );
    assert_eq!(
        coordinator.last_source_capture_ordinal(),
        Some(CaptureOrdinal(3))
    );
    assert_eq!(
        coordinator.last_feedback_capture_ordinal(),
        Some(CaptureOrdinal(5))
    );
    assert_eq!(coordinator.next_commit_ordinal(), 54);

    let raw_capture_order = [
        source_two,
        source_three,
        first_audit.transmissions[0].unwrap(),
        first_audit.transmissions[1].unwrap(),
    ];
    assert_eq!(
        raw_capture_order.map(|event| event.capture_ordinal),
        [
            CaptureOrdinal(2),
            CaptureOrdinal(3),
            CaptureOrdinal(4),
            CaptureOrdinal(5),
        ]
    );
    let mut journal = [0_u8; RECORD_LEN * 4];
    for (index, event) in raw_capture_order.into_iter().enumerate() {
        let offset = index * RECORD_LEN;
        assert_eq!(
            encode_record(event, &mut journal[offset..offset + RECORD_LEN]),
            Ok(RECORD_LEN)
        );
    }
    let replay = replay_bytes::<4>(&journal, Sequence(2)).unwrap();
    assert_eq!(replay.records, 4);
    assert_eq!(replay.last_capture_ordinal, CaptureOrdinal(5));
    assert!(scratch.is_clean());
    second_operations.assert_exact(&[OP_RESERVE, OP_SOURCE, OP_COMMIT, OP_FINISH]);
}

#[test]
fn proven_unsent_restores_venue_state_but_consumes_exact_fifo_slot() {
    let (mut reactor, source_event) = prepared_quote_reactor();
    let (mut session, mut adapter) = live_session();
    let operations = FixedOperationLog::new();
    let submissions = [proven_unsent(21, 2_010), sent(22, 2_020)];
    let mut transport = FixedTransport::new(&operations, submissions);
    let mut audit = FixedAudit::new(&operations);
    let mut scratch = NativeLiveScratch::<64>::new();
    let mut coordinator = coordinator();

    let status = coordinator
        .process_event(
            source_event,
            MonotonicTimestampNs(2_000),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        )
        .unwrap();

    assert_eq!(
        status,
        NativeLiveStatus::Completed(quant_hft_core::NativeLiveSummary {
            source_commit_ordinal: FIRST_COMMIT_ORDINAL,
            commands: 2,
            sent: 1,
            proven_unsent: 1,
        })
    );
    let source_commit = audit.commits[0].unwrap();
    let first = transport.contexts[0].unwrap();
    let second = transport.contexts[1].unwrap();
    assert_eq!(first.egress.command_index, 0);
    assert_eq!(second.egress.command_index, 1);
    assert_eq!(first.venue_sequence, Sequence(700));
    assert_eq!(second.venue_sequence, Sequence(700));
    assert_ne!(first.egress.command, second.egress.command);
    assert_eq!(session.next_outbound(), Sequence(701));
    assert_eq!(adapter.codec_state, 2);
    assert_eq!(adapter.durable_commits, 3);
    assert!(!adapter.dirty_input_seen);
    assert_eq!(reactor.outstanding_transmissions(), 0);
    assert_eq!(reactor.counters().transmissions_proven_unsent, 1);
    assert_eq!(reactor.counters().transmissions_sent, 1);
    assert_feedback(
        &audit,
        0,
        CaptureOrdinal(3),
        source_commit.commands[0].unwrap(),
        TransmissionStatus::ProvenUnsent,
        MonotonicTimestampNs(2_010),
        51,
    );
    assert_feedback(
        &audit,
        1,
        CaptureOrdinal(4),
        source_commit.commands[1].unwrap(),
        TransmissionStatus::Sent,
        MonotonicTimestampNs(2_020),
        52,
    );
    assert_eq!(
        audit.egress[0].unwrap().disposition,
        NativeSubmitDisposition::ProvenUnsent
    );
    assert_eq!(
        audit.egress[1].unwrap().disposition,
        NativeSubmitDisposition::Sent
    );
    assert_eq!(audit.intents, transport.contexts);
    assert!(scratch.is_clean());
    operations.assert_exact(&[
        OP_RESERVE,
        OP_SOURCE,
        OP_COMMIT,
        OP_INTENT,
        OP_SUBMIT,
        OP_EGRESS,
        OP_TRANSMISSION,
        OP_COMMIT,
        OP_INTENT,
        OP_SUBMIT,
        OP_EGRESS,
        OP_TRANSMISSION,
        OP_COMMIT,
        OP_FINISH,
    ]);
}

#[test]
fn ambiguous_submit_quiesces_once_never_reuses_sequence_and_fail_latches() {
    let (mut reactor, source_event) = prepared_quote_reactor();
    let (mut session, mut adapter) = live_session();
    let operations = FixedOperationLog::new();
    let submissions = [ambiguous(31, 2_010), sent(32, 2_020)];
    let mut transport = FixedTransport::new(&operations, submissions);
    let mut audit = FixedAudit::new(&operations);
    let mut scratch = NativeLiveScratch::<64>::new();
    let mut coordinator = coordinator();

    let status = coordinator
        .process_event(
            source_event,
            MonotonicTimestampNs(2_000),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        )
        .unwrap();

    let first_context = transport.contexts[0].unwrap();
    assert_eq!(
        status,
        NativeLiveStatus::Ambiguous {
            frame_ordinal: FIRST_FRAME_ORDINAL,
            egress: first_context.egress,
        }
    );
    assert_eq!(coordinator.phase(), NativeLivePhase::Ambiguous);
    assert_eq!(audit.sealed_checkpoints[0], Some(coordinator.checkpoint()));
    assert_eq!(
        coordinator.last_source_capture_ordinal(),
        Some(CaptureOrdinal(2))
    );
    assert_eq!(coordinator.last_feedback_capture_ordinal(), None);
    assert_eq!(coordinator.last_outbound_frame_ordinal(), Some(90));
    assert_eq!(coordinator.next_commit_ordinal(), 51);
    assert_eq!(transport.submit_count, 1);
    assert_eq!(transport.quiesce_count, 1);
    assert_eq!(first_context.venue_sequence, Sequence(700));
    assert_eq!(session.next_outbound(), Sequence(701));
    assert_eq!(adapter.codec_state, 2);
    assert_eq!(adapter.durable_commits, 3);
    assert_eq!(reactor.outstanding_transmissions(), 2);
    assert!(reactor.mandatory_kill_pending());
    assert_eq!(reactor.counters().transmissions_processed, 0);
    assert_eq!(audit.commit_count, 1);
    assert_eq!(audit.intent_count, 1);
    assert_eq!(audit.egress_count, 0);
    assert_eq!(audit.proof_fault_count, 1);
    assert_eq!(audit.transmission_count, 0);
    assert_eq!(audit.finish_count, 1);
    assert_eq!(audit.abort_count, 0);
    let proof_fault = audit.proof_faults[0].unwrap();
    assert_eq!(proof_fault.context, first_context);
    assert_eq!(proof_fault.proof, 31);
    assert_eq!(
        proof_fault.claimed_disposition,
        NativeSubmitDisposition::Ambiguous
    );
    assert_eq!(proof_fault.fault, NativeLiveProofFault::Ambiguous);
    assert_eq!(transport.verify_attempts, 1);
    assert_eq!(transport.verifier_state, 0);
    assert_eq!(transport.verifier_commits, 0);
    assert_eq!(transport.verifier_restores, 1);
    assert_eq!(audit.intents[0], transport.contexts[0]);
    assert!(scratch.is_clean());
    operations.assert_exact(&[
        OP_RESERVE,
        OP_SOURCE,
        OP_COMMIT,
        OP_INTENT,
        OP_SUBMIT,
        OP_QUIESCE,
        OP_PROOF_FAULT,
        OP_FINISH,
    ]);

    assert_eq!(
        coordinator.process_event(
            source_event,
            MonotonicTimestampNs(2_001),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        ),
        Err(NativeLiveError::Phase(NativeLivePhase::Ambiguous))
    );
    assert_eq!(transport.submit_count, 1);
    assert_eq!(transport.quiesce_count, 1);
    assert_eq!(audit.reserve_calls, 1);
    assert_eq!(session.next_outbound(), Sequence(701));
    assert!(scratch.is_clean());
}

#[test]
fn rejected_or_ambiguous_proven_unsent_proof_never_rolls_back_or_emits_feedback() {
    assert_unverified_proven_unsent_fails_closed(
        ProofMode::Rejected,
        NativeLiveProofFault::Rejected,
    );
    assert_unverified_proven_unsent_fails_closed(
        ProofMode::Ambiguous,
        NativeLiveProofFault::Ambiguous,
    );
}

#[test]
fn proof_status_or_timestamp_mismatch_never_accepts_transport_claim() {
    assert_unverified_proven_unsent_fails_closed(
        ProofMode::Verified(NativeTransmissionDisposition {
            status: TransmissionStatus::Sent,
            monotonic_now: MonotonicTimestampNs(2_010),
        }),
        NativeLiveProofFault::DispositionMismatch {
            claimed: NativeSubmitDisposition::ProvenUnsent,
            verified: NativeSubmitDisposition::Sent,
        },
    );
    assert_unverified_proven_unsent_fails_closed(
        ProofMode::Verified(NativeTransmissionDisposition {
            status: TransmissionStatus::ProvenUnsent,
            monotonic_now: MonotonicTimestampNs(2_011),
        }),
        NativeLiveProofFault::TimestampMismatch {
            claimed: MonotonicTimestampNs(2_010),
            verified: MonotonicTimestampNs(2_011),
        },
    );
}

fn assert_unverified_proven_unsent_fails_closed(
    proof_mode: ProofMode,
    expected_fault: NativeLiveProofFault,
) {
    let (mut reactor, source_event) = prepared_quote_reactor();
    let (mut session, mut adapter) = live_session();
    let operations = FixedOperationLog::new();
    let mut transport =
        FixedTransport::new(&operations, [proven_unsent(81, 2_010), sent(82, 2_020)])
            .with_proof_mode(proof_mode);
    let mut audit = FixedAudit::new(&operations);
    let mut scratch = NativeLiveScratch::<64>::new();
    let mut coordinator = coordinator();

    let status = coordinator
        .process_event(
            source_event,
            MonotonicTimestampNs(2_000),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        )
        .unwrap();

    let context = transport.contexts[0].unwrap();
    assert_eq!(
        status,
        NativeLiveStatus::Ambiguous {
            frame_ordinal: FIRST_FRAME_ORDINAL,
            egress: context.egress,
        }
    );
    assert_eq!(coordinator.phase(), NativeLivePhase::Ambiguous);
    assert_eq!(session.next_outbound(), Sequence(701));
    assert_eq!(adapter.codec_state, 2);
    assert_eq!(adapter.durable_commits, 3);
    assert_eq!(transport.submit_count, 1);
    assert_eq!(transport.quiesce_count, 1);
    assert_eq!(transport.verify_attempts, 1);
    assert_eq!(transport.verifier_state, 0);
    assert_eq!(transport.verifier_commits, 0);
    assert_eq!(transport.verifier_restores, 1);
    assert_eq!(reactor.outstanding_transmissions(), 2);
    assert!(reactor.mandatory_kill_pending());
    assert_eq!(reactor.counters().transmissions_processed, 0);
    assert_eq!(audit.egress_count, 0);
    assert_eq!(audit.proof_fault_count, 1);
    assert_eq!(audit.transmission_count, 0);
    let fault = audit.proof_faults[0].unwrap();
    assert_eq!(fault.context, context);
    assert_eq!(fault.proof, 81);
    assert_eq!(
        fault.claimed_disposition,
        NativeSubmitDisposition::ProvenUnsent
    );
    assert_eq!(fault.claimed_monotonic_now, MonotonicTimestampNs(2_010));
    assert_eq!(fault.fault, expected_fault);
    assert!(scratch.is_clean());
    operations.assert_exact(&[
        OP_RESERVE,
        OP_SOURCE,
        OP_COMMIT,
        OP_INTENT,
        OP_SUBMIT,
        OP_QUIESCE,
        OP_PROOF_FAULT,
        OP_FINISH,
    ]);
}

#[test]
fn audit_reservation_failure_precedes_source_mutation_and_requests_safety() {
    let (mut reactor, source_event) = prepared_quote_reactor();
    let (baseline_reactor, baseline_source) = prepared_quote_reactor();
    assert_eq!(source_event, baseline_source);
    let (mut session, mut adapter) = live_session();
    let session_before = session;
    let adapter_before = adapter;
    let operations = FixedOperationLog::new();
    let mut transport = FixedTransport::new(&operations, [sent(41, 2_010), sent(42, 2_020)]);
    let mut audit = FixedAudit::rejecting(&operations);
    let mut scratch = NativeLiveScratch::<64>::new();
    let mut coordinator = coordinator();

    let status = coordinator
        .process_event(
            source_event,
            MonotonicTimestampNs(2_000),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        )
        .unwrap();

    assert_eq!(
        status,
        NativeLiveStatus::SafetyPending {
            reason: NativeLiveSafetyReason::AuditReservation(AuditFailure::Capacity),
        }
    );
    assert!(
        reactor
            .engine()
            .deterministic_state_eq(baseline_reactor.engine())
    );
    assert!(reactor.mandatory_kill_pending());
    assert!(!reactor.has_retained_event());
    assert_eq!(reactor.outstanding_transmissions(), 0);
    assert_eq!(session, session_before);
    assert_eq!(adapter, adapter_before);
    assert_eq!(transport.submit_count, 0);
    assert_eq!(transport.quiesce_count, 0);
    assert_eq!(audit.reserve_calls, 1);
    assert_eq!(audit.commit_count, 0);
    assert_eq!(audit.intent_count, 0);
    assert_eq!(audit.finish_count, 0);
    assert_eq!(audit.abort_count, 0);
    assert_eq!(audit.emergency_seal_count, 1);
    assert_eq!(coordinator.phase(), NativeLivePhase::SafetyPending);
    assert_eq!(
        audit.emergency_seals[0],
        Some(NativeLiveEmergencySealRecord {
            operation: NativeLiveOperation::ProcessEvent,
            rejected_source: Some(source_event),
            local_monotonic_sample: MonotonicTimestampNs(2_000),
            error: AuditFailure::Capacity,
            checkpoint: coordinator.checkpoint(),
        })
    );
    assert_eq!(coordinator.last_source_capture_ordinal(), None);
    assert_eq!(coordinator.last_feedback_capture_ordinal(), None);
    assert_eq!(coordinator.last_outbound_frame_ordinal(), None);
    assert_eq!(coordinator.next_commit_ordinal(), FIRST_COMMIT_ORDINAL);
    assert!(scratch.is_clean());
    operations.assert_exact(&[OP_RESERVE, OP_EMERGENCY_SEAL]);
}

#[test]
fn undersized_encode_buffer_resolves_both_slots_proven_unsent_then_pends_safety() {
    let (mut reactor, source_event) = prepared_quote_reactor();
    let (mut session, mut adapter) = live_session();
    let session_before = session;
    let adapter_before = adapter;
    let operations = FixedOperationLog::new();
    let mut transport = FixedTransport::new(&operations, [sent(51, 2_010), sent(52, 2_020)]);
    let mut audit = FixedAudit::new(&operations);
    let mut scratch = NativeLiveScratch::<8>::new();
    let mut coordinator = coordinator();

    let status = coordinator
        .process_event(
            source_event,
            MonotonicTimestampNs(2_000),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        )
        .unwrap();

    assert_eq!(
        status,
        NativeLiveStatus::SafetyPending {
            reason: NativeLiveSafetyReason::Encode(NativeLiveEncodeFault::Venue(VenueError::Wire(
                WireError::BufferTooSmall {
                    required: WIRE_LEN,
                    provided: 8,
                }
            ))),
        }
    );
    assert_local_encode_fault_resolution(
        &reactor,
        &session,
        session_before,
        &adapter,
        adapter_before,
        &transport,
        &audit,
        &coordinator,
    );
    assert_eq!(audit.sealed_checkpoints[0], Some(coordinator.checkpoint()));
    assert!(scratch.is_clean());
    operations.assert_exact(&[
        OP_RESERVE,
        OP_SOURCE,
        OP_COMMIT,
        OP_ENCODE_FAULT,
        OP_TRANSMISSION,
        OP_COMMIT,
        OP_TRANSMISSION,
        OP_COMMIT,
        OP_FINISH,
    ]);
}

#[test]
fn dirty_encoded_tail_is_never_submitted_or_reused_and_resolves_fifo() {
    let (mut reactor, source_event) = prepared_quote_reactor();
    let (mut session, mut adapter) = live_session();
    adapter.dirty_tail = true;
    let session_before = session;
    let adapter_before = adapter;
    let operations = FixedOperationLog::new();
    let mut transport = FixedTransport::new(&operations, [sent(61, 2_010), sent(62, 2_020)]);
    let mut audit = FixedAudit::new(&operations);
    let mut scratch = NativeLiveScratch::<64>::new();
    let mut coordinator = coordinator();

    let status = coordinator
        .process_event(
            source_event,
            MonotonicTimestampNs(2_000),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        )
        .unwrap();

    assert_eq!(
        status,
        NativeLiveStatus::SafetyPending {
            reason: NativeLiveSafetyReason::Encode(NativeLiveEncodeFault::DirtyEncodedTail {
                index: WIRE_LEN,
            }),
        }
    );
    assert_local_encode_fault_resolution(
        &reactor,
        &session,
        session_before,
        &adapter,
        adapter_before,
        &transport,
        &audit,
        &coordinator,
    );
    assert!(scratch.is_clean());
    operations.assert_exact(&[
        OP_RESERVE,
        OP_SOURCE,
        OP_COMMIT,
        OP_ENCODE_FAULT,
        OP_TRANSMISSION,
        OP_COMMIT,
        OP_TRANSMISSION,
        OP_COMMIT,
        OP_FINISH,
    ]);
}

#[test]
fn source_slot_one_ambiguity_preserves_sent_prefix_and_unresolved_suffix() {
    let (mut reactor, source_event) = prepared_quote_reactor();
    let (mut session, mut adapter) = live_session();
    let operations = FixedOperationLog::new();
    let mut transport = FixedTransport::new(&operations, [sent(71, 2_010), ambiguous(72, 2_020)]);
    let mut audit = FixedAudit::new(&operations);
    let mut scratch = NativeLiveScratch::<64>::new();
    let mut coordinator = coordinator();

    let status = coordinator
        .process_event(
            source_event,
            MonotonicTimestampNs(2_000),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        )
        .unwrap();

    let second = transport.contexts[1].unwrap();
    assert_eq!(
        status,
        NativeLiveStatus::Ambiguous {
            frame_ordinal: 91,
            egress: second.egress,
        }
    );
    assert_eq!(second.egress.command_index, 1);
    assert_eq!(second.venue_sequence, Sequence(701));
    assert_eq!(session.next_outbound(), Sequence(702));
    assert_eq!(reactor.outstanding_transmissions(), 1);
    assert_eq!(reactor.counters().transmissions_sent, 1);
    assert_eq!(reactor.counters().transmissions_processed, 1);
    assert!(reactor.mandatory_kill_pending());
    assert_eq!(coordinator.phase(), NativeLivePhase::Ambiguous);
    assert_eq!(
        coordinator.last_source_capture_ordinal(),
        Some(CaptureOrdinal(2))
    );
    assert_eq!(
        coordinator.last_feedback_capture_ordinal(),
        Some(CaptureOrdinal(3))
    );
    assert_eq!(coordinator.last_outbound_frame_ordinal(), Some(91));
    assert_eq!(coordinator.next_commit_ordinal(), 52);
    assert_eq!(audit.commit_count, 2);
    assert_eq!(audit.intent_count, 2);
    assert_eq!(audit.egress_count, 1);
    assert_eq!(audit.proof_fault_count, 1);
    let proof_fault = audit.proof_faults[0].unwrap();
    assert_eq!(proof_fault.context, second);
    assert_eq!(proof_fault.proof, 72);
    assert_eq!(
        proof_fault.claimed_disposition,
        NativeSubmitDisposition::Ambiguous
    );
    assert_eq!(proof_fault.fault, NativeLiveProofFault::Ambiguous);
    assert_eq!(audit.transmission_count, 1);
    assert_eq!(transport.quiesce_count, 1);
    assert!(scratch.is_clean());
    operations.assert_exact(&[
        OP_RESERVE,
        OP_SOURCE,
        OP_COMMIT,
        OP_INTENT,
        OP_SUBMIT,
        OP_EGRESS,
        OP_TRANSMISSION,
        OP_COMMIT,
        OP_INTENT,
        OP_SUBMIT,
        OP_QUIESCE,
        OP_PROOF_FAULT,
        OP_FINISH,
    ]);
}

#[test]
fn known_sent_zero_timestamp_uses_audited_local_clock_and_safety_pends() {
    let (mut reactor, source_event) = prepared_quote_reactor();
    let (mut session, mut adapter) = live_session();
    let operations = FixedOperationLog::new();
    let mut transport = FixedTransport::new(&operations, [sent(73, 0), sent(74, 1_120)]);
    let mut audit = FixedAudit::new(&operations);
    let mut scratch = NativeLiveScratch::<64>::new();
    let mut coordinator = coordinator();

    let status = coordinator
        .process_event(
            source_event,
            MonotonicTimestampNs(2_000),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        )
        .unwrap();

    assert_eq!(
        status,
        NativeLiveStatus::SafetyPending {
            reason: NativeLiveSafetyReason::InvalidSentTimestamp(MonotonicTimestampNs::ZERO),
        }
    );
    assert_eq!(transport.submit_count, 1);
    assert_eq!(transport.quiesce_count, 0);
    assert_eq!(session.next_outbound(), Sequence(701));
    assert_eq!(adapter.codec_state, 2);
    assert_eq!(adapter.durable_commits, 3);
    assert_eq!(reactor.outstanding_transmissions(), 0);
    assert_eq!(reactor.counters().transmissions_sent, 1);
    assert_eq!(reactor.counters().transmissions_proven_unsent, 1);
    assert!(reactor.mandatory_kill_pending());
    assert_eq!(coordinator.phase(), NativeLivePhase::SafetyPending);
    assert_eq!(
        coordinator.last_source_capture_ordinal(),
        Some(CaptureOrdinal(2))
    );
    assert_eq!(
        coordinator.last_feedback_capture_ordinal(),
        Some(CaptureOrdinal(4))
    );
    assert_eq!(coordinator.last_outbound_frame_ordinal(), Some(90));
    assert_eq!(coordinator.next_commit_ordinal(), 53);
    assert_eq!(audit.commit_count, 3);
    assert_eq!(audit.intent_count, 1);
    assert_eq!(audit.egress_count, 1);
    assert_eq!(audit.transmission_count, 2);
    assert_eq!(audit.clock_fallback_count, 1);
    let source_commit = audit.commits[0].unwrap();
    let first_egress = transport.contexts[0].unwrap().egress;
    assert_eq!(
        audit.clock_fallbacks[0],
        Some(NativeLiveClockFallbackRecord {
            egress: first_egress,
            disposition: NativeSubmitDisposition::Sent,
            transport_monotonic_now: MonotonicTimestampNs::ZERO,
            local_monotonic_now: MonotonicTimestampNs(2_000),
            effective_monotonic_now: MonotonicTimestampNs(2_000),
        })
    );
    assert_feedback(
        &audit,
        0,
        CaptureOrdinal(3),
        source_commit.commands[0].unwrap(),
        TransmissionStatus::Sent,
        MonotonicTimestampNs(2_000),
        51,
    );
    assert_feedback(
        &audit,
        1,
        CaptureOrdinal(4),
        source_commit.commands[1].unwrap(),
        TransmissionStatus::ProvenUnsent,
        MonotonicTimestampNs(2_000),
        52,
    );
    assert!(scratch.is_clean());
    operations.assert_exact(&[
        OP_RESERVE,
        OP_SOURCE,
        OP_COMMIT,
        OP_INTENT,
        OP_SUBMIT,
        OP_EGRESS,
        OP_CLOCK_FALLBACK,
        OP_TRANSMISSION,
        OP_COMMIT,
        OP_TRANSMISSION,
        OP_COMMIT,
        OP_FINISH,
    ]);
}

#[test]
fn second_slot_zero_clock_fallback_never_regresses_below_first_applied_feedback() {
    let (mut reactor, source_event) = prepared_quote_reactor();
    let (mut session, mut adapter) = live_session();
    let operations = FixedOperationLog::new();
    let mut transport = FixedTransport::new(&operations, [sent(75, 3_000), sent(76, 0)]);
    let mut audit = FixedAudit::new(&operations);
    let mut scratch = NativeLiveScratch::<64>::new();
    let mut coordinator = coordinator();

    let status = coordinator
        .process_event(
            source_event,
            MonotonicTimestampNs(2_000),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        )
        .unwrap();

    assert_eq!(
        status,
        NativeLiveStatus::SafetyPending {
            reason: NativeLiveSafetyReason::InvalidSentTimestamp(MonotonicTimestampNs::ZERO),
        }
    );
    assert_eq!(transport.submit_count, 2);
    assert_eq!(transport.quiesce_count, 0);
    assert_eq!(session.next_outbound(), Sequence(702));
    assert_eq!(audit.intent_count, 2);
    assert_eq!(audit.egress_count, 2);
    assert_eq!(audit.transmission_count, 2);
    assert_eq!(audit.commit_count, 3);
    assert_eq!(audit.clock_fallback_count, 1);
    let source_commit = audit.commits[0].unwrap();
    let second_egress = transport.contexts[1].unwrap().egress;
    assert_eq!(
        audit.clock_fallbacks[0],
        Some(NativeLiveClockFallbackRecord {
            egress: second_egress,
            disposition: NativeSubmitDisposition::Sent,
            transport_monotonic_now: MonotonicTimestampNs::ZERO,
            local_monotonic_now: MonotonicTimestampNs(2_000),
            effective_monotonic_now: MonotonicTimestampNs(3_000),
        })
    );
    assert_feedback(
        &audit,
        0,
        CaptureOrdinal(3),
        source_commit.commands[0].unwrap(),
        TransmissionStatus::Sent,
        MonotonicTimestampNs(3_000),
        51,
    );
    assert_feedback(
        &audit,
        1,
        CaptureOrdinal(4),
        source_commit.commands[1].unwrap(),
        TransmissionStatus::Sent,
        MonotonicTimestampNs(3_000),
        52,
    );
    assert_eq!(reactor.outstanding_transmissions(), 0);
    assert_eq!(reactor.counters().transmissions_sent, 2);
    assert!(reactor.mandatory_kill_pending());
    assert_eq!(coordinator.phase(), NativeLivePhase::SafetyPending);
    assert_eq!(
        coordinator.last_source_capture_ordinal(),
        Some(CaptureOrdinal(2))
    );
    assert_eq!(
        coordinator.last_feedback_capture_ordinal(),
        Some(CaptureOrdinal(4))
    );
    assert_eq!(coordinator.last_outbound_frame_ordinal(), Some(91));
    assert_eq!(coordinator.next_commit_ordinal(), 53);
    assert!(scratch.is_clean());
    operations.assert_exact(&[
        OP_RESERVE,
        OP_SOURCE,
        OP_COMMIT,
        OP_INTENT,
        OP_SUBMIT,
        OP_EGRESS,
        OP_TRANSMISSION,
        OP_COMMIT,
        OP_INTENT,
        OP_SUBMIT,
        OP_EGRESS,
        OP_CLOCK_FALLBACK,
        OP_TRANSMISSION,
        OP_COMMIT,
        OP_FINISH,
    ]);
}

#[test]
fn source_reactor_fault_records_exact_zero_egress_and_fail_closed_state() {
    let (mut reactor, source_event) = prepared_fault_quote_reactor();
    let (mut session, mut adapter) = live_session();
    let session_before = session;
    let adapter_before = adapter;
    let operations = FixedOperationLog::new();
    let mut transport = FixedTransport::new(&operations, [sent(75, 2_010), sent(76, 2_020)]);
    let mut audit = FixedAudit::new(&operations);
    let mut scratch = NativeLiveScratch::<64>::new();
    let mut coordinator = coordinator();

    let status = coordinator
        .process_event(
            source_event,
            MonotonicTimestampNs(2_000),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        )
        .unwrap();

    assert_eq!(
        status,
        NativeLiveStatus::SafetyPending {
            reason: NativeLiveSafetyReason::ReactorFault {
                route: SchedulerRoute::Normal,
            },
        }
    );
    assert_eq!(audit.source_events, [Some(source_event)]);
    assert_eq!(audit.reactor_fault_count, 1);
    let fault = audit.reactor_faults[0].unwrap();
    assert_eq!(fault.application_ordinal, FIRST_COMMIT_ORDINAL);
    assert_eq!(fault.route, SchedulerRoute::Normal);
    assert_eq!(fault.source_event, Some(source_event));
    assert_eq!(fault.failure.report.commands_published, 0);
    assert_eq!(fault.failure.report.events_processed, 1);
    assert!(fault.egress.iter().all(Option::is_none));
    assert_eq!(fault.outstanding_transmissions, 0);
    assert!(!fault.retained_event);
    assert!(!fault.mandatory_kill_pending);
    assert_eq!(transport.submit_count, 0);
    assert_eq!(transport.quiesce_count, 0);
    assert_eq!(audit.intent_count, 0);
    assert_eq!(audit.egress_count, 0);
    assert_eq!(audit.transmission_count, 0);
    assert_eq!(audit.commit_count, 0);
    assert_eq!(reactor.outstanding_transmissions(), 0);
    assert_eq!(reactor.counters().transmissions_proven_unsent, 0);
    assert!(reactor.mandatory_kill_pending());
    assert_eq!(session, session_before);
    assert_eq!(adapter, adapter_before);
    assert_eq!(coordinator.phase(), NativeLivePhase::SafetyPending);
    assert_eq!(
        coordinator.last_source_capture_ordinal(),
        Some(CaptureOrdinal(2))
    );
    assert_eq!(coordinator.last_feedback_capture_ordinal(), None);
    assert_eq!(coordinator.last_outbound_frame_ordinal(), None);
    assert_eq!(coordinator.next_commit_ordinal(), 51);
    assert!(scratch.is_clean());
    operations.assert_exact(&[OP_RESERVE, OP_SOURCE, OP_REACTOR_FAULT, OP_FINISH]);
}

#[test]
fn post_submit_feedback_reactor_fault_is_audited_quiesced_and_fail_latched() {
    let (mut reactor, source_event) = prepared_quote_reactor();
    let (mut session, mut adapter) = live_session();
    let operations = FixedOperationLog::new();
    let mut transport = FixedTransport::new(&operations, [sent(77, u64::MAX), sent(78, 1_120)]);
    let mut audit = FixedAudit::new(&operations);
    let mut scratch = NativeLiveScratch::<64>::new();
    let mut coordinator = coordinator();

    let result = coordinator.process_event(
        source_event,
        MonotonicTimestampNs(2_000),
        &mut reactor,
        &mut session,
        &mut adapter,
        &mut transport,
        &mut audit,
        &mut scratch,
    );
    let Err(NativeLiveError::Reactor(failure)) = result else {
        panic!("feedback beyond disciplined-clock holdover must fail inside the reactor");
    };

    assert_eq!(audit.source_events, [Some(source_event)]);
    assert_eq!(audit.commit_count, 1);
    assert_eq!(audit.intent_count, 1);
    assert_eq!(audit.egress_count, 1);
    assert_eq!(audit.transmission_count, 1);
    assert_eq!(audit.reactor_fault_count, 1);
    let fault = audit.reactor_faults[0].unwrap();
    assert_eq!(fault.application_ordinal, 51);
    assert_eq!(fault.route, SchedulerRoute::PriorityTransmission);
    assert_eq!(fault.source_event, audit.transmissions[0]);
    assert_eq!(fault.failure, failure);
    assert!(fault.egress.iter().all(Option::is_none));
    assert_eq!(fault.outstanding_transmissions, 2);
    assert!(!fault.retained_event);
    assert!(fault.mandatory_kill_pending);
    assert_eq!(transport.submit_count, 1);
    assert_eq!(transport.quiesce_count, 1);
    assert_eq!(session.next_outbound(), Sequence(701));
    assert_eq!(reactor.outstanding_transmissions(), 2);
    assert!(reactor.mandatory_kill_pending());
    assert_eq!(reactor.counters().transmissions_processed, 1);
    assert_eq!(coordinator.phase(), NativeLivePhase::Failed);
    assert_eq!(audit.sealed_checkpoints[0], Some(coordinator.checkpoint()));
    assert_eq!(
        coordinator.last_source_capture_ordinal(),
        Some(CaptureOrdinal(2))
    );
    assert_eq!(
        coordinator.last_feedback_capture_ordinal(),
        Some(CaptureOrdinal(3))
    );
    assert_eq!(coordinator.last_outbound_frame_ordinal(), Some(90));
    assert_eq!(coordinator.next_commit_ordinal(), 52);
    assert!(scratch.is_clean());
    operations.assert_exact(&[
        OP_RESERVE,
        OP_SOURCE,
        OP_COMMIT,
        OP_INTENT,
        OP_SUBMIT,
        OP_EGRESS,
        OP_TRANSMISSION,
        OP_REACTOR_FAULT,
        OP_QUIESCE,
        OP_FINISH,
    ]);

    assert_eq!(
        coordinator.process_event(
            source_event,
            MonotonicTimestampNs(2_001),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        ),
        Err(NativeLiveError::Phase(NativeLivePhase::Failed))
    );
    assert_eq!(transport.submit_count, 1);
    assert_eq!(transport.quiesce_count, 1);
    assert_eq!(audit.reserve_calls, 1);
}

#[test]
fn all_sent_safety_kill_is_source_less_fifo_audited_and_complete() {
    let (mut reactor, mut session, mut adapter, mut coordinator) = prepared_safety_pending();
    let operations = FixedOperationLog::new();
    let mut transport = FixedTransport::new(&operations, [sent(81, 3_010), sent(82, 3_020)]);
    let mut audit = FixedAudit::new_at(&operations, CaptureOrdinal(7), 92);
    let mut scratch = NativeLiveScratch::<64>::new();

    let status = coordinator
        .drive_safety(
            MonotonicTimestampNs(3_000),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        )
        .unwrap();

    assert_eq!(
        status,
        NativeLiveStatus::KilledRecoveryEntered(quant_hft_core::NativeLiveSummary {
            source_commit_ordinal: 55,
            commands: 2,
            sent: 2,
            proven_unsent: 0,
        })
    );
    assert_eq!(coordinator.phase(), NativeLivePhase::KilledRecovery);
    assert_eq!(audit.sealed_checkpoints[0], Some(coordinator.checkpoint()));
    assert!(!reactor.mandatory_kill_pending());
    assert_eq!(reactor.outstanding_transmissions(), 0);
    assert_eq!(session.next_outbound(), Sequence(704));
    assert_eq!(transport.submit_count, 2);
    assert_eq!(transport.quiesce_count, 0);
    assert_eq!(audit.commit_count, 3);
    assert_eq!(audit.intent_count, 2);
    assert_eq!(audit.egress_count, 2);
    assert_eq!(audit.transmission_count, 2);
    assert_eq!(audit.encode_fault_count, 0);
    let safety_commit = audit.commits[0].unwrap();
    assert_eq!(safety_commit.commit_ordinal, 55);
    assert_eq!(safety_commit.route, SchedulerRoute::SafetyKill);
    assert_eq!(safety_commit.input_kind, Some(ReactorInputKind::SafetyKill));
    assert_eq!(safety_commit.capture_ordinal, CaptureOrdinal(0));
    assert_eq!(safety_commit.source_event_crc32c, 0);
    assert_eq!(safety_commit.egress_input_ordinal, Some(InputOrdinal(0)));
    for index in 0..2 {
        let context = transport.contexts[index].unwrap();
        assert_eq!(audit.intents[index], Some(context));
        assert_eq!(context.frame_ordinal, 92 + index as u64);
        assert_eq!(context.venue_sequence, Sequence(702 + index as u64));
        assert_eq!(context.scheduler_commit_ordinal, 55);
        assert_eq!(context.scheduler_capture_ordinal, CaptureOrdinal(0));
        assert_eq!(context.scheduler_source_event_crc32c, 0);
        assert_eq!(context.egress.input_ordinal, InputOrdinal(0));
        assert_eq!(usize::from(context.egress.command_index), index);
        assert_eq!(
            context.egress.command,
            safety_commit.commands[index].unwrap()
        );
        assert!(matches!(context.egress.command, OrderCommand::Cancel(_)));
        assert_eq!(context.encoded_len, CANCEL_WIRE_LEN);
        assert_eq!(context.encoded()[0], 0x21);
        assert_eq!(read_u64(context.encoded(), 1), 702 + index as u64);
        assert_eq!(audit.egress[index].unwrap().context, context);
    }
    assert_feedback(
        &audit,
        0,
        CaptureOrdinal(7),
        safety_commit.commands[0].unwrap(),
        TransmissionStatus::Sent,
        MonotonicTimestampNs(3_010),
        56,
    );
    assert_feedback(
        &audit,
        1,
        CaptureOrdinal(8),
        safety_commit.commands[1].unwrap(),
        TransmissionStatus::Sent,
        MonotonicTimestampNs(3_020),
        57,
    );
    assert_eq!(
        coordinator.last_source_capture_ordinal(),
        Some(CaptureOrdinal(6))
    );
    assert_eq!(
        coordinator.last_feedback_capture_ordinal(),
        Some(CaptureOrdinal(8))
    );
    assert_eq!(coordinator.last_outbound_frame_ordinal(), Some(93));
    assert_eq!(coordinator.next_commit_ordinal(), 58);
    assert!(scratch.is_clean());
    operations.assert_exact(&[
        OP_RESERVE,
        OP_COMMIT,
        OP_INTENT,
        OP_SUBMIT,
        OP_EGRESS,
        OP_TRANSMISSION,
        OP_COMMIT,
        OP_INTENT,
        OP_SUBMIT,
        OP_EGRESS,
        OP_TRANSMISSION,
        OP_COMMIT,
        OP_FINISH,
    ]);
}

#[test]
fn safety_slot_one_ambiguity_keeps_sequence_and_outstanding_cancel() {
    let (mut reactor, mut session, mut adapter, mut coordinator) = prepared_safety_pending();
    let operations = FixedOperationLog::new();
    let mut transport = FixedTransport::new(&operations, [sent(91, 3_010), ambiguous(92, 3_020)]);
    let mut audit = FixedAudit::new_at(&operations, CaptureOrdinal(7), 92);
    let mut scratch = NativeLiveScratch::<64>::new();

    let status = coordinator
        .drive_safety(
            MonotonicTimestampNs(3_000),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        )
        .unwrap();

    let ambiguous_context = transport.contexts[1].unwrap();
    assert_eq!(
        status,
        NativeLiveStatus::Ambiguous {
            frame_ordinal: 93,
            egress: ambiguous_context.egress,
        }
    );
    assert_eq!(ambiguous_context.egress.input_ordinal, InputOrdinal(0));
    assert_eq!(ambiguous_context.egress.command_index, 1);
    assert_eq!(ambiguous_context.venue_sequence, Sequence(703));
    assert_eq!(session.next_outbound(), Sequence(704));
    assert_eq!(reactor.outstanding_transmissions(), 1);
    assert!(reactor.mandatory_kill_pending());
    assert_eq!(coordinator.phase(), NativeLivePhase::Ambiguous);
    assert_eq!(transport.submit_count, 2);
    assert_eq!(transport.quiesce_count, 1);
    assert_eq!(audit.commit_count, 2);
    assert_eq!(audit.egress_count, 1);
    assert_eq!(audit.proof_fault_count, 1);
    let proof_fault = audit.proof_faults[0].unwrap();
    assert_eq!(proof_fault.context, ambiguous_context);
    assert_eq!(proof_fault.proof, 92);
    assert_eq!(
        proof_fault.claimed_disposition,
        NativeSubmitDisposition::Ambiguous
    );
    assert_eq!(proof_fault.fault, NativeLiveProofFault::Ambiguous);
    assert_eq!(audit.transmission_count, 1);
    assert!(scratch.is_clean());
    operations.assert_exact(&[
        OP_RESERVE,
        OP_COMMIT,
        OP_INTENT,
        OP_SUBMIT,
        OP_EGRESS,
        OP_TRANSMISSION,
        OP_COMMIT,
        OP_INTENT,
        OP_SUBMIT,
        OP_QUIESCE,
        OP_PROOF_FAULT,
        OP_FINISH,
    ]);
}

#[test]
fn safety_reservation_failure_preserves_pending_kill_and_every_source_owner() {
    let (mut reactor, mut session, mut adapter, mut coordinator) = prepared_safety_pending();
    let (baseline_reactor, baseline_session, baseline_adapter, baseline_coordinator) =
        prepared_safety_pending();
    let operations = FixedOperationLog::new();
    let mut transport = FixedTransport::new(&operations, [sent(101, 3_010), sent(102, 3_020)]);
    let mut audit = FixedAudit::rejecting(&operations);
    let mut scratch = NativeLiveScratch::<64>::new();

    let status = coordinator
        .drive_safety(
            MonotonicTimestampNs(3_000),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        )
        .unwrap();

    assert_eq!(
        status,
        NativeLiveStatus::SafetyPending {
            reason: NativeLiveSafetyReason::AuditReservation(AuditFailure::Capacity),
        }
    );
    assert!(reactor.deterministic_state_eq(&baseline_reactor));
    assert_eq!(session, baseline_session);
    assert_eq!(adapter, baseline_adapter);
    assert_eq!(coordinator, baseline_coordinator);
    assert_eq!(coordinator.phase(), NativeLivePhase::SafetyPending);
    assert!(reactor.mandatory_kill_pending());
    assert_eq!(transport.submit_count, 0);
    assert_eq!(transport.quiesce_count, 0);
    assert_eq!(audit.commit_count, 0);
    assert_eq!(audit.emergency_seal_count, 1);
    assert_eq!(
        audit.emergency_seals[0],
        Some(NativeLiveEmergencySealRecord {
            operation: NativeLiveOperation::DriveSafety,
            rejected_source: None,
            local_monotonic_sample: MonotonicTimestampNs(3_000),
            error: AuditFailure::Capacity,
            checkpoint: coordinator.checkpoint(),
        })
    );
    assert!(scratch.is_clean());
    operations.assert_exact(&[OP_RESERVE, OP_EMERGENCY_SEAL]);
}

#[test]
fn safety_local_encode_fault_records_input_zero_and_retrips_after_exact_feedback() {
    let (mut reactor, mut session, mut adapter, mut coordinator) = prepared_safety_pending();
    let session_before = session;
    let adapter_before = adapter;
    let operations = FixedOperationLog::new();
    let mut transport = FixedTransport::new(&operations, [sent(111, 3_010), sent(112, 3_020)]);
    let mut audit = FixedAudit::new_at(&operations, CaptureOrdinal(7), 92);
    let mut scratch = NativeLiveScratch::<8>::new();

    let status = coordinator
        .drive_safety(
            MonotonicTimestampNs(3_000),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        )
        .unwrap();

    assert_eq!(
        status,
        NativeLiveStatus::SafetyPending {
            reason: NativeLiveSafetyReason::Encode(NativeLiveEncodeFault::Venue(VenueError::Wire(
                WireError::BufferTooSmall {
                    required: CANCEL_WIRE_LEN,
                    provided: 8,
                }
            ))),
        }
    );
    let safety_commit = audit.commits[0].unwrap();
    let fault = audit.encode_faults[0].unwrap();
    assert_eq!(fault.egress.input_ordinal, InputOrdinal(0));
    assert_eq!(fault.egress.command_index, 0);
    assert_eq!(fault.egress.command, safety_commit.commands[0].unwrap());
    assert_eq!(fault.monotonic_now, MonotonicTimestampNs(3_000));
    assert_eq!(session, session_before);
    assert_eq!(adapter, adapter_before);
    assert_eq!(transport.submit_count, 0);
    assert_eq!(audit.intent_count, 0);
    assert_eq!(audit.egress_count, 0);
    assert_eq!(audit.encode_fault_count, 1);
    assert_eq!(reactor.outstanding_transmissions(), 0);
    assert!(reactor.mandatory_kill_pending());
    assert_eq!(coordinator.phase(), NativeLivePhase::SafetyPending);
    assert_feedback(
        &audit,
        0,
        CaptureOrdinal(7),
        safety_commit.commands[0].unwrap(),
        TransmissionStatus::ProvenUnsent,
        MonotonicTimestampNs(3_000),
        56,
    );
    assert_feedback(
        &audit,
        1,
        CaptureOrdinal(8),
        safety_commit.commands[1].unwrap(),
        TransmissionStatus::ProvenUnsent,
        MonotonicTimestampNs(3_000),
        57,
    );
    assert!(scratch.is_clean());
    operations.assert_exact(&[
        OP_RESERVE,
        OP_COMMIT,
        OP_ENCODE_FAULT,
        OP_TRANSMISSION,
        OP_COMMIT,
        OP_TRANSMISSION,
        OP_COMMIT,
        OP_FINISH,
    ]);
}

#[test]
fn proven_unsent_safety_cancel_retrips_and_a_retry_can_complete() {
    let (mut reactor, mut session, mut adapter, mut coordinator) = prepared_safety_pending();
    let operations = FixedOperationLog::new();
    let mut transport =
        FixedTransport::new(&operations, [proven_unsent(121, 3_010), sent(122, 3_020)]);
    let mut audit = FixedAudit::new_at(&operations, CaptureOrdinal(7), 92);
    let mut scratch = NativeLiveScratch::<64>::new();

    let status = coordinator
        .drive_safety(
            MonotonicTimestampNs(3_000),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        )
        .unwrap();

    assert_eq!(
        status,
        NativeLiveStatus::SafetyPending {
            reason: NativeLiveSafetyReason::KillCancelProvenUnsent { commands: 1 },
        }
    );
    assert_eq!(transport.contexts[0].unwrap().venue_sequence, Sequence(702));
    assert_eq!(transport.contexts[1].unwrap().venue_sequence, Sequence(702));
    assert_eq!(session.next_outbound(), Sequence(703));
    assert_eq!(reactor.outstanding_transmissions(), 0);
    assert!(reactor.mandatory_kill_pending());
    assert_eq!(coordinator.phase(), NativeLivePhase::SafetyPending);
    assert_eq!(
        coordinator.last_source_capture_ordinal(),
        Some(CaptureOrdinal(6))
    );
    assert_eq!(
        coordinator.last_feedback_capture_ordinal(),
        Some(CaptureOrdinal(8))
    );
    assert_eq!(coordinator.last_outbound_frame_ordinal(), Some(93));
    assert_eq!(coordinator.next_commit_ordinal(), 58);
    assert!(scratch.is_clean());

    let retry_operations = FixedOperationLog::new();
    let mut retry_transport =
        FixedTransport::new(&retry_operations, [sent(123, 3_040), sent(124, 3_050)]);
    let mut retry_audit = FixedAudit::new_at(&retry_operations, CaptureOrdinal(9), 94);
    let retry = coordinator
        .drive_safety(
            MonotonicTimestampNs(3_030),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut retry_transport,
            &mut retry_audit,
            &mut scratch,
        )
        .unwrap();
    assert_eq!(
        retry,
        NativeLiveStatus::KilledRecoveryEntered(quant_hft_core::NativeLiveSummary {
            source_commit_ordinal: 58,
            commands: 1,
            sent: 1,
            proven_unsent: 0,
        })
    );
    let retry_commit = retry_audit.commits[0].unwrap();
    assert_eq!(retry_commit.route, SchedulerRoute::SafetyKill);
    assert_eq!(retry_commit.capture_ordinal, CaptureOrdinal(0));
    assert_eq!(retry_commit.commands.iter().flatten().count(), 1);
    let retry_context = retry_transport.contexts[0].unwrap();
    assert_eq!(retry_context.egress.input_ordinal, InputOrdinal(0));
    assert_eq!(retry_context.egress.command_index, 0);
    assert_eq!(retry_context.venue_sequence, Sequence(703));
    assert_eq!(session.next_outbound(), Sequence(704));
    assert_eq!(coordinator.phase(), NativeLivePhase::KilledRecovery);
    assert!(!reactor.mandatory_kill_pending());
    assert_eq!(reactor.outstanding_transmissions(), 0);
    assert!(scratch.is_clean());
}

#[test]
fn ready_control_kill_enters_killed_recovery_after_only_cancel_egress() {
    let (mut reactor, mut session, mut adapter, mut coordinator) = prepared_live_orders_ready();
    let event = normalize_control_decision(
        CaptureOrdinal(7),
        support::authenticated_kill(1, ConfigDigest([0xA5; 32]), Sequence(1), TimestampNs(3_000)),
    )
    .unwrap();
    let operations = FixedOperationLog::new();
    let mut transport = FixedTransport::new(&operations, [sent(131, 3_010), sent(132, 3_020)]);
    let mut audit = FixedAudit::new_at(&operations, CaptureOrdinal(8), 92);
    let mut scratch = NativeLiveScratch::<64>::new();

    let status = coordinator
        .process_event(
            event,
            MonotonicTimestampNs(3_000),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        )
        .unwrap();

    assert_eq!(
        status,
        NativeLiveStatus::Completed(quant_hft_core::NativeLiveSummary {
            source_commit_ordinal: 55,
            commands: 2,
            sent: 2,
            proven_unsent: 0,
        })
    );
    assert_eq!(coordinator.phase(), NativeLivePhase::KilledRecovery);
    assert!(reactor.engine().kill_snapshot().is_some());
    assert!(!reactor.mandatory_kill_pending());
    assert_eq!(reactor.outstanding_transmissions(), 0);
    let commit = audit.commits[0].unwrap();
    commit.verify_source(event).unwrap();
    assert_eq!(commit.route, SchedulerRoute::Normal);
    assert_eq!(commit.input_kind, Some(ReactorInputKind::Control));
    assert!(
        commit
            .commands
            .iter()
            .flatten()
            .all(|command| matches!(command, OrderCommand::Cancel(_)))
    );
    assert!(scratch.is_clean());
}

#[test]
fn safety_complete_accepts_cancel_confirmations_and_converges_lifecycle() {
    let (mut reactor, mut session, mut adapter, mut coordinator) = prepared_safety_pending();
    let operations = FixedOperationLog::new();
    let mut transport = FixedTransport::new(&operations, [sent(141, 3_010), sent(142, 3_020)]);
    let mut audit = FixedAudit::new_at(&operations, CaptureOrdinal(7), 92);
    let mut scratch = NativeLiveScratch::<64>::new();
    assert!(matches!(
        coordinator
            .drive_safety(
                MonotonicTimestampNs(3_000),
                &mut reactor,
                &mut session,
                &mut adapter,
                &mut transport,
                &mut audit,
                &mut scratch,
            )
            .unwrap(),
        NativeLiveStatus::KilledRecoveryEntered(_)
    ));
    let cancels = audit.commits[0]
        .unwrap()
        .commands
        .map(|slot| match slot.unwrap() {
            OrderCommand::Cancel(cancel) => cancel,
            _ => panic!("safety fixture must publish cancel orders"),
        });

    for (index, cancel) in cancels.into_iter().enumerate() {
        let remaining = reactor
            .engine()
            .orders()
            .order(cancel.client_order_id)
            .unwrap()
            .remaining_quantity;
        let event = canceled_event(
            CaptureOrdinal(9 + index as u64),
            Sequence(4 + index as u64),
            cancel,
            remaining,
            1_400 + index as u64 * 10,
        );
        let recovery_operations = FixedOperationLog::new();
        let mut recovery_transport =
            FixedTransport::new(&recovery_operations, [sent(143, 3_110), sent(144, 3_120)]);
        let mut recovery_audit = FixedAudit::new(&recovery_operations);
        let status = coordinator
            .process_event(
                event,
                MonotonicTimestampNs(3_100),
                &mut reactor,
                &mut session,
                &mut adapter,
                &mut recovery_transport,
                &mut recovery_audit,
                &mut scratch,
            )
            .unwrap();
        assert_eq!(
            status,
            NativeLiveStatus::Completed(quant_hft_core::NativeLiveSummary {
                source_commit_ordinal: 58 + index as u64,
                commands: 0,
                sent: 0,
                proven_unsent: 0,
            })
        );
        assert_eq!(coordinator.phase(), NativeLivePhase::KilledRecovery);
        assert!(reactor.engine().kill_snapshot().is_some());
        assert!(
            reactor
                .engine()
                .orders()
                .order(cancel.client_order_id)
                .is_none()
        );
        assert_eq!(recovery_transport.submit_count, 0);
        assert_eq!(recovery_audit.intent_count, 0);
        assert!(scratch.is_clean());
    }
    assert_eq!(
        coordinator.last_source_capture_ordinal(),
        Some(CaptureOrdinal(10))
    );
    assert_eq!(
        coordinator.last_feedback_capture_ordinal(),
        Some(CaptureOrdinal(8))
    );
    assert_eq!(coordinator.last_outbound_frame_ordinal(), Some(93));
    assert_eq!(coordinator.next_commit_ordinal(), 60);
}

#[allow(clippy::too_many_arguments)]
fn assert_local_encode_fault_resolution(
    reactor: &TestReactor,
    session: &VenueSession,
    session_before: VenueSession,
    adapter: &FixedVenueAdapter,
    adapter_before: FixedVenueAdapter,
    transport: &FixedTransport<'_>,
    audit: &FixedAudit<'_>,
    coordinator: &NativeLiveCoordinator,
) {
    assert_eq!(*session, session_before);
    assert_eq!(*adapter, adapter_before);
    assert_eq!(transport.submit_count, 0);
    assert_eq!(transport.quiesce_count, 0);
    assert_eq!(reactor.outstanding_transmissions(), 0);
    assert_eq!(reactor.counters().transmissions_proven_unsent, 2);
    assert!(reactor.mandatory_kill_pending());
    assert_eq!(audit.commit_count, 3);
    assert_eq!(audit.intent_count, 0);
    assert_eq!(audit.egress_count, 0);
    assert_eq!(audit.transmission_count, 2);
    assert_eq!(audit.finish_count, 1);
    assert_eq!(audit.abort_count, 0);
    let source_commit = audit.commits[0].unwrap();
    assert_eq!(audit.encode_fault_count, 1);
    let fault = audit.encode_faults[0].unwrap();
    assert_eq!(
        fault.egress,
        ReactorEgress {
            input_ordinal: InputOrdinal(2),
            command_index: 0,
            command: source_commit.commands[0].unwrap(),
        }
    );
    assert_eq!(fault.monotonic_now, MonotonicTimestampNs(2_000));
    for index in 0..2 {
        assert_feedback(
            audit,
            index,
            CaptureOrdinal(3 + index as u64),
            source_commit.commands[index].unwrap(),
            TransmissionStatus::ProvenUnsent,
            MonotonicTimestampNs(2_000),
            51 + index as u64,
        );
    }
    assert_eq!(coordinator.phase(), NativeLivePhase::SafetyPending);
    assert_eq!(
        coordinator.last_source_capture_ordinal(),
        Some(CaptureOrdinal(2))
    );
    assert_eq!(
        coordinator.last_feedback_capture_ordinal(),
        Some(CaptureOrdinal(4))
    );
    assert_eq!(coordinator.last_outbound_frame_ordinal(), None);
    assert_eq!(coordinator.next_commit_ordinal(), 53);
}

#[allow(clippy::too_many_arguments)]
fn assert_feedback(
    audit: &FixedAudit<'_>,
    index: usize,
    capture_ordinal: CaptureOrdinal,
    command: OrderCommand,
    status: TransmissionStatus,
    monotonic_now: MonotonicTimestampNs,
    commit_ordinal: u64,
) {
    let input = TransmissionInput {
        command,
        status,
        monotonic_now,
    };
    let event = normalize_transmission(capture_ordinal, input).unwrap();
    assert_eq!(audit.transmissions[index], Some(event));
    let commit = audit.commits[index + 1].unwrap();
    assert_eq!(commit.commit_ordinal, commit_ordinal);
    assert_eq!(commit.route, SchedulerRoute::PriorityTransmission);
    assert_eq!(commit.capture_ordinal, capture_ordinal);
    assert_eq!(commit.commands, [None; 2]);
    commit.verify_source(event).unwrap();
}

#[test]
fn decoded_journal_control_is_rejected_before_live_reservation_or_mutation() {
    let authenticated = normalize_control_decision(
        FIRST_CAPTURE_ORDINAL,
        support::authenticated_kill(1, ConfigDigest([0xA5; 32]), Sequence(1), TimestampNs(1_100)),
    )
    .unwrap();
    let mut record = [0_u8; RECORD_LEN];
    encode_record(authenticated, &mut record).unwrap();
    let (decoded, consumed) = decode_record(&record).unwrap();
    assert_eq!(consumed, RECORD_LEN);

    assert_source_route_rejected(decoded, NativeLiveError::ControlProvenance);
}

fn assert_source_route_rejected(source_event: NormalizedEvent, expected: NativeLiveError) {
    let (mut reactor, _) = prepared_quote_reactor();
    let (reactor_before, _) = prepared_quote_reactor();
    let (mut session, mut adapter) = live_session();
    let session_before = session;
    let adapter_before = adapter;
    let operations = FixedOperationLog::new();
    let mut transport = FixedTransport::new(&operations, [sent(9_101, 2_010), sent(9_102, 2_020)]);
    let mut audit = FixedAudit::new(&operations);
    let mut scratch = NativeLiveScratch::<64>::new();
    let mut coordinator = coordinator();
    let coordinator_before = coordinator;

    assert_eq!(
        coordinator.process_event(
            source_event,
            MonotonicTimestampNs(2_000),
            &mut reactor,
            &mut session,
            &mut adapter,
            &mut transport,
            &mut audit,
            &mut scratch,
        ),
        Err(expected)
    );
    assert_eq!(coordinator, coordinator_before);
    assert!(reactor.deterministic_state_eq(&reactor_before));
    assert_eq!(session, session_before);
    assert_eq!(adapter, adapter_before);
    audit.assert_untouched();
    assert_eq!(transport.submit_count, 0);
    assert_eq!(transport.quiesce_count, 0);
    assert!(transport.contexts.iter().all(Option::is_none));
    assert!(scratch.is_clean());
}

fn assert_valid_source_route(mut reactor: TestReactor, source_event: NormalizedEvent) {
    let (mut session, mut adapter) = live_session();
    let operations = FixedOperationLog::new();
    let mut transport = FixedTransport::new(&operations, [sent(9_201, 2_010), sent(9_202, 2_020)]);
    let mut audit = FixedAudit::new(&operations);
    let mut scratch = NativeLiveScratch::<64>::new();
    let mut coordinator = coordinator();

    assert_eq!(
        coordinator
            .process_event(
                source_event,
                MonotonicTimestampNs(2_000),
                &mut reactor,
                &mut session,
                &mut adapter,
                &mut transport,
                &mut audit,
                &mut scratch,
            )
            .unwrap(),
        NativeLiveStatus::Completed(quant_hft_core::NativeLiveSummary {
            source_commit_ordinal: FIRST_COMMIT_ORDINAL,
            commands: 0,
            sent: 0,
            proven_unsent: 0,
        })
    );
    assert_eq!(audit.reserve_calls, 1);
    assert_eq!(audit.source_event_count, 1);
    assert_eq!(audit.commit_count, 1);
    assert_eq!(audit.finish_count, 1);
    assert_eq!(transport.submit_count, 0);
    assert!(scratch.is_clean());
}

fn coordinator() -> NativeLiveCoordinator {
    NativeLiveCoordinator::new(
        IDENTITY,
        instrument_definition(),
        MARKET_DATA_SOURCE,
        ORDER_ENTRY_SOURCE,
        MONOTONIC_CLOCK_EPOCH,
        FIRST_CAPTURE_ORDINAL,
        FIRST_COMMIT_ORDINAL,
    )
    .unwrap()
}

fn sent(proof: u64, monotonic_now: u64) -> NativeSubmit<u64> {
    NativeSubmit::Sent {
        proof,
        monotonic_now: MonotonicTimestampNs(monotonic_now),
    }
}

fn proven_unsent(proof: u64, monotonic_now: u64) -> NativeSubmit<u64> {
    NativeSubmit::ProvenUnsent {
        proof,
        monotonic_now: MonotonicTimestampNs(monotonic_now),
    }
}

fn ambiguous(proof: u64, monotonic_now: u64) -> NativeSubmit<u64> {
    NativeSubmit::Ambiguous {
        proof,
        monotonic_now: MonotonicTimestampNs(monotonic_now),
    }
}

fn submission_parts(
    submission: NativeSubmit<u64>,
) -> (u64, NativeSubmitDisposition, MonotonicTimestampNs) {
    match submission {
        NativeSubmit::Sent {
            proof,
            monotonic_now,
        } => (proof, NativeSubmitDisposition::Sent, monotonic_now),
        NativeSubmit::ProvenUnsent {
            proof,
            monotonic_now,
        } => (proof, NativeSubmitDisposition::ProvenUnsent, monotonic_now),
        NativeSubmit::Ambiguous {
            proof,
            monotonic_now,
        } => (proof, NativeSubmitDisposition::Ambiguous, monotonic_now),
    }
}

fn live_session() -> (VenueSession, FixedVenueAdapter) {
    live_session_with_definition(instrument_definition())
}

fn live_session_with_definition(
    definition: quant_hft_core::InstrumentDefinition,
) -> (VenueSession, FixedVenueAdapter) {
    let mut adapter = FixedVenueAdapter::default();
    let mut session =
        VenueSession::new::<FixedVenueAdapter>(Sequence(700), Sequence(1), 10_000, definition)
            .unwrap();
    session.connect(TimestampNs(10)).unwrap();
    let mut decoded = [None; 1];
    session
        .decode_inbound(&mut adapter, &[0x01], TimestampNs(30), &mut decoded)
        .unwrap();
    (session, adapter)
}

fn prepared_live_orders_ready() -> (
    TestReactor,
    VenueSession,
    FixedVenueAdapter,
    NativeLiveCoordinator,
) {
    let (mut reactor, quote_event) = prepared_quote_reactor();
    let (mut session, mut adapter) = live_session();
    let mut coordinator = coordinator();
    let mut scratch = NativeLiveScratch::<64>::new();

    let quote_commands = {
        let operations = FixedOperationLog::new();
        let mut transport = FixedTransport::new(&operations, [sent(201, 2_010), sent(202, 2_020)]);
        let mut audit = FixedAudit::new(&operations);
        assert!(matches!(
            coordinator
                .process_event(
                    quote_event,
                    MonotonicTimestampNs(2_000),
                    &mut reactor,
                    &mut session,
                    &mut adapter,
                    &mut transport,
                    &mut audit,
                    &mut scratch,
                )
                .unwrap(),
            NativeLiveStatus::Completed(_)
        ));
        let commit = audit.commits[0].unwrap();
        commit.commands.map(|slot| match slot.unwrap() {
            OrderCommand::New(order) => order,
            _ => panic!("quote fixture must publish new orders"),
        })
    };

    for (index, order) in quote_commands.into_iter().enumerate() {
        let capture_ordinal = CaptureOrdinal(5 + index as u64);
        let order_sequence = Sequence(2 + index as u64);
        let event = accepted_event(
            capture_ordinal,
            order_sequence,
            order,
            VenueOrderId(50_001 + index as u64),
            1_150 + index as u64 * 10,
        );
        let operations = FixedOperationLog::new();
        let mut transport = FixedTransport::new(&operations, [sent(203, 2_010), sent(204, 2_020)]);
        let mut audit = FixedAudit::new(&operations);
        let status = coordinator
            .process_event(
                event,
                MonotonicTimestampNs(2_030),
                &mut reactor,
                &mut session,
                &mut adapter,
                &mut transport,
                &mut audit,
                &mut scratch,
            )
            .unwrap();
        assert_eq!(
            status,
            NativeLiveStatus::Completed(quant_hft_core::NativeLiveSummary {
                source_commit_ordinal: 53 + index as u64,
                commands: 0,
                sent: 0,
                proven_unsent: 0,
            })
        );
        assert_eq!(transport.submit_count, 0);
        assert!(scratch.is_clean());
    }
    assert_eq!(coordinator.phase(), NativeLivePhase::Ready);
    assert_eq!(
        coordinator.last_source_capture_ordinal(),
        Some(CaptureOrdinal(6))
    );
    assert_eq!(
        coordinator.last_feedback_capture_ordinal(),
        Some(CaptureOrdinal(4))
    );
    assert_eq!(coordinator.last_outbound_frame_ordinal(), Some(91));
    assert_eq!(coordinator.next_commit_ordinal(), 55);
    (reactor, session, adapter, coordinator)
}

fn prepared_safety_pending() -> (
    TestReactor,
    VenueSession,
    FixedVenueAdapter,
    NativeLiveCoordinator,
) {
    let (mut reactor, mut session, mut adapter, mut coordinator) = prepared_live_orders_ready();
    let mut scratch = NativeLiveScratch::<64>::new();

    let pending_event = market_event(
        CaptureOrdinal(7),
        MarketDataMessage {
            sequence: Sequence(102),
            exchange_timestamp: TimestampNs(1_170),
            hardware_receive_timestamp: TimestampNs(1_180),
            instrument: InstrumentId(9),
            payload: MarketDataPayload::TradingStatus { status_code: 1 },
        },
    );
    {
        let operations = FixedOperationLog::new();
        let mut transport = FixedTransport::new(&operations, [sent(205, 2_010), sent(206, 2_020)]);
        let mut audit = FixedAudit::rejecting(&operations);
        assert_eq!(
            coordinator
                .process_event(
                    pending_event,
                    MonotonicTimestampNs(2_030),
                    &mut reactor,
                    &mut session,
                    &mut adapter,
                    &mut transport,
                    &mut audit,
                    &mut scratch,
                )
                .unwrap(),
            NativeLiveStatus::SafetyPending {
                reason: NativeLiveSafetyReason::AuditReservation(AuditFailure::Capacity),
            }
        );
    }
    assert!(reactor.mandatory_kill_pending());
    assert_eq!(reactor.outstanding_transmissions(), 0);
    assert_eq!(coordinator.phase(), NativeLivePhase::SafetyPending);
    assert_eq!(
        coordinator.last_source_capture_ordinal(),
        Some(CaptureOrdinal(6))
    );
    assert_eq!(
        coordinator.last_feedback_capture_ordinal(),
        Some(CaptureOrdinal(4))
    );
    assert_eq!(coordinator.last_outbound_frame_ordinal(), Some(91));
    assert_eq!(coordinator.next_commit_ordinal(), 55);
    assert!(scratch.is_clean());
    (reactor, session, adapter, coordinator)
}

fn accepted_event(
    capture_ordinal: CaptureOrdinal,
    sequence: Sequence,
    order: NewOrder,
    venue_order_id: VenueOrderId,
    monotonic: u64,
) -> NormalizedEvent {
    normalize_order_entry(
        VenueCaptureMetadata {
            venue: IDENTITY.venue,
            source: ORDER_ENTRY_SOURCE,
            capture_ordinal,
            monotonic_timestamp: MonotonicTimestampNs(monotonic),
            recovery: false,
        },
        InboundMessage {
            sequence,
            exchange_timestamp: TimestampNs(monotonic - 2),
            hardware_receive_timestamp: TimestampNs(monotonic - 1),
            payload: InboundPayload::Order(OrderEvent::Accepted(Accepted {
                client_order_id: order.client_order_id,
                venue_order_id,
                price: order.price,
                quantity: order.quantity,
            })),
        },
    )
    .unwrap()
}

fn canceled_event(
    capture_ordinal: CaptureOrdinal,
    sequence: Sequence,
    cancel: CancelOrder,
    canceled_quantity: Quantity,
    monotonic: u64,
) -> NormalizedEvent {
    normalize_order_entry(
        VenueCaptureMetadata {
            venue: IDENTITY.venue,
            source: ORDER_ENTRY_SOURCE,
            capture_ordinal,
            monotonic_timestamp: MonotonicTimestampNs(monotonic),
            recovery: false,
        },
        InboundMessage {
            sequence,
            exchange_timestamp: TimestampNs(monotonic - 2),
            hardware_receive_timestamp: TimestampNs(monotonic - 1),
            payload: InboundPayload::Order(OrderEvent::Canceled(Canceled {
                client_order_id: cancel.client_order_id,
                venue_order_id: cancel.venue_order_id,
                canceled_quantity,
                leaves_quantity: Quantity::ZERO,
            })),
        },
    )
    .unwrap()
}

fn prepared_live_orders_reactor_for_control() -> TestReactor {
    let (mut reactor, quote_event) = prepared_quote_reactor();
    let mut egress = [None; 2];
    let quote = dispatch_reactor_replay_event(&mut reactor, quote_event, &mut egress).unwrap();
    assert_eq!(quote.commands, 2);
    let commands = egress.map(|slot| slot.unwrap().command);

    for (index, command) in commands.into_iter().enumerate() {
        let feedback = normalize_transmission(
            CaptureOrdinal(100 + index as u64),
            TransmissionInput {
                command,
                status: TransmissionStatus::Sent,
                monotonic_now: MonotonicTimestampNs(1_100),
            },
        )
        .unwrap();
        let mut feedback_egress = [None; 2];
        let outcome =
            dispatch_reactor_replay_event(&mut reactor, feedback, &mut feedback_egress).unwrap();
        assert_eq!(outcome.commands, 0);
        assert!(feedback_egress.iter().all(Option::is_none));
    }

    for (index, command) in commands.into_iter().enumerate() {
        let OrderCommand::New(order) = command else {
            panic!("quote fixture must publish new orders");
        };
        let accepted = accepted_event(
            CaptureOrdinal(110 + index as u64),
            Sequence(2 + index as u64),
            order,
            VenueOrderId(60_001 + index as u64),
            1_100,
        );
        let mut accepted_egress = [None; 2];
        let outcome =
            dispatch_reactor_replay_event(&mut reactor, accepted, &mut accepted_egress).unwrap();
        assert_eq!(outcome.commands, 0);
        assert!(accepted_egress.iter().all(Option::is_none));
    }
    assert_eq!(reactor.engine().orders().order_count(), 2);
    reactor
}

fn prepared_quote_reactor() -> (TestReactor, NormalizedEvent) {
    prepared_quote_reactor_for_engine_venue(IDENTITY.venue)
}

fn prepared_quote_reactor_for_engine_venue(
    engine_venue: VenueId,
) -> (TestReactor, NormalizedEvent) {
    let mut reactor = TestReactor::new(ready_engine_for_venue(engine_venue));
    let first = market_event(
        CaptureOrdinal(1),
        MarketDataMessage {
            sequence: Sequence(100),
            exchange_timestamp: TimestampNs(1_080),
            hardware_receive_timestamp: TimestampNs(1_090),
            instrument: InstrumentId(9),
            payload: MarketDataPayload::Book(BookDelta::Add {
                order_id: quant_hft_core::MarketByOrderId(9_000),
                side: Side::Buy,
                price: PriceTicks(99),
                quantity: Quantity(100),
            }),
        },
    );
    let mut egress = [None; 2];
    let outcome = dispatch_reactor_replay_event(&mut reactor, first, &mut egress).unwrap();
    assert_eq!(outcome.commands, 0);
    assert!(egress.iter().all(Option::is_none));
    let quote = market_event(
        FIRST_CAPTURE_ORDINAL,
        MarketDataMessage {
            sequence: Sequence(101),
            exchange_timestamp: TimestampNs(1_081),
            hardware_receive_timestamp: TimestampNs(1_090),
            instrument: InstrumentId(9),
            payload: MarketDataPayload::TradingStatus { status_code: 1 },
        },
    );
    (reactor, quote)
}

fn prepared_fault_quote_reactor() -> (TestReactor, NormalizedEvent) {
    let mut reactor = TestReactor::new(ready_engine());
    let first = market_event(
        CaptureOrdinal(1),
        MarketDataMessage {
            sequence: Sequence(100),
            exchange_timestamp: TimestampNs(1_080),
            hardware_receive_timestamp: TimestampNs(1_090),
            instrument: InstrumentId(9),
            payload: MarketDataPayload::Book(BookDelta::Add {
                order_id: quant_hft_core::MarketByOrderId(9_000),
                side: Side::Buy,
                price: PriceTicks(99),
                quantity: Quantity(100),
            }),
        },
    );
    let mut egress = [None; 2];
    let outcome = dispatch_reactor_replay_event(&mut reactor, first, &mut egress).unwrap();
    assert_eq!(outcome.commands, 0);
    assert!(egress.iter().all(Option::is_none));
    let quote = market_event(
        FIRST_CAPTURE_ORDINAL,
        MarketDataMessage {
            sequence: Sequence(102),
            exchange_timestamp: TimestampNs(1_081),
            hardware_receive_timestamp: TimestampNs(1_090),
            instrument: InstrumentId(9),
            payload: MarketDataPayload::TradingStatus { status_code: 1 },
        },
    );
    (reactor, quote)
}

fn market_event(capture_ordinal: CaptureOrdinal, message: MarketDataMessage) -> NormalizedEvent {
    market_event_at(capture_ordinal, message, 1_100)
}

fn market_event_at(
    capture_ordinal: CaptureOrdinal,
    message: MarketDataMessage,
    monotonic_now: u64,
) -> NormalizedEvent {
    normalize_market_data(
        VenueCaptureMetadata {
            venue: IDENTITY.venue,
            source: MARKET_DATA_SOURCE,
            capture_ordinal,
            monotonic_timestamp: MonotonicTimestampNs(monotonic_now),
            recovery: false,
        },
        message,
    )
    .unwrap()
}

fn ready_engine() -> TestEngine {
    ready_engine_with_order_capacity::<8>()
}

fn ready_engine_for_venue(venue: VenueId) -> TestEngine {
    ready_engine_with_order_capacity_for_venue::<8>(venue)
}

fn ready_engine_with_order_capacity<const MAX_ORDERS: usize>()
-> ExecutionEngine<64, 16, MAX_ORDERS, 16, 16> {
    ready_engine_with_order_capacity_for_venue::<MAX_ORDERS>(IDENTITY.venue)
}

fn ready_engine_with_order_capacity_for_venue<const MAX_ORDERS: usize>(
    venue: VenueId,
) -> ExecutionEngine<64, 16, MAX_ORDERS, 16, 16> {
    let mut config = engine_config();
    config.venue = venue;
    config.instrument_definition.venue = venue;
    let mut engine = ExecutionEngine::<64, 16, MAX_ORDERS, 16, 16>::new(config).unwrap();
    engine
        .observe_clock(ClockSample {
            utc: TimestampNs(1_000),
            monotonic: MonotonicTimestampNs(1_000),
            uncertainty_ns: 10,
        })
        .unwrap();
    let mut output = [None; 2];
    for (monotonic, payload) in [
        (
            1_010,
            SnapshotPayload::Begin {
                snapshot_id: 1,
                last_incremental_sequence: Sequence(99),
            },
        ),
        (
            1_020,
            SnapshotPayload::Order(SnapshotOrder {
                instrument: InstrumentId(9),
                order_id: quant_hft_core::MarketByOrderId(9_001),
                side: Side::Sell,
                price: PriceTicks(101),
                quantity: Quantity(100),
            }),
        ),
        (
            1_030,
            SnapshotPayload::End {
                snapshot_id: 1,
                last_incremental_sequence: Sequence(99),
            },
        ),
    ] {
        engine
            .on_snapshot(
                SnapshotMessage {
                    exchange_timestamp: TimestampNs(monotonic - 5),
                    hardware_receive_timestamp: TimestampNs(monotonic),
                    payload,
                },
                MonotonicTimestampNs(monotonic),
                &mut output,
            )
            .unwrap();
    }
    engine
        .on_order_entry(
            InboundMessage {
                sequence: Sequence(1),
                exchange_timestamp: TimestampNs(1_035),
                hardware_receive_timestamp: TimestampNs(1_040),
                payload: InboundPayload::Session(SessionEvent::LogonAccepted),
            },
            MonotonicTimestampNs(1_040),
            &mut output,
        )
        .unwrap();
    engine
        .apply_control_decision(
            support::authenticated_arm(
                1,
                ConfigDigest([0xA5; 32]),
                Sequence(1),
                TimestampNs(1_050),
                TimestampNs(u64::MAX),
            ),
            &mut output,
        )
        .unwrap();
    engine
}

fn engine_config() -> EngineConfig {
    EngineConfig {
        venue: IDENTITY.venue,
        instrument: InstrumentId(9),
        first_market_sequence: Sequence(100),
        first_order_sequence: Sequence(1),
        first_client_order_id: ClientOrderId(10_000),
        first_risk_order_id: OrderId(20_000),
        instrument_definition: support::instrument_definition(IDENTITY.venue, InstrumentId(9)),
        max_clock_uncertainty_ns: 1_000,
        max_clock_offset_step_ns: 100,
        max_clock_holdover_ns: 100_000,
        clock_drift_parts_per_billion: 10,
        risk_session: RiskSessionId(1),
        risk_definition: InstrumentRiskDefinition {
            instrument: InstrumentId(9),
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

fn write_new_order(output: &mut [u8], sequence: Sequence, order: NewOrder) {
    output[0] = 0x20;
    write_u64(output, 1, sequence.0);
    write_u64(output, 9, order.client_order_id.0);
    write_u32(output, 17, order.instrument.0);
    output[21] = order.side as u8;
    write_i64(output, 22, order.price.0);
    write_i64(output, 30, order.quantity.0);
    output[38] = order.time_in_force as u8;
    write_u64(output, 39, order.created_at.0);
}

fn write_cancel(output: &mut [u8], sequence: Sequence, cancel: CancelOrder) {
    output[0] = 0x21;
    write_u64(output, 1, sequence.0);
    write_u64(output, 9, cancel.client_order_id.0);
    write_u64(output, 17, cancel.venue_order_id.0);
    write_u64(output, 25, cancel.created_at.0);
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

fn read_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(input[offset..offset + 8].try_into().unwrap())
}

#[test]
fn fixture_wire_layout_matches_post_only_new_orders() {
    let order = NewOrder {
        client_order_id: ClientOrderId(1),
        instrument: InstrumentId(9),
        side: Side::Buy,
        price: PriceTicks(100),
        quantity: Quantity(10),
        time_in_force: TimeInForce::PostOnly,
        created_at: TimestampNs(1_000),
    };
    let mut wire = [0_u8; WIRE_LEN];
    write_new_order(&mut wire, Sequence(700), order);
    assert_eq!(wire[0], 0x20);
    assert_eq!(read_u64(&wire, 1), 700);
    assert_eq!(wire[38], TimeInForce::PostOnly as u8);
}
