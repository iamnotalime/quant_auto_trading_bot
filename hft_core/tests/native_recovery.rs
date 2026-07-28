use quant_hft_core::audit_container::{
    AUDIT_CONTAINER_HEADER_LEN, AUDIT_CONTAINER_SEAL_LEN, AuditAnchor, AuditAuthenticator,
    AuditContainerHeader, AuditContainerId, AuditContainerWriter, AuditPredecessor,
    AuditRecordKind, AuditTag, VerifiedAuditContainer, audit_record_len, verify_audit_container,
};
use quant_hft_core::control::ConfigDigest;
use quant_hft_core::events::{CaptureOrdinal, EventSource, SequenceDomain, SessionEpoch, SourceId};
use quant_hft_core::native_audit_codec::{
    NATIVE_AUDIT_RECORD_HEADER_LEN, NATIVE_LIVE_CHECKPOINT_RECORD_LEN, NativeAuditCodecError,
    encode_native_live_checkpoint_record,
};
use quant_hft_core::native_live::{NativeLiveCheckpoint, NativeLivePhase};
use quant_hft_core::native_recovery::{
    NativeLiveCheckpointHeaderField, NativeLiveRecordedNonRunnablePhase,
    NativeLiveRecordedRunnablePhase, NativeLiveRecoveryCheckpointError, NativeLiveRecoveryEvidence,
    NativeLiveRecoveryRequirement, NativeLiveRecoveryScanError, NativeLiveTrailingRecordKind,
    scan_native_live_recovery,
};
use quant_hft_core::reference_data::{
    InstrumentDefinitionBinding, NativeProductId, ReferenceDataAuthorityId, ReferenceDataDigest,
};
use quant_hft_core::types::{InstrumentId, VenueId};
use quant_hft_core::venue::{ProtocolId, SessionId, VenueIdentity};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

const ALGORITHM_ID: u32 = 0x5245_434F;
const KEY_ID: u64 = 0x5645_5259;
const FIRST_RECORD_ORDINAL: u64 = 81;
const SCOPE_TICKET: u64 = 44;

#[derive(Debug)]
struct CountingAllocator;

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

// SAFETY: every operation is forwarded unchanged to `System`; the thread-local
// counter observes calls without changing pointer, layout, or lifetime semantics.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_allocation();
        // SAFETY: the caller supplies the `GlobalAlloc` contract and the layout is
        // forwarded unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the pointer and layout came from the forwarded system allocation.
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_allocation();
        // SAFETY: the caller supplies the contract and the layout is forwarded.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count_allocation();
        // SAFETY: all arguments are forwarded unchanged to the system allocator.
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestAuthError {
    Rejected,
}

#[derive(Clone, Copy, Debug)]
struct TestAuthenticator {
    key: [u64; 4],
}

impl TestAuthenticator {
    const fn new() -> Self {
        Self {
            key: [
                0x87cd_91ef_ba16_52a1,
                0x2d1e_d17f_a11d_17ed,
                0x4c49_5645_5245_434f,
                0xa311_c470_5ea1_0001,
            ],
        }
    }

    fn tag(self, message: &[u8]) -> AuditTag {
        let mut lanes = self.key;
        for (index, byte) in message.iter().copied().enumerate() {
            let lane = index & 3;
            let position = u64::try_from(index).expect("test input length fits u64");
            lanes[lane] ^= u64::from(byte).wrapping_add(position.rotate_left(11));
            lanes[lane] = lanes[lane]
                .rotate_left(19)
                .wrapping_mul(0x9e37_79b1_85eb_ca87);
        }
        let mut output = [0_u8; 32];
        for (index, lane) in lanes.into_iter().enumerate() {
            let offset = index * 8;
            output[offset..offset + 8].copy_from_slice(&lane.to_le_bytes());
        }
        AuditTag(output)
    }
}

impl AuditAuthenticator for TestAuthenticator {
    type Error = TestAuthError;

    fn algorithm_id(&self) -> u32 {
        ALGORITHM_ID
    }

    fn key_id(&self) -> u64 {
        KEY_ID
    }

    fn authenticate(&mut self, message: &[u8]) -> Result<AuditTag, Self::Error> {
        Ok(self.tag(message))
    }

    fn verify(&mut self, message: &[u8], tag: AuditTag) -> Result<(), Self::Error> {
        if self.tag(message) == tag {
            Ok(())
        } else {
            Err(TestAuthError::Rejected)
        }
    }
}

fn header() -> AuditContainerHeader {
    AuditContainerHeader {
        algorithm_id: ALGORITHM_ID,
        key_id: KEY_ID,
        container_id: AuditContainerId([0x47; 16]),
        generation: 1,
        first_record_ordinal: FIRST_RECORD_ORDINAL,
        monotonic_clock_epoch: 55,
        config_digest: ConfigDigest([0xC3; 32]),
        software_digest: [0x5A; 32],
        venue_identity: VenueIdentity {
            venue: VenueId(7),
            market_data_protocol: ProtocolId(11),
            order_entry_protocol: ProtocolId(12),
            session: SessionId(13),
        },
        market_data_source: EventSource::new(
            SourceId::new(11, 21),
            SequenceDomain::MarketData,
            SessionEpoch(31),
        ),
        order_entry_source: EventSource::new(
            SourceId::new(12, 22),
            SequenceDomain::OrderEntry,
            SessionEpoch(32),
        ),
        drop_copy_source: Some(EventSource::new(
            SourceId::new(13, 23),
            SequenceDomain::DropCopy,
            SessionEpoch(33),
        )),
        instrument_definition_binding: InstrumentDefinitionBinding {
            venue: VenueId(7),
            instrument: InstrumentId(42),
            native_product: NativeProductId(0xB7C),
            authority: ReferenceDataAuthorityId(91),
            reference_data_version: 4,
            reference_data_digest: ReferenceDataDigest([0x6D; 32]),
        },
        predecessor: None,
    }
}

fn rotated_header() -> AuditContainerHeader {
    let mut current = header();
    current.container_id = AuditContainerId([0x48; 16]);
    current.generation = 2;
    current.predecessor = Some(AuditPredecessor {
        container_id: AuditContainerId([0x47; 16]),
        generation: 1,
        seal_tag: AuditTag([0xA7; 32]),
    });
    current
}

fn checkpoint(header: AuditContainerHeader, phase: NativeLivePhase) -> NativeLiveCheckpoint {
    NativeLiveCheckpoint {
        expected_identity: header.venue_identity,
        expected_instrument_binding: header.instrument_definition_binding,
        expected_market_data_source: header.market_data_source,
        expected_order_entry_source: header.order_entry_source,
        expected_drop_copy_source: header.drop_copy_source,
        monotonic_clock_epoch: header.monotonic_clock_epoch,
        expected_first_source_capture: CaptureOrdinal(100),
        last_source_capture: Some(CaptureOrdinal(102)),
        last_feedback_capture: Some(CaptureOrdinal(103)),
        last_outbound_frame: Some(61),
        next_commit_ordinal: 19,
        phase,
    }
}

fn encode_checkpoint(
    scope_ticket: u64,
    value: NativeLiveCheckpoint,
) -> [u8; NATIVE_LIVE_CHECKPOINT_RECORD_LEN] {
    let mut output = [0_u8; NATIVE_LIVE_CHECKPOINT_RECORD_LEN];
    let written = encode_native_live_checkpoint_record(scope_ticket, value, &mut output).unwrap();
    assert_eq!(written, output.len());
    output
}

fn build(
    expected_header: &AuditContainerHeader,
    records: &[(AuditRecordKind, &[u8])],
) -> (Vec<u8>, AuditAnchor) {
    let mut authenticator = TestAuthenticator::new();
    let mut header_bytes = [0_u8; AUDIT_CONTAINER_HEADER_LEN];
    let mut writer =
        AuditContainerWriter::begin(expected_header, &mut authenticator, &mut header_bytes)
            .unwrap();
    let mut bytes = header_bytes.to_vec();
    for (kind, payload) in records {
        let mut output = vec![0_u8; audit_record_len(payload.len()).unwrap()];
        let written = writer
            .append(*kind, payload, &mut authenticator, &mut output)
            .unwrap();
        assert_eq!(written, output.len());
        bytes.extend_from_slice(&output);
    }
    let mut seal = [0_u8; AUDIT_CONTAINER_SEAL_LEN];
    let anchor = writer.seal(&mut authenticator, &mut seal).unwrap();
    bytes.extend_from_slice(&seal);
    (bytes, anchor)
}

fn verified<'a>(
    bytes: &'a [u8],
    expected_header: &AuditContainerHeader,
    anchor: AuditAnchor,
) -> VerifiedAuditContainer<'a> {
    verify_audit_container(
        bytes,
        expected_header,
        anchor,
        &mut TestAuthenticator::new(),
    )
    .unwrap()
}

fn scan_one(
    expected_header: AuditContainerHeader,
    payload: &[u8],
) -> Result<NativeLiveRecoveryEvidence, NativeLiveRecoveryScanError> {
    let (bytes, anchor) = build(
        &expected_header,
        &[(AuditRecordKind::LIVE_CHECKPOINT, payload)],
    );
    scan_native_live_recovery(verified(&bytes, &expected_header, anchor))
}

#[test]
fn every_recorded_phase_maps_only_to_a_stronger_non_authorizing_requirement() {
    let expected_header = header();
    let cases = [
        (
            NativeLivePhase::Ready,
            NativeLiveRecoveryRequirement::OwnedReplayRequired(
                NativeLiveRecordedRunnablePhase::Ready,
            ),
        ),
        (
            NativeLivePhase::SafetyPending,
            NativeLiveRecoveryRequirement::OwnedReplayRequired(
                NativeLiveRecordedRunnablePhase::SafetyPending,
            ),
        ),
        (
            NativeLivePhase::KilledRecovery,
            NativeLiveRecoveryRequirement::OwnedReplayRequired(
                NativeLiveRecordedRunnablePhase::KilledRecovery,
            ),
        ),
        (
            NativeLivePhase::Ambiguous,
            NativeLiveRecoveryRequirement::ManualReconciliation(
                NativeLiveRecordedNonRunnablePhase::Ambiguous,
            ),
        ),
        (
            NativeLivePhase::Failed,
            NativeLiveRecoveryRequirement::ManualReconciliation(
                NativeLiveRecordedNonRunnablePhase::Failed,
            ),
        ),
    ];

    for (phase, requirement) in cases {
        let recorded_checkpoint = checkpoint(expected_header, phase);
        let payload = encode_checkpoint(SCOPE_TICKET, recorded_checkpoint);
        let (bytes, anchor) = build(
            &expected_header,
            &[(AuditRecordKind::LIVE_CHECKPOINT, &payload)],
        );
        let evidence =
            scan_native_live_recovery(verified(&bytes, &expected_header, anchor)).unwrap();

        assert_eq!(evidence.header, expected_header);
        assert_eq!(evidence.anchor, anchor);
        assert_eq!(evidence.scope_ticket, SCOPE_TICKET);
        assert_eq!(evidence.checkpoint_record_ordinal, FIRST_RECORD_ORDINAL);
        assert_eq!(evidence.recorded_checkpoint, recorded_checkpoint);
        assert_eq!(evidence.requirement, requirement);
    }
}

#[test]
fn scope_ticket_zero_is_preserved_because_the_current_ticket_contract_allows_it() {
    let expected_header = header();
    let payload = encode_checkpoint(0, checkpoint(expected_header, NativeLivePhase::Failed));
    let evidence = scan_one(expected_header, &payload).unwrap();
    assert_eq!(evidence.scope_ticket, 0);
}

#[test]
fn rotated_container_is_rejected_before_local_checkpoint_or_intent_is_considered() {
    let expected_header = rotated_header();
    let payload = encode_checkpoint(
        SCOPE_TICKET,
        checkpoint(expected_header, NativeLivePhase::Failed),
    );
    let expected_error = NativeLiveRecoveryScanError::PredecessorHistoryUnverified {
        current_generation: 2,
        predecessor_container_id: AuditContainerId([0x47; 16]),
        predecessor_generation: 1,
    };

    let (checkpoint_bytes, checkpoint_anchor) = build(
        &expected_header,
        &[(AuditRecordKind::LIVE_CHECKPOINT, &payload)],
    );
    assert_eq!(
        scan_native_live_recovery(verified(
            &checkpoint_bytes,
            &expected_header,
            checkpoint_anchor,
        )),
        Err(expected_error)
    );

    let (intent_bytes, intent_anchor) = build(
        &expected_header,
        &[
            (AuditRecordKind::NATIVE_INTENT, b"local-intent".as_slice()),
            (AuditRecordKind::LIVE_CHECKPOINT, payload.as_slice()),
        ],
    );
    assert_eq!(
        scan_native_live_recovery(verified(&intent_bytes, &expected_header, intent_anchor,)),
        Err(expected_error)
    );
}

#[test]
fn scanner_function_consumes_the_verified_container_by_value() {
    type ScanFunction =
        for<'a> fn(
            VerifiedAuditContainer<'a>,
        ) -> Result<NativeLiveRecoveryEvidence, NativeLiveRecoveryScanError>;
    let scanner: ScanFunction = scan_native_live_recovery;
    let _ = scanner;
}

#[test]
fn empty_multiple_and_nonfinal_checkpoint_histories_are_rejected() {
    let expected_header = header();
    let payload = encode_checkpoint(
        SCOPE_TICKET,
        checkpoint(expected_header, NativeLivePhase::Failed),
    );

    let (empty_bytes, empty_anchor) = build(&expected_header, &[]);
    assert_eq!(
        scan_native_live_recovery(verified(&empty_bytes, &expected_header, empty_anchor)),
        Err(NativeLiveRecoveryScanError::MissingCheckpoint)
    );

    let (multiple_bytes, multiple_anchor) = build(
        &expected_header,
        &[
            (AuditRecordKind::LIVE_CHECKPOINT, payload.as_slice()),
            (AuditRecordKind::LIVE_CHECKPOINT, payload.as_slice()),
        ],
    );
    assert_eq!(
        scan_native_live_recovery(verified(&multiple_bytes, &expected_header, multiple_anchor,)),
        Err(NativeLiveRecoveryScanError::MultipleCheckpoints {
            first_ordinal: FIRST_RECORD_ORDINAL,
            second_ordinal: FIRST_RECORD_ORDINAL + 1,
        })
    );

    let (known_bytes, known_anchor) = build(
        &expected_header,
        &[
            (AuditRecordKind::LIVE_CHECKPOINT, payload.as_slice()),
            (AuditRecordKind::FAULT, b"fault"),
        ],
    );
    assert_eq!(
        scan_native_live_recovery(verified(&known_bytes, &expected_header, known_anchor)),
        Err(NativeLiveRecoveryScanError::CheckpointNotFinal {
            checkpoint_ordinal: FIRST_RECORD_ORDINAL,
            following_ordinal: FIRST_RECORD_ORDINAL + 1,
            following_kind: NativeLiveTrailingRecordKind::KnownUnsupported(AuditRecordKind::FAULT,),
        })
    );

    let unknown_kind = AuditRecordKind(77);
    let (unknown_bytes, unknown_anchor) = build(
        &expected_header,
        &[
            (AuditRecordKind::LIVE_CHECKPOINT, payload.as_slice()),
            (unknown_kind, b"future"),
        ],
    );
    assert_eq!(
        scan_native_live_recovery(verified(&unknown_bytes, &expected_header, unknown_anchor,)),
        Err(NativeLiveRecoveryScanError::CheckpointNotFinal {
            checkpoint_ordinal: FIRST_RECORD_ORDINAL,
            following_ordinal: FIRST_RECORD_ORDINAL + 1,
            following_kind: NativeLiveTrailingRecordKind::Unknown(77),
        })
    );
}

#[test]
fn all_other_known_kinds_and_unknown_kinds_are_categorized_before_checkpoint() {
    let expected_header = header();
    let payload = encode_checkpoint(
        SCOPE_TICKET,
        checkpoint(expected_header, NativeLivePhase::Failed),
    );
    let unsupported = [
        AuditRecordKind::NORMALIZED_EVENT,
        AuditRecordKind::SCHEDULER_COMMIT,
        AuditRecordKind::NATIVE_INGRESS,
        AuditRecordKind::NATIVE_DISPOSITION,
        AuditRecordKind::ABORTED_RESERVATION,
        AuditRecordKind::FAULT,
    ];

    for kind in unsupported {
        let (bytes, anchor) = build(
            &expected_header,
            &[
                (kind, b"unsupported"),
                (AuditRecordKind::LIVE_CHECKPOINT, payload.as_slice()),
            ],
        );
        assert_eq!(
            scan_native_live_recovery(verified(&bytes, &expected_header, anchor)),
            Err(NativeLiveRecoveryScanError::UnsupportedRecord {
                record_ordinal: FIRST_RECORD_ORDINAL,
                kind,
            })
        );
    }

    let unknown = AuditRecordKind(91);
    let (bytes, anchor) = build(
        &expected_header,
        &[
            (unknown, b"unknown"),
            (AuditRecordKind::LIVE_CHECKPOINT, payload.as_slice()),
        ],
    );
    assert_eq!(
        scan_native_live_recovery(verified(&bytes, &expected_header, anchor)),
        Err(NativeLiveRecoveryScanError::UnknownRecordKind {
            record_ordinal: FIRST_RECORD_ORDINAL,
            kind: 91,
        })
    );
}

#[test]
fn any_native_intent_is_sticky_and_never_cleared_by_an_outer_disposition() {
    let expected_header = header();
    let payload = encode_checkpoint(
        SCOPE_TICKET,
        checkpoint(expected_header, NativeLivePhase::Ambiguous),
    );
    let cases: &[&[(AuditRecordKind, &[u8])]] = &[
        &[(AuditRecordKind::NATIVE_INTENT, b"intent")],
        &[
            (AuditRecordKind::NATIVE_INTENT, b"intent"),
            (AuditRecordKind::NATIVE_DISPOSITION, b"apparent-disposition"),
            (AuditRecordKind::LIVE_CHECKPOINT, payload.as_slice()),
        ],
        &[
            (AuditRecordKind::LIVE_CHECKPOINT, payload.as_slice()),
            (AuditRecordKind::NATIVE_INTENT, b"late-intent"),
        ],
        &[
            (AuditRecordKind(90), b"unknown-first"),
            (AuditRecordKind::NATIVE_INTENT, b"intent"),
            (AuditRecordKind::LIVE_CHECKPOINT, payload.as_slice()),
        ],
        &[
            (AuditRecordKind::NATIVE_INTENT, b"first-intent"),
            (AuditRecordKind::NATIVE_INTENT, b"second-intent"),
        ],
    ];

    for (case_index, records) in cases.iter().enumerate() {
        let (bytes, anchor) = build(&expected_header, records);
        let expected_ordinal = if case_index == 2 || case_index == 3 {
            FIRST_RECORD_ORDINAL + 1
        } else {
            FIRST_RECORD_ORDINAL
        };
        assert_eq!(
            scan_native_live_recovery(verified(&bytes, &expected_header, anchor)),
            Err(NativeLiveRecoveryScanError::UnfinishedIntent {
                record_ordinal: expected_ordinal,
            })
        );
    }
}

#[test]
fn malformed_noncanonical_and_unsupported_checkpoint_payloads_are_rejected() {
    let expected_header = header();
    assert_eq!(
        scan_one(expected_header, b"bad"),
        Err(NativeLiveRecoveryScanError::CheckpointPayload {
            record_ordinal: FIRST_RECORD_ORDINAL,
            error: NativeAuditCodecError::Truncated {
                required: NATIVE_AUDIT_RECORD_HEADER_LEN,
                available: 3,
            },
        })
    );

    let canonical = encode_checkpoint(
        SCOPE_TICKET,
        checkpoint(expected_header, NativeLivePhase::Failed),
    );

    let mut unsupported_version = canonical;
    unsupported_version[4..6].copy_from_slice(&2_u16.to_le_bytes());
    assert_eq!(
        scan_one(expected_header, &unsupported_version),
        Err(NativeLiveRecoveryScanError::CheckpointPayload {
            record_ordinal: FIRST_RECORD_ORDINAL,
            error: NativeAuditCodecError::UnsupportedVersion(2),
        })
    );

    let mut unsupported_variant = canonical;
    unsupported_variant[20..22].copy_from_slice(&2_u16.to_le_bytes());
    assert_eq!(
        scan_one(expected_header, &unsupported_variant),
        Err(NativeLiveRecoveryScanError::CheckpointPayload {
            record_ordinal: FIRST_RECORD_ORDINAL,
            error: NativeAuditCodecError::InvalidVariant(2),
        })
    );

    let mut trailing = [0_u8; NATIVE_LIVE_CHECKPOINT_RECORD_LEN + 1];
    trailing[..NATIVE_LIVE_CHECKPOINT_RECORD_LEN].copy_from_slice(&canonical);
    assert_eq!(
        scan_one(expected_header, &trailing),
        Err(NativeLiveRecoveryScanError::CheckpointPayload {
            record_ordinal: FIRST_RECORD_ORDINAL,
            error: NativeAuditCodecError::TrailingBytes(1),
        })
    );

    let mut bad_checksum = canonical;
    let last = bad_checksum.len() - 1;
    bad_checksum[last] ^= 0x80;
    assert!(matches!(
        scan_one(expected_header, &bad_checksum),
        Err(NativeLiveRecoveryScanError::CheckpointPayload {
            record_ordinal: FIRST_RECORD_ORDINAL,
            error: NativeAuditCodecError::ChecksumMismatch { .. },
        })
    ));
}

#[test]
fn every_checkpoint_identity_field_is_bound_to_the_authenticated_header() {
    let expected_header = header();
    let base = checkpoint(expected_header, NativeLivePhase::Failed);

    let mut identity = base;
    identity.expected_identity.session = SessionId(999);
    let mut binding = base;
    binding.expected_instrument_binding.reference_data_version += 1;
    let mut market_data = base;
    market_data.expected_market_data_source.id.channel += 1;
    let mut order_entry = base;
    order_entry.expected_order_entry_source.session_epoch.0 += 1;
    let mut drop_copy = base;
    drop_copy.expected_drop_copy_source = None;
    let mut clock = base;
    clock.monotonic_clock_epoch += 1;

    let cases = [
        (identity, NativeLiveCheckpointHeaderField::VenueIdentity),
        (
            binding,
            NativeLiveCheckpointHeaderField::InstrumentDefinitionBinding,
        ),
        (
            market_data,
            NativeLiveCheckpointHeaderField::MarketDataSource,
        ),
        (
            order_entry,
            NativeLiveCheckpointHeaderField::OrderEntrySource,
        ),
        (drop_copy, NativeLiveCheckpointHeaderField::DropCopySource),
        (clock, NativeLiveCheckpointHeaderField::MonotonicClockEpoch),
    ];

    for (value, field) in cases {
        let payload = encode_checkpoint(SCOPE_TICKET, value);
        assert_eq!(
            scan_one(expected_header, &payload),
            Err(NativeLiveRecoveryScanError::InvalidCheckpoint {
                record_ordinal: FIRST_RECORD_ORDINAL,
                error: NativeLiveRecoveryCheckpointError::HeaderMismatch(field),
            })
        );
    }
}

#[test]
fn checkpoint_cursor_invariants_are_validated_without_runtime_owners() {
    let expected_header = header();
    let base = checkpoint(expected_header, NativeLivePhase::Failed);

    let mut first_zero = base;
    first_zero.expected_first_source_capture = CaptureOrdinal(0);
    let mut source_before_first = base;
    source_before_first.last_source_capture = Some(CaptureOrdinal(99));
    let mut exhausted_frame = base;
    exhausted_frame.last_outbound_frame = Some(u64::MAX);
    let mut zero_commit = base;
    zero_commit.next_commit_ordinal = 0;

    let cases = [
        (
            first_zero,
            NativeLiveRecoveryCheckpointError::InvalidExpectedFirstSourceCapture(CaptureOrdinal(0)),
        ),
        (
            source_before_first,
            NativeLiveRecoveryCheckpointError::InvalidLastSourceCapture {
                expected_at_least: CaptureOrdinal(100),
                actual: CaptureOrdinal(99),
            },
        ),
        (
            exhausted_frame,
            NativeLiveRecoveryCheckpointError::InvalidLastOutboundFrame(u64::MAX),
        ),
        (
            zero_commit,
            NativeLiveRecoveryCheckpointError::InvalidNextCommitOrdinal(0),
        ),
    ];

    for (value, error) in cases {
        let payload = encode_checkpoint(SCOPE_TICKET, value);
        assert_eq!(
            scan_one(expected_header, &payload),
            Err(NativeLiveRecoveryScanError::InvalidCheckpoint {
                record_ordinal: FIRST_RECORD_ORDINAL,
                error,
            })
        );
    }
}

#[test]
fn authenticated_scan_performs_no_heap_allocation() {
    // Initialize the thread-local allocator counters before entering the measured
    // section so TLS setup itself cannot contaminate the result.
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(false));
    ALLOCATIONS.with(|allocations| allocations.set(0));

    let expected_header = header();
    let payload = encode_checkpoint(
        SCOPE_TICKET,
        checkpoint(expected_header, NativeLivePhase::Failed),
    );
    let (bytes, anchor) = build(
        &expected_header,
        &[(AuditRecordKind::LIVE_CHECKPOINT, &payload)],
    );
    let container = verified(&bytes, &expected_header, anchor);

    let rotated = rotated_header();
    let rotated_payload =
        encode_checkpoint(SCOPE_TICKET, checkpoint(rotated, NativeLivePhase::Failed));
    let (rotated_bytes, rotated_anchor) = build(
        &rotated,
        &[(AuditRecordKind::LIVE_CHECKPOINT, &rotated_payload)],
    );
    let rotated_container = verified(&rotated_bytes, &rotated, rotated_anchor);

    TRACK_ALLOCATIONS.with(|tracking| tracking.set(true));
    let result = scan_native_live_recovery(container);
    let rotated_result = scan_native_live_recovery(rotated_container);
    TRACK_ALLOCATIONS.with(|tracking| tracking.set(false));
    let allocations = ALLOCATIONS.with(Cell::get);

    assert!(result.is_ok());
    assert!(matches!(
        rotated_result,
        Err(NativeLiveRecoveryScanError::PredecessorHistoryUnverified { .. })
    ));
    assert_eq!(allocations, 0, "native recovery scan allocated");
}
