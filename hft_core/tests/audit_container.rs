use quant_hft_core::audit_container::{
    AUDIT_CONTAINER_HEADER_LEN, AUDIT_CONTAINER_SEAL_LEN, AUDIT_RECORD_PREFIX_LEN, AuditAnchor,
    AuditAuthenticator, AuditContainerError, AuditContainerHeader, AuditContainerId,
    AuditContainerWriter, AuditHeaderError, AuditRecordKind, AuditTag, audit_record_len,
    verify_audit_container,
};
use quant_hft_core::control::ConfigDigest;
use quant_hft_core::events::{
    CaptureOrdinal, EventKind, EventSide, EventSource, NormalizedEvent, SequenceDomain,
    SessionEpoch, SourceId,
};
use quant_hft_core::journal::{RECORD_LEN, crc32c, encode_record};
use quant_hft_core::reference_data::{
    InstrumentDefinitionBinding, NativeProductId, ReferenceDataAuthorityId, ReferenceDataDigest,
};
use quant_hft_core::venue::{ProtocolId, SessionId, VenueIdentity};
use quant_hft_core::{
    EventHeader, InstrumentId, OrderId, PriceTicks, Quantity, Sequence, TimestampNs, VenueId,
};

const ALGORITHM_ID: u32 = 0x5445_5354;
const KEY_ID: u64 = 0x00A1_1D17;
const FIRST_ORDINAL: u64 = 41;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestAuthError {
    Rejected,
}

/// Deterministic test double only. It deliberately is not exported by the library and
/// is not a cryptographic construction.
#[derive(Clone, Copy, Debug)]
struct TestAuthenticator {
    key: [u64; 4],
}

impl TestAuthenticator {
    const fn new() -> Self {
        Self {
            key: [
                0x71f0_a15e_1d61_5eed,
                0x0ddc_0ffe_e15e_5eed,
                0xd15c_a4d5_a11d_17ed,
                0xfeed_face_cafe_beef,
            ],
        }
    }

    fn tag(self, message: &[u8]) -> AuditTag {
        let mut lanes = self.key;
        for (index, byte) in message.iter().copied().enumerate() {
            let lane = index & 3;
            lanes[lane] ^= u64::from(byte).wrapping_add(
                u64::try_from(index)
                    .expect("test input index is a u64")
                    .rotate_left(u32::try_from(lane + 7).expect("lane is a u32")),
            );
            lanes[lane] = lanes[lane]
                .rotate_left(17)
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

fn header(
    id_byte: u8,
    generation: u64,
    predecessor: Option<quant_hft_core::AuditPredecessor>,
) -> AuditContainerHeader {
    AuditContainerHeader {
        algorithm_id: ALGORITHM_ID,
        key_id: KEY_ID,
        container_id: AuditContainerId([id_byte; 16]),
        generation,
        first_record_ordinal: FIRST_ORDINAL,
        monotonic_clock_epoch: 9,
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
        predecessor,
    }
}

fn build(
    header: &AuditContainerHeader,
    records: &[(AuditRecordKind, &[u8])],
) -> (Vec<u8>, AuditAnchor) {
    let mut authenticator = TestAuthenticator::new();
    let mut header_bytes = [0_u8; AUDIT_CONTAINER_HEADER_LEN];
    let mut writer =
        AuditContainerWriter::begin(header, &mut authenticator, &mut header_bytes).unwrap();
    let mut bytes = header_bytes.to_vec();
    for (kind, payload) in records {
        let mut record = vec![0_u8; audit_record_len(payload.len()).unwrap()];
        let written = writer
            .append(*kind, payload, &mut authenticator, &mut record)
            .unwrap();
        assert_eq!(written, record.len());
        bytes.extend_from_slice(&record);
    }
    let mut seal = [0_u8; AUDIT_CONTAINER_SEAL_LEN];
    let anchor = writer.seal(&mut authenticator, &mut seal).unwrap();
    bytes.extend_from_slice(&seal);
    (bytes, anchor)
}

#[test]
fn exact_header_chain_records_and_external_anchor_round_trip() {
    let expected_header = header(1, 1, None);
    let records = [
        (AuditRecordKind::NORMALIZED_EVENT, b"event-one".as_slice()),
        (AuditRecordKind::SCHEDULER_COMMIT, b"commit-two".as_slice()),
        (AuditRecordKind::LIVE_CHECKPOINT, b"checkpoint".as_slice()),
    ];
    let (bytes, anchor) = build(&expected_header, &records);
    let verified = verify_audit_container(
        &bytes,
        &expected_header,
        anchor,
        &mut TestAuthenticator::new(),
    )
    .unwrap();

    assert_eq!(verified.header(), &expected_header);
    assert_eq!(verified.anchor(), anchor);
    let observed: Vec<_> = verified.records().collect();
    assert_eq!(observed.len(), 3);
    assert_eq!(observed[0].ordinal, FIRST_ORDINAL);
    assert_eq!(observed[0].payload, b"event-one");
    assert_eq!(observed[1].ordinal, FIRST_ORDINAL + 1);
    assert_eq!(observed[1].payload, b"commit-two");
    assert_eq!(observed[2].ordinal, FIRST_ORDINAL + 2);
    assert_eq!(observed[2].payload, b"checkpoint");

    let mut wrong_header = expected_header;
    wrong_header.config_digest = ConfigDigest([0xC4; 32]);
    assert_eq!(
        verify_audit_container(&bytes, &wrong_header, anchor, &mut TestAuthenticator::new())
            .unwrap_err(),
        AuditContainerError::HeaderMismatch
    );

    let mut wrong_drop_copy = expected_header;
    wrong_drop_copy
        .drop_copy_source
        .as_mut()
        .unwrap()
        .session_epoch = SessionEpoch(34);
    assert_eq!(
        verify_audit_container(
            &bytes,
            &wrong_drop_copy,
            anchor,
            &mut TestAuthenticator::new()
        )
        .unwrap_err(),
        AuditContainerError::HeaderMismatch
    );

    let mut wrong_definition = expected_header;
    wrong_definition
        .instrument_definition_binding
        .reference_data_digest = ReferenceDataDigest([0x6E; 32]);
    assert_eq!(
        verify_audit_container(
            &bytes,
            &wrong_definition,
            anchor,
            &mut TestAuthenticator::new()
        )
        .unwrap_err(),
        AuditContainerError::HeaderMismatch
    );
}

#[test]
fn optional_drop_copy_and_reference_binding_have_canonical_wire_identity() {
    let mut expected_header = header(1, 1, None);
    expected_header.drop_copy_source = None;
    let (bytes, anchor) = build(
        &expected_header,
        &[(AuditRecordKind::LIVE_CHECKPOINT, b"checkpoint")],
    );
    assert!(
        verify_audit_container(
            &bytes,
            &expected_header,
            anchor,
            &mut TestAuthenticator::new()
        )
        .is_ok()
    );

    let header_tag_offset = AUDIT_CONTAINER_HEADER_LEN - 32;
    let mut partial_optional_source = bytes.clone();
    partial_optional_source[200] = 13;
    let tag = TestAuthenticator::new().tag(&partial_optional_source[..header_tag_offset]);
    partial_optional_source[header_tag_offset..AUDIT_CONTAINER_HEADER_LEN].copy_from_slice(&tag.0);
    assert_eq!(
        verify_audit_container(
            &partial_optional_source,
            &expected_header,
            anchor,
            &mut TestAuthenticator::new()
        )
        .unwrap_err(),
        AuditContainerError::InvalidHeader(AuditHeaderError::InvalidDropCopySource)
    );

    let mut missing_reference_digest = bytes;
    missing_reference_digest[256..288].fill(0);
    let tag = TestAuthenticator::new().tag(&missing_reference_digest[..header_tag_offset]);
    missing_reference_digest[header_tag_offset..AUDIT_CONTAINER_HEADER_LEN].copy_from_slice(&tag.0);
    assert_eq!(
        verify_audit_container(
            &missing_reference_digest,
            &expected_header,
            anchor,
            &mut TestAuthenticator::new()
        )
        .unwrap_err(),
        AuditContainerError::InvalidHeader(AuditHeaderError::InvalidInstrumentDefinitionBinding)
    );
}

#[test]
fn rewritten_inner_crc_cannot_forge_outer_authentication() {
    let source = EventSource::new(
        SourceId::new(11, 21),
        SequenceDomain::MarketData,
        SessionEpoch(31),
    );
    let event = NormalizedEvent::new(
        EventHeader {
            venue: VenueId(7),
            instrument: InstrumentId(42),
            sequence: Sequence(1),
            exchange_timestamp: TimestampNs(1_000),
            hardware_receive_timestamp: TimestampNs(1_001),
        },
        source,
        CaptureOrdinal(1),
        EventKind::BookAdd,
        EventSide::Buy,
        0,
        OrderId(100),
        PriceTicks(25_000),
        Quantity(10),
        0,
    );
    let mut journal_record = [0_u8; RECORD_LEN];
    assert_eq!(encode_record(event, &mut journal_record), Ok(RECORD_LEN));
    let expected_header = header(1, 1, None);
    let (mut bytes, anchor) = build(
        &expected_header,
        &[(AuditRecordKind::NORMALIZED_EVENT, &journal_record)],
    );

    let payload_start = AUDIT_CONTAINER_HEADER_LEN + AUDIT_RECORD_PREFIX_LEN;
    bytes[payload_start + 104] ^= 0x01;
    let checksum = crc32c(&bytes[payload_start..payload_start + RECORD_LEN - 4]);
    bytes[payload_start + RECORD_LEN - 4..payload_start + RECORD_LEN]
        .copy_from_slice(&checksum.to_le_bytes());
    assert_eq!(
        verify_audit_container(
            &bytes,
            &expected_header,
            anchor,
            &mut TestAuthenticator::new()
        )
        .unwrap_err(),
        AuditContainerError::Authenticator(TestAuthError::Rejected)
    );
}

#[test]
fn header_mutation_reordering_and_cross_container_splice_fail_closed() {
    let expected_header = header(1, 1, None);
    let records = [
        (AuditRecordKind::NATIVE_INGRESS, b"aaa".as_slice()),
        (AuditRecordKind::NATIVE_INTENT, b"bbb".as_slice()),
    ];
    let (bytes, anchor) = build(&expected_header, &records);

    let mut mutated_header = bytes.clone();
    mutated_header[64] ^= 0x01;
    assert_eq!(
        verify_audit_container(
            &mutated_header,
            &expected_header,
            anchor,
            &mut TestAuthenticator::new()
        )
        .unwrap_err(),
        AuditContainerError::Authenticator(TestAuthError::Rejected)
    );

    let record_len = audit_record_len(3).unwrap();
    let first_start = AUDIT_CONTAINER_HEADER_LEN;
    let second_start = first_start + record_len;
    let mut reordered = bytes.clone();
    let first = bytes[first_start..second_start].to_vec();
    let second = bytes[second_start..second_start + record_len].to_vec();
    reordered[first_start..second_start].copy_from_slice(&second);
    reordered[second_start..second_start + record_len].copy_from_slice(&first);
    assert_eq!(
        verify_audit_container(
            &reordered,
            &expected_header,
            anchor,
            &mut TestAuthenticator::new()
        )
        .unwrap_err(),
        AuditContainerError::RecordOrdinalMismatch {
            expected: FIRST_ORDINAL,
            actual: FIRST_ORDINAL + 1,
        }
    );

    let other_header = header(2, 1, None);
    let (other, _) = build(&other_header, &records);
    let mut spliced = bytes.clone();
    spliced[first_start..second_start].copy_from_slice(&other[first_start..second_start]);
    assert_eq!(
        verify_audit_container(
            &spliced,
            &expected_header,
            anchor,
            &mut TestAuthenticator::new()
        )
        .unwrap_err(),
        AuditContainerError::RecordContainerMismatch
    );
}

#[test]
fn missing_partial_and_nonterminal_seals_detect_truncation_or_injection() {
    let expected_header = header(1, 1, None);
    let (bytes, anchor) = build(
        &expected_header,
        &[(AuditRecordKind::FAULT, b"fault-record")],
    );

    let mut missing_seal = bytes.clone();
    missing_seal.truncate(bytes.len() - AUDIT_CONTAINER_SEAL_LEN);
    assert_eq!(
        verify_audit_container(
            &missing_seal,
            &expected_header,
            anchor,
            &mut TestAuthenticator::new()
        )
        .unwrap_err(),
        AuditContainerError::MissingSeal
    );

    let mut omitted_record = bytes.clone();
    omitted_record.drain(
        AUDIT_CONTAINER_HEADER_LEN
            ..AUDIT_CONTAINER_HEADER_LEN + audit_record_len(b"fault-record".len()).unwrap(),
    );
    assert_eq!(
        verify_audit_container(
            &omitted_record,
            &expected_header,
            anchor,
            &mut TestAuthenticator::new()
        )
        .unwrap_err(),
        AuditContainerError::InvalidSeal
    );

    let mut partial_seal = bytes.clone();
    partial_seal.pop();
    assert_eq!(
        verify_audit_container(
            &partial_seal,
            &expected_header,
            anchor,
            &mut TestAuthenticator::new()
        )
        .unwrap_err(),
        AuditContainerError::Truncated {
            required: AUDIT_CONTAINER_SEAL_LEN,
            available: AUDIT_CONTAINER_SEAL_LEN - 1,
        }
    );

    let mut injected = bytes.clone();
    injected.push(0xA5);
    assert_eq!(
        verify_audit_container(
            &injected,
            &expected_header,
            anchor,
            &mut TestAuthenticator::new()
        )
        .unwrap_err(),
        AuditContainerError::TrailingBytes(1)
    );
}

#[test]
fn trusted_latest_anchor_and_rotation_link_reject_complete_old_container() {
    let old_header = header(1, 1, None);
    let (old_bytes, old_anchor) = build(
        &old_header,
        &[(AuditRecordKind::LIVE_CHECKPOINT, b"old-checkpoint")],
    );
    let new_header = header(2, 2, Some(old_anchor.predecessor()));
    let (new_bytes, new_anchor) = build(
        &new_header,
        &[(AuditRecordKind::LIVE_CHECKPOINT, b"new-checkpoint")],
    );

    assert!(
        verify_audit_container(
            &new_bytes,
            &new_header,
            new_anchor,
            &mut TestAuthenticator::new()
        )
        .is_ok()
    );
    assert_eq!(
        verify_audit_container(
            &old_bytes,
            &new_header,
            new_anchor,
            &mut TestAuthenticator::new()
        )
        .unwrap_err(),
        AuditContainerError::HeaderMismatch
    );

    let mut wrong_anchor = old_anchor;
    wrong_anchor.record_count += 1;
    assert_eq!(
        verify_audit_container(
            &old_bytes,
            &old_header,
            wrong_anchor,
            &mut TestAuthenticator::new()
        )
        .unwrap_err(),
        AuditContainerError::AnchorMismatch
    );
}

#[test]
fn invalid_identity_rotation_and_authenticator_are_rejected_before_output() {
    let mut invalid_rotation = header(1, 1, None);
    invalid_rotation.generation = 2;
    assert_eq!(
        invalid_rotation.validate(),
        Err(AuditHeaderError::InvalidPredecessor)
    );

    let mut invalid_source = header(1, 1, None);
    invalid_source.market_data_source.session_epoch = SessionEpoch(0);
    assert_eq!(
        invalid_source.validate(),
        Err(AuditHeaderError::InvalidMarketDataSource)
    );

    let mut invalid_drop_copy = header(1, 1, None);
    invalid_drop_copy.drop_copy_source = Some(invalid_drop_copy.order_entry_source);
    assert_eq!(
        invalid_drop_copy.validate(),
        Err(AuditHeaderError::InvalidDropCopySource)
    );

    let mut wrong_definition_venue = header(1, 1, None);
    wrong_definition_venue.instrument_definition_binding.venue = VenueId(8);
    assert_eq!(
        wrong_definition_venue.validate(),
        Err(AuditHeaderError::InstrumentDefinitionVenueMismatch {
            expected: VenueId(7),
            actual: VenueId(8),
        })
    );

    let mut wrong_key_header = header(1, 1, None);
    wrong_key_header.key_id += 1;
    let mut output = [0xA5_u8; AUDIT_CONTAINER_HEADER_LEN];
    assert_eq!(
        AuditContainerWriter::begin(
            &wrong_key_header,
            &mut TestAuthenticator::new(),
            &mut output,
        )
        .unwrap_err(),
        AuditContainerError::AuthenticatorIdentityMismatch
    );
    assert_eq!(output, [0xA5; AUDIT_CONTAINER_HEADER_LEN]);
}
