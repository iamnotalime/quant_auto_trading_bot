use quant_hft_core::journal::crc32c;
use quant_hft_core::venue::{ProtocolId, SessionId, VenueIdentity};
use quant_hft_core::{
    CaptureOrdinal, EventSource, InstrumentDefinitionBinding, InstrumentId,
    NATIVE_AUDIT_RECORD_HEADER_LEN, NATIVE_LIVE_CHECKPOINT_BODY_LEN,
    NATIVE_LIVE_CHECKPOINT_RECORD_LEN, NativeAuditCodecError, NativeAuditRecordVariant,
    NativeCheckpointOptionField, NativeCheckpointSourceField, NativeLiveCheckpoint,
    NativeLivePhase, NativeProductId, ReferenceDataAuthorityId, ReferenceDataDigest,
    SequenceDomain, SessionEpoch, SourceId, VenueId, decode_native_audit_record,
    decode_native_live_checkpoint_record, encode_native_audit_record,
    encode_native_live_checkpoint_record,
};

const SCOPE_TICKET: u64 = 0x1020_3040_5060_7080;
const BODY_OFFSET: usize = NATIVE_AUDIT_RECORD_HEADER_LEN;
const MARKET_SOURCE_DOMAIN_OFFSET: usize = BODY_OFFSET + 80 + 16;
const ORDER_SOURCE_DOMAIN_OFFSET: usize = BODY_OFFSET + 97 + 16;
const DROP_COPY_TAG_OFFSET: usize = BODY_OFFSET + 114;
const DROP_COPY_SOURCE_OFFSET: usize = BODY_OFFSET + 115;
const DROP_COPY_DOMAIN_OFFSET: usize = DROP_COPY_SOURCE_OFFSET + 16;
const PHASE_OFFSET: usize = BODY_OFFSET + 180;
const CHECKPOINT_RESERVED_OFFSET: usize = BODY_OFFSET + 181;

fn checkpoint(drop_copy: bool, phase: NativeLivePhase) -> NativeLiveCheckpoint {
    NativeLiveCheckpoint {
        expected_identity: VenueIdentity {
            venue: VenueId(0x1234),
            market_data_protocol: ProtocolId(0x1020_3040),
            order_entry_protocol: ProtocolId(0x5060_7080),
            session: SessionId(0x1122_3344_5566_7788),
        },
        expected_instrument_binding: InstrumentDefinitionBinding {
            venue: VenueId(0x1234),
            instrument: InstrumentId(0x90a0_b0c0),
            native_product: NativeProductId(0x0102_0304_0506_0708),
            authority: ReferenceDataAuthorityId(0x1112_1314_1516_1718),
            reference_data_version: 0x2122_2324_2526_2728,
            reference_data_digest: ReferenceDataDigest([0x5a; 32]),
        },
        expected_market_data_source: EventSource::new(
            SourceId::new(0x1020_3040, 0x1111_2222),
            SequenceDomain::MarketData,
            SessionEpoch(0x3132_3334_3536_3738),
        ),
        expected_order_entry_source: EventSource::new(
            SourceId::new(0x5060_7080, 0x3333_4444),
            SequenceDomain::OrderEntry,
            SessionEpoch(0x4142_4344_4546_4748),
        ),
        expected_drop_copy_source: drop_copy.then_some(EventSource::new(
            SourceId::new(0x90a0_b0c0, 0x5555_6666),
            SequenceDomain::DropCopy,
            SessionEpoch(0x5152_5354_5556_5758),
        )),
        monotonic_clock_epoch: 0x6162_6364_6566_6768,
        expected_first_source_capture: CaptureOrdinal(101),
        last_source_capture: Some(CaptureOrdinal(202)),
        last_feedback_capture: Some(CaptureOrdinal(303)),
        last_outbound_frame: Some(404),
        next_commit_ordinal: 505,
        phase,
    }
}

fn encoded_checkpoint(value: NativeLiveCheckpoint) -> [u8; NATIVE_LIVE_CHECKPOINT_RECORD_LEN] {
    let mut record = [0xa5; NATIVE_LIVE_CHECKPOINT_RECORD_LEN];
    let encoded = encode_native_live_checkpoint_record(SCOPE_TICKET, value, &mut record)
        .expect("checkpoint encoding");
    assert_eq!(encoded, NATIVE_LIVE_CHECKPOINT_RECORD_LEN);
    record
}

fn rewrite_crc(record: &mut [u8]) {
    let checksum_offset = record.len() - 4;
    let checksum = crc32c(&record[..checksum_offset]);
    record[checksum_offset..].copy_from_slice(&checksum.to_le_bytes());
}

fn write_u16(record: &mut [u8], offset: usize, value: u16) {
    record[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(record: &mut [u8], offset: usize, value: u32) {
    record[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn generic_qhlr_v1_envelope_round_trips_exactly_and_preserves_tail() {
    let body = [0xde, 0xad, 0xbe, 0xef];
    let mut storage = [0xa5; 48];
    let written = encode_native_audit_record(
        SCOPE_TICKET,
        NativeAuditRecordVariant::Checkpoint,
        &body,
        &mut storage,
    )
    .expect("generic encoding");

    assert_eq!(written, 40);
    assert_eq!(&storage[0..4], b"QHLR");
    assert_eq!(u16::from_le_bytes([storage[4], storage[5]]), 1);
    assert_eq!(u16::from_le_bytes([storage[6], storage[7]]), 32);
    assert_eq!(u32::from_le_bytes(storage[8..12].try_into().unwrap()), 40);
    assert_eq!(
        u64::from_le_bytes(storage[12..20].try_into().unwrap()),
        SCOPE_TICKET
    );
    assert_eq!(u16::from_le_bytes(storage[20..22].try_into().unwrap()), 1);
    assert_eq!(&storage[22..24], &[0, 0]);
    assert_eq!(u32::from_le_bytes(storage[24..28].try_into().unwrap()), 4);
    assert_eq!(&storage[28..32], &[0; 4]);
    assert_eq!(&storage[32..36], &body);
    assert!(storage[written..].iter().all(|byte| *byte == 0xa5));

    let decoded = decode_native_audit_record(&storage[..written]).expect("generic decoding");
    assert_eq!(decoded.scope_ticket, SCOPE_TICKET);
    assert_eq!(decoded.variant, NativeAuditRecordVariant::Checkpoint);
    assert_eq!(decoded.body, body);
}

#[test]
fn generic_encoder_rejects_short_output_without_mutating_it() {
    let mut output = [0xa5; 39];
    assert_eq!(
        encode_native_audit_record(
            SCOPE_TICKET,
            NativeAuditRecordVariant::Checkpoint,
            &[1, 2, 3, 4],
            &mut output,
        ),
        Err(NativeAuditCodecError::BufferTooSmall {
            required: 40,
            available: 39,
        })
    );
    assert_eq!(output, [0xa5; 39]);
}

#[test]
fn envelope_rejects_magic_version_header_flags_reserved_and_variant_corruption() {
    let pristine = encoded_checkpoint(checkpoint(true, NativeLivePhase::Ambiguous));

    let mut record = pristine;
    record[0] ^= 1;
    assert_eq!(
        decode_native_audit_record(&record),
        Err(NativeAuditCodecError::InvalidMagic)
    );

    let mut record = pristine;
    write_u16(&mut record, 4, 2);
    assert_eq!(
        decode_native_audit_record(&record),
        Err(NativeAuditCodecError::UnsupportedVersion(2))
    );

    let mut record = pristine;
    write_u16(&mut record, 6, 31);
    assert_eq!(
        decode_native_audit_record(&record),
        Err(NativeAuditCodecError::InvalidHeaderLength(31))
    );

    let mut record = pristine;
    write_u16(&mut record, 22, 1);
    assert_eq!(
        decode_native_audit_record(&record),
        Err(NativeAuditCodecError::InvalidFlags(1))
    );

    let mut record = pristine;
    write_u32(&mut record, 28, 1);
    assert_eq!(
        decode_native_audit_record(&record),
        Err(NativeAuditCodecError::InvalidReserved(1))
    );

    let mut record = pristine;
    write_u16(&mut record, 20, u16::MAX);
    rewrite_crc(&mut record);
    assert_eq!(
        decode_native_audit_record(&record),
        Err(NativeAuditCodecError::InvalidVariant(u16::MAX))
    );
}

#[test]
fn envelope_rejects_inconsistent_truncated_trailing_and_corrupt_lengths() {
    let pristine = encoded_checkpoint(checkpoint(true, NativeLivePhase::Ambiguous));

    let mut record = pristine;
    write_u32(&mut record, 8, 219);
    assert_eq!(
        decode_native_audit_record(&record),
        Err(NativeAuditCodecError::InvalidTotalLength {
            recorded: 219,
            expected: 220,
        })
    );

    let mut record = pristine;
    write_u32(&mut record, 24, 183);
    assert_eq!(
        decode_native_audit_record(&record),
        Err(NativeAuditCodecError::InvalidTotalLength {
            recorded: 220,
            expected: 219,
        })
    );

    assert_eq!(
        decode_native_audit_record(&pristine[..pristine.len() - 1]),
        Err(NativeAuditCodecError::Truncated {
            required: 220,
            available: 219,
        })
    );

    let mut trailing = [0_u8; NATIVE_LIVE_CHECKPOINT_RECORD_LEN + 1];
    trailing[..pristine.len()].copy_from_slice(&pristine);
    assert_eq!(
        decode_native_audit_record(&trailing),
        Err(NativeAuditCodecError::TrailingBytes(1))
    );

    assert_eq!(
        decode_native_audit_record(&pristine[..31]),
        Err(NativeAuditCodecError::Truncated {
            required: 32,
            available: 31,
        })
    );
}

#[test]
fn envelope_checksum_covers_header_and_body() {
    let pristine = encoded_checkpoint(checkpoint(true, NativeLivePhase::Ambiguous));
    for offset in [12, BODY_OFFSET + 7] {
        let mut record = pristine;
        record[offset] ^= 1;
        assert!(matches!(
            decode_native_audit_record(&record),
            Err(NativeAuditCodecError::ChecksumMismatch { .. })
        ));
    }
}

#[test]
fn checkpoint_round_trips_every_phase_and_present_option() {
    for phase in [
        NativeLivePhase::Ready,
        NativeLivePhase::SafetyPending,
        NativeLivePhase::KilledRecovery,
        NativeLivePhase::Ambiguous,
        NativeLivePhase::Failed,
    ] {
        let expected = checkpoint(true, phase);
        let record = encoded_checkpoint(expected);
        assert_eq!(
            decode_native_live_checkpoint_record(&record),
            Ok((SCOPE_TICKET, expected))
        );
        assert_eq!(
            u32::from_le_bytes(record[8..12].try_into().unwrap()) as usize,
            NATIVE_LIVE_CHECKPOINT_RECORD_LEN
        );
        assert_eq!(
            u32::from_le_bytes(record[24..28].try_into().unwrap()) as usize,
            NATIVE_LIVE_CHECKPOINT_BODY_LEN
        );
    }
}

#[test]
fn checkpoint_sources_use_the_existing_canonical_packed_order() {
    let record = encoded_checkpoint(checkpoint(true, NativeLivePhase::Ambiguous));
    let market = BODY_OFFSET + 80;
    assert_eq!(
        u32::from_le_bytes(record[market..market + 4].try_into().unwrap()),
        0x1020_3040
    );
    assert_eq!(
        u32::from_le_bytes(record[market + 4..market + 8].try_into().unwrap()),
        0x1111_2222
    );
    assert_eq!(
        u64::from_le_bytes(record[market + 8..market + 16].try_into().unwrap()),
        0x3132_3334_3536_3738
    );
    assert_eq!(record[market + 16], SequenceDomain::MarketData as u8);

    let order_entry = BODY_OFFSET + 97;
    assert_eq!(
        u64::from_le_bytes(
            record[order_entry + 8..order_entry + 16]
                .try_into()
                .unwrap()
        ),
        0x4142_4344_4546_4748
    );
    assert_eq!(record[order_entry + 16], SequenceDomain::OrderEntry as u8);

    assert_eq!(record[DROP_COPY_TAG_OFFSET], 1);
    assert_eq!(
        u64::from_le_bytes(
            record[DROP_COPY_SOURCE_OFFSET + 8..DROP_COPY_SOURCE_OFFSET + 16]
                .try_into()
                .unwrap()
        ),
        0x5152_5354_5556_5758
    );
    assert_eq!(
        record[DROP_COPY_SOURCE_OFFSET + 16],
        SequenceDomain::DropCopy as u8
    );
}

#[test]
fn checkpoint_round_trips_canonical_absent_options() {
    let mut expected = checkpoint(false, NativeLivePhase::Failed);
    expected.last_source_capture = None;
    expected.last_feedback_capture = None;
    expected.last_outbound_frame = None;
    let record = encoded_checkpoint(expected);

    assert_eq!(record[DROP_COPY_TAG_OFFSET], 0);
    assert!(
        record[DROP_COPY_SOURCE_OFFSET..DROP_COPY_SOURCE_OFFSET + 17]
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(
        decode_native_live_checkpoint_record(&record),
        Ok((SCOPE_TICKET, expected))
    );
}

#[test]
fn checkpoint_encoder_rejects_noncanonical_some_zero_options_atomically() {
    for (field, mutate) in [
        (NativeCheckpointOptionField::LastSourceCapture, 0_u8),
        (NativeCheckpointOptionField::LastFeedbackCapture, 1_u8),
        (NativeCheckpointOptionField::LastOutboundFrame, 2_u8),
    ] {
        let mut value = checkpoint(true, NativeLivePhase::Ambiguous);
        match mutate {
            0 => value.last_source_capture = Some(CaptureOrdinal(0)),
            1 => value.last_feedback_capture = Some(CaptureOrdinal(0)),
            _ => value.last_outbound_frame = Some(0),
        }
        let mut output = [0xa5; NATIVE_LIVE_CHECKPOINT_RECORD_LEN];
        assert_eq!(
            encode_native_live_checkpoint_record(SCOPE_TICKET, value, &mut output),
            Err(NativeAuditCodecError::NonCanonicalOption(field))
        );
        assert_eq!(output, [0xa5; NATIVE_LIVE_CHECKPOINT_RECORD_LEN]);
    }
}

#[test]
fn checkpoint_decoder_rejects_noncanonical_drop_copy_option() {
    let pristine = encoded_checkpoint(checkpoint(false, NativeLivePhase::Ambiguous));

    let mut record = pristine;
    record[DROP_COPY_SOURCE_OFFSET] = 1;
    rewrite_crc(&mut record);
    assert_eq!(
        decode_native_live_checkpoint_record(&record),
        Err(NativeAuditCodecError::NonCanonicalOption(
            NativeCheckpointOptionField::DropCopySource
        ))
    );

    let mut record = pristine;
    record[DROP_COPY_TAG_OFFSET] = 2;
    rewrite_crc(&mut record);
    assert_eq!(
        decode_native_live_checkpoint_record(&record),
        Err(NativeAuditCodecError::InvalidOptionTag {
            field: NativeCheckpointOptionField::DropCopySource,
            value: 2,
        })
    );
}

#[test]
fn checkpoint_decoder_rejects_every_invalid_source_domain() {
    let pristine = encoded_checkpoint(checkpoint(true, NativeLivePhase::Ambiguous));
    for (offset, field) in [
        (
            MARKET_SOURCE_DOMAIN_OFFSET,
            NativeCheckpointSourceField::MarketData,
        ),
        (
            ORDER_SOURCE_DOMAIN_OFFSET,
            NativeCheckpointSourceField::OrderEntry,
        ),
        (
            DROP_COPY_DOMAIN_OFFSET,
            NativeCheckpointSourceField::DropCopy,
        ),
    ] {
        let mut record = pristine;
        record[offset] = u8::MAX;
        rewrite_crc(&mut record);
        assert_eq!(
            decode_native_live_checkpoint_record(&record),
            Err(NativeAuditCodecError::InvalidSequenceDomain {
                field,
                value: u8::MAX,
            })
        );
    }
}

#[test]
fn checkpoint_decoder_rejects_phase_reserved_and_body_length_corruption() {
    let pristine = encoded_checkpoint(checkpoint(true, NativeLivePhase::Ambiguous));

    let mut record = pristine;
    record[PHASE_OFFSET] = u8::MAX;
    rewrite_crc(&mut record);
    assert_eq!(
        decode_native_live_checkpoint_record(&record),
        Err(NativeAuditCodecError::InvalidPhase(u8::MAX))
    );

    let mut record = pristine;
    record[CHECKPOINT_RESERVED_OFFSET] = 1;
    rewrite_crc(&mut record);
    assert_eq!(
        decode_native_live_checkpoint_record(&record),
        Err(NativeAuditCodecError::InvalidCheckpointReserved)
    );

    let mut short_body_record = [0_u8; NATIVE_LIVE_CHECKPOINT_RECORD_LEN - 1];
    let written = encode_native_audit_record(
        SCOPE_TICKET,
        NativeAuditRecordVariant::Checkpoint,
        &[0; NATIVE_LIVE_CHECKPOINT_BODY_LEN - 1],
        &mut short_body_record,
    )
    .expect("generic short checkpoint body");
    assert_eq!(written, short_body_record.len());
    assert_eq!(
        decode_native_live_checkpoint_record(&short_body_record),
        Err(NativeAuditCodecError::InvalidBodyLength {
            variant: NativeAuditRecordVariant::Checkpoint,
            expected: 184,
            actual: 183,
        })
    );
}

#[test]
fn checkpoint_encoder_reports_exact_required_capacity() {
    let mut output = [0xa5; NATIVE_LIVE_CHECKPOINT_RECORD_LEN - 1];
    assert_eq!(
        encode_native_live_checkpoint_record(
            SCOPE_TICKET,
            checkpoint(true, NativeLivePhase::Ambiguous),
            &mut output,
        ),
        Err(NativeAuditCodecError::BufferTooSmall {
            required: NATIVE_LIVE_CHECKPOINT_RECORD_LEN,
            available: NATIVE_LIVE_CHECKPOINT_RECORD_LEN - 1,
        })
    );
    assert!(output.iter().all(|byte| *byte == 0xa5));
}
