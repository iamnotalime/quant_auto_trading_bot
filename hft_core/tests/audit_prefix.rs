use quant_hft_core::audit_prefix::{
    AUDIT_PREFIX_AUTHENTICATED_LEN, AUDIT_PREFIX_MAGIC, AUDIT_PREFIX_RECORD_LEN,
    AUDIT_PREFIX_VERSION, AuditPrefixAnchor, AuditPrefixCursor, AuditPrefixError, AuditPrefixFlags,
    AuditPrefixHeaderField, AuditPrefixRecordVariant, AuditPrefixTicketState,
    decode_audit_prefix_anchor, encode_audit_prefix_anchor, encode_audit_prefix_authenticated,
};
use quant_hft_core::control::ConfigDigest;
use quant_hft_core::events::{EventSource, SequenceDomain, SessionEpoch, SourceId};
use quant_hft_core::reference_data::{
    InstrumentDefinitionBinding, NativeProductId, ReferenceDataAuthorityId, ReferenceDataDigest,
};
use quant_hft_core::venue::{ProtocolId, SessionId, VenueIdentity};
use quant_hft_core::{
    AUDIT_CONTAINER_HEADER_LEN, AUDIT_CONTAINER_SEAL_LEN, AUDIT_RECORD_PREFIX_LEN, AUDIT_TAG_LEN,
    AuditContainerHeader, AuditContainerId, AuditRecordKind, AuditTag, InstrumentId, VenueId,
};

const ALGORITHM_ID: u32 = 0x5148_5041;
const KEY_ID: u64 = 0x1122_3344_5566_7788;
const FIRST_ORDINAL: u64 = 41;
const HEADER_TAG: AuditTag = AuditTag([0xA3; AUDIT_TAG_LEN]);
const CHAIN_TAG: AuditTag = AuditTag([0xB4; AUDIT_TAG_LEN]);
const PREVIOUS_ANCHOR_TAG: AuditTag = AuditTag([0xC5; AUDIT_TAG_LEN]);
const DEPLOYMENT_TAG: AuditTag = AuditTag([0xD6; AUDIT_TAG_LEN]);

fn header() -> AuditContainerHeader {
    AuditContainerHeader {
        algorithm_id: ALGORITHM_ID,
        key_id: KEY_ID,
        container_id: AuditContainerId([0x42; 16]),
        generation: 1,
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
        predecessor: None,
    }
}

fn closed_anchor() -> AuditPrefixAnchor {
    AuditPrefixAnchor {
        flags: AuditPrefixFlags::NONE,
        algorithm_id: ALGORITHM_ID,
        key_id: KEY_ID,
        anchor_sequence: 2,
        previous_anchor_sequence: 1,
        container_id: AuditContainerId([0x42; 16]),
        container_generation: 1,
        committed_file_length: 700,
        record_count: 1,
        first_record_ordinal: FIRST_ORDINAL,
        last_record_ordinal: FIRST_ORDINAL,
        header_tag: HEADER_TAG,
        current_record_chain_tag: CHAIN_TAG,
        // Ticket values are opaque; zero is a valid scoped ticket in the current
        // NativeLiveAudit contract. The state, not a sentinel, carries presence.
        scope_ticket: 0,
        ticket_state: AuditPrefixTicketState::TicketClosed,
        last_record_kind: AuditRecordKind::LIVE_CHECKPOINT,
        last_record_variant: AuditPrefixRecordVariant::CHECKPOINT,
        unresolved_intent_count: 0,
        next_record_ordinal: FIRST_ORDINAL + 1,
        next_frame_ordinal: 11,
        next_capture_ordinal: 12,
        next_commit_ordinal: 13,
        next_ticket_id: 0,
        monotonic_clock_epoch: 9,
        previous_anchor_tag: PREVIOUS_ANCHOR_TAG,
    }
}

fn encoded(anchor: &AuditPrefixAnchor) -> [u8; AUDIT_PREFIX_RECORD_LEN] {
    let mut output = [0_u8; AUDIT_PREFIX_RECORD_LEN];
    assert_eq!(
        encode_audit_prefix_anchor(anchor, &header(), HEADER_TAG, DEPLOYMENT_TAG, &mut output),
        Ok(AUDIT_PREFIX_RECORD_LEN)
    );
    output
}

#[test]
fn roundtrip_uses_the_exact_canonical_offsets() {
    let anchor = closed_anchor();
    let mut complete = [0xEE_u8; AUDIT_PREFIX_RECORD_LEN + 9];
    let written = encode_audit_prefix_anchor(
        &anchor,
        &header(),
        HEADER_TAG,
        DEPLOYMENT_TAG,
        &mut complete,
    )
    .unwrap();
    assert_eq!(written, AUDIT_PREFIX_RECORD_LEN);
    assert_eq!(&complete[AUDIT_PREFIX_RECORD_LEN..], &[0xEE; 9]);

    assert_eq!(&complete[0..4], &AUDIT_PREFIX_MAGIC);
    assert_eq!(u16_at(&complete, 4), AUDIT_PREFIX_VERSION);
    assert_eq!(u16_at(&complete, 6), 264);
    assert_eq!(u32_at(&complete, 8), 296);
    assert_eq!(u32_at(&complete, 12), anchor.flags.bits());
    assert_eq!(u32_at(&complete, 16), ALGORITHM_ID);
    assert_eq!(u32_at(&complete, 20), 0);
    assert_eq!(u64_at(&complete, 24), KEY_ID);
    assert_eq!(u64_at(&complete, 32), 2);
    assert_eq!(u64_at(&complete, 40), 1);
    assert_eq!(&complete[48..64], &[0x42; 16]);
    assert_eq!(u64_at(&complete, 64), 1);
    assert_eq!(u64_at(&complete, 72), 700);
    assert_eq!(u64_at(&complete, 80), 1);
    assert_eq!(u64_at(&complete, 88), FIRST_ORDINAL);
    assert_eq!(u64_at(&complete, 96), FIRST_ORDINAL);
    assert_eq!(&complete[104..136], &HEADER_TAG.0);
    assert_eq!(&complete[136..168], &CHAIN_TAG.0);
    assert_eq!(u64_at(&complete, 168), 0);
    assert_eq!(u16_at(&complete, 176), 4);
    assert_eq!(u16_at(&complete, 178), AuditRecordKind::LIVE_CHECKPOINT.0);
    assert_eq!(u16_at(&complete, 180), 1);
    assert_eq!(complete[182], 0);
    assert_eq!(complete[183], 0);
    assert_eq!(u64_at(&complete, 184), FIRST_ORDINAL + 1);
    assert_eq!(u64_at(&complete, 192), 11);
    assert_eq!(u64_at(&complete, 200), 12);
    assert_eq!(u64_at(&complete, 208), 13);
    assert_eq!(u64_at(&complete, 216), 0);
    assert_eq!(u64_at(&complete, 224), 9);
    assert_eq!(&complete[232..264], &PREVIOUS_ANCHOR_TAG.0);
    assert_eq!(&complete[264..296], &DEPLOYMENT_TAG.0);

    let decoded =
        decode_audit_prefix_anchor(&complete[..AUDIT_PREFIX_RECORD_LEN], &header(), HEADER_TAG)
            .unwrap();
    assert_eq!(decoded.anchor, anchor);
    assert_eq!(decoded.deployment_tag, DEPLOYMENT_TAG);
}

#[test]
fn authenticated_encoder_emits_exactly_the_tag_input() {
    let anchor = closed_anchor();
    let complete = encoded(&anchor);
    let mut authenticated = [0x7C_u8; AUDIT_PREFIX_AUTHENTICATED_LEN + 7];
    assert_eq!(
        encode_audit_prefix_authenticated(&anchor, &header(), HEADER_TAG, &mut authenticated),
        Ok(AUDIT_PREFIX_AUTHENTICATED_LEN)
    );
    assert_eq!(
        &authenticated[..AUDIT_PREFIX_AUTHENTICATED_LEN],
        &complete[..AUDIT_PREFIX_AUTHENTICATED_LEN]
    );
    assert_eq!(&authenticated[AUDIT_PREFIX_AUTHENTICATED_LEN..], &[0x7C; 7]);

    let mut short_prefix = [0xA5_u8; AUDIT_PREFIX_AUTHENTICATED_LEN - 1];
    assert_eq!(
        encode_audit_prefix_authenticated(&anchor, &header(), HEADER_TAG, &mut short_prefix),
        Err(AuditPrefixError::BufferTooSmall {
            required: AUDIT_PREFIX_AUTHENTICATED_LEN,
            available: AUDIT_PREFIX_AUTHENTICATED_LEN - 1,
        })
    );
    assert_eq!(short_prefix, [0xA5; AUDIT_PREFIX_AUTHENTICATED_LEN - 1]);

    let mut short_complete = [0x5A_u8; AUDIT_PREFIX_RECORD_LEN - 1];
    assert_eq!(
        encode_audit_prefix_anchor(
            &anchor,
            &header(),
            HEADER_TAG,
            DEPLOYMENT_TAG,
            &mut short_complete,
        ),
        Err(AuditPrefixError::BufferTooSmall {
            required: AUDIT_PREFIX_RECORD_LEN,
            available: AUDIT_PREFIX_RECORD_LEN - 1,
        })
    );
    assert_eq!(short_complete, [0x5A; AUDIT_PREFIX_RECORD_LEN - 1]);
}

#[test]
fn decoder_rejects_framing_reserved_and_trailing_corruption() {
    let anchor = closed_anchor();
    let canonical = encoded(&anchor);

    assert_eq!(
        decode_audit_prefix_anchor(&canonical[..295], &header(), HEADER_TAG),
        Err(AuditPrefixError::Truncated {
            required: 296,
            available: 295,
        })
    );
    let mut trailing = [0_u8; 297];
    trailing[..296].copy_from_slice(&canonical);
    assert_eq!(
        decode_audit_prefix_anchor(&trailing, &header(), HEADER_TAG),
        Err(AuditPrefixError::TrailingBytes(1))
    );

    assert_corruption(&canonical, 0, 0, AuditPrefixError::InvalidMagic);
    assert_corruption(&canonical, 4, 2, AuditPrefixError::UnsupportedVersion(2));
    assert_corruption(
        &canonical,
        6,
        0,
        AuditPrefixError::InvalidAuthenticatedLength(256),
    );
    assert_corruption(&canonical, 8, 0, AuditPrefixError::InvalidTotalLength(256));
    assert_corruption(
        &canonical,
        15,
        0x80,
        AuditPrefixError::UnknownFlags(0x8000_0000),
    );
    assert_corruption(&canonical, 20, 1, AuditPrefixError::InvalidReserved);
    assert_corruption(&canonical, 183, 1, AuditPrefixError::InvalidReserved);
    let mut invalid_state = canonical;
    invalid_state[176..178].copy_from_slice(&9_u16.to_le_bytes());
    assert_eq!(
        decode_audit_prefix_anchor(&invalid_state, &header(), HEADER_TAG),
        Err(AuditPrefixError::InvalidTicketState(9))
    );
}

#[test]
fn deployment_tag_is_opaque_and_codec_success_is_not_mac_verification() {
    let anchor = closed_anchor();
    let mut bytes = encoded(&anchor);

    bytes[264] ^= 0xFF;
    let decoded = decode_audit_prefix_anchor(&bytes, &header(), HEADER_TAG).unwrap();
    assert_eq!(decoded.deployment_tag.0[0], DEPLOYMENT_TAG.0[0] ^ 0xFF);

    // This authenticated-field mutation remains semantically valid. Acceptance is
    // intentional proof that the codec does not pretend to verify the unchanged tag.
    bytes[192..200].copy_from_slice(&99_u64.to_le_bytes());
    let decoded = decode_audit_prefix_anchor(&bytes, &header(), HEADER_TAG).unwrap();
    assert_eq!(decoded.anchor.next_frame_ordinal, 99);
    assert_eq!(decoded.deployment_tag.0[1..], DEPLOYMENT_TAG.0[1..]);
}

#[test]
fn header_bindings_and_anchor_sequences_are_exact() {
    let base = closed_anchor();

    assert_invalid(
        AuditPrefixAnchor {
            algorithm_id: 0,
            ..base
        },
        AuditPrefixError::InvalidAlgorithmId,
    );
    assert_invalid(
        AuditPrefixAnchor { key_id: 0, ..base },
        AuditPrefixError::InvalidKeyId,
    );
    assert_invalid(
        AuditPrefixAnchor {
            anchor_sequence: 0,
            previous_anchor_sequence: 0,
            ..base
        },
        AuditPrefixError::InvalidAnchorSequence,
    );
    assert_invalid(
        AuditPrefixAnchor {
            previous_anchor_sequence: 0,
            ..base
        },
        AuditPrefixError::InvalidPreviousAnchorSequence,
    );
    assert_invalid(
        AuditPrefixAnchor {
            anchor_sequence: 1,
            previous_anchor_sequence: 0,
            previous_anchor_tag: PREVIOUS_ANCHOR_TAG,
            ..base
        },
        AuditPrefixError::NonCanonicalPreviousAnchorTag,
    );
    assert_invalid(
        AuditPrefixAnchor {
            container_id: AuditContainerId([0; 16]),
            ..base
        },
        AuditPrefixError::InvalidContainerId,
    );
    assert_invalid(
        AuditPrefixAnchor {
            container_generation: 0,
            ..base
        },
        AuditPrefixError::InvalidContainerGeneration,
    );
    assert_invalid(
        AuditPrefixAnchor {
            monotonic_clock_epoch: 0,
            ..base
        },
        AuditPrefixError::InvalidMonotonicClockEpoch,
    );

    let mut mismatched_header = header();
    mismatched_header.first_record_ordinal += 1;
    let mut output = [0_u8; AUDIT_PREFIX_RECORD_LEN];
    assert_eq!(
        encode_audit_prefix_anchor(
            &base,
            &mismatched_header,
            HEADER_TAG,
            DEPLOYMENT_TAG,
            &mut output,
        ),
        Err(AuditPrefixError::HeaderMismatch(
            AuditPrefixHeaderField::FirstRecordOrdinal,
        ))
    );
    assert_eq!(
        encode_audit_prefix_anchor(
            &base,
            &header(),
            AuditTag([0xEE; 32]),
            DEPLOYMENT_TAG,
            &mut output,
        ),
        Err(AuditPrefixError::HeaderMismatch(
            AuditPrefixHeaderField::HeaderTag,
        ))
    );
}

#[test]
fn record_ordinals_cursors_and_kind_variant_pairs_are_canonical() {
    let base = closed_anchor();
    assert_invalid(
        AuditPrefixAnchor {
            last_record_ordinal: FIRST_ORDINAL + 1,
            ..base
        },
        AuditPrefixError::InvalidRecordOrdinals,
    );
    assert_invalid(
        AuditPrefixAnchor {
            next_record_ordinal: 0,
            ..base
        },
        AuditPrefixError::InvalidRecordOrdinals,
    );
    assert_invalid(
        AuditPrefixAnchor {
            next_frame_ordinal: 0,
            ..base
        },
        AuditPrefixError::InvalidCursor(AuditPrefixCursor::NextFrameOrdinal),
    );
    assert_invalid(
        AuditPrefixAnchor {
            next_capture_ordinal: 0,
            ..base
        },
        AuditPrefixError::InvalidCursor(AuditPrefixCursor::NextCaptureOrdinal),
    );
    assert_invalid(
        AuditPrefixAnchor {
            next_commit_ordinal: 0,
            ..base
        },
        AuditPrefixError::InvalidCursor(AuditPrefixCursor::NextCommitOrdinal),
    );
    assert_invalid(
        AuditPrefixAnchor {
            last_record_kind: AuditRecordKind::FAULT,
            ..base
        },
        AuditPrefixError::InvalidRecordVariant,
    );
    assert_invalid(
        AuditPrefixAnchor {
            last_record_variant: AuditPrefixRecordVariant(2),
            ..base
        },
        AuditPrefixError::InvalidRecordVariant,
    );
    assert_invalid(
        AuditPrefixAnchor {
            committed_file_length: (AUDIT_CONTAINER_HEADER_LEN
                + AUDIT_RECORD_PREFIX_LEN
                + AUDIT_TAG_LEN
                - 1) as u64,
            ..base
        },
        AuditPrefixError::InvalidCommittedFileLength,
    );
}

#[test]
fn lifecycle_states_enforce_only_their_canonical_self_consistency() {
    let header_only = AuditPrefixAnchor {
        flags: AuditPrefixFlags::NONE,
        algorithm_id: ALGORITHM_ID,
        key_id: KEY_ID,
        anchor_sequence: 1,
        previous_anchor_sequence: 0,
        container_id: AuditContainerId([0x42; 16]),
        container_generation: 1,
        committed_file_length: AUDIT_CONTAINER_HEADER_LEN as u64,
        record_count: 0,
        first_record_ordinal: FIRST_ORDINAL,
        last_record_ordinal: 0,
        header_tag: HEADER_TAG,
        current_record_chain_tag: HEADER_TAG,
        scope_ticket: 0,
        ticket_state: AuditPrefixTicketState::HeaderOnly,
        last_record_kind: AuditRecordKind(0),
        last_record_variant: AuditPrefixRecordVariant::NONE,
        unresolved_intent_count: 0,
        next_record_ordinal: FIRST_ORDINAL,
        next_frame_ordinal: 1,
        next_capture_ordinal: 1,
        next_commit_ordinal: 1,
        next_ticket_id: 0,
        monotonic_clock_epoch: 9,
        previous_anchor_tag: AuditTag([0; 32]),
    };
    assert_eq!(
        header_only.validate_against_header(&header(), HEADER_TAG),
        Ok(())
    );
    assert_invalid(
        AuditPrefixAnchor {
            current_record_chain_tag: CHAIN_TAG,
            ..header_only
        },
        AuditPrefixError::InvalidCurrentRecordChainTag,
    );

    let unresolved = AuditPrefixAnchor {
        record_count: 2,
        last_record_ordinal: FIRST_ORDINAL + 1,
        next_record_ordinal: FIRST_ORDINAL + 2,
        committed_file_length: 900,
        ticket_state: AuditPrefixTicketState::TicketUnresolvedIntent,
        last_record_kind: AuditRecordKind::NATIVE_INTENT,
        last_record_variant: AuditPrefixRecordVariant(2),
        unresolved_intent_count: 2,
        ..closed_anchor()
    };
    assert_eq!(
        unresolved.validate_against_header(&header(), HEADER_TAG),
        Ok(())
    );

    let sealed = AuditPrefixAnchor {
        flags: AuditPrefixFlags::CONTAINER_SEALED,
        ticket_state: AuditPrefixTicketState::ContainerSealed,
        scope_ticket: 0,
        committed_file_length: (AUDIT_CONTAINER_HEADER_LEN
            + AUDIT_RECORD_PREFIX_LEN
            + AUDIT_TAG_LEN
            + AUDIT_CONTAINER_SEAL_LEN) as u64,
        ..closed_anchor()
    };
    assert_eq!(
        sealed.validate_against_header(&header(), HEADER_TAG),
        Ok(())
    );

    assert_invalid(
        AuditPrefixAnchor {
            unresolved_intent_count: 1,
            ..closed_anchor()
        },
        AuditPrefixError::InvalidUnresolvedIntentCount,
    );
    assert_invalid(
        AuditPrefixAnchor {
            flags: AuditPrefixFlags::EMERGENCY_LANE,
            ..closed_anchor()
        },
        AuditPrefixError::InvalidTicketSemantics(AuditPrefixTicketState::TicketClosed),
    );
    assert_invalid(
        AuditPrefixAnchor {
            ticket_state: AuditPrefixTicketState::TicketAborted,
            ..closed_anchor()
        },
        AuditPrefixError::InvalidTicketSemantics(AuditPrefixTicketState::TicketAborted),
    );
}

fn assert_invalid(anchor: AuditPrefixAnchor, expected: AuditPrefixError) {
    let mut output = [0xA5_u8; AUDIT_PREFIX_RECORD_LEN];
    assert_eq!(
        encode_audit_prefix_anchor(&anchor, &header(), HEADER_TAG, DEPLOYMENT_TAG, &mut output,),
        Err(expected)
    );
    assert_eq!(output, [0xA5; AUDIT_PREFIX_RECORD_LEN]);
}

fn assert_corruption(
    canonical: &[u8; AUDIT_PREFIX_RECORD_LEN],
    offset: usize,
    value: u8,
    expected: AuditPrefixError,
) {
    let mut corrupted = *canonical;
    corrupted[offset] = value;
    assert_eq!(
        decode_audit_prefix_anchor(&corrupted, &header(), HEADER_TAG),
        Err(expected)
    );
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
