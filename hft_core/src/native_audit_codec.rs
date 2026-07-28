//! Canonical payload framing for retained native-live audit records.
//!
//! `QHLR` records are intended to be the payload of an authenticated
//! [`crate::audit_container`] record. CRC32C detects accidental corruption only; it
//! does not authenticate the payload or protect it from rollback. Recovery must use
//! the surrounding authenticated container and its externally retained latest
//! anchor before trusting a decoded value.

use crate::events::{CaptureOrdinal, EventSource, SequenceDomain, SessionEpoch, SourceId};
use crate::journal::crc32c;
use crate::native_live::{NativeLiveCheckpoint, NativeLivePhase};
use crate::reference_data::{
    InstrumentDefinitionBinding, NativeProductId, ReferenceDataAuthorityId, ReferenceDataDigest,
};
use crate::types::{InstrumentId, VenueId};
use crate::venue::{ProtocolId, SessionId, VenueIdentity};

pub const NATIVE_AUDIT_RECORD_MAGIC: [u8; 4] = *b"QHLR";
pub const NATIVE_AUDIT_RECORD_VERSION: u16 = 1;
pub const NATIVE_AUDIT_RECORD_HEADER_LEN: usize = 32;
pub const NATIVE_AUDIT_RECORD_CHECKSUM_LEN: usize = 4;
pub const NATIVE_LIVE_CHECKPOINT_BODY_LEN: usize = 184;
pub const NATIVE_LIVE_CHECKPOINT_RECORD_LEN: usize = NATIVE_AUDIT_RECORD_HEADER_LEN
    + NATIVE_LIVE_CHECKPOINT_BODY_LEN
    + NATIVE_AUDIT_RECORD_CHECKSUM_LEN;

const HEADER_LEN_WIRE: u16 = 32;
const CHECKPOINT_BODY_LEN_WIRE: u32 = 184;
const FIXED_RECORD_OVERHEAD: usize =
    NATIVE_AUDIT_RECORD_HEADER_LEN + NATIVE_AUDIT_RECORD_CHECKSUM_LEN;

const IDENTITY_OFFSET: usize = 0;
const BINDING_OFFSET: usize = 18;
const MARKET_DATA_SOURCE_OFFSET: usize = 80;
const ORDER_ENTRY_SOURCE_OFFSET: usize = 97;
const DROP_COPY_OPTION_OFFSET: usize = 114;
const DROP_COPY_SOURCE_OFFSET: usize = 115;
const MONOTONIC_CLOCK_EPOCH_OFFSET: usize = 132;
const EXPECTED_FIRST_SOURCE_CAPTURE_OFFSET: usize = 140;
const LAST_SOURCE_CAPTURE_OFFSET: usize = 148;
const LAST_FEEDBACK_CAPTURE_OFFSET: usize = 156;
const LAST_OUTBOUND_FRAME_OFFSET: usize = 164;
const NEXT_COMMIT_ORDINAL_OFFSET: usize = 172;
const PHASE_OFFSET: usize = 180;
const CHECKPOINT_RESERVED_OFFSET: usize = 181;

/// Stable discriminator inside a generic `QHLR` envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum NativeAuditRecordVariant {
    Checkpoint = 1,
}

impl NativeAuditRecordVariant {
    const fn from_wire(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Checkpoint),
            _ => None,
        }
    }
}

/// Source field whose sequence-domain discriminator was not recognized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCheckpointSourceField {
    MarketData,
    OrderEntry,
    DropCopy,
}

/// Optional checkpoint field whose fixed wire representation was not canonical.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCheckpointOptionField {
    DropCopySource,
    LastSourceCapture,
    LastFeedbackCapture,
    LastOutboundFrame,
}

/// Exact structural or canonical-encoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeAuditCodecError {
    BufferTooSmall {
        required: usize,
        available: usize,
    },
    PayloadTooLarge(usize),
    Truncated {
        required: usize,
        available: usize,
    },
    TrailingBytes(usize),
    InvalidMagic,
    UnsupportedVersion(u16),
    InvalidHeaderLength(u16),
    InvalidTotalLength {
        recorded: u32,
        expected: u32,
    },
    InvalidFlags(u16),
    InvalidReserved(u32),
    InvalidVariant(u16),
    InvalidBodyLength {
        variant: NativeAuditRecordVariant,
        expected: u32,
        actual: u32,
    },
    ChecksumMismatch {
        recorded: u32,
        calculated: u32,
    },
    InvalidSequenceDomain {
        field: NativeCheckpointSourceField,
        value: u8,
    },
    InvalidOptionTag {
        field: NativeCheckpointOptionField,
        value: u8,
    },
    NonCanonicalOption(NativeCheckpointOptionField),
    InvalidPhase(u8),
    InvalidCheckpointReserved,
}

/// Borrowed, structurally verified view of one complete `QHLR` record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeAuditRecordView<'a> {
    pub scope_ticket: u64,
    pub variant: NativeAuditRecordVariant,
    pub body: &'a [u8],
}

/// Encode a generic version-1 `QHLR` envelope into caller-owned storage.
///
/// The checksum covers the complete 32-byte header and body. Bytes after the
/// returned record length are not modified.
///
/// # Errors
///
/// Returns an error when the body cannot be represented by the fixed 32-bit wire
/// lengths or when `output` is shorter than the complete record.
pub fn encode_native_audit_record(
    scope_ticket: u64,
    variant: NativeAuditRecordVariant,
    body: &[u8],
    output: &mut [u8],
) -> Result<usize, NativeAuditCodecError> {
    let body_len = u32::try_from(body.len())
        .map_err(|_| NativeAuditCodecError::PayloadTooLarge(body.len()))?;
    let Some(total_len) = FIXED_RECORD_OVERHEAD.checked_add(body.len()) else {
        return Err(NativeAuditCodecError::PayloadTooLarge(body.len()));
    };
    let total_len_wire =
        u32::try_from(total_len).map_err(|_| NativeAuditCodecError::PayloadTooLarge(body.len()))?;
    if output.len() < total_len {
        return Err(NativeAuditCodecError::BufferTooSmall {
            required: total_len,
            available: output.len(),
        });
    }

    let record = &mut output[..total_len];
    record.fill(0);
    record[0..4].copy_from_slice(&NATIVE_AUDIT_RECORD_MAGIC);
    write_u16(record, 4, NATIVE_AUDIT_RECORD_VERSION);
    write_u16(record, 6, HEADER_LEN_WIRE);
    write_u32(record, 8, total_len_wire);
    write_u64(record, 12, scope_ticket);
    write_u16(record, 20, variant as u16);
    // Bytes 22..24 are canonical zero flags; 28..32 are reserved and zero.
    write_u32(record, 24, body_len);
    let checksum_offset = NATIVE_AUDIT_RECORD_HEADER_LEN + body.len();
    record[NATIVE_AUDIT_RECORD_HEADER_LEN..checksum_offset].copy_from_slice(body);
    let checksum = crc32c(&record[..checksum_offset]);
    write_u32(record, checksum_offset, checksum);
    Ok(total_len)
}

/// Decode one exact, complete version-1 `QHLR` record without allocating.
///
/// Unlike stream-oriented capture decoders, this function rejects trailing bytes.
/// The returned body borrows from `input`.
///
/// # Errors
///
/// Returns the first framing, canonical-header, known-variant, envelope-length, or
/// checksum error. Variant-specific body length and schema validation belongs to the
/// corresponding typed decoder.
pub fn decode_native_audit_record(
    input: &[u8],
) -> Result<NativeAuditRecordView<'_>, NativeAuditCodecError> {
    if input.len() < NATIVE_AUDIT_RECORD_HEADER_LEN {
        return Err(NativeAuditCodecError::Truncated {
            required: NATIVE_AUDIT_RECORD_HEADER_LEN,
            available: input.len(),
        });
    }
    if input[0..4] != NATIVE_AUDIT_RECORD_MAGIC {
        return Err(NativeAuditCodecError::InvalidMagic);
    }
    let version = read_u16(input, 4);
    if version != NATIVE_AUDIT_RECORD_VERSION {
        return Err(NativeAuditCodecError::UnsupportedVersion(version));
    }
    let header_len = read_u16(input, 6);
    if header_len != HEADER_LEN_WIRE {
        return Err(NativeAuditCodecError::InvalidHeaderLength(header_len));
    }
    let flags = read_u16(input, 22);
    if flags != 0 {
        return Err(NativeAuditCodecError::InvalidFlags(flags));
    }
    let reserved = read_u32(input, 28);
    if reserved != 0 {
        return Err(NativeAuditCodecError::InvalidReserved(reserved));
    }
    let variant_wire = read_u16(input, 20);
    let variant = NativeAuditRecordVariant::from_wire(variant_wire)
        .ok_or(NativeAuditCodecError::InvalidVariant(variant_wire))?;
    let body_len_wire = read_u32(input, 24);
    let body_len = usize::try_from(body_len_wire)
        .map_err(|_| NativeAuditCodecError::PayloadTooLarge(usize::MAX))?;
    let expected_total = FIXED_RECORD_OVERHEAD
        .checked_add(body_len)
        .ok_or(NativeAuditCodecError::PayloadTooLarge(body_len))?;
    let expected_total_wire = u32::try_from(expected_total)
        .map_err(|_| NativeAuditCodecError::PayloadTooLarge(body_len))?;
    let recorded_total_wire = read_u32(input, 8);
    if recorded_total_wire != expected_total_wire {
        return Err(NativeAuditCodecError::InvalidTotalLength {
            recorded: recorded_total_wire,
            expected: expected_total_wire,
        });
    }
    if input.len() < expected_total {
        return Err(NativeAuditCodecError::Truncated {
            required: expected_total,
            available: input.len(),
        });
    }
    if input.len() > expected_total {
        return Err(NativeAuditCodecError::TrailingBytes(
            input.len() - expected_total,
        ));
    }

    let checksum_offset = NATIVE_AUDIT_RECORD_HEADER_LEN + body_len;
    let recorded_checksum = read_u32(input, checksum_offset);
    let calculated_checksum = crc32c(&input[..checksum_offset]);
    if recorded_checksum != calculated_checksum {
        return Err(NativeAuditCodecError::ChecksumMismatch {
            recorded: recorded_checksum,
            calculated: calculated_checksum,
        });
    }
    Ok(NativeAuditRecordView {
        scope_ticket: read_u64(input, 12),
        variant,
        body: &input[NATIVE_AUDIT_RECORD_HEADER_LEN..checksum_offset],
    })
}

/// Encode every field of [`NativeLiveCheckpoint`] in its fixed 184-byte body.
///
/// Optional capture/frame identifiers use zero for absence because zero is already
/// invalid in those namespaces. A drop-copy option has an explicit one-byte presence
/// tag followed by an always-present 17-byte source slot; the absent slot must be all
/// zero. This prevents multiple byte encodings of the same logical checkpoint.
///
/// # Errors
///
/// Returns [`NativeAuditCodecError::NonCanonicalOption`] for `Some(0)` and otherwise
/// forwards generic envelope capacity/length errors.
pub fn encode_native_live_checkpoint_record(
    scope_ticket: u64,
    checkpoint: NativeLiveCheckpoint,
    output: &mut [u8],
) -> Result<usize, NativeAuditCodecError> {
    reject_zero_option(
        checkpoint.last_source_capture.map(|value| value.0),
        NativeCheckpointOptionField::LastSourceCapture,
    )?;
    reject_zero_option(
        checkpoint.last_feedback_capture.map(|value| value.0),
        NativeCheckpointOptionField::LastFeedbackCapture,
    )?;
    reject_zero_option(
        checkpoint.last_outbound_frame,
        NativeCheckpointOptionField::LastOutboundFrame,
    )?;

    let mut body = [0_u8; NATIVE_LIVE_CHECKPOINT_BODY_LEN];
    encode_identity(&mut body, IDENTITY_OFFSET, checkpoint.expected_identity);
    encode_binding(
        &mut body,
        BINDING_OFFSET,
        checkpoint.expected_instrument_binding,
    );
    encode_source(
        &mut body,
        MARKET_DATA_SOURCE_OFFSET,
        checkpoint.expected_market_data_source,
    );
    encode_source(
        &mut body,
        ORDER_ENTRY_SOURCE_OFFSET,
        checkpoint.expected_order_entry_source,
    );
    if let Some(source) = checkpoint.expected_drop_copy_source {
        body[DROP_COPY_OPTION_OFFSET] = 1;
        encode_source(&mut body, DROP_COPY_SOURCE_OFFSET, source);
    }
    write_u64(
        &mut body,
        MONOTONIC_CLOCK_EPOCH_OFFSET,
        checkpoint.monotonic_clock_epoch,
    );
    write_u64(
        &mut body,
        EXPECTED_FIRST_SOURCE_CAPTURE_OFFSET,
        checkpoint.expected_first_source_capture.0,
    );
    write_u64(
        &mut body,
        LAST_SOURCE_CAPTURE_OFFSET,
        checkpoint.last_source_capture.map_or(0, |value| value.0),
    );
    write_u64(
        &mut body,
        LAST_FEEDBACK_CAPTURE_OFFSET,
        checkpoint.last_feedback_capture.map_or(0, |value| value.0),
    );
    write_u64(
        &mut body,
        LAST_OUTBOUND_FRAME_OFFSET,
        checkpoint.last_outbound_frame.unwrap_or(0),
    );
    write_u64(
        &mut body,
        NEXT_COMMIT_ORDINAL_OFFSET,
        checkpoint.next_commit_ordinal,
    );
    body[PHASE_OFFSET] = phase_wire(checkpoint.phase);
    encode_native_audit_record(
        scope_ticket,
        NativeAuditRecordVariant::Checkpoint,
        &body,
        output,
    )
}

/// Decode one exact checkpoint record and return its envelope scope/ticket.
///
/// This validates canonical wire representation, not deployment semantics or replay
/// ownership. In particular, decoding metadata does not authorize runnable recovery;
/// [`crate::native_live::NativeLiveCoordinator`] retains that fail-closed boundary.
///
/// # Errors
///
/// Returns a generic envelope error, an exact checkpoint body-length error, or the
/// first invalid source/option/phase/reserved-body encoding.
pub fn decode_native_live_checkpoint_record(
    input: &[u8],
) -> Result<(u64, NativeLiveCheckpoint), NativeAuditCodecError> {
    let record = decode_native_audit_record(input)?;
    if record.body.len() != NATIVE_LIVE_CHECKPOINT_BODY_LEN {
        return Err(NativeAuditCodecError::InvalidBodyLength {
            variant: record.variant,
            expected: CHECKPOINT_BODY_LEN_WIRE,
            actual: u32::try_from(record.body.len()).unwrap_or(u32::MAX),
        });
    }
    let body = record.body;
    if body[CHECKPOINT_RESERVED_OFFSET..NATIVE_LIVE_CHECKPOINT_BODY_LEN]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(NativeAuditCodecError::InvalidCheckpointReserved);
    }

    let expected_drop_copy_source = match body[DROP_COPY_OPTION_OFFSET] {
        0 => {
            if body[DROP_COPY_SOURCE_OFFSET..MONOTONIC_CLOCK_EPOCH_OFFSET]
                .iter()
                .any(|byte| *byte != 0)
            {
                return Err(NativeAuditCodecError::NonCanonicalOption(
                    NativeCheckpointOptionField::DropCopySource,
                ));
            }
            None
        }
        1 => Some(decode_source(
            body,
            DROP_COPY_SOURCE_OFFSET,
            NativeCheckpointSourceField::DropCopy,
        )?),
        value => {
            return Err(NativeAuditCodecError::InvalidOptionTag {
                field: NativeCheckpointOptionField::DropCopySource,
                value,
            });
        }
    };

    let checkpoint = NativeLiveCheckpoint {
        expected_identity: decode_identity(body, IDENTITY_OFFSET),
        expected_instrument_binding: decode_binding(body, BINDING_OFFSET),
        expected_market_data_source: decode_source(
            body,
            MARKET_DATA_SOURCE_OFFSET,
            NativeCheckpointSourceField::MarketData,
        )?,
        expected_order_entry_source: decode_source(
            body,
            ORDER_ENTRY_SOURCE_OFFSET,
            NativeCheckpointSourceField::OrderEntry,
        )?,
        expected_drop_copy_source,
        monotonic_clock_epoch: read_u64(body, MONOTONIC_CLOCK_EPOCH_OFFSET),
        expected_first_source_capture: CaptureOrdinal(read_u64(
            body,
            EXPECTED_FIRST_SOURCE_CAPTURE_OFFSET,
        )),
        last_source_capture: decode_nonzero_capture(read_u64(body, LAST_SOURCE_CAPTURE_OFFSET)),
        last_feedback_capture: decode_nonzero_capture(read_u64(body, LAST_FEEDBACK_CAPTURE_OFFSET)),
        last_outbound_frame: decode_nonzero_u64(read_u64(body, LAST_OUTBOUND_FRAME_OFFSET)),
        next_commit_ordinal: read_u64(body, NEXT_COMMIT_ORDINAL_OFFSET),
        phase: decode_phase(body[PHASE_OFFSET])?,
    };
    Ok((record.scope_ticket, checkpoint))
}

fn reject_zero_option(
    value: Option<u64>,
    field: NativeCheckpointOptionField,
) -> Result<(), NativeAuditCodecError> {
    if value == Some(0) {
        Err(NativeAuditCodecError::NonCanonicalOption(field))
    } else {
        Ok(())
    }
}

const fn decode_nonzero_capture(value: u64) -> Option<CaptureOrdinal> {
    if value == 0 {
        None
    } else {
        Some(CaptureOrdinal(value))
    }
}

const fn decode_nonzero_u64(value: u64) -> Option<u64> {
    if value == 0 { None } else { Some(value) }
}

fn encode_identity(output: &mut [u8], offset: usize, identity: VenueIdentity) {
    write_u16(output, offset, identity.venue.0);
    write_u32(output, offset + 2, identity.market_data_protocol.0);
    write_u32(output, offset + 6, identity.order_entry_protocol.0);
    write_u64(output, offset + 10, identity.session.0);
}

fn decode_identity(input: &[u8], offset: usize) -> VenueIdentity {
    VenueIdentity {
        venue: VenueId(read_u16(input, offset)),
        market_data_protocol: ProtocolId(read_u32(input, offset + 2)),
        order_entry_protocol: ProtocolId(read_u32(input, offset + 6)),
        session: SessionId(read_u64(input, offset + 10)),
    }
}

fn encode_binding(output: &mut [u8], offset: usize, binding: InstrumentDefinitionBinding) {
    write_u16(output, offset, binding.venue.0);
    write_u32(output, offset + 2, binding.instrument.0);
    write_u64(output, offset + 6, binding.native_product.0);
    write_u64(output, offset + 14, binding.authority.0);
    write_u64(output, offset + 22, binding.reference_data_version);
    output[offset + 30..offset + 62].copy_from_slice(&binding.reference_data_digest.0);
}

fn decode_binding(input: &[u8], offset: usize) -> InstrumentDefinitionBinding {
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&input[offset + 30..offset + 62]);
    InstrumentDefinitionBinding {
        venue: VenueId(read_u16(input, offset)),
        instrument: InstrumentId(read_u32(input, offset + 2)),
        native_product: NativeProductId(read_u64(input, offset + 6)),
        authority: ReferenceDataAuthorityId(read_u64(input, offset + 14)),
        reference_data_version: read_u64(input, offset + 22),
        reference_data_digest: ReferenceDataDigest(digest),
    }
}

fn encode_source(output: &mut [u8], offset: usize, source: EventSource) {
    write_u32(output, offset, source.id.protocol);
    write_u32(output, offset + 4, source.id.channel);
    write_u64(output, offset + 8, source.session_epoch.0);
    output[offset + 16] = source.sequence_domain as u8;
}

fn decode_source(
    input: &[u8],
    offset: usize,
    field: NativeCheckpointSourceField,
) -> Result<EventSource, NativeAuditCodecError> {
    let domain_wire = input[offset + 16];
    let sequence_domain = SequenceDomain::from_wire(domain_wire).ok_or(
        NativeAuditCodecError::InvalidSequenceDomain {
            field,
            value: domain_wire,
        },
    )?;
    Ok(EventSource::new(
        SourceId::new(read_u32(input, offset), read_u32(input, offset + 4)),
        sequence_domain,
        SessionEpoch(read_u64(input, offset + 8)),
    ))
}

const fn phase_wire(phase: NativeLivePhase) -> u8 {
    match phase {
        NativeLivePhase::Ready => 0,
        NativeLivePhase::SafetyPending => 1,
        NativeLivePhase::KilledRecovery => 2,
        NativeLivePhase::Ambiguous => 3,
        NativeLivePhase::Failed => 4,
    }
}

const fn decode_phase(value: u8) -> Result<NativeLivePhase, NativeAuditCodecError> {
    match value {
        0 => Ok(NativeLivePhase::Ready),
        1 => Ok(NativeLivePhase::SafetyPending),
        2 => Ok(NativeLivePhase::KilledRecovery),
        3 => Ok(NativeLivePhase::Ambiguous),
        4 => Ok(NativeLivePhase::Failed),
        _ => Err(NativeAuditCodecError::InvalidPhase(value)),
    }
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
