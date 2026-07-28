//! Canonical provider-neutral framing for audit-prefix anchor records.
//!
//! A `QHPA` record is exactly 296 bytes. Bytes `0..264` are the authenticated
//! message and bytes `264..296` carry an opaque deployment-provided 256-bit tag.
//! This module performs only canonical encoding and structural/semantic validation.
//! It does **not** calculate or verify a MAC, flush either the audit container or
//! anchor durably, perform compare-and-swap publication, establish freshness, or
//! authorize recovery. A deployment must authenticate the exact 264-byte prefix,
//! publish the complete record in a freshness domain outside the writable journal,
//! and make its own fail-closed recovery decision.
//!
//! In particular, this version's single ticket state and unresolved-intent count do
//! not identify exact intents or prove reconciliation; the `next_*` values are
//! encoded claims, not replay-derived leases. Bytes past `committed_file_length` must
//! be retired after a crash, and QHAC-v2 generation rotation still requires a valid
//! predecessor terminal seal. Safe recovered-prefix terminalization (or a later
//! predecessor-to-prefix-anchor protocol) is outside this codec.

use crate::audit_container::{
    AUDIT_CONTAINER_HEADER_LEN, AUDIT_CONTAINER_SEAL_LEN, AUDIT_RECORD_PREFIX_LEN, AUDIT_TAG_LEN,
    AuditContainerHeader, AuditContainerId, AuditHeaderError, AuditRecordKind, AuditTag,
};

pub const AUDIT_PREFIX_MAGIC: [u8; 4] = *b"QHPA";
pub const AUDIT_PREFIX_VERSION: u16 = 1;
pub const AUDIT_PREFIX_AUTHENTICATED_LEN: usize = 264;
pub const AUDIT_PREFIX_TAG_LEN: usize = AUDIT_TAG_LEN;
pub const AUDIT_PREFIX_RECORD_LEN: usize = AUDIT_PREFIX_AUTHENTICATED_LEN + AUDIT_PREFIX_TAG_LEN;

const AUTHENTICATED_LEN_WIRE: u16 = 264;
const RECORD_LEN_WIRE: u32 = 296;

const FLAGS_OFFSET: usize = 12;
const ALGORITHM_ID_OFFSET: usize = 16;
const RESERVED_WORD_OFFSET: usize = 20;
const KEY_ID_OFFSET: usize = 24;
const ANCHOR_SEQUENCE_OFFSET: usize = 32;
const PREVIOUS_ANCHOR_SEQUENCE_OFFSET: usize = 40;
const CONTAINER_ID_OFFSET: usize = 48;
const CONTAINER_GENERATION_OFFSET: usize = 64;
const COMMITTED_FILE_LENGTH_OFFSET: usize = 72;
const RECORD_COUNT_OFFSET: usize = 80;
const FIRST_RECORD_ORDINAL_OFFSET: usize = 88;
const LAST_RECORD_ORDINAL_OFFSET: usize = 96;
const HEADER_TAG_OFFSET: usize = 104;
const CURRENT_RECORD_CHAIN_TAG_OFFSET: usize = 136;
const SCOPE_TICKET_OFFSET: usize = 168;
const TICKET_STATE_OFFSET: usize = 176;
const LAST_RECORD_KIND_OFFSET: usize = 178;
const LAST_RECORD_VARIANT_OFFSET: usize = 180;
const UNRESOLVED_INTENT_COUNT_OFFSET: usize = 182;
const RESERVED_BYTE_OFFSET: usize = 183;
const NEXT_RECORD_ORDINAL_OFFSET: usize = 184;
const NEXT_FRAME_ORDINAL_OFFSET: usize = 192;
const NEXT_CAPTURE_ORDINAL_OFFSET: usize = 200;
const NEXT_COMMIT_ORDINAL_OFFSET: usize = 208;
const NEXT_TICKET_ID_OFFSET: usize = 216;
const MONOTONIC_CLOCK_EPOCH_OFFSET: usize = 224;
const PREVIOUS_ANCHOR_TAG_OFFSET: usize = 232;
const DEPLOYMENT_TAG_OFFSET: usize = AUDIT_PREFIX_AUTHENTICATED_LEN;

const MIN_RECORD_WIRE_LEN: u64 = (AUDIT_RECORD_PREFIX_LEN + AUDIT_TAG_LEN) as u64;
const HEADER_WIRE_LEN: u64 = AUDIT_CONTAINER_HEADER_LEN as u64;
const SEAL_WIRE_LEN: u64 = AUDIT_CONTAINER_SEAL_LEN as u64;
const MAX_UNRESOLVED_INTENTS: u8 = 2;

/// Canonical `QHPA` state flags. Unknown bits are rejected.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct AuditPrefixFlags(u32);

impl AuditPrefixFlags {
    pub const NONE: Self = Self(0);
    pub const EMERGENCY_LANE: Self = Self(1 << 0);
    pub const CONTAINER_SEALED: Self = Self(1 << 1);

    const KNOWN_BITS: u32 = Self::EMERGENCY_LANE.0 | Self::CONTAINER_SEALED.0;

    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    const fn from_wire(bits: u32) -> Option<Self> {
        if bits & !Self::KNOWN_BITS == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }
}

/// Lifecycle claim encoded by one prefix anchor.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum AuditPrefixTicketState {
    HeaderOnly = 0,
    BetweenTickets = 1,
    TicketOpen = 2,
    TicketUnresolvedIntent = 3,
    TicketClosed = 4,
    TicketAborted = 5,
    EmergencyOpen = 6,
    EmergencyClosed = 7,
    ContainerSealed = 8,
}

impl AuditPrefixTicketState {
    const fn from_wire(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::HeaderOnly),
            1 => Some(Self::BetweenTickets),
            2 => Some(Self::TicketOpen),
            3 => Some(Self::TicketUnresolvedIntent),
            4 => Some(Self::TicketClosed),
            5 => Some(Self::TicketAborted),
            6 => Some(Self::EmergencyOpen),
            7 => Some(Self::EmergencyClosed),
            8 => Some(Self::ContainerSealed),
            _ => None,
        }
    }
}

/// QHLR payload discriminator carried beside the outer audit-record kind.
///
/// Zero is reserved for an anchor with no retained records. Values other than the
/// currently assigned checkpoint value are preserved for the remaining QHLR codecs;
/// their outer-kind mapping must be validated by those codecs before publication.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct AuditPrefixRecordVariant(pub u16);

impl AuditPrefixRecordVariant {
    pub const NONE: Self = Self(0);
    pub const CHECKPOINT: Self = Self(1);
}

/// Nonzero monotonic cursor whose canonical validation failed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuditPrefixCursor {
    NextRecordOrdinal,
    NextFrameOrdinal,
    NextCaptureOrdinal,
    NextCommitOrdinal,
}

/// Header identity field to which the prefix anchor did not bind.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuditPrefixHeaderField {
    AlgorithmId,
    KeyId,
    ContainerId,
    ContainerGeneration,
    FirstRecordOrdinal,
    HeaderTag,
    MonotonicClockEpoch,
}

/// Exact canonical framing, semantic, or header-binding rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditPrefixError {
    BufferTooSmall { required: usize, available: usize },
    Truncated { required: usize, available: usize },
    TrailingBytes(usize),
    InvalidMagic,
    UnsupportedVersion(u16),
    InvalidAuthenticatedLength(u16),
    InvalidTotalLength(u32),
    UnknownFlags(u32),
    InvalidReserved,
    InvalidTicketState(u16),
    InvalidHeader(AuditHeaderError),
    HeaderMismatch(AuditPrefixHeaderField),
    InvalidAlgorithmId,
    InvalidKeyId,
    InvalidAnchorSequence,
    InvalidPreviousAnchorSequence,
    NonCanonicalPreviousAnchorTag,
    InvalidContainerId,
    InvalidContainerGeneration,
    InvalidMonotonicClockEpoch,
    InvalidCommittedFileLength,
    InvalidRecordOrdinals,
    InvalidCurrentRecordChainTag,
    InvalidScopeTicket,
    InvalidRecordKind,
    InvalidRecordVariant,
    InvalidUnresolvedIntentCount,
    InvalidTicketSemantics(AuditPrefixTicketState),
    InvalidCursor(AuditPrefixCursor),
}

/// Semantic fields encoded in the authenticated 264-byte `QHPA` prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditPrefixAnchor {
    pub flags: AuditPrefixFlags,
    pub algorithm_id: u32,
    pub key_id: u64,
    pub anchor_sequence: u64,
    pub previous_anchor_sequence: u64,
    pub container_id: AuditContainerId,
    pub container_generation: u64,
    pub committed_file_length: u64,
    pub record_count: u64,
    pub first_record_ordinal: u64,
    pub last_record_ordinal: u64,
    pub header_tag: AuditTag,
    pub current_record_chain_tag: AuditTag,
    pub scope_ticket: u64,
    pub ticket_state: AuditPrefixTicketState,
    pub last_record_kind: AuditRecordKind,
    pub last_record_variant: AuditPrefixRecordVariant,
    pub unresolved_intent_count: u8,
    pub next_record_ordinal: u64,
    pub next_frame_ordinal: u64,
    pub next_capture_ordinal: u64,
    pub next_commit_ordinal: u64,
    pub next_ticket_id: u64,
    pub monotonic_clock_epoch: u64,
    pub previous_anchor_tag: AuditTag,
}

impl AuditPrefixAnchor {
    /// Validate canonical semantics without claiming authentication or freshness.
    ///
    /// # Errors
    ///
    /// Returns the first invalid sequence, identity, ordinal, cursor, or lifecycle
    /// relationship.
    pub fn validate(&self) -> Result<(), AuditPrefixError> {
        if self.algorithm_id == 0 {
            return Err(AuditPrefixError::InvalidAlgorithmId);
        }
        if self.key_id == 0 {
            return Err(AuditPrefixError::InvalidKeyId);
        }
        if self.anchor_sequence == 0 {
            return Err(AuditPrefixError::InvalidAnchorSequence);
        }
        let expected_previous = self.anchor_sequence - 1;
        if self.previous_anchor_sequence != expected_previous {
            return Err(AuditPrefixError::InvalidPreviousAnchorSequence);
        }
        if self.anchor_sequence == 1 && !all_zero(&self.previous_anchor_tag.0) {
            return Err(AuditPrefixError::NonCanonicalPreviousAnchorTag);
        }
        if self.container_id.is_zero() {
            return Err(AuditPrefixError::InvalidContainerId);
        }
        if self.container_generation == 0 {
            return Err(AuditPrefixError::InvalidContainerGeneration);
        }
        if self.first_record_ordinal == 0 {
            return Err(AuditPrefixError::InvalidRecordOrdinals);
        }

        self.validate_record_ordinals()?;
        self.validate_cursors()?;
        self.validate_record_identity()?;
        self.validate_ticket_state()?;
        self.validate_committed_length()?;
        Ok(())
    }

    /// Bind all duplicated header identity and the authenticated header tag.
    ///
    /// This comparison is semantic only. `expected_header_tag` must already have
    /// been obtained from a separately authenticated container header.
    ///
    /// # Errors
    ///
    /// Returns an invalid-header error or the first mismatched binding field.
    pub fn validate_against_header(
        &self,
        header: &AuditContainerHeader,
        expected_header_tag: AuditTag,
    ) -> Result<(), AuditPrefixError> {
        self.validate()?;
        header.validate().map_err(AuditPrefixError::InvalidHeader)?;
        if self.algorithm_id != header.algorithm_id {
            return Err(AuditPrefixError::HeaderMismatch(
                AuditPrefixHeaderField::AlgorithmId,
            ));
        }
        if self.key_id != header.key_id {
            return Err(AuditPrefixError::HeaderMismatch(
                AuditPrefixHeaderField::KeyId,
            ));
        }
        if self.container_id != header.container_id {
            return Err(AuditPrefixError::HeaderMismatch(
                AuditPrefixHeaderField::ContainerId,
            ));
        }
        if self.container_generation != header.generation {
            return Err(AuditPrefixError::HeaderMismatch(
                AuditPrefixHeaderField::ContainerGeneration,
            ));
        }
        if self.first_record_ordinal != header.first_record_ordinal {
            return Err(AuditPrefixError::HeaderMismatch(
                AuditPrefixHeaderField::FirstRecordOrdinal,
            ));
        }
        if self.header_tag != expected_header_tag {
            return Err(AuditPrefixError::HeaderMismatch(
                AuditPrefixHeaderField::HeaderTag,
            ));
        }
        if self.monotonic_clock_epoch != header.monotonic_clock_epoch {
            return Err(AuditPrefixError::HeaderMismatch(
                AuditPrefixHeaderField::MonotonicClockEpoch,
            ));
        }
        Ok(())
    }

    fn validate_record_ordinals(&self) -> Result<(), AuditPrefixError> {
        if self.record_count == 0 {
            if self.last_record_ordinal != 0
                || self.next_record_ordinal != self.first_record_ordinal
            {
                return Err(AuditPrefixError::InvalidRecordOrdinals);
            }
            return Ok(());
        }

        let Some(last_offset) = self.record_count.checked_sub(1) else {
            return Err(AuditPrefixError::InvalidRecordOrdinals);
        };
        let Some(expected_last) = self.first_record_ordinal.checked_add(last_offset) else {
            return Err(AuditPrefixError::InvalidRecordOrdinals);
        };
        let Some(expected_next) = expected_last.checked_add(1) else {
            return Err(AuditPrefixError::InvalidRecordOrdinals);
        };
        if self.last_record_ordinal != expected_last || self.next_record_ordinal != expected_next {
            return Err(AuditPrefixError::InvalidRecordOrdinals);
        }
        Ok(())
    }

    fn validate_cursors(&self) -> Result<(), AuditPrefixError> {
        for (value, cursor) in [
            (
                self.next_record_ordinal,
                AuditPrefixCursor::NextRecordOrdinal,
            ),
            (self.next_frame_ordinal, AuditPrefixCursor::NextFrameOrdinal),
            (
                self.next_capture_ordinal,
                AuditPrefixCursor::NextCaptureOrdinal,
            ),
            (
                self.next_commit_ordinal,
                AuditPrefixCursor::NextCommitOrdinal,
            ),
        ] {
            if value == 0 {
                return Err(AuditPrefixError::InvalidCursor(cursor));
            }
        }
        if self.monotonic_clock_epoch == 0 {
            return Err(AuditPrefixError::InvalidMonotonicClockEpoch);
        }
        Ok(())
    }

    fn validate_record_identity(&self) -> Result<(), AuditPrefixError> {
        if self.record_count == 0 {
            if self.last_record_kind.0 != 0 {
                return Err(AuditPrefixError::InvalidRecordKind);
            }
            if self.last_record_variant != AuditPrefixRecordVariant::NONE {
                return Err(AuditPrefixError::InvalidRecordVariant);
            }
            if self.current_record_chain_tag != self.header_tag {
                return Err(AuditPrefixError::InvalidCurrentRecordChainTag);
            }
            return Ok(());
        }

        if self.last_record_kind.0 == 0 {
            return Err(AuditPrefixError::InvalidRecordKind);
        }
        if self.last_record_variant == AuditPrefixRecordVariant::NONE {
            return Err(AuditPrefixError::InvalidRecordVariant);
        }
        let checkpoint_kind = self.last_record_kind == AuditRecordKind::LIVE_CHECKPOINT;
        let checkpoint_variant = self.last_record_variant == AuditPrefixRecordVariant::CHECKPOINT;
        if checkpoint_kind != checkpoint_variant {
            return Err(AuditPrefixError::InvalidRecordVariant);
        }
        Ok(())
    }

    fn validate_ticket_state(&self) -> Result<(), AuditPrefixError> {
        let emergency = self.flags.contains(AuditPrefixFlags::EMERGENCY_LANE);
        let sealed = self.flags.contains(AuditPrefixFlags::CONTAINER_SEALED);
        let emergency_state = matches!(
            self.ticket_state,
            AuditPrefixTicketState::EmergencyOpen | AuditPrefixTicketState::EmergencyClosed
        );
        if sealed != (self.ticket_state == AuditPrefixTicketState::ContainerSealed) {
            return Err(AuditPrefixError::InvalidTicketSemantics(self.ticket_state));
        }
        if emergency_state != emergency
            && self.ticket_state != AuditPrefixTicketState::ContainerSealed
        {
            return Err(AuditPrefixError::InvalidTicketSemantics(self.ticket_state));
        }

        let scoped = matches!(
            self.ticket_state,
            AuditPrefixTicketState::TicketOpen
                | AuditPrefixTicketState::TicketUnresolvedIntent
                | AuditPrefixTicketState::TicketClosed
                | AuditPrefixTicketState::TicketAborted
        );
        // `NativeLiveAudit::Ticket` currently permits the numeric value zero. The
        // state says whether this opaque wire value is in scope; numeric ordering
        // against `next_ticket_id` would invent a stronger ticket contract.
        if !scoped && self.scope_ticket != 0 {
            return Err(AuditPrefixError::InvalidScopeTicket);
        }

        match self.ticket_state {
            AuditPrefixTicketState::HeaderOnly => {
                if self.record_count != 0 || self.unresolved_intent_count != 0 {
                    return Err(AuditPrefixError::InvalidTicketSemantics(self.ticket_state));
                }
            }
            AuditPrefixTicketState::BetweenTickets
            | AuditPrefixTicketState::TicketOpen
            | AuditPrefixTicketState::TicketClosed
            | AuditPrefixTicketState::TicketAborted
            | AuditPrefixTicketState::EmergencyOpen
            | AuditPrefixTicketState::EmergencyClosed => {
                if self.record_count == 0 {
                    return Err(AuditPrefixError::InvalidTicketSemantics(self.ticket_state));
                }
            }
            AuditPrefixTicketState::TicketUnresolvedIntent => {
                if self.record_count == 0
                    || self.unresolved_intent_count == 0
                    || self.unresolved_intent_count > MAX_UNRESOLVED_INTENTS
                    || self.last_record_kind != AuditRecordKind::NATIVE_INTENT
                    || self.last_record_variant == AuditPrefixRecordVariant::CHECKPOINT
                {
                    return Err(AuditPrefixError::InvalidTicketSemantics(self.ticket_state));
                }
            }
            AuditPrefixTicketState::ContainerSealed => {}
        }

        if self.ticket_state != AuditPrefixTicketState::TicketUnresolvedIntent
            && self.unresolved_intent_count != 0
        {
            return Err(AuditPrefixError::InvalidUnresolvedIntentCount);
        }
        if self.ticket_state == AuditPrefixTicketState::TicketClosed
            && (self.last_record_kind != AuditRecordKind::LIVE_CHECKPOINT
                || self.last_record_variant != AuditPrefixRecordVariant::CHECKPOINT)
        {
            return Err(AuditPrefixError::InvalidTicketSemantics(self.ticket_state));
        }
        if self.ticket_state == AuditPrefixTicketState::TicketAborted
            && (self.last_record_kind != AuditRecordKind::ABORTED_RESERVATION
                || self.last_record_variant == AuditPrefixRecordVariant::CHECKPOINT)
        {
            return Err(AuditPrefixError::InvalidTicketSemantics(self.ticket_state));
        }
        Ok(())
    }

    fn validate_committed_length(&self) -> Result<(), AuditPrefixError> {
        let Some(records_len) = self.record_count.checked_mul(MIN_RECORD_WIRE_LEN) else {
            return Err(AuditPrefixError::InvalidCommittedFileLength);
        };
        let Some(mut minimum) = HEADER_WIRE_LEN.checked_add(records_len) else {
            return Err(AuditPrefixError::InvalidCommittedFileLength);
        };
        if self.ticket_state == AuditPrefixTicketState::ContainerSealed {
            let Some(sealed_minimum) = minimum.checked_add(SEAL_WIRE_LEN) else {
                return Err(AuditPrefixError::InvalidCommittedFileLength);
            };
            minimum = sealed_minimum;
        }
        if self.committed_file_length < minimum
            || (self.ticket_state == AuditPrefixTicketState::HeaderOnly
                && self.committed_file_length != HEADER_WIRE_LEN)
        {
            return Err(AuditPrefixError::InvalidCommittedFileLength);
        }
        Ok(())
    }
}

/// Decoded semantic anchor plus its still-unverified deployment tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaggedAuditPrefixAnchor {
    pub anchor: AuditPrefixAnchor,
    pub deployment_tag: AuditTag,
}

/// Encode exactly the 264 bytes a deployment authenticator must authenticate.
///
/// Bytes after the returned length are untouched. Successful encoding proves only
/// canonical structure and binding to the supplied header/tag; it does not publish,
/// flush, authenticate, or establish freshness for the anchor.
///
/// # Errors
///
/// Returns the first semantic/header-binding error or a short-buffer error.
pub fn encode_audit_prefix_authenticated(
    anchor: &AuditPrefixAnchor,
    header: &AuditContainerHeader,
    expected_header_tag: AuditTag,
    output: &mut [u8],
) -> Result<usize, AuditPrefixError> {
    anchor.validate_against_header(header, expected_header_tag)?;
    require_output(output, AUDIT_PREFIX_AUTHENTICATED_LEN)?;
    encode_authenticated_unchecked(anchor, &mut output[..AUDIT_PREFIX_AUTHENTICATED_LEN]);
    Ok(AUDIT_PREFIX_AUTHENTICATED_LEN)
}

/// Encode one complete 296-byte `QHPA` record with an opaque deployment tag.
///
/// The caller must calculate `deployment_tag` over the exact output of
/// [`encode_audit_prefix_authenticated`]. This function does not verify that fact.
/// Bytes after the returned record are untouched.
///
/// # Errors
///
/// Returns the first semantic/header-binding error or a short-buffer error.
pub fn encode_audit_prefix_anchor(
    anchor: &AuditPrefixAnchor,
    header: &AuditContainerHeader,
    expected_header_tag: AuditTag,
    deployment_tag: AuditTag,
    output: &mut [u8],
) -> Result<usize, AuditPrefixError> {
    anchor.validate_against_header(header, expected_header_tag)?;
    require_output(output, AUDIT_PREFIX_RECORD_LEN)?;
    let record = &mut output[..AUDIT_PREFIX_RECORD_LEN];
    encode_authenticated_unchecked(anchor, &mut record[..AUDIT_PREFIX_AUTHENTICATED_LEN]);
    record[DEPLOYMENT_TAG_OFFSET..AUDIT_PREFIX_RECORD_LEN].copy_from_slice(&deployment_tag.0);
    Ok(AUDIT_PREFIX_RECORD_LEN)
}

/// Decode one exact 296-byte `QHPA` record and bind it to a verified header identity.
///
/// The returned deployment tag remains opaque and unverified. A successful return
/// is not evidence of MAC validity, durable persistence, CAS publication, freshness,
/// or recovery authorization. The deployment must verify `input[..264]` against the
/// returned tag through its reviewed authentication provider.
///
/// # Errors
///
/// Returns the first framing, canonical, semantic, or header-binding error.
pub fn decode_audit_prefix_anchor(
    input: &[u8],
    header: &AuditContainerHeader,
    expected_header_tag: AuditTag,
) -> Result<TaggedAuditPrefixAnchor, AuditPrefixError> {
    if input.len() < AUDIT_PREFIX_RECORD_LEN {
        return Err(AuditPrefixError::Truncated {
            required: AUDIT_PREFIX_RECORD_LEN,
            available: input.len(),
        });
    }
    if input.len() > AUDIT_PREFIX_RECORD_LEN {
        return Err(AuditPrefixError::TrailingBytes(
            input.len() - AUDIT_PREFIX_RECORD_LEN,
        ));
    }
    if input[0..4] != AUDIT_PREFIX_MAGIC {
        return Err(AuditPrefixError::InvalidMagic);
    }
    let version = read_u16(input, 4);
    if version != AUDIT_PREFIX_VERSION {
        return Err(AuditPrefixError::UnsupportedVersion(version));
    }
    let authenticated_len = read_u16(input, 6);
    if authenticated_len != AUTHENTICATED_LEN_WIRE {
        return Err(AuditPrefixError::InvalidAuthenticatedLength(
            authenticated_len,
        ));
    }
    let total_len = read_u32(input, 8);
    if total_len != RECORD_LEN_WIRE {
        return Err(AuditPrefixError::InvalidTotalLength(total_len));
    }
    let flags_bits = read_u32(input, FLAGS_OFFSET);
    let flags = AuditPrefixFlags::from_wire(flags_bits)
        .ok_or(AuditPrefixError::UnknownFlags(flags_bits))?;
    if read_u32(input, RESERVED_WORD_OFFSET) != 0 || input[RESERVED_BYTE_OFFSET] != 0 {
        return Err(AuditPrefixError::InvalidReserved);
    }
    let ticket_state_wire = read_u16(input, TICKET_STATE_OFFSET);
    let ticket_state = AuditPrefixTicketState::from_wire(ticket_state_wire)
        .ok_or(AuditPrefixError::InvalidTicketState(ticket_state_wire))?;

    let mut container_id = [0_u8; 16];
    container_id.copy_from_slice(&input[CONTAINER_ID_OFFSET..CONTAINER_GENERATION_OFFSET]);
    let mut header_tag = [0_u8; AUDIT_TAG_LEN];
    header_tag.copy_from_slice(&input[HEADER_TAG_OFFSET..CURRENT_RECORD_CHAIN_TAG_OFFSET]);
    let mut chain_tag = [0_u8; AUDIT_TAG_LEN];
    chain_tag.copy_from_slice(&input[CURRENT_RECORD_CHAIN_TAG_OFFSET..SCOPE_TICKET_OFFSET]);
    let mut previous_anchor_tag = [0_u8; AUDIT_TAG_LEN];
    previous_anchor_tag.copy_from_slice(&input[PREVIOUS_ANCHOR_TAG_OFFSET..DEPLOYMENT_TAG_OFFSET]);
    let mut deployment_tag = [0_u8; AUDIT_TAG_LEN];
    deployment_tag.copy_from_slice(&input[DEPLOYMENT_TAG_OFFSET..AUDIT_PREFIX_RECORD_LEN]);

    let anchor = AuditPrefixAnchor {
        flags,
        algorithm_id: read_u32(input, ALGORITHM_ID_OFFSET),
        key_id: read_u64(input, KEY_ID_OFFSET),
        anchor_sequence: read_u64(input, ANCHOR_SEQUENCE_OFFSET),
        previous_anchor_sequence: read_u64(input, PREVIOUS_ANCHOR_SEQUENCE_OFFSET),
        container_id: AuditContainerId(container_id),
        container_generation: read_u64(input, CONTAINER_GENERATION_OFFSET),
        committed_file_length: read_u64(input, COMMITTED_FILE_LENGTH_OFFSET),
        record_count: read_u64(input, RECORD_COUNT_OFFSET),
        first_record_ordinal: read_u64(input, FIRST_RECORD_ORDINAL_OFFSET),
        last_record_ordinal: read_u64(input, LAST_RECORD_ORDINAL_OFFSET),
        header_tag: AuditTag(header_tag),
        current_record_chain_tag: AuditTag(chain_tag),
        scope_ticket: read_u64(input, SCOPE_TICKET_OFFSET),
        ticket_state,
        last_record_kind: AuditRecordKind(read_u16(input, LAST_RECORD_KIND_OFFSET)),
        last_record_variant: AuditPrefixRecordVariant(read_u16(input, LAST_RECORD_VARIANT_OFFSET)),
        unresolved_intent_count: input[UNRESOLVED_INTENT_COUNT_OFFSET],
        next_record_ordinal: read_u64(input, NEXT_RECORD_ORDINAL_OFFSET),
        next_frame_ordinal: read_u64(input, NEXT_FRAME_ORDINAL_OFFSET),
        next_capture_ordinal: read_u64(input, NEXT_CAPTURE_ORDINAL_OFFSET),
        next_commit_ordinal: read_u64(input, NEXT_COMMIT_ORDINAL_OFFSET),
        next_ticket_id: read_u64(input, NEXT_TICKET_ID_OFFSET),
        monotonic_clock_epoch: read_u64(input, MONOTONIC_CLOCK_EPOCH_OFFSET),
        previous_anchor_tag: AuditTag(previous_anchor_tag),
    };
    anchor.validate_against_header(header, expected_header_tag)?;
    Ok(TaggedAuditPrefixAnchor {
        anchor,
        deployment_tag: AuditTag(deployment_tag),
    })
}

fn encode_authenticated_unchecked(anchor: &AuditPrefixAnchor, output: &mut [u8]) {
    output.fill(0);
    output[0..4].copy_from_slice(&AUDIT_PREFIX_MAGIC);
    write_u16(output, 4, AUDIT_PREFIX_VERSION);
    write_u16(output, 6, AUTHENTICATED_LEN_WIRE);
    write_u32(output, 8, RECORD_LEN_WIRE);
    write_u32(output, FLAGS_OFFSET, anchor.flags.bits());
    write_u32(output, ALGORITHM_ID_OFFSET, anchor.algorithm_id);
    write_u64(output, KEY_ID_OFFSET, anchor.key_id);
    write_u64(output, ANCHOR_SEQUENCE_OFFSET, anchor.anchor_sequence);
    write_u64(
        output,
        PREVIOUS_ANCHOR_SEQUENCE_OFFSET,
        anchor.previous_anchor_sequence,
    );
    output[CONTAINER_ID_OFFSET..CONTAINER_GENERATION_OFFSET]
        .copy_from_slice(&anchor.container_id.0);
    write_u64(
        output,
        CONTAINER_GENERATION_OFFSET,
        anchor.container_generation,
    );
    write_u64(
        output,
        COMMITTED_FILE_LENGTH_OFFSET,
        anchor.committed_file_length,
    );
    write_u64(output, RECORD_COUNT_OFFSET, anchor.record_count);
    write_u64(
        output,
        FIRST_RECORD_ORDINAL_OFFSET,
        anchor.first_record_ordinal,
    );
    write_u64(
        output,
        LAST_RECORD_ORDINAL_OFFSET,
        anchor.last_record_ordinal,
    );
    output[HEADER_TAG_OFFSET..CURRENT_RECORD_CHAIN_TAG_OFFSET]
        .copy_from_slice(&anchor.header_tag.0);
    output[CURRENT_RECORD_CHAIN_TAG_OFFSET..SCOPE_TICKET_OFFSET]
        .copy_from_slice(&anchor.current_record_chain_tag.0);
    write_u64(output, SCOPE_TICKET_OFFSET, anchor.scope_ticket);
    write_u16(output, TICKET_STATE_OFFSET, anchor.ticket_state as u16);
    write_u16(output, LAST_RECORD_KIND_OFFSET, anchor.last_record_kind.0);
    write_u16(
        output,
        LAST_RECORD_VARIANT_OFFSET,
        anchor.last_record_variant.0,
    );
    output[UNRESOLVED_INTENT_COUNT_OFFSET] = anchor.unresolved_intent_count;
    write_u64(
        output,
        NEXT_RECORD_ORDINAL_OFFSET,
        anchor.next_record_ordinal,
    );
    write_u64(output, NEXT_FRAME_ORDINAL_OFFSET, anchor.next_frame_ordinal);
    write_u64(
        output,
        NEXT_CAPTURE_ORDINAL_OFFSET,
        anchor.next_capture_ordinal,
    );
    write_u64(
        output,
        NEXT_COMMIT_ORDINAL_OFFSET,
        anchor.next_commit_ordinal,
    );
    write_u64(output, NEXT_TICKET_ID_OFFSET, anchor.next_ticket_id);
    write_u64(
        output,
        MONOTONIC_CLOCK_EPOCH_OFFSET,
        anchor.monotonic_clock_epoch,
    );
    output[PREVIOUS_ANCHOR_TAG_OFFSET..DEPLOYMENT_TAG_OFFSET]
        .copy_from_slice(&anchor.previous_anchor_tag.0);
}

fn require_output(output: &[u8], required: usize) -> Result<(), AuditPrefixError> {
    if output.len() < required {
        return Err(AuditPrefixError::BufferTooSmall {
            required,
            available: output.len(),
        });
    }
    Ok(())
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
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

fn write_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(output: &mut [u8], offset: usize, value: u64) {
    output[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
