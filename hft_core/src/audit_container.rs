//! Authenticated, append-only retained-record container framing.
//!
//! This module defines domain-separated wire framing and verification state, not a
//! cryptographic primitive, filesystem writer, key store, or freshness oracle. A
//! production deployment must supply a reviewed [`AuditAuthenticator`] (normally a
//! dedicated-key MAC backed by protected key material), persist every returned byte
//! range durably and in order, and compare the terminal [`AuditAnchor`] with a latest
//! anchor held outside the writable journal failure domain.
//!
//! The external anchor is essential. An authenticated file proves integrity, but an
//! attacker who can replace the whole file can otherwise replay an older, completely
//! valid file. A monotonic HSM record, independently replicated ledger, or WORM object
//! manifest must retain the latest anchor before recovery may trust the container.

use core::fmt;

use crate::control::ConfigDigest;
use crate::events::{EventSource, SequenceDomain, SessionEpoch, SourceId};
use crate::reference_data::{
    InstrumentDefinitionBinding, NativeProductId, ReferenceDataAuthorityId, ReferenceDataDigest,
};
use crate::types::{InstrumentId, VenueId};
use crate::venue::{ProtocolId, SessionId, VenueIdentity};

pub const AUDIT_CONTAINER_MAGIC: [u8; 4] = *b"QHAC";
pub const AUDIT_CONTAINER_VERSION: u16 = 2;
pub const AUDIT_CONTAINER_HEADER_LEN: usize = 376;
pub const AUDIT_RECORD_MAGIC: [u8; 4] = *b"QHAR";
pub const AUDIT_RECORD_PREFIX_LEN: usize = 88;
pub const AUDIT_TAG_LEN: usize = 32;
pub const AUDIT_SEAL_MAGIC: [u8; 4] = *b"QHAS";
pub const AUDIT_CONTAINER_SEAL_LEN: usize = 160;

const HEADER_TAG_OFFSET: usize = 344;
const SEAL_TAG_OFFSET: usize = 128;
const RECORD_FIXED_LEN: usize = AUDIT_RECORD_PREFIX_LEN + AUDIT_TAG_LEN;
const HEADER_LEN_WIRE: u16 = 376;
const RECORD_PREFIX_LEN_WIRE: u16 = 88;
const SEAL_PREFIX_LEN_WIRE: u16 = 128;
const SEAL_LEN_WIRE: u32 = 160;

/// Opaque 128-bit identifier generated independently for one retained container.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct AuditContainerId(pub [u8; 16]);

impl AuditContainerId {
    #[must_use]
    pub fn is_zero(self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

/// Fixed 256-bit tag emitted and verified by the deployment authenticator.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct AuditTag(pub [u8; AUDIT_TAG_LEN]);

/// Link from a rotated container to the authenticated terminal seal of its parent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditPredecessor {
    pub container_id: AuditContainerId,
    pub generation: u64,
    pub seal_tag: AuditTag,
}

/// Exact identity authenticated by the container header.
///
/// `config_digest` must cover every strategy, risk, reference-data, account, and
/// transport setting whose substitution would change execution. `software_digest`
/// is the deployment's canonical digest of the certified executable/artifact set.
/// The selected instrument definition is also carried explicitly so venue/product,
/// issuing authority, artifact version, and artifact digest cannot be substituted
/// behind the opaque configuration digest. `drop_copy_source` is absent only when
/// independent drop copy is not configured for this process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditContainerHeader {
    pub algorithm_id: u32,
    pub key_id: u64,
    pub container_id: AuditContainerId,
    pub generation: u64,
    pub first_record_ordinal: u64,
    pub monotonic_clock_epoch: u64,
    pub config_digest: ConfigDigest,
    pub software_digest: [u8; 32],
    pub venue_identity: VenueIdentity,
    pub market_data_source: EventSource,
    pub order_entry_source: EventSource,
    pub drop_copy_source: Option<EventSource>,
    pub instrument_definition_binding: InstrumentDefinitionBinding,
    pub predecessor: Option<AuditPredecessor>,
}

impl AuditContainerHeader {
    /// Validate all non-cryptographic header invariants.
    ///
    /// # Errors
    ///
    /// Returns the exact invalid identity or rotation invariant.
    pub fn validate(&self) -> Result<(), AuditHeaderError> {
        if self.algorithm_id == 0 {
            return Err(AuditHeaderError::InvalidAlgorithmId);
        }
        if self.key_id == 0 {
            return Err(AuditHeaderError::InvalidKeyId);
        }
        if self.container_id.is_zero() {
            return Err(AuditHeaderError::InvalidContainerId);
        }
        if self.generation == 0 {
            return Err(AuditHeaderError::InvalidGeneration);
        }
        match (self.generation, self.predecessor) {
            (1, None) => {}
            (1, Some(_)) | (_, None) => return Err(AuditHeaderError::InvalidPredecessor),
            (generation, Some(predecessor)) => {
                let Some(expected_generation) = predecessor.generation.checked_add(1) else {
                    return Err(AuditHeaderError::InvalidPredecessor);
                };
                if predecessor.container_id.is_zero()
                    || predecessor.container_id == self.container_id
                    || predecessor.generation == 0
                    || generation != expected_generation
                {
                    return Err(AuditHeaderError::InvalidPredecessor);
                }
            }
        }
        if self.first_record_ordinal == 0 {
            return Err(AuditHeaderError::InvalidFirstRecordOrdinal);
        }
        if self.monotonic_clock_epoch == 0 {
            return Err(AuditHeaderError::InvalidMonotonicClockEpoch);
        }
        if self.config_digest.is_zero() {
            return Err(AuditHeaderError::InvalidConfigDigest);
        }
        if all_zero(&self.software_digest) {
            return Err(AuditHeaderError::InvalidSoftwareDigest);
        }
        if !self.venue_identity.is_valid() {
            return Err(AuditHeaderError::InvalidVenueIdentity);
        }
        if !valid_source(
            self.market_data_source,
            SequenceDomain::MarketData,
            self.venue_identity.market_data_protocol,
        ) {
            return Err(AuditHeaderError::InvalidMarketDataSource);
        }
        if !valid_source(
            self.order_entry_source,
            SequenceDomain::OrderEntry,
            self.venue_identity.order_entry_protocol,
        ) {
            return Err(AuditHeaderError::InvalidOrderEntrySource);
        }
        if self.drop_copy_source.is_some_and(|source| {
            source.sequence_domain != SequenceDomain::DropCopy
                || !source.id.is_valid()
                || source.session_epoch.0 == 0
        }) {
            return Err(AuditHeaderError::InvalidDropCopySource);
        }
        if !self.instrument_definition_binding.is_valid() {
            return Err(AuditHeaderError::InvalidInstrumentDefinitionBinding);
        }
        if self.instrument_definition_binding.venue != self.venue_identity.venue {
            return Err(AuditHeaderError::InstrumentDefinitionVenueMismatch {
                expected: self.venue_identity.venue,
                actual: self.instrument_definition_binding.venue,
            });
        }
        Ok(())
    }
}

/// Structural header rejection before any retained record can be trusted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditHeaderError {
    InvalidAlgorithmId,
    InvalidKeyId,
    InvalidContainerId,
    InvalidGeneration,
    InvalidPredecessor,
    InvalidFirstRecordOrdinal,
    InvalidMonotonicClockEpoch,
    InvalidConfigDigest,
    InvalidSoftwareDigest,
    InvalidVenueIdentity,
    InvalidMarketDataSource,
    InvalidOrderEntrySource,
    InvalidDropCopySource,
    InvalidInstrumentDefinitionBinding,
    InstrumentDefinitionVenueMismatch { expected: VenueId, actual: VenueId },
}

/// Deployment-owned MAC boundary.
///
/// Implementations must use a reviewed, unforgeable 256-bit authenticator, compare
/// tags in constant time, protect keys from the journal writer, and domain-dedicate
/// the key to this format. `algorithm_id` and `key_id` must be stable, nonzero public
/// identifiers, never key material. A test checksum or ordinary hash is insufficient.
pub trait AuditAuthenticator {
    type Error: Copy;

    fn algorithm_id(&self) -> u32;
    fn key_id(&self) -> u64;

    /// Authenticate one complete header, record prefix plus payload, or seal prefix.
    ///
    /// # Errors
    ///
    /// Returns a fixed provider/HSM error without emitting a usable tag.
    fn authenticate(&mut self, message: &[u8]) -> Result<AuditTag, Self::Error>;

    /// Verify a tag using a constant-time implementation.
    ///
    /// # Errors
    ///
    /// Returns the provider's authentication failure for a forged or unavailable tag.
    fn verify(&mut self, message: &[u8], tag: AuditTag) -> Result<(), Self::Error>;
}

/// Application-defined record discriminator. Zero is reserved for framing errors.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct AuditRecordKind(pub u16);

impl AuditRecordKind {
    pub const NORMALIZED_EVENT: Self = Self(1);
    pub const SCHEDULER_COMMIT: Self = Self(2);
    pub const NATIVE_INGRESS: Self = Self(3);
    pub const NATIVE_INTENT: Self = Self(4);
    pub const NATIVE_DISPOSITION: Self = Self(5);
    pub const LIVE_CHECKPOINT: Self = Self(6);
    pub const ABORTED_RESERVATION: Self = Self(7);
    pub const FAULT: Self = Self(8);
}

/// Authenticated terminal identity retained in a separate freshness domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditAnchor {
    pub container_id: AuditContainerId,
    pub generation: u64,
    pub record_count: u64,
    pub first_record_ordinal: u64,
    pub last_record_ordinal: u64,
    pub header_tag: AuditTag,
    pub seal_tag: AuditTag,
}

impl AuditAnchor {
    #[must_use]
    pub const fn predecessor(self) -> AuditPredecessor {
        AuditPredecessor {
            container_id: self.container_id,
            generation: self.generation,
            seal_tag: self.seal_tag,
        }
    }
}

/// Exact container construction or verification failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditContainerError<AuthenticatorError: Copy> {
    Authenticator(AuthenticatorError),
    BufferTooSmall { required: usize, available: usize },
    PayloadTooLarge(usize),
    InvalidHeader(AuditHeaderError),
    InvalidHeaderMagic,
    UnsupportedHeaderVersion(u16),
    InvalidHeaderLength(u16),
    InvalidHeaderEncoding,
    HeaderMismatch,
    AuthenticatorIdentityMismatch,
    InvalidRecordMagic,
    UnsupportedRecordVersion(u16),
    InvalidRecordHeaderLength(u16),
    InvalidRecordLength(u32),
    InvalidRecordKind,
    RecordContainerMismatch,
    RecordGenerationMismatch { expected: u64, actual: u64 },
    RecordOrdinalMismatch { expected: u64, actual: u64 },
    RecordChainMismatch,
    CounterOverflow,
    ContainerAlreadySealed,
    MissingSeal,
    InvalidSeal,
    AnchorMismatch,
    Truncated { required: usize, available: usize },
    TrailingBytes(usize),
}

/// Return the complete authenticated wire length for one payload, if representable.
#[must_use]
pub fn audit_record_len(payload_len: usize) -> Option<usize> {
    let _ = u32::try_from(payload_len).ok()?;
    RECORD_FIXED_LEN.checked_add(payload_len)
}

/// Allocation-free writer state. Callers own and durably append every output buffer.
#[derive(Debug, Eq, PartialEq)]
pub struct AuditContainerWriter {
    header: AuditContainerHeader,
    header_tag: AuditTag,
    chain_tag: AuditTag,
    next_record_ordinal: u64,
    record_count: u64,
    sealed: bool,
}

impl AuditContainerWriter {
    /// Authenticate and encode a new header into `output`.
    ///
    /// The caller must durably create a new file/object and append exactly the first
    /// [`AUDIT_CONTAINER_HEADER_LEN`] bytes before appending any records.
    ///
    /// # Errors
    ///
    /// Returns a structural, buffer, authenticator-identity, or provider failure.
    pub fn begin<A: AuditAuthenticator>(
        header: &AuditContainerHeader,
        authenticator: &mut A,
        output: &mut [u8],
    ) -> Result<Self, AuditContainerError<A::Error>> {
        header
            .validate()
            .map_err(AuditContainerError::InvalidHeader)?;
        check_authenticator(header, authenticator)?;
        require_output(output, AUDIT_CONTAINER_HEADER_LEN)?;

        let encoded = &mut output[..AUDIT_CONTAINER_HEADER_LEN];
        encode_header_prefix(header, encoded);
        let tag = authenticator
            .authenticate(&encoded[..HEADER_TAG_OFFSET])
            .map_err(AuditContainerError::Authenticator)?;
        encoded[HEADER_TAG_OFFSET..AUDIT_CONTAINER_HEADER_LEN].copy_from_slice(&tag.0);
        Ok(Self {
            header: *header,
            header_tag: tag,
            chain_tag: tag,
            next_record_ordinal: header.first_record_ordinal,
            record_count: 0,
            sealed: false,
        })
    }

    #[must_use]
    pub const fn header(&self) -> &AuditContainerHeader {
        &self.header
    }

    #[must_use]
    pub const fn record_count(&self) -> u64 {
        self.record_count
    }

    /// Authenticate one payload into caller-owned storage without allocation.
    ///
    /// The writer state changes only after the authenticator returns a tag. The caller
    /// must append exactly the returned prefix to the same durability domain before
    /// treating the record as committed.
    ///
    /// # Errors
    ///
    /// Returns an invalid kind, exhausted counter, short buffer, or provider failure.
    pub fn append<A: AuditAuthenticator>(
        &mut self,
        kind: AuditRecordKind,
        payload: &[u8],
        authenticator: &mut A,
        output: &mut [u8],
    ) -> Result<usize, AuditContainerError<A::Error>> {
        if self.sealed {
            return Err(AuditContainerError::ContainerAlreadySealed);
        }
        if kind.0 == 0 {
            return Err(AuditContainerError::InvalidRecordKind);
        }
        check_authenticator(&self.header, authenticator)?;
        let Some(record_len) = audit_record_len(payload.len()) else {
            return Err(AuditContainerError::PayloadTooLarge(payload.len()));
        };
        let record_len_wire = u32::try_from(record_len)
            .map_err(|_| AuditContainerError::PayloadTooLarge(payload.len()))?;
        let payload_len_wire = u32::try_from(payload.len())
            .map_err(|_| AuditContainerError::PayloadTooLarge(payload.len()))?;
        let next_ordinal = self
            .next_record_ordinal
            .checked_add(1)
            .ok_or(AuditContainerError::CounterOverflow)?;
        let next_count = self
            .record_count
            .checked_add(1)
            .ok_or(AuditContainerError::CounterOverflow)?;
        require_output(output, record_len)?;

        let encoded = &mut output[..record_len];
        encoded.fill(0);
        encoded[0..4].copy_from_slice(&AUDIT_RECORD_MAGIC);
        write_u16(encoded, 4, AUDIT_CONTAINER_VERSION);
        write_u16(encoded, 6, RECORD_PREFIX_LEN_WIRE);
        write_u32(encoded, 8, record_len_wire);
        write_u32(encoded, 12, payload_len_wire);
        write_u16(encoded, 16, kind.0);
        write_u64(encoded, 24, self.next_record_ordinal);
        write_u64(encoded, 32, self.header.generation);
        encoded[40..56].copy_from_slice(&self.header.container_id.0);
        encoded[56..88].copy_from_slice(&self.chain_tag.0);
        let tag_offset = AUDIT_RECORD_PREFIX_LEN + payload.len();
        encoded[AUDIT_RECORD_PREFIX_LEN..tag_offset].copy_from_slice(payload);
        let tag = authenticator
            .authenticate(&encoded[..tag_offset])
            .map_err(AuditContainerError::Authenticator)?;
        encoded[tag_offset..record_len].copy_from_slice(&tag.0);

        self.chain_tag = tag;
        self.next_record_ordinal = next_ordinal;
        self.record_count = next_count;
        Ok(record_len)
    }

    /// Authenticate the terminal seal and return the external freshness anchor.
    ///
    /// Recovery must reject the resulting bytes unless `anchor` exactly matches the
    /// latest independently retained anchor. The caller must durably sync the seal
    /// before atomically publishing that anchor. No record may follow this seal.
    ///
    /// # Errors
    ///
    /// Returns a short buffer, repeated seal, identity mismatch, or provider failure.
    pub fn seal<A: AuditAuthenticator>(
        &mut self,
        authenticator: &mut A,
        output: &mut [u8],
    ) -> Result<AuditAnchor, AuditContainerError<A::Error>> {
        if self.sealed {
            return Err(AuditContainerError::ContainerAlreadySealed);
        }
        check_authenticator(&self.header, authenticator)?;
        require_output(output, AUDIT_CONTAINER_SEAL_LEN)?;
        let last_record_ordinal = if self.record_count == 0 {
            0
        } else {
            self.next_record_ordinal - 1
        };

        let encoded = &mut output[..AUDIT_CONTAINER_SEAL_LEN];
        encoded.fill(0);
        encoded[0..4].copy_from_slice(&AUDIT_SEAL_MAGIC);
        write_u16(encoded, 4, AUDIT_CONTAINER_VERSION);
        write_u16(encoded, 6, SEAL_PREFIX_LEN_WIRE);
        write_u32(encoded, 8, SEAL_LEN_WIRE);
        encoded[16..32].copy_from_slice(&self.header.container_id.0);
        write_u64(encoded, 32, self.header.generation);
        write_u64(encoded, 40, self.record_count);
        write_u64(encoded, 48, self.header.first_record_ordinal);
        write_u64(encoded, 56, last_record_ordinal);
        encoded[64..96].copy_from_slice(&self.header_tag.0);
        encoded[96..128].copy_from_slice(&self.chain_tag.0);
        let seal_tag = authenticator
            .authenticate(&encoded[..SEAL_TAG_OFFSET])
            .map_err(AuditContainerError::Authenticator)?;
        encoded[SEAL_TAG_OFFSET..AUDIT_CONTAINER_SEAL_LEN].copy_from_slice(&seal_tag.0);

        self.sealed = true;
        Ok(AuditAnchor {
            container_id: self.header.container_id,
            generation: self.header.generation,
            record_count: self.record_count,
            first_record_ordinal: self.header.first_record_ordinal,
            last_record_ordinal,
            header_tag: self.header_tag,
            seal_tag,
        })
    }
}

/// One authenticated record borrowed from a fully verified container.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditRecordView<'a> {
    pub kind: AuditRecordKind,
    pub ordinal: u64,
    pub payload: &'a [u8],
}

/// Fully authenticated and externally freshness-anchored container.
pub struct VerifiedAuditContainer<'a> {
    bytes: &'a [u8],
    header: AuditContainerHeader,
    anchor: AuditAnchor,
    records_end: usize,
}

impl fmt::Debug for VerifiedAuditContainer<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedAuditContainer")
            .field("header", &self.header)
            .field("anchor", &self.anchor)
            .field("wire_len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl VerifiedAuditContainer<'_> {
    #[must_use]
    pub const fn header(&self) -> &AuditContainerHeader {
        &self.header
    }

    #[must_use]
    pub const fn anchor(&self) -> AuditAnchor {
        self.anchor
    }

    #[must_use]
    pub fn records(&self) -> VerifiedAuditRecords<'_> {
        VerifiedAuditRecords {
            bytes: &self.bytes[AUDIT_CONTAINER_HEADER_LEN..self.records_end],
            offset: 0,
            remaining: self.anchor.record_count,
        }
    }
}

/// Exact-size iterator over a previously authenticated immutable byte slice.
#[derive(Clone, Debug)]
pub struct VerifiedAuditRecords<'a> {
    bytes: &'a [u8],
    offset: usize,
    remaining: u64,
}

impl<'a> Iterator for VerifiedAuditRecords<'a> {
    type Item = AuditRecordView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let record = self.bytes.get(self.offset..)?;
        let record_len = usize::try_from(read_u32(record, 8)).ok()?;
        let payload_len = usize::try_from(read_u32(record, 12)).ok()?;
        let payload_end = AUDIT_RECORD_PREFIX_LEN.checked_add(payload_len)?;
        let view = AuditRecordView {
            kind: AuditRecordKind(read_u16(record, 16)),
            ordinal: read_u64(record, 24),
            payload: record.get(AUDIT_RECORD_PREFIX_LEN..payload_end)?,
        };
        self.offset = self.offset.checked_add(record_len)?;
        self.remaining -= 1;
        Some(view)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = usize::try_from(self.remaining).unwrap_or(usize::MAX);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for VerifiedAuditRecords<'_> {}

/// Authenticate an entire immutable container before exposing any payload.
///
/// `expected_header` comes from the selected deployment configuration;
/// `expected_anchor` must come from an independent, latest-only freshness domain.
/// The verifier requires exactly one terminal seal and rejects any trailing byte.
///
/// # Errors
///
/// Returns the first framing, identity, chain, tag, truncation, or rollback failure.
#[allow(clippy::too_many_lines)]
pub fn verify_audit_container<'a, A: AuditAuthenticator>(
    input: &'a [u8],
    expected_header: &AuditContainerHeader,
    expected_anchor: AuditAnchor,
    authenticator: &mut A,
) -> Result<VerifiedAuditContainer<'a>, AuditContainerError<A::Error>> {
    expected_header
        .validate()
        .map_err(AuditContainerError::InvalidHeader)?;
    check_authenticator(expected_header, authenticator)?;
    if !anchor_matches_header(expected_anchor, expected_header) {
        return Err(AuditContainerError::AnchorMismatch);
    }
    let (header, header_tag) = decode_header(input)?;
    check_authenticator(&header, authenticator)?;
    authenticator
        .verify(&input[..HEADER_TAG_OFFSET], header_tag)
        .map_err(AuditContainerError::Authenticator)?;
    if header != *expected_header {
        return Err(AuditContainerError::HeaderMismatch);
    }

    let mut offset = AUDIT_CONTAINER_HEADER_LEN;
    let mut next_record_ordinal = header.first_record_ordinal;
    let mut record_count = 0_u64;
    let mut chain_tag = header_tag;
    loop {
        let remaining = input
            .get(offset..)
            .ok_or(AuditContainerError::CounterOverflow)?;
        if remaining.is_empty() {
            return Err(AuditContainerError::MissingSeal);
        }
        if remaining.len() < 4 {
            return Err(AuditContainerError::Truncated {
                required: 4,
                available: remaining.len(),
            });
        }
        if remaining[0..4] == AUDIT_RECORD_MAGIC {
            if record_count >= expected_anchor.record_count {
                return Err(AuditContainerError::AnchorMismatch);
            }
            if remaining.len() < AUDIT_RECORD_PREFIX_LEN {
                return Err(AuditContainerError::Truncated {
                    required: AUDIT_RECORD_PREFIX_LEN,
                    available: remaining.len(),
                });
            }
            let version = read_u16(remaining, 4);
            if version != AUDIT_CONTAINER_VERSION {
                return Err(AuditContainerError::UnsupportedRecordVersion(version));
            }
            let header_len = read_u16(remaining, 6);
            if usize::from(header_len) != AUDIT_RECORD_PREFIX_LEN {
                return Err(AuditContainerError::InvalidRecordHeaderLength(header_len));
            }
            let record_len_wire = read_u32(remaining, 8);
            let record_len = usize::try_from(record_len_wire)
                .map_err(|_| AuditContainerError::InvalidRecordLength(record_len_wire))?;
            let payload_len = usize::try_from(read_u32(remaining, 12))
                .map_err(|_| AuditContainerError::InvalidRecordLength(record_len_wire))?;
            let expected_record_len = audit_record_len(payload_len)
                .ok_or(AuditContainerError::InvalidRecordLength(record_len_wire))?;
            if record_len != expected_record_len || remaining[18..24] != [0; 6] {
                return Err(AuditContainerError::InvalidRecordLength(record_len_wire));
            }
            if remaining.len() < record_len {
                return Err(AuditContainerError::Truncated {
                    required: record_len,
                    available: remaining.len(),
                });
            }
            if read_u16(remaining, 16) == 0 {
                return Err(AuditContainerError::InvalidRecordKind);
            }
            if remaining[40..56] != header.container_id.0 {
                return Err(AuditContainerError::RecordContainerMismatch);
            }
            let generation = read_u64(remaining, 32);
            if generation != header.generation {
                return Err(AuditContainerError::RecordGenerationMismatch {
                    expected: header.generation,
                    actual: generation,
                });
            }
            let ordinal = read_u64(remaining, 24);
            if ordinal != next_record_ordinal {
                return Err(AuditContainerError::RecordOrdinalMismatch {
                    expected: next_record_ordinal,
                    actual: ordinal,
                });
            }
            if remaining[56..88] != chain_tag.0 {
                return Err(AuditContainerError::RecordChainMismatch);
            }
            let tag_offset = AUDIT_RECORD_PREFIX_LEN
                .checked_add(payload_len)
                .ok_or(AuditContainerError::CounterOverflow)?;
            let mut tag_bytes = [0_u8; AUDIT_TAG_LEN];
            tag_bytes.copy_from_slice(&remaining[tag_offset..record_len]);
            let tag = AuditTag(tag_bytes);
            authenticator
                .verify(&remaining[..tag_offset], tag)
                .map_err(AuditContainerError::Authenticator)?;
            chain_tag = tag;
            next_record_ordinal = next_record_ordinal
                .checked_add(1)
                .ok_or(AuditContainerError::CounterOverflow)?;
            record_count = record_count
                .checked_add(1)
                .ok_or(AuditContainerError::CounterOverflow)?;
            offset = offset
                .checked_add(record_len)
                .ok_or(AuditContainerError::CounterOverflow)?;
            continue;
        }
        if remaining[0..4] != AUDIT_SEAL_MAGIC {
            return Err(AuditContainerError::InvalidRecordMagic);
        }
        if remaining.len() < AUDIT_CONTAINER_SEAL_LEN {
            return Err(AuditContainerError::Truncated {
                required: AUDIT_CONTAINER_SEAL_LEN,
                available: remaining.len(),
            });
        }
        if read_u16(remaining, 4) != AUDIT_CONTAINER_VERSION
            || usize::from(read_u16(remaining, 6)) != SEAL_TAG_OFFSET
            || usize::try_from(read_u32(remaining, 8)).ok() != Some(AUDIT_CONTAINER_SEAL_LEN)
            || remaining[12..16] != [0; 4]
            || remaining[16..32] != header.container_id.0
            || read_u64(remaining, 32) != header.generation
            || read_u64(remaining, 40) != record_count
            || read_u64(remaining, 48) != header.first_record_ordinal
            || remaining[64..96] != header_tag.0
            || remaining[96..128] != chain_tag.0
        {
            return Err(AuditContainerError::InvalidSeal);
        }
        let last_record_ordinal = if record_count == 0 {
            0
        } else {
            next_record_ordinal - 1
        };
        if read_u64(remaining, 56) != last_record_ordinal {
            return Err(AuditContainerError::InvalidSeal);
        }
        let mut seal_tag_bytes = [0_u8; AUDIT_TAG_LEN];
        seal_tag_bytes.copy_from_slice(&remaining[SEAL_TAG_OFFSET..AUDIT_CONTAINER_SEAL_LEN]);
        let seal_tag = AuditTag(seal_tag_bytes);
        authenticator
            .verify(&remaining[..SEAL_TAG_OFFSET], seal_tag)
            .map_err(AuditContainerError::Authenticator)?;
        let anchor = AuditAnchor {
            container_id: header.container_id,
            generation: header.generation,
            record_count,
            first_record_ordinal: header.first_record_ordinal,
            last_record_ordinal,
            header_tag,
            seal_tag,
        };
        if anchor != expected_anchor {
            return Err(AuditContainerError::AnchorMismatch);
        }
        if remaining.len() != AUDIT_CONTAINER_SEAL_LEN {
            return Err(AuditContainerError::TrailingBytes(
                remaining.len() - AUDIT_CONTAINER_SEAL_LEN,
            ));
        }
        return Ok(VerifiedAuditContainer {
            bytes: input,
            header,
            anchor,
            records_end: offset,
        });
    }
}

fn check_authenticator<A: AuditAuthenticator>(
    header: &AuditContainerHeader,
    authenticator: &A,
) -> Result<(), AuditContainerError<A::Error>> {
    if authenticator.algorithm_id() != header.algorithm_id
        || authenticator.key_id() != header.key_id
    {
        return Err(AuditContainerError::AuthenticatorIdentityMismatch);
    }
    Ok(())
}

fn anchor_matches_header(anchor: AuditAnchor, header: &AuditContainerHeader) -> bool {
    if anchor.container_id != header.container_id
        || anchor.generation != header.generation
        || anchor.first_record_ordinal != header.first_record_ordinal
    {
        return false;
    }
    if anchor.record_count == 0 {
        return anchor.last_record_ordinal == 0;
    }
    let Some(last_offset) = anchor.record_count.checked_sub(1) else {
        return false;
    };
    header
        .first_record_ordinal
        .checked_add(last_offset)
        .is_some_and(|last| last == anchor.last_record_ordinal)
}

fn require_output<Error: Copy>(
    output: &[u8],
    required: usize,
) -> Result<(), AuditContainerError<Error>> {
    if output.len() < required {
        return Err(AuditContainerError::BufferTooSmall {
            required,
            available: output.len(),
        });
    }
    Ok(())
}

fn encode_header_prefix(header: &AuditContainerHeader, output: &mut [u8]) {
    output.fill(0);
    output[0..4].copy_from_slice(&AUDIT_CONTAINER_MAGIC);
    write_u16(output, 4, AUDIT_CONTAINER_VERSION);
    write_u16(output, 6, HEADER_LEN_WIRE);
    write_u32(output, 8, header.algorithm_id);
    write_u64(output, 16, header.key_id);
    write_u64(output, 24, header.generation);
    write_u64(output, 32, header.first_record_ordinal);
    write_u64(output, 40, header.monotonic_clock_epoch);
    output[48..64].copy_from_slice(&header.container_id.0);
    output[64..96].copy_from_slice(&header.config_digest.0);
    output[96..128].copy_from_slice(&header.software_digest);
    write_u16(output, 128, header.venue_identity.venue.0);
    write_u32(output, 132, header.venue_identity.market_data_protocol.0);
    write_u32(output, 136, header.venue_identity.order_entry_protocol.0);
    write_u64(output, 144, header.venue_identity.session.0);
    encode_source(output, 152, header.market_data_source);
    encode_source(output, 176, header.order_entry_source);
    if let Some(drop_copy_source) = header.drop_copy_source {
        encode_source(output, 200, drop_copy_source);
    }
    encode_instrument_binding(output, 224, header.instrument_definition_binding);
    if let Some(predecessor) = header.predecessor {
        output[288..304].copy_from_slice(&predecessor.container_id.0);
        write_u64(output, 304, predecessor.generation);
        output[312..344].copy_from_slice(&predecessor.seal_tag.0);
    }
}

fn decode_header<Error: Copy>(
    input: &[u8],
) -> Result<(AuditContainerHeader, AuditTag), AuditContainerError<Error>> {
    if input.len() < AUDIT_CONTAINER_HEADER_LEN {
        return Err(AuditContainerError::Truncated {
            required: AUDIT_CONTAINER_HEADER_LEN,
            available: input.len(),
        });
    }
    let encoded = &input[..AUDIT_CONTAINER_HEADER_LEN];
    if encoded[0..4] != AUDIT_CONTAINER_MAGIC {
        return Err(AuditContainerError::InvalidHeaderMagic);
    }
    let version = read_u16(encoded, 4);
    if version != AUDIT_CONTAINER_VERSION {
        return Err(AuditContainerError::UnsupportedHeaderVersion(version));
    }
    let header_len = read_u16(encoded, 6);
    if usize::from(header_len) != AUDIT_CONTAINER_HEADER_LEN {
        return Err(AuditContainerError::InvalidHeaderLength(header_len));
    }
    if encoded[12..16] != [0; 4]
        || encoded[130..132] != [0; 2]
        || encoded[140..144] != [0; 4]
        || encoded[169..176] != [0; 7]
        || encoded[193..200] != [0; 7]
        || encoded[217..224] != [0; 7]
        || encoded[226..228] != [0; 2]
    {
        return Err(AuditContainerError::InvalidHeaderEncoding);
    }
    let market_data_source = decode_source(encoded, 152)?;
    let order_entry_source = decode_source(encoded, 176)?;
    let drop_copy_source = if all_zero(&encoded[200..224]) {
        None
    } else {
        Some(decode_source(encoded, 200)?)
    };
    let instrument_definition_binding = decode_instrument_binding(encoded, 224);
    let mut container_id = [0_u8; 16];
    container_id.copy_from_slice(&encoded[48..64]);
    let mut config_digest = [0_u8; 32];
    config_digest.copy_from_slice(&encoded[64..96]);
    let mut software_digest = [0_u8; 32];
    software_digest.copy_from_slice(&encoded[96..128]);
    let mut predecessor_id = [0_u8; 16];
    predecessor_id.copy_from_slice(&encoded[288..304]);
    let predecessor_generation = read_u64(encoded, 304);
    let mut predecessor_tag = [0_u8; AUDIT_TAG_LEN];
    predecessor_tag.copy_from_slice(&encoded[312..344]);
    let predecessor =
        if predecessor_generation == 0 && all_zero(&predecessor_id) && all_zero(&predecessor_tag) {
            None
        } else {
            Some(AuditPredecessor {
                container_id: AuditContainerId(predecessor_id),
                generation: predecessor_generation,
                seal_tag: AuditTag(predecessor_tag),
            })
        };
    let header = AuditContainerHeader {
        algorithm_id: read_u32(encoded, 8),
        key_id: read_u64(encoded, 16),
        container_id: AuditContainerId(container_id),
        generation: read_u64(encoded, 24),
        first_record_ordinal: read_u64(encoded, 32),
        monotonic_clock_epoch: read_u64(encoded, 40),
        config_digest: ConfigDigest(config_digest),
        software_digest,
        venue_identity: VenueIdentity {
            venue: VenueId(read_u16(encoded, 128)),
            market_data_protocol: ProtocolId(read_u32(encoded, 132)),
            order_entry_protocol: ProtocolId(read_u32(encoded, 136)),
            session: SessionId(read_u64(encoded, 144)),
        },
        market_data_source,
        order_entry_source,
        drop_copy_source,
        instrument_definition_binding,
        predecessor,
    };
    header
        .validate()
        .map_err(AuditContainerError::InvalidHeader)?;
    let mut tag = [0_u8; AUDIT_TAG_LEN];
    tag.copy_from_slice(&encoded[HEADER_TAG_OFFSET..AUDIT_CONTAINER_HEADER_LEN]);
    Ok((header, AuditTag(tag)))
}

fn valid_source(source: EventSource, domain: SequenceDomain, protocol: ProtocolId) -> bool {
    source.sequence_domain == domain
        && source.id.protocol == protocol.0
        && source.id.channel != 0
        && source.session_epoch.0 != 0
}

fn encode_source(output: &mut [u8], offset: usize, source: EventSource) {
    write_u32(output, offset, source.id.protocol);
    write_u32(output, offset + 4, source.id.channel);
    write_u64(output, offset + 8, source.session_epoch.0);
    output[offset + 16] = sequence_domain_wire(source.sequence_domain);
}

fn encode_instrument_binding(
    output: &mut [u8],
    offset: usize,
    binding: InstrumentDefinitionBinding,
) {
    write_u16(output, offset, binding.venue.0);
    write_u32(output, offset + 4, binding.instrument.0);
    write_u64(output, offset + 8, binding.native_product.0);
    write_u64(output, offset + 16, binding.authority.0);
    write_u64(output, offset + 24, binding.reference_data_version);
    output[offset + 32..offset + 64].copy_from_slice(&binding.reference_data_digest.0);
}

fn decode_instrument_binding(input: &[u8], offset: usize) -> InstrumentDefinitionBinding {
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&input[offset + 32..offset + 64]);
    InstrumentDefinitionBinding {
        venue: VenueId(read_u16(input, offset)),
        instrument: InstrumentId(read_u32(input, offset + 4)),
        native_product: NativeProductId(read_u64(input, offset + 8)),
        authority: ReferenceDataAuthorityId(read_u64(input, offset + 16)),
        reference_data_version: read_u64(input, offset + 24),
        reference_data_digest: ReferenceDataDigest(digest),
    }
}

fn decode_source<Error: Copy>(
    input: &[u8],
    offset: usize,
) -> Result<EventSource, AuditContainerError<Error>> {
    let domain = SequenceDomain::from_wire(input[offset + 16])
        .ok_or(AuditContainerError::InvalidHeaderEncoding)?;
    Ok(EventSource::new(
        SourceId::new(read_u32(input, offset), read_u32(input, offset + 4)),
        domain,
        SessionEpoch(read_u64(input, offset + 8)),
    ))
}

const fn sequence_domain_wire(domain: SequenceDomain) -> u8 {
    match domain {
        SequenceDomain::Local => 0,
        SequenceDomain::MarketData => 1,
        SequenceDomain::OrderEntry => 2,
        SequenceDomain::DropCopy => 3,
    }
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
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
