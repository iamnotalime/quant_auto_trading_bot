//! Canonical normalized events at the capture/replay boundary.
//!
//! A venue sequence belongs to a protocol channel or order-entry session, not to an
//! instrument. Version-3 events therefore carry explicit protocol/channel identity,
//! sequence domain, session epoch, and a process-global capture ordinal. Instrument is
//! payload routing metadata and is deliberately not part of sequence-source identity.

use crate::types::{
    EventHeader, MonotonicTimestampNs, OrderId, PriceTicks, Quantity, Sequence, Side, TimestampNs,
    VenueId,
};

pub const EVENT_FLAG_SNAPSHOT: u16 = 1 << 0;
pub const EVENT_FLAG_RECOVERY: u16 = 1 << 1;
pub const KNOWN_EVENT_FLAGS: u16 = EVENT_FLAG_SNAPSHOT | EVENT_FLAG_RECOVERY;

/// Stable protocol/channel identity within one venue.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(C)]
pub struct SourceId {
    pub protocol: u32,
    pub channel: u32,
}

impl SourceId {
    #[must_use]
    pub const fn new(protocol: u32, channel: u32) -> Self {
        Self { protocol, channel }
    }

    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.protocol != 0 && self.channel != 0
    }
}

/// Namespace in which `EventHeader::sequence` advances.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum SequenceDomain {
    Local = 0,
    MarketData = 1,
    OrderEntry = 2,
    /// Independently authenticated execution-report channel. Its sequence cursor is
    /// never shared with the primary order-entry session.
    DropCopy = 3,
}

impl SequenceDomain {
    #[must_use]
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Local),
            1 => Some(Self::MarketData),
            2 => Some(Self::OrderEntry),
            3 => Some(Self::DropCopy),
            _ => None,
        }
    }
}

/// Monotonic connection generation assigned by the authenticated adapter.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct SessionEpoch(pub u64);

/// Gapless process-global order in which normalized events were captured.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct CaptureOrdinal(pub u64);

/// The complete source of one venue sequence namespace.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(C)]
pub struct EventSource {
    pub id: SourceId,
    pub sequence_domain: SequenceDomain,
    pub session_epoch: SessionEpoch,
}

impl EventSource {
    pub const LOCAL: Self = Self {
        id: SourceId {
            protocol: 0,
            channel: 0,
        },
        sequence_domain: SequenceDomain::Local,
        session_epoch: SessionEpoch(0),
    };

    #[must_use]
    pub const fn new(
        id: SourceId,
        sequence_domain: SequenceDomain,
        session_epoch: SessionEpoch,
    ) -> Self {
        Self {
            id,
            sequence_domain,
            session_epoch,
        }
    }

    #[must_use]
    pub const fn is_local(self) -> bool {
        matches!(self.sequence_domain, SequenceDomain::Local)
            && self.id.protocol == 0
            && self.id.channel == 0
            && self.session_epoch.0 == 0
    }
}

/// A normalized event discriminator. Numeric values are journal wire ABI.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum EventKind {
    BookAdd = 1,
    BookModify = 2,
    BookCancel = 3,
    BookExecute = 4,
    Trade = 5,
    SnapshotStart = 6,
    SnapshotEnd = 7,
    OrderAccepted = 8,
    OrderRejected = 9,
    OrderFill = 10,
    OrderCancelled = 11,
    Heartbeat = 12,
    /// Declares the exact first missing sequence in `header.sequence`; `reference`
    /// is the last sequence that incremental recovery must restore.
    RecoveryStart = 13,
    /// Closes incremental recovery without consuming a source sequence.
    RecoveryEnd = 14,
    TradingStatus = 15,
    SessionLogonAccepted = 16,
    SessionLogonRejected = 17,
    SessionReplayComplete = 18,
    SessionSnapshotRequired = 19,
    SessionLogout = 20,
    ClockSample = 21,
    ControlArm = 22,
    ControlDisarm = 23,
    ControlHeartbeat = 24,
    ControlKill = 25,
    TransmissionNew = 26,
    TransmissionCancel = 27,
    TransmissionReplace = 28,
    TransmissionCancelAll = 29,
    Timer = 30,
    BookClear = 31,
    OwnedMboBinding = 32,
    LifecycleCorrectionObserved = 33,
}

impl EventKind {
    #[must_use]
    pub const fn from_wire(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::BookAdd),
            2 => Some(Self::BookModify),
            3 => Some(Self::BookCancel),
            4 => Some(Self::BookExecute),
            5 => Some(Self::Trade),
            6 => Some(Self::SnapshotStart),
            7 => Some(Self::SnapshotEnd),
            8 => Some(Self::OrderAccepted),
            9 => Some(Self::OrderRejected),
            10 => Some(Self::OrderFill),
            11 => Some(Self::OrderCancelled),
            12 => Some(Self::Heartbeat),
            13 => Some(Self::RecoveryStart),
            14 => Some(Self::RecoveryEnd),
            15 => Some(Self::TradingStatus),
            16 => Some(Self::SessionLogonAccepted),
            17 => Some(Self::SessionLogonRejected),
            18 => Some(Self::SessionReplayComplete),
            19 => Some(Self::SessionSnapshotRequired),
            20 => Some(Self::SessionLogout),
            21 => Some(Self::ClockSample),
            22 => Some(Self::ControlArm),
            23 => Some(Self::ControlDisarm),
            24 => Some(Self::ControlHeartbeat),
            25 => Some(Self::ControlKill),
            26 => Some(Self::TransmissionNew),
            27 => Some(Self::TransmissionCancel),
            28 => Some(Self::TransmissionReplace),
            29 => Some(Self::TransmissionCancelAll),
            30 => Some(Self::Timer),
            31 => Some(Self::BookClear),
            32 => Some(Self::OwnedMboBinding),
            33 => Some(Self::LifecycleCorrectionObserved),
            _ => None,
        }
    }

    #[must_use]
    pub const fn is_boundary(self) -> bool {
        matches!(
            self,
            Self::SnapshotStart | Self::SnapshotEnd | Self::RecoveryStart | Self::RecoveryEnd
        )
    }

    #[must_use]
    pub const fn is_local(self) -> bool {
        matches!(
            self,
            Self::ClockSample
                | Self::ControlArm
                | Self::ControlDisarm
                | Self::ControlHeartbeat
                | Self::ControlKill
                | Self::TransmissionNew
                | Self::TransmissionCancel
                | Self::TransmissionReplace
                | Self::TransmissionCancelAll
                | Self::Timer
                | Self::OwnedMboBinding
        )
    }
}

/// An explicit side code with stable wire representation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum EventSide {
    None = 0,
    Buy = 1,
    Sell = 2,
}

impl EventSide {
    #[must_use]
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::Buy),
            2 => Some(Self::Sell),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_side(self) -> Option<Side> {
        match self {
            Self::None => None,
            Self::Buy => Some(Side::Buy),
            Self::Sell => Some(Side::Sell),
        }
    }
}

impl From<Side> for EventSide {
    fn from(value: Side) -> Self {
        match value {
            Side::Buy => Self::Buy,
            Side::Sell => Self::Sell,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalField {
    Instrument,
    Side,
    OrderId,
    Price,
    Quantity,
    Reference,
    SecondaryId,
    TertiaryId,
    LeavesQuantity,
    Auxiliary,
    Blob,
    MonotonicTimestamp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventError {
    InvalidVenue(VenueId),
    InvalidSource(SourceId),
    InvalidSessionEpoch(SessionEpoch),
    InvalidCaptureOrdinal(CaptureOrdinal),
    InstrumentRequired(EventKind),
    InvalidSequence(Sequence),
    InvalidExchangeTimestamp(TimestampNs),
    InvalidReceiveTimestamp(TimestampNs),
    ReceiveBeforeExchange {
        exchange: TimestampNs,
        receive: TimestampNs,
    },
    SequenceDomainMismatch {
        kind: EventKind,
        domain: SequenceDomain,
    },
    UnknownFlags(u16),
    FlagsNotAllowed {
        kind: EventKind,
        flags: u16,
    },
    SideRequired(EventKind),
    SideMustBeNone(EventKind),
    OrderIdRequired(EventKind),
    IdentifiersMustDiffer(EventKind),
    PositivePriceRequired(EventKind),
    PositiveQuantityRequired(EventKind),
    ReferenceRequired(EventKind),
    CanonicalZeroRequired {
        kind: EventKind,
        field: CanonicalField,
    },
    LocalSourceRequired(EventKind),
    VenueSourceRequired(EventKind),
    InvalidMonotonicTimestamp(MonotonicTimestampNs),
    InvalidAuxiliary(EventKind),
    InvalidBlob(EventKind),
}

/// In-memory provenance for control records. This marker is deliberately outside the
/// journal wire ABI: decoding an unauthenticated record can only produce replay
/// provenance, never a live authenticated-control capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControlEventOrigin {
    Untrusted,
    AuthenticatedGate,
    JournalReplay,
}

/// Fixed-field normalized event used at the authenticated adapter/core boundary.
///
/// Rust layout is never persisted directly. `journal` serializes every field in a
/// fixed little-endian v5 format. `reference` is kind-specific: trade/snapshot IDs,
/// venue/reject identifiers, or the recovery target sequence.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct NormalizedEvent {
    pub header: EventHeader,
    pub source: EventSource,
    pub capture_ordinal: CaptureOrdinal,
    pub monotonic_timestamp: MonotonicTimestampNs,
    pub order_id: OrderId,
    pub secondary_id: u64,
    pub tertiary_id: u64,
    pub price: PriceTicks,
    pub quantity: Quantity,
    pub leaves_quantity: Quantity,
    pub reference: u64,
    pub auxiliary: u64,
    pub blob: [u8; 32],
    pub kind: EventKind,
    pub flags: u16,
    pub side: EventSide,
    control_origin: ControlEventOrigin,
}

impl NormalizedEvent {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        header: EventHeader,
        source: EventSource,
        capture_ordinal: CaptureOrdinal,
        kind: EventKind,
        side: EventSide,
        flags: u16,
        order_id: OrderId,
        price: PriceTicks,
        quantity: Quantity,
        reference: u64,
    ) -> Self {
        Self {
            header,
            source,
            capture_ordinal,
            monotonic_timestamp: MonotonicTimestampNs(header.hardware_receive_timestamp.0),
            order_id,
            secondary_id: 0,
            tertiary_id: 0,
            price,
            quantity,
            leaves_quantity: Quantity::ZERO,
            reference,
            auxiliary: 0,
            blob: [0; 32],
            kind,
            flags,
            side,
            control_origin: ControlEventOrigin::Untrusted,
        }
    }

    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new_full(
        header: EventHeader,
        source: EventSource,
        capture_ordinal: CaptureOrdinal,
        monotonic_timestamp: MonotonicTimestampNs,
        kind: EventKind,
        side: EventSide,
        flags: u16,
        order_id: OrderId,
        secondary_id: u64,
        tertiary_id: u64,
        price: PriceTicks,
        quantity: Quantity,
        leaves_quantity: Quantity,
        reference: u64,
        auxiliary: u64,
        blob: [u8; 32],
    ) -> Self {
        Self {
            header,
            source,
            capture_ordinal,
            monotonic_timestamp,
            order_id,
            secondary_id,
            tertiary_id,
            price,
            quantity,
            leaves_quantity,
            reference,
            auxiliary,
            blob,
            kind,
            flags,
            side,
            control_origin: ControlEventOrigin::Untrusted,
        }
    }

    pub(crate) const fn with_control_origin(mut self, origin: ControlEventOrigin) -> Self {
        self.control_origin = origin;
        self
    }

    pub(crate) const fn control_origin(self) -> ControlEventOrigin {
        self.control_origin
    }

    #[must_use]
    pub const fn is_snapshot(self) -> bool {
        self.flags & EVENT_FLAG_SNAPSHOT != 0
    }

    #[must_use]
    pub const fn is_recovery(self) -> bool {
        self.flags & EVENT_FLAG_RECOVERY != 0
    }

    /// Check source, header, timestamp, domain, flag, and canonical payload invariants.
    ///
    /// # Errors
    ///
    /// Returns [`EventError`] when any field is invalid or a kind-irrelevant field is
    /// not in its single canonical representation.
    pub fn validate(self) -> Result<(), EventError> {
        self.validate_header()?;
        self.validate_domain()?;
        let unknown_flags = self.flags & !KNOWN_EVENT_FLAGS;
        if unknown_flags != 0 {
            return Err(EventError::UnknownFlags(unknown_flags));
        }
        self.validate_payload()
    }

    fn validate_header(self) -> Result<(), EventError> {
        if self.capture_ordinal.0 == 0 {
            return Err(EventError::InvalidCaptureOrdinal(self.capture_ordinal));
        }
        if self.kind.is_local() {
            if !self.source.is_local() {
                return Err(EventError::LocalSourceRequired(self.kind));
            }
            if self.header.venue.0 != 0
                || self.header.instrument.0 != 0
                || self.header.sequence.0 != 0
                || self.header.exchange_timestamp != TimestampNs::ZERO
                || self.header.hardware_receive_timestamp != TimestampNs::ZERO
            {
                return Err(EventError::CanonicalZeroRequired {
                    kind: self.kind,
                    field: CanonicalField::Instrument,
                });
            }
            let monotonic_required = matches!(
                self.kind,
                EventKind::ClockSample
                    | EventKind::TransmissionNew
                    | EventKind::TransmissionCancel
                    | EventKind::TransmissionReplace
                    | EventKind::TransmissionCancelAll
                    | EventKind::Timer
                    | EventKind::OwnedMboBinding
            );
            if monotonic_required && self.monotonic_timestamp == MonotonicTimestampNs::ZERO {
                return Err(EventError::InvalidMonotonicTimestamp(
                    self.monotonic_timestamp,
                ));
            }
            if !monotonic_required && self.monotonic_timestamp != MonotonicTimestampNs::ZERO {
                return Err(EventError::CanonicalZeroRequired {
                    kind: self.kind,
                    field: CanonicalField::MonotonicTimestamp,
                });
            }
            return Ok(());
        }
        if self.source.is_local() || self.source.sequence_domain == SequenceDomain::Local {
            return Err(EventError::VenueSourceRequired(self.kind));
        }
        if self.header.venue.0 == 0 {
            return Err(EventError::InvalidVenue(self.header.venue));
        }
        if !self.source.id.is_valid() {
            return Err(EventError::InvalidSource(self.source.id));
        }
        if self.source.session_epoch.0 == 0 {
            return Err(EventError::InvalidSessionEpoch(self.source.session_epoch));
        }
        if self.header.sequence.0 == 0 && !self.is_snapshot() {
            return Err(EventError::InvalidSequence(self.header.sequence));
        }
        if self.header.exchange_timestamp == TimestampNs::ZERO {
            return Err(EventError::InvalidExchangeTimestamp(
                self.header.exchange_timestamp,
            ));
        }
        if self.header.hardware_receive_timestamp == TimestampNs::ZERO {
            return Err(EventError::InvalidReceiveTimestamp(
                self.header.hardware_receive_timestamp,
            ));
        }
        if self.header.hardware_receive_timestamp < self.header.exchange_timestamp {
            return Err(EventError::ReceiveBeforeExchange {
                exchange: self.header.exchange_timestamp,
                receive: self.header.hardware_receive_timestamp,
            });
        }
        if self.monotonic_timestamp == MonotonicTimestampNs::ZERO {
            return Err(EventError::InvalidMonotonicTimestamp(
                self.monotonic_timestamp,
            ));
        }
        Ok(())
    }

    fn validate_domain(self) -> Result<(), EventError> {
        let valid = match self.kind {
            EventKind::BookAdd
            | EventKind::BookModify
            | EventKind::BookCancel
            | EventKind::BookExecute
            | EventKind::BookClear
            | EventKind::Trade
            | EventKind::SnapshotStart
            | EventKind::SnapshotEnd
            | EventKind::TradingStatus => self.source.sequence_domain == SequenceDomain::MarketData,
            EventKind::OrderAccepted
            | EventKind::OrderRejected
            | EventKind::OrderFill
            | EventKind::OrderCancelled
            | EventKind::LifecycleCorrectionObserved
            | EventKind::SessionLogonAccepted
            | EventKind::SessionLogonRejected
            | EventKind::SessionReplayComplete
            | EventKind::SessionSnapshotRequired
            | EventKind::SessionLogout => matches!(
                self.source.sequence_domain,
                SequenceDomain::OrderEntry | SequenceDomain::DropCopy
            ),
            EventKind::Heartbeat | EventKind::RecoveryStart | EventKind::RecoveryEnd => true,
            EventKind::ClockSample
            | EventKind::ControlArm
            | EventKind::ControlDisarm
            | EventKind::ControlHeartbeat
            | EventKind::ControlKill
            | EventKind::TransmissionNew
            | EventKind::TransmissionCancel
            | EventKind::TransmissionReplace
            | EventKind::TransmissionCancelAll
            | EventKind::Timer
            | EventKind::OwnedMboBinding => self.source.sequence_domain == SequenceDomain::Local,
        };
        if valid {
            Ok(())
        } else {
            Err(EventError::SequenceDomainMismatch {
                kind: self.kind,
                domain: self.source.sequence_domain,
            })
        }
    }

    fn validate_payload(self) -> Result<(), EventError> {
        match self.kind {
            EventKind::BookAdd => self.validate_book_add(),
            EventKind::BookModify | EventKind::BookExecute => {
                self.reject_flags(EVENT_FLAG_SNAPSHOT)?;
                self.require_none_side()?;
                self.require_order_id()?;
                self.require_positive_price()?;
                self.require_positive_quantity()?;
                self.require_zero(CanonicalField::Reference)?;
                self.require_extended_zero()
            }
            EventKind::BookCancel => {
                self.reject_flags(EVENT_FLAG_SNAPSHOT)?;
                self.require_none_side()?;
                self.require_order_id()?;
                self.require_zero(CanonicalField::Price)?;
                self.require_zero(CanonicalField::Quantity)?;
                self.require_zero(CanonicalField::Reference)?;
                self.require_extended_zero()
            }
            EventKind::BookClear => {
                self.reject_flags(EVENT_FLAG_SNAPSHOT)?;
                self.require_instrument()?;
                self.require_none_side()?;
                self.require_zero(CanonicalField::OrderId)?;
                self.require_zero(CanonicalField::Price)?;
                self.require_zero(CanonicalField::Quantity)?;
                self.require_zero(CanonicalField::Reference)?;
                self.require_extended_zero()
            }
            EventKind::Trade => {
                self.reject_flags(EVENT_FLAG_SNAPSHOT)?;
                self.require_side()?;
                self.require_positive_price()?;
                self.require_positive_quantity()?;
                self.require_zero(CanonicalField::OrderId)?;
                self.require_reference()?;
                self.require_extended_zero()
            }
            EventKind::SnapshotStart | EventKind::SnapshotEnd => self.validate_snapshot_boundary(),
            EventKind::OrderAccepted => {
                self.reject_flags(EVENT_FLAG_SNAPSHOT)?;
                self.require_zero(CanonicalField::Instrument)?;
                self.require_none_side()?;
                self.require_order_id()?;
                self.require_secondary_id()?;
                self.require_positive_price()?;
                self.require_positive_quantity()?;
                self.require_zero(CanonicalField::TertiaryId)?;
                self.require_zero(CanonicalField::LeavesQuantity)?;
                self.require_zero(CanonicalField::Reference)?;
                self.require_zero(CanonicalField::Auxiliary)?;
                self.require_zero(CanonicalField::Blob)
            }
            EventKind::OrderFill => self.validate_order_fill(),
            EventKind::OrderRejected => {
                self.reject_flags(EVENT_FLAG_SNAPSHOT)?;
                self.require_zero(CanonicalField::Instrument)?;
                self.require_none_side()?;
                self.require_order_id()?;
                self.require_zero(CanonicalField::Price)?;
                self.require_zero(CanonicalField::Quantity)?;
                self.require_zero(CanonicalField::LeavesQuantity)?;
                self.require_zero(CanonicalField::Reference)?;
                self.require_zero(CanonicalField::SecondaryId)?;
                self.require_zero(CanonicalField::TertiaryId)?;
                self.require_zero(CanonicalField::Blob)?;
                if self.auxiliary > u64::from(u32::MAX) {
                    return Err(EventError::InvalidAuxiliary(self.kind));
                }
                Ok(())
            }
            EventKind::OrderCancelled => self.validate_order_cancelled(),
            EventKind::LifecycleCorrectionObserved => self.validate_lifecycle_correction_observed(),
            EventKind::Heartbeat => self.validate_heartbeat(),
            EventKind::RecoveryStart | EventKind::RecoveryEnd => self.validate_recovery_boundary(),
            EventKind::TradingStatus => self.validate_trading_status(),
            EventKind::SessionLogonAccepted | EventKind::SessionSnapshotRequired => {
                self.validate_empty_venue_payload()
            }
            EventKind::SessionLogonRejected | EventKind::SessionLogout => {
                self.validate_session_code()
            }
            EventKind::SessionReplayComplete => {
                self.validate_empty_venue_payload_base()?;
                self.require_reference()
            }
            EventKind::ClockSample => self.validate_clock_sample(),
            EventKind::ControlArm
            | EventKind::ControlDisarm
            | EventKind::ControlHeartbeat
            | EventKind::ControlKill => self.validate_control(),
            EventKind::TransmissionNew
            | EventKind::TransmissionCancel
            | EventKind::TransmissionReplace
            | EventKind::TransmissionCancelAll => self.validate_transmission(),
            EventKind::Timer => self.validate_timer(),
            EventKind::OwnedMboBinding => self.validate_owned_mbo_binding(),
        }
    }

    fn validate_book_add(self) -> Result<(), EventError> {
        self.require_instrument()?;
        self.require_side()?;
        self.require_order_id()?;
        self.require_positive_price()?;
        self.require_positive_quantity()?;
        if self.is_snapshot() {
            self.require_reference()?;
        } else {
            self.require_zero(CanonicalField::Reference)?;
        }
        self.require_extended_zero()
    }

    fn validate_snapshot_boundary(self) -> Result<(), EventError> {
        if !self.is_snapshot() {
            return Err(EventError::FlagsNotAllowed {
                kind: self.kind,
                flags: self.flags,
            });
        }
        self.require_zero(CanonicalField::Instrument)?;
        self.require_none_side()?;
        self.require_zero(CanonicalField::OrderId)?;
        self.require_zero(CanonicalField::Price)?;
        self.require_zero(CanonicalField::Quantity)?;
        self.require_reference()?;
        self.require_extended_zero()
    }

    fn validate_recovery_boundary(self) -> Result<(), EventError> {
        if self.flags != EVENT_FLAG_RECOVERY {
            return Err(EventError::FlagsNotAllowed {
                kind: self.kind,
                flags: self.flags,
            });
        }
        self.require_zero(CanonicalField::Instrument)?;
        self.require_none_side()?;
        self.require_zero(CanonicalField::OrderId)?;
        self.require_zero(CanonicalField::Price)?;
        self.require_zero(CanonicalField::Quantity)?;
        self.require_reference()?;
        self.require_extended_zero()
    }

    fn validate_heartbeat(self) -> Result<(), EventError> {
        if self.flags & EVENT_FLAG_SNAPSHOT != 0 {
            return Err(EventError::FlagsNotAllowed {
                kind: self.kind,
                flags: self.flags,
            });
        }
        self.require_zero(CanonicalField::Instrument)?;
        self.require_none_side()?;
        self.require_zero(CanonicalField::OrderId)?;
        self.require_zero(CanonicalField::Price)?;
        self.require_zero(CanonicalField::Quantity)?;
        self.require_zero(CanonicalField::Reference)?;
        self.require_extended_zero()
    }

    fn validate_order_fill(self) -> Result<(), EventError> {
        self.reject_flags(EVENT_FLAG_SNAPSHOT)?;
        self.require_zero(CanonicalField::Instrument)?;
        self.require_none_side()?;
        self.require_order_id()?;
        self.require_secondary_id()?;
        if self.tertiary_id == 0 {
            return Err(EventError::CanonicalZeroRequired {
                kind: self.kind,
                field: CanonicalField::TertiaryId,
            });
        }
        self.require_positive_price()?;
        self.require_positive_quantity()?;
        if self.leaves_quantity.0 < 0 {
            return Err(EventError::PositiveQuantityRequired(self.kind));
        }
        self.require_zero(CanonicalField::Reference)?;
        if !(1..=3).contains(&self.auxiliary) {
            return Err(EventError::InvalidAuxiliary(self.kind));
        }
        self.require_zero(CanonicalField::Blob)
    }

    fn validate_order_cancelled(self) -> Result<(), EventError> {
        self.reject_flags(EVENT_FLAG_SNAPSHOT)?;
        self.require_zero(CanonicalField::Instrument)?;
        self.require_none_side()?;
        self.require_order_id()?;
        self.require_secondary_id()?;
        self.require_zero(CanonicalField::TertiaryId)?;
        self.require_zero(CanonicalField::Price)?;
        if self.quantity.0 < 0 || self.leaves_quantity.0 < 0 {
            return Err(EventError::PositiveQuantityRequired(self.kind));
        }
        self.require_zero(CanonicalField::Reference)?;
        self.require_zero(CanonicalField::Auxiliary)?;
        self.require_zero(CanonicalField::Blob)
    }

    fn validate_lifecycle_correction_observed(self) -> Result<(), EventError> {
        self.reject_flags(EVENT_FLAG_SNAPSHOT)?;
        self.require_zero(CanonicalField::Instrument)?;
        self.require_none_side()?;
        self.require_zero(CanonicalField::OrderId)?;
        self.require_zero(CanonicalField::SecondaryId)?;
        if self.tertiary_id == 0 {
            return Err(EventError::CanonicalZeroRequired {
                kind: self.kind,
                field: CanonicalField::TertiaryId,
            });
        }
        self.require_zero(CanonicalField::Price)?;
        self.require_zero(CanonicalField::Quantity)?;
        self.require_zero(CanonicalField::LeavesQuantity)?;
        self.require_reference()?;
        if !(1..=2).contains(&self.auxiliary) {
            return Err(EventError::InvalidAuxiliary(self.kind));
        }
        if self.blob.iter().all(|byte| *byte == 0) {
            return Err(EventError::InvalidBlob(self.kind));
        }
        Ok(())
    }

    fn validate_trading_status(self) -> Result<(), EventError> {
        self.reject_flags(EVENT_FLAG_SNAPSHOT)?;
        self.require_instrument()?;
        self.require_none_side()?;
        self.require_zero(CanonicalField::OrderId)?;
        self.require_zero(CanonicalField::SecondaryId)?;
        self.require_zero(CanonicalField::TertiaryId)?;
        self.require_zero(CanonicalField::Price)?;
        self.require_zero(CanonicalField::Quantity)?;
        self.require_zero(CanonicalField::LeavesQuantity)?;
        self.require_zero(CanonicalField::Reference)?;
        if self.auxiliary > u64::from(u16::MAX) {
            return Err(EventError::InvalidAuxiliary(self.kind));
        }
        self.require_zero(CanonicalField::Blob)
    }

    fn validate_empty_venue_payload_base(self) -> Result<(), EventError> {
        self.reject_flags(EVENT_FLAG_SNAPSHOT | EVENT_FLAG_RECOVERY)?;
        self.require_zero(CanonicalField::Instrument)?;
        self.require_none_side()?;
        self.require_zero(CanonicalField::OrderId)?;
        self.require_zero(CanonicalField::SecondaryId)?;
        self.require_zero(CanonicalField::TertiaryId)?;
        self.require_zero(CanonicalField::Price)?;
        self.require_zero(CanonicalField::Quantity)?;
        self.require_zero(CanonicalField::LeavesQuantity)?;
        self.require_zero(CanonicalField::Blob)
    }

    fn validate_empty_venue_payload(self) -> Result<(), EventError> {
        self.validate_empty_venue_payload_base()?;
        self.require_zero(CanonicalField::Reference)?;
        self.require_zero(CanonicalField::Auxiliary)
    }

    fn validate_session_code(self) -> Result<(), EventError> {
        self.validate_empty_venue_payload_base()?;
        self.require_zero(CanonicalField::Reference)?;
        if self.auxiliary > u64::from(u32::MAX) {
            return Err(EventError::InvalidAuxiliary(self.kind));
        }
        Ok(())
    }

    fn validate_clock_sample(self) -> Result<(), EventError> {
        self.reject_flags(EVENT_FLAG_SNAPSHOT | EVENT_FLAG_RECOVERY)?;
        self.require_none_side()?;
        self.require_zero(CanonicalField::OrderId)?;
        self.require_zero(CanonicalField::SecondaryId)?;
        self.require_zero(CanonicalField::TertiaryId)?;
        self.require_zero(CanonicalField::Price)?;
        self.require_zero(CanonicalField::Quantity)?;
        self.require_zero(CanonicalField::LeavesQuantity)?;
        self.require_reference()?;
        self.require_zero(CanonicalField::Blob)
    }

    fn validate_control(self) -> Result<(), EventError> {
        self.reject_flags(EVENT_FLAG_SNAPSHOT | EVENT_FLAG_RECOVERY)?;
        self.require_none_side()?;
        self.require_zero(CanonicalField::Price)?;
        self.require_zero(CanonicalField::Quantity)?;
        self.require_zero(CanonicalField::LeavesQuantity)?;
        if self.order_id.0 == 0 || self.secondary_id == 0 || self.reference == 0 {
            return Err(EventError::InvalidAuxiliary(self.kind));
        }
        match self.kind {
            EventKind::ControlArm => {
                if self.tertiary_id <= self.reference
                    || self.auxiliary == 0
                    || self.blob.iter().all(|byte| *byte == 0)
                {
                    return Err(EventError::InvalidBlob(self.kind));
                }
            }
            EventKind::ControlHeartbeat => {
                if self.tertiary_id <= self.reference {
                    return Err(EventError::InvalidAuxiliary(self.kind));
                }
                self.require_zero(CanonicalField::Auxiliary)?;
                self.require_zero(CanonicalField::Blob)?;
            }
            EventKind::ControlKill => {
                if self.tertiary_id == 0
                    || !(1..=8).contains(&(self.auxiliary & 0xff))
                    || !(1..=2).contains(&((self.auxiliary >> 8) & 0xff))
                    || self.auxiliary >> 16 != 0
                {
                    return Err(EventError::InvalidAuxiliary(self.kind));
                }
                self.require_zero(CanonicalField::Blob)?;
            }
            EventKind::ControlDisarm => {
                self.require_zero(CanonicalField::TertiaryId)?;
                self.require_zero(CanonicalField::Auxiliary)?;
                self.require_zero(CanonicalField::Blob)?;
            }
            _ => return Err(EventError::InvalidAuxiliary(self.kind)),
        }
        Ok(())
    }

    fn validate_transmission(self) -> Result<(), EventError> {
        self.reject_flags(EVENT_FLAG_SNAPSHOT | EVENT_FLAG_RECOVERY)?;
        self.require_zero(CanonicalField::LeavesQuantity)?;
        self.require_zero(CanonicalField::Blob)?;
        let status = self.auxiliary & 0xff;
        if !(1..=2).contains(&status) {
            return Err(EventError::InvalidAuxiliary(self.kind));
        }
        match self.kind {
            EventKind::TransmissionNew => {
                self.require_order_id()?;
                self.require_secondary_id()?;
                self.require_zero(CanonicalField::TertiaryId)?;
                self.require_side()?;
                self.require_positive_price()?;
                self.require_positive_quantity()?;
                self.require_reference()?;
                let tif = (self.auxiliary >> 8) & 0xff;
                if !(1..=5).contains(&tif) || self.auxiliary >> 16 != 0 {
                    return Err(EventError::InvalidAuxiliary(self.kind));
                }
            }
            EventKind::TransmissionCancel => {
                self.require_order_id()?;
                self.require_secondary_id()?;
                self.require_none_side()?;
                self.require_zero(CanonicalField::TertiaryId)?;
                self.require_zero(CanonicalField::Price)?;
                self.require_zero(CanonicalField::Quantity)?;
                self.require_reference()?;
                if self.auxiliary >> 8 != 0 {
                    return Err(EventError::InvalidAuxiliary(self.kind));
                }
            }
            EventKind::TransmissionReplace => {
                self.require_order_id()?;
                self.require_secondary_id()?;
                if self.order_id.0 == self.secondary_id {
                    return Err(EventError::IdentifiersMustDiffer(self.kind));
                }
                if self.tertiary_id == 0 {
                    return Err(EventError::CanonicalZeroRequired {
                        kind: self.kind,
                        field: CanonicalField::TertiaryId,
                    });
                }
                self.require_none_side()?;
                self.require_positive_price()?;
                self.require_positive_quantity()?;
                self.require_reference()?;
                if self.auxiliary >> 8 != 0 {
                    return Err(EventError::InvalidAuxiliary(self.kind));
                }
            }
            EventKind::TransmissionCancelAll => {
                self.require_none_side()?;
                self.require_zero(CanonicalField::SecondaryId)?;
                self.require_zero(CanonicalField::TertiaryId)?;
                self.require_zero(CanonicalField::Price)?;
                self.require_zero(CanonicalField::Quantity)?;
                self.require_reference()?;
                let scope = (self.auxiliary >> 8) & 0xff;
                if !(1..=2).contains(&scope)
                    || self.auxiliary >> 16 != 0
                    || (scope == 1 && self.order_id.0 != 0)
                    || (scope == 2 && self.order_id.0 == 0)
                {
                    return Err(EventError::InvalidAuxiliary(self.kind));
                }
            }
            _ => return Err(EventError::InvalidAuxiliary(self.kind)),
        }
        Ok(())
    }

    fn validate_timer(self) -> Result<(), EventError> {
        self.reject_flags(EVENT_FLAG_SNAPSHOT | EVENT_FLAG_RECOVERY)?;
        self.require_order_id()?;
        self.require_secondary_id()?;
        self.require_none_side()?;
        self.require_zero(CanonicalField::TertiaryId)?;
        self.require_zero(CanonicalField::Price)?;
        self.require_zero(CanonicalField::Quantity)?;
        self.require_zero(CanonicalField::LeavesQuantity)?;
        self.require_zero(CanonicalField::Reference)?;
        if self.monotonic_timestamp.0 < self.secondary_id || !(1..=3).contains(&self.auxiliary) {
            return Err(EventError::InvalidAuxiliary(self.kind));
        }
        self.require_zero(CanonicalField::Blob)
    }

    fn validate_owned_mbo_binding(self) -> Result<(), EventError> {
        self.reject_flags(EVENT_FLAG_SNAPSHOT | EVENT_FLAG_RECOVERY)?;
        self.require_order_id()?;
        self.require_secondary_id()?;
        if self.tertiary_id == 0 {
            return Err(EventError::CanonicalZeroRequired {
                kind: self.kind,
                field: CanonicalField::TertiaryId,
            });
        }
        self.require_none_side()?;
        self.require_zero(CanonicalField::Price)?;
        self.require_zero(CanonicalField::Quantity)?;
        self.require_zero(CanonicalField::LeavesQuantity)?;
        self.require_reference()?;
        self.require_zero(CanonicalField::Blob)?;

        let method = self.auxiliary & 0xff;
        let rule_id = (self.auxiliary >> 8) & u64::from(u32::MAX);
        let venue = (self.auxiliary >> 40) & u64::from(u16::MAX);
        let valid_method = (method == 1 && rule_id == 0) || (method == 2 && rule_id != 0);
        if !valid_method || venue == 0 || self.auxiliary >> 56 != 0 {
            return Err(EventError::InvalidAuxiliary(self.kind));
        }
        Ok(())
    }

    fn require_extended_zero(self) -> Result<(), EventError> {
        self.require_zero(CanonicalField::SecondaryId)?;
        self.require_zero(CanonicalField::TertiaryId)?;
        self.require_zero(CanonicalField::LeavesQuantity)?;
        self.require_zero(CanonicalField::Auxiliary)?;
        self.require_zero(CanonicalField::Blob)
    }

    fn require_secondary_id(self) -> Result<(), EventError> {
        if self.secondary_id == 0 {
            Err(EventError::CanonicalZeroRequired {
                kind: self.kind,
                field: CanonicalField::SecondaryId,
            })
        } else {
            Ok(())
        }
    }

    fn reject_flags(self, rejected: u16) -> Result<(), EventError> {
        if self.flags & rejected == 0 {
            Ok(())
        } else {
            Err(EventError::FlagsNotAllowed {
                kind: self.kind,
                flags: self.flags,
            })
        }
    }

    fn require_instrument(self) -> Result<(), EventError> {
        if self.header.instrument.0 == 0 {
            Err(EventError::InstrumentRequired(self.kind))
        } else {
            Ok(())
        }
    }

    fn require_side(self) -> Result<(), EventError> {
        if self.side == EventSide::None {
            Err(EventError::SideRequired(self.kind))
        } else {
            Ok(())
        }
    }

    fn require_none_side(self) -> Result<(), EventError> {
        if self.side == EventSide::None {
            Ok(())
        } else {
            Err(EventError::SideMustBeNone(self.kind))
        }
    }

    fn require_order_id(self) -> Result<(), EventError> {
        if self.order_id == OrderId(0) {
            Err(EventError::OrderIdRequired(self.kind))
        } else {
            Ok(())
        }
    }

    fn require_positive_price(self) -> Result<(), EventError> {
        if self.price.is_positive() {
            Ok(())
        } else {
            Err(EventError::PositivePriceRequired(self.kind))
        }
    }

    fn require_positive_quantity(self) -> Result<(), EventError> {
        if self.quantity.is_positive() {
            Ok(())
        } else {
            Err(EventError::PositiveQuantityRequired(self.kind))
        }
    }

    fn require_reference(self) -> Result<(), EventError> {
        if self.reference == 0 {
            Err(EventError::ReferenceRequired(self.kind))
        } else {
            Ok(())
        }
    }

    fn require_zero(self, field: CanonicalField) -> Result<(), EventError> {
        let is_zero = match field {
            CanonicalField::Instrument => self.header.instrument.0 == 0,
            CanonicalField::Side => self.side == EventSide::None,
            CanonicalField::OrderId => self.order_id.0 == 0,
            CanonicalField::Price => self.price == PriceTicks::ZERO,
            CanonicalField::Quantity => self.quantity == Quantity::ZERO,
            CanonicalField::Reference => self.reference == 0,
            CanonicalField::SecondaryId => self.secondary_id == 0,
            CanonicalField::TertiaryId => self.tertiary_id == 0,
            CanonicalField::LeavesQuantity => self.leaves_quantity == Quantity::ZERO,
            CanonicalField::Auxiliary => self.auxiliary == 0,
            CanonicalField::Blob => self.blob.iter().all(|byte| *byte == 0),
            CanonicalField::MonotonicTimestamp => {
                self.monotonic_timestamp == MonotonicTimestampNs::ZERO
            }
        };
        if is_zero {
            Ok(())
        } else {
            Err(EventError::CanonicalZeroRequired {
                kind: self.kind,
                field,
            })
        }
    }
}

impl PartialEq for NormalizedEvent {
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header
            && self.source == other.source
            && self.capture_ordinal == other.capture_ordinal
            && self.monotonic_timestamp == other.monotonic_timestamp
            && self.order_id == other.order_id
            && self.secondary_id == other.secondary_id
            && self.tertiary_id == other.tertiary_id
            && self.price == other.price
            && self.quantity == other.quantity
            && self.leaves_quantity == other.leaves_quantity
            && self.reference == other.reference
            && self.auxiliary == other.auxiliary
            && self.blob == other.blob
            && self.kind == other.kind
            && self.flags == other.flags
            && self.side == other.side
    }
}

impl Eq for NormalizedEvent {}
