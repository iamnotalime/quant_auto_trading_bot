use core::fmt;

/// UTC nanoseconds since Unix epoch. Venue adapters must retain the original exchange
/// timestamp separately from the local hardware receive timestamp.
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct TimestampNs(pub u64);

impl TimestampNs {
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub const fn saturating_duration_since(self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }

    #[must_use]
    pub const fn checked_duration_since(self, earlier: Self) -> Option<u64> {
        self.0.checked_sub(earlier.0)
    }

    #[must_use]
    pub const fn checked_add(self, nanoseconds: u64) -> Option<Self> {
        match self.0.checked_add(nanoseconds) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

impl fmt::Debug for TimestampNs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}ns", self.0)
    }
}

/// Nanoseconds from a process-local monotonic clock origin. This value must never be
/// serialized or compared directly with UTC/venue timestamps.
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct MonotonicTimestampNs(pub u64);

impl MonotonicTimestampNs {
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub const fn saturating_duration_since(self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

impl fmt::Debug for MonotonicTimestampNs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "mono+{}ns", self.0)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct InstrumentId(pub u32);

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct VenueId(pub u16);

/// ISO/internal currency key whose atomic-unit convention is fixed by deployment.
/// Zero is invalid and reserved for an absent currency binding.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct CurrencyId(pub u32);

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct OrderId(pub u64);

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Sequence(pub u64);

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct PriceTicks(pub i64);

impl PriceTicks {
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub const fn is_positive(self) -> bool {
        self.0 > 0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct Quantity(pub i64);

impl Quantity {
    pub const ZERO: Self = Self(0);

    #[must_use]
    pub const fn is_positive(self) -> bool {
        self.0 > 0
    }

    #[must_use]
    pub const fn unsigned_abs(self) -> u64 {
        self.0.unsigned_abs()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum Side {
    Buy = 1,
    Sell = 2,
}

impl Side {
    #[must_use]
    pub const fn sign(self) -> i64 {
        match self {
            Self::Buy => 1,
            Self::Sell => -1,
        }
    }

    #[must_use]
    pub const fn opposite(self) -> Self {
        match self {
            Self::Buy => Self::Sell,
            Self::Sell => Self::Buy,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct EventHeader {
    pub venue: VenueId,
    pub instrument: InstrumentId,
    pub sequence: Sequence,
    pub exchange_timestamp: TimestampNs,
    pub hardware_receive_timestamp: TimestampNs,
}

impl EventHeader {
    #[must_use]
    pub const fn wire_latency_ns(self) -> Option<u64> {
        self.hardware_receive_timestamp
            .checked_duration_since(self.exchange_timestamp)
    }
}
