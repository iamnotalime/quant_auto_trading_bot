use crate::types::TimestampNs;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum KillCode {
    Manual = 1,
    MarketDataGap = 2,
    ClockUnsafe = 3,
    RiskLimit = 4,
    LossLimit = 5,
    AdverseSelection = 6,
    VenueDisconnect = 7,
    InternalInvariant = 8,
    DropCopyMismatch = 9,
    LifecycleCorrection = 10,
}

impl KillCode {
    const fn from_raw(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Manual),
            2 => Some(Self::MarketDataGap),
            3 => Some(Self::ClockUnsafe),
            4 => Some(Self::RiskLimit),
            5 => Some(Self::LossLimit),
            6 => Some(Self::AdverseSelection),
            7 => Some(Self::VenueDisconnect),
            8 => Some(Self::InternalInvariant),
            9 => Some(Self::DropCopyMismatch),
            10 => Some(Self::LifecycleCorrection),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KillSnapshot {
    pub code: KillCode,
    pub triggered_at: TimestampNs,
}

/// Non-blocking view of the first-fault publication state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KillState {
    Clear,
    /// A triggering thread owns the latch but has not published the complete snapshot.
    Publishing,
    Triggered(KillSnapshot),
}

#[derive(Debug)]
pub struct KillLatch {
    triggered_at_ns: AtomicU64,
    code: AtomicU8,
}

impl KillLatch {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            triggered_at_ns: AtomicU64::new(0),
            code: AtomicU8::new(0),
        }
    }

    /// Monotonic first-fault latch. A later fault cannot overwrite the initiating cause.
    pub fn trigger(&self, code: KillCode, now: TimestampNs) -> bool {
        if self
            .code
            .compare_exchange(0, u8::MAX, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        self.triggered_at_ns.store(now.0, Ordering::Relaxed);
        self.code.store(code as u8, Ordering::Release);
        true
    }

    #[must_use]
    pub fn is_triggered(&self) -> bool {
        matches!(self.code.load(Ordering::Acquire), 1..=10 | u8::MAX)
    }

    #[must_use]
    pub fn snapshot(&self) -> Option<KillSnapshot> {
        match self.state() {
            KillState::Triggered(snapshot) => Some(snapshot),
            KillState::Clear | KillState::Publishing => None,
        }
    }

    /// Observe the latch without waiting for a preempted publisher.
    #[must_use]
    pub fn state(&self) -> KillState {
        let raw = self.code.load(Ordering::Acquire);
        if raw == 0 {
            return KillState::Clear;
        }
        if raw == u8::MAX {
            return KillState::Publishing;
        }
        let Some(code) = KillCode::from_raw(raw) else {
            return KillState::Publishing;
        };
        let triggered_at = TimestampNs(self.triggered_at_ns.load(Ordering::Relaxed));
        KillState::Triggered(KillSnapshot { code, triggered_at })
    }
}

impl Default for KillLatch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{KillCode, KillLatch, KillSnapshot, KillState};
    use crate::types::TimestampNs;

    #[test]
    fn first_kill_reason_is_monotonic() {
        let latch = KillLatch::new();
        assert!(latch.trigger(KillCode::MarketDataGap, TimestampNs(100)));
        assert!(!latch.trigger(KillCode::Manual, TimestampNs(200)));
        assert_eq!(
            latch.snapshot(),
            Some(KillSnapshot {
                code: KillCode::MarketDataGap,
                triggered_at: TimestampNs(100),
            })
        );
        assert_eq!(
            latch.state(),
            KillState::Triggered(KillSnapshot {
                code: KillCode::MarketDataGap,
                triggered_at: TimestampNs(100),
            })
        );
    }
}
