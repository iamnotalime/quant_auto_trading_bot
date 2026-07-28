use crate::types::{MonotonicTimestampNs, TimestampNs};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockSample {
    pub utc: TimestampNs,
    pub monotonic: MonotonicTimestampNs,
    pub uncertainty_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisciplinedTimestamp {
    pub utc: TimestampNs,
    pub uncertainty_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockError {
    Uninitialized,
    InvalidUtcTimestamp,
    InvalidMonotonicTimestamp,
    MonotonicRegression,
    UtcRegression,
    ExcessiveUncertainty,
    OffsetStep,
    HoldoverExpired,
    ArithmeticOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClockDiscipline {
    last_sample: Option<ClockSample>,
    offset_ns: i64,
    max_uncertainty_ns: u64,
    max_offset_step_ns: u64,
    max_holdover_ns: u64,
    drift_parts_per_billion: u64,
}

impl ClockDiscipline {
    #[must_use]
    pub const fn new(
        max_uncertainty_ns: u64,
        max_offset_step_ns: u64,
        max_holdover_ns: u64,
        drift_parts_per_billion: u64,
    ) -> Self {
        Self {
            last_sample: None,
            offset_ns: 0,
            max_uncertainty_ns,
            max_offset_step_ns,
            max_holdover_ns,
            drift_parts_per_billion,
        }
    }

    /// Incorporate a new synchronization sample.
    ///
    /// # Errors
    ///
    /// Returns a clock error when uncertainty, ordering, offset-step, or arithmetic
    /// bounds are violated. A rejected sample never changes the accepted clock state.
    pub fn observe(&mut self, sample: ClockSample) -> Result<(), ClockError> {
        if sample.utc == TimestampNs::ZERO {
            return Err(ClockError::InvalidUtcTimestamp);
        }
        if sample.monotonic == MonotonicTimestampNs::ZERO {
            return Err(ClockError::InvalidMonotonicTimestamp);
        }
        if sample.uncertainty_ns > self.max_uncertainty_ns {
            return Err(ClockError::ExcessiveUncertainty);
        }
        let offset = i128::from(sample.utc.0) - i128::from(sample.monotonic.0);
        let offset = i64::try_from(offset).map_err(|_| ClockError::ArithmeticOverflow)?;
        if let Some(prior) = self.last_sample {
            if sample.monotonic <= prior.monotonic {
                return Err(ClockError::MonotonicRegression);
            }
            if sample.utc < prior.utc {
                return Err(ClockError::UtcRegression);
            }
            if offset.abs_diff(self.offset_ns) > self.max_offset_step_ns {
                return Err(ClockError::OffsetStep);
            }
        }
        self.offset_ns = offset;
        self.last_sample = Some(sample);
        Ok(())
    }

    /// Convert a monotonic hardware-clock reading to disciplined UTC.
    ///
    /// # Errors
    ///
    /// Returns an error before the first sample, after holdover expiry, on time
    /// regression, excessive uncertainty, or arithmetic overflow.
    pub fn timestamp(
        &self,
        monotonic_now: MonotonicTimestampNs,
    ) -> Result<DisciplinedTimestamp, ClockError> {
        let sample = self.last_sample.ok_or(ClockError::Uninitialized)?;
        if monotonic_now < sample.monotonic {
            return Err(ClockError::MonotonicRegression);
        }
        let age = monotonic_now.saturating_duration_since(sample.monotonic);
        if age > self.max_holdover_ns {
            return Err(ClockError::HoldoverExpired);
        }
        let drift = (u128::from(age) * u128::from(self.drift_parts_per_billion))
            .div_ceil(1_000_000_000_u128);
        let drift = u64::try_from(drift).map_err(|_| ClockError::ArithmeticOverflow)?;
        let uncertainty = sample
            .uncertainty_ns
            .checked_add(drift)
            .ok_or(ClockError::ArithmeticOverflow)?;
        if uncertainty > self.max_uncertainty_ns {
            return Err(ClockError::ExcessiveUncertainty);
        }
        let utc = i128::from(monotonic_now.0) + i128::from(self.offset_ns);
        let utc = u64::try_from(utc).map_err(|_| ClockError::ArithmeticOverflow)?;
        Ok(DisciplinedTimestamp {
            utc: TimestampNs(utc),
            uncertainty_ns: uncertainty,
        })
    }

    #[must_use]
    pub const fn last_sample(&self) -> Option<ClockSample> {
        self.last_sample
    }
}

#[cfg(test)]
mod tests {
    use super::{ClockDiscipline, ClockError, ClockSample, DisciplinedTimestamp};
    use crate::types::{MonotonicTimestampNs, TimestampNs};

    #[test]
    fn clock_rejects_steps_regressions_and_expired_holdover() {
        let mut clock = ClockDiscipline::new(1_000, 100, 10_000, 10);
        clock
            .observe(ClockSample {
                utc: TimestampNs(1_000_000),
                monotonic: MonotonicTimestampNs(500_000),
                uncertainty_ns: 100,
            })
            .unwrap();
        assert_eq!(
            clock.timestamp(MonotonicTimestampNs(500_100)),
            Ok(DisciplinedTimestamp {
                utc: TimestampNs(1_000_100),
                uncertainty_ns: 101,
            })
        );
        assert_eq!(
            clock.observe(ClockSample {
                utc: TimestampNs(1_000_010),
                monotonic: MonotonicTimestampNs(499_999),
                uncertainty_ns: 100,
            }),
            Err(ClockError::MonotonicRegression)
        );
        assert_eq!(
            clock.timestamp(MonotonicTimestampNs(520_001)),
            Err(ClockError::HoldoverExpired)
        );

        let mut invalid = ClockDiscipline::new(1_000, 100, 10_000, 10);
        assert_eq!(
            invalid.observe(ClockSample {
                utc: TimestampNs::ZERO,
                monotonic: MonotonicTimestampNs(1),
                uncertainty_ns: 1,
            }),
            Err(ClockError::InvalidUtcTimestamp)
        );
        assert_eq!(invalid.last_sample(), None);
    }
}
