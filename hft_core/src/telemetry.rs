use crate::types::TimestampNs;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LatencyStage {
    Wire = 0,
    Decode = 1,
    Decision = 2,
    Encode = 3,
    Acknowledgement = 4,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PipelineLatency {
    pub exchange_to_receive_ns: u64,
    pub receive_to_decision_ns: u64,
    pub decision_to_send_ns: u64,
    pub send_to_ack_ns: u64,
}

impl PipelineLatency {
    #[must_use]
    pub fn from_timestamps(
        exchange: TimestampNs,
        receive: TimestampNs,
        decision: TimestampNs,
        send: TimestampNs,
        acknowledgement: TimestampNs,
    ) -> Option<Self> {
        if !(exchange <= receive
            && receive <= decision
            && decision <= send
            && send <= acknowledgement)
        {
            return None;
        }
        Some(Self {
            exchange_to_receive_ns: receive.saturating_duration_since(exchange),
            receive_to_decision_ns: decision.saturating_duration_since(receive),
            decision_to_send_ns: send.saturating_duration_since(decision),
            send_to_ack_ns: acknowledgement.saturating_duration_since(send),
        })
    }
}

#[derive(Clone, Debug)]
pub struct LatencyHistogram<const N: usize> {
    buckets: [u64; N],
    count: u64,
    sum_ns: u128,
    minimum_ns: u64,
    maximum_ns: u64,
}

impl<const N: usize> LatencyHistogram<N> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buckets: [0; N],
            count: 0,
            sum_ns: 0,
            minimum_ns: u64::MAX,
            maximum_ns: 0,
        }
    }

    /// Log2 nanosecond buckets: bucket 0 is 0-1ns, bucket k ends at 2^(k+1)-1ns.
    pub fn record(&mut self, latency_ns: u64) {
        if N == 0 {
            return;
        }
        let raw = if latency_ns <= 1 {
            0
        } else {
            63_u32.saturating_sub(latency_ns.leading_zeros()) as usize
        };
        let index = raw.min(N - 1);
        self.buckets[index] = self.buckets[index].saturating_add(1);
        self.count = self.count.saturating_add(1);
        self.sum_ns = self.sum_ns.saturating_add(u128::from(latency_ns));
        self.minimum_ns = self.minimum_ns.min(latency_ns);
        self.maximum_ns = self.maximum_ns.max(latency_ns);
    }

    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }

    #[must_use]
    pub const fn minimum_ns(&self) -> Option<u64> {
        if self.count == 0 {
            None
        } else {
            Some(self.minimum_ns)
        }
    }

    #[must_use]
    pub const fn maximum_ns(&self) -> Option<u64> {
        if self.count == 0 {
            None
        } else {
            Some(self.maximum_ns)
        }
    }

    #[must_use]
    pub fn mean_ns(&self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        u64::try_from(self.sum_ns / u128::from(self.count)).ok()
    }

    #[must_use]
    pub fn percentile_upper_bound_ns(&self, numerator: u64, denominator: u64) -> Option<u64> {
        if self.count == 0 || denominator == 0 || numerator > denominator || N == 0 {
            return None;
        }
        let target = u128::from(self.count)
            .saturating_mul(u128::from(numerator))
            .div_ceil(u128::from(denominator));
        let mut cumulative = 0_u128;
        for (index, count) in self.buckets.iter().enumerate() {
            cumulative = cumulative.saturating_add(u128::from(*count));
            if cumulative >= target.max(1) {
                let shift = u32::try_from(index + 1).ok()?;
                if shift >= u64::BITS {
                    return Some(u64::MAX);
                }
                return 1_u64
                    .checked_shl(shift)
                    .map(|value| value.saturating_sub(1));
            }
        }
        Some(self.maximum_ns)
    }
}

impl<const N: usize> Default for LatencyHistogram<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{LatencyHistogram, PipelineLatency};
    use crate::types::TimestampNs;

    #[test]
    fn pipeline_rejects_timestamp_regression() {
        assert!(
            PipelineLatency::from_timestamps(
                TimestampNs(1),
                TimestampNs(3),
                TimestampNs(2),
                TimestampNs(4),
                TimestampNs(5),
            )
            .is_none()
        );
    }

    #[test]
    fn histogram_is_fixed_and_deterministic() {
        let mut histogram = LatencyHistogram::<16>::new();
        for value in [1, 2, 3, 4, 8, 16, 32, 64] {
            histogram.record(value);
        }
        assert_eq!(histogram.count(), 8);
        assert_eq!(histogram.minimum_ns(), Some(1));
        assert_eq!(histogram.maximum_ns(), Some(64));
        assert!(histogram.percentile_upper_bound_ns(99, 100).unwrap() >= 64);

        let mut terminal = LatencyHistogram::<64>::new();
        terminal.record(u64::MAX);
        assert_eq!(terminal.percentile_upper_bound_ns(100, 100), Some(u64::MAX));
    }
}
