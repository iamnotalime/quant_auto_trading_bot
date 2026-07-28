use quant_hft_core::adverse::{AdverseConfig, AdverseError, AdverseFill, AdverseMonitor};
use quant_hft_core::kill::{KillCode, KillLatch};
use quant_hft_core::types::{InstrumentId, PriceTicks, Quantity, Side, TimestampNs};

type Monitor = AdverseMonitor<2, 8>;

fn config() -> AdverseConfig {
    AdverseConfig {
        markout_horizon_ns: 10,
        rolling_window_ns: 100,
        breach_markout_ticks: 2,
        halt_after_consecutive: 10,
        halt_aggregate_loss: 10_000,
        kill_after_consecutive: 20,
        kill_aggregate_loss: 20_000,
    }
}

fn fill(execution_id: u64, exchange_timestamp: u64) -> AdverseFill {
    AdverseFill {
        execution_id,
        instrument: InstrumentId(1),
        side: Side::Buy,
        fill_price: PriceTicks(100),
        quantity: Quantity(10),
        fill_timestamp: TimestampNs(exchange_timestamp),
    }
}

#[test]
fn buffered_pre_horizon_mark_does_not_use_processing_delay_as_markout_time() {
    let kill = KillLatch::new();
    let mut monitor = Monitor::new(config()).expect("monitor");
    monitor
        .on_fill(fill(1, 100), TimestampNs(1_000), &kill)
        .expect("delayed fill");

    let buffered = monitor
        .on_mark(
            InstrumentId(1),
            PriceTicks(97),
            TimestampNs(105),
            TimestampNs(2_000),
            &kill,
        )
        .expect("buffered mark");
    assert_eq!(buffered.evaluated_fills, 0);
    assert_eq!(
        monitor
            .fill(1)
            .expect("pending fill")
            .evaluation_mark_timestamp,
        None
    );

    let due = monitor
        .on_mark(
            InstrumentId(1),
            PriceTicks(97),
            TimestampNs(110),
            TimestampNs(2_100),
            &kill,
        )
        .expect("economic horizon mark");
    assert_eq!(due.evaluated_fills, 1);
    assert_eq!(due.weighted_markout_delta, -30);
    assert_eq!(
        monitor
            .fill(1)
            .expect("evaluated fill")
            .evaluation_mark_timestamp,
        Some(TimestampNs(110))
    );
    assert_eq!(monitor.last_observed_timestamp(), Some(TimestampNs(2_100)));
    assert!(!kill.is_triggered());
}

#[test]
fn observed_fill_time_is_not_used_to_expire_exchange_time_markouts() {
    let kill = KillLatch::new();
    let mut monitor = Monitor::new(config()).expect("monitor");
    monitor
        .on_fill(fill(1, 100), TimestampNs(1_000), &kill)
        .expect("first fill");
    monitor
        .on_mark(
            InstrumentId(1),
            PriceTicks(101),
            TimestampNs(110),
            TimestampNs(2_000),
            &kill,
        )
        .expect("evaluation");

    // The processing clock is far beyond the rolling window, but the new fill's
    // exchange timestamp is only one nanosecond after the evaluated mark.
    monitor
        .on_fill(fill(2, 111), TimestampNs(50_000), &kill)
        .expect("second delayed fill");
    assert_eq!(monitor.tracked_fill_count(), 2);
    assert!(monitor.fill(1).is_some());
    assert!(monitor.fill(2).is_some());
    assert_eq!(monitor.last_observed_timestamp(), Some(TimestampNs(50_000)));
}

#[test]
fn late_fill_beyond_retained_mark_frontier_fails_closed_without_mutation() {
    let kill = KillLatch::new();
    let mut monitor = Monitor::new(config()).expect("monitor");
    monitor
        .on_mark(
            InstrumentId(1),
            PriceTicks(97),
            TimestampNs(110),
            TimestampNs(1_000),
            &kill,
        )
        .expect("frontier mark");
    let instrument_before = monitor.instrument(InstrumentId(1));

    assert_eq!(
        monitor.on_fill(fill(1, 100), TimestampNs(1_100), &kill),
        Err(AdverseError::LateFillBeyondMarkFrontier {
            fill: TimestampNs(100),
            frontier: TimestampNs(110),
        })
    );
    assert_eq!(monitor.instrument(InstrumentId(1)), instrument_before);
    assert_eq!(monitor.tracked_fill_count(), 0);
    assert_eq!(monitor.fill(1), None);
    assert_eq!(monitor.last_observed_timestamp(), Some(TimestampNs(1_000)));
    assert_eq!(
        kill.snapshot().expect("event-order kill"),
        quant_hft_core::kill::KillSnapshot {
            code: KillCode::ClockUnsafe,
            triggered_at: TimestampNs(1_100),
        }
    );
}

#[test]
fn delayed_fill_before_horizon_is_retained_and_evaluated_once_at_first_due_mark() {
    let kill = KillLatch::new();
    let mut monitor = Monitor::new(config()).expect("monitor");
    monitor
        .on_mark(
            InstrumentId(1),
            PriceTicks(99),
            TimestampNs(105),
            TimestampNs(1_000),
            &kill,
        )
        .expect("pre-horizon frontier");
    monitor
        .on_fill(fill(1, 100), TimestampNs(1_100), &kill)
        .expect("delayed but reconstructable fill");

    let due = monitor
        .on_mark(
            InstrumentId(1),
            PriceTicks(97),
            TimestampNs(110),
            TimestampNs(1_200),
            &kill,
        )
        .expect("first due mark");
    assert_eq!(due.evaluated_fills, 1);
    assert_eq!(due.weighted_markout_delta, -30);
    assert_eq!(
        monitor
            .fill(1)
            .expect("evaluated fill")
            .evaluation_mark_timestamp,
        Some(TimestampNs(110))
    );

    let repeated = monitor
        .on_mark(
            InstrumentId(1),
            PriceTicks(90),
            TimestampNs(111),
            TimestampNs(1_300),
            &kill,
        )
        .expect("later mark");
    assert_eq!(repeated.evaluated_fills, 0);
    assert_eq!(repeated.weighted_markout_delta, 0);
    assert!(!kill.is_triggered());
}

#[test]
fn economic_and_observation_regressions_fail_atomically_on_separate_cursors() {
    let economic_kill = KillLatch::new();
    let mut economic = Monitor::new(config()).expect("monitor");
    economic
        .on_fill(fill(1, 100), TimestampNs(1_000), &economic_kill)
        .expect("fill");
    economic
        .on_mark(
            InstrumentId(1),
            PriceTicks(101),
            TimestampNs(110),
            TimestampNs(2_000),
            &economic_kill,
        )
        .expect("first mark");
    let fill_before = economic.fill(1);
    let instrument_before = economic.instrument(InstrumentId(1));
    assert_eq!(
        economic.on_mark(
            InstrumentId(1),
            PriceTicks(99),
            TimestampNs(109),
            TimestampNs(2_001),
            &economic_kill,
        ),
        Err(AdverseError::MarkTimestampRegression {
            prior: TimestampNs(110),
            received: TimestampNs(109),
        })
    );
    assert_eq!(economic.fill(1), fill_before);
    assert_eq!(economic.instrument(InstrumentId(1)), instrument_before);
    assert_eq!(economic.last_observed_timestamp(), Some(TimestampNs(2_000)));
    assert_eq!(
        economic_kill.snapshot().expect("economic kill"),
        quant_hft_core::kill::KillSnapshot {
            code: KillCode::ClockUnsafe,
            triggered_at: TimestampNs(2_001),
        }
    );

    let observation_kill = KillLatch::new();
    let mut observation = Monitor::new(config()).expect("monitor");
    observation
        .on_mark(
            InstrumentId(1),
            PriceTicks(100),
            TimestampNs(100),
            TimestampNs(1_000),
            &observation_kill,
        )
        .expect("first observation");
    let instrument_before = observation.instrument(InstrumentId(1));
    assert_eq!(
        observation.on_mark(
            InstrumentId(1),
            PriceTicks(101),
            TimestampNs(101),
            TimestampNs(999),
            &observation_kill,
        ),
        Err(AdverseError::ClockRegression {
            prior: TimestampNs(1_000),
            received: TimestampNs(999),
        })
    );
    assert_eq!(observation.instrument(InstrumentId(1)), instrument_before);
    assert_eq!(
        observation.last_observed_timestamp(),
        Some(TimestampNs(1_000))
    );
    assert_eq!(
        observation_kill
            .snapshot()
            .expect("observation regression kill")
            .triggered_at,
        TimestampNs(1_000)
    );
}

#[test]
fn zero_observation_after_a_safe_event_uses_the_causal_kill_floor() {
    let kill = KillLatch::new();
    let mut monitor = Monitor::new(config()).expect("monitor");
    monitor
        .on_mark(
            InstrumentId(1),
            PriceTicks(100),
            TimestampNs(100),
            TimestampNs(1_000),
            &kill,
        )
        .expect("safe observation");
    let instrument_before = monitor.instrument(InstrumentId(1));

    assert_eq!(
        monitor.on_mark(
            InstrumentId(1),
            PriceTicks(101),
            TimestampNs(101),
            TimestampNs::ZERO,
            &kill,
        ),
        Err(AdverseError::ZeroEventTimestamp)
    );
    assert_eq!(monitor.instrument(InstrumentId(1)), instrument_before);
    assert_eq!(monitor.last_observed_timestamp(), Some(TimestampNs(1_000)));
    assert_eq!(
        kill.snapshot().expect("clock kill").triggered_at,
        TimestampNs(1_000)
    );
}

#[test]
fn zero_and_future_mark_times_fail_before_monitor_mutation() {
    for (mark_timestamp, observed_at, expected) in [
        (
            TimestampNs::ZERO,
            TimestampNs(10),
            AdverseError::ZeroMarkTimestamp,
        ),
        (
            TimestampNs(11),
            TimestampNs(10),
            AdverseError::FutureMarkTimestamp {
                mark: TimestampNs(11),
                observed_at: TimestampNs(10),
            },
        ),
    ] {
        let kill = KillLatch::new();
        let mut monitor = Monitor::new(config()).expect("monitor");
        assert_eq!(
            monitor.on_mark(
                InstrumentId(1),
                PriceTicks(100),
                mark_timestamp,
                observed_at,
                &kill,
            ),
            Err(expected)
        );
        assert_eq!(monitor.instrument_count(), 0);
        assert_eq!(monitor.tracked_fill_count(), 0);
        assert_eq!(monitor.last_observed_timestamp(), None);
        assert_eq!(
            kill.snapshot().expect("clock kill").triggered_at,
            observed_at
        );
    }
}
