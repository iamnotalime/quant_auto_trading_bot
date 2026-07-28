//! Bounded, side-aware post-fill markout surveillance.

use crate::kill::{KillCode, KillLatch};
use crate::types::{InstrumentId, PriceTicks, Quantity, Side, TimestampNs};

/// Thresholds use integer price ticks and `price_ticks * quantity`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdverseConfig {
    pub markout_horizon_ns: u64,
    pub rolling_window_ns: u64,
    pub breach_markout_ticks: i64,
    pub halt_after_consecutive: u32,
    pub halt_aggregate_loss: i128,
    pub kill_after_consecutive: u32,
    pub kill_aggregate_loss: i128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdverseInstrumentSnapshot {
    pub instrument: InstrumentId,
    pub consecutive_breaches: u32,
    pub rolling_weighted_markout: i128,
    pub halted: bool,
    pub last_mark: Option<PriceTicks>,
    pub last_mark_timestamp: Option<TimestampNs>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrackedFillSnapshot {
    pub execution_id: u64,
    pub instrument: InstrumentId,
    pub side: Side,
    pub fill_price: PriceTicks,
    pub quantity: Quantity,
    pub fill_timestamp: TimestampNs,
    /// Economic exchange timestamp of the mark used for evaluation.
    pub evaluation_mark_timestamp: Option<TimestampNs>,
    pub signed_markout_ticks: Option<i128>,
    pub weighted_markout: Option<i128>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdverseFill {
    pub execution_id: u64,
    pub instrument: InstrumentId,
    pub side: Side,
    pub fill_price: PriceTicks,
    pub quantity: Quantity,
    pub fill_timestamp: TimestampNs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FillTrackOutcome {
    pub ordinal: u64,
    pub instrument_halted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdverseMarkOutcome {
    pub evaluated_fills: usize,
    pub weighted_markout_delta: i128,
    pub rolling_weighted_markout: i128,
    pub consecutive_breaches: u32,
    pub instrument_halted: bool,
    pub halt_triggered: bool,
    /// True only when this mark won the global first-fault race.
    pub global_kill_triggered: bool,
    /// Record visits across the validation and commit passes. This is bounded by
    /// `2 * MAX_FILLS` and makes hot-path work observable in deterministic tests.
    pub work_units: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdverseError {
    InvalidConfig,
    InvalidInstrumentId,
    InvalidExecutionId,
    DuplicateExecution(u64),
    InvalidPrice(PriceTicks),
    InvalidQuantity(Quantity),
    ZeroFillTimestamp,
    ZeroMarkTimestamp,
    ZeroEventTimestamp,
    FutureFillTimestamp {
        fill: TimestampNs,
        now: TimestampNs,
    },
    ClockRegression {
        prior: TimestampNs,
        received: TimestampNs,
    },
    FutureMarkTimestamp {
        mark: TimestampNs,
        observed_at: TimestampNs,
    },
    /// The retained mark frontier has already crossed this fill's configured
    /// evaluation horizon. Without a bounded historical mark buffer, evaluating
    /// the fill against a later price would invent a markout.
    LateFillBeyondMarkFrontier {
        fill: TimestampNs,
        frontier: TimestampNs,
    },
    InstrumentCapacity {
        capacity: usize,
    },
    FillCapacity {
        capacity: usize,
    },
    MarkTimestampRegression {
        prior: TimestampNs,
        received: TimestampNs,
    },
    ArithmeticOverflow,
    InternalInvariant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AdverseInstrument {
    instrument: InstrumentId,
    consecutive_breaches: u32,
    halted: bool,
    last_mark: Option<i64>,
    last_mark_timestamp: Option<TimestampNs>,
}

impl AdverseInstrument {
    const fn new(instrument: InstrumentId) -> Self {
        Self {
            instrument,
            consecutive_breaches: 0,
            halted: false,
            last_mark: None,
            last_mark_timestamp: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TrackedFill {
    execution_id: u64,
    ordinal: u64,
    instrument: InstrumentId,
    side: Side,
    fill_price: i64,
    quantity: i64,
    fill_timestamp: TimestampNs,
    evaluation_mark_timestamp: Option<TimestampNs>,
    signed_markout_ticks: Option<i128>,
    weighted_markout: Option<i128>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EvaluationBatch {
    evaluated_fills: usize,
    weighted_markout_delta: i128,
    rolling_weighted_markout: i128,
    consecutive_breaches: u32,
    retained_fills: usize,
    work_units: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InstrumentPlan {
    index: usize,
    state: AdverseInstrument,
    instrument_count: usize,
}

impl TrackedFill {
    const fn snapshot(self) -> TrackedFillSnapshot {
        TrackedFillSnapshot {
            execution_id: self.execution_id,
            instrument: self.instrument,
            side: self.side,
            fill_price: PriceTicks(self.fill_price),
            quantity: Quantity(self.quantity),
            fill_timestamp: self.fill_timestamp,
            evaluation_mark_timestamp: self.evaluation_mark_timestamp,
            signed_markout_ticks: self.signed_markout_ticks,
            weighted_markout: self.weighted_markout,
        }
    }
}

/// Fixed-capacity single-writer markout monitor. Evaluated fills remain resident
/// only for the configured rolling window, after which their slots are reused.
#[derive(Debug, Eq, PartialEq)]
pub struct AdverseMonitor<const MAX_INSTRUMENTS: usize, const MAX_FILLS: usize> {
    config: AdverseConfig,
    instruments: [Option<AdverseInstrument>; MAX_INSTRUMENTS],
    fills: [Option<TrackedFill>; MAX_FILLS],
    instrument_count: usize,
    fill_count: usize,
    next_ordinal: u64,
    /// Processing-order cursor. This is deliberately distinct from exchange-time
    /// mark and fill chronology.
    last_observed_timestamp: Option<TimestampNs>,
}

impl<const MAX_INSTRUMENTS: usize, const MAX_FILLS: usize>
    AdverseMonitor<MAX_INSTRUMENTS, MAX_FILLS>
{
    /// Construct a monitor with statically bounded tables.
    ///
    /// # Errors
    ///
    /// Returns [`AdverseError::InvalidConfig`] for zero, inverted, or
    /// non-monotonic thresholds, or for a zero compile-time capacity.
    pub fn new(config: AdverseConfig) -> Result<Self, AdverseError> {
        if config.markout_horizon_ns == 0
            || config.rolling_window_ns < config.markout_horizon_ns
            || config.breach_markout_ticks <= 0
            || config.halt_after_consecutive == 0
            || config.halt_aggregate_loss <= 0
            || config.kill_after_consecutive < config.halt_after_consecutive
            || config.kill_aggregate_loss < config.halt_aggregate_loss
            || MAX_INSTRUMENTS == 0
            || MAX_FILLS == 0
        {
            return Err(AdverseError::InvalidConfig);
        }
        Ok(Self {
            config,
            instruments: [None; MAX_INSTRUMENTS],
            fills: [None; MAX_FILLS],
            instrument_count: 0,
            fill_count: 0,
            next_ordinal: 1,
            last_observed_timestamp: None,
        })
    }

    #[must_use]
    pub const fn config(&self) -> AdverseConfig {
        self.config
    }

    #[must_use]
    pub const fn instrument_count(&self) -> usize {
        self.instrument_count
    }

    #[must_use]
    pub const fn tracked_fill_count(&self) -> usize {
        self.fill_count
    }

    #[must_use]
    pub const fn last_observed_timestamp(&self) -> Option<TimestampNs> {
        self.last_observed_timestamp
    }

    /// Backward-compatible name for the processing observation cursor.
    #[must_use]
    pub const fn last_event_timestamp(&self) -> Option<TimestampNs> {
        self.last_observed_timestamp
    }

    #[must_use]
    pub fn is_halted(&self, instrument: InstrumentId) -> bool {
        self.find_instrument(instrument)
            .and_then(|index| self.instruments[index])
            .is_some_and(|state| state.halted)
    }

    /// Return current local-halt and rolling-markout state.
    ///
    /// # Errors
    ///
    /// Returns an arithmetic or invariant error if retained markouts cannot be
    /// summed consistently.
    pub fn instrument(
        &self,
        instrument: InstrumentId,
    ) -> Result<Option<AdverseInstrumentSnapshot>, AdverseError> {
        let Some(index) = self.find_instrument(instrument) else {
            return Ok(None);
        };
        let state = self.instruments[index].ok_or(AdverseError::InternalInvariant)?;
        Ok(Some(AdverseInstrumentSnapshot {
            instrument: state.instrument,
            consecutive_breaches: state.consecutive_breaches,
            rolling_weighted_markout: self.rolling_markout(instrument)?,
            halted: state.halted,
            last_mark: state.last_mark.map(PriceTicks),
            last_mark_timestamp: state.last_mark_timestamp,
        }))
    }

    #[must_use]
    pub fn fill(&self, execution_id: u64) -> Option<TrackedFillSnapshot> {
        self.fills
            .iter()
            .flatten()
            .find(|fill| fill.execution_id == execution_id)
            .copied()
            .map(TrackedFill::snapshot)
    }

    /// Track a fill fact even if the instrument is already halted. Dropping fills
    /// would blind post-trade controls to exposure accumulated during cancellation.
    ///
    /// # Errors
    ///
    /// Rejects malformed or duplicate fills, exhausted fixed capacity, ordinal
    /// overflow, and internal table inconsistencies. Fatal errors latch `kill`.
    // Validation and retention planning precede the sole mutation block so `Err`
    // leaves the monitor unchanged.
    #[allow(clippy::too_many_lines)]
    pub fn on_fill(
        &mut self,
        fill: AdverseFill,
        now: TimestampNs,
        kill: &KillLatch,
    ) -> Result<FillTrackOutcome, AdverseError> {
        self.validate_observation_or_kill(now, kill)?;
        if fill.fill_timestamp == TimestampNs::ZERO {
            return Self::kill_error(
                kill,
                now,
                KillCode::ClockUnsafe,
                AdverseError::ZeroFillTimestamp,
            );
        }
        if fill.fill_timestamp > now {
            return Self::kill_error(
                kill,
                now,
                KillCode::ClockUnsafe,
                AdverseError::FutureFillTimestamp {
                    fill: fill.fill_timestamp,
                    now,
                },
            );
        }
        if fill.instrument.0 == 0 {
            return Self::kill_error(
                kill,
                now,
                KillCode::InternalInvariant,
                AdverseError::InvalidInstrumentId,
            );
        }
        if fill.execution_id == 0 {
            return Self::kill_error(
                kill,
                now,
                KillCode::InternalInvariant,
                AdverseError::InvalidExecutionId,
            );
        }
        if !fill.fill_price.is_positive() {
            return Self::kill_error(
                kill,
                now,
                KillCode::InternalInvariant,
                AdverseError::InvalidPrice(fill.fill_price),
            );
        }
        if !fill.quantity.is_positive() {
            return Self::kill_error(
                kill,
                now,
                KillCode::InternalInvariant,
                AdverseError::InvalidQuantity(fill.quantity),
            );
        }
        if self.fill(fill.execution_id).is_some() {
            return Self::kill_error(
                kill,
                now,
                KillCode::InternalInvariant,
                AdverseError::DuplicateExecution(fill.execution_id),
            );
        }
        let next_ordinal = self.next_ordinal.checked_add(1).ok_or_else(|| {
            kill.trigger(KillCode::InternalInvariant, now);
            AdverseError::ArithmeticOverflow
        })?;
        let plan = self.instrument_plan(fill.instrument).inspect_err(|_| {
            kill.trigger(KillCode::InternalInvariant, now);
        })?;
        if let Some(frontier) = plan.state.last_mark_timestamp
            && frontier.saturating_duration_since(fill.fill_timestamp)
                >= self.config.markout_horizon_ns
        {
            return Self::kill_error(
                kill,
                now,
                KillCode::ClockUnsafe,
                AdverseError::LateFillBeyondMarkFrontier {
                    fill: fill.fill_timestamp,
                    frontier,
                },
            );
        }
        if self.fill_count == MAX_FILLS {
            return Self::kill_error(
                kill,
                now,
                KillCode::InternalInvariant,
                AdverseError::FillCapacity {
                    capacity: MAX_FILLS,
                },
            );
        }
        let candidate_fill_count = self.fill_count.checked_add(1).ok_or_else(|| {
            kill.trigger(KillCode::InternalInvariant, now);
            AdverseError::ArithmeticOverflow
        })?;
        let ordinal = self.next_ordinal;

        self.instruments[plan.index] = Some(plan.state);
        self.instrument_count = plan.instrument_count;
        self.next_ordinal = next_ordinal;
        self.fills[self.fill_count] = Some(TrackedFill {
            execution_id: fill.execution_id,
            ordinal,
            instrument: fill.instrument,
            side: fill.side,
            fill_price: fill.fill_price.0,
            quantity: fill.quantity.0,
            fill_timestamp: fill.fill_timestamp,
            evaluation_mark_timestamp: None,
            signed_markout_ticks: None,
            weighted_markout: None,
        });
        self.fill_count = candidate_fill_count;
        self.last_observed_timestamp = Some(now);
        Ok(FillTrackOutcome {
            ordinal,
            instrument_halted: plan.state.halted,
        })
    }

    /// Evaluate every due fill for this instrument in fill-arrival order.
    ///
    /// # Errors
    ///
    /// Rejects an invalid mark, a regressing mark timestamp, exhausted instrument
    /// capacity, arithmetic overflow, or an internal table inconsistency.
    pub fn on_mark(
        &mut self,
        instrument: InstrumentId,
        mark: PriceTicks,
        mark_timestamp: TimestampNs,
        observed_at: TimestampNs,
        kill: &KillLatch,
    ) -> Result<AdverseMarkOutcome, AdverseError> {
        self.validate_observation_or_kill(observed_at, kill)?;
        if mark_timestamp == TimestampNs::ZERO {
            return Self::kill_error(
                kill,
                observed_at,
                KillCode::ClockUnsafe,
                AdverseError::ZeroMarkTimestamp,
            );
        }
        if mark_timestamp > observed_at {
            return Self::kill_error(
                kill,
                observed_at,
                KillCode::ClockUnsafe,
                AdverseError::FutureMarkTimestamp {
                    mark: mark_timestamp,
                    observed_at,
                },
            );
        }
        if instrument.0 == 0 {
            return Self::kill_error(
                kill,
                observed_at,
                KillCode::InternalInvariant,
                AdverseError::InvalidInstrumentId,
            );
        }
        if !mark.is_positive() {
            return Self::kill_error(
                kill,
                observed_at,
                KillCode::InternalInvariant,
                AdverseError::InvalidPrice(mark),
            );
        }
        let plan = self.instrument_plan(instrument).inspect_err(|_| {
            kill.trigger(KillCode::InternalInvariant, observed_at);
        })?;
        let prior_state = plan.state;
        if let Some(prior) = prior_state.last_mark_timestamp
            && mark_timestamp < prior
        {
            return Self::kill_error(
                kill,
                observed_at,
                KillCode::ClockUnsafe,
                AdverseError::MarkTimestampRegression {
                    prior,
                    received: mark_timestamp,
                },
            );
        }
        let batch = self
            .plan_mark(
                instrument,
                mark,
                mark_timestamp,
                prior_state.consecutive_breaches,
            )
            .inspect_err(|error| {
                kill.trigger(Self::error_kill_code(*error), observed_at);
            })?;
        let consecutive = batch.consecutive_breaches;
        let rolling = batch.rolling_weighted_markout;
        let aggregate_halt = rolling <= -self.config.halt_aggregate_loss;
        let consecutive_halt = consecutive >= self.config.halt_after_consecutive;
        let instrument_halted = prior_state.halted || aggregate_halt || consecutive_halt;
        let halt_triggered = instrument_halted && !prior_state.halted;
        let aggregate_kill = rolling <= -self.config.kill_aggregate_loss;
        let consecutive_kill = consecutive >= self.config.kill_after_consecutive;
        let candidate_state = AdverseInstrument {
            consecutive_breaches: consecutive,
            halted: instrument_halted,
            last_mark: Some(mark.0),
            last_mark_timestamp: Some(mark_timestamp),
            ..prior_state
        };

        self.commit_mark_records(instrument, mark, mark_timestamp, batch.retained_fills);
        self.instruments[plan.index] = Some(candidate_state);
        self.instrument_count = plan.instrument_count;
        self.last_observed_timestamp = Some(observed_at);
        let global_kill_triggered = (aggregate_kill || consecutive_kill)
            && kill.trigger(KillCode::AdverseSelection, observed_at);
        Ok(AdverseMarkOutcome {
            evaluated_fills: batch.evaluated_fills,
            weighted_markout_delta: batch.weighted_markout_delta,
            rolling_weighted_markout: rolling,
            consecutive_breaches: consecutive,
            instrument_halted,
            halt_triggered,
            global_kill_triggered,
            work_units: batch.work_units,
        })
    }

    fn plan_mark(
        &self,
        instrument: InstrumentId,
        mark: PriceTicks,
        mark_timestamp: TimestampNs,
        mut consecutive: u32,
    ) -> Result<EvaluationBatch, AdverseError> {
        let mut evaluated_fills = 0_usize;
        let mut weighted_markout_delta = 0_i128;
        let mut rolling_weighted_markout = 0_i128;
        let mut retained_fills = 0_usize;
        let mut prior_ordinal = None;
        for index in 0..self.fill_count {
            let fill = self.fills[index].ok_or(AdverseError::InternalInvariant)?;
            if prior_ordinal.is_some_and(|ordinal| fill.ordinal <= ordinal) {
                return Err(AdverseError::InternalInvariant);
            }
            prior_ordinal = Some(fill.ordinal);
            let evaluated_markout = Self::validated_evaluated_markout(fill)?;
            let same_instrument = fill.instrument == instrument;
            if same_instrument && self.is_expired(fill, mark_timestamp) {
                continue;
            }
            retained_fills = retained_fills
                .checked_add(1)
                .ok_or(AdverseError::ArithmeticOverflow)?;
            if !same_instrument {
                continue;
            }
            if let Some(weighted) = evaluated_markout {
                rolling_weighted_markout = rolling_weighted_markout
                    .checked_add(weighted)
                    .ok_or(AdverseError::ArithmeticOverflow)?;
                continue;
            }
            if mark_timestamp.saturating_duration_since(fill.fill_timestamp)
                < self.config.markout_horizon_ns
            {
                continue;
            }
            let (signed_markout, weighted_markout) = Self::fill_markout(fill, mark)?;
            weighted_markout_delta = weighted_markout_delta
                .checked_add(weighted_markout)
                .ok_or(AdverseError::ArithmeticOverflow)?;
            rolling_weighted_markout = rolling_weighted_markout
                .checked_add(weighted_markout)
                .ok_or(AdverseError::ArithmeticOverflow)?;
            consecutive = if signed_markout <= -i128::from(self.config.breach_markout_ticks) {
                consecutive
                    .checked_add(1)
                    .ok_or(AdverseError::ArithmeticOverflow)?
            } else {
                0
            };
            evaluated_fills = evaluated_fills
                .checked_add(1)
                .ok_or(AdverseError::ArithmeticOverflow)?;
        }
        if self.fills[self.fill_count..].iter().any(Option::is_some) {
            return Err(AdverseError::InternalInvariant);
        }
        let work_units = self
            .fill_count
            .checked_mul(2)
            .ok_or(AdverseError::ArithmeticOverflow)?;
        Ok(EvaluationBatch {
            evaluated_fills,
            weighted_markout_delta,
            rolling_weighted_markout,
            consecutive_breaches: consecutive,
            retained_fills,
            work_units,
        })
    }

    fn fill_markout(fill: TrackedFill, mark: PriceTicks) -> Result<(i128, i128), AdverseError> {
        let signed = i128::from(mark.0)
            .checked_sub(i128::from(fill.fill_price))
            .and_then(|delta| delta.checked_mul(i128::from(fill.side.sign())))
            .ok_or(AdverseError::ArithmeticOverflow)?;
        let weighted = signed
            .checked_mul(i128::from(fill.quantity))
            .ok_or(AdverseError::ArithmeticOverflow)?;
        Ok((signed, weighted))
    }

    fn validated_evaluated_markout(fill: TrackedFill) -> Result<Option<i128>, AdverseError> {
        match (
            fill.evaluation_mark_timestamp,
            fill.signed_markout_ticks,
            fill.weighted_markout,
        ) {
            (None, None, None) => Ok(None),
            (Some(_), Some(_), Some(weighted)) => Ok(Some(weighted)),
            _ => Err(AdverseError::InternalInvariant),
        }
    }

    fn find_instrument(&self, instrument: InstrumentId) -> Option<usize> {
        self.instruments
            .iter()
            .position(|slot| slot.is_some_and(|state| state.instrument == instrument))
    }

    fn instrument_plan(&self, instrument: InstrumentId) -> Result<InstrumentPlan, AdverseError> {
        if let Some(index) = self.find_instrument(instrument) {
            let state = self.instruments[index].ok_or(AdverseError::InternalInvariant)?;
            return Ok(InstrumentPlan {
                index,
                state,
                instrument_count: self.instrument_count,
            });
        }
        if self.instrument_count == MAX_INSTRUMENTS {
            return Err(AdverseError::InstrumentCapacity {
                capacity: MAX_INSTRUMENTS,
            });
        }
        let slot = self
            .instruments
            .iter()
            .position(Option::is_none)
            .ok_or(AdverseError::InternalInvariant)?;
        let instrument_count = self
            .instrument_count
            .checked_add(1)
            .ok_or(AdverseError::ArithmeticOverflow)?;
        Ok(InstrumentPlan {
            index: slot,
            state: AdverseInstrument::new(instrument),
            instrument_count,
        })
    }

    fn is_expired(&self, fill: TrackedFill, now: TimestampNs) -> bool {
        let Some(evaluation_mark_timestamp) = fill.evaluation_mark_timestamp else {
            return false;
        };
        // Venue reports for independent orders/symbols may be delivered out of
        // timestamp order. Such a record is retained; per-instrument mark regressions
        // are rejected separately before evaluation.
        now.saturating_duration_since(evaluation_mark_timestamp) > self.config.rolling_window_ns
    }

    fn commit_mark_records(
        &mut self,
        instrument: InstrumentId,
        mark: PriceTicks,
        mark_timestamp: TimestampNs,
        retained_fills: usize,
    ) {
        let previous_count = self.fill_count;
        let mut write = 0_usize;
        for read in 0..previous_count {
            let mut fill = self.fills[read].expect("mark plan validated fill prefix");
            let expired = fill.instrument == instrument
                && fill
                    .evaluation_mark_timestamp
                    .is_some_and(|evaluation_mark_timestamp| {
                        mark_timestamp.saturating_duration_since(evaluation_mark_timestamp)
                            > self.config.rolling_window_ns
                    });
            if expired {
                continue;
            }
            let due = fill.instrument == instrument
                && fill.evaluation_mark_timestamp.is_none()
                && mark_timestamp.saturating_duration_since(fill.fill_timestamp)
                    >= self.config.markout_horizon_ns;
            if due {
                let (signed, weighted) =
                    Self::fill_markout(fill, mark).expect("mark plan validated markout arithmetic");
                fill.evaluation_mark_timestamp = Some(mark_timestamp);
                fill.signed_markout_ticks = Some(signed);
                fill.weighted_markout = Some(weighted);
            }
            self.fills[write] = Some(fill);
            write += 1;
        }
        for index in write..previous_count {
            self.fills[index] = None;
        }
        debug_assert_eq!(write, retained_fills);
        self.fill_count = retained_fills;
    }

    fn validate_observation(&self, observed_at: TimestampNs) -> Result<(), AdverseError> {
        if observed_at == TimestampNs::ZERO {
            return Err(AdverseError::ZeroEventTimestamp);
        }
        if let Some(prior) = self.last_observed_timestamp
            && observed_at < prior
        {
            return Err(AdverseError::ClockRegression {
                prior,
                received: observed_at,
            });
        }
        Ok(())
    }

    fn validate_observation_or_kill(
        &self,
        observed_at: TimestampNs,
        kill: &KillLatch,
    ) -> Result<(), AdverseError> {
        match self.validate_observation(observed_at) {
            Ok(()) => Ok(()),
            Err(error) => Self::kill_error(
                kill,
                self.observation_fault_timestamp(error, observed_at),
                KillCode::ClockUnsafe,
                error,
            ),
        }
    }

    const fn error_kill_code(error: AdverseError) -> KillCode {
        match error {
            AdverseError::ZeroFillTimestamp
            | AdverseError::ZeroMarkTimestamp
            | AdverseError::ZeroEventTimestamp
            | AdverseError::FutureFillTimestamp { .. }
            | AdverseError::FutureMarkTimestamp { .. }
            | AdverseError::LateFillBeyondMarkFrontier { .. }
            | AdverseError::ClockRegression { .. }
            | AdverseError::MarkTimestampRegression { .. } => KillCode::ClockUnsafe,
            AdverseError::InvalidConfig
            | AdverseError::InvalidInstrumentId
            | AdverseError::InvalidExecutionId
            | AdverseError::DuplicateExecution(_)
            | AdverseError::InvalidPrice(_)
            | AdverseError::InvalidQuantity(_)
            | AdverseError::InstrumentCapacity { .. }
            | AdverseError::FillCapacity { .. }
            | AdverseError::ArithmeticOverflow
            | AdverseError::InternalInvariant => KillCode::InternalInvariant,
        }
    }

    fn rolling_markout(&self, instrument: InstrumentId) -> Result<i128, AdverseError> {
        self.fills
            .iter()
            .flatten()
            .filter(|fill| fill.instrument == instrument)
            .filter_map(|fill| fill.weighted_markout)
            .try_fold(0_i128, |aggregate, markout| {
                aggregate
                    .checked_add(markout)
                    .ok_or(AdverseError::ArithmeticOverflow)
            })
    }

    fn kill_error<T>(
        kill: &KillLatch,
        now: TimestampNs,
        code: KillCode,
        error: AdverseError,
    ) -> Result<T, AdverseError> {
        kill.trigger(code, now);
        Err(error)
    }

    const fn observation_fault_timestamp(
        &self,
        error: AdverseError,
        attempted: TimestampNs,
    ) -> TimestampNs {
        match error {
            AdverseError::ClockRegression { prior, .. } => prior,
            AdverseError::ZeroEventTimestamp => {
                if let Some(prior) = self.last_observed_timestamp {
                    prior
                } else {
                    attempted
                }
            }
            AdverseError::InvalidConfig
            | AdverseError::InvalidInstrumentId
            | AdverseError::InvalidExecutionId
            | AdverseError::DuplicateExecution(_)
            | AdverseError::InvalidPrice(_)
            | AdverseError::InvalidQuantity(_)
            | AdverseError::ZeroFillTimestamp
            | AdverseError::ZeroMarkTimestamp
            | AdverseError::FutureFillTimestamp { .. }
            | AdverseError::FutureMarkTimestamp { .. }
            | AdverseError::LateFillBeyondMarkFrontier { .. }
            | AdverseError::InstrumentCapacity { .. }
            | AdverseError::FillCapacity { .. }
            | AdverseError::MarkTimestampRegression { .. }
            | AdverseError::ArithmeticOverflow
            | AdverseError::InternalInvariant => attempted,
        }
    }
}
