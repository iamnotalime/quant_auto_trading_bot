//! Fixed-capacity, fail-closed pre-trade and inventory risk.

use crate::kill::{KillCode, KillLatch};
pub use crate::types::CurrencyId;
use crate::types::{InstrumentId, OrderId, PriceTicks, Quantity, Side, TimestampNs};

/// Monotonic risk-accounting session key. Zero is invalid.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct RiskSessionId(pub u64);

/// Defines how integer price ticks and contract quantities map to base-currency
/// atomic units. Dynamic FX is explicit and unsupported in this fixed-rate core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstrumentValuation {
    Fixed {
        /// Base-currency atomic units for one price tick and one underlying unit.
        base_units_per_price_tick: i128,
        /// Underlying units represented by one risk quantity/contract.
        contract_multiplier: u64,
    },
    DynamicFxUnsupported,
}

/// Immutable economics and native-unit position cap for one instrument.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstrumentRiskDefinition {
    pub instrument: InstrumentId,
    pub base_currency: CurrencyId,
    pub valuation: InstrumentValuation,
    pub position_limit: Quantity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RiskAdjustmentKind {
    /// Positive magnitude paid by the portfolio; converted to a negative P&L delta.
    Fee,
    /// Positive magnitude received by the portfolio.
    Rebate,
    /// Signed portfolio funding: positive receipt, negative payment.
    Funding,
}

/// Fee, rebate, or funding amount already normalized to base-currency atomic units.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RiskAdjustment {
    pub currency: CurrencyId,
    pub kind: RiskAdjustmentKind,
    pub amount_base_units: i128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdjustmentOutcome {
    pub applied_delta_base_units: i128,
    pub lifetime_adjustments_base_units: i128,
    pub session_pnl_base_units: i128,
    pub loss_limit_breached: bool,
    pub kill_triggered: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionRollOutcome {
    pub previous_session: RiskSessionId,
    pub current_session: RiskSessionId,
    pub lifetime_pnl_baseline_base_units: i128,
}

/// Monetary limits are base-currency atomic units. Quantities remain native
/// contracts/units and are additionally bounded by each instrument definition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RiskLimits {
    pub max_order_quantity: Quantity,
    pub max_order_notional: i128,
    pub max_gross_notional: i128,
    pub max_net_notional: i128,
    pub max_daily_loss: i128,
    pub max_market_age_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreTradeRequest {
    pub order_id: OrderId,
    pub instrument: InstrumentId,
    pub side: Side,
    pub price: PriceTicks,
    pub quantity: Quantity,
    pub now: TimestampNs,
    pub clock_healthy: bool,
    /// Set from the adverse-selection monitor before entering this gate.
    pub instrument_halted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RiskApproval {
    pub projected_position_quantity: Quantity,
    pub projected_gross_notional: i128,
    pub projected_net_notional: i128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstrumentRiskSnapshot {
    pub instrument: InstrumentId,
    pub definition: InstrumentRiskDefinition,
    pub position: Quantity,
    /// Lifetime signed inventory cost in base-currency atomic units.
    pub signed_position_cost: i128,
    pub open_buy_quantity: Quantity,
    pub open_sell_quantity: Quantity,
    /// Reserved buy notional in base-currency atomic units.
    pub open_buy_notional: i128,
    /// Reserved sell notional in base-currency atomic units.
    pub open_sell_notional: i128,
    pub mark: Option<PriceTicks>,
    pub last_market_timestamp: Option<TimestampNs>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderRiskSnapshot {
    pub order_id: OrderId,
    pub instrument: InstrumentId,
    pub side: Side,
    pub limit_price: PriceTicks,
    /// Per-unit price used by the current open-exposure reservation. This is the
    /// greater of the order limit and the instrument's latest accepted mark.
    pub reservation_price: PriceTicks,
    pub remaining_quantity: Quantity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExposureSnapshot {
    /// Conservative gross exposure in base-currency atomic units.
    pub gross_notional: i128,
    /// Worst portfolio long/short scenario in base-currency atomic units.
    pub net_notional: i128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MarkOutcome {
    pub daily_pnl: i128,
    pub exposure: ExposureSnapshot,
    pub risk_limit_breached: bool,
    pub loss_limit_breached: bool,
    /// True only when this event won the global first-fault race.
    pub kill_triggered: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FillOutcome {
    pub position: Quantity,
    pub remaining_order_quantity: Quantity,
    pub realized_pnl_delta: i128,
    pub daily_pnl: i128,
    pub risk_limit_breached: bool,
    pub loss_limit_breached: bool,
    /// True only when this event won the global first-fault race.
    pub kill_triggered: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancelOutcome {
    pub canceled_quantity: Quantity,
    pub remaining_order_quantity: Quantity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RiskError {
    InvalidLimits,
    InvalidSessionId,
    NonMonotonicSession {
        current: RiskSessionId,
        requested: RiskSessionId,
    },
    InvalidCurrencyId,
    InvalidInstrumentDefinition,
    DuplicateInstrumentDefinition(InstrumentId),
    UnsupportedDynamicFx(InstrumentId),
    CurrencyMismatch {
        expected: CurrencyId,
        received: CurrencyId,
    },
    NoBaseCurrency,
    GlobalKill,
    ClockUnsafe,
    FutureMarketTimestamp {
        market: TimestampNs,
        now: TimestampNs,
    },
    MarketTimestampRegression {
        prior: TimestampNs,
        received: TimestampNs,
    },
    StaleMarket {
        age_ns: u64,
        max_age_ns: u64,
    },
    MissingValuationMark(InstrumentId),
    FutureValuationMark {
        instrument: InstrumentId,
        market: TimestampNs,
        now: TimestampNs,
    },
    StaleValuationMark {
        instrument: InstrumentId,
        age_ns: u64,
        max_age_ns: u64,
    },
    InstrumentHalted(InstrumentId),
    InvalidInstrumentId,
    UnknownInstrument(InstrumentId),
    InstrumentCapacity {
        capacity: usize,
    },
    OrderCapacity {
        capacity: usize,
    },
    InvalidOrderId,
    DuplicateOrder(OrderId),
    UnknownOrder(OrderId),
    InvalidPrice(PriceTicks),
    InvalidQuantity(Quantity),
    FillExceedsRemaining {
        requested: Quantity,
        remaining: Quantity,
    },
    CancelExceedsRemaining {
        requested: Quantity,
        remaining: Quantity,
    },
    OrderQuantityLimit {
        requested: Quantity,
        limit: Quantity,
    },
    PositionLimit {
        projected: Quantity,
        limit: Quantity,
    },
    OrderNotionalLimit {
        requested: i128,
        limit: i128,
    },
    GrossNotionalLimit {
        projected: i128,
        limit: i128,
    },
    NetNotionalLimit {
        projected: i128,
        limit: i128,
    },
    DailyLossLimit {
        pnl: i128,
        limit: i128,
    },
    InvalidAdjustment,
    ArithmeticOverflow,
    InternalInvariant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InstrumentRisk {
    definition: InstrumentRiskDefinition,
    base_units_per_tick_contract: i128,
    position: i64,
    signed_position_cost: i128,
    open_buy_quantity: i64,
    open_sell_quantity: i64,
    open_buy_notional: i128,
    open_sell_notional: i128,
    mark: Option<i64>,
    last_market_timestamp: Option<TimestampNs>,
}

impl InstrumentRisk {
    const fn new(definition: InstrumentRiskDefinition, base_units_per_tick_contract: i128) -> Self {
        Self {
            definition,
            base_units_per_tick_contract,
            position: 0,
            signed_position_cost: 0,
            open_buy_quantity: 0,
            open_sell_quantity: 0,
            open_buy_notional: 0,
            open_sell_notional: 0,
            mark: None,
            last_market_timestamp: None,
        }
    }

    fn snapshot(self) -> InstrumentRiskSnapshot {
        InstrumentRiskSnapshot {
            instrument: self.definition.instrument,
            definition: self.definition,
            position: Quantity(self.position),
            signed_position_cost: self.signed_position_cost,
            open_buy_quantity: Quantity(self.open_buy_quantity),
            open_sell_quantity: Quantity(self.open_sell_quantity),
            open_buy_notional: self.open_buy_notional,
            open_sell_notional: self.open_sell_notional,
            mark: self.mark.map(PriceTicks),
            last_market_timestamp: self.last_market_timestamp,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OrderRisk {
    order_id: OrderId,
    instrument: InstrumentId,
    side: Side,
    limit_price: i64,
    reservation_price: i64,
    remaining_quantity: i64,
}

impl OrderRisk {
    const fn snapshot(self) -> OrderRiskSnapshot {
        OrderRiskSnapshot {
            order_id: self.order_id,
            instrument: self.instrument,
            side: self.side,
            limit_price: PriceTicks(self.limit_price),
            reservation_price: PriceTicks(self.reservation_price),
            remaining_quantity: Quantity(self.remaining_quantity),
        }
    }
}

/// Single-writer hot-path state. All arrays are allocated in the object itself.
#[derive(Debug, Eq, PartialEq)]
pub struct RiskEngine<const MAX_INSTRUMENTS: usize, const MAX_ORDERS: usize> {
    limits: RiskLimits,
    instruments: [Option<InstrumentRisk>; MAX_INSTRUMENTS],
    orders: [Option<OrderRisk>; MAX_ORDERS],
    instrument_count: usize,
    order_count: usize,
    base_currency: Option<CurrencyId>,
    session_id: RiskSessionId,
    session_baseline_pnl: i128,
    lifetime_realized_pnl: i128,
    lifetime_adjustments: i128,
}

impl<const MAX_INSTRUMENTS: usize, const MAX_ORDERS: usize>
    RiskEngine<MAX_INSTRUMENTS, MAX_ORDERS>
{
    /// Construct empty, fixed-capacity risk state.
    ///
    /// # Errors
    ///
    /// Returns [`RiskError::InvalidLimits`] if any limit or compile-time capacity
    /// is zero, negative, or otherwise unsafe, and [`RiskError::InvalidSessionId`]
    /// when the initial session is zero.
    pub fn new(limits: RiskLimits, initial_session: RiskSessionId) -> Result<Self, RiskError> {
        if !limits.max_order_quantity.is_positive()
            || limits.max_order_notional <= 0
            || limits.max_gross_notional <= 0
            || limits.max_net_notional <= 0
            || limits.max_daily_loss <= 0
            || limits.max_market_age_ns == 0
            || MAX_INSTRUMENTS == 0
            || MAX_ORDERS == 0
        {
            return Err(RiskError::InvalidLimits);
        }
        if initial_session.0 == 0 {
            return Err(RiskError::InvalidSessionId);
        }
        Ok(Self {
            limits,
            instruments: [None; MAX_INSTRUMENTS],
            orders: [None; MAX_ORDERS],
            instrument_count: 0,
            order_count: 0,
            base_currency: None,
            session_id: initial_session,
            session_baseline_pnl: 0,
            lifetime_realized_pnl: 0,
            lifetime_adjustments: 0,
        })
    }

    #[must_use]
    pub const fn limits(&self) -> RiskLimits {
        self.limits
    }

    #[must_use]
    pub const fn instrument_count(&self) -> usize {
        self.instrument_count
    }

    #[must_use]
    pub const fn order_count(&self) -> usize {
        self.order_count
    }

    #[must_use]
    pub const fn base_currency(&self) -> Option<CurrencyId> {
        self.base_currency
    }

    #[must_use]
    pub const fn session_id(&self) -> RiskSessionId {
        self.session_id
    }

    #[must_use]
    pub const fn session_baseline_pnl(&self) -> i128 {
        self.session_baseline_pnl
    }

    #[must_use]
    pub const fn lifetime_realized_pnl(&self) -> i128 {
        self.lifetime_realized_pnl
    }

    #[must_use]
    pub const fn lifetime_adjustments(&self) -> i128 {
        self.lifetime_adjustments
    }

    /// Register immutable base-currency economics before accepting a mark.
    ///
    /// # Errors
    ///
    /// Rejects invalid identifiers/values, dynamic-FX products, duplicate or full
    /// tables, arithmetic overflow, and a currency different from prior definitions.
    pub fn register_instrument(
        &mut self,
        definition: InstrumentRiskDefinition,
    ) -> Result<(), RiskError> {
        if definition.instrument.0 == 0 {
            return Err(RiskError::InvalidInstrumentId);
        }
        if definition.base_currency.0 == 0 {
            return Err(RiskError::InvalidCurrencyId);
        }
        if !definition.position_limit.is_positive() {
            return Err(RiskError::InvalidInstrumentDefinition);
        }
        let scale = match definition.valuation {
            InstrumentValuation::Fixed {
                base_units_per_price_tick,
                contract_multiplier,
            } => {
                if base_units_per_price_tick <= 0 || contract_multiplier == 0 {
                    return Err(RiskError::InvalidInstrumentDefinition);
                }
                base_units_per_price_tick
                    .checked_mul(i128::from(contract_multiplier))
                    .ok_or(RiskError::ArithmeticOverflow)?
            }
            InstrumentValuation::DynamicFxUnsupported => {
                return Err(RiskError::UnsupportedDynamicFx(definition.instrument));
            }
        };
        if self.find_instrument(definition.instrument).is_some() {
            return Err(RiskError::DuplicateInstrumentDefinition(
                definition.instrument,
            ));
        }
        if self.instrument_count == MAX_INSTRUMENTS {
            return Err(RiskError::InstrumentCapacity {
                capacity: MAX_INSTRUMENTS,
            });
        }
        if let Some(expected) = self.base_currency
            && definition.base_currency != expected
        {
            return Err(RiskError::CurrencyMismatch {
                expected,
                received: definition.base_currency,
            });
        }
        let slot = self
            .instruments
            .iter()
            .position(Option::is_none)
            .ok_or(RiskError::InternalInvariant)?;
        let count = self
            .instrument_count
            .checked_add(1)
            .ok_or(RiskError::ArithmeticOverflow)?;
        self.instruments[slot] = Some(InstrumentRisk::new(definition, scale));
        self.instrument_count = count;
        self.base_currency = Some(definition.base_currency);
        Ok(())
    }

    #[must_use]
    pub fn definition(&self, instrument: InstrumentId) -> Option<InstrumentRiskDefinition> {
        self.find_instrument(instrument)
            .and_then(|index| self.instruments[index])
            .map(|state| state.definition)
    }

    #[must_use]
    pub fn instrument(&self, instrument: InstrumentId) -> Option<InstrumentRiskSnapshot> {
        self.find_instrument(instrument)
            .and_then(|index| self.instruments[index])
            .map(InstrumentRisk::snapshot)
    }

    #[must_use]
    pub fn order(&self, order_id: OrderId) -> Option<OrderRiskSnapshot> {
        self.find_order(order_id)
            .and_then(|index| self.orders[index])
            .map(OrderRisk::snapshot)
    }

    /// Update the valuation mark and enforce post-market risk. A delayed or
    /// regressing mark is rejected before it can alter state.
    ///
    /// # Errors
    ///
    /// Rejects unsafe clock state, invalid/stale/regressing market data, exhausted
    /// fixed capacity, arithmetic overflow, or an internal invariant failure.
    // Candidate aggregates are fully checked before the single state commit.
    #[allow(clippy::too_many_lines)]
    pub fn on_mark(
        &mut self,
        instrument: InstrumentId,
        mark: PriceTicks,
        market_timestamp: TimestampNs,
        now: TimestampNs,
        clock_healthy: bool,
        kill: &KillLatch,
    ) -> Result<MarkOutcome, RiskError> {
        if !clock_healthy {
            return Self::kill_error(kill, KillCode::ClockUnsafe, now, RiskError::ClockUnsafe);
        }
        if instrument.0 == 0 {
            return Self::kill_error(
                kill,
                KillCode::InternalInvariant,
                now,
                RiskError::InvalidInstrumentId,
            );
        }
        if !mark.is_positive() {
            return Self::kill_error(
                kill,
                KillCode::InternalInvariant,
                now,
                RiskError::InvalidPrice(mark),
            );
        }
        if market_timestamp > now {
            return Self::kill_error(
                kill,
                KillCode::ClockUnsafe,
                now,
                RiskError::FutureMarketTimestamp {
                    market: market_timestamp,
                    now,
                },
            );
        }
        let age_ns = now.saturating_duration_since(market_timestamp);
        if age_ns > self.limits.max_market_age_ns {
            return Self::kill_error(
                kill,
                KillCode::MarketDataGap,
                now,
                RiskError::StaleMarket {
                    age_ns,
                    max_age_ns: self.limits.max_market_age_ns,
                },
            );
        }

        let index = self.find_instrument(instrument).ok_or_else(|| {
            kill.trigger(KillCode::MarketDataGap, now);
            RiskError::UnknownInstrument(instrument)
        })?;
        let prior_state = self.instruments[index].ok_or(RiskError::InternalInvariant)?;
        if let Some(prior) = prior_state.last_market_timestamp
            && market_timestamp < prior
        {
            return Self::kill_error(
                kill,
                KillCode::MarketDataGap,
                now,
                RiskError::MarketTimestampRegression {
                    prior,
                    received: market_timestamp,
                },
            );
        }
        let revaluation = self
            .revalue_open_reservations(prior_state, mark.0)
            .inspect_err(|_| {
                kill.trigger(KillCode::InternalInvariant, now);
            })?;
        let mut candidate = revaluation.state;
        candidate.mark = Some(mark.0);
        candidate.last_market_timestamp = Some(market_timestamp);
        let daily_pnl = self
            .session_pnl_with_state(
                Some((index, candidate)),
                self.lifetime_realized_pnl,
                self.lifetime_adjustments,
                self.session_baseline_pnl,
            )
            .inspect_err(|_| {
                kill.trigger(KillCode::InternalInvariant, now);
            })?;
        let exposure = self
            .exposure_with_state(index, candidate)
            .inspect_err(|_| {
                kill.trigger(KillCode::InternalInvariant, now);
            })?;
        let risk_limit_breached = revaluation.max_order_notional_breached
            || exposure.gross_notional > self.limits.max_gross_notional
            || exposure.net_notional > self.limits.max_net_notional;
        let loss_limit_breached = daily_pnl <= -self.limits.max_daily_loss;
        // Every arithmetic/projection check above completed against the candidate.
        // Repricing the fixed order table cannot fail and is committed with the
        // instrument aggregates as one single-writer state transition.
        for order in self.orders.iter_mut().flatten() {
            if order.instrument == instrument {
                order.reservation_price = order.limit_price.max(mark.0);
            }
        }
        self.instruments[index] = Some(candidate);
        let kill_triggered = if loss_limit_breached {
            kill.trigger(KillCode::LossLimit, now)
        } else if risk_limit_breached {
            kill.trigger(KillCode::RiskLimit, now)
        } else {
            false
        };
        Ok(MarkOutcome {
            daily_pnl,
            exposure,
            risk_limit_breached,
            loss_limit_breached,
            kill_triggered,
        })
    }

    /// Atomically validates and reserves an order. No exposure is mutated on rejection.
    ///
    /// # Errors
    ///
    /// Rejects any active global or local halt, unsafe/stale inputs, duplicate or
    /// malformed orders, capacity exhaustion, arithmetic overflow, and every
    /// configured pre-trade or loss-limit breach.
    // The sole mutation block intentionally follows every validation/projection so
    // a rejected order cannot leave a partial reservation.
    #[allow(clippy::too_many_lines)]
    pub fn authorize_order(
        &mut self,
        request: PreTradeRequest,
        kill: &KillLatch,
    ) -> Result<RiskApproval, RiskError> {
        if kill.is_triggered() {
            return Err(RiskError::GlobalKill);
        }
        if !request.clock_healthy {
            return Self::kill_error(
                kill,
                KillCode::ClockUnsafe,
                request.now,
                RiskError::ClockUnsafe,
            );
        }
        if request.instrument_halted {
            return Err(RiskError::InstrumentHalted(request.instrument));
        }
        if request.instrument.0 == 0 {
            return Self::kill_error(
                kill,
                KillCode::InternalInvariant,
                request.now,
                RiskError::InvalidInstrumentId,
            );
        }
        if request.order_id.0 == 0 {
            return Self::kill_error(
                kill,
                KillCode::RiskLimit,
                request.now,
                RiskError::InvalidOrderId,
            );
        }
        if !request.price.is_positive() {
            return Self::kill_error(
                kill,
                KillCode::RiskLimit,
                request.now,
                RiskError::InvalidPrice(request.price),
            );
        }
        if !request.quantity.is_positive() {
            return Self::kill_error(
                kill,
                KillCode::RiskLimit,
                request.now,
                RiskError::InvalidQuantity(request.quantity),
            );
        }
        if self.find_order(request.order_id).is_some() {
            return Self::kill_error(
                kill,
                KillCode::InternalInvariant,
                request.now,
                RiskError::DuplicateOrder(request.order_id),
            );
        }
        let instrument_index = self.find_instrument(request.instrument).ok_or_else(|| {
            kill.trigger(KillCode::MarketDataGap, request.now);
            RiskError::UnknownInstrument(request.instrument)
        })?;
        let state = self.instruments[instrument_index].ok_or(RiskError::InternalInvariant)?;
        self.validate_active_marks(request.now, Some(instrument_index))
            .inspect_err(|error| {
                kill.trigger(Self::error_kill_code(*error), request.now);
            })?;
        let state = self
            .revalue_open_reservations(
                state,
                state
                    .mark
                    .ok_or(RiskError::MissingValuationMark(request.instrument))?,
            )
            .inspect_err(|_| {
                kill.trigger(KillCode::InternalInvariant, request.now);
            })?
            .state;
        if request.quantity.0 > self.limits.max_order_quantity.0 {
            return Self::kill_error(
                kill,
                KillCode::RiskLimit,
                request.now,
                RiskError::OrderQuantityLimit {
                    requested: request.quantity,
                    limit: self.limits.max_order_quantity,
                },
            );
        }
        if self.order_count == MAX_ORDERS {
            return Self::kill_error(
                kill,
                KillCode::InternalInvariant,
                request.now,
                RiskError::OrderCapacity {
                    capacity: MAX_ORDERS,
                },
            );
        }
        let mark = state
            .mark
            .ok_or(RiskError::MissingValuationMark(request.instrument))?;
        let reservation_price = request.price.0.max(mark);
        let reservation_notional = Self::notional(
            reservation_price,
            request.quantity.0,
            state.base_units_per_tick_contract,
        )
        .ok_or_else(|| {
            kill.trigger(KillCode::InternalInvariant, request.now);
            RiskError::ArithmeticOverflow
        })?;
        if reservation_notional > self.limits.max_order_notional {
            return Self::kill_error(
                kill,
                KillCode::RiskLimit,
                request.now,
                RiskError::OrderNotionalLimit {
                    requested: reservation_notional,
                    limit: self.limits.max_order_notional,
                },
            );
        }
        let daily_pnl = self.session_pnl_checked().inspect_err(|_| {
            kill.trigger(KillCode::InternalInvariant, request.now);
        })?;
        if daily_pnl <= -self.limits.max_daily_loss {
            return Self::kill_error(
                kill,
                KillCode::LossLimit,
                request.now,
                RiskError::DailyLossLimit {
                    pnl: daily_pnl,
                    limit: self.limits.max_daily_loss,
                },
            );
        }

        let (buy_quantity, sell_quantity, buy_notional, sell_notional) = Self::project_open(
            state,
            request.side,
            request.quantity.0,
            reservation_notional,
        )
        .ok_or_else(|| {
            kill.trigger(KillCode::InternalInvariant, request.now);
            RiskError::ArithmeticOverflow
        })?;
        let long_position = i128::from(state.position)
            .checked_add(i128::from(buy_quantity))
            .ok_or_else(|| {
                kill.trigger(KillCode::InternalInvariant, request.now);
                RiskError::ArithmeticOverflow
            })?;
        let short_position = i128::from(state.position)
            .checked_sub(i128::from(sell_quantity))
            .ok_or_else(|| {
                kill.trigger(KillCode::InternalInvariant, request.now);
                RiskError::ArithmeticOverflow
            })?;
        let projected_position =
            if Self::abs_i128(long_position)? >= Self::abs_i128(short_position)? {
                long_position
            } else {
                short_position
            };
        let projected_quantity = i64::try_from(projected_position)
            .map_err(|_| RiskError::ArithmeticOverflow)
            .inspect_err(|_| {
                kill.trigger(KillCode::InternalInvariant, request.now);
            })?;
        if Self::abs_i128(projected_position)? > i128::from(state.definition.position_limit.0) {
            return Self::kill_error(
                kill,
                KillCode::RiskLimit,
                request.now,
                RiskError::PositionLimit {
                    projected: Quantity(projected_quantity),
                    limit: state.definition.position_limit,
                },
            );
        }

        let exposure = self
            .projected_exposure_checked(instrument_index, buy_notional, sell_notional)
            .inspect_err(|_| {
                kill.trigger(KillCode::InternalInvariant, request.now);
            })?;
        if exposure.gross_notional > self.limits.max_gross_notional {
            return Self::kill_error(
                kill,
                KillCode::RiskLimit,
                request.now,
                RiskError::GrossNotionalLimit {
                    projected: exposure.gross_notional,
                    limit: self.limits.max_gross_notional,
                },
            );
        }
        if exposure.net_notional > self.limits.max_net_notional {
            return Self::kill_error(
                kill,
                KillCode::RiskLimit,
                request.now,
                RiskError::NetNotionalLimit {
                    projected: exposure.net_notional,
                    limit: self.limits.max_net_notional,
                },
            );
        }

        let order_slot = self
            .orders
            .iter()
            .position(Option::is_none)
            .ok_or(RiskError::InternalInvariant)?;
        self.orders[order_slot] = Some(OrderRisk {
            order_id: request.order_id,
            instrument: request.instrument,
            side: request.side,
            limit_price: request.price.0,
            reservation_price,
            remaining_quantity: request.quantity.0,
        });
        self.order_count += 1;
        let state = self.instruments[instrument_index]
            .as_mut()
            .ok_or(RiskError::InternalInvariant)?;
        state.open_buy_quantity = buy_quantity;
        state.open_sell_quantity = sell_quantity;
        state.open_buy_notional = buy_notional;
        state.open_sell_notional = sell_notional;
        Ok(RiskApproval {
            projected_position_quantity: Quantity(projected_quantity),
            projected_gross_notional: exposure.gross_notional,
            projected_net_notional: exposure.net_notional,
        })
    }

    /// Apply an execution even while killed; fills are facts and inventory must converge.
    ///
    /// # Errors
    ///
    /// Rejects an unknown order, invalid or excessive fill, arithmetic overflow,
    /// or an internal reservation/inventory inconsistency. Such faults latch `kill`.
    // The candidate inventory, P&L, exposure, and order count are checked before
    // the single commit so a returned error cannot expose partial state.
    #[allow(clippy::too_many_lines)]
    pub fn on_fill(
        &mut self,
        order_id: OrderId,
        fill_price: PriceTicks,
        fill_quantity: Quantity,
        now: TimestampNs,
        kill: &KillLatch,
    ) -> Result<FillOutcome, RiskError> {
        if !fill_price.is_positive() {
            return Self::kill_error(
                kill,
                KillCode::InternalInvariant,
                now,
                RiskError::InvalidPrice(fill_price),
            );
        }
        if !fill_quantity.is_positive() {
            return Self::kill_error(
                kill,
                KillCode::InternalInvariant,
                now,
                RiskError::InvalidQuantity(fill_quantity),
            );
        }
        let order_index = self.find_order(order_id).ok_or_else(|| {
            kill.trigger(KillCode::InternalInvariant, now);
            RiskError::UnknownOrder(order_id)
        })?;
        let order = self.orders[order_index].ok_or(RiskError::InternalInvariant)?;
        if fill_quantity.0 > order.remaining_quantity {
            return Self::kill_error(
                kill,
                KillCode::InternalInvariant,
                now,
                RiskError::FillExceedsRemaining {
                    requested: fill_quantity,
                    remaining: Quantity(order.remaining_quantity),
                },
            );
        }
        let instrument_index = self
            .find_instrument(order.instrument)
            .ok_or(RiskError::InternalInvariant)?;
        let state = self.instruments[instrument_index].ok_or(RiskError::InternalInvariant)?;
        let state = self
            .revalue_open_reservations(
                state,
                state
                    .mark
                    .ok_or(RiskError::MissingValuationMark(order.instrument))?,
            )
            .inspect_err(|_| {
                kill.trigger(KillCode::InternalInvariant, now);
            })?
            .state;
        let computation = Self::compute_fill(state, order.side, fill_price.0, fill_quantity.0)
            .ok_or_else(|| {
                kill.trigger(KillCode::InternalInvariant, now);
                RiskError::ArithmeticOverflow
            })?;
        let new_realized = self
            .lifetime_realized_pnl
            .checked_add(computation.realized_delta)
            .ok_or_else(|| {
                kill.trigger(KillCode::InternalInvariant, now);
                RiskError::ArithmeticOverflow
            })?;
        let released_notional = Self::notional(
            order.reservation_price,
            fill_quantity.0,
            state.base_units_per_tick_contract,
        )
        .ok_or_else(|| {
            kill.trigger(KillCode::InternalInvariant, now);
            RiskError::ArithmeticOverflow
        })?;
        let new_remaining = order.remaining_quantity - fill_quantity.0;
        let mut candidate_state =
            Self::release_open(state, order.side, fill_quantity.0, released_notional).ok_or_else(
                || {
                    kill.trigger(KillCode::InternalInvariant, now);
                    RiskError::InternalInvariant
                },
            )?;
        candidate_state.position = computation.position;
        candidate_state.signed_position_cost = computation.signed_cost;
        let candidate_order_count = if new_remaining == 0 {
            self.order_count.checked_sub(1).ok_or_else(|| {
                kill.trigger(KillCode::InternalInvariant, now);
                RiskError::InternalInvariant
            })?
        } else {
            self.order_count
        };
        let daily_pnl = self
            .session_pnl_with_state(
                Some((instrument_index, candidate_state)),
                new_realized,
                self.lifetime_adjustments,
                self.session_baseline_pnl,
            )
            .inspect_err(|_| {
                kill.trigger(KillCode::InternalInvariant, now);
            })?;
        let exposure = self
            .exposure_with_state(instrument_index, candidate_state)
            .inspect_err(|_| {
                kill.trigger(KillCode::InternalInvariant, now);
            })?;
        let risk_limit_breached = computation.position.unsigned_abs()
            > state.definition.position_limit.unsigned_abs()
            || exposure.gross_notional > self.limits.max_gross_notional
            || exposure.net_notional > self.limits.max_net_notional;
        let loss_limit_breached = daily_pnl <= -self.limits.max_daily_loss;

        self.instruments[instrument_index] = Some(candidate_state);
        self.lifetime_realized_pnl = new_realized;
        self.order_count = candidate_order_count;
        self.orders[order_index] = if new_remaining == 0 {
            None
        } else {
            Some(OrderRisk {
                remaining_quantity: new_remaining,
                ..order
            })
        };
        let kill_triggered = if loss_limit_breached {
            kill.trigger(KillCode::LossLimit, now)
        } else if risk_limit_breached {
            kill.trigger(KillCode::RiskLimit, now)
        } else {
            false
        };
        Ok(FillOutcome {
            position: Quantity(computation.position),
            remaining_order_quantity: Quantity(new_remaining),
            realized_pnl_delta: computation.realized_delta,
            daily_pnl,
            risk_limit_breached,
            loss_limit_breached,
            kill_triggered,
        })
    }

    /// Release a venue-confirmed cancel. Partial cancel confirmations are supported.
    ///
    /// # Errors
    ///
    /// Rejects an unknown order, invalid or excessive canceled quantity, arithmetic
    /// overflow, or an inconsistent reservation. Fatal faults latch `kill`.
    pub fn on_cancel(
        &mut self,
        order_id: OrderId,
        canceled_quantity: Quantity,
        now: TimestampNs,
        kill: &KillLatch,
    ) -> Result<CancelOutcome, RiskError> {
        if !canceled_quantity.is_positive() {
            return Self::kill_error(
                kill,
                KillCode::InternalInvariant,
                now,
                RiskError::InvalidQuantity(canceled_quantity),
            );
        }
        let order_index = self.find_order(order_id).ok_or_else(|| {
            kill.trigger(KillCode::InternalInvariant, now);
            RiskError::UnknownOrder(order_id)
        })?;
        let order = self.orders[order_index].ok_or(RiskError::InternalInvariant)?;
        if canceled_quantity.0 > order.remaining_quantity {
            return Self::kill_error(
                kill,
                KillCode::InternalInvariant,
                now,
                RiskError::CancelExceedsRemaining {
                    requested: canceled_quantity,
                    remaining: Quantity(order.remaining_quantity),
                },
            );
        }
        let instrument_index = self
            .find_instrument(order.instrument)
            .ok_or(RiskError::InternalInvariant)?;
        let state = self.instruments[instrument_index].ok_or(RiskError::InternalInvariant)?;
        let state = self
            .revalue_open_reservations(
                state,
                state
                    .mark
                    .ok_or(RiskError::MissingValuationMark(order.instrument))?,
            )
            .inspect_err(|_| {
                kill.trigger(KillCode::InternalInvariant, now);
            })?
            .state;
        let released_notional = Self::notional(
            order.reservation_price,
            canceled_quantity.0,
            state.base_units_per_tick_contract,
        )
        .ok_or_else(|| {
            kill.trigger(KillCode::InternalInvariant, now);
            RiskError::ArithmeticOverflow
        })?;
        let candidate_state =
            Self::release_open(state, order.side, canceled_quantity.0, released_notional)
                .ok_or_else(|| {
                    kill.trigger(KillCode::InternalInvariant, now);
                    RiskError::InternalInvariant
                })?;
        let remaining = order.remaining_quantity - canceled_quantity.0;
        let candidate_order_count = if remaining == 0 {
            self.order_count.checked_sub(1).ok_or_else(|| {
                kill.trigger(KillCode::InternalInvariant, now);
                RiskError::InternalInvariant
            })?
        } else {
            self.order_count
        };
        let candidate_order = (remaining != 0).then_some(OrderRisk {
            remaining_quantity: remaining,
            ..order
        });

        self.instruments[instrument_index] = Some(candidate_state);
        self.orders[order_index] = candidate_order;
        self.order_count = candidate_order_count;
        Ok(CancelOutcome {
            canceled_quantity,
            remaining_order_quantity: Quantity(remaining),
        })
    }

    /// Roll to a strictly newer accounting session and baseline current lifetime
    /// marked P&L. Inventory quantities and lifetime inventory cost are unchanged.
    ///
    /// # Errors
    ///
    /// Rejects zero/nonmonotonic session identifiers, unsafe clock state, missing,
    /// future, or stale marks on active instruments, and arithmetic overflow.
    pub fn roll_session(
        &mut self,
        next_session: RiskSessionId,
        now: TimestampNs,
        clock_healthy: bool,
        kill: &KillLatch,
    ) -> Result<SessionRollOutcome, RiskError> {
        if !clock_healthy {
            return Self::kill_error(kill, KillCode::ClockUnsafe, now, RiskError::ClockUnsafe);
        }
        if next_session.0 == 0 {
            return Self::kill_error(
                kill,
                KillCode::InternalInvariant,
                now,
                RiskError::InvalidSessionId,
            );
        }
        if next_session <= self.session_id {
            return Self::kill_error(
                kill,
                KillCode::InternalInvariant,
                now,
                RiskError::NonMonotonicSession {
                    current: self.session_id,
                    requested: next_session,
                },
            );
        }
        self.validate_active_marks(now, None).inspect_err(|error| {
            kill.trigger(Self::error_kill_code(*error), now);
        })?;
        let baseline = self
            .lifetime_pnl_with_state(None, self.lifetime_realized_pnl, self.lifetime_adjustments)
            .inspect_err(|_| {
                kill.trigger(KillCode::InternalInvariant, now);
            })?;
        let previous_session = self.session_id;
        self.session_id = next_session;
        self.session_baseline_pnl = baseline;
        Ok(SessionRollOutcome {
            previous_session,
            current_session: next_session,
            lifetime_pnl_baseline_base_units: baseline,
        })
    }

    /// Apply a fee, rebate, or funding fact already normalized to this engine's
    /// base-currency atomic units. Accounting facts remain applicable after a kill.
    ///
    /// # Errors
    ///
    /// Rejects invalid amount signs, missing/mismatched base currency, an unsafe
    /// clock, and arithmetic overflow. A valid accounting fact is accepted even
    /// after a kill; a loss-causing fact is committed before latching the loss kill.
    pub fn apply_adjustment(
        &mut self,
        adjustment: RiskAdjustment,
        now: TimestampNs,
        clock_healthy: bool,
        kill: &KillLatch,
    ) -> Result<AdjustmentOutcome, RiskError> {
        if !clock_healthy {
            return Self::kill_error(kill, KillCode::ClockUnsafe, now, RiskError::ClockUnsafe);
        }
        let expected = self.base_currency.ok_or(RiskError::NoBaseCurrency)?;
        if adjustment.currency.0 == 0 {
            return Self::kill_error(
                kill,
                KillCode::InternalInvariant,
                now,
                RiskError::InvalidCurrencyId,
            );
        }
        if adjustment.currency != expected {
            return Self::kill_error(
                kill,
                KillCode::InternalInvariant,
                now,
                RiskError::CurrencyMismatch {
                    expected,
                    received: adjustment.currency,
                },
            );
        }
        let delta = match adjustment.kind {
            RiskAdjustmentKind::Fee if adjustment.amount_base_units > 0 => adjustment
                .amount_base_units
                .checked_neg()
                .ok_or(RiskError::ArithmeticOverflow)?,
            RiskAdjustmentKind::Rebate if adjustment.amount_base_units > 0 => {
                adjustment.amount_base_units
            }
            RiskAdjustmentKind::Funding if adjustment.amount_base_units != 0 => {
                adjustment.amount_base_units
            }
            RiskAdjustmentKind::Fee | RiskAdjustmentKind::Rebate | RiskAdjustmentKind::Funding => {
                return Self::kill_error(
                    kill,
                    KillCode::InternalInvariant,
                    now,
                    RiskError::InvalidAdjustment,
                );
            }
        };
        let candidate_adjustments =
            self.lifetime_adjustments
                .checked_add(delta)
                .ok_or_else(|| {
                    kill.trigger(KillCode::InternalInvariant, now);
                    RiskError::ArithmeticOverflow
                })?;
        let session_pnl = self
            .session_pnl_with_state(
                None,
                self.lifetime_realized_pnl,
                candidate_adjustments,
                self.session_baseline_pnl,
            )
            .inspect_err(|_| {
                kill.trigger(KillCode::InternalInvariant, now);
            })?;
        let loss_limit_breached = session_pnl <= -self.limits.max_daily_loss;
        self.lifetime_adjustments = candidate_adjustments;
        let kill_triggered = loss_limit_breached && kill.trigger(KillCode::LossLimit, now);
        Ok(AdjustmentOutcome {
            applied_delta_base_units: delta,
            lifetime_adjustments_base_units: candidate_adjustments,
            session_pnl_base_units: session_pnl,
            loss_limit_breached,
            kill_triggered,
        })
    }

    /// Return session P&L in base-currency atomic units relative to the current
    /// session baseline.
    ///
    /// # Errors
    ///
    /// Returns [`RiskError::ArithmeticOverflow`] if the bounded sum is unrepresentable.
    pub fn daily_pnl(&self) -> Result<i128, RiskError> {
        self.session_pnl_checked()
    }

    /// Return conservative gross and scenario-net exposure in base-currency units.
    ///
    /// # Errors
    ///
    /// Returns [`RiskError::ArithmeticOverflow`] if the bounded sum is unrepresentable.
    pub fn exposure(&self) -> Result<ExposureSnapshot, RiskError> {
        self.exposure_checked()
    }

    fn find_instrument(&self, instrument: InstrumentId) -> Option<usize> {
        self.instruments
            .iter()
            .position(|slot| slot.is_some_and(|state| state.definition.instrument == instrument))
    }

    fn find_order(&self, order_id: OrderId) -> Option<usize> {
        self.orders
            .iter()
            .position(|slot| slot.is_some_and(|order| order.order_id == order_id))
    }

    fn notional(price: i64, quantity: i64, base_units_per_tick_contract: i128) -> Option<i128> {
        i128::from(price)
            .checked_mul(i128::from(quantity))?
            .checked_mul(base_units_per_tick_contract)
    }

    /// Recompute exact per-order open reservations for one candidate mark without
    /// mutating state. Existing aggregates and stored reservation prices are also
    /// validated against the prior mark so a corrupt table cannot be re-blessed.
    fn revalue_open_reservations(
        &self,
        prior: InstrumentRisk,
        candidate_mark: i64,
    ) -> Result<ReservationRevaluation, RiskError> {
        if candidate_mark <= 0 {
            return Err(RiskError::InvalidPrice(PriceTicks(candidate_mark)));
        }
        let mut buy_quantity = 0_i64;
        let mut sell_quantity = 0_i64;
        let mut prior_buy_notional = 0_i128;
        let mut prior_sell_notional = 0_i128;
        let mut candidate_buy_notional = 0_i128;
        let mut candidate_sell_notional = 0_i128;
        let mut max_order_notional_breached = false;
        for order in self.orders.iter().flatten() {
            if order.instrument != prior.definition.instrument {
                continue;
            }
            if order.limit_price <= 0
                || order.reservation_price <= 0
                || order.remaining_quantity <= 0
            {
                return Err(RiskError::InternalInvariant);
            }
            let prior_mark = prior.mark.ok_or(RiskError::InternalInvariant)?;
            if order.reservation_price != order.limit_price.max(prior_mark) {
                return Err(RiskError::InternalInvariant);
            }
            let prior_notional = Self::notional(
                order.reservation_price,
                order.remaining_quantity,
                prior.base_units_per_tick_contract,
            )
            .ok_or(RiskError::ArithmeticOverflow)?;
            let candidate_notional = Self::notional(
                order.limit_price.max(candidate_mark),
                order.remaining_quantity,
                prior.base_units_per_tick_contract,
            )
            .ok_or(RiskError::ArithmeticOverflow)?;
            max_order_notional_breached |= candidate_notional > self.limits.max_order_notional;
            match order.side {
                Side::Buy => {
                    buy_quantity = buy_quantity
                        .checked_add(order.remaining_quantity)
                        .ok_or(RiskError::ArithmeticOverflow)?;
                    prior_buy_notional = prior_buy_notional
                        .checked_add(prior_notional)
                        .ok_or(RiskError::ArithmeticOverflow)?;
                    candidate_buy_notional = candidate_buy_notional
                        .checked_add(candidate_notional)
                        .ok_or(RiskError::ArithmeticOverflow)?;
                }
                Side::Sell => {
                    sell_quantity = sell_quantity
                        .checked_add(order.remaining_quantity)
                        .ok_or(RiskError::ArithmeticOverflow)?;
                    prior_sell_notional = prior_sell_notional
                        .checked_add(prior_notional)
                        .ok_or(RiskError::ArithmeticOverflow)?;
                    candidate_sell_notional = candidate_sell_notional
                        .checked_add(candidate_notional)
                        .ok_or(RiskError::ArithmeticOverflow)?;
                }
            }
        }
        if buy_quantity != prior.open_buy_quantity
            || sell_quantity != prior.open_sell_quantity
            || prior_buy_notional != prior.open_buy_notional
            || prior_sell_notional != prior.open_sell_notional
        {
            return Err(RiskError::InternalInvariant);
        }
        Ok(ReservationRevaluation {
            state: InstrumentRisk {
                open_buy_quantity: buy_quantity,
                open_sell_quantity: sell_quantity,
                open_buy_notional: candidate_buy_notional,
                open_sell_notional: candidate_sell_notional,
                ..prior
            },
            max_order_notional_breached,
        })
    }

    fn abs_i128(value: i128) -> Result<i128, RiskError> {
        value.checked_abs().ok_or(RiskError::ArithmeticOverflow)
    }

    fn project_open(
        state: InstrumentRisk,
        side: Side,
        quantity: i64,
        notional: i128,
    ) -> Option<(i64, i64, i128, i128)> {
        let mut buy_quantity = state.open_buy_quantity;
        let mut sell_quantity = state.open_sell_quantity;
        let mut buy_notional = state.open_buy_notional;
        let mut sell_notional = state.open_sell_notional;
        match side {
            Side::Buy => {
                buy_quantity = buy_quantity.checked_add(quantity)?;
                buy_notional = buy_notional.checked_add(notional)?;
            }
            Side::Sell => {
                sell_quantity = sell_quantity.checked_add(quantity)?;
                sell_notional = sell_notional.checked_add(notional)?;
            }
        }
        Some((buy_quantity, sell_quantity, buy_notional, sell_notional))
    }

    fn projected_exposure_checked(
        &self,
        override_index: usize,
        override_buy_notional: i128,
        override_sell_notional: i128,
    ) -> Result<ExposureSnapshot, RiskError> {
        self.exposure_with_overrides(
            Some((
                override_index,
                override_buy_notional,
                override_sell_notional,
            )),
            None,
        )
    }

    fn exposure_checked(&self) -> Result<ExposureSnapshot, RiskError> {
        self.exposure_with_overrides(None, None)
    }

    fn exposure_with_state(
        &self,
        override_index: usize,
        state: InstrumentRisk,
    ) -> Result<ExposureSnapshot, RiskError> {
        self.exposure_with_overrides(None, Some((override_index, state)))
    }

    fn exposure_with_overrides(
        &self,
        open_override: Option<(usize, i128, i128)>,
        state_override: Option<(usize, InstrumentRisk)>,
    ) -> Result<ExposureSnapshot, RiskError> {
        let mut gross = 0_i128;
        let mut long_scenario = 0_i128;
        let mut short_scenario = 0_i128;
        for (index, stored_state) in self.instruments.iter().enumerate() {
            let Some(stored_state) = stored_state else {
                continue;
            };
            let state = state_override
                .filter(|(candidate, _)| *candidate == index)
                .map_or(*stored_state, |(_, candidate)| candidate);
            let (buy_notional, sell_notional) = open_override
                .filter(|(candidate, _, _)| *candidate == index)
                .map_or(
                    (state.open_buy_notional, state.open_sell_notional),
                    |(_, buy, sell)| (buy, sell),
                );
            let position_value = Self::marked_position_value(state)?;
            let long_case = position_value
                .checked_add(buy_notional)
                .ok_or(RiskError::ArithmeticOverflow)?;
            let short_case = position_value
                .checked_sub(sell_notional)
                .ok_or(RiskError::ArithmeticOverflow)?;
            let worst = Self::abs_i128(long_case)?.max(Self::abs_i128(short_case)?);
            gross = gross
                .checked_add(worst)
                .ok_or(RiskError::ArithmeticOverflow)?;
            let instrument_long = position_value
                .checked_add(buy_notional)
                .ok_or(RiskError::ArithmeticOverflow)?;
            let instrument_short = position_value
                .checked_sub(sell_notional)
                .ok_or(RiskError::ArithmeticOverflow)?;
            long_scenario = long_scenario
                .checked_add(instrument_long)
                .ok_or(RiskError::ArithmeticOverflow)?;
            short_scenario = short_scenario
                .checked_add(instrument_short)
                .ok_or(RiskError::ArithmeticOverflow)?;
        }
        Ok(ExposureSnapshot {
            gross_notional: gross,
            net_notional: Self::abs_i128(long_scenario)?.max(Self::abs_i128(short_scenario)?),
        })
    }

    fn session_pnl_checked(&self) -> Result<i128, RiskError> {
        self.session_pnl_with_state(
            None,
            self.lifetime_realized_pnl,
            self.lifetime_adjustments,
            self.session_baseline_pnl,
        )
    }

    fn session_pnl_with_state(
        &self,
        state_override: Option<(usize, InstrumentRisk)>,
        lifetime_realized_pnl: i128,
        lifetime_adjustments: i128,
        session_baseline_pnl: i128,
    ) -> Result<i128, RiskError> {
        self.lifetime_pnl_with_state(state_override, lifetime_realized_pnl, lifetime_adjustments)?
            .checked_sub(session_baseline_pnl)
            .ok_or(RiskError::ArithmeticOverflow)
    }

    fn lifetime_pnl_with_state(
        &self,
        state_override: Option<(usize, InstrumentRisk)>,
        lifetime_realized_pnl: i128,
        lifetime_adjustments: i128,
    ) -> Result<i128, RiskError> {
        let mut pnl = lifetime_realized_pnl
            .checked_add(lifetime_adjustments)
            .ok_or(RiskError::ArithmeticOverflow)?;
        for (index, stored_state) in self.instruments.iter().enumerate() {
            let Some(stored_state) = stored_state else {
                continue;
            };
            let state = state_override
                .filter(|(candidate, _)| *candidate == index)
                .map_or(*stored_state, |(_, candidate)| candidate);
            let marked_value = Self::marked_position_value(state)?;
            let unrealized = marked_value
                .checked_sub(state.signed_position_cost)
                .ok_or(RiskError::ArithmeticOverflow)?;
            pnl = pnl
                .checked_add(unrealized)
                .ok_or(RiskError::ArithmeticOverflow)?;
        }
        Ok(pnl)
    }

    fn marked_position_value(state: InstrumentRisk) -> Result<i128, RiskError> {
        if state.position == 0 {
            return Ok(0);
        }
        let mark = state
            .mark
            .ok_or(RiskError::MissingValuationMark(state.definition.instrument))?;
        Self::notional(mark, state.position, state.base_units_per_tick_contract)
            .ok_or(RiskError::ArithmeticOverflow)
    }

    fn validate_active_marks(
        &self,
        now: TimestampNs,
        required_index: Option<usize>,
    ) -> Result<(), RiskError> {
        for (index, state) in self.instruments.iter().enumerate() {
            let Some(state) = state else {
                continue;
            };
            let active = state.position != 0
                || state.open_buy_quantity != 0
                || state.open_sell_quantity != 0;
            if !active && required_index != Some(index) {
                continue;
            }
            if state.mark.is_none() {
                return Err(RiskError::MissingValuationMark(state.definition.instrument));
            }
            let timestamp = state
                .last_market_timestamp
                .ok_or(RiskError::MissingValuationMark(state.definition.instrument))?;
            if timestamp > now {
                return Err(RiskError::FutureValuationMark {
                    instrument: state.definition.instrument,
                    market: timestamp,
                    now,
                });
            }
            let age_ns = now.saturating_duration_since(timestamp);
            if age_ns > self.limits.max_market_age_ns {
                return Err(RiskError::StaleValuationMark {
                    instrument: state.definition.instrument,
                    age_ns,
                    max_age_ns: self.limits.max_market_age_ns,
                });
            }
        }
        Ok(())
    }

    fn release_open(
        state: InstrumentRisk,
        side: Side,
        quantity: i64,
        notional: i128,
    ) -> Option<InstrumentRisk> {
        let mut released = state;
        match side {
            Side::Buy => {
                let open_quantity = state.open_buy_quantity.checked_sub(quantity)?;
                let open_notional = state.open_buy_notional.checked_sub(notional)?;
                if open_quantity < 0 || open_notional < 0 {
                    return None;
                }
                released.open_buy_quantity = open_quantity;
                released.open_buy_notional = open_notional;
            }
            Side::Sell => {
                let open_quantity = state.open_sell_quantity.checked_sub(quantity)?;
                let open_notional = state.open_sell_notional.checked_sub(notional)?;
                if open_quantity < 0 || open_notional < 0 {
                    return None;
                }
                released.open_sell_quantity = open_quantity;
                released.open_sell_notional = open_notional;
            }
        }
        Some(released)
    }

    fn compute_fill(
        state: InstrumentRisk,
        side: Side,
        fill_price: i64,
        fill_quantity: i64,
    ) -> Option<FillComputation> {
        let fill_signed = side.sign().checked_mul(fill_quantity)?;
        let new_position = state.position.checked_add(fill_signed)?;
        if state.position == 0 || state.position.signum() == fill_signed.signum() {
            let added_cost =
                Self::notional(fill_price, fill_signed, state.base_units_per_tick_contract)?;
            return Some(FillComputation {
                position: new_position,
                signed_cost: state.signed_position_cost.checked_add(added_cost)?,
                realized_delta: 0,
            });
        }

        let position_abs = i128::from(state.position).checked_abs()?;
        let close_quantity = position_abs.min(i128::from(fill_quantity));
        let closed_cost = state
            .signed_position_cost
            .checked_mul(close_quantity)?
            .checked_div(position_abs)?;
        let close_at_fill = i128::from(state.position.signum())
            .checked_mul(i128::from(fill_price))?
            .checked_mul(state.base_units_per_tick_contract)?
            .checked_mul(close_quantity)?;
        let realized_delta = close_at_fill.checked_sub(closed_cost)?;
        let remaining_old_cost = state.signed_position_cost.checked_sub(closed_cost)?;
        let close_fill_signed = i128::from(-state.position.signum()).checked_mul(close_quantity)?;
        let residual_fill_signed = i128::from(fill_signed).checked_sub(close_fill_signed)?;
        let residual_cost = residual_fill_signed
            .checked_mul(i128::from(fill_price))?
            .checked_mul(state.base_units_per_tick_contract)?;
        let signed_cost = remaining_old_cost.checked_add(residual_cost)?;
        Some(FillComputation {
            position: new_position,
            signed_cost,
            realized_delta,
        })
    }

    fn kill_error<T>(
        kill: &KillLatch,
        code: KillCode,
        now: TimestampNs,
        error: RiskError,
    ) -> Result<T, RiskError> {
        kill.trigger(code, now);
        Err(error)
    }

    const fn error_kill_code(error: RiskError) -> KillCode {
        match error {
            RiskError::ClockUnsafe
            | RiskError::FutureMarketTimestamp { .. }
            | RiskError::FutureValuationMark { .. } => KillCode::ClockUnsafe,
            RiskError::StaleMarket { .. }
            | RiskError::StaleValuationMark { .. }
            | RiskError::MissingValuationMark(_)
            | RiskError::UnknownInstrument(_) => KillCode::MarketDataGap,
            RiskError::DailyLossLimit { .. } => KillCode::LossLimit,
            RiskError::OrderQuantityLimit { .. }
            | RiskError::PositionLimit { .. }
            | RiskError::OrderNotionalLimit { .. }
            | RiskError::GrossNotionalLimit { .. }
            | RiskError::NetNotionalLimit { .. }
            | RiskError::InstrumentHalted(_) => KillCode::RiskLimit,
            RiskError::InvalidLimits
            | RiskError::InvalidSessionId
            | RiskError::NonMonotonicSession { .. }
            | RiskError::InvalidCurrencyId
            | RiskError::InvalidInstrumentDefinition
            | RiskError::DuplicateInstrumentDefinition(_)
            | RiskError::UnsupportedDynamicFx(_)
            | RiskError::CurrencyMismatch { .. }
            | RiskError::NoBaseCurrency
            | RiskError::GlobalKill
            | RiskError::MarketTimestampRegression { .. }
            | RiskError::InvalidInstrumentId
            | RiskError::InstrumentCapacity { .. }
            | RiskError::OrderCapacity { .. }
            | RiskError::InvalidOrderId
            | RiskError::DuplicateOrder(_)
            | RiskError::UnknownOrder(_)
            | RiskError::InvalidPrice(_)
            | RiskError::InvalidQuantity(_)
            | RiskError::FillExceedsRemaining { .. }
            | RiskError::CancelExceedsRemaining { .. }
            | RiskError::InvalidAdjustment
            | RiskError::ArithmeticOverflow
            | RiskError::InternalInvariant => KillCode::InternalInvariant,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FillComputation {
    position: i64,
    signed_cost: i128,
    realized_delta: i128,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReservationRevaluation {
    state: InstrumentRisk,
    max_order_notional_breached: bool,
}
