//! Deterministic, integer-only reference market-making policy.
//!
//! This is an execution policy and integration fixture, not evidence of alpha. A live
//! strategy must arrive as reviewed compiled Rust logic and pass independent research,
//! replay, capacity, and deployment gates; Python is not called for per-tick decisions.

use crate::types::{PriceTicks, Quantity, Side};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotePolicyConfig {
    pub base_quantity: Quantity,
    pub base_half_spread_ticks: i64,
    pub max_volatility_spread_ticks: i64,
    pub max_abs_alpha_ticks: i64,
    pub inventory_skew_numerator: i64,
    pub inventory_skew_denominator: i64,
    pub max_abs_inventory: Quantity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MarketFeatures {
    pub best_bid: PriceTicks,
    pub best_bid_quantity: Quantity,
    pub best_ask: PriceTicks,
    pub best_ask_quantity: Quantity,
    /// Bounded short-horizon forecast produced inside the compiled hot process.
    pub short_horizon_alpha_ticks: i64,
    /// Non-negative spread add-on from a compiled short-horizon volatility estimator.
    pub volatility_spread_ticks: i64,
    pub inventory: Quantity,
    pub instrument_halted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuoteLeg {
    pub side: Side,
    pub price: PriceTicks,
    pub quantity: Quantity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuoteDecision {
    pub fair_value: PriceTicks,
    pub half_spread_ticks: i64,
    pub bid: Option<QuoteLeg>,
    pub ask: Option<QuoteLeg>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StrategyError {
    InvalidConfiguration,
    InvalidBook,
    InvalidFeature,
    ArithmeticOverflow,
}

/// Inventory-aware, post-only reference quoter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InventoryAwareQuoter {
    config: QuotePolicyConfig,
}

impl InventoryAwareQuoter {
    /// Validate and construct the policy.
    ///
    /// # Errors
    ///
    /// Returns [`StrategyError::InvalidConfiguration`] for non-positive quantities,
    /// spreads, denominators, inventory limits, or negative forecast bounds.
    pub fn new(config: QuotePolicyConfig) -> Result<Self, StrategyError> {
        if !config.base_quantity.is_positive()
            || config.base_half_spread_ticks <= 0
            || config.max_volatility_spread_ticks < 0
            || config.max_abs_alpha_ticks < 0
            || config.inventory_skew_numerator < 0
            || config.inventory_skew_denominator <= 0
            || !config.max_abs_inventory.is_positive()
        {
            return Err(StrategyError::InvalidConfiguration);
        }
        Ok(Self { config })
    }

    #[must_use]
    pub const fn config(self) -> QuotePolicyConfig {
        self.config
    }

    /// Produce bounded post-only quote intents from a top-of-book snapshot.
    ///
    /// Microprice weights the ask by displayed bid size and the bid by displayed ask
    /// size. Positive inventory shifts fair value down; negative inventory shifts it up.
    /// A local adverse-selection halt suppresses both quote legs without discarding the
    /// calculated fair value.
    ///
    /// # Errors
    ///
    /// Returns [`StrategyError`] for crossed/empty books, invalid signed features, or
    /// any checked-arithmetic failure.
    pub fn decide(self, features: MarketFeatures) -> Result<QuoteDecision, StrategyError> {
        Self::validate_features(features)?;

        let bid_quantity = i128::from(features.best_bid_quantity.0);
        let ask_quantity = i128::from(features.best_ask_quantity.0);
        let displayed = bid_quantity
            .checked_add(ask_quantity)
            .ok_or(StrategyError::ArithmeticOverflow)?;
        let ask_weighted = i128::from(features.best_ask.0)
            .checked_mul(bid_quantity)
            .ok_or(StrategyError::ArithmeticOverflow)?;
        let bid_weighted = i128::from(features.best_bid.0)
            .checked_mul(ask_quantity)
            .ok_or(StrategyError::ArithmeticOverflow)?;
        let microprice = ask_weighted
            .checked_add(bid_weighted)
            .and_then(|value| value.checked_div(displayed))
            .ok_or(StrategyError::ArithmeticOverflow)?;

        let alpha = features.short_horizon_alpha_ticks.clamp(
            -self.config.max_abs_alpha_ticks,
            self.config.max_abs_alpha_ticks,
        );
        let inventory_skew = i128::from(features.inventory.0)
            .checked_mul(i128::from(self.config.inventory_skew_numerator))
            .and_then(|value| value.checked_div(i128::from(self.config.inventory_skew_denominator)))
            .ok_or(StrategyError::ArithmeticOverflow)?;
        let fair = microprice
            .checked_add(i128::from(alpha))
            .and_then(|value| value.checked_sub(inventory_skew))
            .ok_or(StrategyError::ArithmeticOverflow)?;
        let fair = i64::try_from(fair).map_err(|_| StrategyError::ArithmeticOverflow)?;
        if fair <= 0 {
            return Err(StrategyError::InvalidFeature);
        }

        let volatility = features
            .volatility_spread_ticks
            .min(self.config.max_volatility_spread_ticks);
        let half_spread = self
            .config
            .base_half_spread_ticks
            .checked_add(volatility)
            .ok_or(StrategyError::ArithmeticOverflow)?;
        let desired_bid = fair
            .checked_sub(half_spread)
            .ok_or(StrategyError::ArithmeticOverflow)?;
        let desired_ask = fair
            .checked_add(half_spread)
            .ok_or(StrategyError::ArithmeticOverflow)?;
        if desired_bid <= 0 {
            return Err(StrategyError::InvalidFeature);
        }

        let bid_price = PriceTicks(desired_bid.min(features.best_bid.0));
        let ask_price = PriceTicks(desired_ask.max(features.best_ask.0));
        if bid_price >= ask_price {
            return Err(StrategyError::InvalidBook);
        }

        let base = self.config.base_quantity.0;
        let max_inventory = self.config.max_abs_inventory.0;
        let projected_buy = features
            .inventory
            .0
            .checked_add(base)
            .ok_or(StrategyError::ArithmeticOverflow)?;
        let projected_sell = features
            .inventory
            .0
            .checked_sub(base)
            .ok_or(StrategyError::ArithmeticOverflow)?;
        let can_buy = projected_buy <= max_inventory;
        let can_sell = projected_sell >= -max_inventory;
        let suppressed = features.instrument_halted;

        Ok(QuoteDecision {
            fair_value: PriceTicks(fair),
            half_spread_ticks: half_spread,
            bid: (can_buy && !suppressed).then_some(QuoteLeg {
                side: Side::Buy,
                price: bid_price,
                quantity: self.config.base_quantity,
            }),
            ask: (can_sell && !suppressed).then_some(QuoteLeg {
                side: Side::Sell,
                price: ask_price,
                quantity: self.config.base_quantity,
            }),
        })
    }

    fn validate_features(features: MarketFeatures) -> Result<(), StrategyError> {
        if !features.best_bid.is_positive()
            || !features.best_ask.is_positive()
            || features.best_bid >= features.best_ask
            || !features.best_bid_quantity.is_positive()
            || !features.best_ask_quantity.is_positive()
        {
            return Err(StrategyError::InvalidBook);
        }
        if features.volatility_spread_ticks < 0 {
            return Err(StrategyError::InvalidFeature);
        }
        Ok(())
    }
}
