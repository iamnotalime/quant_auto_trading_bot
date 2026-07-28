use quant_hft_core::strategy::{
    InventoryAwareQuoter, MarketFeatures, QuotePolicyConfig, StrategyError,
};
use quant_hft_core::{PriceTicks, Quantity, Side};

fn policy() -> InventoryAwareQuoter {
    InventoryAwareQuoter::new(QuotePolicyConfig {
        base_quantity: Quantity(10),
        base_half_spread_ticks: 1,
        max_volatility_spread_ticks: 5,
        max_abs_alpha_ticks: 4,
        inventory_skew_numerator: 1,
        inventory_skew_denominator: 10,
        max_abs_inventory: Quantity(20),
    })
    .expect("valid policy")
}

fn balanced() -> MarketFeatures {
    MarketFeatures {
        best_bid: PriceTicks(100),
        best_bid_quantity: Quantity(50),
        best_ask: PriceTicks(102),
        best_ask_quantity: Quantity(50),
        short_horizon_alpha_ticks: 0,
        volatility_spread_ticks: 0,
        inventory: Quantity::ZERO,
        instrument_halted: false,
    }
}

#[test]
fn balanced_book_produces_deterministic_post_only_quotes() {
    let first = policy().decide(balanced()).expect("decision");
    let second = policy().decide(balanced()).expect("repeat");
    assert_eq!(first, second);
    assert_eq!(first.fair_value, PriceTicks(101));
    assert_eq!(first.bid.expect("bid").price, PriceTicks(100));
    assert_eq!(first.ask.expect("ask").price, PriceTicks(102));
    assert_eq!(first.bid.expect("bid").side, Side::Buy);
    assert_eq!(first.ask.expect("ask").side, Side::Sell);
}

#[test]
fn microprice_alpha_volatility_and_inventory_are_bounded() {
    let mut features = balanced();
    features.best_bid_quantity = Quantity(90);
    features.best_ask_quantity = Quantity(10);
    features.short_horizon_alpha_ticks = 100;
    features.volatility_spread_ticks = 100;
    features.inventory = Quantity(20);
    let decision = policy().decide(features).expect("bounded decision");

    // Microprice is 101 (integer floor), alpha is capped at +4, inventory skew is 2.
    assert_eq!(decision.fair_value, PriceTicks(103));
    assert_eq!(decision.half_spread_ticks, 6);
    assert!(
        decision.bid.is_none(),
        "max-long inventory cannot add another buy"
    );
    assert_eq!(
        decision.ask.expect("risk-reducing ask").price,
        PriceTicks(109)
    );
}

#[test]
fn adverse_halt_suppresses_both_legs_and_invalid_books_fail() {
    let mut halted = balanced();
    halted.instrument_halted = true;
    let decision = policy().decide(halted).expect("halt decision");
    assert!(decision.bid.is_none());
    assert!(decision.ask.is_none());

    let mut crossed = balanced();
    crossed.best_bid = crossed.best_ask;
    assert_eq!(policy().decide(crossed), Err(StrategyError::InvalidBook));

    let mut invalid_volatility = balanced();
    invalid_volatility.volatility_spread_ticks = -1;
    assert_eq!(
        policy().decide(invalid_volatility),
        Err(StrategyError::InvalidFeature)
    );
}

#[test]
fn invalid_policy_is_rejected() {
    assert_eq!(
        InventoryAwareQuoter::new(QuotePolicyConfig {
            base_quantity: Quantity::ZERO,
            base_half_spread_ticks: 1,
            max_volatility_spread_ticks: 1,
            max_abs_alpha_ticks: 1,
            inventory_skew_numerator: 1,
            inventory_skew_denominator: 1,
            max_abs_inventory: Quantity(1),
        }),
        Err(StrategyError::InvalidConfiguration)
    );
}
