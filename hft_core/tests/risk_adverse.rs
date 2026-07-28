use quant_hft_core::adverse::{AdverseConfig, AdverseError, AdverseFill, AdverseMonitor};
use quant_hft_core::kill::{KillCode, KillLatch, KillSnapshot};
use quant_hft_core::risk::{
    CurrencyId, InstrumentRiskDefinition, InstrumentValuation, PreTradeRequest, RiskAdjustment,
    RiskAdjustmentKind, RiskEngine, RiskError, RiskLimits, RiskSessionId,
};
use quant_hft_core::{InstrumentId, OrderId, PriceTicks, Quantity, Side, TimestampNs};

fn limits() -> RiskLimits {
    RiskLimits {
        max_order_quantity: Quantity(100),
        max_order_notional: 100_000,
        max_gross_notional: 200_000,
        max_net_notional: 200_000,
        max_daily_loss: 10_000,
        max_market_age_ns: 100,
    }
}

const BASE_CURRENCY: CurrencyId = CurrencyId(840);

fn definition(
    instrument: u32,
    base_units_per_price_tick: i128,
    contract_multiplier: u64,
    position_limit: i64,
) -> InstrumentRiskDefinition {
    InstrumentRiskDefinition {
        instrument: InstrumentId(instrument),
        base_currency: BASE_CURRENCY,
        valuation: InstrumentValuation::Fixed {
            base_units_per_price_tick,
            contract_multiplier,
        },
        position_limit: Quantity(position_limit),
    }
}

fn risk_engine<const INSTRUMENTS: usize, const ORDERS: usize>(
    limits: RiskLimits,
    position_limit: i64,
) -> RiskEngine<INSTRUMENTS, ORDERS> {
    let mut risk = RiskEngine::new(limits, RiskSessionId(1)).expect("valid risk engine");
    for instrument in 1..=INSTRUMENTS {
        risk.register_instrument(definition(
            u32::try_from(instrument).expect("test instrument fits u32"),
            1,
            1,
            position_limit,
        ))
        .expect("valid instrument definition");
    }
    risk
}

fn request(
    order_id: u64,
    instrument: u32,
    side: Side,
    price: i64,
    quantity: i64,
    now: u64,
) -> PreTradeRequest {
    PreTradeRequest {
        order_id: OrderId(order_id),
        instrument: InstrumentId(instrument),
        side,
        price: PriceTicks(price),
        quantity: Quantity(quantity),
        now: TimestampNs(now),
        clock_healthy: true,
        instrument_halted: false,
    }
}

fn mark<const INSTRUMENTS: usize, const ORDERS: usize>(
    risk: &mut RiskEngine<INSTRUMENTS, ORDERS>,
    instrument: u32,
    price: i64,
    timestamp: u64,
    kill: &KillLatch,
) {
    risk.on_mark(
        InstrumentId(instrument),
        PriceTicks(price),
        TimestampNs(timestamp),
        TimestampNs(timestamp),
        true,
        kill,
    )
    .expect("valid mark");
}

#[test]
fn buy_sell_fills_update_signed_inventory_cost_and_pnl() {
    let kill = KillLatch::new();
    let mut risk = risk_engine::<2, 8>(limits(), 100);
    mark(&mut risk, 1, 100, 1_000, &kill);

    let approval = risk
        .authorize_order(request(1, 1, Side::Buy, 100, 10, 1_001), &kill)
        .expect("buy approved");
    assert_eq!(approval.projected_position_quantity, Quantity(10));
    assert_eq!(approval.projected_gross_notional, 1_000);
    let reserved = risk.instrument(InstrumentId(1)).expect("instrument");
    assert_eq!(reserved.open_buy_quantity, Quantity(10));
    assert_eq!(reserved.open_buy_notional, 1_000);

    let buy = risk
        .on_fill(
            OrderId(1),
            PriceTicks(100),
            Quantity(10),
            TimestampNs(1_002),
            &kill,
        )
        .expect("buy fill");
    assert_eq!(buy.position, Quantity(10));
    assert_eq!(buy.realized_pnl_delta, 0);
    assert_eq!(risk.order_count(), 0);

    mark(&mut risk, 1, 110, 1_010, &kill);
    assert_eq!(risk.daily_pnl(), Ok(100));
    risk.authorize_order(request(2, 1, Side::Sell, 110, 15, 1_011), &kill)
        .expect("crossing sell approved by risk");
    let sell = risk
        .on_fill(
            OrderId(2),
            PriceTicks(110),
            Quantity(15),
            TimestampNs(1_012),
            &kill,
        )
        .expect("sell fill");
    assert_eq!(sell.position, Quantity(-5));
    assert_eq!(sell.realized_pnl_delta, 100);
    let short = risk.instrument(InstrumentId(1)).expect("short inventory");
    assert_eq!(short.position, Quantity(-5));
    assert_eq!(short.signed_position_cost, -550);
    assert_eq!(risk.daily_pnl(), Ok(100));

    mark(&mut risk, 1, 120, 1_020, &kill);
    assert_eq!(risk.daily_pnl(), Ok(50));
    assert!(!kill.is_triggered());
}

#[test]
fn partial_and_full_cancels_release_open_exposure_exactly() {
    let kill = KillLatch::new();
    let mut risk = risk_engine::<1, 2>(limits(), 100);
    mark(&mut risk, 1, 100, 100, &kill);
    risk.authorize_order(request(1, 1, Side::Buy, 100, 10, 101), &kill)
        .expect("approved");

    let partial = risk
        .on_cancel(OrderId(1), Quantity(4), TimestampNs(102), &kill)
        .expect("partial cancel");
    assert_eq!(partial.remaining_order_quantity, Quantity(6));
    let state = risk.instrument(InstrumentId(1)).expect("instrument");
    assert_eq!(state.open_buy_quantity, Quantity(6));
    assert_eq!(state.open_buy_notional, 600);
    assert_eq!(risk.exposure().expect("exposure").gross_notional, 600);

    let full = risk
        .on_cancel(OrderId(1), Quantity(6), TimestampNs(103), &kill)
        .expect("remaining cancel");
    assert_eq!(full.remaining_order_quantity, Quantity::ZERO);
    assert!(risk.order(OrderId(1)).is_none());
    assert_eq!(risk.exposure().expect("exposure").gross_notional, 0);
}

#[test]
fn opposing_reservations_never_net_between_long_and_short_scenarios() {
    let same_kill = KillLatch::new();
    let mut same = risk_engine::<1, 4>(limits(), 100);
    mark(&mut same, 1, 100, 10, &same_kill);
    same.authorize_order(request(1, 1, Side::Buy, 100, 6, 11), &same_kill)
        .expect("buy reservation");
    same.authorize_order(request(2, 1, Side::Sell, 100, 4, 12), &same_kill)
        .expect("sell reservation");
    assert_eq!(
        same.exposure().expect("same exposure"),
        quant_hft_core::risk::ExposureSnapshot {
            gross_notional: 600,
            net_notional: 600,
        },
        "buy and sell reservations must not cancel in the net gate"
    );

    let cross_kill = KillLatch::new();
    let mut cross = risk_engine::<2, 4>(limits(), 100);
    mark(&mut cross, 1, 100, 10, &cross_kill);
    mark(&mut cross, 2, 100, 10, &cross_kill);
    cross
        .authorize_order(request(1, 1, Side::Buy, 100, 6, 11), &cross_kill)
        .expect("cross buy reservation");
    cross
        .authorize_order(request(2, 2, Side::Sell, 100, 4, 12), &cross_kill)
        .expect("cross sell reservation");
    assert_eq!(
        cross.exposure().expect("cross exposure"),
        quant_hft_core::risk::ExposureSnapshot {
            gross_notional: 1_000,
            net_notional: 600,
        },
        "opposing orders on different instruments must also remain scenario-separated"
    );
}

#[test]
fn low_sell_limit_is_reserved_at_mark_and_revalued_before_fill() {
    let mut tight = limits();
    tight.max_gross_notional = 500;
    tight.max_net_notional = 500;

    let initial_kill = KillLatch::new();
    let mut initial = risk_engine::<1, 2>(tight, 100);
    mark(&mut initial, 1, 1_000, 10, &initial_kill);
    assert_eq!(
        initial.authorize_order(request(1, 1, Side::Sell, 100, 1, 11), &initial_kill),
        Err(RiskError::GrossNotionalLimit {
            projected: 1_000,
            limit: 500,
        })
    );
    assert_eq!(initial.order_count(), 0);
    assert_eq!(initial.exposure().unwrap().gross_notional, 0);
    assert_eq!(initial_kill.snapshot().unwrap().code, KillCode::RiskLimit);

    let move_kill = KillLatch::new();
    let mut moved = risk_engine::<1, 2>(tight, 100);
    mark(&mut moved, 1, 100, 10, &move_kill);
    moved
        .authorize_order(request(1, 1, Side::Sell, 100, 1, 11), &move_kill)
        .expect("initial reservation fits");
    assert_eq!(
        moved.order(OrderId(1)).unwrap().reservation_price,
        PriceTicks(100)
    );
    let outcome = moved
        .on_mark(
            InstrumentId(1),
            PriceTicks(1_000),
            TimestampNs(12),
            TimestampNs(12),
            true,
            &move_kill,
        )
        .expect("market fact commits before risk kill");
    assert_eq!(outcome.exposure.gross_notional, 1_000);
    assert_eq!(outcome.exposure.net_notional, 1_000);
    assert!(outcome.risk_limit_breached);
    assert!(outcome.kill_triggered);
    let state = moved.instrument(InstrumentId(1)).unwrap();
    assert_eq!(state.open_sell_notional, 1_000);
    assert_eq!(
        moved.order(OrderId(1)).unwrap().reservation_price,
        PriceTicks(1_000)
    );
}

#[test]
fn mark_revaluation_continuously_enforces_max_order_notional() {
    let mut tight = limits();
    tight.max_order_notional = 500;
    tight.max_gross_notional = 10_000;
    tight.max_net_notional = 10_000;
    let kill = KillLatch::new();
    let mut risk = risk_engine::<1, 2>(tight, 100);
    mark(&mut risk, 1, 100, 10, &kill);
    risk.authorize_order(request(1, 1, Side::Sell, 100, 1, 11), &kill)
        .expect("initial per-order reservation fits");

    let outcome = risk
        .on_mark(
            InstrumentId(1),
            PriceTicks(1_000),
            TimestampNs(12),
            TimestampNs(12),
            true,
            &kill,
        )
        .expect("accepted market fact commits conservative revaluation");

    assert!(outcome.risk_limit_breached);
    assert!(outcome.kill_triggered);
    assert_eq!(outcome.exposure.gross_notional, 1_000);
    assert_eq!(
        risk.order(OrderId(1)).unwrap().reservation_price,
        PriceTicks(1_000)
    );
    assert_eq!(
        risk.instrument(InstrumentId(1)).unwrap().open_sell_notional,
        1_000
    );
    assert_eq!(kill.snapshot().unwrap().code, KillCode::RiskLimit);
}

#[test]
fn mixed_limits_and_sides_revalue_each_order_exactly_in_both_directions() {
    let kill = KillLatch::new();
    let mut risk = risk_engine::<1, 8>(limits(), 100);
    mark(&mut risk, 1, 100, 10, &kill);
    for (order_id, side, limit) in [
        (1, Side::Buy, 50),
        (2, Side::Buy, 150),
        (3, Side::Sell, 80),
        (4, Side::Sell, 200),
    ] {
        risk.authorize_order(request(order_id, 1, side, limit, 1, 11), &kill)
            .expect("mixed reservation");
    }
    let initial = risk.instrument(InstrumentId(1)).unwrap();
    assert_eq!(initial.open_buy_notional, 250);
    assert_eq!(initial.open_sell_notional, 300);
    assert_eq!(risk.exposure().unwrap().gross_notional, 300);

    let up = risk
        .on_mark(
            InstrumentId(1),
            PriceTicks(120),
            TimestampNs(12),
            TimestampNs(12),
            true,
            &kill,
        )
        .unwrap();
    assert_eq!(up.exposure.gross_notional, 320);
    assert_eq!(up.exposure.net_notional, 320);
    let state = risk.instrument(InstrumentId(1)).unwrap();
    assert_eq!(state.open_buy_notional, 270);
    assert_eq!(state.open_sell_notional, 320);
    assert_eq!(
        [1_u64, 2, 3, 4].map(|id| risk.order(OrderId(id)).unwrap().reservation_price),
        [
            PriceTicks(120),
            PriceTicks(150),
            PriceTicks(120),
            PriceTicks(200),
        ]
    );

    let down = risk
        .on_mark(
            InstrumentId(1),
            PriceTicks(60),
            TimestampNs(13),
            TimestampNs(13),
            true,
            &kill,
        )
        .unwrap();
    assert_eq!(down.exposure.gross_notional, 280);
    assert_eq!(down.exposure.net_notional, 280);
    let state = risk.instrument(InstrumentId(1)).unwrap();
    assert_eq!(state.open_buy_notional, 210);
    assert_eq!(state.open_sell_notional, 280);
    assert_eq!(
        [1_u64, 2, 3, 4].map(|id| risk.order(OrderId(id)).unwrap().reservation_price),
        [
            PriceTicks(60),
            PriceTicks(150),
            PriceTicks(80),
            PriceTicks(200),
        ]
    );
    assert!(!kill.is_triggered());
}

#[test]
fn repriced_fill_cancel_and_position_reducing_order_preserve_scenario_netting() {
    let kill = KillLatch::new();
    let mut risk = risk_engine::<1, 4>(limits(), 100);
    mark(&mut risk, 1, 100, 10, &kill);
    risk.authorize_order(request(1, 1, Side::Buy, 50, 10, 11), &kill)
        .unwrap();
    mark(&mut risk, 1, 200, 12, &kill);
    assert_eq!(
        risk.instrument(InstrumentId(1)).unwrap().open_buy_notional,
        2_000
    );
    risk.on_fill(
        OrderId(1),
        PriceTicks(50),
        Quantity(4),
        TimestampNs(13),
        &kill,
    )
    .unwrap();
    let partially_filled = risk.instrument(InstrumentId(1)).unwrap();
    assert_eq!(partially_filled.position, Quantity(4));
    assert_eq!(partially_filled.open_buy_quantity, Quantity(6));
    assert_eq!(partially_filled.open_buy_notional, 1_200);
    assert_eq!(risk.exposure().unwrap().gross_notional, 2_000);
    risk.on_cancel(OrderId(1), Quantity(6), TimestampNs(14), &kill)
        .unwrap();
    assert_eq!(risk.exposure().unwrap().gross_notional, 800);

    let reducing = risk
        .authorize_order(request(2, 1, Side::Sell, 100, 2, 15), &kill)
        .unwrap();
    assert_eq!(reducing.projected_gross_notional, 800);
    assert_eq!(reducing.projected_net_notional, 800);
    assert_eq!(
        risk.instrument(InstrumentId(1)).unwrap().open_sell_notional,
        400
    );

    mark(&mut risk, 1, 50, 16, &kill);
    let down = risk.instrument(InstrumentId(1)).unwrap();
    assert_eq!(down.open_sell_notional, 200);
    assert_eq!(risk.exposure().unwrap().gross_notional, 200);
    mark(&mut risk, 1, 300, 17, &kill);
    let up = risk.instrument(InstrumentId(1)).unwrap();
    assert_eq!(up.open_sell_notional, 600);
    assert_eq!(risk.exposure().unwrap().gross_notional, 1_200);
    risk.on_cancel(OrderId(2), Quantity(2), TimestampNs(18), &kill)
        .unwrap();
    assert_eq!(risk.exposure().unwrap().gross_notional, 1_200);
    assert!(!kill.is_triggered());
}

#[test]
fn reservation_revaluation_overflow_is_atomic() {
    let kill = KillLatch::new();
    let extreme_limits = RiskLimits {
        max_order_quantity: Quantity(1),
        max_order_notional: i128::MAX,
        max_gross_notional: i128::MAX,
        max_net_notional: i128::MAX,
        max_daily_loss: i128::MAX,
        max_market_age_ns: 100,
    };
    let mut risk = RiskEngine::<1, 2>::new(extreme_limits, RiskSessionId(1)).unwrap();
    risk.register_instrument(definition(1, i128::MAX, 1, 1))
        .unwrap();
    mark(&mut risk, 1, 1, 10, &kill);
    risk.authorize_order(request(1, 1, Side::Sell, 1, 1, 11), &kill)
        .unwrap();
    let instrument_before = risk.instrument(InstrumentId(1));
    let order_before = risk.order(OrderId(1));
    let exposure_before = risk.exposure();
    let pnl_before = risk.daily_pnl();
    let order_count_before = risk.order_count();

    assert_eq!(
        risk.on_mark(
            InstrumentId(1),
            PriceTicks(2),
            TimestampNs(12),
            TimestampNs(12),
            true,
            &kill,
        ),
        Err(RiskError::ArithmeticOverflow)
    );
    assert_eq!(risk.instrument(InstrumentId(1)), instrument_before);
    assert_eq!(risk.order(OrderId(1)), order_before);
    assert_eq!(risk.exposure(), exposure_before);
    assert_eq!(risk.daily_pnl(), pnl_before);
    assert_eq!(risk.order_count(), order_count_before);
    assert_eq!(kill.snapshot().unwrap().code, KillCode::InternalInvariant);
}

#[test]
fn every_configured_pretrade_limit_is_enforced_before_reservation() {
    let mut quantity_limits = limits();
    quantity_limits.max_order_quantity = Quantity(5);
    let quantity_kill = KillLatch::new();
    let mut quantity_risk = risk_engine::<1, 2>(quantity_limits, 100);
    mark(&mut quantity_risk, 1, 100, 10, &quantity_kill);
    assert_eq!(
        quantity_risk.authorize_order(request(1, 1, Side::Buy, 100, 6, 11), &quantity_kill,),
        Err(RiskError::OrderQuantityLimit {
            requested: Quantity(6),
            limit: Quantity(5),
        })
    );
    assert_eq!(quantity_risk.order_count(), 0);

    let mut notional_limits = limits();
    notional_limits.max_order_notional = 500;
    let notional_kill = KillLatch::new();
    let mut notional_risk = risk_engine::<1, 2>(notional_limits, 100);
    mark(&mut notional_risk, 1, 100, 10, &notional_kill);
    assert_eq!(
        notional_risk.authorize_order(request(1, 1, Side::Buy, 100, 6, 11), &notional_kill,),
        Err(RiskError::OrderNotionalLimit {
            requested: 600,
            limit: 500,
        })
    );
    assert_eq!(notional_risk.order_count(), 0);

    let mut mark_notional_limits = limits();
    mark_notional_limits.max_order_notional = 500;
    mark_notional_limits.max_gross_notional = 10_000;
    mark_notional_limits.max_net_notional = 10_000;
    let mark_notional_kill = KillLatch::new();
    let mut mark_notional_risk = risk_engine::<1, 2>(mark_notional_limits, 100);
    mark(&mut mark_notional_risk, 1, 1_000, 10, &mark_notional_kill);
    assert_eq!(
        mark_notional_risk
            .authorize_order(request(1, 1, Side::Sell, 100, 1, 11), &mark_notional_kill,),
        Err(RiskError::OrderNotionalLimit {
            requested: 1_000,
            limit: 500,
        })
    );
    assert_eq!(mark_notional_risk.order_count(), 0);
    assert_eq!(mark_notional_risk.exposure().unwrap().gross_notional, 0);

    let position_limits = limits();
    let position_kill = KillLatch::new();
    let mut position_risk = risk_engine::<1, 3>(position_limits, 10);
    mark(&mut position_risk, 1, 100, 10, &position_kill);
    position_risk
        .authorize_order(request(1, 1, Side::Buy, 100, 6, 11), &position_kill)
        .expect("first reservation");
    assert_eq!(
        position_risk.authorize_order(request(2, 1, Side::Buy, 100, 5, 12), &position_kill,),
        Err(RiskError::PositionLimit {
            projected: Quantity(11),
            limit: Quantity(10),
        })
    );
    assert!(position_risk.order(OrderId(1)).is_some());
    assert!(position_risk.order(OrderId(2)).is_none());

    let mut gross_limits = limits();
    gross_limits.max_gross_notional = 1_000;
    gross_limits.max_net_notional = 10_000;
    let gross_kill = KillLatch::new();
    let mut gross_risk = risk_engine::<2, 3>(gross_limits, 100);
    mark(&mut gross_risk, 1, 100, 10, &gross_kill);
    mark(&mut gross_risk, 2, 100, 10, &gross_kill);
    gross_risk
        .authorize_order(request(1, 1, Side::Buy, 100, 6, 11), &gross_kill)
        .expect("first gross reservation");
    assert_eq!(
        gross_risk.authorize_order(request(2, 2, Side::Buy, 100, 6, 11), &gross_kill,),
        Err(RiskError::GrossNotionalLimit {
            projected: 1_200,
            limit: 1_000,
        })
    );
    assert_eq!(gross_risk.order_count(), 1);

    let mut net_limits = limits();
    net_limits.max_gross_notional = 10_000;
    net_limits.max_net_notional = 500;
    let net_kill = KillLatch::new();
    let mut net_risk = risk_engine::<1, 2>(net_limits, 100);
    mark(&mut net_risk, 1, 100, 10, &net_kill);
    assert_eq!(
        net_risk.authorize_order(request(1, 1, Side::Buy, 100, 6, 11), &net_kill),
        Err(RiskError::NetNotionalLimit {
            projected: 600,
            limit: 500,
        })
    );
    assert_eq!(net_risk.order_count(), 0);

    for latch in [
        &quantity_kill,
        &notional_kill,
        &position_kill,
        &gross_kill,
        &net_kill,
    ] {
        assert_eq!(
            latch.snapshot().expect("risk limit kill").code,
            KillCode::RiskLimit
        );
    }
}

#[test]
fn unsafe_clock_and_stale_market_fail_closed_with_first_fault() {
    let clock_kill = KillLatch::new();
    let mut clock_risk = risk_engine::<1, 2>(limits(), 100);
    mark(&mut clock_risk, 1, 100, 100, &clock_kill);
    let mut unsafe_request = request(1, 1, Side::Buy, 100, 1, 101);
    unsafe_request.clock_healthy = false;
    assert_eq!(
        clock_risk.authorize_order(unsafe_request, &clock_kill),
        Err(RiskError::ClockUnsafe)
    );
    assert_eq!(
        clock_kill.snapshot(),
        Some(KillSnapshot {
            code: KillCode::ClockUnsafe,
            triggered_at: TimestampNs(101),
        })
    );
    assert!(!clock_kill.trigger(KillCode::Manual, TimestampNs(999)));
    assert_eq!(
        clock_kill.snapshot().expect("first fault retained").code,
        KillCode::ClockUnsafe
    );

    let stale_kill = KillLatch::new();
    let mut stale_risk = risk_engine::<1, 2>(limits(), 100);
    mark(&mut stale_risk, 1, 100, 1_000, &stale_kill);
    assert_eq!(
        stale_risk.authorize_order(request(1, 1, Side::Buy, 100, 1, 1_101), &stale_kill,),
        Err(RiskError::StaleValuationMark {
            instrument: InstrumentId(1),
            age_ns: 101,
            max_age_ns: 100,
        })
    );
    assert_eq!(
        stale_kill.snapshot().expect("stale kill").code,
        KillCode::MarketDataGap
    );
    assert_eq!(stale_risk.order_count(), 0);
}

#[test]
fn aggregate_arithmetic_overflow_rejects_without_reserving_order() {
    let huge = RiskLimits {
        max_order_quantity: Quantity(i64::MAX),
        max_order_notional: i128::MAX,
        max_gross_notional: i128::MAX,
        max_net_notional: i128::MAX,
        max_daily_loss: i128::MAX,
        max_market_age_ns: 100,
    };
    let kill = KillLatch::new();
    let mut risk = risk_engine::<4, 4>(huge, i64::MAX);
    for instrument in 1..=4 {
        mark(&mut risk, instrument, i64::MAX, 10, &kill);
    }
    for order_id in 1..=2 {
        risk.authorize_order(
            request(
                u64::from(order_id),
                order_id,
                Side::Buy,
                i64::MAX,
                i64::MAX,
                11,
            ),
            &kill,
        )
        .expect("first two fit i128 aggregate");
    }
    assert_eq!(
        risk.authorize_order(request(3, 3, Side::Buy, i64::MAX, i64::MAX, 11), &kill,),
        Err(RiskError::ArithmeticOverflow)
    );
    assert_eq!(risk.order_count(), 2);
    assert!(risk.order(OrderId(3)).is_none());
    assert_eq!(
        kill.snapshot().expect("overflow kill").code,
        KillCode::InternalInvariant
    );
}

fn maximum_limits() -> RiskLimits {
    RiskLimits {
        max_order_quantity: Quantity(i64::MAX),
        max_order_notional: i128::MAX,
        max_gross_notional: i128::MAX,
        max_net_notional: i128::MAX,
        max_daily_loss: i128::MAX,
        max_market_age_ns: 1_000,
    }
}

#[test]
fn overflowing_mark_is_atomic_across_all_public_risk_state() {
    let kill = KillLatch::new();
    let mut risk = risk_engine::<4, 8>(maximum_limits(), i64::MAX);
    for instrument in 1..=4 {
        mark(&mut risk, instrument, 1, 10, &kill);
        risk.authorize_order(
            request(
                u64::from(instrument),
                instrument,
                Side::Buy,
                1,
                i64::MAX,
                11,
            ),
            &kill,
        )
        .expect("reservation");
        risk.on_fill(
            OrderId(u64::from(instrument)),
            PriceTicks(1),
            Quantity(i64::MAX),
            TimestampNs(12),
            &kill,
        )
        .expect("low-price fill");
    }
    risk.on_mark(
        InstrumentId(1),
        PriceTicks(i64::MAX),
        TimestampNs(20),
        TimestampNs(20),
        true,
        &kill,
    )
    .expect("first large mark fits");
    risk.on_mark(
        InstrumentId(2),
        PriceTicks(i64::MAX),
        TimestampNs(21),
        TimestampNs(21),
        true,
        &kill,
    )
    .expect("second large mark fits");

    let instrument_before = risk.instrument(InstrumentId(3));
    let exposure_before = risk.exposure();
    let pnl_before = risk.daily_pnl();
    let counts_before = (risk.instrument_count(), risk.order_count());
    assert_eq!(
        risk.on_mark(
            InstrumentId(3),
            PriceTicks(i64::MAX),
            TimestampNs(22),
            TimestampNs(22),
            true,
            &kill,
        ),
        Err(RiskError::ArithmeticOverflow)
    );
    assert_eq!(risk.instrument(InstrumentId(3)), instrument_before);
    assert_eq!(risk.exposure(), exposure_before);
    assert_eq!(risk.daily_pnl(), pnl_before);
    assert_eq!((risk.instrument_count(), risk.order_count()), counts_before);
    assert_eq!(
        kill.snapshot().expect("overflow kill").code,
        KillCode::InternalInvariant
    );
}

#[test]
fn overflowing_fill_is_atomic_across_inventory_order_and_aggregates() {
    let kill = KillLatch::new();
    let mut risk = risk_engine::<3, 6>(maximum_limits(), i64::MAX);
    for instrument in 1..=3 {
        mark(&mut risk, instrument, 1, 10, &kill);
    }
    for instrument in 1..=2 {
        risk.authorize_order(
            request(
                u64::from(instrument),
                instrument,
                Side::Buy,
                i64::MAX,
                i64::MAX,
                11,
            ),
            &kill,
        )
        .expect("large reservation");
        risk.on_fill(
            OrderId(u64::from(instrument)),
            PriceTicks(i64::MAX),
            Quantity(i64::MAX),
            TimestampNs(12),
            &kill,
        )
        .expect("first two aggregate fills fit");
    }
    risk.authorize_order(request(3, 3, Side::Buy, i64::MAX, i64::MAX, 13), &kill)
        .expect("third reservation fits before fill P&L");

    let instrument_before = risk.instrument(InstrumentId(3));
    let order_before = risk.order(OrderId(3));
    let exposure_before = risk.exposure();
    let pnl_before = risk.daily_pnl();
    let counts_before = (risk.instrument_count(), risk.order_count());
    let realized_before = risk.lifetime_realized_pnl();
    assert_eq!(
        risk.on_fill(
            OrderId(3),
            PriceTicks(i64::MAX),
            Quantity(i64::MAX),
            TimestampNs(14),
            &kill,
        ),
        Err(RiskError::ArithmeticOverflow)
    );
    assert_eq!(risk.instrument(InstrumentId(3)), instrument_before);
    assert_eq!(risk.order(OrderId(3)), order_before);
    assert_eq!(risk.exposure(), exposure_before);
    assert_eq!(risk.daily_pnl(), pnl_before);
    assert_eq!((risk.instrument_count(), risk.order_count()), counts_before);
    assert_eq!(risk.lifetime_realized_pnl(), realized_before);
    assert_eq!(
        kill.snapshot().expect("overflow kill").code,
        KillCode::InternalInvariant
    );
}

#[test]
fn mark_to_market_loss_triggers_monotonic_loss_kill() {
    let mut loss_limits = limits();
    loss_limits.max_daily_loss = 100;
    let kill = KillLatch::new();
    let mut risk = risk_engine::<1, 2>(loss_limits, 100);
    mark(&mut risk, 1, 100, 100, &kill);
    risk.authorize_order(request(1, 1, Side::Buy, 100, 10, 101), &kill)
        .expect("approved");
    risk.on_fill(
        OrderId(1),
        PriceTicks(100),
        Quantity(10),
        TimestampNs(102),
        &kill,
    )
    .expect("fill");
    let outcome = risk
        .on_mark(
            InstrumentId(1),
            PriceTicks(89),
            TimestampNs(110),
            TimestampNs(110),
            true,
            &kill,
        )
        .expect("loss mark applies");
    assert_eq!(outcome.daily_pnl, -110);
    assert!(outcome.loss_limit_breached);
    assert!(outcome.kill_triggered);
    assert_eq!(
        kill.snapshot().expect("loss kill").code,
        KillCode::LossLimit
    );
    assert!(!kill.trigger(KillCode::Manual, TimestampNs(200)));
    assert_eq!(
        kill.snapshot().expect("first kill").code,
        KillCode::LossLimit
    );
}

#[test]
fn heterogeneous_tick_values_and_contract_multipliers_share_base_units() {
    let kill = KillLatch::new();
    let mut risk = RiskEngine::<2, 4>::new(limits(), RiskSessionId(1)).expect("risk");
    risk.register_instrument(definition(1, 2, 5, 100))
        .expect("scale ten");
    risk.register_instrument(definition(2, 3, 4, 100))
        .expect("scale twelve");
    mark(&mut risk, 1, 100, 100, &kill);
    mark(&mut risk, 2, 50, 100, &kill);
    risk.authorize_order(request(1, 1, Side::Buy, 100, 2, 101), &kill)
        .expect("base-normalized buy");
    risk.authorize_order(request(2, 2, Side::Sell, 50, 3, 101), &kill)
        .expect("base-normalized sell");
    assert_eq!(
        risk.exposure().expect("reserved exposure").gross_notional,
        3_800
    );
    assert_eq!(
        risk.exposure().expect("reserved exposure").net_notional,
        2_000
    );
    risk.on_fill(
        OrderId(1),
        PriceTicks(100),
        Quantity(2),
        TimestampNs(102),
        &kill,
    )
    .expect("buy fill");
    risk.on_fill(
        OrderId(2),
        PriceTicks(50),
        Quantity(3),
        TimestampNs(102),
        &kill,
    )
    .expect("sell fill");
    assert_eq!(
        risk.instrument(InstrumentId(1))
            .expect("one")
            .signed_position_cost,
        2_000
    );
    assert_eq!(
        risk.instrument(InstrumentId(2))
            .expect("two")
            .signed_position_cost,
        -1_800
    );
    mark(&mut risk, 1, 101, 110, &kill);
    mark(&mut risk, 2, 49, 110, &kill);
    assert_eq!(risk.daily_pnl(), Ok(56));
    let exposure = risk.exposure().expect("marked exposure");
    assert_eq!(exposure.gross_notional, 3_784);
    assert_eq!(exposure.net_notional, 256);
}

#[test]
fn registration_rejects_cross_currency_dynamic_fx_and_scale_overflow_atomically() {
    let mut risk = RiskEngine::<3, 2>::new(limits(), RiskSessionId(1)).expect("risk");
    risk.register_instrument(definition(1, 1, 1, 10))
        .expect("base");
    let count_before = risk.instrument_count();
    let currency_before = risk.base_currency();
    let euro = InstrumentRiskDefinition {
        base_currency: CurrencyId(978),
        ..definition(2, 1, 1, 10)
    };
    assert_eq!(
        risk.register_instrument(euro),
        Err(RiskError::CurrencyMismatch {
            expected: BASE_CURRENCY,
            received: CurrencyId(978),
        })
    );
    let dynamic = InstrumentRiskDefinition {
        valuation: InstrumentValuation::DynamicFxUnsupported,
        ..definition(2, 1, 1, 10)
    };
    assert_eq!(
        risk.register_instrument(dynamic),
        Err(RiskError::UnsupportedDynamicFx(InstrumentId(2)))
    );
    assert_eq!(
        risk.register_instrument(definition(2, i128::MAX, 2, 10)),
        Err(RiskError::ArithmeticOverflow)
    );
    assert_eq!(risk.instrument_count(), count_before);
    assert_eq!(risk.base_currency(), currency_before);
    assert!(risk.definition(InstrumentId(2)).is_none());
}

#[test]
fn unregistered_and_unmarked_instruments_fail_before_state_changes() {
    let mark_kill = KillLatch::new();
    let mut unregistered = RiskEngine::<1, 1>::new(limits(), RiskSessionId(1)).expect("risk");
    assert_eq!(
        unregistered.on_mark(
            InstrumentId(1),
            PriceTicks(100),
            TimestampNs(1),
            TimestampNs(1),
            true,
            &mark_kill,
        ),
        Err(RiskError::UnknownInstrument(InstrumentId(1)))
    );
    assert_eq!(unregistered.instrument_count(), 0);
    let order_kill = KillLatch::new();
    let mut unmarked = RiskEngine::<1, 1>::new(limits(), RiskSessionId(1)).expect("risk");
    unmarked
        .register_instrument(definition(1, 1, 1, 10))
        .expect("definition");
    assert_eq!(
        unmarked.authorize_order(request(1, 1, Side::Buy, 100, 1, 1), &order_kill),
        Err(RiskError::MissingValuationMark(InstrumentId(1)))
    );
    assert_eq!(unmarked.order_count(), 0);
}

#[test]
fn every_active_instrument_requires_a_fresh_nonfuture_mark_before_reservation() {
    let stale_kill = KillLatch::new();
    let mut stale = risk_engine::<2, 4>(limits(), 100);
    mark(&mut stale, 1, 100, 1_000, &stale_kill);
    mark(&mut stale, 2, 100, 1_000, &stale_kill);
    stale
        .authorize_order(request(2, 2, Side::Buy, 100, 1, 1_001), &stale_kill)
        .expect("second instrument active");
    mark(&mut stale, 1, 100, 1_101, &stale_kill);
    assert_eq!(
        stale.authorize_order(request(1, 1, Side::Buy, 100, 1, 1_101), &stale_kill),
        Err(RiskError::StaleValuationMark {
            instrument: InstrumentId(2),
            age_ns: 101,
            max_age_ns: 100,
        })
    );
    assert!(stale.order(OrderId(1)).is_none());
    assert!(stale.order(OrderId(2)).is_some());
    assert_eq!(
        stale_kill.snapshot().expect("stale exposure kill").code,
        KillCode::MarketDataGap
    );

    let future_kill = KillLatch::new();
    let mut future = risk_engine::<2, 4>(limits(), 100);
    mark(&mut future, 1, 100, 2_000, &future_kill);
    mark(&mut future, 2, 100, 2_001, &future_kill);
    future
        .authorize_order(request(2, 2, Side::Buy, 100, 1, 2_001), &future_kill)
        .expect("future-mark instrument active at its timestamp");
    assert_eq!(
        future.authorize_order(request(1, 1, Side::Buy, 100, 1, 2_000), &future_kill),
        Err(RiskError::FutureValuationMark {
            instrument: InstrumentId(2),
            market: TimestampNs(2_001),
            now: TimestampNs(2_000),
        })
    );
    assert!(future.order(OrderId(1)).is_none());
    assert!(future.order(OrderId(2)).is_some());
    assert_eq!(
        future_kill.snapshot().expect("future exposure kill").code,
        KillCode::ClockUnsafe
    );
}

#[test]
fn session_roll_rebaselines_carried_inventory_without_erasing_lifetime_cost() {
    assert!(matches!(
        RiskEngine::<1, 1>::new(limits(), RiskSessionId(0)),
        Err(RiskError::InvalidSessionId)
    ));

    let kill = KillLatch::new();
    let mut risk = RiskEngine::<1, 2>::new(limits(), RiskSessionId(10)).expect("risk");
    risk.register_instrument(definition(1, 2, 5, 100))
        .expect("ten base units per tick-contract");
    mark(&mut risk, 1, 100, 100, &kill);
    risk.authorize_order(request(1, 1, Side::Buy, 100, 2, 101), &kill)
        .expect("buy");
    risk.on_fill(
        OrderId(1),
        PriceTicks(100),
        Quantity(2),
        TimestampNs(102),
        &kill,
    )
    .expect("fill");
    mark(&mut risk, 1, 110, 110, &kill);
    assert_eq!(risk.daily_pnl(), Ok(200));
    let carried = risk.instrument(InstrumentId(1)).expect("carried inventory");

    let roll = risk
        .roll_session(RiskSessionId(11), TimestampNs(110), true, &kill)
        .expect("fresh session roll");
    assert_eq!(roll.previous_session, RiskSessionId(10));
    assert_eq!(roll.current_session, RiskSessionId(11));
    assert_eq!(roll.lifetime_pnl_baseline_base_units, 200);
    assert_eq!(risk.daily_pnl(), Ok(0));
    let after_roll = risk
        .instrument(InstrumentId(1))
        .expect("inventory retained");
    assert_eq!(after_roll.position, carried.position);
    assert_eq!(
        after_roll.signed_position_cost,
        carried.signed_position_cost
    );

    mark(&mut risk, 1, 115, 120, &kill);
    assert_eq!(risk.daily_pnl(), Ok(100));
    assert_eq!(
        risk.roll_session(RiskSessionId(11), TimestampNs(120), true, &kill),
        Err(RiskError::NonMonotonicSession {
            current: RiskSessionId(11),
            requested: RiskSessionId(11),
        })
    );
    assert_eq!(risk.session_id(), RiskSessionId(11));
    assert_eq!(risk.session_baseline_pnl(), 200);
    assert_eq!(risk.daily_pnl(), Ok(100));
}

#[test]
fn fees_rebates_and_funding_are_checked_base_currency_accounting_facts() {
    let mut loss_limits = limits();
    loss_limits.max_daily_loss = 100;
    let kill = KillLatch::new();
    let mut risk = risk_engine::<1, 1>(loss_limits, 10);

    let fee = risk
        .apply_adjustment(
            RiskAdjustment {
                currency: BASE_CURRENCY,
                kind: RiskAdjustmentKind::Fee,
                amount_base_units: 101,
            },
            TimestampNs(10),
            true,
            &kill,
        )
        .expect("valid fee commits");
    assert_eq!(fee.applied_delta_base_units, -101);
    assert_eq!(fee.session_pnl_base_units, -101);
    assert!(fee.loss_limit_breached);
    assert!(fee.kill_triggered);
    assert_eq!(
        kill.snapshot().expect("fee loss kill").code,
        KillCode::LossLimit
    );

    let rebate = risk
        .apply_adjustment(
            RiskAdjustment {
                currency: BASE_CURRENCY,
                kind: RiskAdjustmentKind::Rebate,
                amount_base_units: 11,
            },
            TimestampNs(11),
            true,
            &kill,
        )
        .expect("accounting fact applies after kill");
    assert_eq!(rebate.session_pnl_base_units, -90);
    let funding = risk
        .apply_adjustment(
            RiskAdjustment {
                currency: BASE_CURRENCY,
                kind: RiskAdjustmentKind::Funding,
                amount_base_units: -10,
            },
            TimestampNs(12),
            true,
            &kill,
        )
        .expect("signed funding");
    assert_eq!(funding.session_pnl_base_units, -100);
    assert_eq!(risk.lifetime_adjustments(), -100);

    let before = risk.lifetime_adjustments();
    assert_eq!(
        risk.apply_adjustment(
            RiskAdjustment {
                currency: CurrencyId(978),
                kind: RiskAdjustmentKind::Fee,
                amount_base_units: 1,
            },
            TimestampNs(13),
            true,
            &kill,
        ),
        Err(RiskError::CurrencyMismatch {
            expected: BASE_CURRENCY,
            received: CurrencyId(978),
        })
    );
    assert_eq!(risk.lifetime_adjustments(), before);

    let fact_kill = KillLatch::new();
    let mut carried = risk_engine::<1, 2>(limits(), 10);
    mark(&mut carried, 1, 100, 100, &fact_kill);
    carried
        .authorize_order(request(1, 1, Side::Buy, 100, 1, 101), &fact_kill)
        .expect("buy");
    carried
        .on_fill(
            OrderId(1),
            PriceTicks(100),
            Quantity(1),
            TimestampNs(102),
            &fact_kill,
        )
        .expect("fill");
    assert!(fact_kill.trigger(KillCode::Manual, TimestampNs(150)));
    let post_kill_fact = carried
        .apply_adjustment(
            RiskAdjustment {
                currency: BASE_CURRENCY,
                kind: RiskAdjustmentKind::Funding,
                amount_base_units: -1,
            },
            TimestampNs(1_000),
            true,
            &fact_kill,
        )
        .expect("accounting converges despite a kill and an old position mark");
    assert_eq!(post_kill_fact.session_pnl_base_units, -1);
    assert_eq!(carried.lifetime_adjustments(), -1);
    assert_eq!(
        fact_kill.snapshot().expect("first kill retained").code,
        KillCode::Manual
    );
}

#[test]
fn adjustment_overflow_and_stale_session_roll_are_atomic() {
    let overflow_kill = KillLatch::new();
    let mut overflow = risk_engine::<1, 1>(maximum_limits(), i64::MAX);
    overflow
        .apply_adjustment(
            RiskAdjustment {
                currency: BASE_CURRENCY,
                kind: RiskAdjustmentKind::Rebate,
                amount_base_units: i128::MAX,
            },
            TimestampNs(1),
            true,
            &overflow_kill,
        )
        .expect("maximum adjustment");
    assert_eq!(
        overflow.apply_adjustment(
            RiskAdjustment {
                currency: BASE_CURRENCY,
                kind: RiskAdjustmentKind::Rebate,
                amount_base_units: 1,
            },
            TimestampNs(2),
            true,
            &overflow_kill,
        ),
        Err(RiskError::ArithmeticOverflow)
    );
    assert_eq!(overflow.lifetime_adjustments(), i128::MAX);
    assert_eq!(overflow.daily_pnl(), Ok(i128::MAX));

    let stale_kill = KillLatch::new();
    let mut stale = risk_engine::<1, 2>(limits(), 100);
    mark(&mut stale, 1, 100, 1_000, &stale_kill);
    stale
        .authorize_order(request(1, 1, Side::Buy, 100, 1, 1_001), &stale_kill)
        .expect("active reservation");
    assert_eq!(
        stale.roll_session(RiskSessionId(2), TimestampNs(1_101), true, &stale_kill),
        Err(RiskError::StaleValuationMark {
            instrument: InstrumentId(1),
            age_ns: 101,
            max_age_ns: 100,
        })
    );
    assert_eq!(stale.session_id(), RiskSessionId(1));
    assert_eq!(stale.session_baseline_pnl(), 0);
    assert_eq!(stale.order_count(), 1);
}

fn adverse_config() -> AdverseConfig {
    AdverseConfig {
        markout_horizon_ns: 10,
        rolling_window_ns: 100,
        breach_markout_ticks: 2,
        halt_after_consecutive: 2,
        halt_aggregate_loss: 1_000,
        kill_after_consecutive: 3,
        kill_aggregate_loss: 2_000,
    }
}

fn adverse_fill(
    execution_id: u64,
    instrument: u32,
    side: Side,
    price: i64,
    quantity: i64,
    timestamp: u64,
) -> AdverseFill {
    AdverseFill {
        execution_id,
        instrument: InstrumentId(instrument),
        side,
        fill_price: PriceTicks(price),
        quantity: Quantity(quantity),
        fill_timestamp: TimestampNs(timestamp),
    }
}

#[test]
fn buy_and_sell_markouts_are_signed_from_the_fill_side() {
    let kill = KillLatch::new();
    let mut monitor = AdverseMonitor::<2, 4>::new(adverse_config()).expect("valid config");
    monitor
        .on_fill(
            adverse_fill(1, 1, Side::Buy, 100, 10, 1),
            TimestampNs(1),
            &kill,
        )
        .expect("buy tracked");
    let buy = monitor
        .on_mark(
            InstrumentId(1),
            PriceTicks(97),
            TimestampNs(11),
            TimestampNs(11),
            &kill,
        )
        .expect("buy markout");
    assert_eq!(buy.weighted_markout_delta, -30);
    let buy_fill = monitor.fill(1).expect("evaluated buy");
    assert_eq!(buy_fill.signed_markout_ticks, Some(-3));

    monitor
        .on_fill(
            adverse_fill(2, 2, Side::Sell, 100, 10, 12),
            TimestampNs(12),
            &kill,
        )
        .expect("sell tracked");
    let sell = monitor
        .on_mark(
            InstrumentId(2),
            PriceTicks(103),
            TimestampNs(22),
            TimestampNs(22),
            &kill,
        )
        .expect("sell markout");
    assert_eq!(sell.weighted_markout_delta, -30);
    assert_eq!(
        monitor
            .fill(2)
            .expect("evaluated sell")
            .signed_markout_ticks,
        Some(-3)
    );
    assert!(!kill.is_triggered());
}

#[test]
fn consecutive_adverse_fills_halt_instrument_then_escalate_global_kill() {
    let kill = KillLatch::new();
    let mut monitor = AdverseMonitor::<1, 4>::new(adverse_config()).expect("valid config");
    for execution_id in 1..=2 {
        monitor
            .on_fill(
                adverse_fill(execution_id, 1, Side::Buy, 100, 10, execution_id),
                TimestampNs(execution_id),
                &kill,
            )
            .expect("fill tracked");
    }
    let halt = monitor
        .on_mark(
            InstrumentId(1),
            PriceTicks(97),
            TimestampNs(12),
            TimestampNs(12),
            &kill,
        )
        .expect("halt mark");
    assert_eq!(halt.evaluated_fills, 2);
    assert_eq!(halt.consecutive_breaches, 2);
    assert!(halt.halt_triggered);
    assert!(monitor.is_halted(InstrumentId(1)));
    assert!(!kill.is_triggered());

    monitor
        .on_fill(
            adverse_fill(3, 1, Side::Buy, 100, 10, 13),
            TimestampNs(13),
            &kill,
        )
        .expect("fills remain tracked while locally halted");
    let escalation = monitor
        .on_mark(
            InstrumentId(1),
            PriceTicks(97),
            TimestampNs(23),
            TimestampNs(23),
            &kill,
        )
        .expect("escalation mark");
    assert_eq!(escalation.consecutive_breaches, 3);
    assert!(escalation.global_kill_triggered);
    assert_eq!(
        kill.snapshot().expect("adverse kill").code,
        KillCode::AdverseSelection
    );
}

#[test]
fn aggregate_markout_halts_before_more_severe_global_threshold() {
    let config = AdverseConfig {
        halt_after_consecutive: 50,
        halt_aggregate_loss: 50,
        kill_after_consecutive: 100,
        kill_aggregate_loss: 100,
        ..adverse_config()
    };
    let kill = KillLatch::new();
    let mut monitor = AdverseMonitor::<1, 3>::new(config).expect("valid config");
    monitor
        .on_fill(
            adverse_fill(1, 1, Side::Buy, 100, 20, 1),
            TimestampNs(1),
            &kill,
        )
        .expect("fill one");
    let local = monitor
        .on_mark(
            InstrumentId(1),
            PriceTicks(97),
            TimestampNs(11),
            TimestampNs(11),
            &kill,
        )
        .expect("local aggregate breach");
    assert_eq!(local.rolling_weighted_markout, -60);
    assert!(local.instrument_halted);
    assert!(!kill.is_triggered());

    monitor
        .on_fill(
            adverse_fill(2, 1, Side::Buy, 100, 20, 12),
            TimestampNs(12),
            &kill,
        )
        .expect("fill two");
    let global = monitor
        .on_mark(
            InstrumentId(1),
            PriceTicks(97),
            TimestampNs(22),
            TimestampNs(22),
            &kill,
        )
        .expect("global aggregate breach");
    assert_eq!(global.rolling_weighted_markout, -120);
    assert!(global.global_kill_triggered);
}

#[test]
fn bounded_fill_capacity_fails_closed_and_rolling_records_expire() {
    let capacity_kill = KillLatch::new();
    let mut full = AdverseMonitor::<1, 1>::new(adverse_config()).expect("valid config");
    full.on_fill(
        adverse_fill(1, 1, Side::Buy, 100, 1, 1),
        TimestampNs(1),
        &capacity_kill,
    )
    .expect("first fill");
    assert_eq!(
        full.on_fill(
            adverse_fill(2, 1, Side::Buy, 100, 1, 2),
            TimestampNs(2),
            &capacity_kill,
        ),
        Err(AdverseError::FillCapacity { capacity: 1 })
    );
    assert_eq!(
        capacity_kill.snapshot().expect("capacity kill").code,
        KillCode::InternalInvariant
    );

    let expiry_kill = KillLatch::new();
    let mut expiry = AdverseMonitor::<1, 1>::new(adverse_config()).expect("valid config");
    expiry
        .on_fill(
            adverse_fill(1, 1, Side::Buy, 100, 1, 1),
            TimestampNs(1),
            &expiry_kill,
        )
        .expect("fill");
    expiry
        .on_mark(
            InstrumentId(1),
            PriceTicks(101),
            TimestampNs(11),
            TimestampNs(11),
            &expiry_kill,
        )
        .expect("evaluation");
    assert_eq!(expiry.tracked_fill_count(), 1);
    let expired = expiry
        .on_mark(
            InstrumentId(1),
            PriceTicks(101),
            TimestampNs(112),
            TimestampNs(112),
            &expiry_kill,
        )
        .expect("expiry");
    assert_eq!(expired.rolling_weighted_markout, 0);
    assert_eq!(expiry.tracked_fill_count(), 0);
}

#[test]
fn local_adverse_halt_is_an_explicit_pretrade_gate() {
    let kill = KillLatch::new();
    let mut monitor = AdverseMonitor::<1, 2>::new(adverse_config()).expect("valid config");
    for execution_id in 1..=2 {
        monitor
            .on_fill(
                adverse_fill(execution_id, 1, Side::Buy, 100, 1, execution_id),
                TimestampNs(execution_id),
                &kill,
            )
            .expect("fill");
    }
    monitor
        .on_mark(
            InstrumentId(1),
            PriceTicks(97),
            TimestampNs(12),
            TimestampNs(12),
            &kill,
        )
        .expect("local halt");
    assert!(!kill.is_triggered());

    let mut risk = risk_engine::<1, 2>(limits(), 100);
    mark(&mut risk, 1, 100, 10, &kill);
    let mut halted_request = request(1, 1, Side::Buy, 100, 1, 11);
    halted_request.instrument_halted = monitor.is_halted(InstrumentId(1));
    assert_eq!(
        risk.authorize_order(halted_request, &kill),
        Err(RiskError::InstrumentHalted(InstrumentId(1)))
    );
    assert_eq!(risk.order_count(), 0);
}

#[test]
fn zero_instrument_identity_is_rejected_without_creating_state() {
    let mark_kill = KillLatch::new();
    let mut mark_risk = RiskEngine::<1, 1>::new(limits(), RiskSessionId(1)).expect("risk");
    assert_eq!(
        mark_risk.on_mark(
            InstrumentId(0),
            PriceTicks(100),
            TimestampNs(1),
            TimestampNs(1),
            true,
            &mark_kill,
        ),
        Err(RiskError::InvalidInstrumentId)
    );
    assert_eq!(mark_risk.instrument_count(), 0);

    let order_kill = KillLatch::new();
    let mut order_risk = RiskEngine::<1, 1>::new(limits(), RiskSessionId(1)).expect("risk");
    assert_eq!(
        order_risk.authorize_order(request(1, 0, Side::Buy, 100, 1, 1), &order_kill,),
        Err(RiskError::InvalidInstrumentId)
    );
    assert_eq!(order_risk.order_count(), 0);

    let fill_kill = KillLatch::new();
    let mut fill_monitor = AdverseMonitor::<1, 1>::new(adverse_config()).expect("monitor");
    assert_eq!(
        fill_monitor.on_fill(
            adverse_fill(1, 0, Side::Buy, 100, 1, 1),
            TimestampNs(1),
            &fill_kill,
        ),
        Err(AdverseError::InvalidInstrumentId)
    );
    assert_eq!(fill_monitor.instrument_count(), 0);
    assert_eq!(fill_monitor.tracked_fill_count(), 0);

    let adverse_mark_kill = KillLatch::new();
    let mut mark_monitor = AdverseMonitor::<1, 1>::new(adverse_config()).expect("monitor");
    assert_eq!(
        mark_monitor.on_mark(
            InstrumentId(0),
            PriceTicks(100),
            TimestampNs(1),
            TimestampNs(1),
            &adverse_mark_kill,
        ),
        Err(AdverseError::InvalidInstrumentId)
    );
    assert_eq!(mark_monitor.instrument_count(), 0);
}

#[test]
fn adverse_fill_rejects_zero_future_and_regressing_clock_without_mutation() {
    let zero_kill = KillLatch::new();
    let mut zero = AdverseMonitor::<1, 2>::new(adverse_config()).expect("monitor");
    assert_eq!(
        zero.on_fill(
            adverse_fill(1, 1, Side::Buy, 100, 1, 0),
            TimestampNs(1),
            &zero_kill,
        ),
        Err(AdverseError::ZeroFillTimestamp)
    );
    assert_eq!(zero.tracked_fill_count(), 0);
    assert_eq!(zero.instrument_count(), 0);
    assert_eq!(zero.last_event_timestamp(), None);

    let future_kill = KillLatch::new();
    let mut future = AdverseMonitor::<1, 2>::new(adverse_config()).expect("monitor");
    assert_eq!(
        future.on_fill(
            adverse_fill(1, 1, Side::Buy, 100, 1, 2),
            TimestampNs(1),
            &future_kill,
        ),
        Err(AdverseError::FutureFillTimestamp {
            fill: TimestampNs(2),
            now: TimestampNs(1),
        })
    );
    assert_eq!(future.tracked_fill_count(), 0);
    assert_eq!(future.instrument_count(), 0);
    assert_eq!(future.last_event_timestamp(), None);

    let regression_kill = KillLatch::new();
    let mut regression = AdverseMonitor::<1, 2>::new(adverse_config()).expect("monitor");
    regression
        .on_fill(
            adverse_fill(1, 1, Side::Buy, 100, 1, 1),
            TimestampNs(1),
            &regression_kill,
        )
        .expect("valid fill");
    regression
        .on_mark(
            InstrumentId(1),
            PriceTicks(100),
            TimestampNs(2),
            TimestampNs(2),
            &regression_kill,
        )
        .expect("valid mark");
    let fill_before = regression.fill(1);
    let instrument_before = regression.instrument(InstrumentId(1));
    assert_eq!(
        regression.on_fill(
            adverse_fill(2, 1, Side::Buy, 100, 1, 1),
            TimestampNs::ZERO,
            &regression_kill,
        ),
        Err(AdverseError::ZeroEventTimestamp)
    );
    assert_eq!(regression.fill(1), fill_before);
    assert_eq!(regression.fill(2), None);
    assert_eq!(regression.instrument(InstrumentId(1)), instrument_before);
    assert_eq!(regression.last_event_timestamp(), Some(TimestampNs(2)));
}

#[test]
fn adverse_overflow_is_atomic_and_linear_work_is_observable() {
    let overflow_config = AdverseConfig {
        markout_horizon_ns: 1,
        rolling_window_ns: 100,
        breach_markout_ticks: i64::MAX,
        halt_after_consecutive: u32::MAX,
        halt_aggregate_loss: i128::MAX,
        kill_after_consecutive: u32::MAX,
        kill_aggregate_loss: i128::MAX,
    };
    let overflow_kill = KillLatch::new();
    let mut overflow = AdverseMonitor::<1, 4>::new(overflow_config).expect("monitor");
    for execution_id in 1..=3 {
        overflow
            .on_fill(
                adverse_fill(execution_id, 1, Side::Buy, i64::MAX, i64::MAX, 1),
                TimestampNs(1),
                &overflow_kill,
            )
            .expect("pending huge fill");
    }
    let fills_before = [overflow.fill(1), overflow.fill(2), overflow.fill(3)];
    let instrument_before = overflow.instrument(InstrumentId(1));
    let count_before = overflow.tracked_fill_count();
    let clock_before = overflow.last_event_timestamp();
    assert_eq!(
        overflow.on_mark(
            InstrumentId(1),
            PriceTicks(1),
            TimestampNs(2),
            TimestampNs(2),
            &overflow_kill,
        ),
        Err(AdverseError::ArithmeticOverflow)
    );
    assert_eq!(
        [overflow.fill(1), overflow.fill(2), overflow.fill(3)],
        fills_before
    );
    assert_eq!(overflow.instrument(InstrumentId(1)), instrument_before);
    assert_eq!(overflow.tracked_fill_count(), count_before);
    assert_eq!(overflow.last_event_timestamp(), clock_before);
    assert_eq!(
        overflow_kill.snapshot().expect("overflow kill").code,
        KillCode::InternalInvariant
    );

    let work_kill = KillLatch::new();
    let mut work = AdverseMonitor::<1, 8>::new(adverse_config()).expect("monitor");
    for execution_id in 1..=6 {
        work.on_fill(
            adverse_fill(execution_id, 1, Side::Buy, 100, 1, execution_id),
            TimestampNs(execution_id),
            &work_kill,
        )
        .expect("fill");
    }
    let outcome = work
        .on_mark(
            InstrumentId(1),
            PriceTicks(101),
            TimestampNs(16),
            TimestampNs(16),
            &work_kill,
        )
        .expect("bounded evaluation");
    assert_eq!(outcome.evaluated_fills, 6);
    assert_eq!(outcome.work_units, 12);
    assert!(outcome.work_units <= 2 * 8);
}

#[test]
fn cross_instrument_time_cannot_evict_losses_without_a_same_instrument_frontier() {
    let config = AdverseConfig {
        markout_horizon_ns: 1,
        rolling_window_ns: 5,
        ..adverse_config()
    };
    let kill = KillLatch::new();
    let mut monitor = AdverseMonitor::<3, 2>::new(config).expect("monitor");
    monitor
        .on_fill(
            adverse_fill(1, 1, Side::Buy, 100, 1, 1),
            TimestampNs(1),
            &kill,
        )
        .expect("first fill");
    monitor
        .on_mark(
            InstrumentId(1),
            PriceTicks(101),
            TimestampNs(2),
            TimestampNs(2),
            &kill,
        )
        .expect("first evaluation");
    monitor
        .on_fill(
            adverse_fill(2, 2, Side::Buy, 100, 1, 3),
            TimestampNs(3),
            &kill,
        )
        .expect("second fill");
    monitor
        .on_mark(
            InstrumentId(2),
            PriceTicks(101),
            TimestampNs(4),
            TimestampNs(4),
            &kill,
        )
        .expect("second evaluation");
    assert_eq!(monitor.tracked_fill_count(), 2);

    assert_eq!(
        monitor.on_fill(
            adverse_fill(3, 3, Side::Buy, 100, 1, 10),
            TimestampNs(10),
            &kill,
        ),
        Err(AdverseError::FillCapacity { capacity: 2 })
    );
    assert_eq!(monitor.tracked_fill_count(), 2);
    assert!(monitor.fill(1).is_some());
    assert!(monitor.fill(2).is_some());
    assert!(monitor.fill(3).is_none());

    monitor
        .on_mark(
            InstrumentId(1),
            PriceTicks(101),
            TimestampNs(8),
            TimestampNs(11),
            &kill,
        )
        .expect("same-instrument frontier expires only its own record");
    assert_eq!(monitor.tracked_fill_count(), 1);
    assert!(monitor.fill(1).is_none());
    assert!(monitor.fill(2).is_some());
    assert_eq!(
        monitor
            .instrument(InstrumentId(1))
            .expect("snapshot")
            .expect("instrument")
            .rolling_weighted_markout,
        0
    );
}
