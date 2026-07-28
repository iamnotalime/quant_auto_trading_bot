use quant_hft_core::adverse::{AdverseConfig, AdverseError, AdverseMonitor};
use quant_hft_core::kill::{KillCode, KillLatch};
use quant_hft_core::orders::{
    CancelConfirmed, CancelReason, CancelRejected, ExecutionPriceViolation, FillReport,
    LifecycleEvent, ManagedOrderState, NewAccepted, NewOrderRequest, NewRejected, OrderEconomics,
    OrderError, OrderManager, VenueOrderIdentity,
};
use quant_hft_core::risk::{
    CurrencyId, InstrumentRiskDefinition, InstrumentValuation, RiskAdjustment, RiskAdjustmentKind,
    RiskEngine, RiskError, RiskLimits, RiskSessionId,
};
use quant_hft_core::types::{
    InstrumentId, OrderId, PriceTicks, Quantity, Sequence, Side, TimestampNs,
};
use quant_hft_core::venue::{ClientOrderId, TradeId, VenueOrderId};

const INSTRUMENT: InstrumentId = InstrumentId(7);
const PRICE: PriceTicks = PriceTicks(100);

type TestAdverse = AdverseMonitor<4, 16>;
type TestOrders = OrderManager<16, 16>;

fn limits() -> RiskLimits {
    RiskLimits {
        max_order_quantity: Quantity(1_000),
        max_order_notional: 1_000_000,
        max_gross_notional: 10_000_000,
        max_net_notional: 10_000_000,
        max_daily_loss: 1_000_000,
        max_market_age_ns: 10_000,
    }
}

fn adverse_config() -> AdverseConfig {
    AdverseConfig {
        markout_horizon_ns: 100,
        rolling_window_ns: 1_000,
        breach_markout_ticks: 2,
        halt_after_consecutive: 3,
        halt_aggregate_loss: 100,
        kill_after_consecutive: 5,
        kill_aggregate_loss: 1_000,
    }
}

fn seeded_risk<const MAX_ORDERS: usize>(kill: &KillLatch) -> RiskEngine<4, MAX_ORDERS> {
    let mut risk = RiskEngine::new(limits(), RiskSessionId(1)).unwrap();
    risk.register_instrument(InstrumentRiskDefinition {
        instrument: INSTRUMENT,
        base_currency: CurrencyId(840),
        valuation: InstrumentValuation::Fixed {
            base_units_per_price_tick: 1,
            contract_multiplier: 1,
        },
        position_limit: Quantity(10_000),
    })
    .unwrap();
    risk.on_mark(
        INSTRUMENT,
        PRICE,
        TimestampNs(100),
        TimestampNs(100),
        true,
        kill,
    )
    .unwrap();
    risk
}

fn economics(client: u64, quantity: i64) -> OrderEconomics {
    OrderEconomics {
        client_order_id: ClientOrderId(client),
        instrument: INSTRUMENT,
        side: Side::Buy,
        limit_price: PRICE,
        original_quantity: Quantity(quantity),
    }
}

fn identity(client: u64, venue: u64, quantity: i64) -> VenueOrderIdentity {
    VenueOrderIdentity {
        economics: economics(client, quantity),
        venue_order_id: VenueOrderId(venue),
    }
}

fn prepare<
    const MAX_ORDERS: usize,
    const MAX_TRADES: usize,
    const MAX_RISK_ORDERS: usize,
    const MAX_FILLS: usize,
>(
    orders: &mut OrderManager<MAX_ORDERS, MAX_TRADES>,
    risk: &mut RiskEngine<4, MAX_RISK_ORDERS>,
    adverse: &AdverseMonitor<4, MAX_FILLS>,
    kill: &KillLatch,
    client: u64,
    quantity: i64,
) {
    orders
        .prepare_new(
            NewOrderRequest {
                client_order_id: ClientOrderId(client),
                risk_order_id: OrderId(client),
                instrument: INSTRUMENT,
                side: Side::Buy,
                limit_price: PRICE,
                quantity: Quantity(quantity),
                now: TimestampNs(110),
                clock_healthy: true,
            },
            risk,
            adverse,
            kill,
        )
        .unwrap();
}

fn accept<const MAX_ORDERS: usize, const MAX_TRADES: usize, const MAX_RISK_ORDERS: usize>(
    orders: &mut OrderManager<MAX_ORDERS, MAX_TRADES>,
    risk: &RiskEngine<4, MAX_RISK_ORDERS>,
    kill: &KillLatch,
    client: u64,
    venue: u64,
    quantity: i64,
) {
    orders
        .mark_new_transmitted(ClientOrderId(client), TimestampNs(111), kill)
        .unwrap();
    orders
        .on_new_accepted(
            NewAccepted {
                order: identity(client, venue, quantity),
                sequence: Sequence(1),
                leaves_quantity: Quantity(quantity),
                received_at: TimestampNs(120),
            },
            risk,
            kill,
        )
        .unwrap();
}

fn fill(
    client: u64,
    venue: u64,
    original: i64,
    sequence: u64,
    trade: u64,
    quantity: i64,
    leaves: i64,
) -> FillReport {
    FillReport {
        order: identity(client, venue, original),
        sequence: Sequence(sequence),
        trade_id: TradeId(trade),
        fill_price: PRICE,
        fill_quantity: Quantity(quantity),
        leaves_quantity: Quantity(leaves),
        fill_timestamp: TimestampNs(125 + sequence),
        received_at: TimestampNs(130 + sequence),
    }
}

#[test]
fn unsent_new_can_rollback_but_transmitted_new_cannot() {
    let kill = KillLatch::new();
    let mut risk = seeded_risk::<16>(&kill);
    let adverse = TestAdverse::new(adverse_config()).unwrap();
    let mut orders = TestOrders::new().unwrap();

    prepare(&mut orders, &mut risk, &adverse, &kill, 1, 10);
    let released = orders
        .rollback_unsent_new(ClientOrderId(1), TimestampNs(112), &mut risk, &kill)
        .unwrap();
    assert_eq!(released.canceled_quantity, Quantity(10));
    assert_eq!(orders.order_count(), 0);
    assert_eq!(risk.order_count(), 0);

    prepare(&mut orders, &mut risk, &adverse, &kill, 2, 10);
    orders
        .mark_new_transmitted(ClientOrderId(2), TimestampNs(113), &kill)
        .unwrap();
    assert_eq!(
        orders.rollback_unsent_new(ClientOrderId(2), TimestampNs(114), &mut risk, &kill),
        Err(OrderError::NotProvenUnsent(LifecycleEvent::RollbackNew))
    );
    assert_eq!(risk.order_count(), 1);
    assert!(!kill.is_triggered());
}

#[test]
fn new_reject_releases_once_and_duplicate_report_kills() {
    let kill = KillLatch::new();
    let mut risk = seeded_risk::<16>(&kill);
    let adverse = TestAdverse::new(adverse_config()).unwrap();
    let mut orders = TestOrders::new().unwrap();
    prepare(&mut orders, &mut risk, &adverse, &kill, 1, 10);
    orders
        .mark_new_transmitted(ClientOrderId(1), TimestampNs(111), &kill)
        .unwrap();
    let event = NewRejected {
        order: economics(1, 10),
        sequence: Sequence(1),
        leaves_quantity: Quantity(10),
        received_at: TimestampNs(120),
    };
    orders.on_new_rejected(event, &mut risk, &kill).unwrap();
    assert_eq!(risk.order_count(), 0);
    assert_eq!(orders.order_count(), 0);
    assert_eq!(
        orders.on_new_rejected(event, &mut risk, &kill),
        Err(OrderError::UnknownClientOrder(ClientOrderId(1)))
    );
    assert_eq!(kill.snapshot().unwrap().code, KillCode::InternalInvariant);
}

#[test]
fn requested_partial_then_unsolicited_cancel_preserves_exact_leaves() {
    let kill = KillLatch::new();
    let mut risk = seeded_risk::<16>(&kill);
    let adverse = TestAdverse::new(adverse_config()).unwrap();
    let mut orders = TestOrders::new().unwrap();
    prepare(&mut orders, &mut risk, &adverse, &kill, 1, 10);
    accept(&mut orders, &risk, &kill, 1, 101, 10);

    orders
        .prepare_cancel(ClientOrderId(1), TimestampNs(121), &kill)
        .unwrap();
    orders
        .mark_cancel_transmitted(ClientOrderId(1), TimestampNs(122), &kill)
        .unwrap();
    let partial = orders
        .on_cancel_confirmed(
            CancelConfirmed {
                order: identity(1, 101, 10),
                sequence: Sequence(2),
                canceled_quantity: Quantity(4),
                leaves_quantity: Quantity(6),
                reason: CancelReason::Requested,
                received_at: TimestampNs(123),
            },
            &mut risk,
            &kill,
        )
        .unwrap();
    assert_eq!(partial.remaining_quantity, Quantity(6));
    assert!(!partial.terminal);
    assert_eq!(
        orders.order(ClientOrderId(1)).unwrap().state,
        ManagedOrderState::Live
    );
    assert_eq!(
        risk.order(OrderId(1)).unwrap().remaining_quantity,
        Quantity(6)
    );

    let terminal = orders
        .on_cancel_confirmed(
            CancelConfirmed {
                order: identity(1, 101, 10),
                sequence: Sequence(3),
                canceled_quantity: Quantity(6),
                leaves_quantity: Quantity::ZERO,
                reason: CancelReason::Unsolicited,
                received_at: TimestampNs(124),
            },
            &mut risk,
            &kill,
        )
        .unwrap();
    assert!(terminal.terminal);
    assert_eq!(orders.order_count(), 0);
    assert_eq!(risk.order_count(), 0);
}

#[test]
fn fill_before_new_ack_reconciles_and_full_fill_waits_for_ack() {
    let kill = KillLatch::new();
    let mut risk = seeded_risk::<16>(&kill);
    let mut adverse = TestAdverse::new(adverse_config()).unwrap();
    let mut orders = TestOrders::new().unwrap();
    prepare(&mut orders, &mut risk, &adverse, &kill, 1, 10);
    orders
        .mark_new_transmitted(ClientOrderId(1), TimestampNs(111), &kill)
        .unwrap();

    let partial = orders
        .on_fill(
            fill(1, 101, 10, 1, 5001, 3, 7),
            &mut risk,
            &mut adverse,
            &kill,
        )
        .unwrap();
    assert_eq!(partial.remaining_quantity, Quantity(7));
    assert_eq!(
        orders.order(ClientOrderId(1)).unwrap().state,
        ManagedOrderState::PendingNew
    );
    assert_eq!(risk.instrument(INSTRUMENT).unwrap().position, Quantity(3));
    orders
        .on_new_accepted(
            NewAccepted {
                order: identity(1, 101, 10),
                sequence: Sequence(2),
                leaves_quantity: Quantity(7),
                received_at: TimestampNs(140),
            },
            &risk,
            &kill,
        )
        .unwrap();
    assert_eq!(
        orders.order(ClientOrderId(1)).unwrap().state,
        ManagedOrderState::Live
    );

    prepare(&mut orders, &mut risk, &adverse, &kill, 2, 4);
    orders
        .mark_new_transmitted(ClientOrderId(2), TimestampNs(141), &kill)
        .unwrap();
    let full = orders
        .on_fill(
            fill(2, 102, 4, 1, 5002, 4, 0),
            &mut risk,
            &mut adverse,
            &kill,
        )
        .unwrap();
    assert!(full.retained_for_protocol_resolution);
    let retained = orders.order(ClientOrderId(2)).unwrap();
    assert_eq!(retained.remaining_quantity, Quantity::ZERO);
    assert!(!retained.risk_reservation_active);
    assert!(risk.order(OrderId(2)).is_none());
    assert_eq!(
        orders.on_new_accepted(
            NewAccepted {
                order: identity(2, 102, 4),
                sequence: Sequence(2),
                leaves_quantity: Quantity::ZERO,
                received_at: TimestampNs(150),
            },
            &risk,
            &kill,
        ),
        Ok(None)
    );
    assert!(orders.order(ClientOrderId(2)).is_none());
}

#[test]
fn fills_race_pending_cancel_and_cancel_reject_resolves_both_paths() {
    let kill = KillLatch::new();
    let mut risk = seeded_risk::<16>(&kill);
    let mut adverse = TestAdverse::new(adverse_config()).unwrap();
    let mut orders = TestOrders::new().unwrap();
    prepare(&mut orders, &mut risk, &adverse, &kill, 1, 10);
    accept(&mut orders, &risk, &kill, 1, 101, 10);
    orders
        .prepare_cancel(ClientOrderId(1), TimestampNs(121), &kill)
        .unwrap();
    orders
        .mark_cancel_transmitted(ClientOrderId(1), TimestampNs(122), &kill)
        .unwrap();

    orders
        .on_fill(
            fill(1, 101, 10, 2, 5001, 4, 6),
            &mut risk,
            &mut adverse,
            &kill,
        )
        .unwrap();
    assert_eq!(
        orders.order(ClientOrderId(1)).unwrap().state,
        ManagedOrderState::PendingCancel
    );
    orders
        .on_cancel_rejected(
            CancelRejected {
                order: identity(1, 101, 10),
                sequence: Sequence(3),
                leaves_quantity: Quantity(6),
                received_at: TimestampNs(140),
            },
            &risk,
            &kill,
        )
        .unwrap();
    assert_eq!(
        orders.order(ClientOrderId(1)).unwrap().state,
        ManagedOrderState::Live
    );

    orders
        .prepare_cancel(ClientOrderId(1), TimestampNs(141), &kill)
        .unwrap();
    orders
        .mark_cancel_transmitted(ClientOrderId(1), TimestampNs(142), &kill)
        .unwrap();
    let full = orders
        .on_fill(
            fill(1, 101, 10, 4, 5002, 6, 0),
            &mut risk,
            &mut adverse,
            &kill,
        )
        .unwrap();
    assert!(full.retained_for_protocol_resolution);
    assert_eq!(
        orders.on_cancel_rejected(
            CancelRejected {
                order: identity(1, 101, 10),
                sequence: Sequence(5),
                leaves_quantity: Quantity::ZERO,
                received_at: TimestampNs(150),
            },
            &risk,
            &kill,
        ),
        Ok(None)
    );

    // Some venue protocols answer the crossed cancel with a zero-canceled
    // confirmation instead of a rejection. That response resolves the same race
    // without releasing risk twice.
    prepare(&mut orders, &mut risk, &adverse, &kill, 2, 2);
    accept(&mut orders, &risk, &kill, 2, 102, 2);
    orders
        .prepare_cancel(ClientOrderId(2), TimestampNs(151), &kill)
        .unwrap();
    orders
        .mark_cancel_transmitted(ClientOrderId(2), TimestampNs(152), &kill)
        .unwrap();
    let mut crossed_fill = fill(2, 102, 2, 2, 5003, 2, 0);
    crossed_fill.fill_timestamp = TimestampNs(153);
    crossed_fill.received_at = TimestampNs(153);
    orders
        .on_fill(crossed_fill, &mut risk, &mut adverse, &kill)
        .unwrap();
    let resolved = orders
        .on_cancel_confirmed(
            CancelConfirmed {
                order: identity(2, 102, 2),
                sequence: Sequence(3),
                canceled_quantity: Quantity::ZERO,
                leaves_quantity: Quantity::ZERO,
                reason: CancelReason::Requested,
                received_at: TimestampNs(160),
            },
            &mut risk,
            &kill,
        )
        .unwrap();
    assert_eq!(resolved.risk, None);
    assert!(resolved.terminal);
    assert_eq!(orders.order_count(), 0);
    assert_eq!(risk.instrument(INSTRUMENT).unwrap().position, Quantity(12));
}

#[test]
fn duplicate_trade_is_killed_before_double_inventory() {
    let kill = KillLatch::new();
    let mut risk = seeded_risk::<16>(&kill);
    let mut adverse = TestAdverse::new(adverse_config()).unwrap();
    let mut orders = TestOrders::new().unwrap();
    prepare(&mut orders, &mut risk, &adverse, &kill, 1, 10);
    accept(&mut orders, &risk, &kill, 1, 101, 10);
    orders
        .on_fill(
            fill(1, 101, 10, 2, 5001, 2, 8),
            &mut risk,
            &mut adverse,
            &kill,
        )
        .unwrap();

    assert_eq!(
        orders.on_fill(
            fill(1, 101, 10, 3, 5001, 2, 6),
            &mut risk,
            &mut adverse,
            &kill
        ),
        Err(OrderError::DuplicateTrade(TradeId(5001)))
    );
    assert_eq!(risk.instrument(INSTRUMENT).unwrap().position, Quantity(2));
    assert_eq!(
        risk.order(OrderId(1)).unwrap().remaining_quantity,
        Quantity(8)
    );
    assert_eq!(adverse.tracked_fill_count(), 1);
    assert_eq!(kill.snapshot().unwrap().code, KillCode::InternalInvariant);
}

#[test]
fn mismatch_and_out_of_order_reports_fail_before_inventory() {
    let scenarios: [fn(&mut FillReport); 4] = [
        |report| report.order.economics.side = Side::Sell,
        |report| report.order.venue_order_id = VenueOrderId(999),
        |report| report.leaves_quantity = Quantity(5),
        |report| report.sequence = Sequence(1),
    ];
    for mutate in scenarios {
        let kill = KillLatch::new();
        let mut risk = seeded_risk::<16>(&kill);
        let mut adverse = TestAdverse::new(adverse_config()).unwrap();
        let mut orders = TestOrders::new().unwrap();
        prepare(&mut orders, &mut risk, &adverse, &kill, 1, 10);
        accept(&mut orders, &risk, &kill, 1, 101, 10);
        let mut report = fill(1, 101, 10, 2, 5001, 2, 8);
        mutate(&mut report);
        assert!(
            orders
                .on_fill(report, &mut risk, &mut adverse, &kill)
                .is_err()
        );
        assert_eq!(
            risk.instrument(INSTRUMENT).unwrap().position,
            Quantity::ZERO
        );
        assert_eq!(
            risk.order(OrderId(1)).unwrap().remaining_quantity,
            Quantity(10)
        );
        assert_eq!(adverse.tracked_fill_count(), 0);
        assert_eq!(kill.snapshot().unwrap().code, KillCode::InternalInvariant);
    }
}

#[test]
fn atomic_risk_rejection_rolls_back_trade_id_and_first_fill_venue_binding() {
    let kill = KillLatch::new();
    let mut risk = seeded_risk::<16>(&kill);
    let mut adverse = TestAdverse::new(adverse_config()).unwrap();
    let mut orders = TestOrders::new().unwrap();
    prepare(&mut orders, &mut risk, &adverse, &kill, 1, 2);
    orders
        .mark_new_transmitted(ClientOrderId(1), TimestampNs(111), &kill)
        .unwrap();
    risk.apply_adjustment(
        RiskAdjustment {
            currency: CurrencyId(840),
            kind: RiskAdjustmentKind::Rebate,
            amount_base_units: i128::MAX,
        },
        TimestampNs(120),
        true,
        &kill,
    )
    .expect("install exact overflow boundary");

    let order_before = orders.order(ClientOrderId(1)).unwrap();
    let risk_order_before = risk.order(OrderId(1)).unwrap();
    let instrument_before = risk.instrument(INSTRUMENT).unwrap();
    let mut report = fill(1, 101, 2, 1, 5001, 1, 1);
    report.fill_price = PriceTicks(99);
    let expected = Err(OrderError::Risk(RiskError::ArithmeticOverflow));

    assert_eq!(
        orders.on_fill(report, &mut risk, &mut adverse, &kill),
        expected
    );
    assert_eq!(orders.order(ClientOrderId(1)), Some(order_before));
    assert!(orders.order_by_venue(VenueOrderId(101)).is_none());
    assert!(!orders.has_recent_trade(TradeId(5001)));
    assert_eq!(risk.order(OrderId(1)), Some(risk_order_before));
    assert_eq!(risk.instrument(INSTRUMENT), Some(instrument_before));
    assert_eq!(risk.lifetime_adjustments(), i128::MAX);
    assert_eq!(adverse.tracked_fill_count(), 0);

    // The exact source fact remains retryable instead of being converted into a
    // false DuplicateTrade after the atomic risk rejection.
    assert_eq!(
        orders.on_fill(report, &mut risk, &mut adverse, &kill),
        expected
    );
    assert!(!orders.has_recent_trade(TradeId(5001)));
    assert!(orders.order_by_venue(VenueOrderId(101)).is_none());
}

#[test]
fn worse_than_limit_fill_is_accounted_then_returns_complete_reconciled_fault() {
    let kill = KillLatch::new();
    let mut risk = seeded_risk::<16>(&kill);
    let mut adverse = TestAdverse::new(adverse_config()).unwrap();
    let mut orders = TestOrders::new().unwrap();
    prepare(&mut orders, &mut risk, &adverse, &kill, 1, 2);
    accept(&mut orders, &risk, &kill, 1, 101, 2);
    let mut report = fill(1, 101, 2, 2, 5001, 1, 1);
    report.fill_price = PriceTicks(101);

    assert_eq!(
        orders.on_fill(report, &mut risk, &mut adverse, &kill),
        Err(OrderError::ExecutionPriceAfterReconciled {
            violation: ExecutionPriceViolation {
                side: Side::Buy,
                limit_price: PRICE,
                fill_price: PriceTicks(101),
            },
            risk: None,
            adverse: None,
        })
    );
    assert_eq!(risk.instrument(INSTRUMENT).unwrap().position, Quantity(1));
    assert_eq!(
        risk.order(OrderId(1)).unwrap().remaining_quantity,
        Quantity(1)
    );
    assert_eq!(
        orders.order(ClientOrderId(1)).unwrap().remaining_quantity,
        Quantity(1)
    );
    assert!(orders.has_recent_trade(TradeId(5001)));
    assert!(adverse.fill(5001).is_some());
    assert_eq!(kill.snapshot().unwrap().code, KillCode::InternalInvariant);
}

#[test]
fn adverse_capacity_fault_occurs_after_fill_is_fully_reconciled() {
    let kill = KillLatch::new();
    let mut risk = seeded_risk::<16>(&kill);
    let mut adverse = AdverseMonitor::<4, 1>::new(adverse_config()).unwrap();
    let mut orders = TestOrders::new().unwrap();
    prepare(&mut orders, &mut risk, &adverse, &kill, 1, 2);
    accept(&mut orders, &risk, &kill, 1, 101, 2);
    prepare(&mut orders, &mut risk, &adverse, &kill, 2, 3);
    accept(&mut orders, &risk, &kill, 2, 102, 3);
    orders
        .on_fill(
            fill(1, 101, 2, 2, 5001, 2, 0),
            &mut risk,
            &mut adverse,
            &kill,
        )
        .unwrap();

    assert_eq!(
        orders.on_fill(
            fill(2, 102, 3, 2, 5002, 3, 0),
            &mut risk,
            &mut adverse,
            &kill
        ),
        Err(OrderError::AdverseAfterReconciled(
            AdverseError::FillCapacity { capacity: 1 }
        ))
    );
    assert_eq!(risk.instrument(INSTRUMENT).unwrap().position, Quantity(5));
    assert!(risk.order(OrderId(2)).is_none());
    assert!(orders.order(ClientOrderId(2)).is_none());
    assert!(orders.has_recent_trade(TradeId(5002)));
    assert_eq!(kill.snapshot().unwrap().code, KillCode::InternalInvariant);
}

#[test]
fn fill_facts_apply_while_global_kill_is_already_latched() {
    let kill = KillLatch::new();
    let mut risk = seeded_risk::<16>(&kill);
    let mut adverse = TestAdverse::new(adverse_config()).unwrap();
    let mut orders = TestOrders::new().unwrap();
    prepare(&mut orders, &mut risk, &adverse, &kill, 1, 3);
    accept(&mut orders, &risk, &kill, 1, 101, 3);
    assert!(kill.trigger(KillCode::Manual, TimestampNs(125)));
    orders
        .on_fill(
            fill(1, 101, 3, 2, 5001, 3, 0),
            &mut risk,
            &mut adverse,
            &kill,
        )
        .unwrap();
    assert_eq!(risk.instrument(INSTRUMENT).unwrap().position, Quantity(3));
    assert_eq!(adverse.tracked_fill_count(), 1);
    assert_eq!(kill.snapshot().unwrap().code, KillCode::Manual);
}

#[test]
fn full_trade_history_rejects_first_fill_before_binding_or_accounting_mutation() {
    let kill = KillLatch::new();
    let mut risk = seeded_risk::<16>(&kill);
    let mut adverse = TestAdverse::new(adverse_config()).unwrap();
    let mut orders = OrderManager::<8, 2>::new().unwrap();
    for client in 1_u64..=2 {
        prepare(&mut orders, &mut risk, &adverse, &kill, client, 2);
        accept(&mut orders, &risk, &kill, client, 100 + client, 2);
        orders
            .on_fill(
                fill(client, 100 + client, 2, 2, 5_000 + client, 2, 0),
                &mut risk,
                &mut adverse,
                &kill,
            )
            .unwrap();
    }
    prepare(&mut orders, &mut risk, &adverse, &kill, 3, 2);
    orders
        .mark_new_transmitted(ClientOrderId(3), TimestampNs(140), &kill)
        .unwrap();

    let order_before = orders.order(ClientOrderId(3)).unwrap();
    let risk_order_before = risk.order(OrderId(3)).unwrap();
    let instrument_before = risk.instrument(INSTRUMENT).unwrap();
    let realized_before = risk.lifetime_realized_pnl();
    let pnl_before = risk.daily_pnl();
    let adverse_count_before = adverse.tracked_fill_count();
    let adverse_one_before = adverse.fill(5001);
    let adverse_two_before = adverse.fill(5002);

    assert_eq!(
        orders.on_fill(
            fill(3, 103, 2, 1, 5003, 1, 1),
            &mut risk,
            &mut adverse,
            &kill,
        ),
        Err(OrderError::TradeHistoryCapacity { capacity: 2 })
    );

    assert_eq!(orders.order(ClientOrderId(3)), Some(order_before));
    assert!(orders.order_by_venue(VenueOrderId(103)).is_none());
    assert_eq!(risk.order(OrderId(3)), Some(risk_order_before));
    assert_eq!(risk.instrument(INSTRUMENT), Some(instrument_before));
    assert_eq!(risk.lifetime_realized_pnl(), realized_before);
    assert_eq!(risk.daily_pnl(), pnl_before);
    assert_eq!(adverse.tracked_fill_count(), adverse_count_before);
    assert_eq!(adverse.fill(5001), adverse_one_before);
    assert_eq!(adverse.fill(5002), adverse_two_before);
    assert!(orders.has_recent_trade(TradeId(5001)));
    assert!(orders.has_recent_trade(TradeId(5002)));
    assert!(!orders.has_recent_trade(TradeId(5003)));
    assert_eq!(kill.snapshot().unwrap().code, KillCode::InternalInvariant);
}

#[test]
fn full_trade_history_keeps_oldest_id_and_blocks_consistent_active_order_replay() {
    let kill = KillLatch::new();
    let mut risk = seeded_risk::<16>(&kill);
    let mut adverse = TestAdverse::new(adverse_config()).unwrap();
    let mut orders = OrderManager::<8, 2>::new().unwrap();
    prepare(&mut orders, &mut risk, &adverse, &kill, 1, 3);
    accept(&mut orders, &risk, &kill, 1, 101, 3);
    orders
        .on_fill(
            fill(1, 101, 3, 2, 5001, 1, 2),
            &mut risk,
            &mut adverse,
            &kill,
        )
        .unwrap();
    prepare(&mut orders, &mut risk, &adverse, &kill, 2, 1);
    accept(&mut orders, &risk, &kill, 2, 102, 1);
    orders
        .on_fill(
            fill(2, 102, 1, 2, 5002, 1, 0),
            &mut risk,
            &mut adverse,
            &kill,
        )
        .unwrap();

    let order_before = orders.order(ClientOrderId(1)).unwrap();
    let risk_order_before = risk.order(OrderId(1)).unwrap();
    let instrument_before = risk.instrument(INSTRUMENT).unwrap();
    let realized_before = risk.lifetime_realized_pnl();
    let pnl_before = risk.daily_pnl();
    let adverse_count_before = adverse.tracked_fill_count();
    let adverse_one_before = adverse.fill(5001);
    let adverse_two_before = adverse.fill(5002);

    // The newer sequence and leaves are algebraically valid, so only exact
    // lifetime execution-ID retention prevents this replay from double inventory.
    assert_eq!(
        orders.on_fill(
            fill(1, 101, 3, 3, 5001, 1, 1),
            &mut risk,
            &mut adverse,
            &kill,
        ),
        Err(OrderError::DuplicateTrade(TradeId(5001)))
    );

    assert_eq!(orders.order(ClientOrderId(1)), Some(order_before));
    assert_eq!(risk.order(OrderId(1)), Some(risk_order_before));
    assert_eq!(risk.instrument(INSTRUMENT), Some(instrument_before));
    assert_eq!(risk.lifetime_realized_pnl(), realized_before);
    assert_eq!(risk.daily_pnl(), pnl_before);
    assert_eq!(adverse.tracked_fill_count(), adverse_count_before);
    assert_eq!(adverse.fill(5001), adverse_one_before);
    assert_eq!(adverse.fill(5002), adverse_two_before);
    assert!(orders.has_recent_trade(TradeId(5001)));
    assert!(orders.has_recent_trade(TradeId(5002)));
    assert_eq!(kill.snapshot().unwrap().code, KillCode::InternalInvariant);
}

#[test]
fn unsent_cancel_rolls_back_without_releasing_risk() {
    let kill = KillLatch::new();
    let mut risk = seeded_risk::<16>(&kill);
    let adverse = TestAdverse::new(adverse_config()).unwrap();
    let mut orders = TestOrders::new().unwrap();
    prepare(&mut orders, &mut risk, &adverse, &kill, 1, 10);
    accept(&mut orders, &risk, &kill, 1, 101, 10);
    orders
        .prepare_cancel(ClientOrderId(1), TimestampNs(121), &kill)
        .unwrap();
    let snapshot = orders
        .rollback_unsent_cancel(ClientOrderId(1), TimestampNs(122), &kill)
        .unwrap();
    assert_eq!(snapshot.state, ManagedOrderState::Live);
    assert_eq!(
        risk.order(OrderId(1)).unwrap().remaining_quantity,
        Quantity(10)
    );

    orders
        .prepare_cancel(ClientOrderId(1), TimestampNs(123), &kill)
        .unwrap();
    orders
        .mark_cancel_transmitted(ClientOrderId(1), TimestampNs(124), &kill)
        .unwrap();
    assert_eq!(
        orders.rollback_unsent_cancel(ClientOrderId(1), TimestampNs(125), &kill),
        Err(OrderError::NotProvenUnsent(LifecycleEvent::RollbackCancel))
    );
    assert!(!kill.is_triggered());
}
