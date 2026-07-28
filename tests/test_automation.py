from __future__ import annotations

import json
import hashlib
import sqlite3
from dataclasses import replace
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest

from auto_trader.brokers.simulated import SimulatedBroker
from auto_trader.config import BotConfig, LIVE_ACK_TEXT
from auto_trader.controls import merge_control_marker, parse_control_marker
from auto_trader.covariance_evidence import COVARIANCE_RETURN_SEMANTICS
from auto_trader.daemon import TradingDaemon
from auto_trader.engine import (
    AutomationEngine,
    EmergencyFillProgressError,
    EmergencyPrimarySubmissionError,
)
from auto_trader.models import (
    AccountSnapshot,
    AssetInfo,
    CashActivity,
    MarketClock,
    OrderIntent,
    OrderPhase,
    OrderReceipt,
    OrderSide,
    PositionSnapshot,
    RiskDecision,
    TargetPlan,
)
from auto_trader.risk import RiskManager
from auto_trader.store import StateStore
from auto_trader.strategy import (
    PLAN_AUTHENTICATION_TAG_KEY,
    SEALED_COVARIANCE_RETURN_SEMANTICS,
    build_target_plan,
    clean_live_prices,
    seal_target_plan,
    target_plan_content_hash,
)
from quant_app.backtest import run_backtest
from quant_app.data import generate_demo_prices


_TEST_PLAN_AUTHENTICATION_KEY = hashlib.sha256(
    b"automation-test-plan-authentication-key"
).hexdigest()
_TEST_EMERGENCY_AUTHENTICATION_KEY = hashlib.sha256(
    b"automation-test-emergency-authentication-key"
).hexdigest()


@pytest.fixture()
def prices() -> pd.DataFrame:
    return generate_demo_prices(n_assets=20, years=4, seed=202, end_date="2026-06-30")


def make_engine(tmp_path: Path, prices: pd.DataFrame, execution_enabled: bool) -> AutomationEngine:
    config = BotConfig(
        broker="simulated",
        execution_enabled=execution_enabled,
        symbols=tuple(prices.columns),
        database_path=tmp_path / "state.sqlite3",
        log_path=tmp_path / "bot.log",
        kill_switch_path=tmp_path / "KILL_SWITCH",
        process_lock_path=tmp_path / "bot.lock",
        simulated_prices_path=tmp_path / "unused.csv",
        simulated_state_path=tmp_path / "broker.json",
        simulated_starting_cash=100_000.0,
        simulated_market_always_open=True,
        minimum_assets=8,
    )
    broker = SimulatedBroker(
        prices_path=config.simulated_prices_path,
        state_path=config.simulated_state_path,
        starting_cash=config.simulated_starting_cash,
        market_always_open=True,
        prices=prices,
    )
    return AutomationEngine(config, broker, StateStore(config.database_path))


def enable_authenticated_store(engine: AutomationEngine) -> None:
    """Upgrade a fresh test engine to the production keyed StateStore boundary."""

    engine.store = StateStore(
        engine.config.database_path,
        authentication_key=engine.config.plan_authentication_key_bytes,
    )
    engine.risk.store = engine.store


def test_persisted_plan_is_rejected_after_current_deployment_changes(
    tmp_path: Path, prices: pd.DataFrame
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    engine.generate_plan(force=True)
    engine.config = replace(engine.config, max_orders_per_cycle=49)

    with pytest.raises(RuntimeError, match="current approved deployment"):
        engine.execute_latest_plan(force=True)

    assert engine.broker.get_positions() == {}
    assert engine.broker.list_open_orders(None) == []


def test_persisted_plan_metadata_tampering_fails_content_integrity_before_orders(
    tmp_path: Path, prices: pd.DataFrame
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    plan = engine.generate_plan(force=True)
    with engine.store.connection() as db:
        row = db.execute(
            "SELECT metadata_json FROM plans WHERE plan_id = ?", (plan.plan_id,)
        ).fetchone()
        metadata = json.loads(row["metadata_json"])
        metadata["asset_beta"][str(prices.columns[0])] = 999.0
        db.execute(
            "UPDATE plans SET metadata_json = ? WHERE plan_id = ?",
            (json.dumps(metadata, sort_keys=True), plan.plan_id),
        )

    with pytest.raises(RuntimeError, match="plan_id failed integrity"):
        engine.execute_latest_plan(force=True)

    assert engine.broker.get_positions() == {}
    assert engine.broker.list_open_orders(None) == []


def test_recomputed_plan_id_forgery_fails_secret_authentication_before_orders(
    tmp_path: Path, prices: pd.DataFrame
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    plan = engine.generate_plan(force=True)
    forged_metadata = dict(plan.metadata)
    forged_beta = dict(forged_metadata["asset_beta"])
    forged_beta[str(prices.columns[0])] = 999.0
    forged_metadata["asset_beta"] = forged_beta
    forged = replace(plan, metadata=forged_metadata)
    forged_plan_id = target_plan_content_hash(forged)
    # The attacker recomputes the public hash after rewriting SQLite but cannot
    # compute a new tag without PLAN_AUTHENTICATION_KEY.
    with engine.store.connection() as db:
        db.execute(
            "UPDATE plans SET plan_id = ?, metadata_json = ? WHERE plan_id = ?",
            (
                forged_plan_id,
                json.dumps(forged_metadata, sort_keys=True),
                plan.plan_id,
            ),
        )

    with pytest.raises(RuntimeError, match="plan authentication failed"):
        engine.execute_latest_plan(force=True)

    assert engine.broker.get_positions() == {}
    assert engine.broker.list_open_orders(None) == []


def test_legacy_unkeyed_plan_is_rejected_before_broker_mutation(
    tmp_path: Path, prices: pd.DataFrame
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    plan = engine.generate_plan(force=True)
    legacy_metadata = dict(plan.metadata)
    legacy_metadata.pop(PLAN_AUTHENTICATION_TAG_KEY)
    with engine.store.connection() as db:
        db.execute(
            "UPDATE plans SET metadata_json = ? WHERE plan_id = ?",
            (json.dumps(legacy_metadata, sort_keys=True), plan.plan_id),
        )

    with pytest.raises(RuntimeError, match="missing a valid authentication tag"):
        engine.execute_latest_plan(force=True)

    assert engine.broker.get_positions() == {}
    assert engine.broker.list_open_orders(None) == []


def test_live_planner_excludes_stale_or_gap_contaminated_price_history(
    prices: pd.DataFrame,
) -> None:
    stale = prices.copy()
    stale_symbol = str(stale.columns[0])
    gap_symbol = str(stale.columns[1])
    five_day_gap_symbol = str(stale.columns[2])
    stale.loc[stale.index[-1], stale_symbol] = float("nan")
    stale.loc[stale.index[-60], gap_symbol] = float("nan")
    stale.loc[stale.index[-5], five_day_gap_symbol] = float("nan")

    clean = clean_live_prices(stale, minimum_assets=8)

    assert stale_symbol not in clean.columns
    assert gap_symbol not in clean.columns
    assert five_day_gap_symbol not in clean.columns
    assert not clean.tail(252).isna().any().any()


def test_live_planner_fails_closed_when_stale_data_shrinks_universe_below_minimum(
    prices: pd.DataFrame,
) -> None:
    stale = prices.iloc[:, :10].copy()
    stale.loc[stale.index[-1], stale.columns[:3]] = float("nan")

    with pytest.raises(ValueError, match="complete trailing 252-session"):
        clean_live_prices(stale, minimum_assets=8)


def test_live_plan_data_hash_covers_rows_older_than_legacy_160_bar_tail(
    prices: pd.DataFrame,
) -> None:
    risk = RiskDecision(True, False, False, "normal", 0.0, 0.0, 0.0)
    first = build_target_plan(prices, BotConfig().strategy, risk, minimum_assets=8)
    changed = prices.copy()
    changed.iloc[-200, 0] *= 1.001
    second = build_target_plan(changed, BotConfig().strategy, risk, minimum_assets=8)

    assert first.metadata["data_hash"] != second.metadata["data_hash"]


def test_governed_plan_covariance_matches_sealed_trailing_execution_window(
    prices: pd.DataFrame,
) -> None:
    config = BotConfig().strategy
    risk = RiskDecision(True, False, False, "normal", 0.0, 0.0, 0.0)
    execution_location = 500
    completed_signal_prices = prices.iloc[:execution_location]
    as_of = pd.Timestamp(completed_signal_prices.index[-1]).date()
    intended = (
        pd.Timestamp(completed_signal_prices.index[-1]) + pd.offsets.BDay(1)
    ).date()
    plan = build_target_plan(
        completed_signal_prices,
        config,
        risk,
        minimum_assets=20,
        covariance_execution_prices=completed_signal_prices,
        covariance_corporate_action_split_ratios=pd.DataFrame(
            1.0,
            index=completed_signal_prices.index,
            columns=completed_signal_prices.columns,
        ),
        covariance_corporate_action_cash_distributions=pd.DataFrame(
            0.0,
            index=completed_signal_prices.index,
            columns=completed_signal_prices.columns,
        ),
        covariance_evidence_metadata={
            "fixture": "no_corporate_actions",
            "issued_at": datetime.combine(
                as_of, time(14, 0), tzinfo=timezone.utc
            ).isoformat(),
            "expires_at": datetime.combine(
                intended + timedelta(days=1), time(0, 0), tzinfo=timezone.utc
            ).isoformat(),
            "latest_session": as_of.isoformat(),
            "next_session": intended.isoformat(),
            "return_semantics": COVARIANCE_RETURN_SEMANTICS,
        },
        intended_execution_date=intended,
        covariance_return_semantics=SEALED_COVARIANCE_RETURN_SEMANTICS,
        require_research_covariance_parity=True,
    )
    research = run_backtest(
        prices,
        config,
        execution_return_semantics="next_open_to_open",
        execution_prices=prices,
    )

    assert plan.metadata["research_covariance_parity_certified"] is True
    assert plan.metadata["covariance_return_count"] == 251
    assert (
        plan.metadata["covariance_return_semantics"]
        == SEALED_COVARIANCE_RETURN_SEMANTICS
    )
    assert plan.forecast_volatility == pytest.approx(
        float(research.diagnostics.iloc[execution_location]["forecast_volatility"]),
        abs=1e-12,
    )


def test_governed_plan_and_engine_refuse_close_proxy_covariance(
    tmp_path: Path,
    prices: pd.DataFrame,
) -> None:
    risk = RiskDecision(True, False, False, "normal", 0.0, 0.0, 0.0)
    with pytest.raises(ValueError, match="signed 09:30-09:35"):
        build_target_plan(
            prices,
            BotConfig().strategy,
            risk,
            minimum_assets=20,
            require_research_covariance_parity=True,
        )

    engine = make_engine(tmp_path, prices, execution_enabled=True)
    engine.config = replace(
        engine.config,
        broker="alpaca",
        minimum_assets=20,
        max_data_age_days=10_000,
    )
    with pytest.raises(ValueError, match="signed 09:30-09:35"):
        engine.generate_plan(force=True)



def test_five_session_return_uses_stable_prior_close_anchor(tmp_path: Path) -> None:
    config = BotConfig(
        database_path=tmp_path / "risk.sqlite3",
        kill_switch_path=tmp_path / "KILL_SWITCH",
    )
    store = StateStore(config.database_path)
    start = date(2026, 6, 1)
    prior_equities = [100.0, 102.0, 104.0, 106.0, 108.0]
    for offset, equity in enumerate(prior_equities):
        session = start + timedelta(days=offset)
        snapshot = AccountSnapshot(
            timestamp=datetime.combine(session, datetime.min.time(), tzinfo=timezone.utc),
            equity=equity,
            cash=equity,
            buying_power=equity * 2,
            last_equity=equity,
        )
        store.record_equity(snapshot, session, 0.0, 0.0, 0.0)

    current_session = start + timedelta(days=5)
    current = AccountSnapshot(
        timestamp=datetime.combine(current_session, datetime.min.time(), tzinfo=timezone.utc),
        equity=110.0,
        cash=110.0,
        buying_power=220.0,
        last_equity=108.0,
    )
    first = RiskManager(config, store).evaluate_and_record(current, current_session)
    second = RiskManager(config, store).evaluate_and_record(current, current_session)

    assert first.five_day_return == pytest.approx(0.10)
    assert second.five_day_return == pytest.approx(0.10)


def test_live_submission_requires_exact_acknowledgement() -> None:
    unsafe = BotConfig(
        broker="alpaca",
        execution_enabled=True,
        alpaca_paper=False,
        alpaca_api_key="key",
        alpaca_secret_key="secret",
        alpaca_account_id="account-test-0001",
        plan_authentication_key=_TEST_PLAN_AUTHENTICATION_KEY,
        emergency_authentication_key=_TEST_EMERGENCY_AUTHENTICATION_KEY,
    )
    with pytest.raises(ValueError, match="Live order submission is locked"):
        unsafe.validate()

    safe = replace(
        unsafe,
        live_ack=LIVE_ACK_TEXT,
        dedicated_account=True,
        covariance_evidence_path=Path("governed-covariance-envelope.json"),
        covariance_execution_prices_path=Path("governed-vwap.csv"),
        covariance_corporate_actions_path=Path("governed-actions.csv"),
        covariance_public_keys_path=Path("governed-covariance-keys.json"),
        covariance_public_keys_sha256="a" * 64,
        covariance_provider_id="governed-provider-2026",
        covariance_venue_id="governed-us-venue",
        borrow_evidence_path=Path("governed-borrow-envelope.json"),
        borrow_terms_path=Path("governed-borrow-terms.csv"),
        borrow_public_keys_path=Path("governed-borrow-keys.json"),
        borrow_public_keys_sha256="b" * 64,
        borrow_provider_id="governed-borrow-provider-2026",
        borrow_venue_id="governed-us-venue",
    )
    safe.validate()


def test_plan_only_mode_never_submits_orders(tmp_path: Path, prices: pd.DataFrame) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=False)
    plan = engine.generate_plan(force=True)
    summary = engine.execute_latest_plan(force=True)

    assert plan.status == "approved"
    assert summary.status == "previewed"
    assert summary.submitted_orders == 0
    assert engine.broker.get_positions() == {}
    assert engine.store.recent_orders() == []


def test_simulated_cycle_executes_once_and_reconciles(tmp_path: Path, prices: pd.DataFrame) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    plan = engine.generate_plan(force=True)
    summary = engine.execute_latest_plan(force=True)

    assert summary.status == "executed"
    assert summary.submitted_orders > 0
    assert summary.filled_orders == summary.submitted_orders
    assert summary.residual_notional <= engine.config.residual_notional_tolerance
    assert engine.store.get_plan(plan.plan_id).status == "executed"

    positions_before_duplicate = {
        symbol: position.qty for symbol, position in engine.broker.get_positions().items()
    }

    with pytest.raises(RuntimeError, match="No approved"):
        engine.execute_latest_plan(force=True)
    assert {
        symbol: position.qty for symbol, position in engine.broker.get_positions().items()
    } == positions_before_duplicate
    assert not engine.store.is_halted()


def test_preflight_failure_never_liquidates_existing_positions(
    tmp_path: Path, prices: pd.DataFrame, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    engine.generate_plan(force=True)
    symbol = prices.columns[0]
    engine.broker.submit_market_order(symbol, 5.0, OrderSide.BUY, "manual-preflight")

    monkeypatch.setattr(engine.broker, "get_latest_prices", lambda _symbols: {})

    with pytest.raises(RuntimeError, match="live plan prices"):
        engine.execute_latest_plan(force=True)
    assert engine.broker.get_positions()[symbol].qty == pytest.approx(5.0)
    assert not engine.store.is_halted()


def test_sign_flip_is_decomposed_into_reduce_then_increase(
    tmp_path: Path, prices: pd.DataFrame
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=False)
    symbol = prices.columns[0]
    plan = TargetPlan(
        plan_id="test-sign-flip",
        as_of=prices.index[-1].date(),
        created_at=pd.Timestamp.utcnow().to_pydatetime(),
        regime="favorable",
        regime_multiplier=1.0,
        desired_gross=0.1,
        forecast_volatility=0.1,
        target_weights={symbol: -0.05},
        metadata={"assets": [symbol], "gross_weight": 0.05, "account_equity": 100_000.0},
    )
    current = {
        symbol: PositionSnapshot(
            symbol=symbol,
            qty=10.0,
            market_value=10.0 * prices.iloc[-1][symbol],
            current_price=float(prices.iloc[-1][symbol]),
        )
    }
    targets = {symbol: -10.0}
    latest = {symbol: float(prices.iloc[-1][symbol])}
    reductions, increases = engine._build_order_intents(plan, current, targets, latest)

    assert len(reductions) == 1
    assert reductions[0].side.value == "sell"
    assert reductions[0].qty == 10.0
    assert len(increases) == 1
    assert increases[0].side.value == "sell"
    assert increases[0].qty == 10.0


def test_manual_kill_switch_flattens_managed_positions(
    tmp_path: Path, prices: pd.DataFrame
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    engine.generate_plan(force=True)
    engine.execute_latest_plan(force=True)
    assert engine.broker.get_positions()

    engine.request_kill("test_manual_kill", flatten=True)

    assert engine.store.is_halted()
    assert engine.config.kill_switch_path.exists()
    assert engine.broker.get_positions() == {}


def test_adverse_mark_triggers_shutdown_and_flatten(
    tmp_path: Path, prices: pd.DataFrame
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    engine.generate_plan(force=True)
    engine.execute_latest_plan(force=True)
    positions = engine.broker.get_positions()
    assert positions

    # Move every held long down and every held short up to produce a severe portfolio loss.
    for symbol, position in positions.items():
        factor = 0.65 if position.qty > 0 else 1.35
        engine.broker._prices.loc[engine.broker._prices.index[-1], symbol] *= factor

    decision = engine.monitor()

    assert decision.flatten
    assert engine.store.is_halted()
    assert engine.broker.get_positions() == {}


def test_plan_persistence_is_unique_by_completed_session(
    tmp_path: Path, prices: pd.DataFrame
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=False)
    first = engine.generate_plan(force=False)
    second = engine.generate_plan(force=False)
    assert first.plan_id == second.plan_id
    assert len(engine.store.list_plans()) == 1





def test_halt_only_escalates_to_flatten_when_loss_limit_breaks(
    tmp_path: Path, prices: pd.DataFrame
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    symbol = prices.columns[0]
    engine.broker.submit_market_order(symbol, 50.0, OrderSide.BUY, "halt-escalation-open")
    engine.request_kill("operator_halt_only", flatten=False)

    engine.broker._prices.loc[engine.broker._prices.index[-1], symbol] *= 0.40
    decision = engine.monitor()

    assert decision.flatten is True
    assert decision.reason in {"daily_loss_shutdown", "prelimit_drawdown_flatten", "hard_drawdown_breach"}
    assert engine.broker.get_positions() == {}
    assert engine.store.halt_state().get("flatten") is True


@pytest.mark.parametrize("existing_flatten", [False, True])
def test_auto_resumable_shutdown_preserves_authenticated_active_halt_and_decision(
    tmp_path: Path,
    prices: pd.DataFrame,
    existing_flatten: bool,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=False)
    config = replace(engine.config, auto_resume_after_cooldown=True)
    authentication_key = hashlib.sha256(b"risk-state-authentication-test").digest()
    store = StateStore(
        tmp_path / f"authenticated-risk-{existing_flatten}.sqlite3",
        authentication_key=authentication_key,
    )
    manager = RiskManager(config, store)
    store.set_state("high_watermark", 100_000.0)
    store.request_halt("independent_incident", flatten=existing_flatten)
    before = store.halt_state()
    account = replace(
        engine.broker.get_account(),
        equity=97_000.0,
        cash=97_000.0,
        buying_power=194_000.0,
        last_equity=100_000.0,
    )
    session = engine._local_time(account.timestamp).date()

    decision = manager.evaluate_and_record(account, session)

    assert decision.reason == "daily_loss_shutdown"
    assert decision.flatten is True
    assert decision.halt is True
    halt = store.halt_state()
    assert halt["active"] is True
    assert halt["flatten"] is True
    assert halt["incident_id"] == before["incident_id"]

    # Expiring the automatic cooldown may allow a future risk evaluation, but it
    # cannot acknowledge or clear the independently opened incident.
    store.set_state("cooldown_remaining", 1)
    assert manager.advance_cooldown(session + timedelta(days=1)) == 0
    after_expiry = store.halt_state()
    assert after_expiry["active"] is True
    assert after_expiry["flatten"] is True
    assert after_expiry["incident_id"] == before["incident_id"]


def test_interrupted_execution_recovery_fails_closed(
    tmp_path: Path, prices: pd.DataFrame
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    plan = engine.generate_plan(force=True)
    engine.store.mark_plan_status(plan.plan_id, "executing", "simulated process crash")
    symbol = prices.columns[0]
    engine.broker.submit_market_order(symbol, 7.0, OrderSide.BUY, "crash-position")

    recovered = engine.recover_incomplete_execution()

    assert recovered is True
    assert engine.store.is_halted()
    assert engine.broker.get_positions() == {}
    assert engine.store.get_plan(plan.plan_id).status == "failed"


def test_halt_only_blocks_new_activity_without_flattening(
    tmp_path: Path, prices: pd.DataFrame
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    # This test isolates halt-only semantics. A beta-neutral monitor now correctly
    # treats an unmodeled held position as a separate flattening breach.
    engine.config = replace(
        engine.config,
        strategy=replace(
            engine.config.strategy,
            portfolio=replace(engine.config.strategy.portfolio, beta_neutral=False),
        ),
    )
    symbol = prices.columns[0]
    engine.broker.submit_market_order(symbol, 5.0, OrderSide.BUY, "manual-halt-only")

    engine.request_kill("operator_halt_only", flatten=False)
    decision = engine.monitor()

    assert engine.store.is_halted()
    marker = parse_control_marker(
        engine.config.kill_switch_path.read_text(encoding="utf-8")
    )
    assert marker.reason == "operator_halt_only" and marker.flatten is False
    assert decision.halt is True
    assert decision.flatten is False
    assert symbol in engine.broker.get_positions()


def test_monitor_executes_required_flatten_before_unrelated_order_scan(
    tmp_path: Path, prices: pd.DataFrame, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    account = engine.broker.get_account()
    required = RiskDecision(False, True, True, "objective_shutdown", -0.2, -0.1, -0.1)
    flattened: list[str] = []
    monkeypatch.setattr(engine, "_evaluate_risk", lambda *_args: required)
    monkeypatch.setattr(
        engine,
        "emergency_flatten",
        lambda reason, **_kwargs: flattened.append(reason) or [],
    )
    monkeypatch.setattr(
        engine.broker,
        "list_open_orders",
        lambda *_args, **_kwargs: pytest.fail("order scan must not delay required flatten"),
    )

    decision = engine.monitor()

    assert decision is required
    assert flattened == ["objective_shutdown"]
    assert account.equity > 0


def test_dedicated_monitor_cancels_foreign_order_and_halts_account(
    tmp_path: Path, prices: pd.DataFrame, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    engine.config = replace(engine.config, dedicated_account=True)
    engine.risk.config = engine.config
    symbol = str(prices.columns[0])
    order_id = "manual-pending-order"
    engine.broker._state["orders"][order_id] = {
        "broker_order_id": order_id,
        "client_order_id": "manual-client-order",
        "symbol": symbol,
        "qty": 2.0,
        "side": OrderSide.BUY.value,
        "status": "accepted",
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "filled_qty": 0.0,
        "filled_avg_price": None,
    }
    engine.broker._persist()
    sequence: list[str] = []
    original_request_halt = engine.store.request_halt
    original_cancel = engine.broker.cancel_orders_and_wait

    def request_halt(reason: str, *, flatten: bool = True) -> None:
        if reason == "unauthorized_dedicated_account_order":
            sequence.append("halt")
        original_request_halt(reason, flatten=flatten)

    def cancel_orders(*args, **kwargs):
        sequence.append("cancel")
        return original_cancel(*args, **kwargs)

    monkeypatch.setattr(engine.store, "request_halt", request_halt)
    monkeypatch.setattr(engine.broker, "cancel_orders_and_wait", cancel_orders)

    decision = engine.monitor()

    assert decision.reason == "unauthorized_dedicated_account_order"
    assert decision.flatten is True and decision.halt is True
    assert engine.broker.list_open_orders(None) == []
    assert engine.store.halt_state()["flatten"] is True
    assert sequence[:2] == ["halt", "cancel"]
    assert any(
        event["code"] == "UNAUTHORIZED_ACCOUNT_ORDER"
        for event in engine.store.recent_events()
    )


def test_qauto_prefix_without_authenticated_record_is_foreign_in_dedicated_account(
    tmp_path: Path, prices: pd.DataFrame
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    engine.config = replace(engine.config, dedicated_account=True)
    engine.risk.config = engine.config
    symbol = str(prices.columns[0])
    broker_order_id = "spoofed-qauto-broker-order"
    engine.broker._state["orders"][broker_order_id] = {
        "broker_order_id": broker_order_id,
        "client_order_id": "qauto-spoofed-public-prefix",
        "symbol": symbol,
        "qty": 2.0,
        "side": OrderSide.BUY.value,
        "status": "accepted",
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "filled_qty": 0.0,
        "filled_avg_price": None,
    }
    engine.broker._persist()

    decision = engine.monitor()

    assert decision.reason == "unauthorized_dedicated_account_order"
    assert decision.flatten is True and decision.halt is True
    assert engine.broker.list_open_orders(None) == []
    event = next(
        event
        for event in engine.store.recent_events()
        if event["code"] == "UNAUTHORIZED_ACCOUNT_ORDER"
    )
    assert "missing_authenticated_record" in event["payload_json"]


def test_authenticated_client_id_with_changed_economics_is_not_owned(
    tmp_path: Path, prices: pd.DataFrame
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    engine.config = replace(engine.config, dedicated_account=True)
    engine.risk.config = engine.config
    symbol = str(prices.columns[0])
    submitted_at = datetime.now(timezone.utc)
    broker_order_id = "economics-mismatch-broker-order"
    client_order_id = "qauto-economics-mismatch"
    authenticated = OrderReceipt(
        broker_order_id=broker_order_id,
        client_order_id=client_order_id,
        symbol=symbol,
        qty=2.0,
        side=OrderSide.BUY.value,
        status="accepted",
        submitted_at=submitted_at,
    )
    engine.store.record_order(None, OrderPhase.INCREASE.value, authenticated)
    engine.broker._state["orders"][broker_order_id] = {
        "broker_order_id": broker_order_id,
        "client_order_id": client_order_id,
        "symbol": symbol,
        "qty": 3.0,
        "side": OrderSide.BUY.value,
        "status": "accepted",
        "submitted_at": submitted_at.isoformat(),
        "filled_qty": 0.0,
        "filled_avg_price": None,
    }
    engine.broker._persist()

    decision = engine.monitor()

    assert decision.reason == "unauthorized_dedicated_account_order"
    event = next(
        event
        for event in engine.store.recent_events()
        if event["code"] == "UNAUTHORIZED_ACCOUNT_ORDER"
    )
    assert "quantity_mismatch" in event["payload_json"]


def test_restart_does_not_adopt_unrecorded_qauto_order_in_shared_account(
    tmp_path: Path, prices: pd.DataFrame
) -> None:
    first = make_engine(tmp_path, prices, execution_enabled=True)
    symbol = str(prices.columns[0])
    broker_order_id = "unrecorded-before-restart"
    first.broker._state["orders"][broker_order_id] = {
        "broker_order_id": broker_order_id,
        "client_order_id": "qauto-unrecorded-before-restart",
        "symbol": symbol,
        "qty": 1.0,
        "side": OrderSide.BUY.value,
        "status": "accepted",
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "filled_qty": 0.0,
        "filled_avg_price": None,
    }
    first.broker._persist()
    restarted = AutomationEngine(
        first.config,
        first.broker,
        StateStore(first.config.database_path, require_existing=True),
    )

    decision = restarted.monitor()

    assert decision.reason == "unowned_shared_account_strategy_order"
    assert decision.halt is True and decision.flatten is False
    assert restarted.broker.list_open_orders([symbol])[0].broker_order_id == broker_order_id
    assert restarted.store.halt_state()["active"] is True


def test_restart_cancels_only_exact_authenticated_stale_order(
    tmp_path: Path, prices: pd.DataFrame
) -> None:
    first = make_engine(tmp_path, prices, execution_enabled=True)
    symbol = str(prices.columns[0])
    submitted_at = datetime.now(timezone.utc) - timedelta(minutes=10)
    owned = OrderReceipt(
        broker_order_id="authenticated-stale-order",
        client_order_id="qauto-authenticated-stale-order",
        symbol=symbol,
        qty=1.0,
        side=OrderSide.BUY.value,
        status="accepted",
        submitted_at=submitted_at,
    )
    first.store.record_order(None, OrderPhase.INCREASE.value, owned)
    first.broker._state["orders"][owned.broker_order_id] = {
        "broker_order_id": owned.broker_order_id,
        "client_order_id": owned.client_order_id,
        "symbol": symbol,
        "qty": owned.qty,
        "side": owned.side,
        "status": owned.status,
        "submitted_at": submitted_at.isoformat(),
        "filled_qty": 0.0,
        "filled_avg_price": None,
    }
    first.broker._persist()
    restarted = AutomationEngine(
        first.config,
        first.broker,
        StateStore(first.config.database_path, require_existing=True),
    )

    decision = restarted.monitor()

    assert decision.reason == "risk_checks_passed"
    assert restarted.broker.list_open_orders([symbol]) == []
    row = restarted.store.recent_orders(1)[0]
    assert row["client_order_id"] == owned.client_order_id
    assert row["status"] == "canceled"


def test_dedicated_execution_persists_halt_when_cancel_exposes_foreign_order(
    tmp_path: Path, prices: pd.DataFrame, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    engine.config = replace(engine.config, dedicated_account=True)
    engine.risk.config = engine.config
    engine.generate_plan(force=True)
    symbol = str(prices.columns[0])
    foreign = OrderReceipt(
        broker_order_id="manual-race-order",
        client_order_id="manual-race-client",
        symbol=symbol,
        qty=2.0,
        side=OrderSide.BUY.value,
        status="canceled",
        submitted_at=datetime.now(timezone.utc),
    )
    sequence: list[str] = []
    original_halt = engine.store.request_halt

    def cancel_orders(*_args, **_kwargs):
        sequence.append("cancel")
        return [foreign]

    def request_halt(reason: str, *, flatten: bool = True) -> None:
        if reason == "unauthorized_dedicated_account_order":
            sequence.append("halt")
        original_halt(reason, flatten=flatten)

    def flatten(reason: str, **_kwargs):
        assert reason == "unauthorized_dedicated_account_order"
        assert engine.store.halt_state().get("flatten") is True
        sequence.append("flatten")
        return []

    monkeypatch.setattr(engine.broker, "cancel_orders_and_wait", cancel_orders)
    monkeypatch.setattr(engine.store, "request_halt", request_halt)
    monkeypatch.setattr(engine, "emergency_flatten", flatten)

    with pytest.raises(RuntimeError, match="cancellation exposed an unauthorized"):
        engine.execute_latest_plan(force=True)

    assert sequence == ["cancel", "halt", "flatten"]
    assert engine.store.halt_state()["flatten"] is True
    assert any(
        event["code"] == "UNAUTHORIZED_ACCOUNT_ORDER"
        and "execution_cancel_race" in event["payload_json"]
        for event in engine.store.recent_events()
    )


def test_reopened_position_uses_new_flatten_attempt_id(
    tmp_path: Path, prices: pd.DataFrame
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    symbol = prices.columns[0]

    engine.broker.submit_market_order(symbol, 5.0, OrderSide.BUY, "manual-open-1")
    first = engine.emergency_flatten("persistent_test_halt", persist_halt=True)
    assert engine.broker.get_positions() == {}
    assert len(first) == 1

    # Simulate an external/manual position being reopened while the halt remains active.
    engine.broker.submit_market_order(symbol, 5.0, OrderSide.BUY, "manual-open-2")
    second = engine.emergency_flatten("persistent_test_halt", persist_halt=True)

    assert engine.broker.get_positions() == {}
    assert len(second) == 1
    assert first[0].client_order_id != second[0].client_order_id
    assert first[0].client_order_id.startswith("qauto-")
    assert second[0].client_order_id.startswith("qauto-")


def test_primary_emergency_refuses_replacement_until_reported_fill_reaches_positions(
    tmp_path: Path, prices: pd.DataFrame, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    engine.config = replace(engine.config, dedicated_account=True)
    symbol = str(prices.columns[0])
    engine.broker.submit_market_order(symbol, 5.0, OrderSide.BUY, "manual-open")
    stale_positions = dict(engine.broker.get_positions())
    original_submit = engine.broker.submit_emergency_market_order
    original_positions = engine.broker.get_positions
    emergency_submitted = False
    hide_fill = True

    def submit(*args, **kwargs):
        nonlocal emergency_submitted
        receipt = original_submit(*args, **kwargs)
        emergency_submitted = True
        return receipt

    def lagging_positions():
        if emergency_submitted and hide_fill:
            return dict(stale_positions)
        return original_positions()

    monkeypatch.setattr(engine.broker, "submit_emergency_market_order", submit)
    monkeypatch.setattr(engine.broker, "get_positions", lagging_positions)

    with pytest.raises(EmergencyFillProgressError, match="directional progress"):
        engine.emergency_flatten("lagging_position_test")

    emergency_orders = [
        row for row in engine.store.recent_orders() if row["phase"] == "flatten"
    ]
    assert len(emergency_orders) == 1
    assert engine.store.flatten_attempt_state()["status"] == "in_progress"

    # Once the broker snapshot catches up, reconciliation completes without a second
    # economic submission or a new attempt ID.
    hide_fill = False
    engine.emergency_flatten("lagging_position_test")
    assert engine.broker.get_positions() == {}
    assert len([row for row in engine.store.recent_orders() if row["phase"] == "flatten"]) == 1
    assert engine.store.flatten_attempt_state()["status"] == "completed"


def test_daemon_never_uses_oob_fallback_after_primary_fill_then_state_failure(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    symbol = str(prices.columns[0])
    engine.broker.submit_market_order(symbol, 5.0, OrderSide.BUY, "manual-open")
    stale_positions = dict(engine.broker.get_positions())
    original_submit = engine.broker.submit_emergency_market_order
    original_positions = engine.broker.get_positions
    original_record = engine.store.record_order
    emergency_submitted = False
    fail_persistence_once = True
    hide_fill = True

    def submit(*args, **kwargs):
        nonlocal emergency_submitted
        receipt = original_submit(*args, **kwargs)
        emergency_submitted = True
        return receipt

    def lagging_positions():
        if emergency_submitted and hide_fill:
            return dict(stale_positions)
        return original_positions()

    def record_with_one_failure(*args, **kwargs):
        nonlocal fail_persistence_once
        if fail_persistence_once:
            fail_persistence_once = False
            raise sqlite3.OperationalError("state persistence failed after submit")
        return original_record(*args, **kwargs)

    monkeypatch.setattr(engine.broker, "submit_emergency_market_order", submit)
    monkeypatch.setattr(engine.broker, "get_positions", lagging_positions)
    monkeypatch.setattr(engine.store, "record_order", record_with_one_failure)
    engine.config.kill_switch_path.write_text("mandatory_incident\n", encoding="utf-8")
    daemon = TradingDaemon(engine)
    monkeypatch.setattr(
        daemon,
        "_fallback_emergency_flatten",
        lambda *_args, **_kwargs: pytest.fail(
            "qauto-oob fallback is forbidden after a primary submit may have occurred"
        ),
    )

    with pytest.raises(EmergencyFillProgressError, match="directional progress"):
        daemon._observe_kill_switch()

    assert engine.store.flatten_attempt_state()["status"] == "in_progress"
    primary_orders = list(engine.broker._state["orders"].values())
    assert len([order for order in primary_orders if order["client_order_id"].startswith("qauto-")]) == 1
    assert not any("qauto-oob-" in order["client_order_id"] for order in primary_orders)

    # Retrying while positions lag resolves the same primary ID and remains
    # ambiguous. It must still never mint a broker-only replacement.
    with pytest.raises(EmergencyFillProgressError, match="directional progress"):
        daemon._observe_kill_switch()
    assert len(engine.store.recent_orders()) == 1
    assert engine.store.flatten_attempt_state()["status"] == "in_progress"

    hide_fill = False
    result = daemon._observe_kill_switch()
    assert result is not None and result["status"] in {"flattened", "already_flat"}
    assert engine.store.flatten_attempt_state()["status"] == "completed"
    assert len(engine.store.recent_orders()) == 1


def test_lifecycle_anchor_damage_cannot_prevent_single_journaled_flatten(
    tmp_path: Path,
    prices: pd.DataFrame,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    symbol = str(prices.columns[0])
    engine.broker.submit_market_order(symbol, 4.0, OrderSide.BUY, "manual-anchor-open")
    authenticated = StateStore(
        tmp_path / "damaged-authenticated-state.sqlite3",
        authentication_key=hashlib.sha256(b"damaged-state-anchor").digest(),
    )
    authenticated.clear_halt()
    authenticated.set_state("cooldown_remaining", 20)
    with authenticated.connection() as db:
        db.execute("DELETE FROM state WHERE key = 'cooldown_remaining'")
    with pytest.raises(RuntimeError, match="external checkpoint"):
        authenticated.halt_state()
    engine.store = authenticated
    engine.risk = RiskManager(engine.config, authenticated)

    receipts = engine.emergency_flatten("tampered_state_emergency")

    assert engine.broker.get_positions() == {}
    assert len(receipts) == 1
    client_ids = {
        raw["client_order_id"]
        for raw in engine.broker._state["orders"].values()
        if str(raw["client_order_id"]).startswith("qauto-emg-")
    }
    assert len(client_ids) == 1

    # A replacement daemon cannot read the damaged SQLite authentication anchor, but it
    # must reconcile the same marker/journal incident without another close order.
    daemon = TradingDaemon(engine)
    result = daemon._observe_kill_switch()
    assert result is not None and result["status"] == "already_flat"
    assert {
        raw["client_order_id"]
        for raw in engine.broker._state["orders"].values()
        if str(raw["client_order_id"]).startswith("qauto-emg-")
    } == client_ids


def test_verified_broker_reconciliation_feeds_daemon_progress(
    tmp_path: Path, prices: pd.DataFrame
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    callbacks = 0

    def progressed() -> None:
        nonlocal callbacks
        callbacks += 1

    engine.set_progress_callback(progressed)
    engine.broker.cancel_orders_and_wait(
        None,
        client_prefix=None,
        timeout_seconds=1,
        poll_seconds=1,
    )

    assert callbacks >= 1


def test_cancel_fill_race_is_resnapshotted_before_replacement_orders(
    tmp_path: Path, prices: pd.DataFrame, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    engine.generate_plan(force=True)
    symbol = prices.columns[0]
    broker = engine.broker
    order_id = "cancel-race-order"
    broker._state["orders"][order_id] = {
        "broker_order_id": order_id,
        "client_order_id": "qauto-stale-race",
        "symbol": symbol,
        "qty": 3.0,
        "side": OrderSide.BUY.value,
        "status": "accepted",
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "filled_qty": 0.0,
        "filled_avg_price": None,
    }
    engine.store.record_order(
        None,
        OrderPhase.INCREASE.value,
        OrderReceipt(
            broker_order_id=order_id,
            client_order_id="qauto-stale-race",
            symbol=str(symbol),
            qty=3.0,
            side=OrderSide.BUY.value,
            status="accepted",
            submitted_at=datetime.fromisoformat(
                broker._state["orders"][order_id]["submitted_at"]
            ),
        ),
    )
    broker._persist()
    original_cancel = broker.cancel_order

    def fill_while_canceling(broker_order_id: str) -> None:
        if broker_order_id != order_id:
            original_cancel(broker_order_id)
            return
        raw = broker._state["orders"][order_id]
        price = broker._last_prices()[symbol]
        qty = float(raw["qty"])
        broker._state["cash"] = float(broker._state["cash"]) - qty * price
        broker._state["positions"][symbol] = (
            float(broker._state["positions"].get(symbol, 0.0)) + qty
        )
        raw.update(status="filled", filled_qty=qty, filled_avg_price=price)
        broker._persist()
        raise RuntimeError("broker rejected cancellation because the order already filled")

    monkeypatch.setattr(broker, "cancel_order", fill_while_canceling)

    summary = engine.execute_latest_plan(force=True)

    assert summary.status == "executed"
    assert summary.residual_notional <= engine.config.residual_notional_tolerance
    assert broker._state["orders"][order_id]["status"] == "filled"


def test_unconfirmed_cancellation_blocks_replacement_without_liquidation(
    tmp_path: Path, prices: pd.DataFrame, monkeypatch: pytest.MonkeyPatch
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    engine.config = replace(
        engine.config,
        order_fill_timeout_seconds=0,
        order_poll_seconds=0,
    )
    engine.generate_plan(force=True)
    symbol = str(prices.columns[0])
    broker = engine.broker
    order_id = "stuck-cancel-order"
    broker._state["orders"][order_id] = {
        "broker_order_id": order_id,
        "client_order_id": "qauto-stuck-cancel",
        "symbol": symbol,
        "qty": 3.0,
        "side": OrderSide.BUY.value,
        "status": "accepted",
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "filled_qty": 0.0,
        "filled_avg_price": None,
    }
    engine.store.record_order(
        None,
        OrderPhase.INCREASE.value,
        OrderReceipt(
            broker_order_id=order_id,
            client_order_id="qauto-stuck-cancel",
            symbol=str(symbol),
            qty=3.0,
            side=OrderSide.BUY.value,
            status="accepted",
            submitted_at=datetime.fromisoformat(
                broker._state["orders"][order_id]["submitted_at"]
            ),
        ),
    )
    broker._persist()
    monkeypatch.setattr(broker, "cancel_order", lambda _order_id: None)

    with pytest.raises(RuntimeError, match="cancellation was not confirmed"):
        engine.execute_latest_plan(force=True)

    assert broker._state["orders"][order_id]["status"] == "accepted"
    assert broker.get_positions() == {}
    persisted = engine.store.recent_orders()
    assert len(persisted) == 1
    assert persisted[0]["client_order_id"] == "qauto-stuck-cancel"
    assert persisted[0]["status"] == "accepted"
    assert engine.store.halt_state()["active"] is True
    assert engine.store.halt_state()["flatten"] is False


def test_cancellation_rejects_broker_order_identity_mutation(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    broker = engine.broker
    symbol = str(prices.columns[0])
    order_id = "cancel-identity-order"
    raw = {
        "broker_order_id": order_id,
        "client_order_id": "qauto-cancel-identity",
        "symbol": symbol,
        "qty": 1.0,
        "side": "buy",
        "status": "accepted",
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "filled_qty": 0.0,
        "filled_avg_price": None,
    }
    broker._state["orders"][order_id] = raw
    broker._persist()
    original_get_order = broker.get_order

    def mutated_get_order(broker_order_id: str) -> OrderReceipt:
        return replace(
            original_get_order(broker_order_id),
            client_order_id="different-economic-order",
        )

    monkeypatch.setattr(broker, "get_order", mutated_get_order)

    with pytest.raises(RuntimeError, match="order identity changed during cancellation"):
        broker.cancel_orders_and_wait(
            [symbol],
            timeout_seconds=1,
            poll_seconds=0.01,
        )


def test_dedicated_account_orphan_position_triggers_incident_and_emergency_flatten(
    tmp_path: Path, prices: pd.DataFrame
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    plan_symbols = list(prices.columns[:8])
    orphan = str(prices.columns[8])
    engine.config = replace(
        engine.config,
        symbols=tuple(plan_symbols),
        dedicated_account=True,
    )
    plan = TargetPlan(
        plan_id="dedicated-orphan-cleanup",
        as_of=prices.index[-1].date(),
        created_at=datetime.now(timezone.utc),
        regime="defensive",
        regime_multiplier=0.0,
        desired_gross=0.0,
        forecast_volatility=0.1,
        target_weights={symbol: 0.0 for symbol in plan_symbols},
        metadata={
            "assets": plan_symbols,
            "gross_weight": 0.0,
            "account_equity": 100_000.0,
        },
    )
    plan = seal_target_plan(plan, engine._current_plan_binding())
    assert engine.store.save_plan(plan)
    engine.broker.submit_market_order(orphan, 7.0, OrderSide.BUY, "external-orphan")

    with pytest.raises(RuntimeError, match="outside the authenticated plan universe"):
        engine.execute_latest_plan(force=True)

    assert engine.broker.get_positions() == {}
    halt = engine.store.halt_state()
    assert halt["active"] is True
    assert halt["flatten"] is True


def test_emergency_flatten_retries_partial_fill_and_reconciles(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    engine.config = replace(
        engine.config,
        order_fill_timeout_seconds=0,
        order_poll_seconds=0,
    )
    symbol = str(prices.columns[0])
    broker = engine.broker
    broker.submit_market_order(symbol, 10.0, OrderSide.BUY, "manual-partial-open")
    original_submit = broker.submit_market_order
    partial_submitted = False

    def partial_once(
        order_symbol: str,
        qty: float,
        side: OrderSide,
        client_order_id: str,
    ):
        nonlocal partial_submitted
        if not client_order_id.startswith("qauto-emg-") or partial_submitted:
            return original_submit(order_symbol, qty, side, client_order_id)
        partial_submitted = True
        fill_qty = float(qty) / 2.0
        price = broker._last_prices()[order_symbol]
        signed_fill = fill_qty if side == OrderSide.BUY else -fill_qty
        old_qty = float(broker._state["positions"].get(order_symbol, 0.0))
        broker._state["positions"][order_symbol] = old_qty + signed_fill
        broker._state["cash"] = float(broker._state["cash"]) - signed_fill * price
        order_id = "partial-flatten-order"
        raw = {
            "broker_order_id": order_id,
            "client_order_id": client_order_id,
            "symbol": order_symbol,
            "qty": float(qty),
            "side": side.value,
            "status": "partially_filled",
            "submitted_at": datetime.now(timezone.utc).isoformat(),
            "filled_qty": fill_qty,
            "filled_avg_price": price,
        }
        broker._state["orders"][order_id] = raw
        broker._persist()
        return broker._receipt(raw)

    monkeypatch.setattr(broker, "submit_market_order", partial_once)

    receipts = engine.emergency_flatten("partial_fill_test")

    assert engine.broker.get_positions() == {}
    assert [receipt.status for receipt in receipts] == ["canceled", "filled"]
    assert receipts[0].client_order_id != receipts[1].client_order_id
    assert engine.store.get_state("flatten_attempt")["status"] == "completed"
    assert engine.broker.list_open_orders(None) == []


def test_emergency_flatten_uses_the_dedicated_uncollared_order_path(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    broker = engine.broker
    symbol = str(prices.columns[0])
    original_submit = broker.submit_market_order
    original_submit(symbol, 3.0, OrderSide.BUY, "manual-emergency-path-open")
    emergency_calls = 0

    def emergency_submit(
        order_symbol: str,
        qty: float,
        side: OrderSide,
        client_order_id: str,
    ) -> OrderReceipt:
        nonlocal emergency_calls
        emergency_calls += 1
        return original_submit(order_symbol, qty, side, client_order_id)

    def forbidden_routine_submit(*_args, **_kwargs):
        raise AssertionError("emergency flatten must not use the routine order path")

    monkeypatch.setattr(broker, "submit_emergency_market_order", emergency_submit)
    monkeypatch.setattr(broker, "submit_market_order", forbidden_routine_submit)

    engine.emergency_flatten("dedicated_emergency_path_test")

    assert emergency_calls == 1
    assert broker.get_positions() == {}


def test_emergency_flatten_fails_closed_after_bounded_rejections(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    symbol = str(prices.columns[0])
    broker = engine.broker
    broker.submit_market_order(symbol, 10.0, OrderSide.BUY, "manual-rejected-open")
    submission_calls = 0
    client_ids: list[str] = []

    def reject_flatten(
        order_symbol: str,
        qty: float,
        side: OrderSide,
        client_order_id: str,
    ):
        nonlocal submission_calls
        submission_calls += 1
        client_ids.append(client_order_id)
        existing = next(
            (
                raw
                for raw in broker._state["orders"].values()
                if raw.get("client_order_id") == client_order_id
            ),
            None,
        )
        if existing is not None:
            return broker._receipt(existing)
        order_id = f"rejected-flatten-{submission_calls}"
        raw = {
            "broker_order_id": order_id,
            "client_order_id": client_order_id,
            "symbol": order_symbol,
            "qty": float(qty),
            "side": side.value,
            "status": "rejected",
            "submitted_at": datetime.now(timezone.utc).isoformat(),
            "filled_qty": 0.0,
            "filled_avg_price": None,
        }
        broker._state["orders"][order_id] = raw
        broker._persist()
        return broker._receipt(raw)

    monkeypatch.setattr(broker, "submit_market_order", reject_flatten)

    with pytest.raises(EmergencyPrimarySubmissionError, match="primary emergency order"):
        engine.emergency_flatten("persistent_rejection_test")

    assert submission_calls == 3
    assert len(set(client_ids)) == 3
    assert engine.store.is_halted()
    assert engine.store.halt_state()["flatten"] is True
    assert engine.store.get_state("flatten_attempt")["status"] == "in_progress"
    assert engine.broker.get_positions()[symbol].qty == pytest.approx(10.0)


def test_alpaca_cash_activity_history_is_fully_paginated_and_parsed() -> None:
    from auto_trader.brokers.alpaca import AlpacaBroker

    first_page = [
        {
            "id": f"20260701000000000::cash-{index:03d}",
            "activity_type": "CSD",
            "date": "2026-07-01",
            "net_amount": "100.00",
            "status": "executed",
            "currency": "USD",
        }
        for index in range(100)
    ]
    second_page = [
        {
            "id": "20260702000000000::cash-final",
            "activity_type": "CSW",
            "date": "2026-07-02",
            "net_amount": "-25.00",
            "status": "executed",
            "currency": "USD",
        }
    ]

    class TradingStub:
        calls: list[dict[str, object]] = []

        def get(self, path, params):
            assert path == "/account/activities"
            self.calls.append(dict(params))
            return second_page if "page_token" in params else first_page

    broker = AlpacaBroker.__new__(AlpacaBroker)
    broker.trading = TradingStub()

    activities = broker._get_external_cash_activities()

    assert len(activities) == 101
    assert len(broker.trading.calls) == 2
    assert broker.trading.calls[1]["page_token"] == first_page[-1]["id"]
    assert activities[-1].activity_type == "CSW"
    assert activities[-1].net_amount == pytest.approx(-25.0)


def test_alpaca_cash_activity_failure_is_returned_as_unavailable_evidence() -> None:
    from auto_trader.brokers.alpaca import AlpacaBroker

    class TradingStub:
        @staticmethod
        def get_account():
            return SimpleNamespace(
                equity="100000",
                cash="100000",
                buying_power="200000",
                last_equity="100000",
                trading_blocked=False,
                account_blocked=False,
                shorting_enabled=True,
                multiplier="2",
            )

        @staticmethod
        def get(_path, _params):
            raise RuntimeError("activity endpoint unavailable")

    broker = AlpacaBroker.__new__(AlpacaBroker)
    broker.trading = TradingStub()

    account = broker.get_account()

    assert account.external_cash_activities is None
    assert account.cash_activity_error == "RuntimeError"


def test_alpaca_existing_client_id_must_match_economic_intent() -> None:
    from auto_trader.brokers.alpaca import AlpacaBroker

    existing = SimpleNamespace(
        id="broker-order-1",
        client_order_id="qauto-intent-collision",
        symbol="SPY",
        qty=2.0,
        side="buy",
        status="filled",
        submitted_at=datetime.now(timezone.utc),
        created_at=None,
        filled_qty=2.0,
        filled_avg_price=500.0,
    )

    class TradingStub:
        def get_order_by_client_id(self, _client_order_id):
            return existing

    broker = AlpacaBroker.__new__(AlpacaBroker)
    broker.trading = TradingStub()
    broker._routine_execution_authorized_until = datetime.now(timezone.utc) + timedelta(days=1)

    def forbidden_authorization() -> None:
        raise AssertionError("existing-ID reconciliation must remain read-only")

    broker._routine_authorization_check = forbidden_authorization

    with pytest.raises(RuntimeError, match="does not match the requested"):
        broker.submit_market_order(
            "SPY", 1.0, OrderSide.BUY, "qauto-intent-collision"
        )


def test_alpaca_duplicate_lookup_failure_blocks_submission() -> None:
    from auto_trader.brokers.alpaca import AlpacaBroker
    class LookupFailure(Exception):
        status_code = 503

    class TradingStub:
        submitted = False

        def get_order_by_client_id(self, _client_order_id):
            raise LookupFailure("service unavailable")

        def submit_order(self, **_kwargs):
            self.submitted = True
            raise AssertionError("submit_order must not be called")

    broker = AlpacaBroker.__new__(AlpacaBroker)
    broker.trading = TradingStub()
    broker._routine_execution_authorized_until = datetime.now(timezone.utc) + timedelta(days=1)
    broker._routine_authorization_check = lambda *_args: None

    with pytest.raises(RuntimeError, match="blocked to prevent a duplicate"):
        broker.submit_market_order("SPY", 1.0, OrderSide.BUY, "qauto-test-i-SPY-0")
    assert broker.trading.submitted is False


def test_kill_switch_interrupts_fill_wait_and_confirms_cancellation(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    engine.config = replace(
        engine.config,
        order_poll_seconds=0.01,
        order_fill_timeout_seconds=2,
    )
    plan = TargetPlan(
        plan_id="kill-interrupt-plan",
        as_of=date(2026, 6, 30),
        created_at=datetime.now(timezone.utc),
        regime="neutral",
        regime_multiplier=1.0,
        desired_gross=0.1,
        forecast_volatility=0.1,
        target_weights={str(prices.columns[0]): 0.05},
        metadata={"assets": [str(prices.columns[0])]},
    )
    plan = seal_target_plan(plan, engine._current_plan_binding())
    assert engine.store.save_plan(plan)
    accepted = OrderReceipt(
        broker_order_id="pending-order",
        client_order_id="qauto-kill-interrupt",
        symbol=str(prices.columns[0]),
        qty=1.0,
        side="buy",
        status="accepted",
        submitted_at=datetime.now(timezone.utc),
    )
    canceled = replace(accepted, status="canceled")
    lookups = 0
    cancellation_confirmed = False

    def get_order(_order_id: str) -> OrderReceipt:
        nonlocal lookups
        lookups += 1
        if lookups == 1:
            engine.config.kill_switch_path.write_text("operator_interrupt\n", encoding="utf-8")
        return accepted

    def cancel_and_wait(_order_id: str, **_kwargs) -> OrderReceipt:
        nonlocal cancellation_confirmed
        cancellation_confirmed = True
        return canceled

    monkeypatch.setattr(engine.broker, "get_order", get_order)
    monkeypatch.setattr(engine.broker, "cancel_order_and_wait", cancel_and_wait)

    with pytest.raises(RuntimeError, match="interrupted by the filesystem kill switch"):
        engine._wait_for_receipts(plan.plan_id, None, [accepted])

    assert cancellation_confirmed is True
    assert engine.store.recent_orders(1)[0]["status"] == "canceled"


def test_routine_receipt_wait_cancels_at_hard_0935_deadline(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    accepted = OrderReceipt(
        broker_order_id="pending-at-benchmark-end",
        client_order_id="qauto-benchmark-deadline",
        symbol=str(prices.columns[0]),
        qty=1.0,
        side="buy",
        status="accepted",
        submitted_at=datetime.now(timezone.utc),
    )
    canceled = replace(accepted, status="canceled")
    deadline = datetime.now(timezone.utc) + timedelta(days=1)
    canceled_at_deadline = False
    monkeypatch.setattr(
        engine.broker,
        "get_market_clock",
        lambda: MarketClock(deadline, True, deadline, deadline),
    )

    def cancel_and_wait(_order_id: str, **_kwargs) -> OrderReceipt:
        nonlocal canceled_at_deadline
        canceled_at_deadline = True
        return canceled

    monkeypatch.setattr(engine.broker, "cancel_order_and_wait", cancel_and_wait)
    monkeypatch.setattr(engine.store, "record_order", lambda *_args, **_kwargs: None)

    with pytest.raises(RuntimeError, match="pre-deadline terminality was not proven"):
        engine._wait_for_receipts(
            "benchmark-plan",
            None,
            [accepted],
            routine_deadline=deadline,
        )

    assert canceled_at_deadline is True
    assert engine.store.halt_state()["flatten"] is True


def test_monitor_flattens_actual_account_exposure_breach(
    tmp_path: Path,
    prices: pd.DataFrame,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    engine.config = replace(engine.config, dedicated_account=True)
    symbol = str(prices.columns[0])
    plan = TargetPlan(
        plan_id="actual-exposure-monitor-plan",
        as_of=date(2026, 6, 30),
        created_at=datetime.now(timezone.utc),
        regime="neutral",
        regime_multiplier=1.0,
        desired_gross=0.1,
        forecast_volatility=0.1,
        target_weights={symbol: 0.05},
        metadata={
            "assets": [str(column) for column in prices.columns],
            "asset_beta": {str(column): 1.0 for column in prices.columns},
        },
    )
    plan = seal_target_plan(plan, engine._current_plan_binding())
    assert engine.store.save_plan(plan)
    price = engine.broker.get_latest_prices([symbol])[symbol]
    # Twenty percent one-way exposure is below the gross cap but violates both the
    # dollar-neutral account limit and the configured position concentration limit.
    quantity = max(1.0, round(0.20 * 100_000.0 / price))
    engine.broker.submit_market_order(symbol, quantity, OrderSide.BUY, "manual-exposure-breach")

    decision = engine.monitor()

    assert decision.reason == "actual_net_exposure_breach"
    assert decision.flatten is True
    assert decision.halt is True
    assert engine.broker.get_positions() == {}
    assert engine.store.halt_state()["active"] is True


def test_monitor_flattens_when_position_metadata_authentication_fails(
    tmp_path: Path,
    prices: pd.DataFrame,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    engine.config = replace(engine.config, dedicated_account=True)
    engine.risk.config = engine.config
    plan = engine.generate_plan(force=True)
    symbol = str(prices.columns[0])
    price = engine.broker.get_latest_prices([symbol])[symbol]
    engine.broker.submit_market_order(
        symbol,
        max(1.0, round(5_000.0 / price)),
        OrderSide.BUY,
        "authenticated-plan-tamper-position",
    )
    with engine.store.connection() as db:
        row = db.execute(
            "SELECT metadata_json FROM plans WHERE plan_id = ?", (plan.plan_id,)
        ).fetchone()
        metadata = json.loads(row["metadata_json"])
        metadata["asset_beta"][symbol] = 999.0
        db.execute(
            "UPDATE plans SET metadata_json = ? WHERE plan_id = ?",
            (json.dumps(metadata, sort_keys=True), plan.plan_id),
        )

    decision = engine.monitor()

    assert decision.reason == "actual_plan_metadata_integrity_breach"
    assert decision.flatten is True and decision.halt is True
    assert engine.broker.get_positions() == {}
    assert engine.store.halt_state()["flatten"] is True


def test_forged_newer_nonapproved_plan_does_not_mask_latest_valid_plan(
    tmp_path: Path,
    prices: pd.DataFrame,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=False)
    authentication_key = hashlib.sha256(b"plan-lifecycle-monitor-test").digest()
    engine.store = StateStore(
        tmp_path / "authenticated-plan-lifecycle.sqlite3",
        authentication_key=authentication_key,
    )
    engine.risk = RiskManager(engine.config, engine.store)
    symbol = str(prices.columns[0])
    valid = TargetPlan(
        plan_id="",
        as_of=date(2026, 6, 29),
        created_at=datetime(2026, 6, 30, tzinfo=timezone.utc),
        regime="neutral",
        regime_multiplier=1.0,
        desired_gross=0.1,
        forecast_volatility=0.1,
        target_weights={symbol: 0.05},
        metadata={"assets": [symbol], "asset_beta": {symbol: 1.0}},
        status="executed",
    )
    valid = seal_target_plan(valid, engine._current_plan_binding())
    assert engine.store.save_plan(valid)
    forged = TargetPlan(
        plan_id="",
        as_of=date(2026, 6, 30),
        created_at=datetime(2026, 7, 1, tzinfo=timezone.utc),
        regime="neutral",
        regime_multiplier=1.0,
        desired_gross=0.1,
        forecast_volatility=0.1,
        target_weights={"ATTACKER": 0.9},
        metadata={"assets": ["ATTACKER"], "asset_beta": {"ATTACKER": 0.0}},
        status="approved",
    )
    # Seal the immutable content so this regression isolates lifecycle authentication
    # rather than merely exercising the separate plan-content HMAC.
    forged = seal_target_plan(forged, engine._current_plan_binding())
    assert engine.store.save_plan(forged)
    # A database writer tries to promote a newer, nonapproved row by rewriting only
    # mutable lifecycle state. It cannot forge the lifecycle MAC or anchor.
    with engine.store.connection() as db:
        db.execute(
            "UPDATE plans SET status = ? WHERE plan_id = ?",
            ("failed", forged.plan_id),
        )

    selected, integrity_issues = engine._validated_monitor_plan()

    assert selected is not None and selected.plan_id == valid.plan_id
    assert integrity_issues


def test_hard_to_borrow_short_is_rejected_by_default(
    tmp_path: Path,
    prices: pd.DataFrame,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=False)
    symbol = str(prices.columns[0])
    plan = TargetPlan(
        plan_id="borrow-eligibility-plan",
        as_of=date(2026, 6, 30),
        created_at=datetime.now(timezone.utc),
        regime="neutral",
        regime_multiplier=1.0,
        desired_gross=0.1,
        forecast_volatility=0.1,
        target_weights={symbol: -0.05},
        metadata={"assets": [symbol]},
    )
    info = AssetInfo(
        symbol=symbol,
        tradable=True,
        shortable=True,
        easy_to_borrow=False,
        fractionable=True,
        marginable=True,
    )
    with pytest.raises(RuntimeError, match="not eligible for the planned short"):
        engine._target_quantities(
            plan,
            engine.broker.get_account(),
            engine.broker.get_latest_prices([symbol]),
            {symbol: info},
        )


def test_actual_beta_exposure_is_monitored_independently_of_net(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=False)
    engine.config = replace(engine.config, dedicated_account=True)
    long_symbol, short_symbol = map(str, prices.columns[:2])
    plan = TargetPlan(
        plan_id="actual-beta-monitor-plan",
        as_of=date(2026, 6, 30),
        created_at=datetime.now(timezone.utc),
        regime="neutral",
        regime_multiplier=1.0,
        desired_gross=0.2,
        forecast_volatility=0.1,
        target_weights={long_symbol: 0.05, short_symbol: -0.05},
        metadata={
            "assets": [long_symbol, short_symbol],
            "asset_beta": {long_symbol: 2.0, short_symbol: 0.0},
        },
    )
    plan = seal_target_plan(plan, engine._current_plan_binding())
    assert engine.store.save_plan(plan)
    monkeypatch.setattr(
        engine.broker,
        "get_positions",
        lambda: {
            long_symbol: PositionSnapshot(long_symbol, 100.0, 10_000.0, 100.0),
            short_symbol: PositionSnapshot(short_symbol, -100.0, -10_000.0, 100.0),
        },
    )

    reason, metrics = engine._actual_exposure_breach(engine.broker.get_account())

    assert reason == "actual_beta_exposure_breach"
    assert metrics["net_exposure"] == pytest.approx(0.0)
    assert metrics["beta_exposure"] == pytest.approx(0.2)


@pytest.mark.parametrize(
    ("beta_map", "metric"),
    [
        ({"LONG": 1.0}, "missing_beta_count"),
        ({"LONG": 1.0, "SHORT": "not-a-number"}, "invalid_beta_count"),
    ],
)
def test_actual_beta_monitor_fails_closed_on_incomplete_metadata(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
    beta_map: dict[str, object],
    metric: str,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=False)
    engine.config = replace(engine.config, dedicated_account=True)
    plan = TargetPlan(
        plan_id="missing-beta-monitor-plan",
        as_of=date(2026, 6, 30),
        created_at=datetime.now(timezone.utc),
        regime="neutral",
        regime_multiplier=1.0,
        desired_gross=0.2,
        forecast_volatility=0.1,
        target_weights={"LONG": 0.05, "SHORT": -0.05},
        metadata={"assets": ["LONG", "SHORT"], "asset_beta": beta_map},
    )
    plan = seal_target_plan(plan, engine._current_plan_binding())
    assert engine.store.save_plan(plan)
    monkeypatch.setattr(
        engine.broker,
        "get_positions",
        lambda: {
            "LONG": PositionSnapshot("LONG", 100.0, 10_000.0, 100.0),
            "SHORT": PositionSnapshot("SHORT", -100.0, -10_000.0, 100.0),
        },
    )

    reason, metrics = engine._actual_exposure_breach(engine.broker.get_account())

    assert reason == "actual_beta_metadata_breach"
    assert metrics[metric] == pytest.approx(1.0)


def test_execution_prices_never_fall_back_to_stale_position_marks(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=False)
    symbol = str(prices.columns[0])
    stale_position = PositionSnapshot(
        symbol=symbol,
        qty=10.0,
        market_value=1_000.0,
        current_price=100.0,
    )
    monkeypatch.setattr(engine.broker, "get_latest_prices", lambda _symbols: {})

    prices_result = engine._execution_prices(
        [symbol],
        {symbol: stale_position},
    )

    assert prices_result == {}
    plan = TargetPlan(
        plan_id="missing-fresh-quote-plan",
        as_of=date(2026, 6, 30),
        created_at=datetime.now(timezone.utc),
        regime="neutral",
        regime_multiplier=1.0,
        desired_gross=0.05,
        forecast_volatility=0.1,
        target_weights={symbol: 0.05},
        metadata={"assets": [symbol]},
    )
    with pytest.raises(RuntimeError, match=f"No valid execution price for {symbol}"):
        engine._target_quantities(
            plan,
            engine.broker.get_account(),
            prices_result,
            engine.broker.get_asset_info([symbol]),
        )


def test_alpaca_execution_prices_require_fresh_tight_quotes() -> None:
    from alpaca.data.enums import DataFeed
    from auto_trader.brokers.alpaca import AlpacaBroker

    now = datetime.now(timezone.utc)

    class DataStub:
        def get_stock_latest_quote(self, _request):
            return {
                "FRESH": SimpleNamespace(
                    bid_price=99.95,
                    ask_price=100.05,
                    timestamp=now,
                ),
                "WIDE": SimpleNamespace(
                    bid_price=99.0,
                    ask_price=101.0,
                    timestamp=now,
                ),
                "STALE": SimpleNamespace(
                    bid_price=49.98,
                    ask_price=50.02,
                    timestamp=now - timedelta(seconds=120),
                ),
                "FUTURE": SimpleNamespace(
                    bid_price=49.98,
                    ask_price=50.02,
                    timestamp=now + timedelta(seconds=30),
                ),
                "NAIVE": SimpleNamespace(
                    bid_price=49.98,
                    ask_price=50.02,
                    timestamp=now.replace(tzinfo=None),
                ),
                "NONFINITE": SimpleNamespace(
                    bid_price=float("nan"),
                    ask_price=50.02,
                    timestamp=now,
                ),
            }

    broker = AlpacaBroker.__new__(AlpacaBroker)
    broker.data = DataStub()
    broker.feed = DataFeed.IEX
    broker.max_execution_price_age_seconds = 60
    broker.max_execution_spread_bps = 50.0

    prices_result = broker.get_latest_prices(
        ["FRESH", "WIDE", "STALE", "FUTURE", "NAIVE", "NONFINITE"]
    )

    assert prices_result == {"FRESH": pytest.approx(100.0)}


def test_alpaca_routine_orders_are_collared_but_emergency_orders_are_market() -> None:
    from alpaca.data.enums import DataFeed
    from alpaca.trading.requests import LimitOrderRequest, MarketOrderRequest
    from auto_trader.brokers.alpaca import AlpacaBroker

    now = datetime.now(timezone.utc)
    events: list[str] = []

    class MissingOrder(Exception):
        status_code = 404

    class DataStub:
        calls = 0

        def get_stock_latest_quote(self, _request):
            self.calls += 1
            events.append("quote")
            return {
                "SPY": SimpleNamespace(
                    bid_price=99.95,
                    ask_price=100.05,
                    timestamp=now,
                )
            }

    class TradingStub:
        def __init__(self) -> None:
            self.requests = []

        @staticmethod
        def get_order_by_client_id(_client_order_id):
            events.append("lookup")
            raise MissingOrder("not found")

        def submit_order(self, *, order_data):
            events.append("submit")
            self.requests.append(order_data)
            return SimpleNamespace(
                id=f"broker-{len(self.requests)}",
                client_order_id=order_data.client_order_id,
                symbol=order_data.symbol,
                qty=order_data.qty,
                side=order_data.side,
                status="accepted",
                submitted_at=now,
                created_at=None,
                filled_qty=0.0,
                filled_avg_price=None,
            )

    broker = AlpacaBroker.__new__(AlpacaBroker)
    broker.trading = TradingStub()
    broker.data = DataStub()
    broker.feed = DataFeed.IEX
    broker.max_execution_price_age_seconds = 60
    broker.max_execution_spread_bps = 50.0
    broker.marketable_limit_collar_bps = 35.0
    broker._routine_execution_authorized_until = datetime.now(timezone.utc) + timedelta(days=1)
    authorized_economics: list[tuple[str, float, OrderSide, float]] = []

    def authorize(symbol: str, qty: float, side: OrderSide, limit_price: float) -> None:
        events.append("authorization")
        authorized_economics.append((symbol, qty, side, limit_price))

    broker._routine_authorization_check = authorize

    broker.submit_market_order("SPY", 2.0, OrderSide.BUY, "qauto-routine-collar")
    broker.submit_emergency_market_order(
        "SPY", 2.0, OrderSide.SELL, "qauto-emergency-market"
    )

    routine, emergency = broker.trading.requests
    assert isinstance(routine, LimitOrderRequest)
    assert routine.limit_price == pytest.approx(100.35)
    assert authorized_economics == [("SPY", 2.0, OrderSide.BUY, pytest.approx(100.35))]
    assert isinstance(emergency, MarketOrderRequest)
    assert broker.data.calls == 1
    assert events == [
        "lookup",
        "quote",
        "authorization",
        "submit",
        "lookup",
        "submit",
    ]


def test_alpaca_routine_order_blocks_when_no_compliant_quote_exists() -> None:
    from alpaca.data.enums import DataFeed
    from auto_trader.brokers.alpaca import AlpacaBroker

    class MissingOrder(Exception):
        status_code = 404

    class TradingStub:
        submitted = False

        @staticmethod
        def get_order_by_client_id(_client_order_id):
            raise MissingOrder("not found")

        def submit_order(self, **_kwargs):
            self.submitted = True
            raise AssertionError("a routine order without a valid quote must not be sent")

    class DataStub:
        @staticmethod
        def get_stock_latest_quote(_request):
            return {}

    broker = AlpacaBroker.__new__(AlpacaBroker)
    broker.trading = TradingStub()
    broker.data = DataStub()
    broker.feed = DataFeed.IEX
    broker.max_execution_price_age_seconds = 60
    broker.max_execution_spread_bps = 50.0
    broker.marketable_limit_collar_bps = 35.0
    broker._routine_execution_authorized_until = datetime.now(timezone.utc) + timedelta(days=1)
    broker._routine_authorization_check = lambda *_args: None

    with pytest.raises(RuntimeError, match="blocked rather than sent without a price collar"):
        broker.submit_market_order("SPY", 1.0, OrderSide.BUY, "qauto-no-quote")

    assert broker.trading.submitted is False


def test_alpaca_limit_tick_rounding_never_widens_the_configured_collar() -> None:
    from auto_trader.brokers.alpaca import AlpacaBroker

    broker = AlpacaBroker.__new__(AlpacaBroker)
    broker.marketable_limit_collar_bps = 35.0
    midpoint = 10.001
    raw_buy_cap = midpoint * 1.0035
    raw_sell_floor = midpoint * 0.9965

    buy_limit = broker._marketable_limit_price(midpoint, OrderSide.BUY)
    sell_limit = broker._marketable_limit_price(midpoint, OrderSide.SELL)

    assert buy_limit <= raw_buy_cap
    assert sell_limit >= raw_sell_floor
    assert buy_limit == pytest.approx(10.03)
    assert sell_limit == pytest.approx(9.97)


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    [
        ("equity", float("nan")),
        ("cash", float("inf")),
        ("buying_power", -1.0),
        ("last_equity", 0.0),
        ("multiplier", float("inf")),
    ],
)
def test_invalid_broker_account_snapshot_forces_persistent_flatten_halt(
    tmp_path: Path,
    prices: pd.DataFrame,
    field: str,
    unsafe_value: float,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    account = replace(engine.broker.get_account(), **{field: unsafe_value})

    decision = engine.risk.evaluate_and_record(
        account, engine._local_time(account.timestamp).date()
    )

    assert decision.reason == "invalid_broker_account_snapshot"
    assert decision.flatten is True
    assert decision.halt is True
    halt = engine.store.halt_state()
    assert halt["active"] is True
    assert halt["flatten"] is True


def _alpaca_cash_risk_config(
    tmp_path: Path,
    *,
    execution_enabled: bool,
) -> BotConfig:
    base = BotConfig()
    return replace(
        base,
        broker="alpaca",
        execution_enabled=execution_enabled,
        plan_authentication_key=_TEST_PLAN_AUTHENTICATION_KEY,
        database_path=tmp_path / "cash-risk.sqlite3",
        kill_switch_path=tmp_path / "KILL_SWITCH",
        strategy=replace(
            base.strategy,
            costs=replace(base.strategy.costs, starting_capital=100_000.0),
        ),
    )


def _cash_risk_snapshot(
    *,
    equity: float = 100_000.0,
    activities: tuple[CashActivity, ...] | None = (),
    error: str = "",
) -> AccountSnapshot:
    return AccountSnapshot(
        timestamp=datetime(2026, 7, 13, 15, 0, tzinfo=timezone.utc),
        equity=equity,
        cash=equity,
        buying_power=equity * 2.0,
        last_equity=100_000.0,
        multiplier=2.0,
        external_cash_activities=activities,
        cash_activity_error=error,
    )


@pytest.mark.parametrize(
    ("activity_type", "net_amount", "post_flow_equity"),
    [("CSD", 100_000.0, 190_000.0), ("CSW", -20_000.0, 80_000.0)],
)
def test_new_alpaca_cash_flow_halts_before_risk_baselines_move(
    tmp_path: Path,
    activity_type: str,
    net_amount: float,
    post_flow_equity: float,
) -> None:
    plan_only = _alpaca_cash_risk_config(tmp_path, execution_enabled=False)
    store = StateStore(plan_only.database_path)
    session = date(2026, 7, 13)
    baseline = _cash_risk_snapshot()
    first = RiskManager(plan_only, store).evaluate_and_record(baseline, session)
    assert first.allow_new_risk is True
    assert store.get_state("high_watermark") == pytest.approx(100_000.0)

    flow = CashActivity(
        activity_id=f"20260713000000000::{activity_type.lower()}-flow",
        activity_type=activity_type,
        activity_date=session,
        net_amount=net_amount,
        status="executed",
        currency="USD",
    )
    execution = _alpaca_cash_risk_config(tmp_path, execution_enabled=True)
    changed = _cash_risk_snapshot(
        equity=post_flow_equity,
        activities=(flow,),
    )
    incident = RiskManager(execution, store).evaluate_and_record(changed, session)

    assert incident.reason == "external_cash_activity_detected"
    assert incident.halt is True
    assert incident.flatten is True
    # A deposit cannot raise the high-water mark and a withdrawal cannot rewrite the
    # daily/five-day baselines before independent reconciliation.
    assert store.get_state("high_watermark") == pytest.approx(100_000.0)
    assert store.halt_state()["flatten"] is True
    monitor = store.cash_activity_monitor_state()
    assert monitor is not None and monitor["incident_active"] is True
    assert flow.activity_id in monitor["incident_activity_ids"]

    repeated = RiskManager(execution, store).evaluate_and_record(
        changed,
        session,
        ignore_operator_controls=True,
    )
    assert repeated.reason == "external_cash_activity_reconciliation_required"
    assert repeated.allow_new_risk is False


def test_alpaca_cash_evidence_unavailable_fails_closed(tmp_path: Path) -> None:
    config = _alpaca_cash_risk_config(tmp_path, execution_enabled=True)
    store = StateStore(config.database_path)

    decision = RiskManager(config, store).evaluate_and_record(
        _cash_risk_snapshot(activities=None, error="APIError"),
        date(2026, 7, 13),
    )

    assert decision.reason == "cash_activity_evidence_unavailable"
    assert decision.flatten is True
    assert store.get_state("high_watermark", None) is None


def test_alpaca_execution_cannot_self_initialize_cash_history(tmp_path: Path) -> None:
    config = _alpaca_cash_risk_config(tmp_path, execution_enabled=True)
    store = StateStore(config.database_path)

    decision = RiskManager(config, store).evaluate_and_record(
        _cash_risk_snapshot(),
        date(2026, 7, 13),
    )

    assert decision.reason == "cash_activity_monitor_uninitialized"
    monitor = store.cash_activity_monitor_state()
    assert monitor is not None
    assert monitor["initialized"] is False
    assert monitor["incident_active"] is True
    assert store.get_state("high_watermark", None) is None

    # A deliberate plan-only review can establish the initial baseline, but it does
    # not clear the persistent halt. The existing resume acknowledgement remains a
    # separate, explicit operator action.
    plan_only = _alpaca_cash_risk_config(tmp_path, execution_enabled=False)
    RiskManager(plan_only, store).evaluate_and_record(
        _cash_risk_snapshot(),
        date(2026, 7, 13),
    )
    reviewed = store.cash_activity_monitor_state()
    assert reviewed is not None
    assert reviewed["initialized"] is True
    assert reviewed["incident_active"] is False
    assert store.halt_state()["active"] is True

    resumed = RiskManager(config, store).evaluate_and_record(
        _cash_risk_snapshot(),
        date(2026, 7, 13),
        ignore_operator_controls=True,
    )
    assert resumed.allow_new_risk is True


def test_alpaca_execution_cannot_bootstrap_missing_high_watermark(tmp_path: Path) -> None:
    config = _alpaca_cash_risk_config(tmp_path, execution_enabled=True)
    store = StateStore(config.database_path)
    store.initialize_cash_activity_monitor(())
    store.clear_halt()

    decision = RiskManager(config, store).evaluate_and_record(
        _cash_risk_snapshot(),
        date(2026, 7, 13),
    )

    assert decision.reason == "high_watermark_uninitialized"
    assert decision.flatten is True and decision.halt is True
    assert store.high_watermark_state() is None


def test_alpaca_equity_above_research_aum_is_blocked(tmp_path: Path) -> None:
    config = _alpaca_cash_risk_config(tmp_path, execution_enabled=True)
    store = StateStore(config.database_path)
    store.initialize_cash_activity_monitor(())
    store.clear_halt()

    decision = RiskManager(config, store).evaluate_and_record(
        _cash_risk_snapshot(equity=100_000.02),
        date(2026, 7, 13),
    )

    assert decision.reason == "account_equity_exceeds_approved_research_aum"
    assert decision.flatten is True
    assert decision.halt is True
    assert store.get_state("high_watermark", None) is None


@pytest.mark.parametrize("baseline", ["high_watermark", "session_open"])
def test_nonfinite_persisted_risk_baseline_fails_closed(
    tmp_path: Path,
    prices: pd.DataFrame,
    baseline: str,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    account = engine.broker.get_account()
    if baseline == "high_watermark":
        engine.store.set_state("high_watermark", float("nan"))
    else:
        engine.store.set_state("high_watermark", account.equity)
        key = f"session_open_equity:{engine._local_time(account.timestamp).date().isoformat()}"
        engine.store.set_state(key, float("nan"))

    decision = engine.risk.evaluate_and_record(
        account, engine._local_time(account.timestamp).date()
    )

    assert decision.reason == "invalid_persisted_risk_baseline"
    assert decision.flatten is True
    assert engine.store.halt_state()["flatten"] is True


def test_boolean_session_open_baseline_fails_closed(
    tmp_path: Path, prices: pd.DataFrame
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    account = engine.broker.get_account()
    session = engine._local_time(account.timestamp).date()
    engine.store.set_state("high_watermark", account.equity)
    engine.store.set_state(f"session_open_equity:{session.isoformat()}", True)

    decision = engine.risk.evaluate_and_record(account, session)

    assert decision.reason == "invalid_persisted_risk_baseline"
    assert decision.flatten is True
    assert engine.store.halt_state()["flatten"] is True


def test_missing_session_open_recovers_earliest_intraday_snapshot(
    tmp_path: Path, prices: pd.DataFrame
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    base = engine.broker.get_account()
    first = replace(
        base,
        equity=90_000.0,
        cash=90_000.0,
        buying_power=180_000.0,
        last_equity=100_000.0,
    )
    session = engine._local_time(first.timestamp).date()
    engine.risk.evaluate_and_record(first, session)
    session_key = f"session_open_equity:{session.isoformat()}"
    with engine.store.connection() as db:
        db.execute("DELETE FROM state WHERE key = ?", (session_key,))
    lower = replace(
        first,
        timestamp=first.timestamp + timedelta(minutes=5),
        equity=95_000.0,
        cash=95_000.0,
        buying_power=190_000.0,
    )

    decision = engine.risk.evaluate_and_record(lower, session)

    assert engine.store.get_state(session_key) == pytest.approx(100_000.0)
    assert decision.daily_return == pytest.approx(-0.05)


def test_resume_preserves_high_watermark_and_blocks_unresolved_hard_drawdown(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    enable_authenticated_store(engine)
    base = engine.broker.get_account()
    engine.store.set_state("high_watermark", 100_000.0)
    engine.store.request_halt("operator_review", flatten=False)
    engine.config.kill_switch_path.write_text("operator_review\n", encoding="utf-8")
    distressed = replace(
        base,
        equity=80_000.0,
        cash=80_000.0,
        buying_power=160_000.0,
        last_equity=100_000.0,
    )
    monkeypatch.setattr(engine.broker, "get_account", lambda: distressed)

    with pytest.raises(RuntimeError, match="hard_drawdown_breach"):
        engine.resume()

    assert engine.store.get_state("high_watermark") == pytest.approx(100_000.0)
    assert engine.config.kill_switch_path.exists()
    assert engine.store.halt_state()["flatten"] is True


def test_resume_clears_operator_controls_only_after_objective_risk_passes(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    enable_authenticated_store(engine)
    base = engine.broker.get_account()
    engine.store.set_state("high_watermark", 100_000.0)
    engine.store.request_halt("operator_review", flatten=False)
    engine.store.set_state("cooldown_remaining", 10)
    engine.config.kill_switch_path.write_text("operator_review\n", encoding="utf-8")
    safe = replace(
        base,
        equity=99_500.0,
        cash=99_500.0,
        buying_power=199_000.0,
        last_equity=100_000.0,
    )
    monkeypatch.setattr(engine.broker, "get_account", lambda: safe)

    engine.resume()

    assert engine.store.get_state("high_watermark") == pytest.approx(100_000.0)
    assert engine.store.get_state("cooldown_remaining") == 0
    assert engine.store.halt_state()["active"] is False
    assert not engine.config.kill_switch_path.exists()


def test_execution_error_without_auto_flatten_sets_halt_only(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    engine.config = replace(engine.config, flatten_on_execution_error=False)
    engine.generate_plan(force=True)

    def fail_on_nonempty_intents(_plan, intents):
        if list(intents):
            raise RuntimeError("injected submission failure")
        return []

    monkeypatch.setattr(engine, "_submit_and_wait", fail_on_nonempty_intents)
    monkeypatch.setattr(
        engine,
        "emergency_flatten",
        lambda *_args, **_kwargs: pytest.fail("automatic flatten must remain disabled"),
    )

    with pytest.raises(RuntimeError, match="injected submission failure"):
        engine.execute_latest_plan(force=True)

    halt = engine.store.halt_state()
    assert halt["active"] is True
    assert halt["flatten"] is False


def test_projected_beta_exposure_is_rejected_before_submission(
    tmp_path: Path,
    prices: pd.DataFrame,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=False)
    long_symbol, short_symbol = map(str, prices.columns[:2])
    plan = TargetPlan(
        plan_id="unsafe-projected-beta",
        as_of=prices.index[-1].date(),
        created_at=datetime.now(timezone.utc),
        regime="neutral",
        regime_multiplier=1.0,
        desired_gross=0.10,
        forecast_volatility=0.1,
        target_weights={long_symbol: 0.05, short_symbol: -0.05},
        metadata={
            "assets": [long_symbol, short_symbol],
            "gross_weight": 0.10,
            "asset_beta": {long_symbol: 4.0, short_symbol: 0.0},
        },
    )

    with pytest.raises(RuntimeError, match="Rounded target beta exposure"):
        engine._validate_projected_portfolio(
            plan,
            {long_symbol: 50.0, short_symbol: -50.0},
            {long_symbol: 100.0, short_symbol: 100.0},
            replace(engine.broker.get_account(), equity=100_000.0),
        )


def test_child_order_cap_uses_current_not_stale_plan_equity(
    tmp_path: Path,
    prices: pd.DataFrame,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=False)
    symbol = str(prices.columns[0])
    plan = TargetPlan(
        plan_id="stale-equity-chunk-test",
        as_of=prices.index[-1].date(),
        created_at=datetime.now(timezone.utc),
        regime="neutral",
        regime_multiplier=1.0,
        desired_gross=0.2,
        forecast_volatility=0.1,
        target_weights={symbol: 0.2},
        metadata={"assets": [symbol], "account_equity": 1_000_000.0},
    )

    _reductions, increases = engine._build_order_intents(
        plan,
        {},
        {symbol: 200.0},
        {symbol: 100.0},
        current_account_equity=100_000.0,
    )

    assert len(increases) == 3
    assert max(intent.estimated_notional for intent in increases) <= 8_000.0


def test_each_increase_child_refreshes_account_risk_before_submission(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    symbols = [str(prices.columns[0]), str(prices.columns[1])]
    draft = TargetPlan(
        plan_id="",
        as_of=prices.index[-1].date(),
        created_at=datetime.now(timezone.utc),
        regime="neutral",
        regime_multiplier=1.0,
        desired_gross=0.02,
        forecast_volatility=0.1,
        target_weights={symbol: 0.01 for symbol in symbols},
        metadata={"assets": symbols, "account_equity": 100_000.0},
    )
    plan = seal_target_plan(draft, engine._current_plan_binding())
    assert engine.store.save_plan(plan)
    intents = [
        OrderIntent(
            symbol=symbol,
            qty=1.0,
            side=OrderSide.BUY,
            phase=OrderPhase.INCREASE,
            current_qty=0.0,
            target_qty=1.0,
            estimated_price=100.0,
            estimated_notional=100.0,
            client_order_id=f"qauto-child-refresh-{index}",
        )
        for index, symbol in enumerate(symbols)
    ]
    decisions = iter(
        (
            RiskDecision(True, False, False, "first_child_safe", 0.0, 0.0, 0.0),
            RiskDecision(
                False,
                True,
                True,
                "second_child_drawdown",
                -0.13,
                -0.03,
                -0.05,
            ),
        )
    )
    account_reads = 0
    original_account = engine.broker.get_account

    def get_account():
        nonlocal account_reads
        account_reads += 1
        return original_account()

    monkeypatch.setattr(engine.broker, "get_account", get_account)
    monkeypatch.setattr(engine, "_evaluate_risk", lambda *_args: next(decisions))

    with pytest.raises(RuntimeError, match="second_child_drawdown"):
        engine._submit_and_wait(plan, intents)

    assert account_reads == 2
    positions = engine.broker.get_positions()
    assert symbols[0] in positions
    assert symbols[1] not in positions
    assert len(engine.store.recent_orders()) == 1


def test_indivisible_share_above_child_cap_blocks_increase_but_not_reduction(
    tmp_path: Path,
    prices: pd.DataFrame,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=False)
    symbol = str(prices.columns[0])
    plan = TargetPlan(
        plan_id="expensive-share-cap-test",
        as_of=prices.index[-1].date(),
        created_at=datetime.now(timezone.utc),
        regime="neutral",
        regime_multiplier=1.0,
        desired_gross=0.1,
        forecast_volatility=0.1,
        target_weights={symbol: 0.1},
        metadata={"assets": [symbol], "account_equity": 100_000.0},
    )

    with pytest.raises(RuntimeError, match="One share .* exceeds"):
        engine._build_order_intents(
            plan,
            {},
            {symbol: 1.0},
            {symbol: 10_000.0},
            current_account_equity=100_000.0,
        )

    reductions, increases = engine._build_order_intents(
        plan,
        {symbol: PositionSnapshot(symbol, 1.0, 10_000.0, 10_000.0)},
        {symbol: 0.0},
        {symbol: 10_000.0},
        current_account_equity=100_000.0,
    )
    assert len(reductions) == 1
    assert increases == []


def test_residual_reconciliation_never_values_open_quantity_at_zero() -> None:
    with pytest.raises(RuntimeError, match="cannot be valued without a valid price"):
        AutomationEngine._residual_notional(
            {"ORPHAN": 0.0},
            {"ORPHAN": PositionSnapshot("ORPHAN", 5.0, 500.0, 100.0)},
            {},
        )


def test_above_tolerance_final_residual_triggers_halt_and_flatten(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    engine.generate_plan(force=True)
    monkeypatch.setattr(
        engine,
        "_residual_notional",
        lambda *_args, **_kwargs: engine.config.residual_notional_tolerance + 1.0,
    )

    with pytest.raises(RuntimeError, match="Final residual notional"):
        engine.execute_latest_plan(force=True)

    assert engine.store.halt_state()["active"] is True
    assert engine.store.halt_state()["flatten"] is True
    assert engine.broker.get_positions() == {}


def test_emergency_flatten_rejects_nonfinite_position_quantity(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    engine.config = replace(engine.config, dedicated_account=True)
    monkeypatch.setattr(
        engine.broker,
        "get_positions",
        lambda: {
            "BROKEN": PositionSnapshot(
                "BROKEN", float("nan"), float("nan"), 100.0
            )
        },
    )

    with pytest.raises(RuntimeError, match="non-finite position quantities"):
        engine.emergency_flatten("invalid_position_snapshot")

    assert engine.store.halt_state()["flatten"] is True
    assert engine.store.get_state("flatten_attempt")["status"] == "failed"


def test_actual_exposure_monitor_rejects_position_value_sign_mismatch(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=False)
    symbol = str(prices.columns[0])
    monkeypatch.setattr(
        engine.broker,
        "get_positions",
        lambda: {symbol: PositionSnapshot(symbol, -10.0, 1_000.0, 100.0)},
    )

    reason, _metrics = engine._actual_exposure_breach(engine.broker.get_account())

    assert reason == "actual_exposure_invalid_market_value_sign"


def test_actual_exposure_monitor_rejects_nonfinite_position_price(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=False)
    symbol = str(prices.columns[0])
    monkeypatch.setattr(
        engine.broker,
        "get_positions",
        lambda: {
            symbol: PositionSnapshot(symbol, 10.0, 1_000.0, float("nan"))
        },
    )

    reason, _metrics = engine._actual_exposure_breach(engine.broker.get_account())

    assert reason == "actual_exposure_invalid_current_price"


def test_actual_exposure_monitor_rejects_inconsistent_position_valuation(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=False)
    symbol = str(prices.columns[0])
    monkeypatch.setattr(
        engine.broker,
        "get_positions",
        lambda: {symbol: PositionSnapshot(symbol, 10.0, 100.0, 100.0)},
    )

    reason, _metrics = engine._actual_exposure_breach(engine.broker.get_account())

    assert reason == "actual_exposure_inconsistent_market_value"


def test_polled_order_receipt_cannot_mutate_the_economic_intent(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    accepted = OrderReceipt(
        broker_order_id="broker-intent-mutation",
        client_order_id="qauto-intent-mutation",
        symbol="SPY",
        qty=1.0,
        side="buy",
        status="accepted",
        submitted_at=datetime.now(timezone.utc),
    )
    monkeypatch.setattr(
        engine.broker,
        "get_order",
        lambda _order_id: replace(accepted, symbol="QQQ", status="filled", filled_qty=1.0),
    )

    with pytest.raises(RuntimeError, match="does not match the submitted economic intent"):
        engine._wait_for_receipts("test-plan", None, [accepted])


def test_simulated_duplicate_client_id_must_match_economic_intent(
    tmp_path: Path,
    prices: pd.DataFrame,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    symbol = str(prices.columns[0])
    engine.broker.submit_market_order(symbol, 1.0, OrderSide.BUY, "duplicate-id")

    with pytest.raises(RuntimeError, match="does not match the requested economic intent"):
        engine.broker.submit_market_order(symbol, 2.0, OrderSide.BUY, "duplicate-id")


def test_simulated_existing_corrupt_state_never_reinitializes_as_flat(
    tmp_path: Path,
    prices: pd.DataFrame,
) -> None:
    state_path = tmp_path / "corrupt-simulated-state.json"
    state_path.write_text('{"cash": 100000, "positions": ', encoding="utf-8")
    original = state_path.read_text(encoding="utf-8")

    with pytest.raises(RuntimeError, match="refusing to recreate it as a flat account"):
        SimulatedBroker(
            prices_path=tmp_path / "unused.csv",
            state_path=state_path,
            prices=prices,
        )

    assert state_path.read_text(encoding="utf-8") == original


def test_simulated_held_position_without_latest_mark_fails_closed(
    tmp_path: Path,
    prices: pd.DataFrame,
) -> None:
    damaged_prices = prices.copy()
    symbol = str(damaged_prices.columns[0])
    damaged_prices.loc[damaged_prices.index[-6:], symbol] = float("nan")
    broker = SimulatedBroker(
        prices_path=tmp_path / "unused.csv",
        state_path=tmp_path / "simulated-state.json",
        prices=damaged_prices,
    )
    broker._state["positions"][symbol] = 5.0
    broker._persist()

    with pytest.raises(RuntimeError, match="no valid latest valuation mark"):
        broker.get_positions()
    with pytest.raises(RuntimeError, match="no valid latest valuation mark"):
        broker.get_account()


def test_alpaca_blocks_a_tick_rounded_limit_that_is_not_marketable() -> None:
    from alpaca.data.enums import DataFeed
    from auto_trader.brokers.alpaca import AlpacaBroker

    now = datetime.now(timezone.utc)

    class MissingOrder(Exception):
        status_code = 404

    class TradingStub:
        submitted = False

        @staticmethod
        def get_order_by_client_id(_client_order_id):
            raise MissingOrder("not found")

        def submit_order(self, **_kwargs):
            self.submitted = True
            raise AssertionError("non-marketable order must not be submitted")

    class DataStub:
        @staticmethod
        def get_stock_latest_quote(_request):
            return {
                "TICK": SimpleNamespace(
                    bid_price=0.9975,
                    ask_price=1.0025,
                    timestamp=now,
                )
            }

    broker = AlpacaBroker.__new__(AlpacaBroker)
    broker.trading = TradingStub()
    broker.data = DataStub()
    broker.feed = DataFeed.IEX
    broker.max_execution_price_age_seconds = 60
    broker.max_execution_spread_bps = 50.0
    broker.marketable_limit_collar_bps = 25.0
    broker._routine_execution_authorized_until = datetime.now(timezone.utc) + timedelta(days=1)
    broker._routine_authorization_check = lambda *_args: None

    with pytest.raises(RuntimeError, match="No broker-valid marketable limit"):
        broker.submit_market_order("TICK", 1.0, OrderSide.BUY, "qauto-tick-collar")

    assert broker.trading.submitted is False


def test_primary_emergency_never_dispatches_stale_ambiguous_economics(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    symbol = str(prices.columns[0])
    broker = engine.broker
    broker.submit_market_order(symbol, 10.0, OrderSide.BUY, "manual-open")
    control = merge_control_marker(
        engine.config.kill_switch_path, "stale-intent", flatten=True
    )
    assert control.incident_id is not None
    stale = engine.emergency_journal.prepare_submission(
        control.incident_id,
        symbol=symbol,
        current_qty=10.0,
        side="sell",
        qty=10.0,
    )
    # A manual/partial fill changes broker exposure before the prepared request was
    # ever accepted. The stale client ID therefore returns authoritative absence.
    broker._state["positions"][symbol] = 6.0
    broker._persist()
    submitted_qty: list[float] = []
    original_submit = broker.submit_emergency_market_order

    def submit(symbol: str, qty: float, side: OrderSide, client_order_id: str):
        submitted_qty.append(float(qty))
        assert client_order_id != stale.client_order_id
        return original_submit(symbol, qty, side, client_order_id)

    monkeypatch.setattr(broker, "submit_emergency_market_order", submit)

    with pytest.raises(EmergencyPrimarySubmissionError):
        engine.emergency_flatten("stale-intent")

    assert submitted_qty == [pytest.approx(6.0)]
    assert broker.get_positions() == {}
    assert engine.emergency_journal.active_incident_id() == control.incident_id
    assert engine.config.kill_switch_path.exists()


def test_stale_emergency_replay_resolves_matching_receipt_before_current_close(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    symbol = str(prices.columns[0])
    broker = engine.broker
    broker.submit_market_order(symbol, 10.0, OrderSide.BUY, "manual-open-receipt")
    control = merge_control_marker(
        engine.config.kill_switch_path, "stale-receipt", flatten=True
    )
    assert control.incident_id is not None
    stale = engine.emergency_journal.prepare_submission(
        control.incident_id,
        symbol=symbol,
        current_qty=10.0,
        side="sell",
        qty=10.0,
    )
    broker._state["positions"][symbol] = 6.0
    broker._state["orders"]["prior-partial"] = {
        "broker_order_id": "prior-partial",
        "client_order_id": stale.client_order_id,
        "symbol": symbol,
        "qty": 10.0,
        "side": "sell",
        "status": "canceled",
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "filled_qty": 4.0,
        "filled_avg_price": float(prices[symbol].iloc[-1]),
    }
    broker._persist()
    submitted: list[tuple[float, str]] = []
    original_submit = broker.submit_emergency_market_order

    def submit(symbol: str, qty: float, side: OrderSide, client_order_id: str):
        submitted.append((float(qty), client_order_id))
        return original_submit(symbol, qty, side, client_order_id)

    monkeypatch.setattr(broker, "submit_emergency_market_order", submit)

    engine.emergency_flatten("stale-receipt")

    assert submitted == [(pytest.approx(6.0), submitted[0][1])]
    assert submitted[0][1] != stale.client_order_id
    assert broker.get_positions() == {}


def test_daemon_fallback_never_dispatches_stale_ambiguous_economics(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    symbol = str(prices.columns[0])
    broker = engine.broker
    broker.submit_market_order(symbol, 9.0, OrderSide.BUY, "manual-open-fallback")
    control = merge_control_marker(
        engine.config.kill_switch_path, "stale-fallback", flatten=True
    )
    assert control.incident_id is not None
    stale = engine.emergency_journal.prepare_submission(
        control.incident_id,
        symbol=symbol,
        current_qty=9.0,
        side="sell",
        qty=9.0,
    )
    broker._state["positions"][symbol] = 4.0
    broker._persist()
    submitted_qty: list[float] = []
    original_submit = broker.submit_emergency_market_order

    def submit(symbol: str, qty: float, side: OrderSide, client_order_id: str):
        submitted_qty.append(float(qty))
        assert client_order_id != stale.client_order_id
        return original_submit(symbol, qty, side, client_order_id)

    monkeypatch.setattr(broker, "submit_emergency_market_order", submit)
    daemon = TradingDaemon(engine)
    with pytest.raises(RuntimeError, match="terminal broker receipt"):
        daemon._fallback_emergency_flatten(
            "stale-fallback", RuntimeError("state unavailable"), control.incident_id
        )

    assert submitted_qty == [pytest.approx(4.0)]
    assert broker.get_positions() == {}
    assert engine.emergency_journal.active_incident_id() == control.incident_id
    assert engine.config.kill_switch_path.exists()


def test_resume_requires_double_flat_snapshot_before_completing_active_incident(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    enable_authenticated_store(engine)
    symbol = str(prices.columns[0])
    control = merge_control_marker(
        engine.config.kill_switch_path, "resume-interlock", flatten=True
    )
    assert control.incident_id is not None
    engine.emergency_journal.prepare_submission(
        control.incident_id,
        symbol=symbol,
        current_qty=1.0,
        side="sell",
        qty=1.0,
    )
    engine.broker._state["positions"][symbol] = 1.0
    engine.broker._persist()

    with pytest.raises(RuntimeError, match="broker-flat and order-free"):
        engine.resume()
    assert engine.emergency_journal.active_incident_id() == control.incident_id
    assert engine.config.kill_switch_path.exists()

    engine.broker._state["positions"].clear()
    engine.broker._persist()
    reads = 0
    original_positions = engine.broker.get_positions

    def positions():
        nonlocal reads
        reads += 1
        return original_positions()

    monkeypatch.setattr(engine.broker, "get_positions", positions)
    engine.store.clear_halt()
    with pytest.raises(RuntimeError, match="terminal broker receipt"):
        engine.resume()

    assert reads >= 2
    assert engine.emergency_journal.active_incident_id() == control.incident_id
    assert engine.config.kill_switch_path.exists()


def test_resume_cannot_remove_marker_replaced_during_objective_risk_review(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    enable_authenticated_store(engine)
    merge_control_marker(
        engine.config.kill_switch_path, "operator_reviewed_halt", flatten=False
    )
    engine.store.request_halt("operator_reviewed_halt", flatten=False)

    def concurrent_emergency(*_args, **_kwargs) -> RiskDecision:
        merge_control_marker(
            engine.config.kill_switch_path,
            "concurrent_watchdog_emergency",
            flatten=True,
        )
        return RiskDecision(True, False, False, "safe", 0.0, 0.0, 0.0)

    monkeypatch.setattr(engine.risk, "evaluate_and_record", concurrent_emergency)

    with pytest.raises(RuntimeError, match="control marker changed"):
        engine.resume()

    persisted = parse_control_marker(
        engine.config.kill_switch_path.read_text(encoding="utf-8")
    )
    assert persisted.flatten is True
    assert "concurrent_watchdog_emergency" in persisted.reason
    assert engine.store.halt_state()["active"] is True


def test_resume_blocks_position_appearing_between_flat_confirmations(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    enable_authenticated_store(engine)
    symbol = str(prices.columns[0])
    engine.store.request_halt("operator_review", flatten=False)
    merge_control_marker(
        engine.config.kill_switch_path,
        "operator_review",
        flatten=False,
    )
    snapshots = iter(
        (
            {},
            {symbol: PositionSnapshot(symbol, 1.0, 100.0, 100.0)},
        )
    )
    monkeypatch.setattr(engine.broker, "get_positions", lambda: next(snapshots))

    with pytest.raises(RuntimeError, match="account-flat and order-free"):
        engine.resume()

    halt = engine.store.halt_state()
    assert halt["active"] is True and halt["flatten"] is True
    assert engine.config.kill_switch_path.exists()


def test_resume_blocks_order_appearing_between_order_free_confirmations(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    enable_authenticated_store(engine)
    symbol = str(prices.columns[0])
    engine.store.request_halt("operator_review", flatten=False)
    merge_control_marker(
        engine.config.kill_switch_path,
        "operator_review",
        flatten=False,
    )
    appearing = OrderReceipt(
        broker_order_id="appearing-order",
        client_order_id="qauto-spoof-appearing-order",
        symbol=symbol,
        qty=1.0,
        side=OrderSide.BUY.value,
        status="accepted",
        submitted_at=datetime.now(timezone.utc),
    )
    order_snapshots = iter(([], [appearing]))
    monkeypatch.setattr(
        engine.broker,
        "list_open_orders",
        lambda _symbols=None: next(order_snapshots),
    )

    with pytest.raises(RuntimeError, match="account-flat and order-free"):
        engine.resume()

    halt = engine.store.halt_state()
    assert halt["active"] is True and halt["flatten"] is True
    assert engine.config.kill_switch_path.exists()


def test_resume_cas_cannot_clear_concurrently_replaced_authenticated_halt(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    enable_authenticated_store(engine)
    engine.store.request_halt("operator_review", flatten=False)
    merge_control_marker(
        engine.config.kill_switch_path,
        "operator_review",
        flatten=False,
    )

    def replace_halt(*_args, **_kwargs) -> RiskDecision:
        engine.store.request_halt("concurrent_risk_halt", flatten=True)
        return RiskDecision(True, False, False, "normal", 0.0, 0.0, 0.0)

    monkeypatch.setattr(engine.risk, "evaluate_and_record", replace_halt)

    with pytest.raises(RuntimeError, match="authenticated halt changed"):
        engine.resume()

    halt = engine.store.halt_state()
    assert halt["active"] is True
    assert halt["reason"] == "concurrent_risk_halt"
    assert halt["flatten"] is True
    assert engine.config.kill_switch_path.exists()


def test_daemon_startup_recreates_marker_for_authenticated_active_incident(
    tmp_path: Path,
    prices: pd.DataFrame,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    control = merge_control_marker(
        engine.config.kill_switch_path, "startup-active", flatten=True
    )
    assert control.incident_id is not None
    engine.emergency_journal.prepare_submission(
        control.incident_id,
        symbol=str(prices.columns[0]),
        current_qty=1.0,
        side="sell",
        qty=1.0,
    )
    engine.config.kill_switch_path.unlink()

    daemon = TradingDaemon(engine)

    restored = parse_control_marker(
        engine.config.kill_switch_path.read_text(encoding="utf-8")
    )
    assert restored.flatten is True
    assert restored.incident_id == control.incident_id
    assert engine.store.halt_state()["active"] is True


def test_factory_recreates_marker_before_returning_engine_with_active_incident(
    tmp_path: Path,
    prices: pd.DataFrame,
) -> None:
    from auto_trader.emergency_journal import EmergencyJournal
    from auto_trader.factory import build_engine

    price_path = tmp_path / "prices.csv"
    factory_prices = prices.rename(columns=lambda value: str(value).replace("_", ""))
    factory_prices.to_csv(price_path)
    config = BotConfig(
        broker="simulated",
        execution_enabled=False,
        symbols=tuple(factory_prices.columns),
        database_path=tmp_path / "factory.sqlite3",
        log_path=tmp_path / "factory.log",
        kill_switch_path=tmp_path / "FACTORY_KILL",
        process_lock_path=tmp_path / "factory-process.lock",
        operation_lock_path=tmp_path / "factory-operation.lock",
        simulated_prices_path=price_path,
        simulated_state_path=tmp_path / "factory-broker.json",
        minimum_assets=8,
    )
    journal = EmergencyJournal(
        config.effective_emergency_journal_path,
        config.emergency_authentication_key_bytes,
        config.emergency_journal_scope,
    )
    journal.verify()
    control = merge_control_marker(
        config.kill_switch_path, "factory-active", flatten=True
    )
    assert control.incident_id is not None
    journal.prepare_submission(
        control.incident_id,
        symbol=str(factory_prices.columns[0]),
        current_qty=1.0,
        side="sell",
        qty=1.0,
    )
    config.kill_switch_path.unlink()

    engine = build_engine(config)

    restored = parse_control_marker(
        config.kill_switch_path.read_text(encoding="utf-8")
    )
    assert restored.flatten is True
    assert restored.incident_id == control.incident_id
    assert engine.store.halt_state()["active"] is True


def test_routine_reduction_refresh_clips_manual_fill_and_cannot_cross_zero(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    symbol = str(prices.columns[0])
    engine.broker.submit_market_order(symbol, 10.0, OrderSide.BUY, "manual-long")
    draft = TargetPlan(
        plan_id="",
        as_of=prices.index[-1].date(),
        created_at=datetime.now(timezone.utc),
        regime="neutral",
        regime_multiplier=1.0,
        desired_gross=0.0,
        forecast_volatility=0.1,
        target_weights={symbol: 0.0},
        metadata={"assets": [symbol], "account_equity": 100_000.0},
    )
    plan = seal_target_plan(draft, engine._current_plan_binding())
    assert engine.store.save_plan(plan)
    intent = OrderIntent(
        symbol=symbol,
        qty=10.0,
        side=OrderSide.SELL,
        phase=OrderPhase.REDUCE,
        current_qty=10.0,
        target_qty=0.0,
        estimated_price=float(prices[symbol].iloc[-1]),
        estimated_notional=10.0 * float(prices[symbol].iloc[-1]),
        client_order_id="qauto-stale-reduction",
    )
    engine.broker._state["positions"][symbol] = 3.0
    engine.broker._persist()
    submitted: list[float] = []
    original_submit = engine.broker.submit_market_order

    def submit(symbol: str, qty: float, side: OrderSide, client_order_id: str):
        submitted.append(float(qty))
        return original_submit(symbol, qty, side, client_order_id)

    monkeypatch.setattr(engine.broker, "submit_market_order", submit)
    engine._submit_and_wait(plan, [intent])

    assert submitted == [pytest.approx(3.0)]
    assert engine.broker.get_positions() == {}


def test_terminal_child_fill_must_be_reflected_before_next_child(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    symbol = str(prices.columns[0])
    draft = TargetPlan(
        plan_id="",
        as_of=prices.index[-1].date(),
        created_at=datetime.now(timezone.utc),
        regime="neutral",
        regime_multiplier=1.0,
        desired_gross=0.01,
        forecast_volatility=0.1,
        target_weights={symbol: 0.01},
        metadata={"assets": [symbol], "account_equity": 100_000.0},
    )
    plan = seal_target_plan(draft, engine._current_plan_binding())
    assert engine.store.save_plan(plan)
    price = float(prices[symbol].iloc[-1])
    intents = [
        OrderIntent(
            symbol=symbol,
            qty=1.0,
            side=OrderSide.BUY,
            phase=OrderPhase.INCREASE,
            current_qty=float(index),
            target_qty=2.0,
            estimated_price=price,
            estimated_notional=price,
            client_order_id=f"qauto-reflection-child-{index}",
        )
        for index in range(2)
    ]
    submitted: list[str] = []
    original_submit = engine.broker.submit_market_order
    original_positions = engine.broker.get_positions

    def submit(symbol: str, qty: float, side: OrderSide, client_order_id: str):
        submitted.append(client_order_id)
        return original_submit(symbol, qty, side, client_order_id)

    def lagged_positions():
        actual = original_positions()
        # The broker receipt says the first child filled, but the position endpoint
        # never reflects it within the bounded confirmation sequence.
        return {} if len(submitted) == 1 else actual

    monkeypatch.setattr(engine.broker, "submit_market_order", submit)
    monkeypatch.setattr(engine.broker, "get_positions", lagged_positions)

    with pytest.raises(RuntimeError, match="terminal fill was not reflected"):
        engine._submit_and_wait(plan, intents)

    assert submitted == ["qauto-reflection-child-0"]
    assert original_positions()[symbol].qty == pytest.approx(1.0)


def test_final_reconciliation_requires_two_stable_position_order_snapshots(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    symbol = str(prices.columns[0])
    plan = TargetPlan(
        plan_id="stable-final-snapshot",
        as_of=prices.index[-1].date(),
        created_at=datetime.now(timezone.utc),
        regime="neutral",
        regime_multiplier=1.0,
        desired_gross=0.0,
        forecast_volatility=0.1,
        target_weights={symbol: 0.0},
        metadata={"assets": [symbol]},
    )
    plan = seal_target_plan(plan, engine._current_plan_binding())
    held = PositionSnapshot(symbol, 1.0, 100.0, 100.0)
    snapshots = iter(({}, {symbol: held}, {symbol: held}))
    reads = 0

    def positions():
        nonlocal reads
        reads += 1
        return next(snapshots)

    monkeypatch.setattr(engine.broker, "get_positions", positions)
    monkeypatch.setattr(engine.broker, "list_open_orders", lambda _symbols=None: [])

    confirmed = engine._await_stable_routine_broker_state(
        plan,
        context="hostile final snapshot",
    )

    assert reads == 3
    assert confirmed[symbol].qty == pytest.approx(1.0)


def test_immediate_pre_child_foreign_order_persists_dedicated_halt(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    engine.config = replace(engine.config, dedicated_account=True)
    symbol = str(prices.columns[0])
    plan = TargetPlan(
        plan_id="foreign-pre-child",
        as_of=prices.index[-1].date(),
        created_at=datetime.now(timezone.utc),
        regime="neutral",
        regime_multiplier=1.0,
        desired_gross=0.0,
        forecast_volatility=0.1,
        target_weights={symbol: 0.0},
        metadata={"assets": [symbol], "account_equity": 100_000.0},
    )
    intent = OrderIntent(
        symbol=symbol,
        qty=1.0,
        side=OrderSide.BUY,
        phase=OrderPhase.INCREASE,
        current_qty=0.0,
        target_qty=1.0,
        estimated_price=100.0,
        estimated_notional=100.0,
        client_order_id="qauto-routine-child",
    )
    foreign = OrderReceipt(
        broker_order_id="foreign-order",
        client_order_id="manual-client-id",
        symbol=symbol,
        qty=1.0,
        side="buy",
        status="accepted",
        submitted_at=datetime.now(timezone.utc),
    )
    monkeypatch.setattr(engine.broker, "list_open_orders", lambda symbols=None: [foreign])
    monkeypatch.setattr(
        engine.broker,
        "submit_market_order",
        lambda *_args, **_kwargs: pytest.fail("foreign activity must block submission"),
    )

    with pytest.raises(RuntimeError, match="unauthorized dedicated-account activity"):
        engine._submit_and_wait(plan, [intent])

    assert engine.store.halt_state()["active"] is True
    marker = parse_control_marker(
        engine.config.kill_switch_path.read_text(encoding="utf-8")
    )
    assert marker.flatten is True


def test_immediate_pre_child_unknown_position_persists_dedicated_halt(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    configured = tuple(map(str, prices.columns[:10]))
    engine.config = replace(
        engine.config,
        dedicated_account=True,
        symbols=configured,
    )
    symbol = configured[0]
    foreign_symbol = str(prices.columns[-1])
    engine.broker._state["positions"][foreign_symbol] = 1.0
    engine.broker._persist()
    plan = TargetPlan(
        plan_id="foreign-position-pre-child",
        as_of=prices.index[-1].date(),
        created_at=datetime.now(timezone.utc),
        regime="neutral",
        regime_multiplier=1.0,
        desired_gross=0.0,
        forecast_volatility=0.1,
        target_weights={symbol: 0.0},
        metadata={"assets": [symbol], "account_equity": 100_000.0},
    )
    intent = OrderIntent(
        symbol=symbol,
        qty=1.0,
        side=OrderSide.BUY,
        phase=OrderPhase.INCREASE,
        current_qty=0.0,
        target_qty=1.0,
        estimated_price=100.0,
        estimated_notional=100.0,
        client_order_id="qauto-routine-position-child",
    )
    monkeypatch.setattr(
        engine.broker,
        "submit_market_order",
        lambda *_args, **_kwargs: pytest.fail("foreign position must block submission"),
    )

    with pytest.raises(RuntimeError, match="unauthorized dedicated-account position"):
        engine._submit_and_wait(plan, [intent])

    assert engine.store.halt_state()["active"] is True
    marker = parse_control_marker(
        engine.config.kill_switch_path.read_text(encoding="utf-8")
    )
    assert marker.flatten is True


def test_authenticated_child_blocks_manual_fill_that_would_overshoot_target(
    tmp_path: Path,
    prices: pd.DataFrame,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    symbol = str(prices.columns[0])
    intended_session = (
        datetime.now(timezone.utc) + timedelta(days=1)
    ).date()
    plan = seal_target_plan(
        TargetPlan(
            plan_id="",
            as_of=intended_session - timedelta(days=1),
            created_at=datetime.now(timezone.utc),
            regime="neutral",
            regime_multiplier=1.0,
            desired_gross=0.05,
            forecast_volatility=0.1,
            target_weights={symbol: 0.05},
            metadata={"assets": [symbol], "asset_beta": {symbol: 1.0}},
        ),
        engine._current_plan_binding(),
        engine.config.plan_authentication_key_bytes,
    )
    intent = OrderIntent(
        symbol=symbol,
        qty=50.0,
        side=OrderSide.SELL,
        phase=OrderPhase.REDUCE,
        current_qty=100.0,
        target_qty=50.0,
        estimated_price=100.0,
        estimated_notional=5_000.0,
        client_order_id="qauto-authenticated-target-child",
    )
    engine._active_routine_plan = plan
    engine._active_routine_execution_date = intended_session
    authorization = engine._activate_routine_child_authorization(plan, intent)
    try:
        assert engine._require_active_routine_child_authorization(
            client_order_id=intent.client_order_id,
            symbol=symbol,
            qty=intent.qty,
            side=intent.side,
        ) == authorization
        # A concurrent manual sell moved 100 -> 80. Sending the stale 50-share child
        # would land at 30 and pass the old zero-cross/gross-only checks.
        with pytest.raises(RuntimeError, match="position changed after authorization"):
            engine._validate_child_target_progress(
                current_qty=80.0,
                target_qty=authorization.target_qty,
                side=authorization.side,
                qty=authorization.qty,
                phase=authorization.phase,
                expected_current_qty=authorization.current_qty,
            )
    finally:
        engine._clear_routine_child_authorization(authorization)


def test_transient_path_alternates_children_and_rejects_infeasible_beta_path(
    tmp_path: Path,
    prices: pd.DataFrame,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    long_symbol, short_symbol = "LONG", "SHORT"
    positions = {
        long_symbol: PositionSnapshot(long_symbol, 100.0, 10_000.0, 100.0),
        short_symbol: PositionSnapshot(short_symbol, -100.0, -10_000.0, 100.0),
    }
    execution_prices = {long_symbol: 100.0, short_symbol: 100.0}
    plan = TargetPlan(
        plan_id="transient-path",
        as_of=date.today(),
        created_at=datetime.now(timezone.utc),
        regime="neutral",
        regime_multiplier=1.0,
        desired_gross=0.04,
        forecast_volatility=0.1,
        target_weights={long_symbol: 0.02, short_symbol: -0.02},
        metadata={
            "assets": [long_symbol, short_symbol],
            "asset_beta": {long_symbol: 1.0, short_symbol: 1.0},
        },
    )
    intents = [
        OrderIntent(
            symbol=long_symbol,
            qty=40.0,
            side=OrderSide.SELL,
            phase=OrderPhase.REDUCE,
            current_qty=100.0,
            target_qty=20.0,
            estimated_price=100.0,
            estimated_notional=4_000.0,
            client_order_id=f"a-long-{index}",
        )
        for index in range(2)
    ] + [
        OrderIntent(
            symbol=short_symbol,
            qty=40.0,
            side=OrderSide.BUY,
            phase=OrderPhase.REDUCE,
            current_qty=-100.0,
            target_qty=-20.0,
            estimated_price=100.0,
            estimated_notional=4_000.0,
            client_order_id=f"b-short-{index}",
        )
        for index in range(2)
    ]

    ordered = engine._order_intents_for_transient_limits(
        plan,
        intents,
        positions,
        execution_prices,
        account_equity=100_000.0,
    )
    assert [intent.symbol for intent in ordered] == [
        long_symbol,
        short_symbol,
        long_symbol,
        short_symbol,
    ]

    beta_infeasible = replace(
        plan,
        metadata={
            **plan.metadata,
            "asset_beta": {long_symbol: 3.0, short_symbol: 3.0},
        },
    )
    with pytest.raises(RuntimeError, match="No child ordering satisfies"):
        engine._order_intents_for_transient_limits(
            beta_infeasible,
            [intents[0], intents[2]],
            positions,
            execution_prices,
            account_equity=100_000.0,
        )


@pytest.mark.parametrize("race", ["open-order race", "kill-switch race", "clock race"])
def test_alpaca_final_commit_races_block_before_submit(race: str) -> None:
    from alpaca.data.enums import DataFeed
    from auto_trader.brokers.alpaca import AlpacaBroker

    now = datetime.now(timezone.utc)

    class MissingOrder(Exception):
        status_code = 404

    class TradingStub:
        submitted = False

        @staticmethod
        def get_order_by_client_id(_client_order_id):
            raise MissingOrder("not found")

        def submit_order(self, **_kwargs):
            self.submitted = True
            raise AssertionError("a final commit race must block REST submission")

    class DataStub:
        @staticmethod
        def get_stock_latest_quote(_request):
            return {
                "SPY": SimpleNamespace(
                    bid_price=99.95,
                    ask_price=100.05,
                    timestamp=now,
                )
            }

    contexts = []

    def authorize(_symbol, _qty, _side, _limit, context):
        contexts.append(context)
        if context.final_commit:
            raise RuntimeError(race)
        return now + timedelta(minutes=5)

    broker = AlpacaBroker.__new__(AlpacaBroker)
    broker.trading = TradingStub()
    broker.data = DataStub()
    broker.feed = DataFeed.IEX
    broker.max_execution_price_age_seconds = 60
    broker.max_execution_spread_bps = 50.0
    broker.marketable_limit_collar_bps = 35.0
    broker._routine_execution_authorized_until = now + timedelta(days=1)
    broker._routine_authorization_check = authorize

    with pytest.raises(RuntimeError, match=race):
        broker.submit_market_order("SPY", 1.0, OrderSide.BUY, "qauto-commit-race")

    assert [context.final_commit for context in contexts] == [False, True]
    assert broker.trading.submitted is False


def test_alpaca_refetches_and_rebuilds_quote_that_ages_during_authorization() -> None:
    from auto_trader.brokers.alpaca import AlpacaBroker, VerifiedExecutionQuote

    now = datetime.now(timezone.utc)

    class MissingOrder(Exception):
        status_code = 404

    class TradingStub:
        def __init__(self) -> None:
            self.requests = []

        @staticmethod
        def get_order_by_client_id(_client_order_id):
            raise MissingOrder("not found")

        def submit_order(self, *, order_data):
            self.requests.append(order_data)
            return SimpleNamespace(
                id="broker-refreshed-quote",
                client_order_id=order_data.client_order_id,
                symbol=order_data.symbol,
                qty=order_data.qty,
                side=order_data.side,
                status="accepted",
                submitted_at=now,
                created_at=None,
                filled_qty=0.0,
                filled_avg_price=None,
            )

    first = VerifiedExecutionQuote(99.95, 100.05, 100.0, now)
    second = VerifiedExecutionQuote(100.95, 101.05, 101.0, now)
    quotes = [first, second]
    quote_calls = 0
    contexts = []

    def fresh_quotes(_symbols):
        nonlocal quote_calls
        quote = quotes[quote_calls]
        quote_calls += 1
        return {"SPY": quote}

    def authorize(_symbol, _qty, _side, _limit, context):
        contexts.append(context)
        return now + timedelta(minutes=5)

    broker = AlpacaBroker.__new__(AlpacaBroker)
    broker.trading = TradingStub()
    broker.max_execution_price_age_seconds = 60
    broker.max_execution_spread_bps = 50.0
    broker.marketable_limit_collar_bps = 35.0
    broker._routine_execution_authorized_until = now + timedelta(days=1)
    broker._routine_authorization_check = authorize
    broker._fresh_quotes = fresh_quotes
    broker._quote_is_fresh = lambda quote, **_kwargs: quote is second

    broker.submit_market_order("SPY", 1.0, OrderSide.BUY, "qauto-refreshed-quote")

    assert quote_calls == 2
    assert [context.final_commit for context in contexts] == [False, False, True]
    assert len(broker.trading.requests) == 1
    assert broker.trading.requests[0].limit_price == pytest.approx(101.35)


def test_routine_deadline_never_claims_late_cancel_as_terminal(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    symbol = str(prices.columns[0])
    accepted = OrderReceipt(
        broker_order_id="late-cancel-order",
        client_order_id="qauto-late-cancel",
        symbol=symbol,
        qty=1.0,
        side="buy",
        status="accepted",
        submitted_at=datetime.now(timezone.utc),
    )
    cancellation_timeouts: list[float] = []

    def late_cancel(_order_id: str, *, timeout_seconds: float, poll_seconds: float):
        del poll_seconds
        cancellation_timeouts.append(timeout_seconds)
        return replace(accepted, status="canceled")

    monkeypatch.setattr(engine.broker, "cancel_order_and_wait", late_cancel)
    monkeypatch.setattr(engine, "_routine_deadline_remaining_seconds", lambda _deadline: 0.0)

    with pytest.raises(RuntimeError, match="pre-deadline terminality was not proven"):
        engine._wait_for_receipts(
            "deadline-plan",
            OrderPhase.INCREASE,
            [accepted],
            routine_deadline=datetime.now(timezone.utc) + timedelta(minutes=1),
        )

    assert cancellation_timeouts == [0.0]
    halt = engine.store.halt_state()
    assert halt["active"] is True
    assert halt["flatten"] is True
    marker = parse_control_marker(
        engine.config.kill_switch_path.read_text(encoding="utf-8")
    )
    assert marker.flatten is True


def test_routine_deadline_rejects_terminal_receipt_first_observed_late(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = make_engine(tmp_path, prices, execution_enabled=True)
    filled = OrderReceipt(
        broker_order_id="terminal-observed-late",
        client_order_id="qauto-terminal-observed-late",
        symbol=str(prices.columns[0]),
        qty=1.0,
        side="buy",
        status="filled",
        submitted_at=datetime.now(timezone.utc),
        filled_qty=1.0,
        filled_avg_price=100.0,
    )
    monkeypatch.setattr(
        engine,
        "_routine_deadline_remaining_seconds",
        lambda _deadline: 0.0,
    )

    with pytest.raises(RuntimeError, match="terminal receipt was observed at or after"):
        engine._wait_for_receipts(
            "terminal-observed-late-plan",
            OrderPhase.INCREASE,
            [filled],
            routine_deadline=datetime.now(timezone.utc) + timedelta(minutes=1),
        )

    halt = engine.store.halt_state()
    assert halt["active"] is True
    assert halt["flatten"] is True
    marker = parse_control_marker(
        engine.config.kill_switch_path.read_text(encoding="utf-8")
    )
    assert marker.flatten is True
