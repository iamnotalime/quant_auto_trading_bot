from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path

import pandas as pd
import pytest

import auto_trader.engine as engine_module
from auto_trader.brokers.base import GovernedCovarianceEvidence
from auto_trader.covariance_evidence import COVARIANCE_RETURN_SEMANTICS
from auto_trader.brokers.simulated import SimulatedBroker
from auto_trader.config import BotConfig
from auto_trader.engine import AutomationEngine
from auto_trader.models import MarketClock, RiskDecision
from auto_trader.store import StateStore
from auto_trader.strategy import (
    SEALED_COVARIANCE_RETURN_SEMANTICS,
    build_target_plan,
    seal_target_plan,
    target_plan_content_hash,
)
from quant_app.backtest import run_backtest
from quant_app.data import generate_demo_prices


@pytest.fixture()
def prices() -> pd.DataFrame:
    return generate_demo_prices(
        n_assets=20,
        years=4,
        seed=202,
        end_date="2026-06-30",
    )


def _neutral_corporate_actions(
    prices: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    return (
        pd.DataFrame(1.0, index=prices.index, columns=prices.columns),
        pd.DataFrame(0.0, index=prices.index, columns=prices.columns),
    )


def _next_session(frame: pd.DataFrame):
    return (pd.Timestamp(frame.index[-1]) + pd.offsets.BDay(1)).date()


def _complete_provenance(
    frame: pd.DataFrame,
    supplied: dict[str, str],
) -> dict[str, str]:
    as_of = pd.Timestamp(frame.index[-1]).date()
    intended = _next_session(frame)
    result = {
        "issued_at": datetime.combine(
            as_of, time(14, 0), tzinfo=timezone.utc
        ).isoformat(),
        "expires_at": datetime.combine(
            intended + timedelta(days=1), time(0, 0), tzinfo=timezone.utc
        ).isoformat(),
        "latest_session": as_of.isoformat(),
        "next_session": intended.isoformat(),
        "return_semantics": COVARIANCE_RETURN_SEMANTICS,
    }
    result.update(supplied)
    return result


def _governed_plan(
    signal_prices: pd.DataFrame,
    execution_prices: pd.DataFrame,
    split_ratios: pd.DataFrame | None,
    cash_distributions: pd.DataFrame | None,
    provenance: dict[str, str] | None,
    *,
    config=None,
):
    return build_target_plan(
        signal_prices,
        config or BotConfig().strategy,
        RiskDecision(True, False, False, "normal", 0.0, 0.0, 0.0),
        minimum_assets=20,
        covariance_execution_prices=execution_prices,
        covariance_corporate_action_split_ratios=split_ratios,
        covariance_corporate_action_cash_distributions=cash_distributions,
        covariance_evidence_metadata=(
            _complete_provenance(signal_prices, provenance)
            if provenance is not None
            else None
        ),
        intended_execution_date=_next_session(signal_prices),
        covariance_return_semantics=SEALED_COVARIANCE_RETURN_SEMANTICS,
        require_research_covariance_parity=True,
    )


def test_governed_live_forecast_matches_research_with_real_split_and_cash(
    prices: pd.DataFrame,
) -> None:
    config = BotConfig().strategy
    execution_location = 500
    event_location = 420
    event_symbol = str(prices.columns[3])

    raw_execution_prices = prices.copy()
    raw_execution_prices.loc[
        prices.index[event_location]:, event_symbol
    ] /= 2.0
    # A cash distribution at the same effective event makes the economic return
    # materially different from a raw split-discontinuous VWAP return.
    raw_execution_prices.loc[prices.index[event_location], event_symbol] -= 0.125
    split_ratios, cash_distributions = _neutral_corporate_actions(prices)
    split_ratios.loc[prices.index[event_location], event_symbol] = 2.0
    cash_distributions.loc[prices.index[event_location], event_symbol] = 0.25

    completed = slice(None, execution_location)
    plan = _governed_plan(
        prices.iloc[completed],
        raw_execution_prices.iloc[completed],
        split_ratios.iloc[completed],
        cash_distributions.iloc[completed],
        {
            "snapshot_id": "signed-final-validation-2026-06-29",
            "signature_sha256": "a" * 64,
        },
        config=config,
    )
    research = run_backtest(
        prices,
        config,
        execution_return_semantics="next_open_to_open",
        execution_prices=raw_execution_prices,
        corporate_action_split_ratios=split_ratios,
        corporate_action_cash_distributions=cash_distributions,
    )

    assert plan.metadata["research_covariance_parity_certified"] is True
    assert plan.metadata["covariance_corporate_action_accounting_certified"] is True
    assert plan.metadata["covariance_return_count"] == 251
    assert plan.metadata["covariance_split_ratio_hash"] is not None
    assert plan.metadata["covariance_cash_distribution_hash"] is not None
    assert plan.metadata["covariance_evidence_provenance_hash"] is not None
    assert plan.metadata["covariance_evidence_provenance"]["signature_sha256"] == "a" * 64
    assert (
        plan.metadata["covariance_evidence_provenance"]["snapshot_id"]
        == "signed-final-validation-2026-06-29"
    )
    assert plan.metadata["intended_execution_date"] == _next_session(
        prices.iloc[completed]
    ).isoformat()
    assert plan.forecast_volatility == pytest.approx(
        float(research.diagnostics.iloc[execution_location]["forecast_volatility"]),
        abs=1e-12,
    )
    mutated_metadata = dict(plan.metadata)
    mutated_provenance = dict(mutated_metadata["covariance_evidence_provenance"])
    mutated_provenance["snapshot_id"] = "signed-final-validation-tampered"
    mutated_metadata["covariance_evidence_provenance"] = mutated_provenance
    mutated_plan = replace(plan, metadata=mutated_metadata)
    assert target_plan_content_hash(mutated_plan) != plan.plan_id


def test_governed_covariance_rejects_missing_malformed_or_unproven_actions(
    prices: pd.DataFrame,
) -> None:
    split_ratios, cash_distributions = _neutral_corporate_actions(prices)

    with pytest.raises(ValueError, match="complete split-ratio and cash-distribution"):
        _governed_plan(
            prices,
            prices,
            None,
            cash_distributions,
            {"signature_sha256": "a" * 64},
        )

    malformed_splits = split_ratios.iloc[:-1]
    with pytest.raises(ValueError, match="exactly match execution covariance"):
        _governed_plan(
            prices,
            prices,
            malformed_splits,
            cash_distributions,
            {"signature_sha256": "a" * 64},
        )

    with pytest.raises(ValueError, match="authenticated evidence provenance"):
        _governed_plan(
            prices,
            prices,
            split_ratios,
            cash_distributions,
            None,
        )


def test_daily_close_proxy_is_explicitly_exploratory_and_uncertified(
    prices: pd.DataFrame,
) -> None:
    plan = build_target_plan(
        prices,
        BotConfig().strategy,
        RiskDecision(True, False, False, "normal", 0.0, 0.0, 0.0),
        minimum_assets=20,
    )

    assert plan.metadata["covariance_return_semantics"] == "daily_close_proxy"
    assert plan.metadata["research_covariance_parity_certified"] is False
    assert plan.metadata["covariance_corporate_action_accounting_certified"] is False
    assert plan.metadata["covariance_evidence_provenance_hash"] is None
    assert plan.metadata["covariance_evidence_provenance"] is None


def test_governed_live_refuses_unanchored_rebalance_cadence(
    prices: pd.DataFrame,
) -> None:
    base = BotConfig()
    slower_strategy = replace(
        base.strategy,
        portfolio=replace(base.strategy.portfolio, rebalance_every=2),
    )

    with pytest.raises(ValueError, match="REBALANCE_EVERY=1"):
        replace(
            base,
            broker="alpaca",
            execution_enabled=True,
            strategy=slower_strategy,
        ).validate()

    with pytest.raises(ValueError, match="REBALANCE_EVERY"):
        build_target_plan(
            prices,
            slower_strategy,
            RiskDecision(True, False, False, "normal", 0.0, 0.0, 0.0),
            minimum_assets=20,
            require_research_covariance_parity=True,
        )


def test_governed_live_refuses_research_breadth_below_twenty(
    prices: pd.DataFrame,
) -> None:
    with pytest.raises(ValueError, match="minimum_assets>=20"):
        build_target_plan(
            prices,
            BotConfig().strategy,
            RiskDecision(True, False, False, "normal", 0.0, 0.0, 0.0),
            minimum_assets=19,
            require_research_covariance_parity=True,
        )


def test_alpaca_engine_fails_closed_without_governed_covariance_evidence(
    tmp_path: Path,
    prices: pd.DataFrame,
) -> None:
    config = BotConfig(
        broker="simulated",
        execution_enabled=True,
        symbols=tuple(map(str, prices.columns)),
        database_path=tmp_path / "state.sqlite3",
        log_path=tmp_path / "bot.log",
        kill_switch_path=tmp_path / "KILL_SWITCH",
        process_lock_path=tmp_path / "bot.lock",
        operation_lock_path=tmp_path / "operation.lock",
        kill_switch_ack_path=tmp_path / "KILL_SWITCH.ack.json",
        daemon_health_path=tmp_path / "daemon-health.json",
        emergency_journal_path=tmp_path / "emergency-journal.json",
        simulated_prices_path=tmp_path / "unused.csv",
        simulated_state_path=tmp_path / "broker.json",
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
    engine = AutomationEngine(config, broker, StateStore(config.database_path))
    # Exercise the production decision branch with an adapter that supplies no
    # authenticated evidence. It must not silently substitute its daily closes.
    engine.config = replace(
        engine.config,
        broker="alpaca",
        minimum_assets=20,
        max_data_age_days=10_000,
    )

    with pytest.raises(ValueError, match="signed 09:30-09:35"):
        engine.generate_plan(force=True)


def test_engine_authenticates_monotonic_evidence_before_plan_construction(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = BotConfig(
        broker="simulated",
        execution_enabled=True,
        symbols=tuple(map(str, prices.columns)),
        database_path=tmp_path / "anchored-state.sqlite3",
        log_path=tmp_path / "anchored-bot.log",
        kill_switch_path=tmp_path / "ANCHORED_KILL_SWITCH",
        process_lock_path=tmp_path / "anchored-bot.lock",
        operation_lock_path=tmp_path / "anchored-operation.lock",
        kill_switch_ack_path=tmp_path / "ANCHORED_KILL_SWITCH.ack.json",
        daemon_health_path=tmp_path / "anchored-daemon-health.json",
        emergency_journal_path=tmp_path / "anchored-emergency-journal.json",
        simulated_prices_path=tmp_path / "anchored-unused.csv",
        simulated_state_path=tmp_path / "anchored-broker.json",
        simulated_market_always_open=True,
        minimum_assets=20,
    )
    broker = SimulatedBroker(
        prices_path=config.simulated_prices_path,
        state_path=config.simulated_state_path,
        starting_cash=config.simulated_starting_cash,
        market_always_open=True,
        prices=prices,
    )
    store = StateStore(
        config.database_path,
        authentication_key=hashlib.sha256(b"engine-covariance-anchor-key").digest(),
    )
    engine = AutomationEngine(config, broker, store)
    engine.config = replace(
        engine.config,
        broker="alpaca",
        minimum_assets=20,
        max_data_age_days=10_000,
    )
    evidence_prices = prices.tail(config.history_bars)
    split_ratios, cash_distributions = _neutral_corporate_actions(evidence_prices)
    intended = _next_session(evidence_prices)
    provenance = {
        "latest_session": prices.index[-1].date().isoformat(),
        "issued_at": "2026-06-30T14:00:00+00:00",
        "expires_at": "2026-07-02T00:00:00+00:00",
        "next_session": intended.isoformat(),
        "return_semantics": COVARIANCE_RETURN_SEMANTICS,
        "snapshot_id": "engine-snapshot-2026-06-30",
        "payload_sha256": "c" * 64,
    }
    broker.get_market_clock = lambda: MarketClock(  # type: ignore[method-assign]
        timestamp=datetime(2026, 6, 30, 21, 0, tzinfo=timezone.utc),
        is_open=False,
        next_open=datetime(2026, 7, 1, 13, 30, tzinfo=timezone.utc),
        next_close=datetime(2026, 7, 1, 20, 0, tzinfo=timezone.utc),
    )
    broker.get_governed_covariance_evidence = lambda *_args: (  # type: ignore[method-assign]
        GovernedCovarianceEvidence(
            execution_prices=evidence_prices,
            split_ratios=split_ratios,
            cash_distributions=cash_distributions,
            intended_execution_date=intended,
            provenance=provenance,
        )
    )

    def observe_anchor_before_plan(**_kwargs):
        assert store.get_state(StateStore.COVARIANCE_EVIDENCE_ANCHOR_KEY) == {
            "latest_session": provenance["latest_session"],
            "issued_at": provenance["issued_at"],
            "snapshot_id": provenance["snapshot_id"],
            "payload_sha256": provenance["payload_sha256"],
        }
        raise RuntimeError("plan-construction-observed-after-anchor")

    monkeypatch.setattr(engine_module, "build_target_plan", observe_anchor_before_plan)

    with pytest.raises(RuntimeError, match="observed-after-anchor"):
        engine.generate_plan(force=True)


def test_governed_plan_cannot_execute_after_its_exact_signed_next_session(
    tmp_path: Path,
    prices: pd.DataFrame,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = BotConfig(
        broker="simulated",
        execution_enabled=True,
        symbols=tuple(map(str, prices.columns)),
        minimum_assets=20,
        database_path=tmp_path / "exact-session.sqlite3",
        kill_switch_path=tmp_path / "EXACT_SESSION_KILL",
        simulated_prices_path=tmp_path / "unused.csv",
        simulated_state_path=tmp_path / "exact-session-broker.json",
        simulated_market_always_open=True,
    )
    broker = SimulatedBroker(
        prices_path=config.simulated_prices_path,
        state_path=config.simulated_state_path,
        starting_cash=config.simulated_starting_cash,
        market_always_open=True,
        prices=prices,
    )
    store = StateStore(config.database_path)
    engine = AutomationEngine(
        replace(config, broker="alpaca", minimum_assets=20),
        broker,
        store,
    )
    splits, cash = _neutral_corporate_actions(prices)
    draft = _governed_plan(
        prices,
        prices,
        splits,
        cash,
        {"snapshot_id": "exact-session-hostile-test", "signature_sha256": "d" * 64},
    )
    plan = seal_target_plan(
        draft,
        engine._current_plan_binding(),
        engine.config.plan_authentication_key_bytes,
    )
    assert store.save_plan(plan)
    intended = date.fromisoformat(plan.metadata["intended_execution_date"])
    wrong_session = intended + timedelta(days=1)
    ny = timezone(timedelta(hours=-4))
    broker.get_market_clock = lambda: MarketClock(  # type: ignore[method-assign]
        timestamp=datetime.combine(wrong_session, time(9, 31), tzinfo=ny),
        is_open=True,
        next_open=datetime.combine(
            wrong_session + timedelta(days=1), time(9, 30), tzinfo=ny
        ),
        next_close=datetime.combine(wrong_session, time(16, 0), tzinfo=ny),
    )
    account_read = False

    def forbidden_account_read():
        nonlocal account_read
        account_read = True
        raise AssertionError("wrong-session plan reached account/order preparation")

    monkeypatch.setattr(broker, "get_account", forbidden_account_read)

    with pytest.raises(RuntimeError, match="exact signed next exchange session"):
        engine.execute_latest_plan()

    assert account_read is False
    assert store.get_plan(plan.plan_id).status == "expired"
