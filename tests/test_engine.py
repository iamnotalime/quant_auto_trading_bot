from __future__ import annotations

from dataclasses import replace
from io import BytesIO

import numpy as np
import pandas as pd
import pytest

from quant_app.backtest import BacktestResult, run_backtest
from quant_app.config import AppConfig
from quant_app.data import generate_demo_prices, load_price_csv
from quant_app.metrics import metrics_from_returns, rolling_metrics
from quant_app.validation import (
    block_bootstrap_validation,
    certification_table,
    doubled_cost_config,
    probabilistic_sharpe_probability,
    sharpe_probability_diagnostics,
)


@pytest.fixture(scope="module")
def prices() -> pd.DataFrame:
    return generate_demo_prices(n_assets=10, years=3, seed=101)


@pytest.fixture(scope="module")
def base_result(prices: pd.DataFrame) -> BacktestResult:
    return run_backtest(prices, AppConfig())


@pytest.fixture(scope="module")
def delayed_result(prices: pd.DataFrame) -> BacktestResult:
    return run_backtest(
        prices,
        AppConfig(),
        execution_return_semantics="next_close_proxy",
    )


@pytest.mark.parametrize(
    ("config", "message"),
    [
        (
            replace(
                AppConfig(),
                regime=replace(AppConfig().regime, favorable_ic_tstat=-0.1),
            ),
            "favorable >= neutral > invalid",
        ),
        (
            replace(
                AppConfig(),
                regime=replace(
                    AppConfig().regime,
                    neutral_multiplier=0.2,
                    degraded_multiplier=0.4,
                ),
            ),
            "Regime multipliers must be non-increasing",
        ),
        (
            replace(
                AppConfig(),
                costs=replace(AppConfig().costs, transaction_cost_bps=float("nan")),
            ),
            "transaction_cost_bps must be finite",
        ),
        (
            replace(
                AppConfig(),
                risk=replace(AppConfig().risk, flatten_drawdown=0.09),
            ),
            "Drawdown thresholds must be strictly increasing",
        ),
    ],
)
def test_strategy_configuration_rejects_unsafe_economics(
    config: AppConfig,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        config.validate()


@pytest.fixture(scope="module")
def next_open_result(prices: pd.DataFrame) -> BacktestResult:
    return run_backtest(
        prices,
        AppConfig(),
        execution_return_semantics="next_open_to_open",
        execution_prices=prices,
    )


def test_backtest_respects_leverage_position_and_neutrality_constraints(
    base_result: BacktestResult,
) -> None:
    config = AppConfig()
    assert base_result.diagnostics["gross_exposure"].max() <= config.portfolio.max_gross_leverage + 1e-8
    assert base_result.weights.abs().max().max() <= config.portfolio.max_position_weight + 1e-8
    assert base_result.diagnostics["net_exposure"].abs().max() < 1e-3
    assert base_result.diagnostics["beta_exposure"].abs().max() < 1e-3


def test_future_price_changes_do_not_change_past_weights(
    prices: pd.DataFrame,
    base_result: BacktestResult,
) -> None:
    cutoff = 520
    changed = prices.copy()
    factors = np.linspace(0.55, 1.45, changed.shape[1])
    changed.iloc[cutoff:] = changed.iloc[cutoff:].mul(factors, axis=1)
    altered = run_backtest(changed, AppConfig())

    pd.testing.assert_frame_equal(
        base_result.weights.iloc[:cutoff],
        altered.weights.iloc[:cutoff],
        check_exact=False,
        atol=1e-12,
        rtol=1e-12,
    )
    pd.testing.assert_series_equal(
        base_result.equity.iloc[:cutoff],
        altered.equity.iloc[:cutoff],
        check_exact=False,
        atol=1e-12,
        rtol=1e-12,
    )


def test_extreme_adverse_gap_triggers_flatten_or_hard_breach(
    prices: pd.DataFrame,
    base_result: BacktestResult,
) -> None:
    active_locations = np.flatnonzero(base_result.diagnostics["gross_exposure"].to_numpy() > 0.25)
    assert len(active_locations) > 0
    location = int(active_locations[len(active_locations) // 2])
    assert location + 1 < len(prices)

    held = base_result.weights.iloc[location]
    factors = pd.Series(1.0, index=prices.columns)
    factors.loc[held > 0] = 0.60
    factors.loc[held < 0] = 1.40

    shocked = prices.copy()
    shocked.iloc[location + 1:] = shocked.iloc[location + 1:].mul(factors, axis=1)
    result = run_backtest(shocked, AppConfig())

    post_shock = result.diagnostics.iloc[location + 1: location + 4]
    assert (
        post_shock["hard_drawdown_breach"].any()
        or (post_shock["gross_exposure"] <= 1e-8).any()
    )


def test_doubled_costs_do_not_improve_identical_trade_path_materially(
    prices: pd.DataFrame,
    base_result: BacktestResult,
) -> None:
    stressed = run_backtest(prices, doubled_cost_config(AppConfig()))
    # Risk adaptation can alter the path, but doubled modeled costs should not create a
    # meaningful free improvement over the same deterministic data.
    assert stressed.equity.iloc[-1] <= base_result.equity.iloc[-1] * 1.001


def test_turnover_is_measured_from_marked_to_market_weights(
    base_result: BacktestResult,
) -> None:
    asset_returns = base_result.prices.pct_change(fill_method=None).fillna(0.0)
    errors: list[float] = []
    drift_distances: list[float] = []

    for i in range(1, len(base_result.weights)):
        row = base_result.diagnostics.iloc[i]
        if row["emergency_flatten_turnover"] > 0 or bool(row["hard_drawdown_breach"]):
            continue
        previous = base_result.weights.iloc[i - 1]
        growth = max(1.0 + float(row["holding_net_return"]), 1e-8)
        drifted = previous.mul(1.0 + asset_returns.iloc[i]).div(growth)
        remaining_equity = 1.0 - float(row["transaction_cost"])
        expected_turnover = float(
            (base_result.weights.iloc[i].mul(remaining_equity) - drifted).abs().sum()
        )
        errors.append(abs(float(row["turnover"]) - expected_turnover))
        drift_distances.append(float((drifted - previous).abs().sum()))
        assert float(row["transaction_cost"]) == pytest.approx(
            AppConfig().costs.transaction_cost_bps / 10_000.0 * expected_turnover,
            abs=1e-13,
        )

    assert errors
    assert max(errors) < 1e-10
    assert max(drift_distances) > 1e-5


def test_bootstrap_returns_probabilities_in_unit_interval(base_result: BacktestResult) -> None:
    summary = block_bootstrap_validation(
        base_result.strategy_returns.iloc[-300:],
        n_paths=200,
        horizon_days=252,
        block_size=10,
        target_cagr=0.60,
        max_drawdown=0.15,
    )
    probabilities = [
        summary.probability_positive_cagr,
        summary.probability_cagr_target,
        summary.probability_drawdown_target,
        summary.probability_both_targets,
        summary.probability_both_targets_lower_95,
    ]
    assert all(0.0 <= value <= 1.0 for value in probabilities)
    assert (
        summary.probability_both_targets_lower_95
        <= summary.probability_both_targets
    )


def test_first_period_loss_is_included_in_metrics_rolling_and_bootstrap_drawdown() -> None:
    index = pd.date_range("2024-01-01", periods=2, freq="B")
    returns = pd.Series([-0.10, 1.0 / 9.0], index=index)

    metrics = metrics_from_returns(returns)
    rolling = rolling_metrics(returns, window=2)
    assert metrics["Max Drawdown"] == pytest.approx(-0.10)
    assert rolling["Rolling Max Drawdown"].iloc[-1] == pytest.approx(-0.10)

    constant_loss = pd.Series(-0.01, index=pd.RangeIndex(60))
    bootstrap = block_bootstrap_validation(
        constant_loss,
        n_paths=100,
        horizon_days=63,
        block_size=5,
        target_cagr=0.0,
        max_drawdown=0.50,
    )
    expected_drawdown = 0.99**63 - 1.0
    assert bootstrap.median_max_drawdown == pytest.approx(expected_drawdown)
    assert bootstrap.worst_max_drawdown == pytest.approx(expected_drawdown)


def test_probabilistic_sharpe_penalizes_trials_and_serial_dependence() -> None:
    rng = np.random.default_rng(90210)
    iid = pd.Series(rng.normal(0.001, 0.01, 600))
    unadjusted = probabilistic_sharpe_probability(
        iid,
        trial_count=1,
        autocorrelation_lags=0,
    )
    adjusted = probabilistic_sharpe_probability(
        iid,
        trial_count=50,
        autocorrelation_lags=0,
    )
    assert 0.0 <= adjusted < unadjusted <= 1.0

    innovations = rng.normal(0.0002, 0.01, 600)
    persistent = np.empty_like(innovations)
    persistent[0] = innovations[0]
    for i in range(1, len(persistent)):
        persistent[i] = 0.80 * persistent[i - 1] + innovations[i]
    diagnostic = sharpe_probability_diagnostics(pd.Series(persistent), trial_count=5)
    assert diagnostic.effective_observations < diagnostic.observations
    assert diagnostic.adjusted_benchmark_daily_sharpe > 0.0
    assert "stationary" in diagnostic.assumptions


def test_delayed_execution_semantics_are_explicit_and_require_real_open_prices(
    prices: pd.DataFrame,
    base_result: BacktestResult,
    delayed_result: BacktestResult,
    next_open_result: BacktestResult,
) -> None:
    assert base_result.return_semantics == "close_to_close"
    assert delayed_result.return_semantics == "next_close_proxy"
    assert delayed_result.diagnostics["return_semantics"].eq("next_close_proxy").all()
    assert pd.isna(delayed_result.diagnostics["signal_date"].iloc[0])
    pd.testing.assert_index_equal(
        pd.DatetimeIndex(delayed_result.diagnostics["signal_date"].iloc[1:]),
        prices.index[:-1],
        check_names=False,
    )

    with pytest.raises(ValueError, match="requires actual"):
        run_backtest(
            prices,
            AppConfig(),
            execution_return_semantics="next_open_to_open",
        )

    pd.testing.assert_series_equal(
        next_open_result.equity,
        delayed_result.equity,
        check_exact=False,
        atol=1e-12,
        rtol=1e-12,
    )
    pd.testing.assert_frame_equal(
        next_open_result.weights,
        delayed_result.weights,
        check_exact=False,
        atol=1e-12,
        rtol=1e-12,
    )


def test_current_execution_endpoint_cannot_change_current_target_decision(
    prices: pd.DataFrame,
) -> None:
    config = replace(
        AppConfig(),
        portfolio=replace(AppConfig().portfolio, rebalance_every=1),
    )
    baseline = run_backtest(
        prices,
        config,
        execution_return_semantics="next_open_to_open",
        execution_prices=prices,
    )
    candidates = np.flatnonzero(
        (baseline.weights.shift(1).abs().sum(axis=1).to_numpy() > 0.25)
        & ~baseline.diagnostics["shutdown_active"].to_numpy(dtype=bool)
    )
    candidates = candidates[(candidates > 300) & (candidates + 1 < len(prices))]
    assert len(candidates) > 0
    location = int(candidates[len(candidates) // 2])
    previous = baseline.weights.iloc[location - 1]
    symbol = str(previous.abs().idxmax())

    changed_execution = prices.copy()
    changed_execution.loc[prices.index[location], symbol] *= 1.02
    altered = run_backtest(
        prices,
        config,
        execution_return_semantics="next_open_to_open",
        execution_prices=changed_execution,
    )

    # The row-t endpoint marks the already-held position, but it was unavailable when
    # the row-t target, risk multipliers, and covariance forecast were decided.
    pd.testing.assert_series_equal(
        baseline.weights.iloc[location],
        altered.weights.iloc[location],
        check_exact=False,
        atol=1e-12,
        rtol=1e-12,
    )
    for field in (
        "forecast_volatility",
        "desired_gross",
        "decision_drawdown",
        "drawdown_multiplier",
        "loss_shock_multiplier",
    ):
        assert float(baseline.diagnostics.iloc[location][field]) == pytest.approx(
            float(altered.diagnostics.iloc[location][field]),
            abs=1e-14,
        )
    assert float(baseline.equity.iloc[location]) != pytest.approx(
        float(altered.equity.iloc[location]),
        abs=1e-12,
    )
    assert float(baseline.diagnostics.iloc[location + 1]["forecast_volatility"]) != (
        pytest.approx(
            float(altered.diagnostics.iloc[location + 1]["forecast_volatility"]),
            abs=1e-12,
        )
    )


def test_missing_unheld_execution_endpoint_is_not_zero_imputed_into_reentry_risk(
    prices: pd.DataFrame,
) -> None:
    symbol = str(prices.columns[0])
    gap_location = 50  # warmup: the asset is unheld when the endpoint is absent.
    execution_prices = prices.copy()
    execution_prices.iloc[gap_location, 0] = np.nan
    result = run_backtest(
        prices,
        AppConfig(),
        execution_return_semantics="next_open_to_open",
        execution_prices=execution_prices,
    )

    assert not bool(result.diagnostics.iloc[gap_location]["data_integrity_breach"])
    assert not bool(
        result.diagnostics.iloc[gap_location]["covariance_observation_complete"]
    )
    # A missing endpoint invalidates both adjacent execution intervals. Row 303 still
    # has one of them in its lagged 252-return window; row 304 is the first recovery.
    for location in (252, 253, 303):
        incomplete = str(
            result.diagnostics.iloc[location][
                "incomplete_execution_history_assets"
            ]
        ).split(",")
        assert symbol in incomplete
        assert abs(float(result.weights.iloc[location][symbol])) <= 1e-12
    recovered = str(
        result.diagnostics.iloc[304]["incomplete_execution_history_assets"]
    ).split(",")
    assert symbol not in recovered


def test_split_and_cash_accounting_preserve_economic_execution_return(
    prices: pd.DataFrame,
) -> None:
    config = replace(
        AppConfig(),
        portfolio=replace(AppConfig().portfolio, rebalance_every=1),
    )
    neutral_split = pd.DataFrame(1.0, index=prices.index, columns=prices.columns)
    neutral_cash = pd.DataFrame(0.0, index=prices.index, columns=prices.columns)
    baseline = run_backtest(
        prices,
        config,
        execution_return_semantics="next_open_to_open",
        execution_prices=prices,
        corporate_action_split_ratios=neutral_split,
        corporate_action_cash_distributions=neutral_cash,
    )
    candidates = np.flatnonzero(
        baseline.weights.shift(1).abs().max(axis=1).to_numpy() > 0.02
    )
    candidates = candidates[(candidates > 300) & (candidates + 2 < len(prices))]
    assert len(candidates) > 0
    location = int(candidates[len(candidates) // 2])
    symbol = str(baseline.weights.iloc[location - 1].abs().idxmax())

    raw_split_prices = prices.copy()
    raw_split_prices.loc[prices.index[location]:, symbol] /= 2.0
    raw_split_prices.loc[prices.index[location], symbol] = (
        float(prices.loc[prices.index[location], symbol]) - 0.25
    ) / 2.0
    split_panel = neutral_split.copy()
    split_panel.loc[prices.index[location], symbol] = 2.0
    cash_panel = neutral_cash.copy()
    cash_panel.loc[prices.index[location], symbol] = 0.25
    adjusted = run_backtest(
        prices,
        config,
        execution_return_semantics="next_open_to_open",
        execution_prices=raw_split_prices,
        corporate_action_split_ratios=split_panel,
        corporate_action_cash_distributions=cash_panel,
    )
    unadjusted = run_backtest(
        prices,
        config,
        execution_return_semantics="next_open_to_open",
        execution_prices=raw_split_prices,
    )

    assert bool(adjusted.diagnostics["corporate_action_model_active"].all())
    # The interval's economic holding return is identical. Net strategy return may
    # differ slightly because a cash distribution correctly changes the post-payment
    # security weight and therefore the subsequent rebalance turnover/cost.
    assert float(adjusted.diagnostics.iloc[location]["holding_net_return"]) == pytest.approx(
        float(baseline.diagnostics.iloc[location]["holding_net_return"]), abs=1e-12
    )
    assert float(unadjusted.strategy_returns.iloc[location]) != pytest.approx(
        float(baseline.strategy_returns.iloc[location]), abs=1e-6
    )

    prior_weights = adjusted.weights.iloc[location - 1]
    economic_returns = pd.Series(
        {
            asset: (
                float(raw_split_prices.iloc[location][asset])
                * float(split_panel.iloc[location][asset])
                + float(cash_panel.iloc[location][asset])
            )
            / float(raw_split_prices.iloc[location - 1][asset])
            - 1.0
            for asset in prices.columns
        }
    )
    position_returns = pd.Series(
        {
            asset: (
                float(raw_split_prices.iloc[location][asset])
                * float(split_panel.iloc[location][asset])
            )
            / float(raw_split_prices.iloc[location - 1][asset])
            - 1.0
            for asset in prices.columns
        }
    )
    holding_growth = 1.0 + float(
        adjusted.diagnostics.iloc[location]["holding_net_return"]
    )
    correct_pretrade = prior_weights.mul(1.0 + position_returns).div(holding_growth)
    cash_folded_into_security = prior_weights.mul(1.0 + economic_returns).div(
        holding_growth
    )
    observed_gross = float(
        adjusted.diagnostics.iloc[location]["pre_trade_gross_exposure"]
    )
    assert observed_gross == pytest.approx(
        float(correct_pretrade.abs().sum()), abs=1e-12
    )
    assert observed_gross != pytest.approx(
        float(cash_folded_into_security.abs().sum()), abs=1e-8
    )


def test_point_in_time_borrow_recall_forces_costed_short_close(
    prices: pd.DataFrame,
) -> None:
    config = replace(
        AppConfig(),
        portfolio=replace(AppConfig().portfolio, rebalance_every=1),
    )
    available = pd.DataFrame(True, index=prices.index, columns=prices.columns)
    rates = pd.DataFrame(0.03, index=prices.index, columns=prices.columns)
    recalls = pd.DataFrame(False, index=prices.index, columns=prices.columns)
    baseline = run_backtest(
        prices,
        config,
        execution_return_semantics="next_open_to_open",
        execution_prices=prices,
        borrow_availability=available,
        annual_borrow_rates=rates,
        borrow_recalls=recalls,
    )
    candidates: list[tuple[int, str]] = []
    for location in range(300, len(prices) - 2):
        short = baseline.weights.iloc[location - 1]
        if float(short.min()) < -0.01:
            candidates.append((location, str(short.idxmin())))
    assert candidates
    location, symbol = candidates[len(candidates) // 2]
    recalled_available = available.copy()
    recalled = recalls.copy()
    recalled_available.loc[prices.index[location], symbol] = False
    recalled.loc[prices.index[location], symbol] = True
    result = run_backtest(
        prices,
        config,
        execution_return_semantics="next_open_to_open",
        execution_prices=prices,
        borrow_availability=recalled_available,
        annual_borrow_rates=rates,
        borrow_recalls=recalled,
    )

    assert bool(result.diagnostics["point_in_time_borrow_model_active"].all())
    assert int(result.diagnostics.iloc[location]["borrow_recall_close_count"]) == 1
    assert float(result.weights.iloc[location][symbol]) >= -1e-12
    assert float(result.diagnostics.iloc[location]["turnover"]) > 0.0
    assert bool(result.diagnostics.iloc[location]["target_rebalance"])
    assert bool(result.diagnostics.iloc[location]["target_neutrality_certified"])
    assert abs(float(result.diagnostics.iloc[location]["net_exposure"])) <= 1e-8
    assert abs(float(result.diagnostics.iloc[location]["beta_exposure"])) <= 1e-8


def test_borrow_gated_target_preserves_neutrality_breadth_and_endpoint_causality(
    prices: pd.DataFrame,
) -> None:
    config = replace(
        AppConfig(),
        portfolio=replace(AppConfig().portfolio, rebalance_every=1),
    )
    available = pd.DataFrame(True, index=prices.index, columns=prices.columns)
    rates = pd.DataFrame(0.03, index=prices.index, columns=prices.columns)
    recalls = pd.DataFrame(False, index=prices.index, columns=prices.columns)
    kwargs = {
        "execution_return_semantics": "next_open_to_open",
        "borrow_availability": available,
        "annual_borrow_rates": rates,
        "borrow_recalls": recalls,
    }
    baseline = run_backtest(prices, config, execution_prices=prices, **kwargs)
    candidates: list[tuple[int, str]] = []
    for location in range(300, len(prices) - 2):
        short = baseline.weights.iloc[location]
        if float(short.min()) < -0.01 and not bool(
            baseline.diagnostics.iloc[location]["shutdown_active"]
        ):
            candidates.append((location, str(short.idxmin())))
    assert candidates
    location, symbol = candidates[len(candidates) // 2]

    gated_availability = available.copy()
    gated_availability.loc[prices.index[location], symbol] = False
    gated_kwargs = {
        **kwargs,
        "borrow_availability": gated_availability,
    }
    gated = run_backtest(prices, config, execution_prices=prices, **gated_kwargs)
    row = gated.diagnostics.iloc[location]

    assert abs(float(gated.weights.iloc[location][symbol])) <= 1e-12
    assert int(row["borrow_unavailable_increase_count"]) >= 1
    assert int(row["borrow_eligible_assets"]) == prices.shape[1] - 1
    assert int(row["eligible_assets"]) <= int(row["borrow_eligible_assets"])
    assert bool(row["target_rebalance"])
    assert bool(row["target_neutrality_certified"])
    assert abs(float(row["net_exposure"])) <= 1e-8
    assert abs(float(row["beta_exposure"])) <= 1e-8

    changed_endpoint = prices.copy()
    changed_endpoint.loc[prices.index[location], symbol] *= 1.05
    altered = run_backtest(
        prices,
        config,
        execution_prices=changed_endpoint,
        **gated_kwargs,
    )
    pd.testing.assert_series_equal(
        gated.weights.iloc[location],
        altered.weights.iloc[location],
        check_exact=False,
        atol=1e-12,
        rtol=1e-12,
    )
    assert int(
        altered.diagnostics.iloc[location]["borrow_unavailable_increase_count"]
    ) == int(row["borrow_unavailable_increase_count"])


def test_point_in_time_borrow_rates_are_doubled_in_stress(
    prices: pd.DataFrame,
) -> None:
    available = pd.DataFrame(True, index=prices.index, columns=prices.columns)
    # Rates above 5.0 exercise the old post-multiplier 10.0 cap: a nominal 2x
    # stress must remain exactly 2x across the entire accepted vendor-rate domain.
    rates = pd.DataFrame(6.0, index=prices.index, columns=prices.columns)
    recalls = pd.DataFrame(False, index=prices.index, columns=prices.columns)
    kwargs = {
        "execution_return_semantics": "next_open_to_open",
        "execution_prices": prices,
        "borrow_availability": available,
        "annual_borrow_rates": rates,
        "borrow_recalls": recalls,
    }
    base = run_backtest(prices, AppConfig(), **kwargs)
    stressed = run_backtest(
        prices,
        doubled_cost_config(AppConfig()),
        borrow_rate_stress_multiplier=2.0,
        **kwargs,
    )
    active = np.flatnonzero(base.diagnostics["borrow_cost"].to_numpy() > 0.0)
    assert len(active) > 0
    first = int(active[0])
    assert float(stressed.diagnostics.iloc[first]["borrow_cost"]) == pytest.approx(
        2.0 * float(base.diagnostics.iloc[first]["borrow_cost"]), rel=1e-12
    )
    assert float(
        stressed.diagnostics.iloc[first]["borrow_rate_stress_multiplier"]
    ) == 2.0


def test_missing_unheld_price_is_allowed_but_missing_held_price_invalidates_path(
    prices: pd.DataFrame,
    next_open_result: BacktestResult,
) -> None:
    active = np.flatnonzero(
        next_open_result.diagnostics["gross_exposure"].to_numpy() > 0.10
    )
    assert len(active) > 0
    location = int(active[len(active) // 2])
    assert location + 1 < len(prices)
    held_symbol = str(next_open_result.weights.iloc[location].abs().idxmax())

    missing_mark = prices.copy()
    # Missing pre-listing observations are permitted while the asset is unheld.
    missing_mark.iloc[:100, 0] = np.nan
    missing_mark.loc[missing_mark.index[location + 1], held_symbol] = np.nan
    invalid = run_backtest(
        prices,
        AppConfig(),
        execution_return_semantics="next_open_to_open",
        execution_prices=missing_mark,
    )
    assert not invalid.diagnostics["data_integrity_breach"].iloc[:100].any()
    breach = invalid.diagnostics.iloc[location + 1]
    assert bool(breach["data_integrity_breach"])
    assert not bool(breach["research_path_valid"])
    assert breach["shutdown_reason"] in {
        "missing_held_asset_price",
        "hard_drawdown_breach",
    }
    assert invalid.diagnostics["gross_exposure"].iloc[location + 1] <= 1e-12
    metrics = metrics_from_returns(invalid.strategy_returns, invalid.diagnostics)
    assert metrics["Data Integrity Breaches"] >= 1
    assert metrics["Research Path Valid"] is False


def test_short_raw_close_gap_cannot_be_smoothed_for_a_held_asset(
    prices: pd.DataFrame,
    base_result: BacktestResult,
) -> None:
    active = np.flatnonzero(base_result.diagnostics["gross_exposure"].to_numpy() > 0.10)
    assert len(active) > 0
    location = int(active[len(active) // 2])
    assert location + 1 < len(prices)
    held_symbol = str(base_result.weights.iloc[location].abs().idxmax())
    prior_weight = float(base_result.weights.iloc[location][held_symbol])
    assert abs(prior_weight) > 1e-8

    missing_close = prices.copy()
    breach_date = missing_close.index[location + 1]
    missing_close.loc[breach_date, held_symbol] = np.nan
    invalid = run_backtest(missing_close, AppConfig())

    # Neither signal construction nor portfolio marks may fill the raw gap.
    assert pd.isna(invalid.prices.loc[breach_date, held_symbol])
    assert invalid.observed_prices is not None
    assert pd.isna(invalid.observed_prices.loc[breach_date, held_symbol])
    breach = invalid.diagnostics.loc[breach_date]
    assert bool(breach["data_integrity_breach"])
    assert held_symbol in str(breach["missing_held_assets"]).split(",")
    assert not bool(breach["research_path_valid"])
    assert breach["shutdown_reason"] in {
        "missing_held_asset_price",
        "hard_drawdown_breach",
    }
    assert float(invalid.weights.loc[breach_date].abs().sum()) <= 1e-12


def test_next_open_mode_cannot_open_risk_from_a_missing_signal_close(
    prices: pd.DataFrame,
    next_open_result: BacktestResult,
) -> None:
    previous = next_open_result.weights.shift(1).fillna(0.0).abs()
    openings = next_open_result.weights.abs().gt(0.01) & previous.le(1e-12)
    candidates = np.argwhere(openings.to_numpy())
    candidates = candidates[candidates[:, 0] > 150]
    assert len(candidates) > 0
    trade_location, asset_location = map(int, candidates[len(candidates) // 2])
    assert trade_location > 0
    symbol = str(prices.columns[asset_location])
    signal_date = prices.index[trade_location - 1]
    trade_date = prices.index[trade_location]

    missing_signal_close = prices.copy()
    missing_signal_close.loc[signal_date, symbol] = np.nan
    invalid = run_backtest(
        missing_signal_close,
        AppConfig(),
        execution_return_semantics="next_open_to_open",
        # Execution marks remain complete; only the completed signal-date close is absent.
        execution_prices=prices,
    )

    assert pd.isna(invalid.signals.composite.loc[signal_date, symbol])
    assert abs(float(invalid.weights.loc[signal_date, symbol])) <= 1e-12
    assert abs(float(invalid.weights.loc[trade_date, symbol])) <= 1e-12
    assert not bool(invalid.diagnostics.loc[trade_date, "stale_signal_trade_breach"])


def test_asset_requires_complete_252_close_history_before_reentry(
    prices: pd.DataFrame,
) -> None:
    gap_location = 350
    assert gap_location + 253 < len(prices)
    symbol = str(prices.columns[0])
    missing = prices.copy()
    missing.iloc[gap_location, 0] = np.nan
    result = run_backtest(
        missing,
        AppConfig(),
        execution_return_semantics="next_open_to_open",
        execution_prices=prices,
    )

    # At trade date t the engine uses signal date t-1. The gap therefore excludes the
    # asset from new risk for the next 252 trade dates, until a complete 252-close
    # signal window is available again.
    exclusion = result.weights.iloc[gap_location + 1 : gap_location + 253][symbol]
    assert exclusion.abs().max() <= 1e-12
    for diagnostic_location in (gap_location + 1, gap_location + 252):
        unavailable = str(
            result.diagnostics.iloc[diagnostic_location][
                "incomplete_signal_history_assets"
            ]
        ).split(",")
        assert symbol in unavailable
    recovered = str(
        result.diagnostics.iloc[gap_location + 253][
            "incomplete_signal_history_assets"
        ]
    ).split(",")
    assert symbol not in recovered


def test_csv_loader_never_backfills_future_prices() -> None:
    raw = pd.DataFrame(
        {
            "Date": pd.date_range("2020-01-01", periods=120, freq="B"),
            "A": np.linspace(100, 130, 120),
            "B": np.r_[np.nan, np.linspace(80, 110, 119)],
            "C": np.linspace(50, 70, 120),
            "D": np.linspace(140, 160, 120),
        }
    )
    clean, report = load_price_csv(BytesIO(raw.to_csv(index=False).encode("utf-8")))
    assert pd.isna(clean.iloc[0]["B"])
    assert report.rows == 120


def test_metrics_are_finite_for_demo_result(base_result: BacktestResult) -> None:
    metrics = metrics_from_returns(base_result.strategy_returns, base_result.diagnostics)
    for key in ["CAGR", "Annualized Volatility", "Max Drawdown", "Sharpe Ratio"]:
        assert np.isfinite(metrics[key])

    expected_pre_cost = float(
        base_result.diagnostics["gross_portfolio_return"].mean() * 252
    )
    expected_total_cost = sum(
        float(metrics[key])
        for key in [
            "Annualized Transaction Cost",
            "Annualized Borrow Cost",
            "Annualized Financing Cost",
        ]
    )
    expected_break_even_bps = (
        float(base_result.diagnostics["holding_net_return"].mean() * 252)
        / float(metrics["Annualized Turnover"])
        * 10_000.0
    )
    assert metrics["Annualized Pre-Cost Return"] == pytest.approx(expected_pre_cost)
    assert metrics["Annualized Total Modeled Cost"] == pytest.approx(expected_total_cost)
    assert metrics["Cost Coverage Ratio"] == pytest.approx(
        expected_pre_cost / expected_total_cost
    )
    assert metrics["Break-Even Transaction Cost Bps"] == pytest.approx(
        expected_break_even_bps
    )
    assert metrics["Modeled Transaction Cost Bps"] == pytest.approx(
        AppConfig().costs.transaction_cost_bps
    )

    bootstrap = block_bootstrap_validation(
        base_result.strategy_returns.iloc[-300:],
        n_paths=100,
        horizon_days=252,
        block_size=10,
        target_cagr=0.0,
        max_drawdown=1.0,
    )
    no_margin = metrics.copy()
    no_margin["Cost Coverage Ratio"] = float("nan")
    no_margin["Break-Even Transaction Cost Bps"] = float("nan")
    certified, table = certification_table(
        oos_metrics=no_margin,
        bootstrap=bootstrap,
        double_cost_metrics=metrics,
        rolling_pass_rate=1.0,
        psr_probability=1.0,
        max_gross_limit=AppConfig().portfolio.max_gross_leverage,
        target_cagr=-1.0,
        max_drawdown=1.0,
        confidence=0.50,
    )
    assert not certified
    assert not bool(table.loc["Gross return covers all modeled costs", "Pass"])
    assert not bool(table.loc["Break-even transaction cost margin", "Pass"])
