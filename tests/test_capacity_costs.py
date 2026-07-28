from __future__ import annotations

from dataclasses import replace
from io import BytesIO

import numpy as np
import pandas as pd
import pytest

from quant_app.backtest import (
    CARRY_DAY_COUNT_CONVENTION,
    _aggregate_daily_trade_cost,
    _causal_average_daily_dollar_volume,
    _carry_elapsed_time,
    _construct_weights,
    _rebalance_cost_details,
    run_backtest,
)
from quant_app.config import AppConfig
from quant_app.data import generate_demo_prices, load_dollar_volume_csv
from quant_app.metrics import metrics_from_returns
from quant_app.validation import (
    BootstrapSummary,
    certification_table,
    doubled_cost_config,
    parameter_perturbation_pass_mask,
    rolling_target_pass_rate,
)


@pytest.fixture(scope="module")
def prices() -> pd.DataFrame:
    return generate_demo_prices(n_assets=8, years=2, seed=7331)


@pytest.fixture(scope="module")
def liquid_config() -> AppConfig:
    base = AppConfig()
    return replace(
        base,
        costs=replace(
            base.costs,
            starting_capital=1_000_000.0,
            max_participation_rate=0.05,
            square_root_impact_coefficient=1.0,
        ),
    )


@pytest.fixture(scope="module")
def dollar_volume(prices: pd.DataFrame) -> pd.DataFrame:
    return pd.DataFrame(50_000_000.0, index=prices.index, columns=prices.columns)


@pytest.fixture(scope="module")
def capacity_result(prices, liquid_config, dollar_volume):
    return run_backtest(
        prices,
        liquid_config,
        execution_return_semantics="next_close_proxy",
        daily_dollar_volume=dollar_volume,
    )


def test_adv_uses_only_completed_prior_sessions(prices: pd.DataFrame) -> None:
    raw = pd.DataFrame(
        np.arange(1, len(prices) + 1, dtype=float)[:, None]
        * np.ones((1, len(prices.columns))),
        index=prices.index,
        columns=prices.columns,
    )
    adv = _causal_average_daily_dollar_volume(raw, prices, lookback=5)
    assert adv is not None
    assert adv.iloc[5, 0] == pytest.approx(float(raw.iloc[:5, 0].mean()))

    changed = raw.copy()
    changed.iloc[5:, 0] *= 1_000_000.0
    changed_adv = _causal_average_daily_dollar_volume(changed, prices, lookback=5)
    assert changed_adv is not None
    assert changed_adv.iloc[5, 0] == pytest.approx(adv.iloc[5, 0])
    assert changed_adv.iloc[6, 0] != pytest.approx(adv.iloc[6, 0])


def test_dollar_volume_loader_is_strict_and_never_fills() -> None:
    dates = pd.bdate_range("2024-01-02", periods=80)
    frame = pd.DataFrame(
        {
            "Date": dates,
            "A": 10_000_000.0,
            "B": 20_000_000.0,
        }
    )
    frame.loc[17, "B"] = np.nan
    loaded, report = load_dollar_volume_csv(
        BytesIO(frame.to_csv(index=False).encode("utf-8"))
    )
    assert pd.isna(loaded.iloc[17]["B"])
    assert report.missing_fraction_before_fill > 0.0

    invalid = frame.copy()
    invalid.loc[17, "B"] = 0.0
    with pytest.raises(ValueError, match="finite and strictly positive"):
        load_dollar_volume_csv(
            BytesIO(invalid.to_csv(index=False).encode("utf-8"))
        )


def test_square_root_impact_accounting_is_cost_consistent(
    liquid_config: AppConfig,
) -> None:
    assets = pd.Index(["A", "B"])
    pre_trade = pd.Series([0.0, 0.0], index=assets)
    target = pd.Series([0.10, -0.10], index=assets)
    adv = pd.Series([100_000_000.0, 100_000_000.0], index=assets)
    annual_vol = pd.Series([0.20, 0.20], index=assets)
    detail = _rebalance_cost_details(
        pre_trade,
        target,
        transaction_cost_rate=liquid_config.costs.transaction_cost_bps / 10_000.0,
        pre_trade_equity_dollars=liquid_config.costs.starting_capital,
        adv_dollars=adv,
        annualized_asset_volatility=annual_vol,
        costs=liquid_config.costs,
    )

    assert detail.market_impact_cost > 0.0
    assert detail.total_cost == pytest.approx(
        detail.linear_cost + detail.market_impact_cost,
        abs=1e-14,
    )
    assert detail.trade_notional_dollars.sum() == pytest.approx(
        detail.turnover * liquid_config.costs.starting_capital,
        rel=1e-12,
    )
    remaining_equity = 1.0 - detail.total_cost
    pd.testing.assert_series_equal(
        detail.signed_trade_weights,
        target.mul(remaining_equity),
        check_names=False,
        atol=1e-14,
        rtol=1e-14,
    )

    stressed = _rebalance_cost_details(
        pre_trade,
        target,
        transaction_cost_rate=(
            doubled_cost_config(liquid_config).costs.transaction_cost_bps / 10_000.0
        ),
        pre_trade_equity_dollars=liquid_config.costs.starting_capital,
        adv_dollars=adv,
        annualized_asset_volatility=annual_vol,
        costs=doubled_cost_config(liquid_config).costs,
    )
    assert stressed.market_impact_cost > detail.market_impact_cost
    assert stressed.total_cost > detail.total_cost


def test_same_day_gross_flow_is_charged_convex_aggregate_impact() -> None:
    assets = pd.Index(["A", "B"])
    costs = AppConfig().costs
    adv = pd.Series(10_000_000.0, index=assets)
    annual_vol = pd.Series(0.20, index=assets)
    first_leg = pd.Series([100_000.0, 0.0], index=assets)
    second_leg = pd.Series([100_000.0, 0.0], index=assets)
    equity = 1_000_000.0

    _, _, first_impact = _aggregate_daily_trade_cost(
        first_leg,
        pre_trade_equity_dollars=equity,
        transaction_cost_rate=costs.transaction_cost_bps / 10_000.0,
        adv_dollars=adv,
        annualized_asset_volatility=annual_vol,
        costs=costs,
    )
    _, _, second_impact = _aggregate_daily_trade_cost(
        second_leg,
        pre_trade_equity_dollars=equity,
        transaction_cost_rate=costs.transaction_cost_bps / 10_000.0,
        adv_dollars=adv,
        annualized_asset_volatility=annual_vol,
        costs=costs,
    )
    total, linear, aggregate_impact = _aggregate_daily_trade_cost(
        first_leg + second_leg,
        pre_trade_equity_dollars=equity,
        transaction_cost_rate=costs.transaction_cost_bps / 10_000.0,
        adv_dollars=adv,
        annualized_asset_volatility=annual_vol,
        costs=costs,
    )
    assert aggregate_impact > first_impact + second_impact
    assert total == pytest.approx(linear + aggregate_impact)


def test_endpoint_drawdown_arms_next_execution_instead_of_same_vwap_rescue() -> None:
    prices = generate_demo_prices(n_assets=8, years=2, seed=99)
    volume = pd.DataFrame(10_000_000.0, index=prices.index, columns=prices.columns)
    base = AppConfig()
    stressed = replace(
        base,
        risk=replace(
            base.risk,
            throttle_drawdown=1e-6,
            defensive_drawdown=2e-6,
            severe_drawdown=3e-6,
            flatten_drawdown=4e-6,
            hard_drawdown_limit=0.90,
        ),
        costs=replace(
            base.costs,
            starting_capital=1_000_000.0,
            square_root_impact_coefficient=30.0,
            impact_daily_volatility_floor=0.10,
            max_participation_rate=1.0,
        ),
    )
    result = run_backtest(
        prices,
        stressed,
        execution_return_semantics="next_close_proxy",
        daily_dollar_volume=volume,
    )
    armed = result.diagnostics["shutdown_reason"].eq(
        "drawdown_flatten_armed_next_execution"
    )
    assert armed.any()
    assert not result.diagnostics["emergency_flatten_turnover"].gt(0.0).any()
    first = int(np.flatnonzero(armed.to_numpy())[0])
    assert first + 1 < len(result.weights)
    assert float(result.weights.iloc[first].abs().sum()) > 0.0
    assert float(result.weights.iloc[first + 1].abs().sum()) <= 1e-12
    expected_returns = result.equity.pct_change(fill_method=None)
    expected_returns.iloc[0] = result.equity.iloc[0] - 1.0
    np.testing.assert_allclose(
        result.strategy_returns,
        expected_returns,
        rtol=1e-12,
        atol=1e-12,
    )


def test_integrated_capacity_metrics_reconcile(
    capacity_result,
    liquid_config: AppConfig,
) -> None:
    diagnostics = capacity_result.diagnostics
    np.testing.assert_allclose(
        diagnostics["transaction_cost"],
        diagnostics["linear_transaction_cost"] + diagnostics["market_impact_cost"],
        atol=1e-13,
        rtol=1e-13,
    )
    np.testing.assert_allclose(
        diagnostics["traded_notional_dollars"],
        diagnostics["turnover"] * diagnostics["pre_trade_equity_dollars"],
        atol=1e-5,
        rtol=1e-12,
    )
    assert diagnostics["market_impact_cost"].sum() > 0.0
    assert not diagnostics["liquidity_data_breach"].any()
    assert not diagnostics["participation_breach"].any()
    assert diagnostics["liquidity_path_valid"].all()

    metrics = metrics_from_returns(
        capacity_result.strategy_returns,
        diagnostics,
    )
    assert metrics["Liquidity Model Active"] is True
    assert metrics["Liquidity Data Breaches"] == 0
    assert metrics["Participation Limit Breaches"] == 0
    assert metrics["Annualized Market Impact Cost"] > 0.0
    assert metrics["Modeled Transaction Cost Bps"] > (
        liquid_config.costs.transaction_cost_bps
    )
    assert metrics["ADV Coverage of Traded Notional"] == pytest.approx(1.0)
    assert metrics["Configured Starting Capital Dollars"] == pytest.approx(
        liquid_config.costs.starting_capital
    )
    assert metrics["ADV Lookback Days"] == pytest.approx(
        liquid_config.costs.adv_lookback_days
    )
    assert metrics["Impact Daily Volatility Floor"] == pytest.approx(
        liquid_config.costs.impact_daily_volatility_floor
    )
    assert metrics["Configured Linear Transaction Cost Bps"] == pytest.approx(
        liquid_config.costs.transaction_cost_bps
    )
    assert metrics["Configured Annual Short Borrow Rate"] == pytest.approx(
        liquid_config.costs.annual_short_borrow_rate
    )
    assert metrics["Configured Annual Financing Rate"] == pytest.approx(
        liquid_config.costs.annual_financing_rate
    )
    assert metrics["Carry Day Count Convention"] == CARRY_DAY_COUNT_CONVENTION
    assert metrics["Carry Day Count Valid"] is True
    assert metrics["Maximum Carry Interval Days"] >= 3.0
    assert metrics["Stale Signal Trade Breaches"] == 0


def test_certification_rejects_optimistic_capacity_knobs(capacity_result) -> None:
    metrics = metrics_from_returns(
        capacity_result.strategy_returns,
        capacity_result.diagnostics,
    )
    conservative = {
        **metrics,
        "Configured Participation Limit": 0.01,
        "ADV Lookback Days": 20.0,
        "Square-Root Impact Coefficient": 0.50,
        "Impact Daily Volatility Floor": 0.005,
        "Minimum Eligible Asset Count": 20,
        "Configured Linear Transaction Cost Bps": 1.0,
        "Configured Annual Short Borrow Rate": 0.01,
        "Configured Annual Financing Rate": 0.01,
        "Stale Signal Trade Breaches": 0,
    }
    bootstrap = BootstrapSummary(
        paths=2_000,
        horizon_days=756,
        probability_positive_cagr=1.0,
        probability_cagr_target=1.0,
        probability_drawdown_target=1.0,
        probability_both_targets=1.0,
        median_cagr=1.0,
        fifth_percentile_cagr=1.0,
        median_max_drawdown=0.0,
        fifth_percentile_max_drawdown=0.0,
        worst_max_drawdown=0.0,
        probability_both_targets_lower_95=1.0,
    )

    def table_for(
        values: dict[str, object],
        *,
        target_cagr: float = -1.0,
        max_drawdown: float = 1.0,
        bootstrap_block_size: int = 20,
        double_values: dict[str, object] | None = None,
        economic_inputs_consumed: bool = False,
        rebalance_every: int = 1,
    ) -> pd.DataFrame:
        _, table = certification_table(
            oos_metrics=values,
            bootstrap=bootstrap,
            double_cost_metrics=double_values or values,
            rolling_pass_rate=1.0,
            psr_probability=1.0,
            max_gross_limit=10.0,
            target_cagr=target_cagr,
            max_drawdown=max_drawdown,
            confidence=0.5,
            bootstrap_block_size=bootstrap_block_size,
            corporate_action_model_consumed=economic_inputs_consumed,
            execution_window_liquidity_model_consumed=economic_inputs_consumed,
            point_in_time_borrow_model_consumed=economic_inputs_consumed,
            rebalance_every=rebalance_every,
        )
        return table

    baseline = table_for(conservative)
    assert not bool(
        baseline.loc["Split/share and cash-distribution accounting consumed", "Pass"]
    )
    assert not bool(
        baseline.loc["Execution-window liquidity evidence consumed", "Pass"]
    )
    assert not bool(
        baseline.loc["Point-in-time security/date borrow evidence consumed", "Pass"]
    )
    evidenced = table_for(conservative, economic_inputs_consumed=True)
    assert bool(
        evidenced.loc["Split/share and cash-distribution accounting consumed", "Pass"]
    )
    assert bool(evidenced.loc["Execution-window liquidity evidence consumed", "Pass"])
    assert bool(
        evidenced.loc["Point-in-time security/date borrow evidence consumed", "Pass"]
    )
    realized_over_cap = table_for(
        {
            **conservative,
            "Maximum Realized Participation Rate": 0.02,
            "Realized Participation Limit Breaches": 0,
        },
        economic_inputs_consumed=True,
    )
    assert not bool(
        realized_over_cap.loc["Realized POV participation cap respected", "Pass"]
    )
    assert bool(baseline.loc["Liquidity and square-root impact model active", "Pass"])
    assert bool(baseline.loc["Conservative lagged-ADV lookback", "Pass"])
    assert bool(baseline.loc["Conservative configured participation limit", "Pass"])
    assert bool(baseline.loc["Conservative impact volatility floor", "Pass"])
    assert bool(baseline.loc["Minimum effective eligible OOS asset breadth", "Pass"])
    assert bool(baseline.loc["Conservative bootstrap block size", "Pass"])
    assert bool(
        baseline.loc["Conservative configured linear transaction cost", "Pass"]
    )
    assert bool(baseline.loc["Conservative configured short-borrow rate", "Pass"])
    assert bool(baseline.loc["Conservative configured financing rate", "Pass"])
    assert bool(baseline.loc["Actual elapsed-day carry convention", "Pass"])
    assert not bool(baseline.loc["Project CAGR target not diluted", "Pass"])
    assert not bool(baseline.loc["Project drawdown target not diluted", "Pass"])
    project_targets = table_for(
        conservative,
        target_cagr=0.60,
        max_drawdown=0.15,
    )
    assert bool(project_targets.loc["Project CAGR target not diluted", "Pass"])
    assert bool(project_targets.loc["Project drawdown target not diluted", "Pass"])
    short_block = table_for(conservative, bootstrap_block_size=19)
    assert not bool(short_block.loc["Conservative bootstrap block size", "Pass"])
    non_daily = table_for(conservative, rebalance_every=2)
    assert not bool(non_daily.loc["Governed deployment cadence parity", "Pass"])

    cases = [
        (
            "Configured Participation Limit",
            0.0101,
            "Conservative configured participation limit",
        ),
        ("ADV Lookback Days", 19.0, "Conservative lagged-ADV lookback"),
        (
            "Square-Root Impact Coefficient",
            0.49,
            "Liquidity and square-root impact model active",
        ),
        (
            "Impact Daily Volatility Floor",
            0.0049,
            "Conservative impact volatility floor",
        ),
        (
            "Configured Linear Transaction Cost Bps",
            0.99,
            "Conservative configured linear transaction cost",
        ),
        (
            "Configured Annual Short Borrow Rate",
            0.0099,
            "Conservative configured short-borrow rate",
        ),
        (
            "Configured Annual Financing Rate",
            0.0099,
            "Conservative configured financing rate",
        ),
    ]
    for metric_name, optimistic_value, row_name in cases:
        table = table_for({**conservative, metric_name: optimistic_value})
        assert not bool(table.loc[row_name, "Pass"])

    invalid_double = {
        **conservative,
        "Research Path Valid": False,
        "Liquidity Path Valid": False,
        "Liquidity Data Breaches": 1,
        "Participation Limit Breaches": 1,
        "Data Integrity Breaches": 1,
        "Beta Data Breaches": 1,
        "Stale Signal Trade Breaches": 1,
    }
    double_table = table_for(conservative, double_values=invalid_double)
    assert not bool(
        double_table.loc["Double-cost research and liquidity path valid", "Pass"]
    )


def test_sparse_twenty_column_universe_cannot_pass_effective_breadth_gate() -> None:
    prices = generate_demo_prices(n_assets=20, years=3, seed=20260713)
    sparse = prices.copy()
    # One recent gap in sixteen columns is far below 1% aggregate missingness, yet the
    # 252-close quarantine correctly leaves only four effectively eligible assets.
    sparse.iloc[520, :16] = np.nan
    result = run_backtest(sparse, AppConfig())
    oos_index = result.strategy_returns.index[540:]
    metrics = metrics_from_returns(
        result.strategy_returns.reindex(oos_index),
        result.diagnostics.reindex(oos_index),
    )
    assert sparse.shape[1] == 20
    assert sparse.isna().mean().mean() < 0.01
    assert metrics["Minimum Eligible Asset Count"] <= 4

    bootstrap = BootstrapSummary(
        paths=2_000,
        horizon_days=756,
        probability_positive_cagr=1.0,
        probability_cagr_target=1.0,
        probability_drawdown_target=1.0,
        probability_both_targets=1.0,
        median_cagr=1.0,
        fifth_percentile_cagr=1.0,
        median_max_drawdown=0.0,
        fifth_percentile_max_drawdown=0.0,
        worst_max_drawdown=0.0,
        probability_both_targets_lower_95=1.0,
    )
    _, table = certification_table(
        oos_metrics=metrics,
        bootstrap=bootstrap,
        double_cost_metrics=metrics,
        rolling_pass_rate=1.0,
        psr_probability=1.0,
        max_gross_limit=10.0,
        target_cagr=0.60,
        max_drawdown=0.15,
        confidence=0.95,
        bootstrap_block_size=20,
    )
    assert not bool(
        table.loc["Minimum effective eligible OOS asset breadth", "Pass"]
    )


def test_perturbation_stability_fails_closed_on_path_or_capacity_breach() -> None:
    frame = pd.DataFrame(
        {
            "OOS CAGR": [0.50, 0.50, 0.50, 0.449, 0.50],
            "OOS Sharpe": [1.5, 1.5, 1.5, 1.5, 0.99],
            "OOS Max Drawdown": [-0.10, -0.10, -0.10, -0.10, -0.10],
            "Max Gross": [1.0, 1.0, 1.0, 1.0, 1.0],
            "Configured Max Gross": [2.5, 2.5, 2.5, 2.5, 2.5],
            "Research Path Valid": [True, False, True, True, True],
            "Liquidity Path Valid": [True, False, True, True, True],
            "Liquidity Data Breaches": [0, 0, 0, 0, 0],
            "Participation Limit Breaches": [0, 0, 1, 0, 0],
            "Data Integrity Breaches": [0, 0, 0, 0, 0],
            "Beta Data Breaches": [0, 0, 0, 0, 0],
            "Hard Drawdown Breaches": [0, 0, 0, 0, 0],
            "Stale Signal Trade Breaches": [0, 0, 0, 0, 0],
            "Input Asset Count": [20, 20, 20, 20, 20],
            "Base Input Asset Count": [20, 20, 20, 20, 20],
            "Universe Retention Fraction": [1.0, 1.0, 1.0, 1.0, 1.0],
            "Minimum Eligible Asset Count": [20, 20, 20, 20, 20],
            "Base Minimum Eligible Asset Count": [20, 20, 20, 20, 20],
            "Effective Eligible Retention Fraction": [1.0, 1.0, 1.0, 1.0, 1.0],
        },
        index=[
            "valid",
            "invalid_path",
            "participation_breach",
            "collapsed_cagr",
            "weak_sharpe",
        ],
    )
    mask = parameter_perturbation_pass_mask(frame, max_drawdown=0.15)
    assert mask.to_dict() == {
        "valid": True,
        "invalid_path": False,
        "participation_breach": False,
        "collapsed_cagr": False,
        "weak_sharpe": False,
    }
    assert not parameter_perturbation_pass_mask(
        frame.drop(columns=["Liquidity Path Valid"]),
        max_drawdown=0.15,
    ).any()
    assert not bool(
        parameter_perturbation_pass_mask(
            frame,
            max_drawdown=0.15,
            target_cagr=0.80,
        ).loc["valid"]
    )


def test_missing_adv_on_traded_asset_is_adverse_and_invalidates_path(
    prices: pd.DataFrame,
    liquid_config: AppConfig,
    dollar_volume: pd.DataFrame,
    capacity_result,
) -> None:
    traded_symbol = str(capacity_result.weights.abs().max().idxmax())
    missing = dollar_volume.copy()
    missing[traded_symbol] = np.nan
    result = run_backtest(
        prices,
        liquid_config,
        execution_return_semantics="next_close_proxy",
        daily_dollar_volume=missing,
    )
    breached = result.diagnostics["liquidity_data_breach"]
    assert breached.any()
    assert (
        result.diagnostics.loc[breached, "missing_adv_traded_notional_dollars"] > 0.0
    ).all()
    assert result.diagnostics.loc[breached, "market_impact_cost"].gt(0.0).all()
    assert not result.diagnostics["liquidity_path_valid"].iloc[-1]
    assert not result.diagnostics["research_path_valid"].iloc[-1]

    metrics = metrics_from_returns(result.strategy_returns, result.diagnostics)
    assert metrics["Liquidity Data Breaches"] > 0
    assert metrics["Liquidity Path Valid"] is False
    assert metrics["ADV Coverage of Traded Notional"] < 1.0


def test_participation_breach_is_not_hidden(
    prices: pd.DataFrame,
    liquid_config: AppConfig,
) -> None:
    constrained = replace(
        liquid_config,
        costs=replace(
            liquid_config.costs,
            starting_capital=10_000_000.0,
            max_participation_rate=0.001,
        ),
    )
    thin_volume = pd.DataFrame(
        500_000.0,
        index=prices.index,
        columns=prices.columns,
    )
    result = run_backtest(
        prices,
        constrained,
        execution_return_semantics="next_close_proxy",
        daily_dollar_volume=thin_volume,
    )
    assert result.diagnostics["participation_breach"].any()
    assert (
        result.diagnostics.loc[
            result.diagnostics["participation_breach"],
            "maximum_participation_rate",
        ]
        > constrained.costs.max_participation_rate
    ).all()
    metrics = metrics_from_returns(result.strategy_returns, result.diagnostics)
    assert metrics["Participation Limit Breaches"] > 0
    assert metrics["Maximum Participation Utilization"] > 1.0
    assert metrics["Liquidity Path Valid"] is False


@pytest.mark.parametrize("bad_value", [0.0, -1.0, np.inf])
def test_programmatic_price_frames_reject_invalid_nonmissing_values(
    prices: pd.DataFrame,
    bad_value: float,
) -> None:
    invalid = prices.copy()
    invalid.iloc[10, 2] = bad_value
    with pytest.raises(ValueError, match="finite and strictly positive"):
        run_backtest(invalid, AppConfig())


def test_beta_neutral_constructor_excludes_unknown_beta() -> None:
    assets = pd.Index(list("ABCDEF"))
    alpha = pd.Series([-2.0, -1.0, -0.5, 0.5, 1.0, 2.0], index=assets)
    volatility = pd.Series(0.20, index=assets)
    beta = pd.Series([0.8, 0.9, np.nan, 1.1, 1.2, 1.3], index=assets)
    weights = _construct_weights(
        alpha,
        volatility,
        beta,
        desired_gross=0.30,
        config=AppConfig(),
    )
    assert weights["C"] == 0.0
    assert abs(float(weights.sum())) < 1e-10
    assert abs(float(weights.dot(beta.fillna(0.0)))) < 1e-10


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("starting_capital", 0.0, "starting_capital"),
        ("adv_lookback_days", 1, "adv_lookback_days"),
        ("max_participation_rate", 0.0, "max_participation_rate"),
        ("square_root_impact_coefficient", np.nan, "square_root_impact_coefficient"),
        ("impact_daily_volatility_floor", 0.0, "impact_daily_volatility_floor"),
    ],
)
def test_liquidity_cost_configuration_is_validated(
    field: str,
    value: float,
    message: str,
) -> None:
    base = AppConfig()
    config = replace(base, costs=replace(base.costs, **{field: value}))
    with pytest.raises(ValueError, match=message):
        config.validate()


def test_current_window_volume_collapse_changes_fill_not_causal_order(
    prices: pd.DataFrame,
    liquid_config: AppConfig,
) -> None:
    governed = replace(
        liquid_config,
        costs=replace(
            liquid_config.costs,
            starting_capital=10_000_000.0,
            max_participation_rate=0.01,
        ),
    )
    window_volume = pd.DataFrame(
        1_000_000_000.0,
        index=prices.index,
        columns=prices.columns,
    )
    baseline = run_backtest(
        prices,
        governed,
        execution_return_semantics="next_close_proxy",
        execution_window_dollar_volume=window_volume,
    )
    candidate = baseline.diagnostics[
        baseline.diagnostics["submitted_trade_notional_dollars"] > 1_000_000.0
    ]
    assert not candidate.empty
    hostile_date = candidate["submitted_trade_notional_dollars"].idxmax()

    collapsed_volume = window_volume.copy()
    collapsed_volume.loc[hostile_date] /= 100.0
    collapsed = run_backtest(
        prices,
        governed,
        execution_return_semantics="next_close_proxy",
        execution_window_dollar_volume=collapsed_volume,
    )
    base_row = baseline.diagnostics.loc[hostile_date]
    collapsed_row = collapsed.diagnostics.loc[hostile_date]

    # Row-t volume is an outcome only: it cannot leak into the frozen target order.
    assert collapsed_row["submitted_trade_notional_dollars"] == pytest.approx(
        base_row["submitted_trade_notional_dollars"], rel=1e-12, abs=1e-8
    )
    assert collapsed_row["submitted_turnover"] == pytest.approx(
        base_row["submitted_turnover"], rel=1e-12, abs=1e-12
    )
    assert collapsed_row["desired_gross"] == pytest.approx(
        base_row["desired_gross"], rel=1e-12, abs=1e-12
    )

    assert base_row["execution_fill_ratio"] == pytest.approx(1.0)
    assert not bool(base_row["execution_residual_breach"])
    assert 0.0 < collapsed_row["execution_fill_ratio"] < 1.0
    assert bool(collapsed_row["execution_residual_breach"])
    assert collapsed_row["canceled_trade_notional_dollars"] > 0.0
    assert collapsed_row["filled_trade_notional_dollars"] < base_row[
        "filled_trade_notional_dollars"
    ]
    assert collapsed_row["maximum_realized_participation_rate"] <= (
        governed.costs.max_participation_rate + 1e-12
    )
    assert collapsed_row["transaction_cost"] != pytest.approx(
        base_row["transaction_cost"], rel=1e-10, abs=1e-14
    )
    assert not np.allclose(
        collapsed.weights.loc[hostile_date].to_numpy(dtype=float),
        baseline.weights.loc[hostile_date].to_numpy(dtype=float),
    )
    assert not bool(collapsed_row["liquidity_path_valid"])
    assert not bool(collapsed_row["research_path_valid"])

    metrics = metrics_from_returns(
        collapsed.strategy_returns,
        collapsed.diagnostics,
    )
    assert metrics["Execution Residual Breaches"] > 0
    assert metrics["Canceled Notional Dollars"] > 0.0
    assert metrics["Minimum Execution Fill Ratio"] < 1.0
    bootstrap = BootstrapSummary(
        paths=2_000,
        horizon_days=756,
        probability_positive_cagr=1.0,
        probability_cagr_target=1.0,
        probability_drawdown_target=1.0,
        probability_both_targets=1.0,
        median_cagr=1.0,
        fifth_percentile_cagr=1.0,
        median_max_drawdown=0.0,
        fifth_percentile_max_drawdown=0.0,
        worst_max_drawdown=0.0,
        probability_both_targets_lower_95=1.0,
    )
    _, table = certification_table(
        oos_metrics=metrics,
        bootstrap=bootstrap,
        double_cost_metrics=metrics,
        rolling_pass_rate=1.0,
        psr_probability=1.0,
        max_gross_limit=10.0,
        target_cagr=0.60,
        max_drawdown=0.15,
        confidence=0.95,
        bootstrap_block_size=20,
        corporate_action_model_consumed=True,
        execution_window_liquidity_model_consumed=True,
        point_in_time_borrow_model_consumed=True,
    )
    assert not bool(table.loc["No canceled execution residual", "Pass"])


def test_maximum_gross_metric_includes_pre_trade_drift(capacity_result) -> None:
    diagnostics = capacity_result.diagnostics.copy()
    diagnostics["gross_exposure"] = diagnostics["gross_exposure"].clip(upper=0.50)
    breach_date = diagnostics.index[-1]
    diagnostics.loc[breach_date, "pre_trade_gross_exposure"] = 2.75
    metrics = metrics_from_returns(capacity_result.strategy_returns, diagnostics)
    assert metrics["Maximum Pre-Trade Gross Exposure"] == pytest.approx(2.75)
    assert metrics["Maximum Gross Exposure"] == pytest.approx(2.75)


def test_rolling_target_windows_always_include_latest_complete_tail() -> None:
    index = pd.bdate_range("2024-01-02", periods=300)
    returns = pd.Series(0.001, index=index)
    _, windows = rolling_target_pass_rate(
        returns,
        target_cagr=0.0,
        max_drawdown=0.15,
        window=100,
        step=63,
    )
    assert windows.index[-1] == returns.index[-1]


def test_actual_elapsed_carry_preserves_holiday_and_weekend_days() -> None:
    sessions = pd.DatetimeIndex(
        ["2024-07-03", "2024-07-05", "2024-07-08", "2024-07-09"]
    )
    elapsed = _carry_elapsed_time(sessions)
    assert elapsed["elapsed_calendar_days"].tolist() == [0.0, 2.0, 3.0, 1.0]
    np.testing.assert_allclose(
        elapsed["carry_year_fraction"],
        np.asarray([0.0, 2.0, 3.0, 1.0]) / 365.25,
        rtol=0.0,
        atol=0.0,
    )


def test_borrow_and_financing_costs_use_realized_elapsed_fraction(
    capacity_result,
    liquid_config: AppConfig,
    prices: pd.DataFrame,
    dollar_volume: pd.DataFrame,
) -> None:
    diagnostics = capacity_result.diagnostics
    held_weights = capacity_result.weights.shift(1).fillna(0.0)
    short_gross = -held_weights.clip(upper=0.0).sum(axis=1)
    financed_gross = held_weights.abs().sum(axis=1).sub(1.0).clip(lower=0.0)
    fractions = diagnostics["carry_year_fraction"]
    expected_borrow = (
        short_gross
        * liquid_config.costs.annual_short_borrow_rate
        * fractions
    )
    expected_financing = (
        financed_gross
        * liquid_config.costs.annual_financing_rate
        * fractions
    )
    np.testing.assert_allclose(
        diagnostics["borrow_cost"], expected_borrow, rtol=1e-13, atol=1e-15
    )
    np.testing.assert_allclose(
        diagnostics["financing_cost"],
        expected_financing,
        rtol=1e-13,
        atol=1e-15,
    )
    assert diagnostics.iloc[0]["carry_year_fraction"] == 0.0
    assert diagnostics.iloc[0]["borrow_cost"] == 0.0
    assert diagnostics.iloc[0]["financing_cost"] == 0.0

    active_short = short_gross.gt(1e-12)
    one_day = active_short & diagnostics["elapsed_calendar_days"].eq(1.0)
    weekend = active_short & diagnostics["elapsed_calendar_days"].ge(3.0)
    assert one_day.any() and weekend.any()
    normalized_borrow = diagnostics["borrow_cost"].div(short_gross)
    assert normalized_borrow.loc[weekend].iloc[0] >= 3.0 * (
        liquid_config.costs.annual_short_borrow_rate / 365.25
    )
    assert normalized_borrow.loc[one_day].iloc[0] == pytest.approx(
        liquid_config.costs.annual_short_borrow_rate / 365.25,
        rel=1e-13,
    )
    levered_config = replace(
        liquid_config,
        portfolio=replace(
            liquid_config.portfolio,
            target_volatility=1.0,
            max_gross_leverage=5.0,
            max_position_weight=0.50,
        ),
    )
    levered = run_backtest(
        prices,
        levered_config,
        execution_return_semantics="next_close_proxy",
        daily_dollar_volume=dollar_volume,
    )
    levered_held = levered.weights.shift(1).fillna(0.0)
    levered_financed = levered_held.abs().sum(axis=1).sub(1.0).clip(lower=0.0)
    assert levered_financed.gt(1e-12).any()
    expected_levered_financing = (
        levered_financed
        * levered_config.costs.annual_financing_rate
        * levered.diagnostics["carry_year_fraction"]
    )
    np.testing.assert_allclose(
        levered.diagnostics["financing_cost"],
        expected_levered_financing,
        rtol=1e-13,
        atol=1e-15,
    )
    financed_weekend = levered_financed.gt(1e-12) & levered.diagnostics[
        "elapsed_calendar_days"
    ].ge(3.0)
    assert financed_weekend.any()


def test_backtest_rejects_duplicate_and_non_monotonic_carry_timestamps(
    prices: pd.DataFrame,
) -> None:
    duplicated = prices.copy()
    duplicate_index = duplicated.index.to_list()
    duplicate_index[20] = duplicate_index[19]
    duplicated.index = pd.DatetimeIndex(duplicate_index)
    with pytest.raises(ValueError, match="duplicate"):
        run_backtest(duplicated, AppConfig())

    non_monotonic = prices.copy()
    reversed_pair = non_monotonic.index.to_list()
    reversed_pair[20], reversed_pair[21] = reversed_pair[21], reversed_pair[20]
    non_monotonic.index = pd.DatetimeIndex(reversed_pair)
    with pytest.raises(ValueError, match="strictly increasing"):
        run_backtest(non_monotonic, AppConfig())
