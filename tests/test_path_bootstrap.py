from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import numpy as np
import pandas as pd
import pytest

from quant_app import validation
from quant_app.config import AppConfig


def _bootstrap_summary_with_probability(probability: float) -> validation.BootstrapSummary:
    return validation.BootstrapSummary(
        paths=validation.PATH_AWARE_BOOTSTRAP_PATHS,
        horizon_days=756,
        probability_positive_cagr=probability,
        probability_cagr_target=probability,
        probability_drawdown_target=probability,
        probability_both_targets=probability,
        median_cagr=0.0,
        fifth_percentile_cagr=0.0,
        median_max_drawdown=0.0,
        fifth_percentile_max_drawdown=0.0,
        worst_max_drawdown=0.0,
        probability_both_targets_lower_95=probability,
    )


def test_path_bootstrap_reruns_loss_cooldown_and_is_the_hard_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dates = pd.bdate_range("2024-01-02", periods=121)
    interval_pattern = np.resize(
        np.asarray([0.02] * 7 + [-0.08, 0.03, 0.03], dtype=float),
        len(dates) - 1,
    )
    first_asset = np.r_[100.0, 100.0 * np.cumprod(1.0 + interval_pattern)]
    prices = pd.DataFrame(
        {symbol: first_asset * (1.0 + offset) for offset, symbol in enumerate("ABCD")},
        index=dates,
    )
    volume = pd.DataFrame(1_000_000_000.0, index=dates, columns=prices.columns)
    splits = pd.DataFrame(1.0, index=dates, columns=prices.columns)
    cash = pd.DataFrame(0.0, index=dates, columns=prices.columns)
    availability = pd.DataFrame(True, index=dates, columns=prices.columns)
    rates = pd.DataFrame(0.02, index=dates, columns=prices.columns)
    recalls = pd.DataFrame(False, index=dates, columns=prices.columns)
    observed_cooldown_days: list[int] = []
    observed_economic_inputs: list[bool] = []
    observed_max_elapsed_days: list[int] = []

    def cooldown_state_machine(resampled_prices, _config, **kwargs):
        raw_returns = (
            resampled_prices.iloc[:, 0].pct_change(fill_method=None).fillna(0.0)
        )
        strategy_returns: list[float] = []
        cooldown = 0
        cooldown_days = 0
        for raw_return in raw_returns.to_numpy(dtype=float):
            if cooldown > 0:
                strategy_returns.append(0.0)
                cooldown -= 1
                cooldown_days += 1
            else:
                strategy_returns.append(float(raw_return))
                if raw_return <= -0.05:
                    cooldown = 3
        observed_cooldown_days.append(cooldown_days)
        observed_max_elapsed_days.append(
            int(
                pd.Series(resampled_prices.index)
                .diff()
                .dt.days.fillna(0)
                .max()
            )
        )
        observed_economic_inputs.append(
            all(
                kwargs.get(name) is not None
                for name in (
                    "execution_prices",
                    "execution_window_dollar_volume",
                    "corporate_action_split_ratios",
                    "corporate_action_cash_distributions",
                    "borrow_availability",
                    "annual_borrow_rates",
                    "borrow_recalls",
                )
            )
        )
        diagnostics = pd.DataFrame(
            {
                "research_path_valid": True,
                "liquidity_path_valid": True,
            },
            index=resampled_prices.index,
        )
        elapsed_days = diagnostics.index.to_series().diff().dt.days.fillna(0.0)
        diagnostics["carry_day_count_convention"] = "ACT/365.25"
        diagnostics["elapsed_calendar_days"] = elapsed_days
        diagnostics["carry_year_fraction"] = elapsed_days / 365.25
        return SimpleNamespace(
            strategy_returns=pd.Series(
                strategy_returns,
                index=resampled_prices.index,
            ),
            diagnostics=diagnostics,
        )

    monkeypatch.setattr(validation, "run_backtest", cooldown_state_machine)
    config = AppConfig()
    original = cooldown_state_machine(prices, config)
    observed_cooldown_days.clear()
    observed_economic_inputs.clear()
    observed_max_elapsed_days.clear()
    return_only = validation.block_bootstrap_validation(
        original.strategy_returns.iloc[1:],
        n_paths=100,
        horizon_days=63,
        block_size=10,
        target_cagr=0.0,
        max_drawdown=0.50,
    )
    path_aware = validation.path_aware_block_bootstrap_validation(
        prices,
        config,
        prices.index[1:],
        horizon_days=63,
        block_size=10,
        target_cagr=0.0,
        max_drawdown=0.50,
        n_paths=6,
        execution_return_semantics="next_open_to_open",
        execution_prices=prices,
        execution_window_dollar_volume=volume,
        corporate_action_split_ratios=splits,
        corporate_action_cash_distributions=cash,
        borrow_availability=availability,
        annual_borrow_rates=rates,
        borrow_recalls=recalls,
    )

    assert path_aware.state_machine_rerun
    assert path_aware.method_id == validation.PATH_AWARE_BOOTSTRAP_METHOD_ID
    assert len(observed_cooldown_days) == 6
    assert min(observed_cooldown_days) > 0
    assert min(observed_max_elapsed_days) >= 3
    assert all(observed_economic_inputs)
    assert path_aware.median_cagr != pytest.approx(return_only.median_cagr)

    # A poor but correctly identified path-aware distribution is the gated result.
    gated_path = replace(
        path_aware,
        paths=validation.PATH_AWARE_BOOTSTRAP_PATHS,
        horizon_days=756,
        block_size=20,
        warmup_days=validation.PATH_AWARE_BOOTSTRAP_MIN_WARMUP_DAYS,
        sampling_plan_sha256="a" * 64,
        failed_paths=0,
        valid_path_fraction=1.0,
        probability_both_targets_lower_95=0.0,
    )
    _, path_table = validation.certification_table(
        oos_metrics={},
        bootstrap=gated_path,
        double_cost_metrics={},
        rolling_pass_rate=1.0,
        psr_probability=1.0,
        max_gross_limit=2.5,
        target_cagr=0.60,
        max_drawdown=0.15,
        confidence=0.95,
        bootstrap_block_size=20,
    )
    assert bool(
        path_table.loc["Path-aware bootstrap state-machine identity", "Pass"]
    )
    assert not bool(
        path_table.loc[
            "Path-aware bootstrap lower 95% bound for both targets", "Pass"
        ]
    )

    # Even a perfect return-only diagnostic cannot impersonate hard-gate evidence.
    perfect_return_only = replace(
        _bootstrap_summary_with_probability(1.0),
        paths=2_000,
        block_size=20,
    )
    _, return_table = validation.certification_table(
        oos_metrics={},
        bootstrap=perfect_return_only,
        double_cost_metrics={},
        rolling_pass_rate=1.0,
        psr_probability=1.0,
        max_gross_limit=2.5,
        target_cagr=0.60,
        max_drawdown=0.15,
        confidence=0.95,
        bootstrap_block_size=20,
    )
    assert not bool(
        return_table.loc["Path-aware bootstrap state-machine identity", "Pass"]
    )
    assert not bool(
        return_table.loc[
            "Path-aware bootstrap lower 95% bound for both targets", "Pass"
        ]
    )


def test_path_bootstrap_rejects_unregistered_seed() -> None:
    dates = pd.bdate_range("2024-01-02", periods=80)
    prices = pd.DataFrame(100.0, index=dates, columns=list("ABCD"))
    with pytest.raises(ValueError, match="seed is fixed"):
        validation.path_aware_block_bootstrap_validation(
            prices,
            AppConfig(),
            prices.index[1:],
            horizon_days=63,
            block_size=10,
            target_cagr=0.0,
            max_drawdown=0.50,
            n_paths=2,
            seed=1,
        )
