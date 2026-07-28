from __future__ import annotations

import ast
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pandas as pd

import quant_app.validation as validation
from quant_app.config import AppConfig


def _gate_inputs(n_assets: int = 20) -> dict[str, object]:
    dates = pd.bdate_range("2024-01-02", periods=320)
    symbols = [f"G{i:02d}" for i in range(n_assets)]
    prices = pd.DataFrame(
        {
            symbol: 100.0 + np.arange(len(dates), dtype=float) * 0.01 + index
            for index, symbol in enumerate(symbols)
        },
        index=dates,
    )
    return {
        "prices": prices,
        "in_sample_fraction": 0.60,
        "execution_return_semantics": "next_open_to_open",
        "execution_prices": prices.copy(),
        "execution_window_dollar_volume": pd.DataFrame(
            10_000_000.0, index=dates, columns=symbols
        ),
        "corporate_action_split_ratios": pd.DataFrame(
            1.0, index=dates, columns=symbols
        ),
        "corporate_action_cash_distributions": pd.DataFrame(
            0.0, index=dates, columns=symbols
        ),
        "borrow_availability": pd.DataFrame(True, index=dates, columns=symbols),
        "annual_borrow_rates": pd.DataFrame(0.02, index=dates, columns=symbols),
        "borrow_recalls": pd.DataFrame(False, index=dates, columns=symbols),
    }


def _complete_passing_gate_frame(
    config: AppConfig | None = None,
    *,
    n_assets: int = 20,
) -> pd.DataFrame:
    config = config or AppConfig()
    specifications = validation.parameter_perturbation_specifications(config)
    inputs = _gate_inputs(n_assets)
    identities = validation.parameter_perturbation_identity_frame(
        config=config, **inputs
    )
    frame = identities.copy()
    frame["OOS CAGR"] = 0.45
    frame["OOS Sharpe"] = 1.0
    frame["OOS Max Drawdown"] = -0.15
    frame["Max Gross"] = 1.0
    frame["Configured Max Gross"] = [
        specification.config.portfolio.max_gross_leverage
        for specification in specifications
    ]
    frame["Research Path Valid"] = True
    frame["Liquidity Path Valid"] = True
    for column in (
        "Liquidity Data Breaches",
        "Participation Limit Breaches",
        "Data Integrity Breaches",
        "Beta Data Breaches",
        "Hard Drawdown Breaches",
        "Stale Signal Trade Breaches",
    ):
        frame[column] = 0
    frame["Minimum Eligible Asset Count"] = frame["Input Asset Count"]
    frame["Base Minimum Eligible Asset Count"] = n_assets
    frame["Effective Eligible Retention Fraction"] = (
        frame["Minimum Eligible Asset Count"] / n_assets
    )
    return frame


def _evaluate_complete_gate(
    frame: pd.DataFrame,
    config: AppConfig | None = None,
    *,
    max_drawdown: float = 0.15,
    target_cagr: float = 0.60,
    n_assets: int = 20,
):
    config = config or AppConfig()
    return validation.parameter_perturbation_gate(
        frame,
        config,
        max_drawdown=max_drawdown,
        target_cagr=target_cagr,
        **_gate_inputs(n_assets),
    )


def test_perturbation_family_is_fixed_material_and_crossed() -> None:
    specifications = validation.parameter_perturbation_specifications(AppConfig())

    assert len(specifications) == validation.PARAMETER_PERTURBATION_VARIANT_COUNT == 25
    assert len({item.name for item in specifications}) == 25
    dimensions = {dimension for item in specifications for dimension in item.dimensions}
    assert {
        "alpha",
        "risk",
        "cost",
        "liquidity",
        "timing",
        "universe",
        "regime",
        "borrow",
    }.issubset(dimensions)
    assert sum(len(item.dimensions) >= 3 for item in specifications) >= 8
    assert sorted(
        item.omitted_universe_cohort
        for item in specifications
        if item.omitted_universe_cohort is not None
    ) == list(range(5))
    assert sum(item.borrow_scarcity_cohort is not None for item in specifications) == 1
    assert sum(item.borrow_recall_cohort is not None for item in specifications) == 1
    mandatory_dimensions = {
        dimension
        for item in specifications
        if item.mandatory_critical_case
        for dimension in item.dimensions
    }
    assert set(validation.PERTURBATION_CRITICAL_STRATUM_MIN_PASS_RATE).issubset(
        mandatory_dimensions
    )
    assert min(item.volume_multiplier for item in specifications) <= 0.50
    assert max(item.borrow_rate_multiplier for item in specifications) >= 3.0
    minimum_certified_universe = pd.Index([f"M{i:02d}" for i in range(20)])
    omitted_at_minimum = []
    for cohort in range(5):
        retained = validation._perturbation_universe(
            minimum_certified_universe, cohort
        )
        assert len(retained) == 16
        omitted_at_minimum.extend(
            set(minimum_certified_universe).difference(retained)
        )
    assert set(omitted_at_minimum) == set(minimum_certified_universe)
    assert len(omitted_at_minimum) == 20
    non_divisible_universe = pd.Index([f"N{i:02d}" for i in range(21)])
    retained_cohort_zero = validation._perturbation_universe(
        non_divisible_universe, 0
    )
    retained_cohort_one = validation._perturbation_universe(
        non_divisible_universe, 1
    )
    assert len(retained_cohort_zero) == len(retained_cohort_one) == 17
    assert set(non_divisible_universe).difference(retained_cohort_zero).isdisjoint(
        set(non_divisible_universe).difference(retained_cohort_one)
    )
    preregistration = validation.parameter_perturbation_preregistration(AppConfig())
    assert preregistration["variant_count"] == 25
    assert preregistration["minimum_passing_variants"] == 20
    assert preregistration["policy"]["minimum_project_target_cagr"] == 0.60
    assert preregistration["policy"]["minimum_cagr_target_retention"] == 0.75
    assert preregistration["policy"]["minimum_sharpe"] == 1.0
    assert preregistration["policy"]["maximum_project_drawdown"] == 0.15
    assert preregistration["policy"]["critical_stratum_minimum_pass_rates"] == (
        validation.PERTURBATION_CRITICAL_STRATUM_MIN_PASS_RATE
    )
    assert len(
        preregistration["policy"]["mandatory_critical_variant_ordinals"]
    ) >= 7
    base_hash = validation.parameter_perturbation_specification_hash(AppConfig())
    changed_config = replace(
        AppConfig(),
        portfolio=replace(AppConfig().portfolio, target_volatility=0.08),
    )
    assert len(base_hash) == 64
    assert validation.parameter_perturbation_specification_hash(changed_config) != base_hash


def test_perturbations_stress_consumed_panels_and_universe(
    monkeypatch,
) -> None:
    dates = pd.bdate_range("2024-01-02", periods=320)
    symbols = [f"S{i:02d}" for i in range(25)]
    prices = pd.DataFrame(100.0, index=dates, columns=symbols)
    volume = pd.DataFrame(10_000_000.0, index=dates, columns=symbols)
    availability = pd.DataFrame(True, index=dates, columns=symbols)
    rates = pd.DataFrame(0.02, index=dates, columns=symbols)
    recalls = pd.DataFrame(False, index=dates, columns=symbols)
    calls: list[dict[str, object]] = []

    def fake_backtest(
        frame,
        variant_config,
        *,
        execution_return_semantics=None,
        execution_prices=None,
        execution_window_dollar_volume=None,
        corporate_action_split_ratios=None,
        corporate_action_cash_distributions=None,
        borrow_availability=None,
        annual_borrow_rates=None,
        borrow_recalls=None,
        borrow_rate_stress_multiplier=1.0,
    ):
        calls.append(
            {
                "columns": tuple(frame.columns),
                "volume": execution_window_dollar_volume,
                "borrow_multiplier": borrow_rate_stress_multiplier,
                "availability": borrow_availability.copy(),
                "recalls": borrow_recalls.copy(),
                "rebalance_every": variant_config.portfolio.rebalance_every,
            }
        )
        diagnostics = pd.DataFrame(index=frame.index)
        diagnostics.attrs["asset_count"] = len(frame.columns)
        return SimpleNamespace(
            strategy_returns=pd.Series(0.001, index=frame.index),
            diagnostics=diagnostics,
        )

    monkeypatch.setattr(validation, "run_backtest", fake_backtest)

    def fake_metrics(_returns, diagnostics, **_kwargs):
        asset_count = diagnostics.attrs["asset_count"]
        return {
            "CAGR": 0.60,
            "Max Drawdown": -0.10,
            "Sharpe Ratio": 1.5,
            "Calmar Ratio": 6.0,
            "Maximum Gross Exposure": 1.0,
            "Research Path Valid": True,
            "Liquidity Path Valid": True,
            "Liquidity Data Breaches": 0,
            "Participation Limit Breaches": 0,
            "Data Integrity Breaches": 0,
            "Beta Data Breaches": 0,
            "Hard Drawdown Breaches": 0,
            "Stale Signal Trade Breaches": 0,
            "Minimum Eligible Asset Count": asset_count,
        }

    monkeypatch.setattr(
        validation,
        "metrics_from_returns",
        fake_metrics,
    )

    result = validation.run_parameter_perturbations(
        prices,
        AppConfig(),
        0.60,
        execution_return_semantics="next_open_to_open",
        execution_prices=prices,
        execution_window_dollar_volume=volume,
        corporate_action_split_ratios=pd.DataFrame(
            1.0, index=dates, columns=symbols
        ),
        corporate_action_cash_distributions=pd.DataFrame(
            0.0, index=dates, columns=symbols
        ),
        borrow_availability=availability,
        annual_borrow_rates=rates,
        borrow_recalls=recalls,
    )

    assert len(result) == len(calls) == 25
    assert (result["Execution Volume Multiplier"] < 1.0).sum() >= 6
    assert (result["Borrow Rate Multiplier"] > 1.0).sum() >= 10
    assert (result["Input Asset Count"] < len(symbols)).sum() == 5
    assert result["Perturbation Family ID"].eq(
        validation.PARAMETER_PERTURBATION_FAMILY_ID
    ).all()
    assert result["Perturbation Specification SHA256"].nunique() == 1
    for identity_column in (
        "Variant Specification SHA256",
        "Variant Config SHA256",
        "Variant Symbols SHA256",
        "Borrow Availability Panel SHA256",
        "Borrow Recall Panel SHA256",
        "Variant Economic Inputs SHA256",
        "Variant Input Identity SHA256",
    ):
        assert result[identity_column].map(len).eq(64).all()
    assert result["Preregistered Variant Ordinal"].tolist() == list(range(1, 26))
    assert min(len(call["columns"]) for call in calls) < len(symbols)
    stressed_volume = [
        call["volume"]
        for call in calls
        if float(call["borrow_multiplier"]) >= 2.0
        and float(call["volume"].iloc[0, 0]) < 10_000_000.0
    ]
    assert stressed_volume
    scarcity_calls = [
        call for call in calls if not call["availability"].to_numpy().all()
    ]
    recall_calls = [call for call in calls if call["recalls"].to_numpy().any()]
    assert scarcity_calls
    assert len(recall_calls) == 1
    recall_mask = recall_calls[0]["recalls"].astype(bool)
    assert not recall_calls[0]["availability"].where(recall_mask).stack().any()
    assert sum(int(call["rebalance_every"]) > 1 for call in calls) >= 5
    assert availability.to_numpy().all()
    assert not recalls.to_numpy().any()
    gate_passed, pass_rate, mask = validation.parameter_perturbation_gate(
        result,
        AppConfig(),
        max_drawdown=0.15,
        prices=prices,
        in_sample_fraction=0.60,
        target_cagr=0.60,
        execution_return_semantics="next_open_to_open",
        execution_prices=prices,
        execution_window_dollar_volume=volume,
        corporate_action_split_ratios=pd.DataFrame(
            1.0, index=dates, columns=symbols
        ),
        corporate_action_cash_distributions=pd.DataFrame(
            0.0, index=dates, columns=symbols
        ),
        borrow_availability=availability,
        annual_borrow_rates=rates,
        borrow_recalls=recalls,
    )
    assert gate_passed is True
    assert pass_rate == 1.0
    assert mask.all()


def test_parameter_gate_keeps_fixed_profit_drawdown_and_path_requirements() -> None:
    frame = pd.DataFrame(
        {
            "OOS CAGR": [0.45, 0.449, 0.60, 0.60],
            "OOS Sharpe": [1.0, 2.0, 0.999, 2.0],
            "OOS Max Drawdown": [-0.15, -0.10, -0.10, -0.151],
            "Max Gross": [1.0, 1.0, 1.0, 1.0],
            "Configured Max Gross": [2.5, 2.5, 2.5, 2.5],
            "Research Path Valid": [True, True, True, True],
            "Liquidity Path Valid": [True, True, True, True],
            "Liquidity Data Breaches": [0, 0, 0, 0],
            "Participation Limit Breaches": [0, 0, 0, 0],
            "Data Integrity Breaches": [0, 0, 0, 0],
            "Beta Data Breaches": [0, 0, 0, 0],
            "Hard Drawdown Breaches": [0, 0, 0, 0],
            "Stale Signal Trade Breaches": [0, 0, 0, 0],
            "Input Asset Count": [20, 20, 20, 20],
            "Base Input Asset Count": [20, 20, 20, 20],
            "Universe Retention Fraction": [1.0, 1.0, 1.0, 1.0],
            "Minimum Eligible Asset Count": [20, 20, 20, 20],
            "Base Minimum Eligible Asset Count": [20, 20, 20, 20],
            "Effective Eligible Retention Fraction": [1.0, 1.0, 1.0, 1.0],
        },
        index=["boundary_pass", "cagr_fail", "sharpe_fail", "drawdown_fail"],
    )

    mask = validation.parameter_perturbation_pass_mask(
        frame,
        max_drawdown=0.15,
        target_cagr=0.60,
    )

    assert mask.to_dict() == {
        "boundary_pass": True,
        "cagr_fail": False,
        "sharpe_fail": False,
        "drawdown_fail": False,
    }

    minimum_breadth_stress = frame.iloc[[0]].copy()
    minimum_breadth_stress["Input Asset Count"] = 16
    minimum_breadth_stress["Base Input Asset Count"] = 20
    minimum_breadth_stress["Universe Retention Fraction"] = 0.80
    minimum_breadth_stress["Minimum Eligible Asset Count"] = 16
    minimum_breadth_stress["Base Minimum Eligible Asset Count"] = 20
    minimum_breadth_stress["Effective Eligible Retention Fraction"] = 0.80
    assert validation.parameter_perturbation_pass_mask(
        minimum_breadth_stress,
        max_drawdown=0.15,
    ).all()

    # Neither a looser UI selection nor inconsistent reported fractions may dilute
    # the fixed 15% path limit or the exact 80% effective-breadth requirement.
    assert not bool(
        validation.parameter_perturbation_pass_mask(
            frame.loc[["drawdown_fail"]],
            max_drawdown=0.30,
        ).iloc[0]
    )
    inconsistent_breadth = minimum_breadth_stress.copy()
    inconsistent_breadth["Minimum Eligible Asset Count"] = 15
    assert not validation.parameter_perturbation_pass_mask(
        inconsistent_breadth,
        max_drawdown=0.15,
    ).any()
    impossible_breadth = frame.loc[["boundary_pass"]].copy()
    impossible_breadth["Minimum Eligible Asset Count"] = 21
    impossible_breadth["Effective Eligible Retention Fraction"] = 1.05
    assert not validation.parameter_perturbation_pass_mask(
        impossible_breadth,
        max_drawdown=0.15,
    ).any()
    for breach_column in (
        "Hard Drawdown Breaches",
        "Stale Signal Trade Breaches",
    ):
        breached = frame.loc[["boundary_pass"]].copy()
        breached[breach_column] = 1
        assert not validation.parameter_perturbation_pass_mask(
            breached,
            max_drawdown=0.15,
        ).any()
    excessive_gross = frame.loc[["boundary_pass"]].copy()
    excessive_gross["Max Gross"] = 2.50000002
    assert not validation.parameter_perturbation_pass_mask(
        excessive_gross,
        max_drawdown=0.15,
    ).any()


def test_complete_suite_gate_requires_exact_identity_and_twenty_of_twenty_five() -> None:
    config = AppConfig()
    exactly_twenty = _complete_passing_gate_frame(config)
    # These are the five alpha/risk-only non-mandatory cases.  Aggregate 20/25
    # remains sufficient only when every protected critical stratum also passes.
    exactly_twenty.loc[exactly_twenty.index[1:6], "OOS Sharpe"] = 0.99

    passed, rate, mask = _evaluate_complete_gate(exactly_twenty, config)
    assert passed is True
    assert rate == 0.80
    assert int(mask.sum()) == 20

    nineteen = exactly_twenty.copy()
    nineteen.loc[nineteen.index[6], "OOS CAGR"] = 0.449
    passed, rate, _ = _evaluate_complete_gate(nineteen, config)
    assert passed is False
    assert rate == 19 / 25

    # Twenty favorable cached rows cannot masquerade as 100% of the suite, and an
    # otherwise complete result carrying an older suite digest also fails closed.
    partial = _complete_passing_gate_frame(config).iloc[:20]
    passed, rate, mask = _evaluate_complete_gate(partial, config)
    assert passed is False
    assert pd.isna(rate)
    assert not mask.any()

    stale = _complete_passing_gate_frame(config)
    stale["Perturbation Specification SHA256"] = "0" * 64
    passed, rate, mask = _evaluate_complete_gate(stale, config)
    assert passed is False
    assert pd.isna(rate)
    assert not mask.any()


def test_gate_does_not_let_aggregate_pass_rate_hide_mandatory_failure() -> None:
    frame = _complete_passing_gate_frame()
    specifications = validation.parameter_perturbation_specifications(AppConfig())
    strongest_cost = next(
        item
        for item in specifications
        if item.mandatory_critical_case
        and item.borrow_rate_multiplier == 3.0
    )
    frame.loc[strongest_cost.name, "OOS Sharpe"] = 0.99

    passed, rate, mask = _evaluate_complete_gate(frame)

    assert rate == 24 / 25
    assert int(mask.sum()) == 24
    assert not bool(mask.loc[strongest_cost.name])
    assert passed is False


def test_gate_does_not_let_aggregate_pass_rate_hide_stratum_failure() -> None:
    frame = _complete_passing_gate_frame()
    specifications = validation.parameter_perturbation_specifications(AppConfig())
    nonmandatory_universe = next(
        item
        for item in specifications
        if "universe" in item.dimensions and not item.mandatory_critical_case
    )
    frame.loc[nonmandatory_universe.name, "OOS CAGR"] = 0.449

    passed, rate, mask = _evaluate_complete_gate(frame)

    assert rate == 24 / 25
    assert int(mask.sum()) == 24
    assert not bool(mask.loc[nonmandatory_universe.name])
    assert passed is False


def test_gate_rejects_tampered_variant_and_input_identities() -> None:
    for identity_column in (
        "Variant Config SHA256",
        "Variant Symbols SHA256",
        "Execution Window Volume SHA256",
        "Borrow Availability Panel SHA256",
        "Variant Economic Inputs SHA256",
        "Variant Input Identity SHA256",
    ):
        frame = _complete_passing_gate_frame()
        frame.loc[frame.index[0], identity_column] = "0" * 64

        passed, rate, mask = _evaluate_complete_gate(frame)

        assert passed is False, identity_column
        assert pd.isna(rate), identity_column
        assert not mask.any(), identity_column


def test_gate_recomputes_identity_from_exact_supplied_panels() -> None:
    frame = _complete_passing_gate_frame()
    inputs = _gate_inputs()
    volume = inputs["execution_window_dollar_volume"].copy()
    volume.iloc[0, 0] += 1.0
    inputs["execution_window_dollar_volume"] = volume

    passed, rate, mask = validation.parameter_perturbation_gate(
        frame,
        AppConfig(),
        max_drawdown=0.15,
        target_cagr=0.60,
        **inputs,
    )

    assert passed is False
    assert pd.isna(rate)
    assert not mask.any()


def test_gate_rejects_diluted_base_eligible_breadth_denominator() -> None:
    frame = _complete_passing_gate_frame(n_assets=25)
    frame["Base Minimum Eligible Asset Count"] = 20
    frame["Effective Eligible Retention Fraction"] = (
        frame["Minimum Eligible Asset Count"] / 20
    )

    passed, rate, mask = _evaluate_complete_gate(frame, n_assets=25)

    assert passed is False
    assert pd.isna(rate)
    assert not mask.any()


def test_actual_borrow_stress_requires_complete_point_in_time_panels() -> None:
    inputs = _gate_inputs()
    inputs["borrow_recalls"] = None

    try:
        validation.parameter_perturbation_identity_frame(
            config=AppConfig(),
            **inputs,
        )
    except ValueError as error:
        assert "complete point-in-time borrow panels" in str(error)
    else:
        raise AssertionError("Missing recall evidence must fail closed.")


def test_app_binds_exact_suite_and_software_identities_into_cached_run() -> None:
    tree = ast.parse((Path(__file__).parents[1] / "app.py").read_text(encoding="utf-8"))
    cached_function = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "cached_perturbations"
    )
    argument_names = {argument.arg for argument in cached_function.args.args}
    assert {
        "perturbation_family_id",
        "perturbation_specification_sha256",
        "research_software_sha256",
    }.issubset(argument_names)

    cached_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "cached_perturbations"
    ]
    assert len(cached_calls) == 1
    passed_names = {
        argument.id
        for argument in cached_calls[0].args
        if isinstance(argument, ast.Name)
    }
    assert {
        "perturbation_specification_sha256",
        "research_software_hash",
    }.issubset(passed_names)

    base_cache_function = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "cached_backtest"
    )
    base_cache_argument_names = {
        argument.arg for argument in base_cache_function.args.args
    }
    assert "research_software_sha256" in base_cache_argument_names
    assert not "research_software_sha256".startswith("_")

    base_cache_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "cached_backtest"
    ]
    assert len(base_cache_calls) == 2
    for call in base_cache_calls:
        positional_names = {
            argument.id for argument in call.args if isinstance(argument, ast.Name)
        }
        keyword_names = {
            keyword.value.id
            for keyword in call.keywords
            if isinstance(keyword.value, ast.Name)
        }
        assert "research_software_hash" in positional_names | keyword_names

    literal_strings = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert "parameter_perturbation_specification_sha256" in literal_strings
    assert "parameter_perturbation_minimum_pass_rate" in literal_strings
