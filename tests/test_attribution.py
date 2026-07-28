from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from quant_app.attribution import factor_regression


def test_factor_regression_recovers_alpha_and_beta() -> None:
    rng = np.random.default_rng(42)
    rows = 1_500
    index = pd.bdate_range("2018-01-01", periods=rows)
    market = rng.normal(0.0002, 0.01, rows)
    noise = rng.normal(0.0, 0.003, rows)
    strategy = 0.00035 + 0.40 * market + noise
    result = factor_regression(
        pd.Series(strategy, index=index),
        pd.DataFrame({"market": market}, index=index),
    )
    assert result.annualized_alpha == pytest.approx(0.00035 * 252, abs=0.03)
    assert result.factor_betas["market"] == pytest.approx(0.40, abs=0.04)
    assert result.alpha_tstat_hac > 2.0
    assert result.observations == rows


def test_factor_regression_rejects_insufficient_history() -> None:
    index = pd.bdate_range("2025-01-01", periods=30)
    with pytest.raises(ValueError, match="60 aligned"):
        factor_regression(
            pd.Series(0.0, index=index),
            pd.DataFrame({"market": 0.0}, index=index),
        )


def test_factor_regression_rejects_constant_or_collinear_factors() -> None:
    rng = np.random.default_rng(7)
    index = pd.bdate_range("2020-01-01", periods=300)
    market = rng.normal(0.0, 0.01, len(index))
    strategy = pd.Series(rng.normal(0.0, 0.005, len(index)), index=index)

    with pytest.raises(ValueError, match="nonzero finite variation"):
        factor_regression(
            strategy,
            pd.DataFrame({"market": market, "constant": 0.0}, index=index),
        )

    with pytest.raises(ValueError, match="rank deficient"):
        factor_regression(
            strategy,
            pd.DataFrame(
                {"market": market, "duplicated_market": market * 2.0},
                index=index,
            ),
        )


def test_factor_regression_rejects_reserved_or_duplicate_names() -> None:
    rng = np.random.default_rng(9)
    index = pd.bdate_range("2020-01-01", periods=300)
    strategy = pd.Series(rng.normal(0.0, 0.005, len(index)), index=index)
    factors = pd.DataFrame(
        rng.normal(0.0, 0.01, (len(index), 2)),
        index=index,
        columns=["market", "market"],
    )
    with pytest.raises(ValueError, match="Factor names must be unique"):
        factor_regression(strategy, factors)

    with pytest.raises(ValueError, match="must not be 'strategy'"):
        factor_regression(
            strategy,
            pd.DataFrame({"strategy": rng.normal(0.0, 0.01, len(index))}, index=index),
        )
