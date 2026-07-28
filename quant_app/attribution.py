from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd

TRADING_DAYS = 252


@dataclass(frozen=True)
class FactorRegressionResult:
    observations: int
    annualized_alpha: float
    alpha_tstat_hac: float
    r_squared: float
    residual_annualized_volatility: float
    factor_betas: dict[str, float]
    hac_lags: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "observations": self.observations,
            "annualized_alpha": self.annualized_alpha,
            "alpha_tstat_hac": self.alpha_tstat_hac,
            "r_squared": self.r_squared,
            "residual_annualized_volatility": self.residual_annualized_volatility,
            "factor_betas": dict(self.factor_betas),
            "hac_lags": self.hac_lags,
        }


def factor_regression(
    strategy_returns: pd.Series,
    factor_returns: pd.DataFrame,
    *,
    hac_lags: int | None = None,
) -> FactorRegressionResult:
    """Estimate factor-adjusted alpha with Newey-West standard errors.

    This is an attribution diagnostic, not proof that alpha will persist. Factors must
    themselves be point-in-time and aligned to the same executable return interval as
    the strategy.
    """
    if factor_returns.empty:
        raise ValueError("At least one factor return series is required.")
    if factor_returns.shape[1] > 20:
        raise ValueError("Attribution is limited to 20 pre-specified factors.")
    factor_names = [str(column) for column in factor_returns.columns]
    if len(set(factor_names)) != len(factor_names) or "strategy" in factor_names:
        raise ValueError("Factor names must be unique and must not be 'strategy'.")
    aligned = pd.concat(
        [strategy_returns.rename("strategy"), factor_returns.astype(float)],
        axis=1,
        join="inner",
    ).replace([np.inf, -np.inf], np.nan).dropna()
    minimum_observations = max(60, 10 * (factor_returns.shape[1] + 1))
    if len(aligned) < minimum_observations:
        raise ValueError(
            f"At least {minimum_observations} aligned observations are required "
            "for the requested factor design."
        )

    y = aligned.pop("strategy").to_numpy(dtype=float)
    factors = aligned.to_numpy(dtype=float)
    factor_std = np.std(factors, axis=0, ddof=1)
    degenerate = [
        factor_names[index]
        for index, value in enumerate(factor_std)
        if not np.isfinite(value) or value <= 1e-12
    ]
    if degenerate:
        raise ValueError(
            "Factor return series must have nonzero finite variation: "
            + ", ".join(degenerate)
        )
    standardized = (factors - np.mean(factors, axis=0)) / factor_std
    if np.linalg.matrix_rank(standardized) < standardized.shape[1]:
        raise ValueError("Factor design is rank deficient; remove collinear factors.")
    condition_number = float(np.linalg.cond(standardized))
    if not np.isfinite(condition_number) or condition_number > 1e8:
        raise ValueError(
            "Factor design is numerically ill-conditioned; attribution is not identifiable."
        )

    x = np.column_stack([np.ones(len(aligned)), factors])
    try:
        xtx_inverse = np.linalg.inv(x.T @ x)
    except np.linalg.LinAlgError as exc:
        raise ValueError(
            "Factor design could not be inverted; attribution is not identifiable."
        ) from exc
    coefficients = xtx_inverse @ x.T @ y
    fitted = x @ coefficients
    residuals = y - fitted

    if hac_lags is None:
        hac_lags = min(max(int(np.floor(4.0 * (len(y) / 100.0) ** (2.0 / 9.0))), 1), 20)
    if not isinstance(hac_lags, (int, np.integer)) or hac_lags < 0 or hac_lags >= len(y):
        raise ValueError("hac_lags must be an integer between zero and observations - 1.")

    scores = x * residuals[:, None]
    meat = scores.T @ scores
    for lag in range(1, int(hac_lags) + 1):
        weight = 1.0 - lag / (hac_lags + 1.0)
        cross = scores[lag:].T @ scores[:-lag]
        meat += weight * (cross + cross.T)
    # Finite-sample degrees-of-freedom correction is conservative relative to the
    # raw sandwich covariance and matters for modest sealed holdouts.
    covariance = (
        xtx_inverse
        @ meat
        @ xtx_inverse
        * (len(y) / max(len(y) - x.shape[1], 1))
    )
    alpha_se = float(np.sqrt(max(covariance[0, 0], 0.0)))
    alpha_tstat = float(coefficients[0] / alpha_se) if alpha_se > 0.0 else float("nan")

    total_sum_squares = float(np.square(y - y.mean()).sum())
    residual_sum_squares = float(np.square(residuals).sum())
    r_squared = (
        1.0 - residual_sum_squares / total_sum_squares
        if total_sum_squares > 0.0
        else float("nan")
    )
    residual_volatility = (
        float(np.std(residuals, ddof=x.shape[1]) * np.sqrt(TRADING_DAYS))
        if len(residuals) > x.shape[1]
        else float("nan")
    )
    return FactorRegressionResult(
        observations=len(aligned),
        annualized_alpha=float(coefficients[0] * TRADING_DAYS),
        alpha_tstat_hac=alpha_tstat,
        r_squared=float(r_squared),
        residual_annualized_volatility=residual_volatility,
        factor_betas={name: float(value) for name, value in zip(factor_names, coefficients[1:])},
        hac_lags=int(hac_lags),
    )
