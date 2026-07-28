from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

from .config import RegimeConfig, SignalConfig

TRADING_DAYS = 252


@dataclass(frozen=True)
class SignalBundle:
    composite: pd.DataFrame
    components: dict[str, pd.DataFrame]
    beta: pd.DataFrame
    asset_volatility: pd.DataFrame
    information_coefficient: pd.Series
    ic_tstat: pd.Series
    market_volatility: pd.Series
    signal_dispersion: pd.Series
    regime: pd.Series
    regime_multiplier: pd.Series


def cross_sectional_zscore(frame: pd.DataFrame, clip: float = 3.0) -> pd.DataFrame:
    """Standardize each row without borrowing information from another date."""
    row_mean = frame.mean(axis=1)
    row_std = frame.std(axis=1, ddof=0).replace(0.0, np.nan)
    z = frame.sub(row_mean, axis=0).div(row_std, axis=0)
    return z.clip(lower=-clip, upper=clip)


def rolling_market_beta(returns: pd.DataFrame, lookback: int) -> pd.DataFrame:
    market = returns.mean(axis=1, skipna=True)
    market_var = market.rolling(lookback, min_periods=max(20, lookback // 3)).var()
    beta = pd.DataFrame(index=returns.index, columns=returns.columns, dtype=float)
    for column in returns.columns:
        covariance = returns[column].rolling(
            lookback, min_periods=max(20, lookback // 3)
        ).cov(market)
        beta[column] = covariance.div(market_var.replace(0.0, np.nan))
    return beta.clip(lower=-3.0, upper=3.0)


def _rolling_ic_tstat(ic: pd.Series, window: int) -> pd.Series:
    min_periods = max(20, window // 3)
    mean = ic.rolling(window, min_periods=min_periods).mean()
    std = ic.rolling(window, min_periods=min_periods).std(ddof=1)
    count = ic.rolling(window, min_periods=min_periods).count()
    standard_error = std.div(np.sqrt(count)).replace(0.0, np.nan)
    return mean.div(standard_error)


def build_signal_bundle(
    prices: pd.DataFrame,
    signal_config: SignalConfig,
    regime_config: RegimeConfig,
) -> SignalBundle:
    """Build causal, close-to-next-close signals and signal-health diagnostics."""
    # Missing-price policy belongs to the caller. This function never fills a close;
    # doing so could manufacture both marks and cross-sectional ranks.
    prices = prices.sort_index()
    returns = prices.pct_change(fill_method=None)
    market_returns = returns.mean(axis=1, skipna=True)

    beta = rolling_market_beta(returns, signal_config.beta_lookback)
    # Beta available at t-1 is used to decompose return t.
    residual_returns = returns - beta.shift(1).mul(market_returns, axis=0)

    raw_components = {
        "reversal_3": -prices.pct_change(3, fill_method=None),
        "reversal_10": -prices.pct_change(10, fill_method=None),
        "residual_reversal": -residual_returns.rolling(5, min_periods=3).sum(),
        # Momentum excludes the most recent observations to reduce overlap with reversal.
        "momentum_63": prices.shift(5).div(prices.shift(63)).sub(1.0),
        "momentum_126": prices.shift(21).div(prices.shift(126)).sub(1.0),
    }

    components = {
        name: cross_sectional_zscore(frame, clip=signal_config.signal_clip)
        for name, frame in raw_components.items()
    }
    weights = {
        "reversal_3": signal_config.reversal_3_weight,
        "reversal_10": signal_config.reversal_10_weight,
        "residual_reversal": signal_config.residual_reversal_weight,
        "momentum_63": signal_config.momentum_63_weight,
        "momentum_126": signal_config.momentum_126_weight,
    }
    denominator = sum(abs(value) for value in weights.values())
    if denominator <= 0:
        raise ValueError("At least one signal weight must be non-zero.")

    composite = sum(components[name] * weight for name, weight in weights.items()) / denominator
    composite = cross_sectional_zscore(composite, clip=signal_config.signal_clip)

    asset_volatility = (
        returns.rolling(signal_config.vol_lookback, min_periods=max(10, signal_config.vol_lookback // 2))
        .std(ddof=1)
        .mul(np.sqrt(TRADING_DAYS))
        .clip(lower=0.03, upper=3.0)
    )

    # Signal at close t-1 is evaluated against close-to-close return t.
    information_coefficient = composite.shift(1).corrwith(returns, axis=1)
    ic_tstat = _rolling_ic_tstat(information_coefficient, regime_config.ic_window)

    market_volatility = (
        market_returns.rolling(20, min_periods=10).std(ddof=1).mul(np.sqrt(TRADING_DAYS))
    )
    stress_threshold = market_volatility.rolling(252, min_periods=60).quantile(
        regime_config.volatility_stress_percentile
    )
    signal_dispersion = composite.std(axis=1, ddof=0)

    regime = pd.Series("warmup", index=prices.index, dtype="object")
    ready = ic_tstat.notna() & composite.notna().sum(axis=1).ge(4)
    volatility_stress = ready & stress_threshold.notna() & market_volatility.gt(stress_threshold)
    low_dispersion = ready & signal_dispersion.lt(regime_config.minimum_cross_sectional_dispersion)

    normal_conditions = ready & ~volatility_stress & ~low_dispersion
    regime.loc[
        normal_conditions & ic_tstat.ge(regime_config.favorable_ic_tstat)
    ] = "favorable"
    regime.loc[
        normal_conditions
        & ic_tstat.ge(regime_config.neutral_ic_tstat)
        & ic_tstat.lt(regime_config.favorable_ic_tstat)
    ] = "neutral"
    regime.loc[
        normal_conditions
        & ic_tstat.ge(regime_config.invalid_ic_tstat)
        & ic_tstat.lt(regime_config.neutral_ic_tstat)
    ] = "degraded"
    regime.loc[
        ready
        & (
            volatility_stress
            | low_dispersion
            | ic_tstat.lt(regime_config.invalid_ic_tstat)
        )
    ] = "invalid"

    multiplier_map = {
        "warmup": 0.0,
        "favorable": regime_config.favorable_multiplier,
        "neutral": regime_config.neutral_multiplier,
        "degraded": regime_config.degraded_multiplier,
        "invalid": regime_config.invalid_multiplier,
    }
    regime_multiplier = regime.map(multiplier_map).astype(float)

    return SignalBundle(
        composite=composite,
        components=components,
        beta=beta,
        asset_volatility=asset_volatility,
        information_coefficient=information_coefficient,
        ic_tstat=ic_tstat,
        market_volatility=market_volatility,
        signal_dispersion=signal_dispersion,
        regime=regime,
        regime_multiplier=regime_multiplier,
    )
