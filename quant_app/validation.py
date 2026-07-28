from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import inspect
import json
from statistics import NormalDist
from typing import Any

import numpy as np
import pandas as pd

from .backtest import (
    CARRY_DAY_COUNT_CONVENTION,
    BacktestResult,
    ExecutionReturnSemantics,
    run_backtest,
)
from .config import AppConfig
from .metrics import metrics_from_returns

TRADING_DAYS = 252
STANDARD_NORMAL = NormalDist()
EULER_MASCHERONI = 0.5772156649015329
PARAMETER_PERTURBATION_VARIANT_COUNT = 25
PARAMETER_PERTURBATION_FAMILY_ID = "crossed_robustness_v3_25"

# These are conservative anti-knob floors for a generic, uncalibrated sealed run. A
# strategy-specific execution study may justify stricter assumptions, but the generic
# certification path must not be made easier by selecting a two-day ADV window,
# near-zero impact coefficient/volatility, or an institutionally implausible capacity
# share. They are certification policy, not assertions about achievable live fills.
MAX_CERTIFIED_PARTICIPATION_RATE = 0.01
MIN_CERTIFIED_ADV_LOOKBACK_DAYS = 20
MIN_CERTIFIED_IMPACT_COEFFICIENT = 0.50
MIN_CERTIFIED_IMPACT_VOLATILITY_FLOOR = 0.005
MIN_CERTIFIED_DAILY_OBSERVATION_RATE = 248.0
MAX_CERTIFIED_DAILY_OBSERVATION_RATE = 255.0
MIN_PROJECT_TARGET_CAGR = 0.60
MAX_PROJECT_TARGET_DRAWDOWN = 0.15
MIN_CERTIFIED_ELIGIBLE_ASSET_COUNT = 20
MIN_CERTIFIED_LINEAR_TRANSACTION_COST_BPS = 1.0
MIN_CERTIFIED_ANNUAL_SHORT_BORROW_RATE = 0.01
MIN_CERTIFIED_ANNUAL_FINANCING_RATE = 0.01
MIN_CERTIFIED_BOOTSTRAP_BLOCK_SIZE = 20
MIN_PERTURBATION_CAGR_TARGET_RETENTION = 0.75
MIN_PERTURBATION_SHARPE = 1.00
MIN_PERTURBATION_UNIVERSE_RETENTION = 0.80
MIN_PERTURBATION_PASS_RATE = 0.80
PERTURBATION_CRITICAL_STRATUM_MIN_PASS_RATE = {
    "cost": 0.75,
    "liquidity": 0.75,
    "timing": 0.75,
    "borrow": 0.80,
    # Five deterministic omission cohorts are deliberately exhaustive at the
    # minimum certifiable 20-name breadth. A failure in any one cohort is evidence
    # of hidden name dependence and cannot be diluted by unrelated alpha variants.
    "universe": 1.00,
}
RETURN_ONLY_BOOTSTRAP_METHOD_ID = "return_only_moving_block_diagnostic_v1"
PATH_AWARE_BOOTSTRAP_METHOD_ID = "aligned_input_block_state_machine_v1"
PATH_AWARE_BOOTSTRAP_SEED = 20_260_713
PATH_AWARE_BOOTSTRAP_PATHS = 100
PATH_AWARE_BOOTSTRAP_MIN_WARMUP_DAYS = 254
PATH_AWARE_BOOTSTRAP_POLICY_SHA256 = hashlib.sha256(
    json.dumps(
        {
            "method_id": PATH_AWARE_BOOTSTRAP_METHOD_ID,
            "seed": PATH_AWARE_BOOTSTRAP_SEED,
            "paths": PATH_AWARE_BOOTSTRAP_PATHS,
            "minimum_warmup_days": PATH_AWARE_BOOTSTRAP_MIN_WARMUP_DAYS,
            "block_size_source": "signed_run_specification",
            "resampling_unit": "aligned_market_and_economic_input_interval",
            "state_machine_reset": "once_per_path_before_resampled_warmup",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
).hexdigest()


def sealed_daily_observation_rate_is_valid(value: float) -> bool:
    """Require a U.S.-equity-like session density for 252-session certification."""
    return bool(
        np.isfinite(value)
        and MIN_CERTIFIED_DAILY_OBSERVATION_RATE
        <= float(value)
        <= MAX_CERTIFIED_DAILY_OBSERVATION_RATE
    )


@dataclass(frozen=True)
class BootstrapSummary:
    paths: int
    horizon_days: int
    probability_positive_cagr: float
    probability_cagr_target: float
    probability_drawdown_target: float
    probability_both_targets: float
    median_cagr: float
    fifth_percentile_cagr: float
    median_max_drawdown: float
    fifth_percentile_max_drawdown: float
    worst_max_drawdown: float
    probability_both_targets_lower_95: float = float("nan")
    method_id: str = RETURN_ONLY_BOOTSTRAP_METHOD_ID
    seed: int = 11
    block_size: int = 0
    warmup_days: int = 0
    sampling_plan_sha256: str = ""
    policy_sha256: str = ""
    state_machine_rerun: bool = False
    failed_paths: int = 0
    valid_path_fraction: float = float("nan")

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass(frozen=True)
class SharpeProbabilityDiagnostics:
    probability: float
    observed_daily_sharpe: float
    benchmark_daily_sharpe: float
    adjusted_benchmark_daily_sharpe: float
    observations: int
    effective_observations: float
    autocorrelation_lags: int
    trial_count: int
    assumptions: str

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass(frozen=True)
class ParameterPerturbationSpecification:
    """One preregistered member of the crossed robustness family.

    ``volume_multiplier`` applies directly to the signed execution-window dollar-
    volume panel and ``borrow_rate_multiplier`` applies directly to the PIT security
    rates.  They therefore stress the consumed economic evidence rather than merely
    changing a configuration value that might be dominated by the supplied panel.
    Universe cohorts are deterministic SHA-256 partitions of broker symbols; no
    outcome or future liquidity statistic is used to choose an omitted cohort.
    """

    name: str
    config: AppConfig
    dimensions: tuple[str, ...]
    volume_multiplier: float = 1.0
    borrow_rate_multiplier: float = 1.0
    omitted_universe_cohort: int | None = None
    borrow_scarcity_cohort: int | None = None
    borrow_recall_cohort: int | None = None
    borrow_recall_interval_sessions: int = 0
    mandatory_critical_case: bool = False


@dataclass(frozen=True)
class _PreparedPerturbationInputs:
    specification: ParameterPerturbationSpecification
    ordinal: int
    columns: tuple[object, ...]
    prices: pd.DataFrame
    execution_prices: pd.DataFrame | None
    execution_window_dollar_volume: pd.DataFrame | None
    corporate_action_split_ratios: pd.DataFrame | None
    corporate_action_cash_distributions: pd.DataFrame | None
    borrow_availability: pd.DataFrame | None
    annual_borrow_rates: pd.DataFrame | None
    borrow_recalls: pd.DataFrame | None


def split_index(index: pd.Index, in_sample_fraction: float) -> int:
    if not 0.50 <= in_sample_fraction <= 0.90:
        raise ValueError("In-sample fraction must be between 50% and 90%.")
    return min(max(int(len(index) * in_sample_fraction), 1), len(index) - 1)


def _effective_observation_count(
    returns: pd.Series,
    autocorrelation_lags: int | None,
) -> tuple[float, int]:
    n = len(returns)
    if autocorrelation_lags is None:
        # A short automatic Newey-West bandwidth. It is intentionally capped because
        # noisy long-lag correlations can otherwise dominate a modest holdout.
        autocorrelation_lags = min(
            max(int(np.floor(4.0 * (n / 100.0) ** (2.0 / 9.0))), 1),
            20,
            n - 2,
        )
    if not isinstance(autocorrelation_lags, (int, np.integer)):
        raise TypeError("autocorrelation_lags must be an integer or None.")
    if autocorrelation_lags < 0 or autocorrelation_lags >= n:
        raise ValueError("autocorrelation_lags must be between zero and observations - 1.")
    if autocorrelation_lags == 0:
        return float(n), 0

    correlations: list[float] = []
    for lag in range(1, autocorrelation_lags + 1):
        value = float(returns.autocorr(lag=lag))
        correlations.append(value if np.isfinite(value) else 0.0)
    weights = 1.0 - np.arange(1, autocorrelation_lags + 1) / (autocorrelation_lags + 1.0)
    long_run_multiplier = 1.0 + 2.0 * float(np.dot(weights, correlations))
    if not np.isfinite(long_run_multiplier) or long_run_multiplier <= 0.0:
        effective = float(n)
    else:
        effective = float(np.clip(n / long_run_multiplier, 2.0, float(n)))
    return effective, int(autocorrelation_lags)


def _expected_maximum_normal(trial_count: int) -> float:
    if trial_count <= 1:
        return 0.0
    n = float(trial_count)
    first = STANDARD_NORMAL.inv_cdf(1.0 - 1.0 / n)
    second = STANDARD_NORMAL.inv_cdf(1.0 - 1.0 / (n * np.e))
    return float((1.0 - EULER_MASCHERONI) * first + EULER_MASCHERONI * second)


def sharpe_probability_diagnostics(
    returns: pd.Series,
    benchmark_sharpe: float = 0.0,
    *,
    trial_count: int = 1,
    autocorrelation_lags: int | None = None,
) -> SharpeProbabilityDiagnostics:
    """Return a HAC- and trial-aware probabilistic Sharpe diagnostic.

    The calculation assumes the holdout return process is approximately covariance
    stationary and that ``trial_count`` is the number of effectively independent
    specifications considered. Serial correlation reduces the effective sample size.
    For multiple trials, the benchmark is raised by the expected maximum sampling
    Sharpe (the Deflated-Sharpe extreme-value approximation). It is still a diagnostic,
    not proof of an edge: non-stationarity, correlated trials, holdout reuse, and
    unrecorded researcher choices can invalidate the probability.
    """
    if not isinstance(trial_count, (int, np.integer)):
        raise TypeError("trial_count must be an integer.")
    if trial_count < 1:
        raise ValueError("trial_count must be at least one.")
    if not np.isfinite(benchmark_sharpe):
        raise ValueError("benchmark_sharpe must be finite.")

    r = returns.dropna().astype(float)
    assumptions = (
        "Approximate covariance-stationary returns; HAC effective sample size; "
        "trial_count treated as effectively independent specifications; no unlogged "
        "holdout reuse or selection leakage."
    )
    if len(r) < 30 or r.std(ddof=1) <= 0:
        return SharpeProbabilityDiagnostics(
            probability=float("nan"),
            observed_daily_sharpe=float("nan"),
            benchmark_daily_sharpe=float(benchmark_sharpe),
            adjusted_benchmark_daily_sharpe=float("nan"),
            observations=int(len(r)),
            effective_observations=float("nan"),
            autocorrelation_lags=0,
            trial_count=int(trial_count),
            assumptions=assumptions,
        )

    effective_n, used_lags = _effective_observation_count(r, autocorrelation_lags)
    sr = float(r.mean() / r.std(ddof=1))
    skew = float(r.skew())
    kurtosis = float(r.kurt() + 3.0)  # Pearson kurtosis
    denominator_sq = 1.0 - skew * sr + ((kurtosis - 1.0) / 4.0) * sr * sr
    if not np.isfinite(denominator_sq) or denominator_sq <= 0.0:
        probability = float("nan")
        adjusted_benchmark = float("nan")
    else:
        sampling_standard_error = np.sqrt(denominator_sq / (effective_n - 1.0))
        adjusted_benchmark = float(
            benchmark_sharpe
            + _expected_maximum_normal(int(trial_count)) * sampling_standard_error
        )
        z = (
            (sr - adjusted_benchmark)
            * np.sqrt(effective_n - 1.0)
            / np.sqrt(denominator_sq)
        )
        probability = float(STANDARD_NORMAL.cdf(float(z)))

    return SharpeProbabilityDiagnostics(
        probability=probability,
        observed_daily_sharpe=sr,
        benchmark_daily_sharpe=float(benchmark_sharpe),
        adjusted_benchmark_daily_sharpe=adjusted_benchmark,
        observations=int(len(r)),
        effective_observations=effective_n,
        autocorrelation_lags=used_lags,
        trial_count=int(trial_count),
        assumptions=assumptions,
    )


def probabilistic_sharpe_probability(
    returns: pd.Series,
    benchmark_sharpe: float = 0.0,
    *,
    trial_count: int = 1,
    autocorrelation_lags: int | None = None,
) -> float:
    """Return the probability from :func:`sharpe_probability_diagnostics`.

    The two original positional arguments remain supported. Use
    ``sharpe_probability_diagnostics`` when the effective sample size, deflated
    benchmark, and stationarity assumptions also need to be reported.
    """
    return sharpe_probability_diagnostics(
        returns,
        benchmark_sharpe,
        trial_count=trial_count,
        autocorrelation_lags=autocorrelation_lags,
    ).probability


def block_bootstrap_validation(
    returns: pd.Series,
    n_paths: int,
    horizon_days: int,
    block_size: int,
    target_cagr: float,
    max_drawdown: float,
    seed: int = 11,
) -> BootstrapSummary:
    r = returns.dropna().to_numpy(dtype=float)
    r = np.clip(r, -0.999999, None)
    if len(r) < max(60, block_size * 3):
        raise ValueError("Not enough out-of-sample returns for block bootstrap validation.")
    if n_paths < 100:
        raise ValueError("Use at least 100 bootstrap paths.")
    if horizon_days < 63:
        raise ValueError("Bootstrap horizon must be at least 63 trading days.")

    block_size = min(block_size, max(2, len(r) // 3))
    n_blocks = int(np.ceil(horizon_days / block_size))
    rng = np.random.default_rng(seed)
    starts = rng.integers(0, len(r) - block_size + 1, size=(n_paths, n_blocks))
    offsets = np.arange(block_size)
    indices = starts[:, :, None] + offsets[None, None, :]
    paths = r[indices].reshape(n_paths, -1)[:, :horizon_days]

    equity = np.cumprod(1.0 + paths, axis=1)
    # One unit of capital exists immediately before every simulated path. Keeping it
    # in the high-water mark prevents a first-period loss from disappearing.
    peaks = np.maximum.accumulate(np.maximum(equity, 1.0), axis=1)
    max_dd = np.min(equity / peaks - 1.0, axis=1)
    years = horizon_days / TRADING_DAYS
    cagr = np.power(equity[:, -1], 1.0 / years) - 1.0

    dd_pass = max_dd >= -abs(max_drawdown)
    cagr_pass = cagr >= target_cagr
    both_pass = cagr_pass & dd_pass
    successes = int(np.sum(both_pass))
    # Wilson's lower 95% bound prevents a noisy Monte Carlo point estimate from
    # clearing a strict evidence threshold by a handful of favorable resamples.
    z_95 = 1.959963984540054
    proportion = successes / n_paths
    denominator = 1.0 + z_95 * z_95 / n_paths
    center = proportion + z_95 * z_95 / (2.0 * n_paths)
    radius = z_95 * np.sqrt(
        proportion * (1.0 - proportion) / n_paths
        + z_95 * z_95 / (4.0 * n_paths * n_paths)
    )
    both_lower_95 = float(
        min(max((center - radius) / denominator, 0.0), proportion)
    )
    return BootstrapSummary(
        paths=n_paths,
        horizon_days=horizon_days,
        probability_positive_cagr=float(np.mean(cagr > 0.0)),
        probability_cagr_target=float(np.mean(cagr_pass)),
        probability_drawdown_target=float(np.mean(dd_pass)),
        probability_both_targets=float(np.mean(both_pass)),
        median_cagr=float(np.median(cagr)),
        fifth_percentile_cagr=float(np.quantile(cagr, 0.05)),
        median_max_drawdown=float(np.median(max_dd)),
        fifth_percentile_max_drawdown=float(np.quantile(max_dd, 0.05)),
        worst_max_drawdown=float(np.min(max_dd)),
        probability_both_targets_lower_95=both_lower_95,
        method_id=RETURN_ONLY_BOOTSTRAP_METHOD_ID,
        seed=int(seed),
        block_size=int(block_size),
        state_machine_rerun=False,
        failed_paths=0,
        valid_path_fraction=1.0,
    )


def _stitched_price_path(
    panel: pd.DataFrame,
    selected_positions: np.ndarray,
    synthetic_index: pd.DatetimeIndex,
) -> tuple[pd.DataFrame, np.ndarray]:
    """Stitch sampled source intervals without manufacturing boundary returns.

    Every selected row represents the source interval ``t-1 -> t``.  The source
    price ratio is applied to the current synthetic level, so jumping between
    blocks never introduces a return from unrelated absolute price levels.  The
    returned scale factors also preserve cash distributions relative to raw
    execution prices.
    """
    source = panel.to_numpy(dtype=float)
    assets = panel.columns
    output = np.full((len(selected_positions) + 1, len(assets)), np.nan, dtype=float)
    output[0, :] = 100.0
    current_level = np.full(len(assets), 100.0, dtype=float)
    interval_scales = np.zeros((len(selected_positions), len(assets)), dtype=float)
    for row_number, source_position in enumerate(selected_positions):
        prior = source[source_position - 1]
        current = source[source_position]
        valid = (
            np.isfinite(prior)
            & np.isfinite(current)
            & (prior > 0.0)
            & (current > 0.0)
        )
        scale = np.zeros(len(assets), dtype=float)
        scale[valid] = current_level[valid] / prior[valid]
        next_level = np.full(len(assets), np.nan, dtype=float)
        next_level[valid] = current[valid] * scale[valid]
        output[row_number + 1] = next_level
        current_level[valid] = next_level[valid]
        interval_scales[row_number] = scale
    return (
        pd.DataFrame(output, index=synthetic_index, columns=assets),
        interval_scales,
    )


def _resampled_panel_rows(
    panel: pd.DataFrame,
    selected_positions: np.ndarray,
    synthetic_index: pd.DatetimeIndex,
) -> pd.DataFrame:
    initial_position = int(selected_positions[0]) - 1
    source_positions = np.concatenate(
        [np.asarray([initial_position], dtype=int), selected_positions]
    )
    values = panel.iloc[source_positions].to_numpy(copy=True)
    return pd.DataFrame(values, index=synthetic_index, columns=panel.columns)


def _path_bootstrap_summary(
    cagr: np.ndarray,
    max_drawdown: np.ndarray,
    valid_paths: np.ndarray,
    *,
    horizon_days: int,
    target_cagr: float,
    max_drawdown_target: float,
    block_size: int,
    warmup_days: int,
    sampling_plan_sha256: str,
    failed_paths: int,
) -> BootstrapSummary:
    path_count = len(cagr)
    cagr_pass = (cagr >= target_cagr) & valid_paths
    drawdown_pass = (max_drawdown >= -abs(max_drawdown_target)) & valid_paths
    both_pass = cagr_pass & drawdown_pass
    successes = int(both_pass.sum())
    z_95 = 1.959963984540054
    proportion = successes / path_count
    denominator = 1.0 + z_95 * z_95 / path_count
    center = proportion + z_95 * z_95 / (2.0 * path_count)
    radius = z_95 * np.sqrt(
        proportion * (1.0 - proportion) / path_count
        + z_95 * z_95 / (4.0 * path_count * path_count)
    )
    lower_95 = float(
        min(max((center - radius) / denominator, 0.0), proportion)
    )
    return BootstrapSummary(
        paths=path_count,
        horizon_days=horizon_days,
        probability_positive_cagr=float(np.mean((cagr > 0.0) & valid_paths)),
        probability_cagr_target=float(np.mean(cagr_pass)),
        probability_drawdown_target=float(np.mean(drawdown_pass)),
        probability_both_targets=float(np.mean(both_pass)),
        median_cagr=float(np.median(cagr)),
        fifth_percentile_cagr=float(np.quantile(cagr, 0.05)),
        median_max_drawdown=float(np.median(max_drawdown)),
        fifth_percentile_max_drawdown=float(np.quantile(max_drawdown, 0.05)),
        worst_max_drawdown=float(np.min(max_drawdown)),
        probability_both_targets_lower_95=lower_95,
        method_id=PATH_AWARE_BOOTSTRAP_METHOD_ID,
        seed=PATH_AWARE_BOOTSTRAP_SEED,
        block_size=block_size,
        warmup_days=warmup_days,
        sampling_plan_sha256=sampling_plan_sha256,
        policy_sha256=PATH_AWARE_BOOTSTRAP_POLICY_SHA256,
        state_machine_rerun=True,
        failed_paths=failed_paths,
        valid_path_fraction=float(np.mean(valid_paths)),
    )


def path_aware_block_bootstrap_validation(
    prices: pd.DataFrame,
    config: AppConfig,
    sample_index: pd.Index,
    *,
    horizon_days: int,
    block_size: int,
    target_cagr: float,
    max_drawdown: float,
    n_paths: int = PATH_AWARE_BOOTSTRAP_PATHS,
    seed: int = PATH_AWARE_BOOTSTRAP_SEED,
    execution_return_semantics: ExecutionReturnSemantics = "close_to_close",
    execution_prices: pd.DataFrame | None = None,
    execution_window_dollar_volume: pd.DataFrame | None = None,
    corporate_action_split_ratios: pd.DataFrame | None = None,
    corporate_action_cash_distributions: pd.DataFrame | None = None,
    borrow_availability: pd.DataFrame | None = None,
    annual_borrow_rates: pd.DataFrame | None = None,
    borrow_recalls: pd.DataFrame | None = None,
) -> BootstrapSummary:
    """Resample aligned input intervals and rerun the complete strategy state.

    Unlike a return bootstrap, every path rebuilds close/execution price histories,
    liquidity, corporate actions, and borrow evidence before calling ``run_backtest``.
    Warm-up, covariance, drawdown throttles, cooldown, recalls, transaction costs,
    and realized partial fills are therefore endogenous to the sampled chronology.
    """
    config.validate()
    if seed != PATH_AWARE_BOOTSTRAP_SEED:
        raise ValueError("Path-aware bootstrap seed is fixed by certification policy.")
    if not isinstance(n_paths, (int, np.integer)) or n_paths < 2:
        raise ValueError("Path-aware bootstrap requires at least two paths.")
    if not isinstance(block_size, (int, np.integer)) or block_size < 2:
        raise ValueError("Path-aware bootstrap block_size must be at least two.")
    if horizon_days < 63:
        raise ValueError("Path-aware bootstrap horizon must be at least 63 sessions.")
    if not isinstance(prices, pd.DataFrame):
        raise TypeError("prices must be a pandas DataFrame.")
    if not prices.index.is_unique or not prices.columns.is_unique:
        raise ValueError("Path-aware bootstrap prices must have unique axes.")

    sample_index = pd.Index(sample_index)
    sample_positions = prices.index.get_indexer(sample_index)
    if (
        len(sample_positions) == 0
        or np.any(sample_positions < 1)
        or not np.all(np.diff(sample_positions) == 1)
        or not prices.index[sample_positions].equals(sample_index)
    ):
        raise ValueError(
            "sample_index must be a contiguous ordered subset with a prior endpoint."
        )
    if len(sample_positions) < max(60, int(block_size) * 3):
        raise ValueError(
            "Not enough aligned holdout intervals for path-aware block validation."
        )

    paired_panels = (
        corporate_action_split_ratios,
        corporate_action_cash_distributions,
    )
    if any(panel is not None for panel in paired_panels) and any(
        panel is None for panel in paired_panels
    ):
        raise ValueError("Both corporate-action panels are required together.")
    if corporate_action_split_ratios is not None and execution_prices is None:
        raise ValueError(
            "Corporate-action path resampling requires raw execution prices."
        )
    borrow_panels = (borrow_availability, annual_borrow_rates, borrow_recalls)
    if any(panel is not None for panel in borrow_panels) and any(
        panel is None for panel in borrow_panels
    ):
        raise ValueError("All point-in-time borrow panels are required together.")

    aligned_panels = {
        "execution_prices": execution_prices,
        "execution_window_dollar_volume": execution_window_dollar_volume,
        "corporate_action_split_ratios": corporate_action_split_ratios,
        "corporate_action_cash_distributions": (
            corporate_action_cash_distributions
        ),
        "borrow_availability": borrow_availability,
        "annual_borrow_rates": annual_borrow_rates,
        "borrow_recalls": borrow_recalls,
    }
    for label, panel in aligned_panels.items():
        if panel is None:
            continue
        if (
            not isinstance(panel, pd.DataFrame)
            or not panel.index.equals(prices.index)
            or not panel.columns.equals(prices.columns)
        ):
            raise ValueError(
                f"{label} must exactly match the price index and asset columns."
            )

    warmup_days = max(
        PATH_AWARE_BOOTSTRAP_MIN_WARMUP_DAYS,
        int(config.signals.beta_lookback) + 2,
        int(config.signals.vol_lookback) + 2,
        int(config.regime.ic_window) + 2,
        int(config.costs.adv_lookback_days) + 1,
        int(config.risk.cooldown_days) + 1,
    )
    total_intervals = warmup_days + int(horizon_days)
    n_blocks = int(np.ceil(total_intervals / int(block_size)))
    rng = np.random.default_rng(PATH_AWARE_BOOTSTRAP_SEED)
    local_starts = rng.integers(
        0,
        len(sample_positions) - int(block_size) + 1,
        size=(int(n_paths), n_blocks),
    )
    plan_payload = {
        "method_id": PATH_AWARE_BOOTSTRAP_METHOD_ID,
        "policy_sha256": PATH_AWARE_BOOTSTRAP_POLICY_SHA256,
        "seed": PATH_AWARE_BOOTSTRAP_SEED,
        "paths": int(n_paths),
        "horizon_days": int(horizon_days),
        "block_size": int(block_size),
        "warmup_days": warmup_days,
        "sample_index": [str(value) for value in sample_index],
        "columns": [str(value) for value in prices.columns],
        "starts": local_starts.tolist(),
    }
    sampling_plan_sha256 = hashlib.sha256(
        json.dumps(
            plan_payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    block_offsets = np.arange(int(block_size), dtype=int)
    source_session_dates = pd.DatetimeIndex(prices.index).tz_localize(None).normalize()
    path_cagr = np.full(int(n_paths), -1.0, dtype=float)
    path_drawdown = np.full(int(n_paths), -1.0, dtype=float)
    path_valid = np.zeros(int(n_paths), dtype=bool)
    failed_paths = 0
    for path_number in range(int(n_paths)):
        local_positions = (
            local_starts[path_number, :, None] + block_offsets[None, :]
        ).reshape(-1)[:total_intervals]
        selected_positions = sample_positions[local_positions]
        selected_elapsed_days = np.asarray(
            [
                int(
                    (
                        source_session_dates[position]
                        - source_session_dates[position - 1]
                    ).days
                )
                for position in selected_positions
            ],
            dtype=int,
        )
        if np.any(selected_elapsed_days <= 0):
            raise ValueError(
                "Sampled execution intervals must have positive calendar-day gaps."
            )
        # Preserve the source interval's Friday/weekend/holiday accrual duration.
        # A business-day range would silently turn every sampled interval into a
        # synthetic one-day carry observation.
        synthetic_index = pd.DatetimeIndex(
            pd.Timestamp("2000-01-03")
            + pd.to_timedelta(
                np.r_[0, np.cumsum(selected_elapsed_days)], unit="D"
            )
        )
        resampled_prices, _ = _stitched_price_path(
            prices,
            selected_positions,
            synthetic_index,
        )
        resampled_execution_prices: pd.DataFrame | None = None
        execution_scales: np.ndarray | None = None
        if execution_prices is not None:
            resampled_execution_prices, execution_scales = _stitched_price_path(
                execution_prices,
                selected_positions,
                synthetic_index,
            )
        resampled_volume = (
            _resampled_panel_rows(
                execution_window_dollar_volume,
                selected_positions,
                synthetic_index,
            )
            if execution_window_dollar_volume is not None
            else None
        )
        resampled_splits: pd.DataFrame | None = None
        resampled_cash: pd.DataFrame | None = None
        if corporate_action_split_ratios is not None:
            assert corporate_action_cash_distributions is not None
            assert execution_scales is not None
            resampled_splits = _resampled_panel_rows(
                corporate_action_split_ratios,
                selected_positions,
                synthetic_index,
            )
            resampled_splits.iloc[0] = 1.0
            cash_values = np.zeros(
                (total_intervals + 1, len(prices.columns)), dtype=float
            )
            cash_values[1:] = (
                corporate_action_cash_distributions.iloc[selected_positions]
                .to_numpy(dtype=float)
                * execution_scales
            )
            resampled_cash = pd.DataFrame(
                cash_values,
                index=synthetic_index,
                columns=prices.columns,
            )
        resampled_borrow_availability = (
            _resampled_panel_rows(
                borrow_availability,
                selected_positions,
                synthetic_index,
            ).astype(bool)
            if borrow_availability is not None
            else None
        )
        resampled_borrow_rates = (
            _resampled_panel_rows(
                annual_borrow_rates,
                selected_positions,
                synthetic_index,
            ).astype(float)
            if annual_borrow_rates is not None
            else None
        )
        resampled_borrow_recalls = (
            _resampled_panel_rows(
                borrow_recalls,
                selected_positions,
                synthetic_index,
            ).astype(bool)
            if borrow_recalls is not None
            else None
        )
        try:
            result = run_backtest(
                resampled_prices,
                config,
                execution_return_semantics=execution_return_semantics,
                execution_prices=resampled_execution_prices,
                execution_window_dollar_volume=resampled_volume,
                corporate_action_split_ratios=resampled_splits,
                corporate_action_cash_distributions=resampled_cash,
                borrow_availability=resampled_borrow_availability,
                annual_borrow_rates=resampled_borrow_rates,
                borrow_recalls=resampled_borrow_recalls,
            )
        except (ArithmeticError, ValueError):
            failed_paths += 1
            continue
        scored_returns = result.strategy_returns.iloc[-int(horizon_days):]
        scored_diagnostics = result.diagnostics.iloc[-int(horizon_days):]
        return_values = np.clip(
            scored_returns.fillna(0.0).to_numpy(dtype=float),
            -0.999999,
            None,
        )
        path_equity = np.cumprod(1.0 + return_values)
        path_peaks = np.maximum.accumulate(np.maximum(path_equity, 1.0))
        path_cagr[path_number] = float(
            path_equity[-1] ** (TRADING_DAYS / int(horizon_days)) - 1.0
        )
        path_drawdown[path_number] = float(
            np.min(path_equity / path_peaks - 1.0)
        )
        research_valid = bool(
            "research_path_valid" in scored_diagnostics
            and scored_diagnostics["research_path_valid"]
            .fillna(False)
            .astype(bool)
            .all()
        )
        liquidity_valid = bool(
            "liquidity_path_valid" in scored_diagnostics
            and scored_diagnostics["liquidity_path_valid"]
            .fillna(False)
            .astype(bool)
            .all()
        )
        carry_columns = {
            "carry_day_count_convention",
            "elapsed_calendar_days",
            "carry_year_fraction",
        }
        carry_valid = False
        if carry_columns.issubset(scored_diagnostics.columns):
            scored_carry_days = pd.to_numeric(
                scored_diagnostics["elapsed_calendar_days"], errors="coerce"
            )
            scored_carry_fractions = pd.to_numeric(
                scored_diagnostics["carry_year_fraction"], errors="coerce"
            )
            carry_valid = bool(
                scored_diagnostics["carry_day_count_convention"]
                .eq(CARRY_DAY_COUNT_CONVENTION)
                .all()
                and scored_carry_days.notna().all()
                and scored_carry_fractions.notna().all()
                and np.allclose(
                    scored_carry_fractions.to_numpy(dtype=float),
                    scored_carry_days.to_numpy(dtype=float) / 365.25,
                    rtol=0.0,
                    atol=1e-15,
                )
            )
        path_valid[path_number] = bool(
            research_valid
            and carry_valid
            and (
                execution_window_dollar_volume is None
                or liquidity_valid
            )
        )

    return _path_bootstrap_summary(
        path_cagr,
        path_drawdown,
        path_valid,
        horizon_days=int(horizon_days),
        target_cagr=target_cagr,
        max_drawdown_target=max_drawdown,
        block_size=int(block_size),
        warmup_days=warmup_days,
        sampling_plan_sha256=sampling_plan_sha256,
        failed_paths=failed_paths,
    )


def rolling_target_pass_rate(
    returns: pd.Series,
    target_cagr: float,
    max_drawdown: float,
    window: int = 252,
    step: int = 63,
) -> tuple[float, pd.DataFrame]:
    r = returns.dropna()
    rows: list[dict[str, Any]] = []
    if len(r) < window:
        return float("nan"), pd.DataFrame()

    window_ends = list(range(window, len(r) + 1, step))
    # Always evaluate the most recent complete window.  A step that does not divide
    # the available tail must not silently omit the latest evidence.
    if not window_ends or window_ends[-1] != len(r):
        window_ends.append(len(r))

    for end in window_ends:
        part = r.iloc[end - window: end]
        m = metrics_from_returns(part)
        passed = (
            m.get("CAGR", float("-inf")) >= target_cagr
            and m.get("Max Drawdown", float("-inf")) >= -abs(max_drawdown)
        )
        rows.append(
            {
                "Window End": part.index[-1],
                "CAGR": m.get("CAGR"),
                "Max Drawdown": m.get("Max Drawdown"),
                "Calmar": m.get("Calmar Ratio"),
                "Pass": bool(passed),
            }
        )
    frame = pd.DataFrame(rows).set_index("Window End") if rows else pd.DataFrame()
    return (float(frame["Pass"].mean()) if not frame.empty else float("nan"), frame)


def doubled_cost_config(config: AppConfig) -> AppConfig:
    stressed_costs = replace(
        config.costs,
        transaction_cost_bps=config.costs.transaction_cost_bps * 2.0,
        annual_short_borrow_rate=config.costs.annual_short_borrow_rate * 2.0,
        annual_financing_rate=config.costs.annual_financing_rate * 2.0,
        square_root_impact_coefficient=(
            config.costs.square_root_impact_coefficient * 2.0
        ),
    )
    return replace(config, costs=stressed_costs)


def parameter_perturbation_specifications(
    config: AppConfig,
) -> tuple[ParameterPerturbationSpecification, ...]:
    """Return the fixed, preregistered 25-member crossed robustness family.

    The family deliberately includes material joint changes across alpha composition,
    risk sizing, cost, signed-window liquidity, execution cadence, regime behavior,
    and the investible universe.  This is a validation family, not a hyperparameter
    search: callers must count every member before running any of them and may not
    select a favorable subset after seeing holdout results.
    """

    def signal_tilt(*, reversal: float, momentum: float) -> AppConfig:
        return replace(
            config,
            signals=replace(
                config.signals,
                reversal_3_weight=config.signals.reversal_3_weight * reversal,
                reversal_10_weight=config.signals.reversal_10_weight * reversal,
                residual_reversal_weight=(
                    config.signals.residual_reversal_weight * reversal
                ),
                momentum_63_weight=config.signals.momentum_63_weight * momentum,
                momentum_126_weight=config.signals.momentum_126_weight * momentum,
            ),
        )

    def cost_stress(
        source: AppConfig,
        *,
        linear: float,
        carry: float,
        impact: float,
        capital: float = 1.0,
        participation: float = 1.0,
        adv_lookback: float = 1.0,
        impact_floor: float = 1.0,
    ) -> AppConfig:
        return replace(
            source,
            costs=replace(
                source.costs,
                transaction_cost_bps=(
                    source.costs.transaction_cost_bps * linear
                ),
                annual_short_borrow_rate=(
                    source.costs.annual_short_borrow_rate * carry
                ),
                annual_financing_rate=(
                    source.costs.annual_financing_rate * carry
                ),
                starting_capital=source.costs.starting_capital * capital,
                adv_lookback_days=max(
                    2,
                    min(252, int(round(source.costs.adv_lookback_days * adv_lookback))),
                ),
                max_participation_rate=(
                    source.costs.max_participation_rate * participation
                ),
                square_root_impact_coefficient=(
                    source.costs.square_root_impact_coefficient * impact
                ),
                impact_daily_volatility_floor=(
                    source.costs.impact_daily_volatility_floor * impact_floor
                ),
            ),
        )

    reversal_dominant = signal_tilt(reversal=1.50, momentum=0.50)
    momentum_dominant = signal_tilt(reversal=0.50, momentum=1.50)
    equalized_alpha = replace(
        config,
        signals=replace(
            config.signals,
            reversal_3_weight=0.20,
            reversal_10_weight=0.20,
            residual_reversal_weight=0.20,
            momentum_63_weight=0.20,
            momentum_126_weight=0.20,
        ),
    )
    delevered = replace(
        config,
        portfolio=replace(
            config.portfolio,
            target_volatility=config.portfolio.target_volatility * 0.70,
            max_gross_leverage=config.portfolio.max_gross_leverage * 0.70,
            max_position_weight=config.portfolio.max_position_weight * 0.75,
        ),
    )
    earlier_controls = replace(
        config,
        risk=replace(
            config.risk,
            throttle_drawdown=config.risk.throttle_drawdown * 0.80,
            defensive_drawdown=config.risk.defensive_drawdown * 0.80,
            severe_drawdown=config.risk.severe_drawdown * 0.80,
            flatten_drawdown=config.risk.flatten_drawdown * 0.80,
            hard_drawdown_limit=config.risk.hard_drawdown_limit * 0.80,
            cooldown_days=max(1, int(round(config.risk.cooldown_days * 1.50))),
            daily_loss_trigger=config.risk.daily_loss_trigger * 0.75,
            five_day_loss_trigger=config.risk.five_day_loss_trigger * 0.75,
        ),
    )
    stricter_regime = replace(
        config,
        regime=replace(
            config.regime,
            favorable_ic_tstat=config.regime.favorable_ic_tstat + 0.25,
            neutral_ic_tstat=config.regime.neutral_ic_tstat + 0.25,
            invalid_ic_tstat=config.regime.invalid_ic_tstat + 0.25,
            favorable_multiplier=config.regime.favorable_multiplier * 0.90,
            neutral_multiplier=config.regime.neutral_multiplier * 0.80,
            degraded_multiplier=config.regime.degraded_multiplier * 0.67,
        ),
    )
    faster_risk = replace(
        config,
        portfolio=replace(
            config.portfolio,
            covariance_halflife=max(5, config.portfolio.covariance_halflife // 2),
            max_gross_leverage=config.portfolio.max_gross_leverage * 0.80,
        ),
    )
    slower_risk = replace(
        config,
        portfolio=replace(
            config.portfolio,
            covariance_halflife=config.portfolio.covariance_halflife * 2,
            target_volatility=config.portfolio.target_volatility * 0.80,
        ),
    )

    variants = (
        ParameterPerturbationSpecification(
            "Base", config, ("base",), mandatory_critical_case=True
        ),
        ParameterPerturbationSpecification(
            "Alpha: reversal +50%, momentum -50%",
            reversal_dominant,
            ("alpha",),
        ),
        ParameterPerturbationSpecification(
            "Alpha: reversal -50%, momentum +50%",
            momentum_dominant,
            ("alpha",),
        ),
        ParameterPerturbationSpecification(
            "Alpha/regime: tighter clip, 50% longer IC window",
            replace(
                config,
                signals=replace(
                    config.signals,
                    signal_clip=config.signals.signal_clip * (2.0 / 3.0),
                ),
                regime=replace(
                    config.regime,
                    ic_window=max(20, int(round(config.regime.ic_window * 1.50))),
                ),
            ),
            ("alpha", "regime"),
        ),
        ParameterPerturbationSpecification(
            "Alpha/risk: shorter beta, longer volatility memory",
            replace(
                config,
                signals=replace(
                    config.signals,
                    beta_lookback=max(20, config.signals.beta_lookback // 2),
                    vol_lookback=max(2, config.signals.vol_lookback * 2),
                ),
            ),
            ("alpha", "risk"),
        ),
        ParameterPerturbationSpecification(
            "Risk: 30% lower vol/gross and 25% tighter names",
            delevered,
            ("risk",),
        ),
        ParameterPerturbationSpecification(
            "Risk/timing: 2x covariance half-life, 20% lower vol",
            slower_risk,
            ("risk", "timing"),
        ),
        ParameterPerturbationSpecification(
            "Risk/timing: 0.5x covariance half-life, 20% lower gross",
            faster_risk,
            ("risk", "timing"),
        ),
        ParameterPerturbationSpecification(
            "Risk/timing: 20% earlier controls, 50% longer cooldown",
            earlier_controls,
            ("risk", "timing"),
        ),
        ParameterPerturbationSpecification(
            "Cost: 2x linear/carry/impact",
            cost_stress(config, linear=2.0, carry=2.0, impact=2.0),
            ("cost", "borrow"),
            borrow_rate_multiplier=2.0,
        ),
        ParameterPerturbationSpecification(
            "Cost: 3x linear/carry, 2.5x impact",
            cost_stress(config, linear=3.0, carry=3.0, impact=2.5),
            ("cost", "borrow"),
            borrow_rate_multiplier=3.0,
            mandatory_critical_case=True,
        ),
        ParameterPerturbationSpecification(
            "Liquidity/cost: 1.5x AUM, 25% volume haircut",
            cost_stress(
                config,
                linear=1.25,
                carry=1.25,
                impact=1.50,
                capital=1.50,
                participation=0.75,
                adv_lookback=1.50,
            ),
            ("liquidity", "cost", "borrow"),
            volume_multiplier=0.75,
            borrow_rate_multiplier=1.25,
        ),
        ParameterPerturbationSpecification(
            "Liquidity/cost: 2x AUM, 50% volume haircut",
            cost_stress(
                config,
                linear=1.50,
                carry=1.50,
                impact=2.0,
                capital=2.0,
                participation=0.50,
                adv_lookback=2.0,
                impact_floor=1.50,
            ),
            ("liquidity", "cost", "borrow"),
            volume_multiplier=0.50,
            borrow_rate_multiplier=1.50,
            mandatory_critical_case=True,
        ),
        ParameterPerturbationSpecification(
            "Timing/cost: two-session rebalance, 1.5x linear cost",
            cost_stress(
                replace(
                    config,
                    portfolio=replace(config.portfolio, rebalance_every=2),
                ),
                linear=1.50,
                carry=1.0,
                impact=1.0,
            ),
            ("timing", "cost"),
        ),
        ParameterPerturbationSpecification(
            "Timing/risk/liquidity: three-session rebalance, fast covariance",
            replace(
                faster_risk,
                portfolio=replace(faster_risk.portfolio, rebalance_every=3),
            ),
            ("timing", "risk", "liquidity"),
            volume_multiplier=0.75,
            mandatory_critical_case=True,
        ),
        ParameterPerturbationSpecification(
            "Alpha/timing/cost: reversal tilt, slower, 2x cost",
            cost_stress(
                replace(
                    reversal_dominant,
                    portfolio=replace(
                        reversal_dominant.portfolio,
                        rebalance_every=2,
                    ),
                ),
                linear=2.0,
                carry=2.0,
                impact=2.0,
            ),
            ("alpha", "timing", "cost", "borrow"),
            borrow_rate_multiplier=2.0,
        ),
        ParameterPerturbationSpecification(
            "Alpha/risk/cost: momentum tilt, delevered, 1.5x cost",
            cost_stress(
                replace(momentum_dominant, portfolio=delevered.portfolio),
                linear=1.50,
                carry=1.50,
                impact=1.50,
            ),
            ("alpha", "risk", "cost", "borrow"),
            borrow_rate_multiplier=1.50,
        ),
        ParameterPerturbationSpecification(
            "Regime/risk/liquidity: stricter regime, 25% volume haircut",
            stricter_regime,
            ("regime", "risk", "liquidity"),
            volume_multiplier=0.75,
        ),
        ParameterPerturbationSpecification(
            "Universe/cost: omit deterministic cohort 0, 1.5x cost",
            cost_stress(config, linear=1.50, carry=1.50, impact=1.50),
            ("universe", "cost", "borrow"),
            borrow_rate_multiplier=1.50,
            omitted_universe_cohort=0,
        ),
        ParameterPerturbationSpecification(
            "Universe/risk: omit deterministic cohort 1, delevered",
            delevered,
            ("universe", "risk"),
            omitted_universe_cohort=1,
        ),
        ParameterPerturbationSpecification(
            "Universe/alpha/cost/liquidity: omit cohort 2, momentum adverse",
            cost_stress(
                signal_tilt(reversal=0.70, momentum=1.30),
                linear=1.50,
                carry=1.50,
                impact=1.75,
                capital=1.50,
                participation=0.70,
            ),
            ("universe", "alpha", "cost", "liquidity", "borrow"),
            volume_multiplier=0.65,
            borrow_rate_multiplier=1.50,
            omitted_universe_cohort=2,
        ),
        ParameterPerturbationSpecification(
            "Universe/risk/timing/liquidity: omit cohort 3, slower, 40% haircut",
            replace(
                delevered,
                portfolio=replace(delevered.portfolio, rebalance_every=2),
            ),
            ("universe", "risk", "timing", "liquidity"),
            volume_multiplier=0.60,
            omitted_universe_cohort=3,
        ),
        ParameterPerturbationSpecification(
            "Universe broad adverse cross: omit cohort 4",
            cost_stress(
                replace(
                    signal_tilt(reversal=0.70, momentum=1.30),
                    portfolio=replace(delevered.portfolio, rebalance_every=2),
                ),
                linear=2.0,
                carry=2.0,
                impact=2.0,
                capital=1.50,
                participation=0.70,
            ),
            ("universe", "alpha", "risk", "timing", "cost", "liquidity", "borrow"),
            volume_multiplier=0.60,
            borrow_rate_multiplier=2.0,
            omitted_universe_cohort=4,
            mandatory_critical_case=True,
        ),
        ParameterPerturbationSpecification(
            "Regime/cost/borrow: stricter states, 2x economics, cohort-0 scarcity",
            cost_stress(
                stricter_regime,
                linear=2.0,
                carry=2.0,
                impact=2.0,
            ),
            ("regime", "risk", "cost", "borrow"),
            borrow_rate_multiplier=2.0,
            borrow_scarcity_cohort=0,
            mandatory_critical_case=True,
        ),
        ParameterPerturbationSpecification(
            "Alpha/risk/cost/borrow: equalized sleeves, cohort-1 recalls",
            cost_stress(
                replace(equalized_alpha, portfolio=slower_risk.portfolio),
                linear=1.50,
                carry=1.50,
                impact=1.50,
            ),
            ("alpha", "risk", "timing", "cost", "borrow"),
            borrow_rate_multiplier=1.50,
            borrow_recall_cohort=1,
            borrow_recall_interval_sessions=21,
            mandatory_critical_case=True,
        ),
    )
    if len(variants) != PARAMETER_PERTURBATION_VARIANT_COUNT:
        raise RuntimeError("Update PARAMETER_PERTURBATION_VARIANT_COUNT with the suite.")
    if len({variant.name for variant in variants}) != len(variants):
        raise RuntimeError("Parameter perturbation names must be unique.")
    universe_cohorts = sorted(
        variant.omitted_universe_cohort
        for variant in variants
        if variant.omitted_universe_cohort is not None
    )
    if universe_cohorts != list(range(5)):
        raise RuntimeError(
            "The robustness family must exercise each deterministic universe cohort exactly once."
        )
    for variant in variants:
        variant.config.validate()
        if (
            not np.isfinite(variant.volume_multiplier)
            or not 0.0 < variant.volume_multiplier <= 1.0
            or not np.isfinite(variant.borrow_rate_multiplier)
            or not 1.0 <= variant.borrow_rate_multiplier <= 10.0
        ):
            raise RuntimeError("Parameter perturbation evidence multipliers are invalid.")
        for label, cohort in (
            ("omitted universe", variant.omitted_universe_cohort),
            ("borrow scarcity", variant.borrow_scarcity_cohort),
            ("borrow recall", variant.borrow_recall_cohort),
        ):
            if cohort is not None and not 0 <= cohort < 5:
                raise RuntimeError(f"The {label} cohort must be between zero and four.")
        if variant.borrow_recall_cohort is None:
            if variant.borrow_recall_interval_sessions != 0:
                raise RuntimeError(
                    "A borrow recall interval requires an explicit deterministic cohort."
                )
        elif variant.borrow_recall_interval_sessions < 2:
            raise RuntimeError("Borrow recall stress must recur at an interval of at least two sessions.")
        if (
            variant.borrow_scarcity_cohort is not None
            or variant.borrow_recall_cohort is not None
        ) and "borrow" not in variant.dimensions:
            raise RuntimeError("Actual borrow evidence stresses must belong to the borrow stratum.")
    mandatory_dimensions = {
        dimension
        for variant in variants
        if variant.mandatory_critical_case
        for dimension in variant.dimensions
    }
    if not set(PERTURBATION_CRITICAL_STRATUM_MIN_PASS_RATE).issubset(
        mandatory_dimensions
    ):
        raise RuntimeError("Each critical robustness stratum requires a mandatory case.")
    return variants


def parameter_perturbation_preregistration(
    config: AppConfig,
) -> dict[str, Any]:
    """Return the canonical, inspectable policy and exact 25-member suite.

    The returned value is safe to canonicalize with sorted JSON keys.  It deliberately
    includes every derived variant configuration, evidence multiplier, universe cohort,
    and pass threshold.  A signed run specification can therefore bind the exact suite
    rather than relying on a human-readable family label alone.
    """

    specifications = parameter_perturbation_specifications(config)
    return {
        "family_id": PARAMETER_PERTURBATION_FAMILY_ID,
        "variant_count": PARAMETER_PERTURBATION_VARIANT_COUNT,
        "minimum_passing_variants": int(
            np.ceil(
                PARAMETER_PERTURBATION_VARIANT_COUNT
                * MIN_PERTURBATION_PASS_RATE
            )
        ),
        "policy": {
            "minimum_pass_rate": MIN_PERTURBATION_PASS_RATE,
            "minimum_project_target_cagr": MIN_PROJECT_TARGET_CAGR,
            "minimum_cagr_target_retention": (
                MIN_PERTURBATION_CAGR_TARGET_RETENTION
            ),
            "minimum_sharpe": MIN_PERTURBATION_SHARPE,
            "maximum_project_drawdown": MAX_PROJECT_TARGET_DRAWDOWN,
            "minimum_universe_retention": MIN_PERTURBATION_UNIVERSE_RETENTION,
            "minimum_base_effective_asset_count": (
                MIN_CERTIFIED_ELIGIBLE_ASSET_COUNT
            ),
            "mandatory_critical_variant_ordinals": [
                ordinal
                for ordinal, specification in enumerate(specifications, start=1)
                if specification.mandatory_critical_case
            ],
            "critical_stratum_minimum_pass_rates": dict(
                sorted(PERTURBATION_CRITICAL_STRATUM_MIN_PASS_RATE.items())
            ),
            "required_path_controls": [
                "research_path_valid",
                "liquidity_path_valid",
                "zero_hard_drawdown_breaches",
                "zero_liquidity_data_breaches",
                "zero_participation_limit_breaches",
                "zero_data_integrity_breaches",
                "zero_beta_data_breaches",
                "zero_stale_signal_trade_breaches",
                "configured_gross_leverage_respected",
            ],
        },
        "variants": [
            {
                "ordinal": ordinal,
                "name": specification.name,
                "dimensions": list(specification.dimensions),
                "config": specification.config.to_dict(),
                "execution_volume_multiplier": specification.volume_multiplier,
                "borrow_rate_multiplier": specification.borrow_rate_multiplier,
                "omitted_universe_cohort": (
                    specification.omitted_universe_cohort
                ),
                "borrow_scarcity_cohort": specification.borrow_scarcity_cohort,
                "borrow_recall_cohort": specification.borrow_recall_cohort,
                "borrow_recall_interval_sessions": (
                    specification.borrow_recall_interval_sessions
                ),
                "mandatory_critical_case": specification.mandatory_critical_case,
            }
            for ordinal, specification in enumerate(specifications, start=1)
        ],
    }


def parameter_perturbation_specification_hash(config: AppConfig) -> str:
    """Return a deterministic SHA-256 identity for the preregistered suite."""

    canonical = json.dumps(
        parameter_perturbation_preregistration(config),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _axis_identity(value: object) -> dict[str, str]:
    if isinstance(value, pd.Timestamp):
        rendered = value.isoformat()
    else:
        rendered = str(value)
    value_type = type(value)
    return {
        "type": f"{value_type.__module__}.{value_type.__qualname__}",
        "value": rendered,
    }


def _frame_sha256(frame: pd.DataFrame | None) -> str:
    """Bind exact ordered axes, dtypes, missingness, and values for one panel."""

    if frame is None:
        return _canonical_sha256({"present": False})
    if not isinstance(frame, pd.DataFrame):
        raise ValueError("Perturbation evidence inputs must be pandas DataFrames.")
    metadata = {
        "present": True,
        "shape": list(frame.shape),
        "index": [_axis_identity(value) for value in frame.index],
        "columns": [_axis_identity(value) for value in frame.columns],
        "index_names": [str(value) for value in frame.index.names],
        "column_names": [str(value) for value in frame.columns.names],
        "dtypes": [str(value) for value in frame.dtypes],
    }
    digest = hashlib.sha256()
    digest.update(bytes.fromhex(_canonical_sha256(metadata)))
    digest.update(
        pd.util.hash_pandas_object(
            frame,
            index=True,
            categorize=True,
        ).to_numpy(dtype=np.uint64, copy=False).tobytes()
    )
    return digest.hexdigest()


def _deterministic_cohort_members(
    columns: pd.Index | tuple[object, ...] | list[object], cohort: int
) -> tuple[object, ...]:
    if not 0 <= cohort < 5:
        raise ValueError("Deterministic cohort must be between zero and four.")
    if len(columns) < 5:
        raise ValueError("Deterministic cohort stresses require at least five assets.")
    ranked = sorted(
        columns,
        key=lambda value: hashlib.sha256(
            json.dumps(
                _axis_identity(value),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).digest(),
    )
    cohort_members = [
        column for position, column in enumerate(ranked) if position % 5 == cohort
    ]
    # Cap omissions at floor(20%) so a 21-name universe retains 17 rather than 16.
    return tuple(cohort_members[: len(columns) // 5])


def _perturbation_universe(
    columns: pd.Index,
    omitted_cohort: int | None,
) -> list[object]:
    if omitted_cohort is None:
        return list(columns)
    omitted = set(_deterministic_cohort_members(columns, omitted_cohort))
    retained = [column for column in columns if column not in omitted]
    if len(retained) < 4:
        raise ValueError("Universe perturbation left fewer than four assets.")
    return retained


def _prepare_parameter_perturbation_inputs(
    prices: pd.DataFrame,
    config: AppConfig,
    *,
    execution_prices: pd.DataFrame | None,
    execution_window_dollar_volume: pd.DataFrame | None,
    corporate_action_split_ratios: pd.DataFrame | None,
    corporate_action_cash_distributions: pd.DataFrame | None,
    borrow_availability: pd.DataFrame | None,
    annual_borrow_rates: pd.DataFrame | None,
    borrow_recalls: pd.DataFrame | None,
) -> tuple[_PreparedPerturbationInputs, ...]:
    prepared: list[_PreparedPerturbationInputs] = []
    for ordinal, specification in enumerate(
        parameter_perturbation_specifications(config), start=1
    ):
        columns = tuple(
            _perturbation_universe(prices.columns, specification.omitted_universe_cohort)
        )
        variant_availability = (
            borrow_availability.loc[:, list(columns)].copy()
            if borrow_availability is not None
            else None
        )
        variant_recalls = (
            borrow_recalls.loc[:, list(columns)].copy()
            if borrow_recalls is not None
            else None
        )
        actual_borrow_stress = bool(
            specification.borrow_scarcity_cohort is not None
            or specification.borrow_recall_cohort is not None
        )
        if actual_borrow_stress and (
            variant_availability is None
            or annual_borrow_rates is None
            or variant_recalls is None
        ):
            raise ValueError(
                "The 25-member robustness family requires complete point-in-time "
                "borrow panels for its scarcity and recall cases."
            )
        if specification.borrow_scarcity_cohort is not None:
            assert variant_availability is not None
            scarce_symbols = list(
                _deterministic_cohort_members(
                    columns, specification.borrow_scarcity_cohort
                )
            )
            variant_availability.loc[:, scarce_symbols] = False
        if specification.borrow_recall_cohort is not None:
            assert variant_availability is not None
            assert variant_recalls is not None
            if len(variant_recalls.index) < 2:
                raise ValueError("Borrow recall perturbation requires at least two sessions.")
            recalled_symbols = list(
                _deterministic_cohort_members(columns, specification.borrow_recall_cohort)
            )
            first_recall = min(252, len(variant_recalls.index) - 1)
            recall_positions = list(
                range(
                    first_recall,
                    len(variant_recalls.index),
                    specification.borrow_recall_interval_sessions,
                )
            )
            recall_rows = variant_recalls.index[recall_positions]
            variant_availability.loc[recall_rows, recalled_symbols] = False
            variant_recalls.loc[recall_rows, recalled_symbols] = True
        prepared.append(
            _PreparedPerturbationInputs(
                specification=specification,
                ordinal=ordinal,
                columns=columns,
                prices=prices.loc[:, list(columns)],
                execution_prices=(
                    execution_prices.loc[:, list(columns)]
                    if execution_prices is not None
                    else None
                ),
                execution_window_dollar_volume=(
                    execution_window_dollar_volume.loc[:, list(columns)]
                    * specification.volume_multiplier
                    if execution_window_dollar_volume is not None
                    else None
                ),
                corporate_action_split_ratios=(
                    corporate_action_split_ratios.loc[:, list(columns)]
                    if corporate_action_split_ratios is not None
                    else None
                ),
                corporate_action_cash_distributions=(
                    corporate_action_cash_distributions.loc[:, list(columns)]
                    if corporate_action_cash_distributions is not None
                    else None
                ),
                borrow_availability=variant_availability,
                annual_borrow_rates=(
                    annual_borrow_rates.loc[:, list(columns)]
                    if annual_borrow_rates is not None
                    else None
                ),
                borrow_recalls=variant_recalls,
            )
        )
    return tuple(prepared)


def _parameter_perturbation_identity_frame_from_prepared(
    prepared: tuple[_PreparedPerturbationInputs, ...],
    config: AppConfig,
    in_sample_fraction: float,
    execution_return_semantics: ExecutionReturnSemantics,
) -> pd.DataFrame:
    suite = parameter_perturbation_preregistration(config)
    suite_hash = parameter_perturbation_specification_hash(config)
    rows: list[dict[str, Any]] = []
    for item, variant_payload in zip(prepared, suite["variants"], strict=True):
        specification = item.specification
        panel_hashes = {
            "Close Prices SHA256": _frame_sha256(item.prices),
            "Execution Prices SHA256": _frame_sha256(item.execution_prices),
            "Execution Window Volume SHA256": _frame_sha256(
                item.execution_window_dollar_volume
            ),
            "Corporate Split Panel SHA256": _frame_sha256(
                item.corporate_action_split_ratios
            ),
            "Corporate Cash Panel SHA256": _frame_sha256(
                item.corporate_action_cash_distributions
            ),
            "Borrow Availability Panel SHA256": _frame_sha256(
                item.borrow_availability
            ),
            "Borrow Rate Panel SHA256": _frame_sha256(item.annual_borrow_rates),
            "Borrow Recall Panel SHA256": _frame_sha256(item.borrow_recalls),
        }
        config_hash = _canonical_sha256(specification.config.to_dict())
        symbols_hash = _canonical_sha256(
            [_axis_identity(value) for value in item.columns]
        )
        variant_specification_hash = _canonical_sha256(variant_payload)
        economic_hash = _canonical_sha256(
            {
                "execution_return_semantics": execution_return_semantics,
                "in_sample_fraction": float(in_sample_fraction),
                "rebalance_interval_sessions": (
                    specification.config.portfolio.rebalance_every
                ),
                "execution_volume_multiplier": specification.volume_multiplier,
                "borrow_rate_multiplier": specification.borrow_rate_multiplier,
                "omitted_universe_cohort": specification.omitted_universe_cohort,
                "borrow_scarcity_cohort": specification.borrow_scarcity_cohort,
                "borrow_recall_cohort": specification.borrow_recall_cohort,
                "borrow_recall_interval_sessions": (
                    specification.borrow_recall_interval_sessions
                ),
                "cost_config": specification.config.to_dict()["costs"],
                "panel_hashes": panel_hashes,
            }
        )
        identity_components = {
            "family_id": PARAMETER_PERTURBATION_FAMILY_ID,
            "suite_sha256": suite_hash,
            "ordinal": item.ordinal,
            "name": specification.name,
            "variant_specification_sha256": variant_specification_hash,
            "variant_config_sha256": config_hash,
            "variant_symbols_sha256": symbols_hash,
            "variant_economic_inputs_sha256": economic_hash,
            "panel_hashes": panel_hashes,
        }
        rows.append(
            {
                "Variant": specification.name,
                "Preregistered Variant Ordinal": item.ordinal,
                "Perturbation Family ID": PARAMETER_PERTURBATION_FAMILY_ID,
                "Perturbation Specification SHA256": suite_hash,
                "Variant Specification SHA256": variant_specification_hash,
                "Variant Config SHA256": config_hash,
                "Variant Symbols SHA256": symbols_hash,
                **panel_hashes,
                "Variant Economic Inputs SHA256": economic_hash,
                "Variant Input Identity SHA256": _canonical_sha256(
                    identity_components
                ),
                "Sensitivity Dimensions": "+".join(specification.dimensions),
                "Mandatory Critical Case": specification.mandatory_critical_case,
                "Input Asset Count": len(item.columns),
                "Base Input Asset Count": len(prepared[0].columns),
                "Universe Retention Fraction": (
                    len(item.columns) / len(prepared[0].columns)
                ),
                "Execution Return Semantics": execution_return_semantics,
                "Rebalance Interval Sessions": (
                    specification.config.portfolio.rebalance_every
                ),
                "Execution Volume Multiplier": specification.volume_multiplier,
                "Borrow Rate Multiplier": specification.borrow_rate_multiplier,
                "Omitted Universe Cohort": (
                    specification.omitted_universe_cohort
                    if specification.omitted_universe_cohort is not None
                    else -1
                ),
                "Borrow Scarcity Cohort": (
                    specification.borrow_scarcity_cohort
                    if specification.borrow_scarcity_cohort is not None
                    else -1
                ),
                "Borrow Recall Cohort": (
                    specification.borrow_recall_cohort
                    if specification.borrow_recall_cohort is not None
                    else -1
                ),
                "Borrow Recall Interval Sessions": (
                    specification.borrow_recall_interval_sessions
                ),
            }
        )
    return pd.DataFrame(rows).set_index("Variant")


def parameter_perturbation_identity_frame(
    prices: pd.DataFrame,
    config: AppConfig,
    in_sample_fraction: float,
    *,
    execution_return_semantics: ExecutionReturnSemantics = "next_close_proxy",
    execution_prices: pd.DataFrame | None = None,
    execution_window_dollar_volume: pd.DataFrame | None = None,
    corporate_action_split_ratios: pd.DataFrame | None = None,
    corporate_action_cash_distributions: pd.DataFrame | None = None,
    borrow_availability: pd.DataFrame | None = None,
    annual_borrow_rates: pd.DataFrame | None = None,
    borrow_recalls: pd.DataFrame | None = None,
) -> pd.DataFrame:
    prepared = _prepare_parameter_perturbation_inputs(
        prices,
        config,
        execution_prices=execution_prices,
        execution_window_dollar_volume=execution_window_dollar_volume,
        corporate_action_split_ratios=corporate_action_split_ratios,
        corporate_action_cash_distributions=corporate_action_cash_distributions,
        borrow_availability=borrow_availability,
        annual_borrow_rates=annual_borrow_rates,
        borrow_recalls=borrow_recalls,
    )
    return _parameter_perturbation_identity_frame_from_prepared(
        prepared,
        config,
        in_sample_fraction,
        execution_return_semantics,
    )


def run_parameter_perturbations(
    prices: pd.DataFrame,
    config: AppConfig,
    in_sample_fraction: float,
    *,
    execution_return_semantics: ExecutionReturnSemantics = "next_close_proxy",
    execution_prices: pd.DataFrame | None = None,
    execution_window_dollar_volume: pd.DataFrame | None = None,
    corporate_action_split_ratios: pd.DataFrame | None = None,
    corporate_action_cash_distributions: pd.DataFrame | None = None,
    borrow_availability: pd.DataFrame | None = None,
    annual_borrow_rates: pd.DataFrame | None = None,
    borrow_recalls: pd.DataFrame | None = None,
) -> pd.DataFrame:
    prepared = _prepare_parameter_perturbation_inputs(
        prices,
        config,
        execution_prices=execution_prices,
        execution_window_dollar_volume=execution_window_dollar_volume,
        corporate_action_split_ratios=corporate_action_split_ratios,
        corporate_action_cash_distributions=corporate_action_cash_distributions,
        borrow_availability=borrow_availability,
        annual_borrow_rates=annual_borrow_rates,
        borrow_recalls=borrow_recalls,
    )
    identity_frame = _parameter_perturbation_identity_frame_from_prepared(
        prepared,
        config,
        in_sample_fraction,
        execution_return_semantics,
    )
    rows: list[dict[str, Any]] = []
    split = split_index(prices.index, in_sample_fraction)
    oos_index = prices.index[split:]
    for item in prepared:
        specification = item.specification
        name = specification.name
        variant = specification.config
        if "execution_window_dollar_volume" in inspect.signature(run_backtest).parameters:
            result = run_backtest(
                item.prices,
                variant,
                execution_return_semantics=execution_return_semantics,
                execution_prices=item.execution_prices,
                execution_window_dollar_volume=item.execution_window_dollar_volume,
                corporate_action_split_ratios=item.corporate_action_split_ratios,
                corporate_action_cash_distributions=(
                    item.corporate_action_cash_distributions
                ),
                borrow_availability=item.borrow_availability,
                annual_borrow_rates=item.annual_borrow_rates,
                borrow_recalls=item.borrow_recalls,
                borrow_rate_stress_multiplier=(
                    specification.borrow_rate_multiplier
                ),
            )
        else:
            if any(
                value is not None
                for value in (
                    corporate_action_split_ratios,
                    corporate_action_cash_distributions,
                    borrow_availability,
                    annual_borrow_rates,
                    borrow_recalls,
                )
            ):
                raise ValueError(
                    "The backtest does not consume sealed corporate-action/borrow evidence."
                )
            result = run_backtest(
                item.prices,
                variant,
                execution_return_semantics=execution_return_semantics,
                execution_prices=item.execution_prices,
                daily_dollar_volume=item.execution_window_dollar_volume,
            )
        metrics = metrics_from_returns(
            result.strategy_returns.reindex(oos_index),
            result.diagnostics.reindex(oos_index),
        )
        rows.append(
            {
                "Variant": name,
                **identity_frame.loc[name].to_dict(),
                "OOS CAGR": metrics.get("CAGR"),
                "OOS Max Drawdown": metrics.get("Max Drawdown"),
                "OOS Sharpe": metrics.get("Sharpe Ratio"),
                "OOS Calmar": metrics.get("Calmar Ratio"),
                "Max Gross": metrics.get("Maximum Gross Exposure"),
                "Configured Max Gross": variant.portfolio.max_gross_leverage,
                "Research Path Valid": metrics.get("Research Path Valid", False),
                "Liquidity Path Valid": metrics.get("Liquidity Path Valid", False),
                "Liquidity Data Breaches": metrics.get("Liquidity Data Breaches", 1),
                "Participation Limit Breaches": metrics.get(
                    "Participation Limit Breaches", 1
                ),
                "Data Integrity Breaches": metrics.get("Data Integrity Breaches", 1),
                "Beta Data Breaches": metrics.get("Beta Data Breaches", 1),
                "Hard Drawdown Breaches": metrics.get(
                    "Hard Drawdown Breaches", 1
                ),
                "Stale Signal Trade Breaches": metrics.get(
                    "Stale Signal Trade Breaches", 1
                ),
                "Minimum Eligible Asset Count": metrics.get(
                    "Minimum Eligible Asset Count", 0
                ),
            }
        )
    frame = pd.DataFrame(rows).set_index("Variant")
    base_eligible_assets = float(
        frame.loc[prepared[0].specification.name, "Minimum Eligible Asset Count"]
    )
    frame["Base Minimum Eligible Asset Count"] = base_eligible_assets
    frame["Effective Eligible Retention Fraction"] = (
        frame["Minimum Eligible Asset Count"] / base_eligible_assets
        if np.isfinite(base_eligible_assets) and base_eligible_assets > 0.0
        else float("nan")
    )
    return frame


def parameter_perturbation_pass_mask(
    perturbations: pd.DataFrame,
    *,
    max_drawdown: float,
    target_cagr: float = MIN_PROJECT_TARGET_CAGR,
) -> pd.Series:
    """Return a fail-closed economic, quality, and path-integrity stability mask.

    A variant must retain at least 75% of the non-dilutable 60% project CAGR target
    (or 75% of a stricter configured target) and a Sharpe of at least one. Merely
    remaining a few basis points above zero is not evidence that a 60/15 result is
    robust to nearby specifications. The certified base must still contain at least
    20 assets, while declared universe omissions may retain 80% (16 of a 20-name
    base); this makes breadth sensitivity explicit without making the minimum valid
    base mechanically incapable of completing the family.
    """
    required = {
        "OOS CAGR",
        "OOS Sharpe",
        "OOS Max Drawdown",
        "Max Gross",
        "Configured Max Gross",
        "Research Path Valid",
        "Liquidity Path Valid",
        "Liquidity Data Breaches",
        "Participation Limit Breaches",
        "Data Integrity Breaches",
        "Beta Data Breaches",
        "Hard Drawdown Breaches",
        "Stale Signal Trade Breaches",
        "Input Asset Count",
        "Base Input Asset Count",
        "Universe Retention Fraction",
        "Minimum Eligible Asset Count",
        "Base Minimum Eligible Asset Count",
        "Effective Eligible Retention Fraction",
    }
    if perturbations.empty or not required.issubset(perturbations.columns):
        return pd.Series(False, index=perturbations.index, dtype=bool)
    try:
        target_cagr_value = float(target_cagr)
        requested_max_drawdown = float(max_drawdown)
    except (TypeError, ValueError):
        return pd.Series(False, index=perturbations.index, dtype=bool)
    if (
        not np.isfinite(target_cagr_value)
        or target_cagr_value <= 0.0
        or not np.isfinite(requested_max_drawdown)
        or requested_max_drawdown <= 0.0
    ):
        return pd.Series(False, index=perturbations.index, dtype=bool)
    required_cagr = (
        max(target_cagr_value, MIN_PROJECT_TARGET_CAGR)
        * MIN_PERTURBATION_CAGR_TARGET_RETENTION
    )
    allowed_drawdown = min(
        requested_max_drawdown,
        MAX_PROJECT_TARGET_DRAWDOWN,
    )
    numeric_columns = {
        column: pd.to_numeric(perturbations[column], errors="coerce")
        for column in (
            "OOS CAGR",
            "OOS Sharpe",
            "OOS Max Drawdown",
            "Max Gross",
            "Configured Max Gross",
            "Liquidity Data Breaches",
            "Participation Limit Breaches",
            "Data Integrity Breaches",
            "Beta Data Breaches",
            "Hard Drawdown Breaches",
            "Stale Signal Trade Breaches",
            "Input Asset Count",
            "Base Input Asset Count",
            "Universe Retention Fraction",
            "Minimum Eligible Asset Count",
            "Base Minimum Eligible Asset Count",
            "Effective Eligible Retention Fraction",
        )
    }
    finite_numeric = pd.Series(True, index=perturbations.index, dtype=bool)
    for values in numeric_columns.values():
        finite_numeric &= pd.Series(
            np.isfinite(values.to_numpy(dtype=float)),
            index=perturbations.index,
        )

    input_count = numeric_columns["Input Asset Count"]
    base_input_count = numeric_columns["Base Input Asset Count"]
    reported_input_retention = numeric_columns["Universe Retention Fraction"]
    eligible_count = numeric_columns["Minimum Eligible Asset Count"]
    base_eligible_count = numeric_columns["Base Minimum Eligible Asset Count"]
    reported_eligible_retention = numeric_columns[
        "Effective Eligible Retention Fraction"
    ]
    calculated_input_retention = input_count.div(base_input_count.replace(0.0, np.nan))
    calculated_eligible_retention = eligible_count.div(
        base_eligible_count.replace(0.0, np.nan)
    )
    count_fields_are_integral = (
        input_count.eq(np.floor(input_count))
        & base_input_count.eq(np.floor(base_input_count))
        & eligible_count.eq(np.floor(eligible_count))
        & base_eligible_count.eq(np.floor(base_eligible_count))
    )
    retention_fields_are_consistent = pd.Series(
        np.isclose(
            reported_input_retention.to_numpy(dtype=float),
            calculated_input_retention.to_numpy(dtype=float),
            rtol=0.0,
            atol=1e-12,
            equal_nan=False,
        )
        & np.isclose(
            reported_eligible_retention.to_numpy(dtype=float),
            calculated_eligible_retention.to_numpy(dtype=float),
            rtol=0.0,
            atol=1e-12,
            equal_nan=False,
        ),
        index=perturbations.index,
    )
    strict_research_path = perturbations["Research Path Valid"].map(
        lambda value: isinstance(value, (bool, np.bool_)) and bool(value)
    )
    strict_liquidity_path = perturbations["Liquidity Path Valid"].map(
        lambda value: isinstance(value, (bool, np.bool_)) and bool(value)
    )
    return (
        finite_numeric
        & numeric_columns["OOS CAGR"].ge(required_cagr)
        & numeric_columns["OOS Sharpe"].ge(MIN_PERTURBATION_SHARPE)
        & numeric_columns["OOS Max Drawdown"].ge(-allowed_drawdown)
        & numeric_columns["Max Gross"].ge(0.0)
        & numeric_columns["Configured Max Gross"].gt(0.0)
        & numeric_columns["Max Gross"].le(
            numeric_columns["Configured Max Gross"] + 1e-8
        )
        & strict_research_path
        & strict_liquidity_path
        & numeric_columns["Liquidity Data Breaches"].eq(0)
        & numeric_columns["Participation Limit Breaches"].eq(0)
        & numeric_columns["Data Integrity Breaches"].eq(0)
        & numeric_columns["Beta Data Breaches"].eq(0)
        & numeric_columns["Hard Drawdown Breaches"].eq(0)
        & numeric_columns["Stale Signal Trade Breaches"].eq(0)
        & count_fields_are_integral
        & retention_fields_are_consistent
        & base_input_count.ge(
            MIN_CERTIFIED_ELIGIBLE_ASSET_COUNT
        )
        & input_count.le(base_input_count)
        & input_count.ge(4)
        & reported_input_retention.ge(
            MIN_PERTURBATION_UNIVERSE_RETENTION
        )
        & base_eligible_count.ge(
            MIN_CERTIFIED_ELIGIBLE_ASSET_COUNT
        )
        & base_eligible_count.le(base_input_count)
        & eligible_count.le(input_count)
        & eligible_count.ge(4)
        & reported_eligible_retention.ge(
            MIN_PERTURBATION_UNIVERSE_RETENTION
        )
    ).astype(bool)


def parameter_perturbation_gate(
    perturbations: pd.DataFrame,
    config: AppConfig,
    *,
    max_drawdown: float,
    prices: pd.DataFrame,
    in_sample_fraction: float,
    target_cagr: float = MIN_PROJECT_TARGET_CAGR,
    execution_return_semantics: ExecutionReturnSemantics = "next_close_proxy",
    execution_prices: pd.DataFrame | None = None,
    execution_window_dollar_volume: pd.DataFrame | None = None,
    corporate_action_split_ratios: pd.DataFrame | None = None,
    corporate_action_cash_distributions: pd.DataFrame | None = None,
    borrow_availability: pd.DataFrame | None = None,
    annual_borrow_rates: pd.DataFrame | None = None,
    borrow_recalls: pd.DataFrame | None = None,
) -> tuple[bool, float, pd.Series]:
    """Evaluate only a complete result for the exact preregistered 25-member suite.

    This outer gate prevents a partial cache entry, duplicated favorable row, reordered
    subset, or result from an older suite/configuration from earning an 80% pass rate.
    The returned rate is NaN when suite completeness/identity is not proven.
    """

    false_mask = pd.Series(False, index=perturbations.index, dtype=bool)
    specifications = parameter_perturbation_specifications(config)
    expected_names = [specification.name for specification in specifications]
    try:
        expected_identity = parameter_perturbation_identity_frame(
            prices,
            config,
            in_sample_fraction,
            execution_return_semantics=execution_return_semantics,
            execution_prices=execution_prices,
            execution_window_dollar_volume=execution_window_dollar_volume,
            corporate_action_split_ratios=corporate_action_split_ratios,
            corporate_action_cash_distributions=corporate_action_cash_distributions,
            borrow_availability=borrow_availability,
            annual_borrow_rates=annual_borrow_rates,
            borrow_recalls=borrow_recalls,
        )
    except (KeyError, TypeError, ValueError):
        return False, float("nan"), false_mask
    identity_columns = set(expected_identity.columns)
    complete = bool(
        len(perturbations) == PARAMETER_PERTURBATION_VARIANT_COUNT
        and perturbations.index.is_unique
        and list(perturbations.index) == expected_names
        and identity_columns.issubset(perturbations.columns)
    )
    if not complete:
        return False, float("nan"), false_mask

    identity_valid = True
    for column in expected_identity.columns:
        expected_values = expected_identity[column]
        actual_values = perturbations[column]
        if pd.api.types.is_bool_dtype(expected_values.dtype):
            matches = actual_values.map(
                lambda value: isinstance(value, (bool, np.bool_))
            ) & actual_values.eq(expected_values)
        elif pd.api.types.is_numeric_dtype(expected_values.dtype):
            numeric = pd.to_numeric(actual_values, errors="coerce")
            matches = pd.Series(
                np.isclose(
                    numeric.to_numpy(dtype=float),
                    expected_values.to_numpy(dtype=float),
                    rtol=0.0,
                    atol=0.0,
                    equal_nan=False,
                ),
                index=perturbations.index,
            )
        else:
            matches = actual_values.eq(expected_values)
        if not bool(matches.all()):
            identity_valid = False
            break
    if not identity_valid:
        return False, float("nan"), false_mask

    # Result-derived breadth uses the Base row as its denominator.  It is not an
    # input identity, so verify it independently before any pass rate is computed;
    # otherwise a cached result could replace a 25-name base denominator with the
    # minimum 20 and make a 16-name universe stress appear to retain 80% breadth.
    try:
        eligible_counts = pd.to_numeric(
            perturbations["Minimum Eligible Asset Count"], errors="coerce"
        )
        declared_base_counts = pd.to_numeric(
            perturbations["Base Minimum Eligible Asset Count"], errors="coerce"
        )
        base_eligible_count = float(eligible_counts.loc[expected_names[0]])
    except (KeyError, TypeError, ValueError):
        return False, float("nan"), false_mask
    base_breadth_valid = bool(
        np.isfinite(base_eligible_count)
        and np.isfinite(declared_base_counts.to_numpy(dtype=float)).all()
        and declared_base_counts.eq(base_eligible_count).all()
    )
    if not base_breadth_valid:
        return False, float("nan"), false_mask

    mask = parameter_perturbation_pass_mask(
        perturbations,
        max_drawdown=max_drawdown,
        target_cagr=target_cagr,
    )
    pass_rate = float(mask.sum() / PARAMETER_PERTURBATION_VARIANT_COUNT)
    mandatory_names = [
        specification.name
        for specification in specifications
        if specification.mandatory_critical_case
    ]
    mandatory_passed = bool(mask.reindex(mandatory_names, fill_value=False).all())
    strata_passed = True
    for stratum, minimum_rate in PERTURBATION_CRITICAL_STRATUM_MIN_PASS_RATE.items():
        names = [
            specification.name
            for specification in specifications
            if stratum in specification.dimensions
        ]
        required = int(np.ceil(len(names) * minimum_rate))
        if not names or int(mask.reindex(names, fill_value=False).sum()) < required:
            strata_passed = False
            break
    passed = bool(
        pass_rate >= MIN_PERTURBATION_PASS_RATE
        and mandatory_passed
        and strata_passed
    )
    return passed, pass_rate, mask


def certification_table(
    oos_metrics: dict[str, Any],
    bootstrap: BootstrapSummary,
    double_cost_metrics: dict[str, Any],
    rolling_pass_rate: float,
    psr_probability: float,
    max_gross_limit: float,
    target_cagr: float,
    max_drawdown: float,
    confidence: float,
    trial_count: int = 1,
    bootstrap_block_size: int = 0,
    minimum_cost_coverage: float = 2.0,
    minimum_break_even_cost_multiple: float = 2.0,
    corporate_action_model_consumed: bool = False,
    execution_window_liquidity_model_consumed: bool = False,
    point_in_time_borrow_model_consumed: bool = False,
    rebalance_every: int = 1,
) -> tuple[bool, pd.DataFrame]:
    required_calmar = target_cagr / max(abs(max_drawdown), 1e-9)
    sampling_plan_hash = str(bootstrap.sampling_plan_sha256)
    sampling_plan_hash_valid = bool(
        len(sampling_plan_hash) == 64
        and all(character in "0123456789abcdef" for character in sampling_plan_hash)
    )
    path_bootstrap_identity_valid = bool(
        bootstrap.method_id == PATH_AWARE_BOOTSTRAP_METHOD_ID
        and bootstrap.policy_sha256 == PATH_AWARE_BOOTSTRAP_POLICY_SHA256
        and bootstrap.seed == PATH_AWARE_BOOTSTRAP_SEED
        and bootstrap.paths == PATH_AWARE_BOOTSTRAP_PATHS
        and bootstrap.block_size == bootstrap_block_size
        and bootstrap.warmup_days >= PATH_AWARE_BOOTSTRAP_MIN_WARMUP_DAYS
        and bootstrap.state_machine_rerun
        and bootstrap.failed_paths == 0
        and np.isfinite(bootstrap.valid_path_fraction)
        and sampling_plan_hash_valid
    )
    max_gross_observed = float(oos_metrics.get("Maximum Gross Exposure", float("inf")))
    hard_breaches = int(oos_metrics.get("Hard Drawdown Breaches", 1))
    data_integrity_breaches = int(oos_metrics.get("Data Integrity Breaches", 1))
    beta_data_breaches = int(oos_metrics.get("Beta Data Breaches", 1))
    research_path_valid = bool(oos_metrics.get("Research Path Valid", False))
    liquidity_model_active = bool(oos_metrics.get("Liquidity Model Active", False))
    liquidity_data_breaches = int(oos_metrics.get("Liquidity Data Breaches", 1))
    participation_breaches = int(
        oos_metrics.get("Participation Limit Breaches", 1)
    )
    realized_volume_breaches = int(
        oos_metrics.get("Realized Volume Data Breaches", 1)
    )
    realized_participation_breaches = int(
        oos_metrics.get("Realized Participation Limit Breaches", 1)
    )
    maximum_realized_participation = float(
        oos_metrics.get("Maximum Realized Participation Rate", float("nan"))
    )
    execution_residual_breaches = int(
        oos_metrics.get("Execution Residual Breaches", 1)
    )
    canceled_notional_fraction = float(
        oos_metrics.get("Canceled Notional Fraction", float("inf"))
    )
    liquidity_path_valid = bool(oos_metrics.get("Liquidity Path Valid", False))
    impact_coefficient = float(
        oos_metrics.get("Square-Root Impact Coefficient", float("nan"))
    )
    configured_participation_limit = float(
        oos_metrics.get("Configured Participation Limit", float("nan"))
    )
    adv_lookback_days = float(
        oos_metrics.get("ADV Lookback Days", float("nan"))
    )
    impact_volatility_floor = float(
        oos_metrics.get("Impact Daily Volatility Floor", float("nan"))
    )
    eligible_asset_count = int(oos_metrics.get("Minimum Eligible Asset Count", 0))
    configured_linear_cost_bps = float(
        oos_metrics.get("Configured Linear Transaction Cost Bps", float("nan"))
    )
    configured_borrow_rate = float(
        oos_metrics.get("Configured Annual Short Borrow Rate", float("nan"))
    )
    configured_financing_rate = float(
        oos_metrics.get("Configured Annual Financing Rate", float("nan"))
    )
    carry_day_count_convention = str(
        oos_metrics.get("Carry Day Count Convention", "missing")
    )
    carry_day_count_valid = bool(oos_metrics.get("Carry Day Count Valid", False))
    stale_signal_breaches = int(oos_metrics.get("Stale Signal Trade Breaches", 1))
    double_research_path_valid = bool(
        double_cost_metrics.get("Research Path Valid", False)
    )
    double_liquidity_path_valid = bool(
        double_cost_metrics.get("Liquidity Path Valid", False)
    )
    double_liquidity_breaches = int(
        double_cost_metrics.get("Liquidity Data Breaches", 1)
    )
    double_participation_breaches = int(
        double_cost_metrics.get("Participation Limit Breaches", 1)
    )
    double_realized_volume_breaches = int(
        double_cost_metrics.get("Realized Volume Data Breaches", 1)
    )
    double_realized_participation_breaches = int(
        double_cost_metrics.get("Realized Participation Limit Breaches", 1)
    )
    double_maximum_realized_participation = float(
        double_cost_metrics.get(
            "Maximum Realized Participation Rate", float("nan")
        )
    )
    double_configured_participation_limit = float(
        double_cost_metrics.get("Configured Participation Limit", float("nan"))
    )
    double_execution_residual_breaches = int(
        double_cost_metrics.get("Execution Residual Breaches", 1)
    )
    double_canceled_notional_fraction = float(
        double_cost_metrics.get("Canceled Notional Fraction", float("inf"))
    )
    double_data_breaches = int(double_cost_metrics.get("Data Integrity Breaches", 1))
    double_beta_breaches = int(double_cost_metrics.get("Beta Data Breaches", 1))
    double_stale_signal_breaches = int(
        double_cost_metrics.get("Stale Signal Trade Breaches", 1)
    )
    double_carry_day_count_convention = str(
        double_cost_metrics.get("Carry Day Count Convention", "missing")
    )
    double_carry_day_count_valid = bool(
        double_cost_metrics.get("Carry Day Count Valid", False)
    )
    double_path_valid = bool(
        double_research_path_valid
        and double_liquidity_path_valid
        and double_liquidity_breaches == 0
        and double_participation_breaches == 0
        and double_realized_volume_breaches == 0
        and double_realized_participation_breaches == 0
        and np.isfinite(double_maximum_realized_participation)
        and np.isfinite(double_configured_participation_limit)
        and double_maximum_realized_participation
        <= double_configured_participation_limit + 1e-12
        and double_execution_residual_breaches == 0
        and np.isfinite(double_canceled_notional_fraction)
        and double_canceled_notional_fraction <= 1e-12
        and double_data_breaches == 0
        and double_beta_breaches == 0
        and double_stale_signal_breaches == 0
        and double_carry_day_count_valid
        and double_carry_day_count_convention == CARRY_DAY_COUNT_CONVENTION
    )
    cost_coverage = float(oos_metrics.get("Cost Coverage Ratio", float("nan")))
    break_even_cost_bps = float(
        oos_metrics.get("Break-Even Transaction Cost Bps", float("nan"))
    )
    modeled_cost_bps = float(
        oos_metrics.get("Modeled Transaction Cost Bps", float("nan"))
    )
    required_break_even_bps = modeled_cost_bps * minimum_break_even_cost_multiple

    rows = [
        (
            "Governed deployment cadence parity",
            rebalance_every,
            "= 1 session",
            isinstance(rebalance_every, (int, np.integer))
            and not isinstance(rebalance_every, (bool, np.bool_))
            and int(rebalance_every) == 1,
        ),
        (
            "Split/share and cash-distribution accounting consumed",
            bool(corporate_action_model_consumed),
            "Yes; complete signed point-in-time panel",
            bool(corporate_action_model_consumed),
        ),
        (
            "Execution-window liquidity evidence consumed",
            bool(execution_window_liquidity_model_consumed),
            "Yes; 09:30-09:35 dollar notional, not full-session ADV",
            bool(execution_window_liquidity_model_consumed),
        ),
        (
            "Point-in-time security/date borrow evidence consumed",
            bool(point_in_time_borrow_model_consumed),
            "Yes; availability, rate, and recall handled",
            bool(point_in_time_borrow_model_consumed),
        ),
        (
            "Project CAGR target not diluted",
            target_cagr,
            f">= {MIN_PROJECT_TARGET_CAGR:.0%}",
            target_cagr >= MIN_PROJECT_TARGET_CAGR,
        ),
        (
            "Project drawdown target not diluted",
            max_drawdown,
            f"<= {MAX_PROJECT_TARGET_DRAWDOWN:.0%}",
            0.0 < max_drawdown <= MAX_PROJECT_TARGET_DRAWDOWN,
        ),
        (
            "Minimum effective eligible OOS asset breadth",
            eligible_asset_count,
            f">= {MIN_CERTIFIED_ELIGIBLE_ASSET_COUNT}",
            eligible_asset_count >= MIN_CERTIFIED_ELIGIBLE_ASSET_COUNT,
        ),
        (
            "Conservative bootstrap block size",
            bootstrap_block_size,
            f">= {MIN_CERTIFIED_BOOTSTRAP_BLOCK_SIZE} sessions",
            bootstrap_block_size >= MIN_CERTIFIED_BOOTSTRAP_BLOCK_SIZE,
        ),
        (
            "Path-aware bootstrap state-machine identity",
            (
                f"{bootstrap.method_id}; seed={bootstrap.seed}; "
                f"paths={bootstrap.paths}; valid={bootstrap.valid_path_fraction:.1%}"
            ),
            (
                f"{PATH_AWARE_BOOTSTRAP_METHOD_ID}; fixed seed/policy; "
                f"{PATH_AWARE_BOOTSTRAP_PATHS} complete state-machine paths"
            ),
            path_bootstrap_identity_valid,
        ),
        (
            "Chronological holdout CAGR",
            float(oos_metrics.get("CAGR", float("nan"))),
            f">= {target_cagr:.1%}",
            float(oos_metrics.get("CAGR", float("-inf"))) >= target_cagr,
        ),
        (
            "Chronological holdout max drawdown",
            float(oos_metrics.get("Max Drawdown", float("nan"))),
            f">= {-abs(max_drawdown):.1%}",
            float(oos_metrics.get("Max Drawdown", float("-inf"))) >= -abs(max_drawdown),
        ),
        (
            "Chronological holdout Calmar",
            float(oos_metrics.get("Calmar Ratio", float("nan"))),
            f">= {required_calmar:.2f}",
            float(oos_metrics.get("Calmar Ratio", float("-inf"))) >= required_calmar,
        ),
        (
            "Path-aware bootstrap lower 95% bound for both targets",
            bootstrap.probability_both_targets_lower_95,
            f">= {confidence:.0%}",
            (
                path_bootstrap_identity_valid
                and np.isfinite(bootstrap.probability_both_targets_lower_95)
                and bootstrap.probability_both_targets_lower_95 >= confidence
            ),
        ),
        (
            (
                f"Deflated Sharpe probability ({trial_count} trials)"
                if trial_count > 1
                else "Probability Sharpe is positive (HAC heuristic)"
            ),
            psr_probability,
            f">= {confidence:.0%}",
            np.isfinite(psr_probability) and psr_probability >= confidence,
        ),
        (
            "Rolling one-year target pass rate",
            rolling_pass_rate,
            ">= 80%",
            np.isfinite(rolling_pass_rate) and rolling_pass_rate >= 0.80,
        ),
        (
            "Double-cost CAGR remains positive",
            float(double_cost_metrics.get("CAGR", float("nan"))),
            "> 0%",
            float(double_cost_metrics.get("CAGR", float("-inf"))) > 0.0,
        ),
        (
            "Double-cost max drawdown",
            float(double_cost_metrics.get("Max Drawdown", float("nan"))),
            f">= {-abs(max_drawdown):.1%}",
            float(double_cost_metrics.get("Max Drawdown", float("-inf"))) >= -abs(max_drawdown),
        ),
        (
            "Double-cost research and liquidity path valid",
            double_path_valid,
            (
                "Yes; zero data, beta, ADV, realized-fill, residual, "
                "participation, and stale-signal breaches"
            ),
            double_path_valid,
        ),
        (
            "Gross return covers all modeled costs",
            cost_coverage,
            f">= {minimum_cost_coverage:.2f}x",
            np.isfinite(cost_coverage) and cost_coverage >= minimum_cost_coverage,
        ),
        (
            "Break-even transaction cost margin",
            break_even_cost_bps,
            (
                f">= {required_break_even_bps:.2f} bps"
                if np.isfinite(required_break_even_bps)
                else f">= {minimum_break_even_cost_multiple:.2f}x modeled cost"
            ),
            (
                np.isfinite(break_even_cost_bps)
                and np.isfinite(required_break_even_bps)
                and break_even_cost_bps >= required_break_even_bps
            ),
        ),
        (
            "Gross leverage cap respected",
            max_gross_observed,
            f"<= {max_gross_limit:.2f}x",
            max_gross_observed <= max_gross_limit + 1e-8,
        ),
        (
            "Liquidity and square-root impact model active",
            (
                f"active; Y={impact_coefficient:.4g}"
                if liquidity_model_active and np.isfinite(impact_coefficient)
                else "inactive"
            ),
            f"Active with Y >= {MIN_CERTIFIED_IMPACT_COEFFICIENT:.2f}",
            (
                liquidity_model_active
                and np.isfinite(impact_coefficient)
                and impact_coefficient >= MIN_CERTIFIED_IMPACT_COEFFICIENT
            ),
        ),
        (
            "Conservative lagged-ADV lookback",
            adv_lookback_days,
            f">= {MIN_CERTIFIED_ADV_LOOKBACK_DAYS} sessions",
            (
                np.isfinite(adv_lookback_days)
                and adv_lookback_days >= MIN_CERTIFIED_ADV_LOOKBACK_DAYS
            ),
        ),
        (
            "Conservative configured participation limit",
            configured_participation_limit,
            f"<= {MAX_CERTIFIED_PARTICIPATION_RATE:.1%}",
            (
                np.isfinite(configured_participation_limit)
                and 0.0 < configured_participation_limit
                <= MAX_CERTIFIED_PARTICIPATION_RATE
            ),
        ),
        (
            "Conservative impact volatility floor",
            impact_volatility_floor,
            f">= {MIN_CERTIFIED_IMPACT_VOLATILITY_FLOOR:.1%} daily",
            (
                np.isfinite(impact_volatility_floor)
                and impact_volatility_floor
                >= MIN_CERTIFIED_IMPACT_VOLATILITY_FLOOR
            ),
        ),
        (
            "Conservative configured linear transaction cost",
            configured_linear_cost_bps,
            f">= {MIN_CERTIFIED_LINEAR_TRANSACTION_COST_BPS:.1f} bps",
            (
                np.isfinite(configured_linear_cost_bps)
                and configured_linear_cost_bps
                >= MIN_CERTIFIED_LINEAR_TRANSACTION_COST_BPS
            ),
        ),
        (
            "Conservative configured short-borrow rate",
            configured_borrow_rate,
            f">= {MIN_CERTIFIED_ANNUAL_SHORT_BORROW_RATE:.1%} annual",
            (
                np.isfinite(configured_borrow_rate)
                and configured_borrow_rate
                >= MIN_CERTIFIED_ANNUAL_SHORT_BORROW_RATE
            ),
        ),
        (
            "Conservative configured financing rate",
            configured_financing_rate,
            f">= {MIN_CERTIFIED_ANNUAL_FINANCING_RATE:.1%} annual",
            (
                np.isfinite(configured_financing_rate)
                and configured_financing_rate
                >= MIN_CERTIFIED_ANNUAL_FINANCING_RATE
            ),
        ),
        (
            "Actual elapsed-day carry convention",
            carry_day_count_convention,
            f"= {CARRY_DAY_COUNT_CONVENTION}; realized fractions internally valid",
            (
                carry_day_count_valid
                and carry_day_count_convention == CARRY_DAY_COUNT_CONVENTION
            ),
        ),
        (
            "No traded asset missing lagged ADV",
            liquidity_data_breaches,
            "= 0",
            liquidity_data_breaches == 0 and liquidity_path_valid,
        ),
        (
            "Daily participation cap respected",
            participation_breaches,
            "= 0",
            participation_breaches == 0 and liquidity_path_valid,
        ),
        (
            "No submitted trade missing realized window volume",
            realized_volume_breaches,
            "= 0",
            realized_volume_breaches == 0 and liquidity_path_valid,
        ),
        (
            "Realized POV participation cap respected",
            maximum_realized_participation,
            f"<= {configured_participation_limit:.1%}; zero breach rows",
            (
                realized_participation_breaches == 0
                and np.isfinite(maximum_realized_participation)
                and np.isfinite(configured_participation_limit)
                and maximum_realized_participation
                <= configured_participation_limit + 1e-12
                and liquidity_path_valid
            ),
        ),
        (
            "No canceled execution residual",
            canceled_notional_fraction,
            "= 0; residuals are never modeled as fills",
            (
                execution_residual_breaches == 0
                and np.isfinite(canceled_notional_fraction)
                and canceled_notional_fraction <= 1e-12
                and liquidity_path_valid
            ),
        ),
        (
            "Liquidity path remained capacity-valid",
            liquidity_path_valid,
            "Yes",
            liquidity_path_valid,
        ),
        (
            "No hard drawdown breach",
            hard_breaches,
            "= 0",
            hard_breaches == 0,
        ),
        (
            "No held-asset pricing integrity breach",
            data_integrity_breaches,
            "= 0",
            data_integrity_breaches == 0 and research_path_valid,
        ),
        (
            "No held asset with unknown beta",
            beta_data_breaches,
            "= 0",
            beta_data_breaches == 0 and research_path_valid,
        ),
        (
            "No stale-signal risk increase",
            stale_signal_breaches,
            "= 0",
            stale_signal_breaches == 0 and research_path_valid,
        ),
        (
            "Research path remained price-valid",
            research_path_valid,
            "Yes",
            research_path_valid,
        ),
    ]
    table = pd.DataFrame(rows, columns=["Test", "Observed", "Requirement", "Pass"]).set_index("Test")
    return bool(table["Pass"].all()), table
