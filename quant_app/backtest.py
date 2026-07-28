from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Literal

import numpy as np
import pandas as pd

from .config import AppConfig, CostConfig
from .data import validate_daily_dollar_volume_frame, validate_daily_session_index
from .signals import SignalBundle, build_signal_bundle

TRADING_DAYS = 252
CARRY_DAY_COUNT_CONVENTION = "ACT/365.25"
CARRY_DAYS_PER_YEAR = 365.25
MIN_SIGNAL_PRICE_HISTORY = 252
TRAILING_COVARIANCE_RETURN_COUNT = 251
ExecutionReturnSemantics = Literal[
    "close_to_close",
    "next_close_proxy",
    "next_open_to_open",
]
VALID_EXECUTION_RETURN_SEMANTICS = frozenset(
    {"close_to_close", "next_close_proxy", "next_open_to_open"}
)


def _carry_elapsed_time(index: pd.Index) -> pd.DataFrame:
    """Return fixed-09:35 session gaps under the governed ACT/365.25 basis.

    The index identifies execution sessions.  Because every modeled fill occurs at
    the same local 09:35 cutoff, calendar-date differences are the elapsed accrual
    days; weekends and holidays are therefore retained while DST clock shifts do not
    create fractional-day artifacts.  The first row has no prior holding interval.
    """
    try:
        sessions = pd.DatetimeIndex(index)
    except (TypeError, ValueError) as exc:
        raise ValueError("Execution sessions must use valid timestamps.") from exc
    if sessions.hasnans:
        raise ValueError("Execution sessions contain missing timestamps.")
    if sessions.has_duplicates:
        raise ValueError("Execution sessions must not contain duplicate timestamps.")
    if not sessions.is_monotonic_increasing:
        raise ValueError("Execution sessions must be strictly increasing.")
    session_dates = sessions.tz_localize(None).normalize()
    elapsed_days = pd.Series(session_dates, index=index).diff().dt.days.astype(float)
    elapsed_days.iloc[0] = 0.0
    if not np.isfinite(elapsed_days.to_numpy(dtype=float)).all() or bool(
        elapsed_days.iloc[1:].le(0.0).any()
    ):
        raise ValueError("Execution-session elapsed calendar days must be positive.")
    return pd.DataFrame(
        {
            "elapsed_calendar_days": elapsed_days,
            "carry_year_fraction": elapsed_days.div(CARRY_DAYS_PER_YEAR),
        },
        index=index,
    )


def trailing_ewma_covariance(
    returns: pd.DataFrame,
    halflife: int,
) -> np.ndarray:
    """Return the finite-window EWMA used by both research and deployment.

    The governed live planner has 252 execution-window price observations, hence 251
    completed price-to-price returns.  Reinitializing at the left edge is intentional:
    it makes a plan reproducible from its self-contained trailing evidence rather than
    depending on an unrecorded expanding covariance state.
    """

    if len(returns) > TRAILING_COVARIANCE_RETURN_COUNT:
        returns = returns.tail(TRAILING_COVARIANCE_RETURN_COUNT)
    n_assets = returns.shape[1]
    prior = np.eye(n_assets) * (0.15 / np.sqrt(TRADING_DAYS)) ** 2
    values = returns.to_numpy(dtype=float)
    if values.size == 0:
        return prior
    if not np.isfinite(values).all():
        raise ValueError(
            "Covariance returns must be complete and finite; zero-imputing missing "
            "execution observations is forbidden."
        )
    decay = float(np.exp(np.log(0.5) / max(halflife, 1)))
    observation_weights = decay ** np.arange(len(values) - 1, -1, -1, dtype=float)
    innovation = np.einsum(
        "t,ti,tj->ij",
        observation_weights,
        values,
        values,
        optimize=True,
    )
    return decay ** len(values) * prior + (1.0 - decay) * innovation


@dataclass(frozen=True)
class BacktestResult:
    equity: pd.Series
    strategy_returns: pd.Series
    weights: pd.DataFrame
    diagnostics: pd.DataFrame
    signals: SignalBundle
    prices: pd.DataFrame
    config: AppConfig
    return_semantics: str = "close_to_close"
    # Exact validated observations used for signals and close-based marks. This is
    # explicit even though it currently equals ``prices`` so evidence consumers never
    # have to infer whether an imputed frame was used.
    observed_prices: pd.DataFrame | None = None


@dataclass(frozen=True)
class _RebalanceCost:
    turnover: float
    total_cost: float
    linear_cost: float
    market_impact_cost: float
    signed_trade_weights: pd.Series
    trade_notional_dollars: pd.Series
    participation: pd.Series
    missing_adv_assets: tuple[str, ...]
    participation_breach_assets: tuple[str, ...]


@dataclass(frozen=True)
class _PovExecution:
    """Ex-post execution outcome for a submitted causal target order.

    The submitted order is frozen before the execution endpoint.  Only the signed
    row-t fill-window volume determines how much of that order can actually fill;
    any remainder is canceled at the endpoint and retained as an explicit breach.
    """

    post_trade_weights: pd.Series
    filled_signed_trade_dollars: pd.Series
    filled_trade_notional_dollars: pd.Series
    canceled_trade_notional_dollars: pd.Series
    realized_participation: pd.Series
    missing_volume_assets: tuple[str, ...]
    participation_breach_assets: tuple[str, ...]
    residual_assets: tuple[str, ...]
    fill_ratio: float
    total_cost: float
    linear_cost: float
    market_impact_cost: float


def _drawdown_multiplier(drawdown: float, config: AppConfig) -> float:
    risk = config.risk
    if drawdown <= -risk.flatten_drawdown:
        return 0.0
    if drawdown <= -risk.severe_drawdown:
        return risk.severe_multiplier
    if drawdown <= -risk.defensive_drawdown:
        return risk.defensive_multiplier
    if drawdown <= -risk.throttle_drawdown:
        return risk.throttle_multiplier
    return 1.0


def _neutral_projector(
    beta: np.ndarray,
    dollar_neutral: bool,
    beta_neutral: bool,
) -> tuple[np.ndarray, np.ndarray] | None:
    columns: list[np.ndarray] = []
    if dollar_neutral:
        columns.append(np.ones_like(beta, dtype=float))
    if beta_neutral and np.isfinite(beta).sum() >= 3:
        b = np.nan_to_num(beta, nan=float(np.nanmedian(beta)))
        if np.nanstd(b) > 1e-8:
            columns.append(b)
    if not columns:
        return None

    constraint_matrix = np.column_stack(columns)  # n assets x k constraints
    gram = constraint_matrix.T @ constraint_matrix
    return constraint_matrix, np.linalg.pinv(gram)


def _project_neutral(
    raw: np.ndarray,
    projector: tuple[np.ndarray, np.ndarray] | None,
) -> np.ndarray:
    x = np.asarray(raw, dtype=float).copy()
    if projector is None:
        return x
    constraint_matrix, gram_inverse = projector
    adjustment = constraint_matrix @ gram_inverse @ (constraint_matrix.T @ x)
    return x - adjustment


def _enforce_bounded_neutrality(
    x: np.ndarray,
    beta: np.ndarray,
    cap: float,
    dollar_neutral: bool,
    beta_neutral: bool,
) -> np.ndarray:
    """Apply a small active-set correction for exact neutrality under box bounds."""
    vectors: list[np.ndarray] = []
    if dollar_neutral:
        vectors.append(np.ones_like(x))
    if beta_neutral and np.isfinite(beta).sum() >= 3:
        b = np.nan_to_num(beta, nan=float(np.nanmedian(beta)))
        if np.nanstd(b) > 1e-8:
            vectors.append(b)
    if not vectors:
        return np.clip(x, -cap, cap)

    constraints = np.vstack(vectors)  # k constraints x n assets
    y = np.clip(np.asarray(x, dtype=float), -cap, cap)
    free = np.ones(len(y), dtype=bool)

    for _ in range(len(y) + 2):
        residual = -(constraints @ y)
        if np.max(np.abs(residual)) < 1e-12:
            break
        free_idx = np.flatnonzero(free)
        if len(free_idx) < constraints.shape[0]:
            break
        a_free = constraints[:, free_idx]
        delta = a_free.T @ np.linalg.pinv(a_free @ a_free.T) @ residual
        proposed = y[free_idx] + delta
        violations = np.abs(proposed) > cap + 1e-12
        if not np.any(violations):
            y[free_idx] = proposed
            break

        # Clamp the most severe violation, then resolve the remaining residual.
        severity = np.abs(proposed) - cap
        local = int(np.argmax(severity))
        global_idx = int(free_idx[local])
        y[global_idx] = np.sign(proposed[local]) * cap
        free[global_idx] = False

    return np.clip(y, -cap, cap)


def _eligible_asset_mask(
    alpha: pd.Series,
    asset_vol: pd.Series,
    beta: pd.Series,
    config: AppConfig,
) -> pd.Series:
    valid = alpha.notna() & asset_vol.notna() & asset_vol.gt(0.0)
    if config.portfolio.beta_neutral:
        # A missing beta is not evidence of zero beta.  Excluding the asset is the
        # only fail-closed construction compatible with an explicit beta constraint.
        aligned_beta = beta.reindex(alpha.index)
        valid &= aligned_beta.notna() & np.isfinite(aligned_beta)
    return valid.astype(bool)


def _construct_weights(
    alpha: pd.Series,
    asset_vol: pd.Series,
    beta: pd.Series,
    desired_gross: float,
    config: AppConfig,
) -> pd.Series:
    result = pd.Series(0.0, index=alpha.index)
    valid = _eligible_asset_mask(alpha, asset_vol, beta, config)
    if valid.sum() < 4 or desired_gross <= 0:
        return result

    idx = alpha.index[valid]
    a = alpha.loc[idx].to_numpy(dtype=float)
    vol = asset_vol.loc[idx].clip(lower=0.03).to_numpy(dtype=float)
    b = beta.reindex(idx).to_numpy(dtype=float)
    projector = _neutral_projector(
        b,
        dollar_neutral=config.portfolio.dollar_neutral,
        beta_neutral=config.portfolio.beta_neutral,
    )

    x = a / vol
    x = _project_neutral(x, projector)
    gross = float(np.abs(x).sum())
    if not np.isfinite(gross) or gross <= 1e-12:
        return result
    x = x / gross * desired_gross

    cap = config.portfolio.max_position_weight
    # Alternate between clipping and neutral projection. The final solution may use less
    # gross than requested when the position cap is binding, which is safer than leverage.
    for _ in range(8):
        x = np.clip(x, -cap, cap)
        x = _project_neutral(x, projector)
        current_gross = float(np.abs(x).sum())
        if current_gross <= 1e-12:
            return result
        scale_to_gross = min(desired_gross / current_gross, 1.0)
        x *= scale_to_gross

    x = _enforce_bounded_neutrality(
        x,
        b,
        cap=cap,
        dollar_neutral=config.portfolio.dollar_neutral,
        beta_neutral=config.portfolio.beta_neutral,
    )
    current_gross = float(np.abs(x).sum())
    if current_gross > desired_gross and current_gross > 0:
        x *= desired_gross / current_gross

    result.loc[idx] = x
    return result.fillna(0.0)


def _drift_weights(
    weights: pd.Series,
    asset_returns: pd.Series,
    holding_net_return: float,
) -> pd.Series:
    """Mark yesterday's holdings to market before measuring today's trades.

    ``weights`` are fractions of equity immediately after the prior rebalance. Asset
    notionals change with their own returns while borrow and financing charges reduce
    account equity. The resulting weights are therefore the only self-financing
    pre-trade comparison point for turnover.
    """
    equity_growth = max(1.0 + float(holding_net_return), 1e-8)
    grossed_positions = weights.mul(1.0 + asset_returns.reindex(weights.index))
    return grossed_positions.div(equity_growth).replace([np.inf, -np.inf], np.nan).fillna(0.0)


def _cost_aware_rebalance(
    pre_trade_weights: pd.Series,
    post_trade_target: pd.Series,
    transaction_cost_rate: float,
) -> tuple[float, float]:
    """Solve turnover and cost when targets are weights of post-cost equity.

    If pre-trade equity is one and cost is ``c``, target dollars are
    ``post_trade_target * (1 - c)``. Consequently turnover and cost satisfy
    ``turnover = sum(abs(target * (1 - c) - pre_trade))`` and
    ``c = transaction_cost_rate * turnover``. Solving this fixed point keeps stored
    weights, asset notionals, and post-cost equity mutually consistent.
    """
    rate = float(transaction_cost_rate)
    if not np.isfinite(rate) or rate < 0.0:
        raise ValueError("transaction_cost_rate must be finite and non-negative.")
    if rate == 0.0:
        turnover = float((post_trade_target - pre_trade_weights).abs().sum())
        return turnover, 0.0

    cost_fraction = 0.0
    turnover = 0.0
    for _ in range(100):
        remaining_equity = max(1.0 - cost_fraction, 1e-8)
        turnover = float(
            (post_trade_target.mul(remaining_equity) - pre_trade_weights).abs().sum()
        )
        updated_cost = min(rate * turnover, 1.0 - 1e-8)
        if abs(updated_cost - cost_fraction) <= 1e-14:
            cost_fraction = updated_cost
            break
        cost_fraction = updated_cost

    remaining_equity = max(1.0 - cost_fraction, 1e-8)
    turnover = float(
        (post_trade_target.mul(remaining_equity) - pre_trade_weights).abs().sum()
    )
    cost_fraction = min(rate * turnover, 1.0 - 1e-8)
    return turnover, cost_fraction


def _causal_average_daily_dollar_volume(
    daily_dollar_volume: pd.DataFrame | None,
    prices: pd.DataFrame,
    lookback: int,
) -> pd.DataFrame | None:
    """Build ADV using only dollar volume completed before each trade date.

    The supplied frame is raw daily dollar volume (price times shares/contracts), not
    a forward-filled liquidity estimate.  Row ``t`` is deliberately excluded from the
    ADV used on row ``t`` because its full-session volume is not known before a trade
    scheduled for that session.  A complete trailing window is required; gaps remain
    missing so a trade cannot receive a fabricated zero-impact fill.
    """
    if daily_dollar_volume is None:
        return None
    volume = validate_daily_dollar_volume_frame(
        daily_dollar_volume,
        label="daily_dollar_volume",
        expected_index=prices.index,
    )
    # Missing asset columns become explicit missing observations.  This permits the
    # run to complete with an auditable breach instead of failing before the sealed
    # validation table can explain which traded asset lacked liquidity evidence.
    volume = volume.reindex(columns=prices.columns)
    return volume.shift(1).rolling(lookback, min_periods=lookback).mean()


def _rebalance_cost_details(
    pre_trade_weights: pd.Series,
    post_trade_target: pd.Series,
    *,
    transaction_cost_rate: float,
    pre_trade_equity_dollars: float,
    adv_dollars: pd.Series | None,
    annualized_asset_volatility: pd.Series,
    costs: CostConfig,
) -> _RebalanceCost:
    """Solve post-cost weights with fixed costs plus square-root market impact.

    For a trade ``Q`` against lagged average daily dollar volume ``ADV``, the one-way
    impact rate is ``Y * sigma_daily * sqrt(Q / ADV)``.  Dollar impact is charged on
    every traded dollar in addition to the configured linear spread/fee assumption.
    The nonlinear cost and target dollars are solved together because target weights
    are fractions of post-cost equity.

    A traded asset without valid lagged ADV is charged a 100% adverse impact rate and
    returned as a data breach.  This is intentionally punitive: absent liquidity data
    must never become a free fill.
    """
    equity_dollars = float(pre_trade_equity_dollars)
    if not np.isfinite(equity_dollars) or equity_dollars <= 0.0:
        raise ValueError("pre_trade_equity_dollars must be finite and strictly positive.")

    assets = pre_trade_weights.index
    target = post_trade_target.reindex(assets).fillna(0.0).astype(float)
    pre_trade = pre_trade_weights.reindex(assets).fillna(0.0).astype(float)

    if adv_dollars is None:
        turnover, total_cost = _cost_aware_rebalance(
            pre_trade,
            target,
            transaction_cost_rate,
        )
        remaining_equity = max(1.0 - total_cost, 1e-8)
        signed_trade = target.mul(remaining_equity).sub(pre_trade)
        traded_dollars = signed_trade.abs().mul(equity_dollars)
        return _RebalanceCost(
            turnover=turnover,
            total_cost=total_cost,
            linear_cost=total_cost,
            market_impact_cost=0.0,
            signed_trade_weights=signed_trade,
            trade_notional_dollars=traded_dollars,
            participation=pd.Series(np.nan, index=assets, dtype=float),
            missing_adv_assets=(),
            participation_breach_assets=(),
        )

    adv = pd.to_numeric(adv_dollars.reindex(assets), errors="coerce").astype(float)
    adv_array = adv.to_numpy(dtype=float)
    valid_adv = np.isfinite(adv_array) & (adv_array > 0.0)
    annual_vol = pd.to_numeric(
        annualized_asset_volatility.reindex(assets), errors="coerce"
    ).astype(float)
    daily_vol = annual_vol.div(np.sqrt(TRADING_DAYS))
    daily_vol = daily_vol.where(np.isfinite(daily_vol))
    daily_vol = daily_vol.clip(lower=costs.impact_daily_volatility_floor)
    daily_vol = daily_vol.fillna(costs.impact_daily_volatility_floor)
    daily_vol_array = daily_vol.to_numpy(dtype=float)
    target_array = target.to_numpy(dtype=float)
    pre_trade_array = pre_trade.to_numpy(dtype=float)
    minimum_trade_dollars = max(equity_dollars * 1e-12, 0.01)

    def evaluate(
        cost_fraction: float,
    ) -> tuple[
        float,
        float,
        float,
        np.ndarray,
        np.ndarray,
        np.ndarray,
        np.ndarray,
    ]:
        remaining_equity = max(1.0 - float(cost_fraction), 1e-8)
        signed_trade = target_array * remaining_equity - pre_trade_array
        trade_weight = np.abs(signed_trade)
        traded_dollars = trade_weight * equity_dollars
        traded = traded_dollars > minimum_trade_dollars
        participation = np.full(len(assets), np.nan, dtype=float)
        np.divide(
            traded_dollars,
            adv_array,
            out=participation,
            where=valid_adv,
        )

        impact_rate = np.zeros(len(assets), dtype=float)
        valid_trade = traded & valid_adv
        impact_rate[valid_trade] = np.clip(
            float(costs.square_root_impact_coefficient)
            * daily_vol_array[valid_trade]
            * np.sqrt(participation[valid_trade]),
            0.0,
            1.0,
        )
        # No ADV means no defensible estimate.  Apply an adverse write-off to the
        # affected traded notional while retaining a named breach for certification.
        impact_rate[traded & ~valid_adv] = 1.0

        turnover = float(np.sum(trade_weight))
        linear_cost = float(transaction_cost_rate) * turnover
        impact_cost = float(np.dot(trade_weight, impact_rate))
        raw_total = linear_cost + impact_cost
        total_cost = min(raw_total, 1.0 - 1e-8)
        if raw_total > total_cost and raw_total > 0.0:
            scale = total_cost / raw_total
            linear_cost *= scale
            impact_cost *= scale
        return (
            turnover,
            linear_cost,
            impact_cost,
            signed_trade,
            traded_dollars,
            participation,
            traded,
        )

    # g(c) = c - modeled_cost(c) brackets a root on [0, 1-eps].  Bisection is
    # stable even when missing ADV invokes the deliberately steep adverse cost.
    lower = 0.0
    upper = 1.0 - 1e-8
    for _ in range(60):
        midpoint = (lower + upper) / 2.0
        _, linear, impact, *_ = evaluate(midpoint)
        modeled = min(linear + impact, 1.0 - 1e-8)
        if midpoint < modeled:
            lower = midpoint
        else:
            upper = midpoint
    solved_cost = (lower + upper) / 2.0
    (
        turnover,
        linear_cost,
        impact_cost,
        signed_trade,
        traded_dollars,
        participation,
        traded,
    ) = evaluate(solved_cost)
    total_cost = min(linear_cost + impact_cost, 1.0 - 1e-8)
    missing_adv = tuple(map(str, assets[traded & ~valid_adv]))
    participation_breaches = tuple(
        map(
            str,
            assets[
                traded
                & valid_adv
                & (participation > float(costs.max_participation_rate))
            ],
        )
    )
    return _RebalanceCost(
        turnover=turnover,
        total_cost=total_cost,
        linear_cost=linear_cost,
        market_impact_cost=impact_cost,
        signed_trade_weights=pd.Series(signed_trade, index=assets, dtype=float),
        trade_notional_dollars=pd.Series(traded_dollars, index=assets, dtype=float),
        participation=pd.Series(participation, index=assets, dtype=float),
        missing_adv_assets=missing_adv,
        participation_breach_assets=participation_breaches,
    )


def _aggregate_daily_trade_cost(
    traded_notional_dollars: pd.Series,
    *,
    pre_trade_equity_dollars: float,
    transaction_cost_rate: float,
    adv_dollars: pd.Series,
    annualized_asset_volatility: pd.Series,
    costs: CostConfig,
) -> tuple[float, float, float]:
    """Charge convex impact once on aggregate same-day per-asset gross flow.

    Splitting a primary trade and a same-day emergency flatten into two independent
    square-root calculations understates impact because impact dollars scale as
    ``Q ** 1.5``. This helper prices the realized aggregate gross flow against the same
    lagged ADV and returns total, linear, and impact fractions of pre-trade equity.
    """
    equity = float(pre_trade_equity_dollars)
    if not np.isfinite(equity) or equity <= 0.0:
        raise ValueError("pre_trade_equity_dollars must be finite and strictly positive.")
    assets = traded_notional_dollars.index
    notionals = (
        pd.to_numeric(traded_notional_dollars, errors="coerce")
        .reindex(assets)
        .fillna(0.0)
        .clip(lower=0.0)
    )
    adv = pd.to_numeric(adv_dollars.reindex(assets), errors="coerce")
    valid_adv = adv.notna() & np.isfinite(adv) & adv.gt(0.0)
    annual_vol = pd.to_numeric(
        annualized_asset_volatility.reindex(assets), errors="coerce"
    )
    daily_vol = annual_vol.div(np.sqrt(TRADING_DAYS))
    daily_vol = daily_vol.where(np.isfinite(daily_vol))
    daily_vol = daily_vol.clip(lower=costs.impact_daily_volatility_floor)
    daily_vol = daily_vol.fillna(costs.impact_daily_volatility_floor)
    traded = notionals.gt(max(equity * 1e-12, 0.01))
    participation = notionals.div(adv.where(valid_adv))
    impact_rate = pd.Series(0.0, index=assets, dtype=float)
    valid_trade = traded & valid_adv
    impact_rate.loc[valid_trade] = (
        float(costs.square_root_impact_coefficient)
        * daily_vol.loc[valid_trade]
        * np.sqrt(participation.loc[valid_trade])
    ).clip(lower=0.0, upper=1.0)
    impact_rate.loc[traded & ~valid_adv] = 1.0

    linear_cost = float(transaction_cost_rate * notionals.sum() / equity)
    impact_cost = float(notionals.dot(impact_rate) / equity)
    raw_total = linear_cost + impact_cost
    total_cost = min(raw_total, 1.0 - 1e-8)
    if raw_total > total_cost and raw_total > 0.0:
        scale = total_cost / raw_total
        linear_cost *= scale
        impact_cost *= scale
    return total_cost, linear_cost, impact_cost


def _realized_pov_execution(
    pre_trade_weights: pd.Series,
    submitted_cost: _RebalanceCost,
    *,
    pre_trade_equity_dollars: float,
    realized_window_dollar_volume: pd.Series,
    transaction_cost_rate: float,
    annualized_asset_volatility: pd.Series,
    costs: CostConfig,
) -> _PovExecution:
    """Fill a frozen order against signed row-t window volume under a POV cap.

    Forecast volume is intentionally absent from this function: it belongs to target
    sizing.  This function is exclusively an ex-post outcome model.  Invalid or
    missing row-t volume receives no fill, and a material unfilled remainder is never
    carried forward implicitly.
    """
    equity = float(pre_trade_equity_dollars)
    if not np.isfinite(equity) or equity <= 0.0:
        raise ValueError("pre_trade_equity_dollars must be finite and strictly positive.")

    assets = pre_trade_weights.index
    submitted_signed = (
        submitted_cost.signed_trade_weights.reindex(assets).fillna(0.0).astype(float)
        * equity
    )
    submitted_abs = submitted_signed.abs()
    realized_volume = pd.to_numeric(
        realized_window_dollar_volume.reindex(assets), errors="coerce"
    ).astype(float)
    valid_volume = realized_volume.notna() & np.isfinite(realized_volume) & realized_volume.gt(0.0)
    capacity = realized_volume.where(valid_volume, 0.0).mul(
        float(costs.max_participation_rate)
    )
    filled_abs = pd.Series(
        np.minimum(submitted_abs.to_numpy(dtype=float), capacity.to_numpy(dtype=float)),
        index=assets,
        dtype=float,
    ).clip(lower=0.0)
    filled_signed = filled_abs.mul(np.sign(submitted_signed))
    canceled = submitted_abs.sub(filled_abs).clip(lower=0.0)

    total_cost, linear_cost, impact_cost = _aggregate_daily_trade_cost(
        filled_abs,
        pre_trade_equity_dollars=equity,
        transaction_cost_rate=transaction_cost_rate,
        adv_dollars=realized_volume,
        annualized_asset_volatility=annualized_asset_volatility,
        costs=costs,
    )
    ending_equity = equity * max(1.0 - total_cost, 1e-8)
    post_trade_position_dollars = pre_trade_weights.mul(equity).add(filled_signed)
    post_trade_weights = post_trade_position_dollars.div(ending_equity)

    minimum_trade_dollars = max(equity * 1e-12, 0.01)
    submitted_mask = submitted_abs.gt(minimum_trade_dollars)
    filled_mask = filled_abs.gt(minimum_trade_dollars)
    missing_volume_mask = submitted_mask & ~valid_volume
    residual_mask = canceled.gt(minimum_trade_dollars)
    realized_participation = filled_abs.div(realized_volume.where(valid_volume))
    # This should be impossible under min(Q, POV * V), but keep an explicit
    # fail-closed diagnostic against numerical or future implementation regressions.
    participation_breach_mask = (
        filled_mask
        & valid_volume
        & realized_participation.gt(float(costs.max_participation_rate) + 1e-12)
    )
    submitted_total = float(submitted_abs.sum())
    fill_ratio = (
        float(filled_abs.sum() / submitted_total)
        if submitted_total > minimum_trade_dollars
        else float("nan")
    )
    return _PovExecution(
        post_trade_weights=post_trade_weights,
        filled_signed_trade_dollars=filled_signed,
        filled_trade_notional_dollars=filled_abs,
        canceled_trade_notional_dollars=canceled,
        realized_participation=realized_participation,
        missing_volume_assets=tuple(map(str, assets[missing_volume_mask.to_numpy()])),
        participation_breach_assets=tuple(
            map(str, assets[participation_breach_mask.to_numpy()])
        ),
        residual_assets=tuple(map(str, assets[residual_mask.to_numpy()])),
        fill_ratio=fill_ratio,
        total_cost=total_cost,
        linear_cost=linear_cost,
        market_impact_cost=impact_cost,
    )


def _execution_returns(
    prices: pd.DataFrame,
    semantics: ExecutionReturnSemantics,
    execution_prices: pd.DataFrame | None,
) -> tuple[pd.DataFrame, int, pd.DataFrame]:
    if semantics not in VALID_EXECUTION_RETURN_SEMANTICS:
        choices = ", ".join(sorted(VALID_EXECUTION_RETURN_SEMANTICS))
        raise ValueError(f"execution_return_semantics must be one of: {choices}.")

    if semantics == "next_open_to_open":
        if execution_prices is None:
            raise ValueError(
                "next_open_to_open requires actual, point-in-time execution_prices "
                "(for example, next-session opens); the backtest will not invent them."
            )
        execution_prices = execution_prices.sort_index().astype(float)
        missing_columns = prices.columns.difference(execution_prices.columns)
        if len(missing_columns) > 0:
            raise ValueError(
                "execution_prices is missing assets: " + ", ".join(map(str, missing_columns))
            )
        if not execution_prices.index.equals(prices.index):
            raise ValueError("execution_prices must have exactly the same sorted index as prices.")
        execution_prices = execution_prices.reindex(columns=prices.columns)
        values = execution_prices.to_numpy(dtype=float)
        invalid = (~np.isfinite(values) & ~np.isnan(values)) | (
            np.isfinite(values) & (values <= 0.0)
        )
        if np.any(invalid):
            raise ValueError(
                "Non-missing execution_prices must be finite and strictly positive."
            )
        # A close-t signal is first available to trade at open t+1. In loop row t+1,
        # signal_lag=1 selects that completed prior-session signal.
        return (
            execution_prices.pct_change(fill_method=None),
            1,
            execution_prices.notna(),
        )

    if execution_prices is not None:
        raise ValueError("execution_prices is only used with next_open_to_open semantics.")

    # Even the historical close-to-close label uses the last *completed* close for
    # sizing. The row-t close is the execution endpoint and cannot also be an input to
    # the target purportedly filled there.
    return prices.pct_change(fill_method=None), 1, prices.notna()


def run_backtest(
    prices: pd.DataFrame,
    config: AppConfig,
    *,
    execution_return_semantics: ExecutionReturnSemantics = "close_to_close",
    execution_prices: pd.DataFrame | None = None,
    daily_dollar_volume: pd.DataFrame | None = None,
    execution_window_dollar_volume: pd.DataFrame | None = None,
    corporate_action_split_ratios: pd.DataFrame | None = None,
    corporate_action_cash_distributions: pd.DataFrame | None = None,
    borrow_availability: pd.DataFrame | None = None,
    annual_borrow_rates: pd.DataFrame | None = None,
    borrow_recalls: pd.DataFrame | None = None,
    borrow_rate_stress_multiplier: float = 1.0,
) -> BacktestResult:
    """Run a causal market-neutral research backtest with explicit timing.

    ``close_to_close`` is retained as a historical return-series label, but it no longer
    permits a same-close signal/fill: the last completed close is sized for the next
    close. ``next_close_proxy`` states that one-bar latency explicitly. Neither mode is
    a live open-fill model. ``next_open_to_open`` models the live chronology (close-t
    signal, open-t+1 trade, open-t+1 to open-t+2 holding return) and requires real
    aligned execution prices. No synthetic open proxy is manufactured.
    In every mode, portfolio drawdown/loss controls and execution-return covariance used
    for a row-t target are frozen as of row t-1; the row-t return marks the prior
    holdings and enters risk only for row t+1. Assets also require 252 complete lagged
    execution returns before they may enter or re-enter risk.

    ``execution_window_dollar_volume`` is the dollar notional traded only inside
    the modeled fill window. It is never replaced by unrestricted full-session
    liquidity in sealed research. ``daily_dollar_volume`` remains a legacy
    exploratory input and cannot be supplied together with the window panel.
    When either liquidity panel is supplied, transaction costs also include a
    square-root impact model at ``config.costs.starting_capital``.  ADV is constructed
    from a complete trailing window ending at t-1.  Missing ADV on a traded asset and
    participation above the configured cap remain in the result as hard research-path
    breaches; neither condition is converted to a cost-free fill.
    """
    config.validate()
    if prices.shape[1] < 4:
        raise ValueError("Market-neutral testing requires at least four assets.")
    if len(prices) < 180:
        raise ValueError("At least 180 observations are required.")

    if prices.columns.has_duplicates:
        raise ValueError("Backtest price columns must be unique.")
    if prices.index.has_duplicates:
        raise ValueError("Backtest price index must not contain duplicate dates.")
    if not prices.index.is_monotonic_increasing:
        raise ValueError("Backtest price timestamps must be strictly increasing.")
    try:
        observed_prices = prices.sort_index().astype(float)
    except (TypeError, ValueError) as exc:
        raise ValueError("Backtest prices must be numeric.") from exc
    price_values = observed_prices.to_numpy(dtype=float)
    invalid_prices = (~np.isfinite(price_values) & ~np.isnan(price_values)) | (
        np.isfinite(price_values) & (price_values <= 0.0)
    )
    if np.any(invalid_prices):
        raise ValueError(
            "Every non-missing backtest price must be finite and strictly positive."
        )
    validate_daily_session_index(observed_prices.index, label="Backtest prices")
    carry_elapsed_time = _carry_elapsed_time(observed_prices.index)
    if daily_dollar_volume is not None and execution_window_dollar_volume is not None:
        raise ValueError(
            "Supply execution-window dollar volume or legacy daily dollar volume, not both."
        )
    liquidity_input = (
        execution_window_dollar_volume
        if execution_window_dollar_volume is not None
        else daily_dollar_volume
    )
    causal_adv = _causal_average_daily_dollar_volume(
        liquidity_input,
        observed_prices,
        config.costs.adv_lookback_days,
    )
    realized_execution_window_volume: pd.DataFrame | None = None
    if execution_window_dollar_volume is not None:
        realized_execution_window_volume = validate_daily_dollar_volume_frame(
            execution_window_dollar_volume,
            label="execution_window_dollar_volume",
            expected_index=observed_prices.index,
        ).reindex(columns=observed_prices.columns)
    # Do not impute close prices even for signals. A stale close can otherwise create a
    # fabricated cross-sectional rank and a new next-open trade despite no observed
    # signal-date mark.
    prices = observed_prices.copy()
    complete_signal_price_history = (
        observed_prices.notna()
        .rolling(
            MIN_SIGNAL_PRICE_HISTORY,
            min_periods=MIN_SIGNAL_PRICE_HISTORY,
        )
        .sum()
        .eq(float(MIN_SIGNAL_PRICE_HISTORY))
    )
    returns, signal_lag, execution_price_available = _execution_returns(
        observed_prices,
        execution_return_semantics,
        execution_prices,
    )
    position_returns = returns.copy()
    corporate_panels = (
        corporate_action_split_ratios,
        corporate_action_cash_distributions,
    )
    corporate_action_model_active = any(panel is not None for panel in corporate_panels)
    if corporate_action_model_active:
        if execution_return_semantics != "next_open_to_open" or execution_prices is None:
            raise ValueError(
                "Corporate-action interval accounting requires actual aligned execution prices."
            )
        if any(panel is None for panel in corporate_panels):
            raise ValueError(
                "Both split-ratio and cash-distribution panels are required."
            )
        assert corporate_action_split_ratios is not None
        assert corporate_action_cash_distributions is not None
        for label, panel in (
            ("Corporate-action split ratios", corporate_action_split_ratios),
            ("Corporate-action cash distributions", corporate_action_cash_distributions),
        ):
            if not isinstance(panel, pd.DataFrame):
                raise ValueError(f"{label} must be a pandas DataFrame.")
            if not panel.index.equals(observed_prices.index) or not panel.columns.equals(
                observed_prices.columns
            ):
                raise ValueError(
                    f"{label} must exactly match the price index and asset columns."
                )
        split_values = corporate_action_split_ratios.to_numpy(dtype=float)
        cash_values = corporate_action_cash_distributions.to_numpy(dtype=float)
        if not np.isfinite(split_values).all() or np.any(split_values <= 0.0):
            raise ValueError("Corporate-action split ratios must be complete and positive.")
        if not np.isfinite(cash_values).all() or np.any(cash_values < 0.0):
            raise ValueError(
                "Corporate-action cash distributions must be complete and non-negative."
            )
        execution_numeric = execution_prices.reindex(
            index=observed_prices.index, columns=observed_prices.columns
        ).astype(float)
        # For one pre-action share held over t-1 -> t, the terminal economic value is
        # split_ratio[t] * raw_VWAP[t] + cash_per_pre_action_share[t]. Price levels
        # remain raw tradable VWAPs for sizing/costs; only interval P&L is adjusted.
        returns = (
            execution_numeric.mul(corporate_action_split_ratios)
            .add(corporate_action_cash_distributions)
            .div(execution_numeric.shift(1))
            .sub(1.0)
        )
        position_returns = (
            execution_numeric.mul(corporate_action_split_ratios)
            .div(execution_numeric.shift(1))
            .sub(1.0)
        )

    borrow_panels = (borrow_availability, annual_borrow_rates, borrow_recalls)
    point_in_time_borrow_model_active = any(panel is not None for panel in borrow_panels)
    if (
        not math.isfinite(float(borrow_rate_stress_multiplier))
        or float(borrow_rate_stress_multiplier) < 1.0
        or float(borrow_rate_stress_multiplier) > 10.0
    ):
        raise ValueError("Borrow-rate stress multiplier must be between 1 and 10.")
    if point_in_time_borrow_model_active:
        if any(panel is None for panel in borrow_panels):
            raise ValueError(
                "Borrow availability, annual rates, and recalls must all be supplied."
            )
        assert borrow_availability is not None
        assert annual_borrow_rates is not None
        assert borrow_recalls is not None
        for label, panel in (
            ("Borrow availability", borrow_availability),
            ("Annual borrow rates", annual_borrow_rates),
            ("Borrow recalls", borrow_recalls),
        ):
            if not isinstance(panel, pd.DataFrame):
                raise ValueError(f"{label} must be a pandas DataFrame.")
            if not panel.index.equals(observed_prices.index) or not panel.columns.equals(
                observed_prices.columns
            ):
                raise ValueError(
                    f"{label} must exactly match the price index and asset columns."
                )
        availability_values = borrow_availability.to_numpy()
        recall_values = borrow_recalls.to_numpy()
        if not all(
            isinstance(value, (bool, np.bool_))
            for value in np.concatenate(
                [availability_values.ravel(), recall_values.ravel()]
            )
        ):
            raise ValueError("Borrow availability and recall panels must be boolean.")
        rate_values = annual_borrow_rates.to_numpy(dtype=float)
        if (
            not np.isfinite(rate_values).all()
            or np.any(rate_values < 0.0)
            or np.any(rate_values > 10.0)
        ):
            raise ValueError("Annual borrow rates must be complete and between 0 and 10.")
        if bool((borrow_recalls.astype(bool) & borrow_availability.astype(bool)).any().any()):
            raise ValueError("Recalled borrow cannot simultaneously be available.")
    # Portfolio risk is estimated from execution-interval returns, not close-signal
    # returns.  At a row-t execution, neither the row-t endpoint nor its return is
    # available to the decision.  Requiring a complete trailing window through t-1
    # both enforces that chronology and prevents an unheld missing endpoint from being
    # silently represented as a zero return in covariance or re-entry risk.
    complete_lagged_execution_return_history = (
        returns.notna()
        .shift(1)
        .rolling(
            MIN_SIGNAL_PRICE_HISTORY,
            min_periods=MIN_SIGNAL_PRICE_HISTORY,
        )
        .sum()
        .eq(float(MIN_SIGNAL_PRICE_HISTORY))
    )
    signals = build_signal_bundle(prices, config.signals, config.regime)

    assets = prices.columns
    current_weights = pd.Series(0.0, index=assets)
    equity_value = 1.0
    peak_equity = 1.0
    cooldown_remaining = 0
    research_path_valid = True
    liquidity_path_valid = True

    weights_history: list[pd.Series] = []
    equity_history: list[float] = []
    return_history: list[float] = []
    diagnostics: list[dict[str, object]] = []

    warmup = max(
        126,
        config.signals.beta_lookback,
        config.signals.vol_lookback,
        config.regime.ic_window,
    )

    for i, date in enumerate(prices.index):
        start_equity = equity_value
        elapsed_calendar_days = float(
            carry_elapsed_time["elapsed_calendar_days"].iloc[i]
        )
        carry_year_fraction = float(
            carry_elapsed_time["carry_year_fraction"].iloc[i]
        )
        # Freeze every decision/risk input before observing the execution endpoint for
        # this row.  The current return is still applied to the prior holdings below,
        # preserving self-financing mark-to-market and fill-cost accounting, but can
        # affect sizing only from the next row onward.
        decision_weights = current_weights.copy()
        decision_drawdown = equity_value / peak_equity - 1.0
        dd_multiplier = _drawdown_multiplier(decision_drawdown, config)
        lagged_five_day_returns = pd.Series(return_history[-5:], dtype=float)
        five_day_return = (
            float((1.0 + lagged_five_day_returns).prod() - 1.0)
            if not lagged_five_day_returns.empty
            else 0.0
        )
        previous_strategy_return = float(return_history[-1]) if return_history else 0.0
        loss_shock_multiplier = 1.0
        if (
            previous_strategy_return <= -config.risk.daily_loss_trigger
            or five_day_return <= -config.risk.five_day_loss_trigger
        ):
            loss_shock_multiplier = config.risk.loss_shock_multiplier

        raw_day_returns = returns.iloc[i].replace([np.inf, -np.inf], np.nan)
        raw_position_day_returns = position_returns.iloc[i].replace(
            [np.inf, -np.inf], np.nan
        )
        missing_held_mask = raw_day_returns.isna() & current_weights.abs().gt(1e-12)
        missing_held_assets = list(map(str, assets[missing_held_mask.to_numpy()]))
        data_integrity_breach = bool(missing_held_mask.any())
        if data_integrity_breach:
            research_path_valid = False

        day_returns = raw_day_returns.fillna(0.0)
        position_day_returns = raw_position_day_returns.fillna(0.0)
        # A missing mark on an existing holding can never be treated as a free zero
        # return. Apply an adverse write-down before flattening the modeled position:
        # longs lose their notional; shorts are covered at twice the prior mark.
        day_returns.loc[missing_held_mask & current_weights.gt(0.0)] = -1.0
        day_returns.loc[missing_held_mask & current_weights.lt(0.0)] = 1.0
        position_day_returns.loc[
            missing_held_mask & current_weights.gt(0.0)
        ] = -1.0
        position_day_returns.loc[
            missing_held_mask & current_weights.lt(0.0)
        ] = 1.0

        gross_before = float(current_weights.abs().sum())
        short_gross_before = float((-current_weights.clip(upper=0.0)).sum())
        financed_gross = max(gross_before - 1.0, 0.0)

        gross_portfolio_return = float(current_weights.dot(day_returns))
        if point_in_time_borrow_model_active:
            assert annual_borrow_rates is not None
            # Row i-1 terms were known when the interval's short was established.
            # Row i terms are reserved for the new decision/recall below and cannot
            # retroactively price the already-completed holding interval.
            applicable_rates = (
                annual_borrow_rates.iloc[max(i - 1, 0)].astype(float)
                * float(borrow_rate_stress_multiplier)
            )
            effective_rates = applicable_rates.clip(
                lower=float(config.costs.annual_short_borrow_rate)
            )
            borrow_cost = float(
                (-current_weights.clip(upper=0.0)).dot(effective_rates)
                * carry_year_fraction
            )
        else:
            borrow_cost = (
                short_gross_before
                * config.costs.annual_short_borrow_rate
                * carry_year_fraction
            )
        financing_cost = (
            financed_gross
            * config.costs.annual_financing_rate
            * carry_year_fraction
        )
        holding_net_return = gross_portfolio_return - borrow_cost - financing_cost
        equity_value *= max(1.0 + holding_net_return, 1e-8)
        pre_trade_weights = _drift_weights(
            current_weights,
            position_day_returns,
            holding_net_return,
        )

        peak_equity = max(peak_equity, equity_value)
        pre_trade_drawdown = equity_value / peak_equity - 1.0

        signal_position = i - signal_lag
        signal_available = signal_position >= 0
        signal_row = max(signal_position, 0)
        signal_date = prices.index[signal_position] if signal_available else pd.NaT

        regime_name = str(signals.regime.iloc[signal_row])
        regime_multiplier = float(signals.regime_multiplier.iloc[signal_row])
        shutdown_reason = ""
        shutdown_active = False

        alpha = signals.composite.iloc[signal_row]
        asset_vol = signals.asset_volatility.iloc[signal_row]
        beta = signals.beta.iloc[signal_row]
        signal_close_available = (
            observed_prices.notna().iloc[signal_row].reindex(assets).fillna(False)
        )
        complete_signal_history = (
            complete_signal_price_history.iloc[signal_row]
            .reindex(assets)
            .fillna(False)
        )
        incomplete_signal_history_assets = list(
            map(str, assets[(~complete_signal_history).to_numpy()])
        )
        complete_execution_history = (
            complete_lagged_execution_return_history.iloc[i]
            .reindex(assets)
            .fillna(False)
        )
        incomplete_execution_history_assets = list(
            map(str, assets[(~complete_execution_history).to_numpy()])
        )
        signal_input_eligible = (
            signal_close_available
            & complete_signal_history
            & complete_execution_history
        )
        available_now = pd.Series(True, index=assets, dtype=bool)
        recalled_now = pd.Series(False, index=assets, dtype=bool)
        borrow_short_eligible = pd.Series(True, index=assets, dtype=bool)
        borrow_recall_close_mask = pd.Series(False, index=assets, dtype=bool)
        if point_in_time_borrow_model_active:
            assert borrow_availability is not None
            assert borrow_recalls is not None
            # Same-session locate/recall evidence is timestamped no later than the
            # decision cutoff.  It may gate the target universe, but the completed
            # execution endpoint and its drifted pre-trade weights may not.
            available_now = borrow_availability.iloc[i].reindex(assets).astype(bool)
            recalled_now = borrow_recalls.iloc[i].reindex(assets).astype(bool)
            borrow_short_eligible = available_now & ~recalled_now
            borrow_recall_close_mask = recalled_now & decision_weights.lt(-1e-12)

        signal_eligible_alpha = alpha.where(signal_input_eligible)
        signal_eligible_vol = asset_vol.where(signal_input_eligible)
        # The live market-neutral allocator prefilters to assets eligible for either
        # direction.  Apply the identical conservative rule in sealed research: an
        # asset without current locate evidence is excluded from both legs, so a
        # later per-name clamp cannot destroy dollar or beta neutrality.
        tradable_now = signal_input_eligible & borrow_short_eligible
        alpha = alpha.where(tradable_now)
        asset_vol = asset_vol.where(tradable_now)
        effective_eligible_assets = int(
            _eligible_asset_mask(alpha, asset_vol, beta, config).sum()
        )

        unit_weights = _construct_weights(
            alpha=alpha,
            asset_vol=asset_vol,
            beta=beta,
            desired_gross=1.0,
            config=config,
        )
        covariance_assets = unit_weights.index[
            _eligible_asset_mask(alpha, asset_vol, beta, config).to_numpy()
        ]
        if len(covariance_assets) >= 4:
            covariance_returns = returns.iloc[
                max(0, i - TRAILING_COVARIANCE_RETURN_COUNT):i
            ].loc[:, covariance_assets]
            covariance = trailing_ewma_covariance(
                covariance_returns,
                config.portfolio.covariance_halflife,
            )
            unit = unit_weights.reindex(covariance_assets).to_numpy(dtype=float)
            forecast_vol = float(
                np.sqrt(max(unit @ (covariance * TRADING_DAYS) @ unit, 0.0))
            )
        else:
            forecast_vol = 0.0
        volatility_leverage = (
            config.portfolio.target_volatility / forecast_vol
            if forecast_vol > 1e-8
            else 0.0
        )
        base_gross = min(volatility_leverage, config.portfolio.max_gross_leverage)
        desired_gross = (
            base_gross * regime_multiplier * dd_multiplier * loss_shock_multiplier
        )
        desired_gross = min(max(desired_gross, 0.0), config.portfolio.max_gross_leverage)

        scheduled_rebalance = (
            signal_available
            and (signal_position % max(config.portfolio.rebalance_every, 1)) == 0
        )
        borrow_forced_rebalance = bool(borrow_recall_close_mask.any())
        target_rebalance = scheduled_rebalance or borrow_forced_rebalance
        if data_integrity_breach:
            target_weights = pd.Series(0.0, index=assets)
            desired_gross = 0.0
            cooldown_remaining = max(cooldown_remaining, config.risk.cooldown_days)
            shutdown_active = True
            shutdown_reason = "missing_held_asset_price"
        elif not signal_available or signal_position < warmup:
            target_weights = pd.Series(0.0, index=assets)
            desired_gross = 0.0
            shutdown_active = True
            shutdown_reason = "warmup"
        elif cooldown_remaining > 0:
            target_weights = pd.Series(0.0, index=assets)
            desired_gross = 0.0
            cooldown_remaining -= 1
            shutdown_active = True
            shutdown_reason = "cooldown"
        elif dd_multiplier <= 0.0:
            target_weights = pd.Series(0.0, index=assets)
            desired_gross = 0.0
            cooldown_remaining = config.risk.cooldown_days
            shutdown_active = True
            shutdown_reason = "drawdown_flatten"
        elif regime_multiplier <= 0.0:
            target_weights = pd.Series(0.0, index=assets)
            desired_gross = 0.0
            shutdown_active = True
            shutdown_reason = "invalid_regime"
        elif target_rebalance:
            target_weights = _construct_weights(
                alpha=alpha,
                asset_vol=asset_vol,
                beta=beta,
                desired_gross=desired_gross,
                config=config,
            )
        else:
            # With no scheduled trade, the portfolio keeps its marked-to-market
            # holdings. Resetting to yesterday's weights here would be a free rebalance.
            target_weights = pre_trade_weights.copy()
            # An unscheduled risk reduction is allowed, but its scale must have been
            # decided from the t-1 portfolio. Applying that pre-decided fraction to the
            # row-t drifted holdings retains self-financing semantics without using the
            # row-t endpoint to decide whether to trade.
            decision_gross = float(decision_weights.abs().sum())
            if decision_gross > desired_gross and decision_gross > 0:
                target_weights *= desired_gross / decision_gross

        borrow_unavailable_increase_mask = pd.Series(False, index=assets, dtype=bool)
        if point_in_time_borrow_model_active:
            # Retain an auditable count of shorts the ungated allocator would have
            # requested.  This counter is computed entirely from the frozen signal,
            # risk state, and locate panel; it never compares against row-t drift.
            ungated_target = _construct_weights(
                alpha=signal_eligible_alpha,
                asset_vol=signal_eligible_vol,
                beta=beta,
                desired_gross=desired_gross,
                config=config,
            )
            borrow_unavailable_increase_mask = (
                ungated_target.lt(-1e-12) & ~borrow_short_eligible
            )

        stale_signal_risk_increase_mask = pd.Series(False, index=assets, dtype=bool)
        if target_rebalance:
            stale_signal_risk_increase_mask = (
                target_weights.abs().gt(decision_weights.abs() + 1e-12)
                & ~signal_input_eligible
            )
        stale_signal_risk_increase_assets = list(
            map(str, assets[stale_signal_risk_increase_mask.to_numpy()])
        )
        stale_signal_trade_breach = bool(stale_signal_risk_increase_mask.any())
        if stale_signal_trade_breach:
            # Defensive reductions remain allowed without a signal close, but new or
            # enlarged risk from a stale signal is forbidden and invalidates the run.
            research_path_valid = False
            target_weights.loc[stale_signal_risk_increase_mask] = pre_trade_weights.loc[
                stale_signal_risk_increase_mask
            ]

        # The target above is the causal decision.  Current endpoint availability is a
        # fill outcome, not a sizing input.  A planned trade with no current execution
        # mark is therefore rejected and invalidates the research path; it is never
        # modeled as a free zero-return fill. Existing holdings follow the separate,
        # deliberately adverse missing-mark liquidation path above.
        fill_available = execution_price_available.iloc[i].reindex(assets).fillna(False)
        planned_trade_mask = target_weights.sub(pre_trade_weights).abs().gt(1e-12)
        execution_fill_breach_mask = (
            planned_trade_mask & ~fill_available & ~missing_held_mask
        )
        execution_fill_breach_assets = list(
            map(str, assets[execution_fill_breach_mask.to_numpy()])
        )
        execution_fill_breach = bool(execution_fill_breach_mask.any())
        if execution_fill_breach:
            research_path_valid = False
            target_weights.loc[execution_fill_breach_mask] = pre_trade_weights.loc[
                execution_fill_breach_mask
            ]
            shutdown_active = True
            shutdown_reason = "execution_price_unavailable_for_planned_trade"

        transaction_cost_rate = config.costs.transaction_cost_bps / 10_000.0
        pre_trade_equity_dollars = float(config.costs.starting_capital * equity_value)
        adv_today = causal_adv.iloc[i] if causal_adv is not None else None
        primary_cost = _rebalance_cost_details(
            pre_trade_weights,
            target_weights,
            transaction_cost_rate=transaction_cost_rate,
            pre_trade_equity_dollars=pre_trade_equity_dollars,
            adv_dollars=adv_today,
            annualized_asset_volatility=signals.asset_volatility.iloc[signal_row],
            costs=config.costs,
        )
        submitted_trade_notional_by_asset = primary_cost.trade_notional_dollars.copy()
        submitted_trade_dollars = float(submitted_trade_notional_by_asset.sum())
        executed_weights = target_weights.copy()
        turnover = primary_cost.turnover
        transaction_cost = primary_cost.total_cost
        linear_transaction_cost = primary_cost.linear_cost
        market_impact_cost = primary_cost.market_impact_cost
        traded_notional_by_asset = submitted_trade_notional_by_asset.copy()
        canceled_trade_notional_by_asset = pd.Series(0.0, index=assets, dtype=float)
        realized_participation = pd.Series(np.nan, index=assets, dtype=float)
        realized_missing_volume_mask = pd.Series(False, index=assets, dtype=bool)
        realized_participation_breach_mask = pd.Series(
            False, index=assets, dtype=bool
        )
        execution_residual_mask = pd.Series(False, index=assets, dtype=bool)
        execution_fill_ratio = float("nan")
        if realized_execution_window_volume is not None:
            realized_execution = _realized_pov_execution(
                pre_trade_weights,
                primary_cost,
                pre_trade_equity_dollars=pre_trade_equity_dollars,
                realized_window_dollar_volume=(
                    realized_execution_window_volume.iloc[i]
                ),
                transaction_cost_rate=transaction_cost_rate,
                annualized_asset_volatility=(
                    signals.asset_volatility.iloc[signal_row]
                ),
                costs=config.costs,
            )
            executed_weights = realized_execution.post_trade_weights
            traded_notional_by_asset = (
                realized_execution.filled_trade_notional_dollars
            )
            canceled_trade_notional_by_asset = (
                realized_execution.canceled_trade_notional_dollars
            )
            realized_participation = realized_execution.realized_participation
            asset_labels = pd.Index(map(str, assets))
            realized_missing_volume_mask = pd.Series(
                asset_labels.isin(realized_execution.missing_volume_assets),
                index=assets,
                dtype=bool,
            )
            realized_participation_breach_mask = pd.Series(
                asset_labels.isin(realized_execution.participation_breach_assets),
                index=assets,
                dtype=bool,
            )
            execution_residual_mask = pd.Series(
                asset_labels.isin(realized_execution.residual_assets),
                index=assets,
                dtype=bool,
            )
            execution_fill_ratio = realized_execution.fill_ratio
            turnover = float(
                traded_notional_by_asset.sum() / pre_trade_equity_dollars
            )
            transaction_cost = realized_execution.total_cost
            linear_transaction_cost = realized_execution.linear_cost
            market_impact_cost = realized_execution.market_impact_cost
            if (
                bool(realized_missing_volume_mask.any())
                or bool(realized_participation_breach_mask.any())
                or bool(execution_residual_mask.any())
            ):
                liquidity_path_valid = False
                research_path_valid = False
        equity_value *= max(1.0 - transaction_cost, 1e-8)

        peak_equity = max(peak_equity, equity_value)
        final_drawdown = equity_value / peak_equity - 1.0

        # A breach first observed from the completed row-t endpoint/cost cannot be
        # liquidated at that same already-completed VWAP. Arm the next executable
        # decision; row t retains the target that was causally decided before its fill.
        emergency_flatten_turnover = 0.0
        convex_impact_surcharge = 0.0
        if final_drawdown <= -config.risk.flatten_drawdown and executed_weights.abs().sum() > 0:
            cooldown_remaining = max(
                cooldown_remaining, config.risk.cooldown_days
            )
            shutdown_active = True
            shutdown_reason = "drawdown_flatten_armed_next_execution"

        liquidity_model_active = causal_adv is not None
        participation = pd.Series(np.nan, index=assets, dtype=float)
        missing_adv_mask = pd.Series(False, index=assets, dtype=bool)
        participation_breach_mask = pd.Series(False, index=assets, dtype=bool)
        traded_dollars = float(traded_notional_by_asset.sum())
        missing_adv_traded_dollars = 0.0
        max_participation = float("nan")
        participation_capacity_aum = float("nan")
        if liquidity_model_active:
            assert adv_today is not None
            valid_adv = adv_today.notna() & np.isfinite(adv_today) & adv_today.gt(0.0)
            minimum_trade_dollars = max(pre_trade_equity_dollars * 1e-12, 0.01)
            # This is the causal forecast-cap diagnostic for the submitted order.
            # The separately recorded realized diagnostics below describe fills.
            traded_mask = submitted_trade_notional_by_asset.gt(minimum_trade_dollars)
            missing_adv_mask = traded_mask & ~valid_adv
            participation = submitted_trade_notional_by_asset.div(
                adv_today.where(valid_adv)
            )
            participation_breach_mask = (
                traded_mask
                & valid_adv
                & participation.gt(config.costs.max_participation_rate)
            )
            valid_participation = participation.loc[traded_mask & valid_adv].dropna()
            if not valid_participation.empty:
                max_participation = float(valid_participation.max())
                if max_participation > 0.0:
                    participation_capacity_aum = (
                        pre_trade_equity_dollars
                        * config.costs.max_participation_rate
                        / max_participation
                    )
            missing_adv_traded_dollars = float(
                submitted_trade_notional_by_asset.loc[missing_adv_mask].sum()
            )
            if bool(missing_adv_mask.any()) or bool(participation_breach_mask.any()):
                liquidity_path_valid = False
                research_path_valid = False

        canceled_trade_dollars = float(canceled_trade_notional_by_asset.sum())
        realized_missing_volume_notional = float(
            submitted_trade_notional_by_asset.loc[
                realized_missing_volume_mask
            ].sum()
        )
        valid_realized_participation = realized_participation.replace(
            [np.inf, -np.inf], np.nan
        ).dropna()
        maximum_realized_participation = (
            float(valid_realized_participation.max())
            if not valid_realized_participation.empty
            else float("nan")
        )
        execution_residual_breach = bool(execution_residual_mask.any())

        hard_breach = final_drawdown <= -config.risk.hard_drawdown_limit
        if hard_breach:
            # This breach is observed only after the row-t endpoint/fill.  It arms the
            # next execution's mandatory flatten but cannot rewrite the already-made
            # row-t target decision.
            cooldown_remaining = max(cooldown_remaining, config.risk.cooldown_days)
            shutdown_active = True
            shutdown_reason = "hard_drawdown_breach"

        covariance_observation_complete = bool(raw_day_returns.notna().all())

        net_strategy_return = equity_value / start_equity - 1.0
        current_weights = executed_weights.copy()

        gross_after = float(current_weights.abs().sum())
        net_after = float(current_weights.sum())
        beta_vector = beta.reindex(assets)
        held_beta_missing = (
            current_weights.abs().gt(1e-12)
            & (beta_vector.isna() | ~np.isfinite(beta_vector))
        )
        beta_data_breach = bool(
            config.portfolio.beta_neutral and held_beta_missing.any()
        )
        if beta_data_breach:
            research_path_valid = False
            beta_exposure = float("nan")
        else:
            beta_exposure = float(current_weights.dot(beta_vector.fillna(0.0)))
        target_dollar_neutrality_certified = bool(
            not config.portfolio.dollar_neutral or abs(net_after) <= 1e-8
        )
        target_beta_neutrality_certified = bool(
            not config.portfolio.beta_neutral
            or (
                not beta_data_breach
                and np.isfinite(beta_exposure)
                and abs(beta_exposure) <= 1e-8
            )
        )
        target_neutrality_certified = bool(
            target_dollar_neutrality_certified
            and target_beta_neutrality_certified
        )
        if target_rebalance and not target_neutrality_certified:
            # A constructor/post-processing regression is a validity failure, even if
            # the broader exposure safety limits would not yet be crossed.
            research_path_valid = False

        equity_history.append(equity_value)
        return_history.append(net_strategy_return)
        weights_history.append(current_weights.copy())
        diagnostics.append(
            {
                "date": date,
                "equity": equity_value,
                "strategy_return": net_strategy_return,
                "gross_portfolio_return": gross_portfolio_return,
                "holding_net_return": holding_net_return,
                "borrow_cost": borrow_cost,
                "financing_cost": financing_cost,
                "transaction_cost": transaction_cost,
                "linear_transaction_cost": linear_transaction_cost,
                "market_impact_cost": market_impact_cost,
                "convex_impact_surcharge": convex_impact_surcharge,
                "modeled_transaction_cost_bps": config.costs.transaction_cost_bps,
                "configured_annual_short_borrow_rate": (
                    config.costs.annual_short_borrow_rate
                ),
                "borrow_rate_stress_multiplier": float(
                    borrow_rate_stress_multiplier
                ),
                "corporate_action_model_active": corporate_action_model_active,
                "execution_window_liquidity_model_active": (
                    execution_window_dollar_volume is not None
                ),
                "point_in_time_borrow_model_active": (
                    point_in_time_borrow_model_active
                ),
                "borrow_unavailable_increase_count": int(
                    borrow_unavailable_increase_mask.sum()
                ),
                "borrow_recall_close_count": int(borrow_recall_close_mask.sum()),
                "borrow_eligible_assets": int(borrow_short_eligible.sum()),
                "configured_annual_financing_rate": (
                    config.costs.annual_financing_rate
                ),
                "carry_day_count_convention": CARRY_DAY_COUNT_CONVENTION,
                "elapsed_calendar_days": elapsed_calendar_days,
                "carry_year_fraction": carry_year_fraction,
                "pre_return_gross_exposure": gross_before,
                "pre_return_short_gross_exposure": short_gross_before,
                "pre_return_financed_gross_exposure": financed_gross,
                "effective_transaction_cost_bps": (
                    transaction_cost / turnover * 10_000.0
                    if turnover > 1e-12
                    else float("nan")
                ),
                "turnover": turnover,
                "submitted_turnover": primary_cost.turnover,
                "pre_trade_equity_dollars": pre_trade_equity_dollars,
                "ending_equity_dollars": float(
                    config.costs.starting_capital * equity_value
                ),
                "traded_notional_dollars": traded_dollars,
                "submitted_trade_notional_dollars": submitted_trade_dollars,
                "filled_trade_notional_dollars": traded_dollars,
                "canceled_trade_notional_dollars": canceled_trade_dollars,
                "execution_fill_ratio": execution_fill_ratio,
                "missing_adv_traded_notional_dollars": missing_adv_traded_dollars,
                "realized_missing_volume_notional_dollars": (
                    realized_missing_volume_notional
                ),
                "liquidity_model_active": liquidity_model_active,
                "configured_starting_capital_dollars": (
                    config.costs.starting_capital
                ),
                "adv_lookback_days": config.costs.adv_lookback_days,
                "maximum_participation_rate": max_participation,
                "maximum_forecast_participation_rate": max_participation,
                "maximum_realized_participation_rate": (
                    maximum_realized_participation
                ),
                "participation_limit": config.costs.max_participation_rate,
                "participation_capacity_aum": participation_capacity_aum,
                "square_root_impact_coefficient": (
                    config.costs.square_root_impact_coefficient
                ),
                "impact_daily_volatility_floor": (
                    config.costs.impact_daily_volatility_floor
                ),
                "liquidity_data_breach": bool(
                    missing_adv_mask.any() or realized_missing_volume_mask.any()
                ),
                "participation_breach": bool(
                    participation_breach_mask.any()
                    or realized_participation_breach_mask.any()
                ),
                "realized_volume_data_breach": bool(
                    realized_missing_volume_mask.any()
                ),
                "realized_participation_breach": bool(
                    realized_participation_breach_mask.any()
                ),
                "execution_residual_breach": execution_residual_breach,
                "liquidity_path_valid": liquidity_path_valid,
                "missing_adv_asset_count": int(missing_adv_mask.sum()),
                "missing_adv_assets": ",".join(
                    map(str, assets[missing_adv_mask.to_numpy()])
                ),
                "participation_breach_asset_count": int(
                    participation_breach_mask.sum()
                ),
                "participation_breach_assets": ",".join(
                    map(str, assets[participation_breach_mask.to_numpy()])
                ),
                "realized_missing_volume_asset_count": int(
                    realized_missing_volume_mask.sum()
                ),
                "realized_missing_volume_assets": ",".join(
                    map(str, assets[realized_missing_volume_mask.to_numpy()])
                ),
                "realized_participation_breach_asset_count": int(
                    realized_participation_breach_mask.sum()
                ),
                "realized_participation_breach_assets": ",".join(
                    map(
                        str,
                        assets[realized_participation_breach_mask.to_numpy()],
                    )
                ),
                "execution_residual_asset_count": int(
                    execution_residual_mask.sum()
                ),
                "execution_residual_assets": ",".join(
                    map(str, assets[execution_residual_mask.to_numpy()])
                ),
                "pre_trade_gross_exposure": float(pre_trade_weights.abs().sum()),
                "pre_trade_net_exposure": float(pre_trade_weights.sum()),
                "emergency_flatten_turnover": emergency_flatten_turnover,
                "drawdown": final_drawdown,
                "pre_trade_drawdown": pre_trade_drawdown,
                "decision_drawdown": decision_drawdown,
                "drawdown_multiplier": dd_multiplier,
                "loss_shock_multiplier": loss_shock_multiplier,
                "lagged_five_day_return": five_day_return,
                "previous_strategy_return": previous_strategy_return,
                "gross_exposure": gross_after,
                "net_exposure": net_after,
                "beta_exposure": beta_exposure,
                "target_rebalance": target_rebalance,
                "target_dollar_neutrality_certified": (
                    target_dollar_neutrality_certified
                ),
                "target_beta_neutrality_certified": (
                    target_beta_neutrality_certified
                ),
                "target_neutrality_certified": target_neutrality_certified,
                "beta_data_breach": beta_data_breach,
                "missing_held_beta_count": int(held_beta_missing.sum()),
                "missing_held_beta_assets": ",".join(
                    map(str, assets[held_beta_missing.to_numpy()])
                ),
                "forecast_volatility": forecast_vol,
                "volatility_leverage": volatility_leverage,
                "desired_gross": desired_gross,
                "market_regime": regime_name,
                "regime_multiplier": regime_multiplier,
                "signal_date": signal_date,
                "return_semantics": execution_return_semantics,
                "data_integrity_breach": data_integrity_breach,
                "research_path_valid": research_path_valid,
                "missing_held_asset_count": len(missing_held_assets),
                "missing_held_assets": ",".join(missing_held_assets),
                "stale_signal_trade_breach": stale_signal_trade_breach,
                "stale_signal_trade_assets": ",".join(
                    stale_signal_risk_increase_assets
                ),
                "execution_fill_breach": execution_fill_breach,
                "execution_fill_breach_assets": ",".join(
                    execution_fill_breach_assets
                ),
                "covariance_observation_complete": (
                    covariance_observation_complete
                ),
                "incomplete_signal_history_asset_count": len(
                    incomplete_signal_history_assets
                ),
                "incomplete_signal_history_assets": ",".join(
                    incomplete_signal_history_assets
                ),
                "incomplete_execution_history_asset_count": len(
                    incomplete_execution_history_assets
                ),
                "incomplete_execution_history_assets": ",".join(
                    incomplete_execution_history_assets
                ),
                "information_coefficient": signals.information_coefficient.iloc[signal_row],
                "ic_tstat": signals.ic_tstat.iloc[signal_row],
                "market_volatility": signals.market_volatility.iloc[signal_row],
                "signal_dispersion": signals.signal_dispersion.iloc[signal_row],
                "eligible_assets": effective_eligible_assets,
                "shutdown_active": shutdown_active,
                "shutdown_reason": shutdown_reason,
                "cooldown_remaining": cooldown_remaining,
                "hard_drawdown_breach": hard_breach,
            }
        )

    equity = pd.Series(equity_history, index=prices.index, name="Equity")
    strategy_returns = pd.Series(return_history, index=prices.index, name="Strategy Return")
    weights = pd.DataFrame(weights_history, index=prices.index, columns=assets)
    diagnostic_frame = pd.DataFrame(diagnostics).set_index("date")
    diagnostic_frame.index.name = "Date"

    return BacktestResult(
        equity=equity,
        strategy_returns=strategy_returns,
        weights=weights,
        diagnostics=diagnostic_frame,
        signals=signals,
        prices=prices,
        config=config,
        return_semantics=execution_return_semantics,
        observed_prices=observed_prices,
    )
