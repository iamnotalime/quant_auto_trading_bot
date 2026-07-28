from __future__ import annotations

import math
from typing import Any

import numpy as np
import pandas as pd

TRADING_DAYS = 252


def equity_from_returns(returns: pd.Series, initial: float = 1.0) -> pd.Series:
    clean = returns.fillna(0.0).clip(lower=-0.999999)
    return initial * (1.0 + clean).cumprod()


def drawdown_series(
    equity: pd.Series,
    initial_equity: float | None = None,
) -> pd.Series:
    """Return drawdowns, optionally including capital immediately before the series.

    A sliced return history has no observation for its starting capital. Supplying that
    capital prevents a loss in the first observation from incorrectly becoming the
    high-water mark and disappearing from maximum drawdown.
    """
    equity = equity.dropna()
    peaks = equity.cummax()
    if initial_equity is not None:
        if not np.isfinite(initial_equity) or initial_equity <= 0.0:
            raise ValueError("initial_equity must be finite and strictly positive.")
        peaks = peaks.clip(lower=float(initial_equity))
    return equity.div(peaks).sub(1.0)


def _safe_ratio(numerator: float, denominator: float) -> float:
    if not np.isfinite(numerator) or not np.isfinite(denominator) or abs(denominator) < 1e-12:
        return float("nan")
    return numerator / denominator


def metrics_from_returns(
    returns: pd.Series,
    diagnostics: pd.DataFrame | None = None,
) -> dict[str, Any]:
    r = returns.dropna().astype(float)
    if r.empty:
        return {
            "Observations": 0,
            "CAGR": float("nan"),
            "Max Drawdown": float("nan"),
        }

    equity = equity_from_returns(r)
    years = len(r) / TRADING_DAYS
    total_return = float(equity.iloc[-1] - 1.0)
    cagr = float(equity.iloc[-1] ** (1.0 / years) - 1.0) if years > 0 else float("nan")
    annual_vol = float(r.std(ddof=1) * np.sqrt(TRADING_DAYS))
    annual_mean = float(r.mean() * TRADING_DAYS)
    sharpe = _safe_ratio(annual_mean, annual_vol)

    downside = r[r < 0]
    downside_vol = float(downside.std(ddof=1) * np.sqrt(TRADING_DAYS)) if len(downside) > 1 else float("nan")
    sortino = _safe_ratio(annual_mean, downside_vol)

    dd = drawdown_series(equity, initial_equity=1.0)
    max_dd = float(dd.min())
    calmar = _safe_ratio(cagr, abs(max_dd)) if max_dd < 0 else float("nan")

    gains = float(r[r > 0].sum())
    losses = float(-r[r < 0].sum())
    profit_factor = _safe_ratio(gains, losses)
    hit_rate = float((r > 0).mean())

    var_95 = float(r.quantile(0.05))
    tail = r[r <= var_95]
    cvar_95 = float(tail.mean()) if not tail.empty else float("nan")

    metrics: dict[str, Any] = {
        "Observations": int(len(r)),
        "Years": years,
        "Total Return": total_return,
        "CAGR": cagr,
        "Annualized Volatility": annual_vol,
        "Sharpe Ratio": sharpe,
        "Sortino Ratio": sortino,
        "Max Drawdown": max_dd,
        "Calmar Ratio": calmar,
        "Hit Rate": hit_rate,
        "Profit Factor": profit_factor,
        "Best Day": float(r.max()),
        "Worst Day": float(r.min()),
        "Daily VaR 95%": var_95,
        "Daily CVaR 95%": cvar_95,
        "Skewness": float(r.skew()),
        "Excess Kurtosis": float(r.kurt()),
    }

    if diagnostics is not None and not diagnostics.empty:
        d = diagnostics.reindex(r.index)
        active = d["gross_exposure"].fillna(0.0) > 1e-8
        shutdown = d["shutdown_active"].fillna(False).astype(bool)
        shutdown_starts = shutdown & ~shutdown.shift(1, fill_value=False)
        data_integrity_breaches = (
            d["data_integrity_breach"].fillna(False).astype(bool)
            if "data_integrity_breach" in d
            else pd.Series(False, index=d.index)
        )
        beta_data_breaches = (
            d["beta_data_breach"].fillna(False).astype(bool)
            if "beta_data_breach" in d
            else pd.Series(False, index=d.index)
        )
        research_path_valid = (
            d["research_path_valid"].fillna(False).astype(bool)
            if "research_path_valid" in d
            else pd.Series(True, index=d.index)
        )
        carry_days = (
            pd.to_numeric(d["elapsed_calendar_days"], errors="coerce")
            if "elapsed_calendar_days" in d
            else pd.Series(np.nan, index=d.index, dtype=float)
        )
        carry_year_fractions = (
            pd.to_numeric(d["carry_year_fraction"], errors="coerce")
            if "carry_year_fraction" in d
            else pd.Series(np.nan, index=d.index, dtype=float)
        )
        carry_conventions = (
            d["carry_day_count_convention"].dropna().astype(str).unique().tolist()
            if "carry_day_count_convention" in d
            else []
        )
        carry_day_count_convention = (
            carry_conventions[0] if len(carry_conventions) == 1 else "invalid/mixed"
        )
        carry_day_count_valid = bool(
            carry_day_count_convention == "ACT/365.25"
            and carry_days.notna().all()
            and carry_year_fractions.notna().all()
            and carry_days.ge(0.0).all()
            and carry_year_fractions.ge(0.0).all()
            and np.allclose(
                carry_year_fractions.to_numpy(dtype=float),
                carry_days.to_numpy(dtype=float) / 365.25,
                rtol=0.0,
                atol=1e-15,
            )
        )
        realized_carry_years = float(carry_year_fractions.sum())
        elapsed_years = max(
            realized_carry_years
            if carry_day_count_valid and realized_carry_years > 0.0
            else len(d) / TRADING_DAYS,
            1.0 / TRADING_DAYS,
        )
        annual_turnover = float(d["turnover"].sum() / elapsed_years)
        annual_transaction_cost = float(d["transaction_cost"].sum() / elapsed_years)
        annual_linear_transaction_cost = float(
            (
                d["linear_transaction_cost"]
                if "linear_transaction_cost" in d
                else d["transaction_cost"]
            ).sum()
            / elapsed_years
        )
        annual_market_impact_cost = float(
            (
                d["market_impact_cost"]
                if "market_impact_cost" in d
                else pd.Series(0.0, index=d.index)
            ).sum()
            / elapsed_years
        )
        annual_borrow_cost = float(d["borrow_cost"].sum() / elapsed_years)
        annual_financing_cost = float(d["financing_cost"].sum() / elapsed_years)
        annual_total_cost = (
            annual_transaction_cost + annual_borrow_cost + annual_financing_cost
        )
        annual_pre_cost_return = float(d["gross_portfolio_return"].mean() * TRADING_DAYS)
        annual_pre_transaction_return = float(d["holding_net_return"].mean() * TRADING_DAYS)
        cost_coverage = _safe_ratio(annual_pre_cost_return, annual_total_cost)
        break_even_transaction_bps = (
            _safe_ratio(annual_pre_transaction_return, annual_turnover) * 10_000.0
        )
        linear_transaction_bps = (
            float(d["modeled_transaction_cost_bps"].median())
            if "modeled_transaction_cost_bps" in d
            else float("nan")
        )
        modeled_transaction_bps = (
            _safe_ratio(annual_transaction_cost, annual_turnover) * 10_000.0
        )
        liquidity_model_active = bool(
            d["liquidity_model_active"].fillna(False).astype(bool).all()
        ) if "liquidity_model_active" in d else False
        liquidity_data_breaches = int(
            d["liquidity_data_breach"].fillna(False).astype(bool).sum()
        ) if "liquidity_data_breach" in d else 0
        participation_breaches = int(
            d["participation_breach"].fillna(False).astype(bool).sum()
        ) if "participation_breach" in d else 0
        realized_volume_data_breaches = int(
            d["realized_volume_data_breach"].fillna(False).astype(bool).sum()
        ) if "realized_volume_data_breach" in d else 0
        realized_participation_breaches = int(
            d["realized_participation_breach"].fillna(False).astype(bool).sum()
        ) if "realized_participation_breach" in d else 0
        execution_residual_breaches = int(
            d["execution_residual_breach"].fillna(False).astype(bool).sum()
        ) if "execution_residual_breach" in d else 0
        liquidity_path_valid = bool(
            d["liquidity_path_valid"].fillna(False).astype(bool).all()
        ) if "liquidity_path_valid" in d else False
        maximum_participation = (
            float(d["maximum_participation_rate"].max())
            if "maximum_participation_rate" in d
            else float("nan")
        )
        maximum_realized_participation = (
            float(d["maximum_realized_participation_rate"].max())
            if "maximum_realized_participation_rate" in d
            else float("nan")
        )
        configured_participation_limit = (
            float(d["participation_limit"].median())
            if "participation_limit" in d
            else float("nan")
        )
        capacity_values = (
            d["participation_capacity_aum"].replace([np.inf, -np.inf], np.nan).dropna()
            if "participation_capacity_aum" in d
            else pd.Series(dtype=float)
        )
        total_traded_dollars = (
            float(d["traded_notional_dollars"].sum())
            if "traded_notional_dollars" in d
            else float("nan")
        )
        total_submitted_dollars = (
            float(d["submitted_trade_notional_dollars"].sum())
            if "submitted_trade_notional_dollars" in d
            else total_traded_dollars
        )
        total_canceled_dollars = (
            float(d["canceled_trade_notional_dollars"].sum())
            if "canceled_trade_notional_dollars" in d
            else 0.0
        )
        execution_fill_ratios = (
            d.loc[
                d["submitted_trade_notional_dollars"].gt(0.01),
                "execution_fill_ratio",
            ]
            .replace([np.inf, -np.inf], np.nan)
            .dropna()
            if {
                "submitted_trade_notional_dollars",
                "execution_fill_ratio",
            }.issubset(d.columns)
            else pd.Series(dtype=float)
        )
        missing_adv_traded_dollars = (
            float(d["missing_adv_traded_notional_dollars"].sum())
            if "missing_adv_traded_notional_dollars" in d
            else float("nan")
        )
        adv_coverage = (
            1.0 - missing_adv_traded_dollars / total_traded_dollars
            if (
                np.isfinite(total_traded_dollars)
                and total_traded_dollars > 1e-8
                and np.isfinite(missing_adv_traded_dollars)
            )
            else float("nan")
        )
        impact_coefficient = (
            float(d["square_root_impact_coefficient"].median())
            if "square_root_impact_coefficient" in d
            else float("nan")
        )
        configured_starting_capital = (
            float(d["configured_starting_capital_dollars"].median())
            if "configured_starting_capital_dollars" in d
            else float("nan")
        )
        adv_lookback_days = (
            float(d["adv_lookback_days"].median())
            if "adv_lookback_days" in d
            else float("nan")
        )
        impact_volatility_floor = (
            float(d["impact_daily_volatility_floor"].median())
            if "impact_daily_volatility_floor" in d
            else float("nan")
        )
        configured_short_borrow_rate = (
            float(d["configured_annual_short_borrow_rate"].median())
            if "configured_annual_short_borrow_rate" in d
            else float("nan")
        )
        configured_financing_rate = (
            float(d["configured_annual_financing_rate"].median())
            if "configured_annual_financing_rate" in d
            else float("nan")
        )
        minimum_eligible_asset_count = (
            int(d["eligible_assets"].min())
            if "eligible_assets" in d and d["eligible_assets"].notna().any()
            else 0
        )
        stale_signal_trade_breaches = (
            int(d["stale_signal_trade_breach"].fillna(False).astype(bool).sum())
            if "stale_signal_trade_breach" in d
            else 1
        )
        post_trade_maximum_gross = float(d["gross_exposure"].max())
        pre_trade_maximum_gross = (
            float(d["pre_trade_gross_exposure"].max())
            if "pre_trade_gross_exposure" in d
            else post_trade_maximum_gross
        )
        maximum_gross = float(
            np.nanmax([post_trade_maximum_gross, pre_trade_maximum_gross])
        )

        metrics.update(
            {
                "Average Gross Exposure": float(d["gross_exposure"].mean()),
                "Maximum Gross Exposure": maximum_gross,
                "Maximum Pre-Trade Gross Exposure": pre_trade_maximum_gross,
                "Maximum Post-Trade Gross Exposure": post_trade_maximum_gross,
                "95th Percentile Gross Exposure": float(d["gross_exposure"].quantile(0.95)),
                "Average Absolute Net Exposure": float(d["net_exposure"].abs().mean()),
                "Maximum Absolute Beta Exposure": float(d["beta_exposure"].abs().max()),
                "Annualized Turnover": annual_turnover,
                "Annualized Pre-Cost Return": annual_pre_cost_return,
                "Annualized Pre-Transaction Return": annual_pre_transaction_return,
                "Annualized Transaction Cost": annual_transaction_cost,
                "Annualized Linear Transaction Cost": annual_linear_transaction_cost,
                "Annualized Market Impact Cost": annual_market_impact_cost,
                "Annualized Borrow Cost": annual_borrow_cost,
                "Annualized Financing Cost": annual_financing_cost,
                "Annualized Total Modeled Cost": annual_total_cost,
                "Cost Coverage Ratio": cost_coverage,
                "Break-Even Transaction Cost Bps": break_even_transaction_bps,
                "Modeled Transaction Cost Bps": modeled_transaction_bps,
                "Modeled Linear Transaction Cost Bps": linear_transaction_bps,
                "Configured Linear Transaction Cost Bps": linear_transaction_bps,
                "Configured Annual Short Borrow Rate": configured_short_borrow_rate,
                "Configured Annual Financing Rate": configured_financing_rate,
                "Carry Day Count Convention": carry_day_count_convention,
                "Carry Day Count Valid": carry_day_count_valid,
                "Total Carry Calendar Days": float(carry_days.sum()),
                "Maximum Carry Interval Days": float(carry_days.max()),
                "Realized Carry Elapsed Years": realized_carry_years,
                "Liquidity Model Active": liquidity_model_active,
                "Liquidity Data Breaches": liquidity_data_breaches,
                "Participation Limit Breaches": participation_breaches,
                "Realized Volume Data Breaches": realized_volume_data_breaches,
                "Realized Participation Limit Breaches": (
                    realized_participation_breaches
                ),
                "Execution Residual Breaches": execution_residual_breaches,
                "Liquidity Path Valid": liquidity_path_valid,
                "Maximum Participation Rate": maximum_participation,
                "Maximum Realized Participation Rate": (
                    maximum_realized_participation
                ),
                "Minimum Execution Fill Ratio": (
                    float(execution_fill_ratios.min())
                    if not execution_fill_ratios.empty
                    else float("nan")
                ),
                "Canceled Notional Dollars": total_canceled_dollars,
                "Canceled Notional Fraction": (
                    total_canceled_dollars / total_submitted_dollars
                    if (
                        np.isfinite(total_submitted_dollars)
                        and total_submitted_dollars > 0.01
                    )
                    else 0.0
                ),
                "Configured Participation Limit": configured_participation_limit,
                "Maximum Participation Utilization": _safe_ratio(
                    maximum_participation,
                    configured_participation_limit,
                ),
                "Minimum Participation-Implied AUM Capacity": (
                    float(capacity_values.min())
                    if not capacity_values.empty
                    else float("nan")
                ),
                "ADV Coverage of Traded Notional": adv_coverage,
                "Annualized Traded Notional Dollars": (
                    total_traded_dollars / elapsed_years
                    if np.isfinite(total_traded_dollars)
                    else float("nan")
                ),
                "Configured Starting Capital Dollars": configured_starting_capital,
                "ADV Lookback Days": adv_lookback_days,
                "Square-Root Impact Coefficient": impact_coefficient,
                "Impact Daily Volatility Floor": impact_volatility_floor,
                "Minimum Eligible Asset Count": minimum_eligible_asset_count,
                "Stale Signal Trade Breaches": stale_signal_trade_breaches,
                "Active Days": int(active.sum()),
                "Active Day Fraction": float(active.mean()),
                "Shutdown Events": int(shutdown_starts.sum()),
                "Shutdown Day Fraction": float(shutdown.mean()),
                "Hard Drawdown Breaches": int(d["hard_drawdown_breach"].fillna(False).sum()),
                "Data Integrity Breaches": int(data_integrity_breaches.sum()),
                "Beta Data Breaches": int(beta_data_breaches.sum()),
                "Research Path Valid": bool(research_path_valid.all()),
                "Mean Information Coefficient": float(d["information_coefficient"].mean()),
                "Median IC t-stat": float(d["ic_tstat"].median()),
            }
        )
    return metrics


def annual_performance(returns: pd.Series) -> pd.DataFrame:
    r = returns.dropna()
    records: list[dict[str, float | int]] = []
    for year, group in r.groupby(r.index.year):
        metrics = metrics_from_returns(group)
        records.append(
            {
                "Year": int(year),
                "Return": float((1.0 + group).prod() - 1.0),
                "Volatility": metrics.get("Annualized Volatility", float("nan")),
                "Sharpe": metrics.get("Sharpe Ratio", float("nan")),
                "Max Drawdown": metrics.get("Max Drawdown", float("nan")),
            }
        )
    return pd.DataFrame(records).set_index("Year") if records else pd.DataFrame()


def regime_performance(returns: pd.Series, diagnostics: pd.DataFrame) -> pd.DataFrame:
    aligned = pd.DataFrame(
        {
            "return": returns,
            # The regime selected at close t-1 governs exposure earning return t.
            "regime": diagnostics["market_regime"].shift(1),
            "gross": diagnostics["gross_exposure"].shift(1),
        }
    ).dropna(subset=["return"])

    rows: list[dict[str, Any]] = []
    for regime in ["favorable", "neutral", "degraded", "invalid", "warmup"]:
        part = aligned[aligned["regime"] == regime]
        if part.empty:
            continue
        m = metrics_from_returns(part["return"])
        rows.append(
            {
                "Regime": regime,
                "Days": len(part),
                "Fraction": len(part) / max(len(aligned), 1),
                "CAGR": m.get("CAGR", float("nan")),
                "Volatility": m.get("Annualized Volatility", float("nan")),
                "Sharpe": m.get("Sharpe Ratio", float("nan")),
                "Max Drawdown": m.get("Max Drawdown", float("nan")),
                "Average Gross": float(part["gross"].mean()),
            }
        )
    return pd.DataFrame(rows).set_index("Regime") if rows else pd.DataFrame()


def rolling_metrics(returns: pd.Series, window: int = 252) -> pd.DataFrame:
    r = returns.fillna(0.0)
    rolling_return = (1.0 + r).rolling(window).apply(np.prod, raw=True).sub(1.0)
    rolling_vol = r.rolling(window).std(ddof=1).mul(np.sqrt(TRADING_DAYS))
    rolling_mean = r.rolling(window).mean().mul(TRADING_DAYS)
    rolling_sharpe = rolling_mean.div(rolling_vol.replace(0.0, np.nan))

    def window_max_dd(values: np.ndarray) -> float:
        eq = np.cumprod(1.0 + values)
        # Each rolling slice begins with one unit of capital immediately before its
        # first return. Without that baseline, a first-day loss is omitted.
        peaks = np.maximum.accumulate(np.maximum(eq, 1.0))
        return float(np.min(eq / peaks - 1.0))

    rolling_dd = r.rolling(window).apply(window_max_dd, raw=True)
    return pd.DataFrame(
        {
            "Rolling Return": rolling_return,
            "Rolling Volatility": rolling_vol,
            "Rolling Sharpe": rolling_sharpe,
            "Rolling Max Drawdown": rolling_dd,
        }
    )


def format_metric_value(name: str, value: Any) -> str:
    if value is None or (isinstance(value, float) and not math.isfinite(value)):
        return "N/A"
    if isinstance(value, (bool, np.bool_)):
        return "Yes" if bool(value) else "No"
    if isinstance(value, (int, np.integer)):
        return f"{int(value):,}"
    percentage_terms = (
        "Return",
        "CAGR",
        "Volatility",
        "Drawdown",
        "Hit Rate",
        "VaR",
        "CVaR",
        "Exposure",
        "Cost",
        "Fraction",
    )
    if any(term in name for term in percentage_terms):
        return f"{float(value):.2%}"
    return f"{float(value):.3f}"
