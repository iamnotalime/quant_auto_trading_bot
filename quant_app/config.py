from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Any


def _finite(name: str, value: float) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be numeric.") from exc
    if not math.isfinite(numeric):
        raise ValueError(f"{name} must be finite.")
    return numeric


def _range(
    name: str,
    value: float,
    lower: float,
    upper: float,
    *,
    lower_open: bool = False,
    upper_open: bool = False,
) -> None:
    numeric = _finite(name, value)
    lower_ok = numeric > lower if lower_open else numeric >= lower
    upper_ok = numeric < upper if upper_open else numeric <= upper
    if not lower_ok or not upper_ok:
        left = "(" if lower_open else "["
        right = ")" if upper_open else "]"
        raise ValueError(f"{name} must be in {left}{lower}, {upper}{right}.")


def _integer(name: str, value: int, lower: int, upper: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        raise ValueError(f"{name} must be an integer between {lower} and {upper}.")


@dataclass(frozen=True)
class SignalConfig:
    reversal_3_weight: float = 0.25
    reversal_10_weight: float = 0.20
    residual_reversal_weight: float = 0.25
    momentum_63_weight: float = 0.15
    momentum_126_weight: float = 0.15
    beta_lookback: int = 126
    vol_lookback: int = 20
    signal_clip: float = 3.0


@dataclass(frozen=True)
class PortfolioConfig:
    target_volatility: float = 0.10
    max_gross_leverage: float = 2.50
    max_position_weight: float = 0.08
    covariance_halflife: int = 42
    rebalance_every: int = 1
    beta_neutral: bool = True
    dollar_neutral: bool = True


@dataclass(frozen=True)
class RegimeConfig:
    ic_window: int = 60
    favorable_ic_tstat: float = 0.50
    neutral_ic_tstat: float = 0.00
    invalid_ic_tstat: float = -0.75
    favorable_multiplier: float = 1.00
    neutral_multiplier: float = 0.70
    degraded_multiplier: float = 0.30
    invalid_multiplier: float = 0.00
    volatility_stress_percentile: float = 0.90
    minimum_cross_sectional_dispersion: float = 0.35


@dataclass(frozen=True)
class RiskConfig:
    throttle_drawdown: float = 0.05
    defensive_drawdown: float = 0.08
    severe_drawdown: float = 0.10
    flatten_drawdown: float = 0.12
    hard_drawdown_limit: float = 0.15
    throttle_multiplier: float = 0.75
    defensive_multiplier: float = 0.50
    severe_multiplier: float = 0.20
    cooldown_days: int = 20
    daily_loss_trigger: float = 0.02
    five_day_loss_trigger: float = 0.04
    loss_shock_multiplier: float = 0.50


@dataclass(frozen=True)
class CostConfig:
    transaction_cost_bps: float = 3.0
    annual_short_borrow_rate: float = 0.02
    annual_financing_rate: float = 0.04
    # Normalized returns are converted back to dollars before liquidity and market
    # impact are evaluated.  The liquidity model remains disabled until an aligned
    # daily-dollar-volume frame is supplied to ``run_backtest``.
    starting_capital: float = 10_000_000.0
    adv_lookback_days: int = 20
    max_participation_rate: float = 0.01
    square_root_impact_coefficient: float = 1.0
    impact_daily_volatility_floor: float = 0.01


@dataclass(frozen=True)
class AppConfig:
    signals: SignalConfig = SignalConfig()
    portfolio: PortfolioConfig = PortfolioConfig()
    regime: RegimeConfig = RegimeConfig()
    risk: RiskConfig = RiskConfig()
    costs: CostConfig = CostConfig()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def validate(self) -> None:
        """Reject economically contradictory or numerically unsafe specifications."""
        signal_weights = {
            "reversal_3_weight": self.signals.reversal_3_weight,
            "reversal_10_weight": self.signals.reversal_10_weight,
            "residual_reversal_weight": self.signals.residual_reversal_weight,
            "momentum_63_weight": self.signals.momentum_63_weight,
            "momentum_126_weight": self.signals.momentum_126_weight,
        }
        for name, value in signal_weights.items():
            _range(name, value, 0.0, 10.0)
        if sum(float(value) for value in signal_weights.values()) <= 0.0:
            raise ValueError("At least one signal weight must be positive.")
        _integer("beta_lookback", self.signals.beta_lookback, 20, 2_000)
        _integer("vol_lookback", self.signals.vol_lookback, 2, 1_000)
        _range("signal_clip", self.signals.signal_clip, 0.0, 20.0, lower_open=True)

        portfolio = self.portfolio
        _range("target_volatility", portfolio.target_volatility, 0.0, 1.0, lower_open=True)
        _range("max_gross_leverage", portfolio.max_gross_leverage, 0.0, 10.0, lower_open=True)
        _range("max_position_weight", portfolio.max_position_weight, 0.0, 1.0, lower_open=True)
        _integer("covariance_halflife", portfolio.covariance_halflife, 2, 2_000)
        _integer("rebalance_every", portfolio.rebalance_every, 1, 252)

        regime = self.regime
        _integer("ic_window", regime.ic_window, 10, 2_000)
        thresholds = (
            _finite("favorable_ic_tstat", regime.favorable_ic_tstat),
            _finite("neutral_ic_tstat", regime.neutral_ic_tstat),
            _finite("invalid_ic_tstat", regime.invalid_ic_tstat),
        )
        if not thresholds[0] >= thresholds[1] > thresholds[2]:
            raise ValueError(
                "IC thresholds must satisfy favorable >= neutral > invalid."
            )
        multipliers = (
            regime.favorable_multiplier,
            regime.neutral_multiplier,
            regime.degraded_multiplier,
            regime.invalid_multiplier,
        )
        for name, value in zip(
            ("favorable_multiplier", "neutral_multiplier", "degraded_multiplier", "invalid_multiplier"),
            multipliers,
        ):
            _range(name, value, 0.0, 1.0)
        if list(map(float, multipliers)) != sorted(map(float, multipliers), reverse=True):
            raise ValueError(
                "Regime multipliers must be non-increasing from favorable to invalid."
            )
        _range(
            "volatility_stress_percentile",
            regime.volatility_stress_percentile,
            0.50,
            1.0,
            upper_open=True,
        )
        _range(
            "minimum_cross_sectional_dispersion",
            regime.minimum_cross_sectional_dispersion,
            0.0,
            20.0,
            lower_open=True,
        )

        risk = self.risk
        drawdowns = (
            risk.throttle_drawdown,
            risk.defensive_drawdown,
            risk.severe_drawdown,
            risk.flatten_drawdown,
            risk.hard_drawdown_limit,
        )
        for name, value in zip(
            ("throttle_drawdown", "defensive_drawdown", "severe_drawdown", "flatten_drawdown", "hard_drawdown_limit"),
            drawdowns,
        ):
            _range(name, value, 0.0, 1.0, lower_open=True, upper_open=True)
        numeric_drawdowns = list(map(float, drawdowns))
        if numeric_drawdowns != sorted(numeric_drawdowns) or len(set(numeric_drawdowns)) != len(numeric_drawdowns):
            raise ValueError("Drawdown thresholds must be strictly increasing.")
        risk_multipliers = (
            risk.throttle_multiplier,
            risk.defensive_multiplier,
            risk.severe_multiplier,
        )
        for name, value in zip(
            ("throttle_multiplier", "defensive_multiplier", "severe_multiplier"),
            risk_multipliers,
        ):
            _range(name, value, 0.0, 1.0)
        if list(map(float, risk_multipliers)) != sorted(
            map(float, risk_multipliers), reverse=True
        ):
            raise ValueError("Risk multipliers must not increase as drawdown worsens.")
        _integer("cooldown_days", risk.cooldown_days, 1, 2_000)
        _range("daily_loss_trigger", risk.daily_loss_trigger, 0.0, 1.0, lower_open=True)
        _range("five_day_loss_trigger", risk.five_day_loss_trigger, 0.0, 1.0, lower_open=True)
        _range("loss_shock_multiplier", risk.loss_shock_multiplier, 0.0, 1.0)

        _range("transaction_cost_bps", self.costs.transaction_cost_bps, 0.0, 1_000.0)
        _range("annual_short_borrow_rate", self.costs.annual_short_borrow_rate, 0.0, 2.0)
        _range("annual_financing_rate", self.costs.annual_financing_rate, 0.0, 2.0)
        _range(
            "starting_capital",
            self.costs.starting_capital,
            0.0,
            1.0e15,
            lower_open=True,
        )
        _integer("adv_lookback_days", self.costs.adv_lookback_days, 2, 252)
        _range(
            "max_participation_rate",
            self.costs.max_participation_rate,
            0.0,
            1.0,
            lower_open=True,
        )
        _range(
            "square_root_impact_coefficient",
            self.costs.square_root_impact_coefficient,
            0.0,
            100.0,
        )
        _range(
            "impact_daily_volatility_floor",
            self.costs.impact_daily_volatility_floor,
            0.0,
            1.0,
            lower_open=True,
        )
