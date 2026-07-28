from __future__ import annotations

import hashlib
import hmac
import json
import math
from dataclasses import replace
from datetime import date, datetime, time, timezone
from typing import Any, Mapping
from zoneinfo import ZoneInfo

import numpy as np
import pandas as pd

from auto_trader.models import RiskDecision, TargetPlan
from auto_trader.plan_auth import SIMULATED_PLAN_AUTHENTICATION_KEY
from auto_trader.governed import (
    GOVERNED_EXECUTION_END,
    GOVERNED_MINIMUM_ASSETS,
    GOVERNED_TIMEZONE,
)
from auto_trader.covariance_evidence import (
    COVARIANCE_RETURN_SEMANTICS as SIGNED_EVIDENCE_RETURN_SEMANTICS,
)
from quant_app.backtest import (
    TRAILING_COVARIANCE_RETURN_COUNT,
    _construct_weights,
    _drawdown_multiplier,
    trailing_ewma_covariance,
)
from quant_app.config import AppConfig
from quant_app.data import validate_daily_session_index
from quant_app.signals import TRADING_DAYS, build_signal_bundle


def _canonical_hash(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        default=str,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


PLAN_DEPLOYMENT_BINDING_KEY = "deployment_binding"
PLAN_AUTHENTICATION_TAG_KEY = "plan_authentication_hmac_sha256"
SEALED_COVARIANCE_RETURN_SEMANTICS = (
    "signed_09:30-09:35_America/New_York_split_cash_adjusted_vwap_total_return"
)
_PLAN_BINDING_FIELDS = {
    "schema_version",
    "strategy_config_sha256",
    "bot_config_sha256",
    "approved_symbols",
    "approval_hash",
    "approval_id",
    "authorized_account_id",
}


def _plan_authentication_key(authentication_key: bytes | None) -> bytes:
    key = (
        bytes.fromhex(SIMULATED_PLAN_AUTHENTICATION_KEY)
        if authentication_key is None
        else bytes(authentication_key)
    )
    if len(key) != 32:
        raise ValueError("Target-plan authentication key must contain exactly 32 bytes.")
    return key


def target_plan_content(plan: TargetPlan) -> dict[str, Any]:
    """Return all immutable plan content committed by ``plan_id``."""

    if plan.created_at.tzinfo is None or plan.created_at.utcoffset() is None:
        raise ValueError("Target plan created_at must be timezone-aware.")
    weights: dict[str, float] = {}
    for symbol, raw_weight in sorted(plan.target_weights.items()):
        weight = float(raw_weight)
        if not math.isfinite(weight):
            raise ValueError(f"Target plan contains a non-finite weight for {symbol}.")
        weights[str(symbol)] = weight
    return {
        "schema_version": 1,
        "as_of": plan.as_of.isoformat(),
        "created_at": plan.created_at.astimezone(timezone.utc).isoformat(),
        "regime": plan.regime,
        "regime_multiplier": float(plan.regime_multiplier),
        "desired_gross": float(plan.desired_gross),
        "forecast_volatility": float(plan.forecast_volatility),
        "target_weights": weights,
        # The full immutable metadata object is committed, including assets, beta
        # estimates, data/config hashes, account equity, and deployment binding. The
        # authentication tag is necessarily excluded from its own MAC input.
        "metadata": {
            key: value
            for key, value in plan.metadata.items()
            if key != PLAN_AUTHENTICATION_TAG_KEY
        },
    }


def target_plan_content_hash(plan: TargetPlan) -> str:
    return _canonical_hash(target_plan_content(plan))


def seal_target_plan(
    plan: TargetPlan,
    deployment_binding: Mapping[str, Any] | None = None,
    authentication_key: bytes | None = None,
) -> TargetPlan:
    metadata = dict(plan.metadata)
    metadata.pop(PLAN_AUTHENTICATION_TAG_KEY, None)
    if deployment_binding is not None:
        candidate = dict(deployment_binding)
        if set(candidate) != _PLAN_BINDING_FIELDS or candidate.get("schema_version") != 1:
            raise ValueError("Target plan deployment binding has unexpected or missing fields.")
        metadata[PLAN_DEPLOYMENT_BINDING_KEY] = candidate
    draft = replace(plan, plan_id="", metadata=metadata)
    plan_id = target_plan_content_hash(draft)
    unsigned = replace(draft, plan_id=plan_id)
    key = _plan_authentication_key(authentication_key)
    authentication_tag = hmac.new(
        key,
        _canonical_bytes(target_plan_content(unsigned)),
        hashlib.sha256,
    ).hexdigest()
    return replace(
        unsigned,
        metadata={**metadata, PLAN_AUTHENTICATION_TAG_KEY: authentication_tag},
    )


def validate_target_plan_integrity(
    plan: TargetPlan,
    expected_deployment_binding: Mapping[str, Any],
    authentication_key: bytes | None = None,
) -> None:
    binding = plan.metadata.get(PLAN_DEPLOYMENT_BINDING_KEY)
    if not isinstance(binding, dict) or set(binding) != _PLAN_BINDING_FIELDS:
        raise RuntimeError("Persisted target plan lacks a complete deployment binding.")
    try:
        expected_plan_id = target_plan_content_hash(plan)
    except (TypeError, ValueError, OverflowError) as exc:
        raise RuntimeError(f"Persisted target plan content is invalid: {exc}") from exc
    if plan.plan_id != expected_plan_id:
        raise RuntimeError("Persisted target plan content or plan_id failed integrity validation.")
    authentication_tag = plan.metadata.get(PLAN_AUTHENTICATION_TAG_KEY)
    if (
        not isinstance(authentication_tag, str)
        or len(authentication_tag) != 64
        or any(character not in "0123456789abcdef" for character in authentication_tag)
    ):
        raise RuntimeError("Persisted target plan is missing a valid authentication tag.")
    key = _plan_authentication_key(authentication_key)
    expected_tag = hmac.new(
        key,
        _canonical_bytes(target_plan_content(plan)),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(authentication_tag, expected_tag):
        raise RuntimeError("Persisted target plan authentication failed.")
    if binding != dict(expected_deployment_binding):
        raise RuntimeError(
            "Persisted target plan does not match the current approved deployment."
        )


def _price_hash(prices: pd.DataFrame) -> str:
    # Signals consume the complete cleaned frame (not only the 252-session covariance
    # window), so every exact row, timestamp, column, dtype, and value is committed.
    inventory = {
        "columns": [str(column) for column in prices.columns],
        "dtypes": [str(dtype) for dtype in prices.dtypes],
        "shape": list(prices.shape),
        "frame_csv_sha256": hashlib.sha256(
            prices.to_csv(
                index=True,
                date_format="%Y-%m-%dT%H:%M:%S.%f",
                float_format="%.17g",
                lineterminator="\n",
            ).encode("utf-8")
        ).hexdigest(),
    }
    payload = json.dumps(
        inventory, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _ewma_covariance(returns: pd.DataFrame, halflife: int) -> np.ndarray:
    if returns.empty:
        raise ValueError(
            "Live covariance returns must be complete and finite; zero-imputing "
            "missing market observations is forbidden."
        )
    return trailing_ewma_covariance(returns, halflife)


def clean_live_prices(prices: pd.DataFrame, minimum_assets: int) -> pd.DataFrame:
    frame = prices.copy().sort_index().astype(float)
    validate_daily_session_index(frame.index, label="Live daily prices")
    frame = frame.replace([np.inf, -np.inf], np.nan).where(lambda x: x > 0)
    minimum_observations = max(180, int(len(frame) * 0.80))
    # Every live target depends on 126-session momentum/beta estimates plus rolling
    # volatility and covariance. A forward-filled close would manufacture a zero
    # return, understate risk, and can leave an asset eligible even when its latest
    # completed bar is stale. Keep raw gaps and require a complete trailing window;
    # symbols with IPO/delisting/suspension gaps are excluded rather than imputed.
    trailing_window = min(252, len(frame))
    usable = [
        column
        for column in frame.columns
        if frame[column].notna().sum() >= minimum_observations
        and trailing_window >= 252
        and bool(frame[column].tail(trailing_window).notna().all())
    ]
    frame = frame[usable]
    if frame.shape[1] < minimum_assets:
        raise ValueError(
            f"Only {frame.shape[1]} assets have sufficient point-in-time history and "
            "a complete trailing 252-session risk window; "
            f"at least {minimum_assets} are required."
        )
    if len(frame) < 180:
        raise ValueError("At least 180 completed daily bars are required for live planning.")
    return frame


def build_target_plan(
    prices: pd.DataFrame,
    config: AppConfig,
    risk: RiskDecision,
    minimum_assets: int = 8,
    account_equity: float | None = None,
    *,
    covariance_execution_prices: pd.DataFrame | None = None,
    covariance_corporate_action_split_ratios: pd.DataFrame | None = None,
    covariance_corporate_action_cash_distributions: pd.DataFrame | None = None,
    covariance_evidence_metadata: Mapping[str, str] | None = None,
    intended_execution_date: date | None = None,
    covariance_return_semantics: str = "daily_close_proxy",
    require_research_covariance_parity: bool = False,
) -> TargetPlan:
    config.validate()
    if require_research_covariance_parity and minimum_assets < GOVERNED_MINIMUM_ASSETS:
        raise ValueError(
            "Governed live planning requires minimum_assets>=20 to match the sealed "
            "effective OOS breadth gate."
        )
    prices = clean_live_prices(prices, minimum_assets=minimum_assets)
    signal_as_of = pd.Timestamp(prices.index[-1]).date()
    if require_research_covariance_parity and config.portfolio.rebalance_every != 1:
        raise ValueError(
            "Governed live planning supports daily rebalancing only; REBALANCE_EVERY "
            "must be 1 until a persistent shared cadence anchor is implemented."
        )
    if covariance_execution_prices is None:
        if any(
            value is not None
            for value in (
                covariance_corporate_action_split_ratios,
                covariance_corporate_action_cash_distributions,
                covariance_evidence_metadata,
            )
        ):
            raise ValueError(
                "Covariance corporate-action/provenance evidence requires its exact "
                "execution-price panel."
            )
        if require_research_covariance_parity:
            raise ValueError(
                "Governed live planning requires signed 09:30-09:35 execution-window "
                "prices plus complete split/cash panels used by sealed research "
                "covariance. Daily closes are not a research/live parity substitute."
            )
        if covariance_return_semantics != "daily_close_proxy":
            raise ValueError(
                "Daily-close covariance fallback must be explicitly labeled daily_close_proxy."
            )
        covariance_prices = prices
        covariance_parity_certified = False
        covariance_split_ratios = None
        covariance_cash_distributions = None
        covariance_provenance: dict[str, str] = {}
        signed_covariance_symbols: list[str] = []
    else:
        if covariance_return_semantics != SEALED_COVARIANCE_RETURN_SEMANTICS:
            raise ValueError(
                "Execution covariance evidence must use the sealed signed 09:30-09:35 "
                "split/cash-adjusted VWAP total-return semantics."
            )
        try:
            supplied = covariance_execution_prices.sort_index().astype(float)
        except (TypeError, ValueError) as exc:
            raise ValueError("Execution covariance prices must be numeric.") from exc
        if not supplied.index.equals(prices.index):
            raise ValueError(
                "Execution covariance prices must exactly match the cleaned signal-session index."
            )
        missing_assets = prices.columns.difference(supplied.columns)
        if len(missing_assets):
            raise ValueError(
                "Execution covariance prices are missing cleaned signal assets: "
                + ", ".join(map(str, missing_assets))
            )
        covariance_prices = supplied.reindex(columns=prices.columns)
        signed_covariance_symbols = [str(symbol) for symbol in supplied.columns]
        # Sealed eligibility requires 252 complete lagged execution returns. That is
        # 253 consecutive VWAP observations; EWMA itself then consumes the most recent
        # 252 prices / 251 returns. Keeping the gates distinct avoids live re-entry one
        # session earlier than the research path after a missing endpoint.
        trailing_values = covariance_prices.tail(253).to_numpy(dtype=float)
        if (
            len(covariance_prices) < 253
            or not np.isfinite(trailing_values).all()
            or np.any(trailing_values <= 0.0)
        ):
            raise ValueError(
                "Execution covariance eligibility requires 253 complete, finite, "
                "positive trailing signed-window observations (252 lagged returns)."
            )
        if (
            covariance_corporate_action_split_ratios is None
            or covariance_corporate_action_cash_distributions is None
        ):
            raise ValueError(
                "Execution covariance parity requires complete split-ratio and "
                "cash-distribution panels."
            )
        corporate_panels = (
            (
                "Covariance split ratios",
                covariance_corporate_action_split_ratios,
                True,
            ),
            (
                "Covariance cash distributions",
                covariance_corporate_action_cash_distributions,
                False,
            ),
        )
        for label, panel, strictly_positive in corporate_panels:
            if not isinstance(panel, pd.DataFrame):
                raise ValueError(f"{label} must be a pandas DataFrame.")
            if not panel.index.equals(covariance_prices.index) or not panel.columns.equals(
                covariance_prices.columns
            ):
                raise ValueError(
                    f"{label} must exactly match execution covariance dates and assets."
                )
            values = panel.to_numpy(dtype=float)
            invalid = ~np.isfinite(values)
            invalid |= values <= 0.0 if strictly_positive else values < 0.0
            if bool(invalid.any()):
                requirement = "positive" if strictly_positive else "non-negative"
                raise ValueError(f"{label} must be complete, finite, and {requirement}.")
        if not isinstance(covariance_evidence_metadata, Mapping) or not covariance_evidence_metadata:
            raise ValueError(
                "Execution covariance parity requires authenticated evidence provenance."
            )
        covariance_provenance = {}
        for key, value in covariance_evidence_metadata.items():
            if not isinstance(key, str) or not key.strip():
                raise ValueError("Covariance evidence provenance keys must be non-empty strings.")
            if not isinstance(value, str) or not value.strip():
                raise ValueError(
                    "Covariance evidence provenance values must be non-empty strings."
                )
            covariance_provenance[key.strip()] = value.strip()
        if not isinstance(intended_execution_date, date) or isinstance(
            intended_execution_date, datetime
        ):
            raise ValueError(
                "Governed live planning requires an exact signed intended execution date."
            )
        required_provenance = {
            "issued_at",
            "expires_at",
            "latest_session",
            "next_session",
            "return_semantics",
        }
        missing_provenance = sorted(required_provenance.difference(covariance_provenance))
        if missing_provenance:
            raise ValueError(
                "Execution covariance provenance is missing signed session/freshness fields: "
                + ", ".join(missing_provenance)
                + "."
            )
        if covariance_provenance["latest_session"] != signal_as_of.isoformat():
            raise ValueError(
                "Execution covariance latest_session must equal the signal plan as_of session."
            )
        if covariance_provenance["next_session"] != intended_execution_date.isoformat():
            raise ValueError(
                "Execution covariance next_session must equal the intended execution date."
            )
        if covariance_provenance["return_semantics"] != SIGNED_EVIDENCE_RETURN_SEMANTICS:
            raise ValueError(
                "Execution covariance provenance has the wrong signed return semantics."
            )
        try:
            issued_at = datetime.fromisoformat(
                covariance_provenance["issued_at"].replace("Z", "+00:00")
            )
            expires_at = datetime.fromisoformat(
                covariance_provenance["expires_at"].replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise ValueError(
                "Execution covariance issued_at/expires_at must be valid ISO-8601 timestamps."
            ) from exc
        if (
            issued_at.tzinfo is None
            or issued_at.utcoffset() is None
            or expires_at.tzinfo is None
            or expires_at.utcoffset() is None
        ):
            raise ValueError(
                "Execution covariance issued_at/expires_at must include explicit offsets."
            )
        benchmark_endpoint = datetime.combine(
            intended_execution_date,
            GOVERNED_EXECUTION_END,
            tzinfo=ZoneInfo(GOVERNED_TIMEZONE),
        )
        if expires_at.astimezone(timezone.utc) <= benchmark_endpoint.astimezone(timezone.utc):
            raise ValueError(
                "Execution covariance evidence must remain valid beyond the intended "
                "session's 09:35 benchmark endpoint."
            )
        covariance_split_ratios = covariance_corporate_action_split_ratios.astype(float)
        covariance_cash_distributions = (
            covariance_corporate_action_cash_distributions.astype(float)
        )
        covariance_parity_certified = True

    # Match sealed research exactly: one pre-action share held from t-1 to t is worth
    # split_ratio[t] * raw_VWAP[t] + cash_per_pre_action_share[t]. The first row has no
    # predecessor inside the self-contained 252-price evidence window and is removed.
    if covariance_split_ratios is None or covariance_cash_distributions is None:
        returns = covariance_prices.tail(252).pct_change(fill_method=None).iloc[1:]
    else:
        trailing_prices = covariance_prices.tail(252)
        trailing_splits = covariance_split_ratios.reindex_like(trailing_prices)
        trailing_cash = covariance_cash_distributions.reindex_like(trailing_prices)
        returns = (
            trailing_prices.mul(trailing_splits)
            .add(trailing_cash)
            .div(trailing_prices.shift(1))
            .sub(1.0)
            .iloc[1:]
        )
    if returns.shape[0] != TRAILING_COVARIANCE_RETURN_COUNT or not np.isfinite(
        returns.to_numpy(dtype=float)
    ).all():
        raise ValueError(
            "Execution covariance economic returns must contain 251 complete finite "
            "split/cash-adjusted observations."
        )
    signals = build_signal_bundle(prices, config.signals, config.regime)

    as_of = signal_as_of
    alpha = signals.composite.iloc[-1].reindex(prices.columns)
    asset_vol = signals.asset_volatility.iloc[-1].reindex(prices.columns)
    beta = signals.beta.iloc[-1].reindex(prices.columns)
    regime = str(signals.regime.iloc[-1])
    regime_multiplier = float(signals.regime_multiplier.iloc[-1])

    unit_weights = _construct_weights(
        alpha=alpha,
        asset_vol=asset_vol,
        beta=beta,
        desired_gross=1.0,
        config=config,
    )
    covariance = _ewma_covariance(returns, config.portfolio.covariance_halflife)
    unit = unit_weights.reindex(prices.columns).fillna(0.0).to_numpy(dtype=float)
    forecast_volatility = float(
        np.sqrt(max(unit @ (covariance * TRADING_DAYS) @ unit, 0.0))
    )
    volatility_leverage = (
        config.portfolio.target_volatility / forecast_volatility
        if forecast_volatility > 1e-8
        else 0.0
    )
    base_gross = min(volatility_leverage, config.portfolio.max_gross_leverage)
    drawdown_multiplier = _drawdown_multiplier(risk.drawdown, config)
    loss_multiplier = 1.0
    if (
        risk.daily_return <= -config.risk.daily_loss_trigger
        or risk.five_day_return <= -config.risk.five_day_loss_trigger
    ):
        loss_multiplier = config.risk.loss_shock_multiplier

    desired_gross = base_gross * regime_multiplier * drawdown_multiplier * loss_multiplier
    if not risk.allow_new_risk:
        desired_gross = 0.0
    desired_gross = float(np.clip(desired_gross, 0.0, config.portfolio.max_gross_leverage))

    target = _construct_weights(
        alpha=alpha,
        asset_vol=asset_vol,
        beta=beta,
        desired_gross=desired_gross,
        config=config,
    ).reindex(prices.columns).fillna(0.0)

    gross = float(target.abs().sum())
    net = float(target.sum())
    beta_exposure = float(target.dot(beta.fillna(0.0)))
    weights = {str(symbol): float(weight) for symbol, weight in target.items() if abs(weight) > 1e-10}
    config_hash = _canonical_hash(config.to_dict())
    data_hash = _price_hash(prices)
    metadata = {
        "rows": int(len(prices)),
        "account_equity": float(account_equity) if account_equity is not None else None,
        "assets": list(prices.columns),
        "asset_beta": {
            str(symbol): float(value)
            for symbol, value in beta.items()
            if pd.notna(value) and np.isfinite(float(value))
        },
        "gross_weight": gross,
        "net_weight": net,
        "beta_exposure": beta_exposure,
        "ic_tstat": float(signals.ic_tstat.iloc[-1]) if pd.notna(signals.ic_tstat.iloc[-1]) else None,
        "information_coefficient": (
            float(signals.information_coefficient.iloc[-1])
            if pd.notna(signals.information_coefficient.iloc[-1])
            else None
        ),
        "signal_dispersion": (
            float(signals.signal_dispersion.iloc[-1])
            if pd.notna(signals.signal_dispersion.iloc[-1])
            else None
        ),
        "market_volatility": (
            float(signals.market_volatility.iloc[-1])
            if pd.notna(signals.market_volatility.iloc[-1])
            else None
        ),
        "volatility_leverage": volatility_leverage,
        "drawdown_multiplier": drawdown_multiplier,
        "loss_multiplier": loss_multiplier,
        "risk_reason": risk.reason,
        "drawdown": risk.drawdown,
        "daily_return": risk.daily_return,
        "five_day_return": risk.five_day_return,
        "config_hash": config_hash,
        "data_hash": data_hash,
        "covariance_price_hash": _price_hash(covariance_prices),
        "covariance_split_ratio_hash": (
            _price_hash(covariance_split_ratios)
            if covariance_split_ratios is not None
            else None
        ),
        "covariance_cash_distribution_hash": (
            _price_hash(covariance_cash_distributions)
            if covariance_cash_distributions is not None
            else None
        ),
        "covariance_economic_return_hash": _price_hash(returns),
        "covariance_evidence_provenance_hash": (
            _canonical_hash(covariance_provenance)
            if covariance_provenance
            else None
        ),
        "covariance_evidence_provenance": (
            dict(sorted(covariance_provenance.items()))
            if covariance_provenance
            else None
        ),
        "covariance_evidence_symbols": (
            signed_covariance_symbols if signed_covariance_symbols else None
        ),
        "intended_execution_date": (
            intended_execution_date.isoformat()
            if intended_execution_date is not None
            else None
        ),
        "covariance_corporate_action_accounting_certified": bool(
            covariance_split_ratios is not None
            and covariance_cash_distributions is not None
        ),
        "covariance_return_semantics": covariance_return_semantics,
        "covariance_return_count": TRAILING_COVARIANCE_RETURN_COUNT,
        "research_covariance_parity_certified": covariance_parity_certified,
        "timing": (
            "completed-close signal; exact signed next-session execution; routine "
            "children restricted to 09:30<=time<09:35 America/New_York"
            if require_research_covariance_parity
            else "completed-close signal; intended for next-session execution"
        ),
    }

    return seal_target_plan(TargetPlan(
        plan_id="",
        as_of=as_of,
        created_at=datetime.now(timezone.utc),
        regime=regime,
        regime_multiplier=regime_multiplier,
        desired_gross=desired_gross,
        forecast_volatility=forecast_volatility,
        target_weights=weights,
        metadata=metadata,
        status="approved",
    ))
