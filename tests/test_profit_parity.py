from __future__ import annotations

from datetime import datetime, time, timedelta, timezone

import pandas as pd
import pytest

from auto_trader.covariance_evidence import COVARIANCE_RETURN_SEMANTICS
from auto_trader.models import RiskDecision
from auto_trader.strategy import (
    SEALED_COVARIANCE_RETURN_SEMANTICS,
    build_target_plan,
)
from quant_app.config import AppConfig
from quant_app.data import generate_demo_prices


def _normal_risk() -> RiskDecision:
    return RiskDecision(True, False, False, "normal", 0.0, 0.0, 0.0)


def _neutral_actions(frame: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    return (
        pd.DataFrame(1.0, index=frame.index, columns=frame.columns),
        pd.DataFrame(0.0, index=frame.index, columns=frame.columns),
    )


def _signed_context(frame: pd.DataFrame, snapshot_id: str):
    as_of = pd.Timestamp(frame.index[-1]).date()
    intended = (pd.Timestamp(frame.index[-1]) + pd.offsets.BDay(1)).date()
    return intended, {
        "snapshot_id": snapshot_id,
        "issued_at": datetime.combine(
            as_of, time(14, 0), tzinfo=timezone.utc
        ).isoformat(),
        "expires_at": datetime.combine(
            intended + timedelta(days=1), time(0, 0), tzinfo=timezone.utc
        ).isoformat(),
        "latest_session": as_of.isoformat(),
        "next_session": intended.isoformat(),
        "return_semantics": COVARIANCE_RETURN_SEMANTICS,
    }


def test_governed_execution_eligibility_cannot_resume_one_session_before_research() -> None:
    prices = generate_demo_prices(
        n_assets=20,
        years=4,
        seed=20260713,
        end_date="2026-06-30",
    )
    execution = prices.copy()
    first_end = 500
    # The oldest observation in the required 253-VWAP window. A 252-price-only live
    # gate would omit it and resume one session before the sealed 252-return gate.
    execution.iloc[first_end - 253, 0] = float("nan")

    first_prices = prices.iloc[:first_end]
    first_execution = execution.iloc[:first_end]
    first_splits, first_cash = _neutral_actions(first_execution)
    first_intended, first_provenance = _signed_context(
        first_prices, "gap-boundary-0001"
    )
    with pytest.raises(ValueError, match="253 complete"):
        build_target_plan(
            first_prices,
            AppConfig(),
            _normal_risk(),
            minimum_assets=20,
            covariance_execution_prices=first_execution,
            covariance_corporate_action_split_ratios=first_splits,
            covariance_corporate_action_cash_distributions=first_cash,
            covariance_evidence_metadata=first_provenance,
            intended_execution_date=first_intended,
            covariance_return_semantics=SEALED_COVARIANCE_RETURN_SEMANTICS,
            require_research_covariance_parity=True,
        )

    recovered_prices = prices.iloc[: first_end + 1]
    recovered_execution = execution.iloc[: first_end + 1]
    recovered_splits, recovered_cash = _neutral_actions(recovered_execution)
    recovered_intended, recovered_provenance = _signed_context(
        recovered_prices, "gap-boundary-0002"
    )
    recovered = build_target_plan(
        recovered_prices,
        AppConfig(),
        _normal_risk(),
        minimum_assets=20,
        covariance_execution_prices=recovered_execution,
        covariance_corporate_action_split_ratios=recovered_splits,
        covariance_corporate_action_cash_distributions=recovered_cash,
        covariance_evidence_metadata=recovered_provenance,
        intended_execution_date=recovered_intended,
        covariance_return_semantics=SEALED_COVARIANCE_RETURN_SEMANTICS,
        require_research_covariance_parity=True,
    )
    assert recovered.metadata["covariance_return_count"] == 251
    assert recovered.metadata["research_covariance_parity_certified"] is True
