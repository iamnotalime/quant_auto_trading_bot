from __future__ import annotations

import hashlib
import json
import math
from io import BytesIO
from pathlib import PurePosixPath
from typing import Any, Mapping
from zipfile import ZIP_DEFLATED, ZipFile

import numpy as np
import pandas as pd

from .backtest import BacktestResult


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating, float)):
        return float(value) if math.isfinite(float(value)) else None
    if isinstance(value, (np.bool_, bool)):
        return bool(value)
    if isinstance(value, (pd.Timestamp,)):
        return value.isoformat()
    return value


def build_result_bundle(
    result: BacktestResult,
    full_metrics: dict[str, Any],
    oos_metrics: dict[str, Any],
    validation_payload: dict[str, Any],
    certification: pd.DataFrame,
    *,
    execution_prices: pd.DataFrame | None = None,
    daily_dollar_volume: pd.DataFrame | None = None,
    execution_window_dollar_volume: pd.DataFrame | None = None,
    corporate_action_split_ratios: pd.DataFrame | None = None,
    corporate_action_cash_distributions: pd.DataFrame | None = None,
    corporate_action_as_of_timestamps: pd.DataFrame | None = None,
    borrow_availability: pd.DataFrame | None = None,
    annual_borrow_rates: pd.DataFrame | None = None,
    borrow_recalls: pd.DataFrame | None = None,
    borrow_as_of_timestamps: pd.DataFrame | None = None,
    factor_returns: pd.DataFrame | None = None,
    exchange_session_calendar: pd.DataFrame | None = None,
    stressed_result: BacktestResult | None = None,
    rolling_validation: pd.DataFrame | None = None,
    parameter_perturbations: pd.DataFrame | None = None,
    governance_ledger_snapshot: bytes | None = None,
    trusted_registry_bytes: bytes | None = None,
    research_source_snapshot: Mapping[str, bytes] | None = None,
    signed_manifest_bytes: bytes | None = None,
    anchor_receipt_bytes: bytes | None = None,
) -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        inventory: dict[str, str] = {}

        def write(name: str, value: str | bytes) -> None:
            raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
            archive.writestr(name, raw)
            inventory[name] = hashlib.sha256(raw).hexdigest()

        write("equity.csv", result.equity.to_csv())
        write("strategy_returns.csv", result.strategy_returns.to_csv())
        write("weights.csv", result.weights.to_csv())
        write("diagnostics.csv", result.diagnostics.to_csv())
        observed_prices = (
            result.observed_prices
            if result.observed_prices is not None
            else result.prices
        )
        write("prices_used.csv", observed_prices.to_csv())
        if result.observed_prices is not None and not result.observed_prices.equals(
            result.prices
        ):
            write("signal_prices_after_bounded_fill.csv", result.prices.to_csv())
        if execution_prices is not None:
            write(
                "execution_prices_used.csv",
                execution_prices.to_csv(),
            )
        if daily_dollar_volume is not None:
            write(
                "daily_dollar_volume_used.csv",
                daily_dollar_volume.to_csv(),
            )
        if execution_window_dollar_volume is not None:
            write(
                "execution_window_dollar_volume_used.csv",
                execution_window_dollar_volume.to_csv(),
            )
        evidence_frames = {
            "corporate_actions/split_ratios_used.csv": corporate_action_split_ratios,
            "corporate_actions/cash_distributions_used.csv": (
                corporate_action_cash_distributions
            ),
            "corporate_actions/as_of_timestamps_used.csv": (
                corporate_action_as_of_timestamps
            ),
            "borrow/availability_used.csv": borrow_availability,
            "borrow/annual_rates_used.csv": annual_borrow_rates,
            "borrow/recalls_used.csv": borrow_recalls,
            "borrow/as_of_timestamps_used.csv": borrow_as_of_timestamps,
        }
        for name, frame in evidence_frames.items():
            if frame is not None:
                write(name, frame.to_csv())
        if factor_returns is not None:
            write(
                "factor_returns_used.csv",
                factor_returns.to_csv(),
            )
        if exchange_session_calendar is not None:
            write(
                "exchange_session_calendar_used.csv",
                exchange_session_calendar.to_csv(),
            )
        if stressed_result is not None:
            write("stress/double_cost_equity.csv", stressed_result.equity.to_csv())
            write(
                "stress/double_cost_strategy_returns.csv",
                stressed_result.strategy_returns.to_csv(),
            )
            write("stress/double_cost_weights.csv", stressed_result.weights.to_csv())
            write(
                "stress/double_cost_diagnostics.csv",
                stressed_result.diagnostics.to_csv(),
            )
        if rolling_validation is not None:
            write("validation/rolling_windows.csv", rolling_validation.to_csv())
        if parameter_perturbations is not None:
            write(
                "validation/parameter_perturbations.csv",
                parameter_perturbations.to_csv(),
            )
        if governance_ledger_snapshot is not None:
            write("governance/research_ledger_snapshot.json", governance_ledger_snapshot)
        if trusted_registry_bytes is not None:
            write("governance/trusted_public_keys.json", trusted_registry_bytes)
        if research_source_snapshot is not None:
            for relative_name, source_bytes in sorted(research_source_snapshot.items()):
                path = PurePosixPath(str(relative_name).replace("\\", "/"))
                if path.is_absolute() or ".." in path.parts or not path.parts:
                    raise ValueError("Research source snapshot contains an unsafe path.")
                write(f"research_source/{path.as_posix()}", source_bytes)
        if signed_manifest_bytes is not None:
            write("signed_manifest.json", signed_manifest_bytes)
        if anchor_receipt_bytes is not None:
            write("preregistration_anchor_receipt.bin", anchor_receipt_bytes)
        write("certification_tests.csv", certification.to_csv())
        write(
            "config.json",
            json.dumps(_json_safe(result.config.to_dict()), indent=2),
        )
        write(
            "metrics.json",
            json.dumps(
                _json_safe(
                    {
                        "full_sample": full_metrics,
                        "out_of_sample": oos_metrics,
                        "validation": validation_payload,
                    }
                ),
                indent=2,
            ),
        )
        write(
            "IMPORTANT.txt",
            (
                "RESEARCH OUTPUT ONLY\n\n"
                "This bundle contains hypothetical backtest results. It does not certify future "
                "profitability, a 60% annual return, or a 15% live drawdown ceiling. Results depend "
                "on data quality, survivorship bias, execution, borrow availability, market impact, "
                "financing, and regime stability. Use point-in-time data and independent review "
                "before considering live deployment.\n"
                "SHA256SUMS.json authenticates member integrity only; the bundle still "
                "requires external post-run signing and immutable retention.\n"
            ),
        )
        archive.writestr(
            "SHA256SUMS.json",
            json.dumps(inventory, indent=2, sort_keys=True).encode("utf-8"),
        )
    return buffer.getvalue()
