from __future__ import annotations

import hashlib
import json
from io import BytesIO
from zipfile import ZipFile

import pandas as pd

from quant_app.backtest import BacktestResult
from quant_app.config import AppConfig
from quant_app.reporting import build_result_bundle
from quant_app.signals import SignalBundle


def _minimal_result() -> BacktestResult:
    index = pd.bdate_range("2026-01-02", periods=3)
    columns = ["A", "B"]
    frame = pd.DataFrame(0.0, index=index, columns=columns)
    signals = SignalBundle(
        composite=frame,
        components={},
        beta=frame,
        asset_volatility=frame,
        information_coefficient=pd.Series(0.0, index=index),
        ic_tstat=pd.Series(0.0, index=index),
        market_volatility=pd.Series(0.0, index=index),
        signal_dispersion=pd.Series(0.0, index=index),
        regime=pd.Series("neutral", index=index),
        regime_multiplier=pd.Series(1.0, index=index),
    )
    returns = pd.Series([0.0, 0.01, -0.005], index=index, name="strategy_return")
    return BacktestResult(
        equity=(1.0 + returns).cumprod(),
        strategy_returns=returns,
        weights=frame,
        diagnostics=pd.DataFrame({"test": [1, 2, 3]}, index=index),
        signals=signals,
        prices=pd.DataFrame({"A": [10.0, 10.1, 10.2], "B": [20.0, 19.9, 20.1]}, index=index),
        config=AppConfig(),
    )


def test_result_bundle_retains_capacity_and_governance_evidence() -> None:
    result = _minimal_result()
    execution = result.prices + 0.01
    dollar_volume = pd.DataFrame(
        1_000_000.0,
        index=result.prices.index,
        columns=result.prices.columns,
    )
    factors = pd.DataFrame(
        {"MKT": [0.0, 0.01, -0.01], "VALUE": [0.0, -0.002, 0.003]},
        index=result.prices.index,
    )
    calendar = pd.DataFrame(
        {"is_session": [1, 1, 1]},
        index=result.prices.index,
    )
    manifest = b'{"payload":{"schema_version":6},"signature":"test-only"}'
    receipt = b"immutable-anchor-receipt"

    bundle = build_result_bundle(
        result=result,
        full_metrics={"CAGR": 0.1},
        oos_metrics={"CAGR": 0.1},
        validation_payload={"certified": False},
        certification=pd.DataFrame(
            {"Observed": [False], "Requirement": ["No"], "Pass": [True]},
            index=["Test"],
        ),
        execution_prices=execution,
        daily_dollar_volume=dollar_volume,
        execution_window_dollar_volume=dollar_volume / 20.0,
        corporate_action_split_ratios=pd.DataFrame(
            1.0, index=result.prices.index, columns=result.prices.columns
        ),
        corporate_action_cash_distributions=pd.DataFrame(
            0.0, index=result.prices.index, columns=result.prices.columns
        ),
        corporate_action_as_of_timestamps=pd.DataFrame(
            "2026-01-02T14:30:00+00:00",
            index=result.prices.index,
            columns=result.prices.columns,
        ),
        borrow_availability=pd.DataFrame(
            True, index=result.prices.index, columns=result.prices.columns
        ),
        annual_borrow_rates=pd.DataFrame(
            0.03, index=result.prices.index, columns=result.prices.columns
        ),
        borrow_recalls=pd.DataFrame(
            False, index=result.prices.index, columns=result.prices.columns
        ),
        borrow_as_of_timestamps=pd.DataFrame(
            "2026-01-02T14:30:00+00:00",
            index=result.prices.index,
            columns=result.prices.columns,
        ),
        factor_returns=factors,
        exchange_session_calendar=calendar,
        stressed_result=result,
        rolling_validation=pd.DataFrame({"Pass": [True]}, index=[result.prices.index[-1]]),
        parameter_perturbations=pd.DataFrame({"CAGR": [0.1]}, index=["base"]),
        governance_ledger_snapshot=b'{"research_attempts":[]}',
        trusted_registry_bytes=b'{"schema_version":1,"keys":{}}',
        research_source_snapshot={"app.py": b"print('snapshot')\n", "requirements.lock": b""},
        signed_manifest_bytes=manifest,
        anchor_receipt_bytes=receipt,
    )

    with ZipFile(BytesIO(bundle)) as archive:
        names = set(archive.namelist())
        assert "execution_prices_used.csv" in names
        assert "daily_dollar_volume_used.csv" in names
        assert "execution_window_dollar_volume_used.csv" in names
        assert "corporate_actions/split_ratios_used.csv" in names
        assert "corporate_actions/cash_distributions_used.csv" in names
        assert "corporate_actions/as_of_timestamps_used.csv" in names
        assert "borrow/availability_used.csv" in names
        assert "borrow/annual_rates_used.csv" in names
        assert "borrow/recalls_used.csv" in names
        assert "borrow/as_of_timestamps_used.csv" in names
        assert "factor_returns_used.csv" in names
        assert "exchange_session_calendar_used.csv" in names
        assert "stress/double_cost_diagnostics.csv" in names
        assert "validation/rolling_windows.csv" in names
        assert "validation/parameter_perturbations.csv" in names
        assert "governance/research_ledger_snapshot.json" in names
        assert "governance/trusted_public_keys.json" in names
        assert "research_source/app.py" in names
        assert "research_source/requirements.lock" in names
        assert "SHA256SUMS.json" in names
        assert archive.read("signed_manifest.json") == manifest
        assert archive.read("preregistration_anchor_receipt.bin") == receipt
        round_trip_volume = pd.read_csv(
            archive.open("daily_dollar_volume_used.csv"),
            index_col=0,
        )
        assert round_trip_volume.shape == dollar_volume.shape
        inventory = json.loads(archive.read("SHA256SUMS.json"))
        assert set(inventory) == names - {"SHA256SUMS.json"}
        for name, expected in inventory.items():
            assert hashlib.sha256(archive.read(name)).hexdigest() == expected
