from __future__ import annotations

from io import BytesIO

import numpy as np
import pandas as pd
import pytest

from quant_app.backtest import run_backtest
from quant_app.config import AppConfig
from quant_app.data import (
    load_exchange_session_calendar_csv,
    load_execution_price_csv,
    load_price_csv,
    validate_exchange_session_alignment,
)
from quant_app.validation import sealed_daily_observation_rate_is_valid


def test_long_sample_retains_delisted_asset_with_usable_history() -> None:
    rows = 1_000
    dates = pd.date_range("2018-01-01", periods=rows, freq="B")
    frame = pd.DataFrame(
        {
            "Date": dates,
            "SURVIVOR_A": np.linspace(100.0, 150.0, rows),
            "SURVIVOR_B": np.linspace(80.0, 120.0, rows),
            # This asset has enough observations to be tradable during its life, but
            # only 20% coverage of the final sample. Fractional filters would erase it.
            "DELISTED": np.r_[np.linspace(40.0, 1.0, 200), np.full(rows - 200, np.nan)],
        }
    )
    prices, _ = load_price_csv(BytesIO(frame.to_csv(index=False).encode("utf-8")))
    assert "DELISTED" in prices.columns
    assert pd.isna(prices.loc[dates[210], "DELISTED"])


def test_execution_price_loader_never_fabricates_missing_fills() -> None:
    rows = 120
    dates = pd.date_range("2024-01-01", periods=rows, freq="B")
    missing = np.linspace(100.0, 120.0, rows)
    missing[55] = np.nan
    frame = pd.DataFrame(
        {
            "Date": dates,
            "A": missing,
            "B": np.linspace(50.0, 60.0, rows),
        }
    )
    prices, report = load_execution_price_csv(
        BytesIO(frame.to_csv(index=False).encode("utf-8"))
    )
    assert pd.isna(prices.loc[dates[55], "A"])
    assert report.missing_fraction_before_fill > 0.0


def test_intraday_or_sparse_rows_cannot_masquerade_as_daily_sessions() -> None:
    intraday = pd.DataFrame(
        {
            "Date": pd.date_range("2025-01-02 09:30", periods=240, freq="h"),
            "A": np.linspace(100.0, 110.0, 240),
            "B": np.linspace(50.0, 55.0, 240),
        }
    )
    with pytest.raises(ValueError, match="at most one row per session date"):
        load_price_csv(BytesIO(intraday.to_csv(index=False).encode("utf-8")))

    weekly_index = pd.date_range("2018-01-05", periods=180, freq="W-FRI")
    weekly = pd.DataFrame(
        np.linspace(50.0, 150.0, 180)[:, None] * np.ones((1, 4)),
        index=weekly_index,
        columns=list("ABCD"),
    )
    with pytest.raises(ValueError, match="supports only one-bar-per-session"):
        run_backtest(weekly, AppConfig())


def test_sealed_252_session_gate_rejects_exploratory_calendar_extremes() -> None:
    assert sealed_daily_observation_rate_is_valid(248.0)
    assert sealed_daily_observation_rate_is_valid(252.0)
    assert sealed_daily_observation_rate_is_valid(255.0)
    assert not sealed_daily_observation_rate_is_valid(247.0)
    assert not sealed_daily_observation_rate_is_valid(256.0)
    assert not sealed_daily_observation_rate_is_valid(float("nan"))


def test_authoritative_exchange_calendar_is_strict_and_prevents_sparse_year_offset() -> None:
    official = pd.bdate_range("2022-01-03", periods=756)
    calendar_csv = pd.DataFrame({"Date": official}).to_csv(index=False).encode("utf-8")
    calendar = load_exchange_session_calendar_csv(BytesIO(calendar_csv))
    prices = pd.DataFrame({"A": 1.0}, index=official)
    validate_exchange_session_alignment(calendar, prices=prices)

    # Removing a session cannot be hidden by denser years because equality is exact,
    # not an aggregate observations-per-year heuristic.
    sparse = prices.drop(index=official[300])
    with pytest.raises(ValueError, match="missing=1"):
        validate_exchange_session_alignment(calendar, prices=sparse)

    weekend = pd.DataFrame(
        {"Date": list(official[:252]) + [pd.Timestamp("2023-01-07")]}
    )
    with pytest.raises(ValueError, match="weekend"):
        load_exchange_session_calendar_csv(
            BytesIO(weekend.to_csv(index=False).encode("utf-8"))
        )


def test_close_gaps_are_never_filled_for_marks_or_signals() -> None:
    dates = pd.date_range("2020-01-01", periods=240, freq="B")
    base = np.linspace(100.0, 130.0, len(dates))
    raw = pd.DataFrame(
        {
            "Date": dates,
            "A": base.copy(),
            "B": base * 0.8,
            "C": base * 1.2,
            "D": base * 1.5,
        }
    )
    raw.loc[150:160, "A"] = np.nan
    loaded, _ = load_price_csv(BytesIO(raw.to_csv(index=False).encode("utf-8")))
    assert loaded.loc[dates[150:160], "A"].isna().all()

    result = run_backtest(loaded, AppConfig())
    assert pd.isna(result.prices.loc[dates[154], "A"])
    assert pd.isna(result.prices.loc[dates[155], "A"])
    assert result.observed_prices is not None
    pd.testing.assert_frame_equal(result.prices, result.observed_prices)
    assert pd.isna(result.signals.components["reversal_3"].loc[dates[155], "A"])


def test_price_loader_rejects_ambiguous_schema_and_invalid_dates() -> None:
    dates = pd.date_range("2020-01-01", periods=120, freq="B").astype(str).tolist()
    values = np.linspace(100.0, 120.0, len(dates))

    duplicate = pd.DataFrame(
        np.column_stack([dates, values, values * 2.0]),
        columns=["Date", "A", " A "],
    )
    with pytest.raises(ValueError, match="duplicate asset names"):
        load_price_csv(BytesIO(duplicate.to_csv(index=False).encode("utf-8")))

    invalid = pd.DataFrame({"Date": dates, "A": values, "B": values * 2.0})
    invalid.loc[50, "Date"] = "not-a-date"
    with pytest.raises(ValueError, match="invalid timestamp row"):
        load_price_csv(BytesIO(invalid.to_csv(index=False).encode("utf-8")))

    formula_name = pd.DataFrame({"Date": dates, "=CMD()": values, "B": values})
    with pytest.raises(ValueError, match="spreadsheet-formula-like"):
        load_price_csv(BytesIO(formula_name.to_csv(index=False).encode("utf-8")))


def test_price_loaders_reject_explicit_nonpositive_observations() -> None:
    dates = pd.bdate_range("2025-01-02", periods=120)
    raw = pd.DataFrame(
        {
            "Date": dates,
            "A": np.linspace(100.0, 110.0, len(dates)),
            "B": np.linspace(50.0, 55.0, len(dates)),
        }
    )
    raw.loc[40, "A"] = 0.0
    encoded = BytesIO(raw.to_csv(index=False).encode("utf-8"))
    with pytest.raises(ValueError, match="non-positive"):
        load_price_csv(encoded)

    encoded = BytesIO(raw.to_csv(index=False).encode("utf-8"))
    with pytest.raises(ValueError, match="non-positive"):
        load_execution_price_csv(encoded)

def test_price_loaders_reject_malformed_nonempty_cells() -> None:
    dates = pd.bdate_range("2025-01-02", periods=120)
    malformed = pd.DataFrame(
        {
            "Date": dates,
            "A": np.linspace(100.0, 110.0, len(dates)).astype(object),
            "B": np.linspace(50.0, 55.0, len(dates)),
        }
    )
    malformed.loc[50, "A"] = "not-a-price"
    payload = BytesIO(malformed.to_csv(index=False).encode("utf-8"))
    with pytest.raises(ValueError, match="nonnumeric non-missing"):
        load_price_csv(payload)

    execution_payload = BytesIO(malformed.to_csv(index=False).encode("utf-8"))
    with pytest.raises(ValueError, match="nonnumeric non-missing"):
        load_execution_price_csv(execution_payload)
