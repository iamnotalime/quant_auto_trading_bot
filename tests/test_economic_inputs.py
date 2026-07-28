from __future__ import annotations

from io import BytesIO

import pandas as pd
import pytest

from quant_app.data import load_borrow_csv, load_corporate_action_csv


@pytest.fixture
def axes() -> tuple[pd.DatetimeIndex, pd.Index]:
    return pd.bdate_range("2024-01-02", periods=3), pd.Index(["A", "B"])


def _panel_rows(index: pd.DatetimeIndex, assets: pd.Index) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for date in index:
        for asset in assets:
            rows.append(
                {
                    "Date": date.date().isoformat(),
                    "Asset": asset,
                    # January New York is UTC-5; this is 09:30 local and precedes
                    # the certified 09:30 decision cutoff.
                    "AsOfTimestamp": f"{date.date().isoformat()}T14:30:00Z",
                }
            )
    return rows


def _csv(frame: pd.DataFrame) -> BytesIO:
    return BytesIO(frame.to_csv(index=False).encode("utf-8"))


def test_corporate_action_loader_requires_complete_explicit_panel(
    axes: tuple[pd.DatetimeIndex, pd.Index],
) -> None:
    index, assets = axes
    frame = pd.DataFrame(_panel_rows(index, assets))
    frame["SplitRatio"] = 1.0
    frame["CashDistributionPerPreActionShare"] = 0.0
    event = (frame["Date"] == index[1].date().isoformat()) & frame["Asset"].eq("A")
    frame.loc[event, "SplitRatio"] = 2.0
    frame.loc[event, "CashDistributionPerPreActionShare"] = 0.25

    loaded = load_corporate_action_csv(
        _csv(frame), expected_index=index, expected_columns=assets
    )
    assert loaded.split_ratio.loc[index[1], "A"] == pytest.approx(2.0)
    assert loaded.cash_distribution.loc[index[1], "A"] == pytest.approx(0.25)
    assert loaded.split_ratio.shape == (3, 2)
    assert loaded.as_of_timestamp.notna().all().all()

    missing = frame.iloc[:-1]
    with pytest.raises(ValueError, match="exactly one row"):
        load_corporate_action_csv(
            _csv(missing), expected_index=index, expected_columns=assets
        )

    duplicated = pd.concat([frame, frame.iloc[[0]]], ignore_index=True)
    with pytest.raises(ValueError, match="duplicate Date/Asset"):
        load_corporate_action_csv(
            _csv(duplicated), expected_index=index, expected_columns=assets
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("SplitRatio", 0.0, "strictly positive"),
        ("CashDistributionPerPreActionShare", -0.01, "non-negative"),
    ],
)
def test_corporate_action_loader_rejects_economically_invalid_values(
    axes: tuple[pd.DatetimeIndex, pd.Index],
    field: str,
    value: float,
    message: str,
) -> None:
    index, assets = axes
    frame = pd.DataFrame(_panel_rows(index, assets))
    frame["SplitRatio"] = 1.0
    frame["CashDistributionPerPreActionShare"] = 0.0
    frame.loc[0, field] = value
    with pytest.raises(ValueError, match=message):
        load_corporate_action_csv(
            _csv(frame), expected_index=index, expected_columns=assets
        )


def test_point_in_time_cutoff_and_explicit_timezone_are_fail_closed(
    axes: tuple[pd.DatetimeIndex, pd.Index],
) -> None:
    index, assets = axes
    frame = pd.DataFrame(_panel_rows(index, assets))
    frame["SplitRatio"] = 1.0
    frame["CashDistributionPerPreActionShare"] = 0.0
    frame.loc[0, "AsOfTimestamp"] = "2024-01-02T14:36:00Z"
    with pytest.raises(ValueError, match="after.*09:30"):
        load_corporate_action_csv(
            _csv(frame), expected_index=index, expected_columns=assets
        )

    # Pandas retains the sub-microsecond component separately. Comparing only
    # ``microsecond`` would admit information one nanosecond after the sealed cutoff.
    frame.loc[0, "AsOfTimestamp"] = "2024-01-02T14:30:00.000000001Z"
    with pytest.raises(ValueError, match="after.*09:30"):
        load_corporate_action_csv(
            _csv(frame), expected_index=index, expected_columns=assets
        )

    frame.loc[0, "AsOfTimestamp"] = "2024-01-02T09:30:00"
    with pytest.raises(ValueError, match="explicit UTC offset"):
        load_corporate_action_csv(
            _csv(frame), expected_index=index, expected_columns=assets
        )


def test_borrow_loader_requires_security_date_availability_rate_and_recall(
    axes: tuple[pd.DatetimeIndex, pd.Index],
) -> None:
    index, assets = axes
    frame = pd.DataFrame(_panel_rows(index, assets))
    frame["Available"] = "true"
    frame["AnnualRate"] = 0.03
    frame["Recall"] = "false"
    recalled = (frame["Date"] == index[2].date().isoformat()) & frame["Asset"].eq("B")
    frame.loc[recalled, "Available"] = "false"
    frame.loc[recalled, "Recall"] = "true"
    frame.loc[recalled, "AnnualRate"] = 0.80

    loaded = load_borrow_csv(
        _csv(frame), expected_index=index, expected_columns=assets
    )
    assert not bool(loaded.availability.loc[index[2], "B"])
    assert bool(loaded.recall.loc[index[2], "B"])
    assert loaded.annual_rate.loc[index[2], "B"] == pytest.approx(0.80)

    ambiguous = frame.copy()
    ambiguous.loc[0, "Available"] = 1
    with pytest.raises(ValueError, match="exactly true or false"):
        load_borrow_csv(_csv(ambiguous), expected_index=index, expected_columns=assets)

    impossible = frame.copy()
    impossible.loc[recalled, "Available"] = "true"
    with pytest.raises(ValueError, match="cannot simultaneously"):
        load_borrow_csv(_csv(impossible), expected_index=index, expected_columns=assets)

    invalid_rate = frame.copy()
    invalid_rate.loc[0, "AnnualRate"] = -0.01
    with pytest.raises(ValueError, match="between 0 and 10"):
        load_borrow_csv(_csv(invalid_rate), expected_index=index, expected_columns=assets)
