from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from typing import BinaryIO

import numpy as np
import pandas as pd


@dataclass(frozen=True)
class DataQualityReport:
    rows: int
    assets: int
    start: pd.Timestamp
    end: pd.Timestamp
    missing_fraction_before_fill: float
    duplicate_dates_removed: int
    nonpositive_values_removed: int
    longest_history_years: float
    annualized_observation_rate: float


@dataclass(frozen=True)
class CorporateActionData:
    """Point-in-time actions for one execution-price holding interval.

    On session ``t``, ``split_ratio`` is shares-after / shares-before for actions
    effective between the prior session's 09:35 VWAP and session ``t``'s 09:35
    VWAP. ``cash_distribution`` is cash paid per pre-action share over that same
    interval.  A full asset/session panel (including neutral 1/0 rows) is required
    so absence of an event is explicit rather than inferred from a sparse feed.
    """

    split_ratio: pd.DataFrame
    cash_distribution: pd.DataFrame
    as_of_timestamp: pd.DataFrame


@dataclass(frozen=True)
class BorrowData:
    """Point-in-time security/session borrow terms observed by 09:30 New York."""

    availability: pd.DataFrame
    annual_rate: pd.DataFrame
    recall: pd.DataFrame
    as_of_timestamp: pd.DataFrame


def validate_daily_session_index(
    index: pd.Index,
    *,
    label: str = "Price data",
) -> float:
    """Validate the 252-session daily-bar calendar assumed by this application.

    The signal lookbacks, volatility scaling, financing accrual, and performance
    annualization all use 252 sessions per year. Accepting hourly, weekly, or 24/7
    rows would silently change the economic meaning of every reported statistic.
    Return the observed rows-per-calendar-year rate for audit reporting.
    """
    if not isinstance(index, pd.DatetimeIndex):
        try:
            index = pd.DatetimeIndex(index)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{label} must use a valid DatetimeIndex.") from exc
    if index.hasnans:
        raise ValueError(f"{label} contains missing timestamps.")
    if not index.is_monotonic_increasing:
        raise ValueError(f"{label} timestamps must be sorted in increasing order.")
    session_dates = index.tz_localize(None).normalize()
    if session_dates.duplicated().any():
        raise ValueError(
            f"{label} must contain at most one row per session date; intraday rows "
            "cannot be annualized by this 252-session daily model."
        )
    if len(session_dates) < 2:
        return float("nan")
    elapsed_years = (session_dates[-1] - session_dates[0]).days / 365.25
    if elapsed_years <= 0.0:
        raise ValueError(f"{label} does not span more than one calendar date.")
    observation_rate = float((len(session_dates) - 1) / elapsed_years)
    if len(session_dates) >= 60 and not 180.0 <= observation_rate <= 270.0:
        raise ValueError(
            f"{label} has {observation_rate:.1f} observations per calendar year; "
            "this engine supports only one-bar-per-session 252-session data "
            "(accepted range 180-270)."
        )
    return observation_rate


def load_exchange_session_calendar_csv(source: BinaryIO | bytes) -> pd.DatetimeIndex:
    """Load the authoritative session dates required by sealed validation.

    The application deliberately does not synthesize exchange holidays: exceptional
    closures and calendar corrections must come from an independently retained source.
    A sealed run compares every market-data index with this exact normalized calendar.
    """

    raw = _read_csv(source)
    if raw.empty or raw.shape[1] != 1:
        raise ValueError(
            "Exchange-session calendar CSV must contain exactly one Date column."
        )
    column = raw.columns[0]
    if str(column).strip().lower() not in {"date", "session_date"}:
        raise ValueError("Exchange-session calendar column must be named Date.")
    parsed = pd.to_datetime(raw[column], errors="coerce", utc=False)
    if parsed.isna().any():
        raise ValueError("Exchange-session calendar contains invalid or missing dates.")
    try:
        index = pd.DatetimeIndex(parsed).tz_localize(None).normalize()
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Exchange-session calendar contains incompatible timestamps."
        ) from exc
    if index.duplicated().any():
        raise ValueError("Exchange-session calendar contains duplicate dates.")
    if not index.is_monotonic_increasing:
        raise ValueError("Exchange-session calendar dates must be strictly increasing.")
    if bool((index.dayofweek >= 5).any()):
        raise ValueError("Exchange-session calendar contains a weekend date.")
    if len(index) < 252:
        raise ValueError("Exchange-session calendar must contain at least 252 sessions.")
    validate_daily_session_index(index, label="Exchange-session calendar")
    return pd.DatetimeIndex(index, name="Date")


def validate_exchange_session_alignment(
    calendar: pd.DatetimeIndex,
    **datasets: pd.DataFrame,
) -> None:
    """Require every supplied sealed dataset to use the authoritative sessions exactly."""

    expected = pd.DatetimeIndex(calendar).tz_localize(None).normalize()
    for label, frame in datasets.items():
        actual = pd.DatetimeIndex(frame.index).tz_localize(None).normalize()
        if not actual.equals(expected):
            missing = len(expected.difference(actual))
            unexpected = len(actual.difference(expected))
            raise ValueError(
                f"{label} dates do not exactly match the authoritative exchange "
                f"calendar (missing={missing}, unexpected={unexpected})."
            )


def _normalized_daily_index(parsed_dates: pd.Series, *, label: str) -> pd.DatetimeIndex:
    try:
        index = pd.DatetimeIndex(parsed_dates).tz_localize(None).normalize()
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} contains incompatible or mixed-timezone timestamps.") from exc
    # Validate before duplicate timestamps are aggregated; otherwise hourly input could
    # masquerade as a long daily sample after a groupby.
    validate_daily_session_index(index, label=label)
    return index


def generate_demo_prices(
    n_assets: int = 30,
    years: int = 8,
    seed: int = 7,
    end_date: str = "2026-06-30",
) -> pd.DataFrame:
    """Generate deterministic synthetic prices for demonstrating the application.

    The series intentionally include common factors, volatility regimes, and a modest
    mean-reverting idiosyncratic component. They are not investable market data and
    must never be used as evidence that a strategy is profitable.
    """
    if n_assets < 6:
        raise ValueError("The demo requires at least 6 assets.")
    if years < 2:
        raise ValueError("The demo requires at least 2 years of history.")

    rng = np.random.default_rng(seed)
    n_days = int(round(252 * years))
    dates = pd.bdate_range(end=end_date, periods=n_days)

    n_sectors = max(3, min(8, n_assets // 4))
    sector_id = np.arange(n_assets) % n_sectors
    rng.shuffle(sector_id)

    # Smooth volatility regimes.
    regime = np.ones(n_days)
    regime[int(0.20 * n_days): int(0.31 * n_days)] = 1.9
    regime[int(0.48 * n_days): int(0.58 * n_days)] = 0.7
    regime[int(0.73 * n_days): int(0.82 * n_days)] = 1.5

    market = rng.normal(0.00020, 0.0075 * regime, size=n_days)
    sector_factors = rng.normal(
        0.00004,
        0.0045 * regime[:, None],
        size=(n_days, n_sectors),
    )

    market_beta = rng.uniform(0.45, 1.25, size=n_assets)
    sector_beta = rng.uniform(0.25, 0.85, size=n_assets)
    idio_scale = rng.uniform(0.006, 0.014, size=n_assets)
    drift = rng.normal(0.00005, 0.00004, size=n_assets)

    # Stationary log-price residuals create modest short-horizon relative reversion.
    residual_state = np.zeros((n_days, n_assets))
    rho = rng.uniform(0.88, 0.97, size=n_assets)
    shocks = rng.normal(size=(n_days, n_assets)) * idio_scale[None, :] * regime[:, None]
    for t in range(1, n_days):
        residual_state[t] = rho * residual_state[t - 1] + shocks[t]

    residual_return = np.diff(residual_state, axis=0, prepend=residual_state[[0]])
    log_returns = (
        drift[None, :]
        + market[:, None] * market_beta[None, :]
        + sector_factors[:, sector_id] * sector_beta[None, :]
        + residual_return
    )

    # Add sparse price jumps to exercise the risk controls.
    jump_days = rng.choice(np.arange(50, n_days - 10), size=max(3, years), replace=False)
    for day in jump_days:
        affected = rng.choice(n_assets, size=max(1, n_assets // 8), replace=False)
        log_returns[day, affected] += rng.normal(-0.035, 0.018, size=len(affected))

    start_prices = rng.uniform(35.0, 160.0, size=n_assets)
    prices = start_prices[None, :] * np.exp(np.cumsum(log_returns, axis=0))
    columns = [f"SYN_{i + 1:02d}" for i in range(n_assets)]
    return pd.DataFrame(prices, index=dates, columns=columns).rename_axis("Date")


def _read_csv(source: BinaryIO | bytes) -> pd.DataFrame:
    if isinstance(source, bytes):
        source = BytesIO(source)
    try:
        return pd.read_csv(source)
    except UnicodeDecodeError as exc:
        raise ValueError("CSV must be UTF-8 encoded.") from exc
    except Exception as exc:  # pragma: no cover - pandas provides many parser errors
        raise ValueError(f"Could not parse CSV: {exc}") from exc


def _validated_value_columns(columns: pd.Index, *, label: str) -> list[str]:
    names = [str(column).strip() for column in columns]
    if len(names) > 10_000:
        raise ValueError(f"{label} exceeds the 10,000-asset safety limit.")
    if any(not name for name in names):
        raise ValueError(f"{label} contains a blank asset name.")
    seen: set[str] = set()
    duplicates: set[str] = set()
    for name in names:
        if name in seen:
            duplicates.add(name)
        seen.add(name)
    if duplicates:
        raise ValueError(
            f"{label} contains duplicate asset names: {sorted(duplicates)!r}."
        )
    dangerous = [name for name in names if name[0] in "=+-@"]
    if dangerous:
        raise ValueError(
            f"{label} contains spreadsheet-formula-like asset names: {dangerous!r}."
        )
    return names


def _strict_long_panel(
    source: BinaryIO | bytes,
    *,
    label: str,
    value_columns: tuple[str, ...],
    expected_index: pd.Index,
    expected_columns: pd.Index,
    require_same_session_as_of: bool = False,
) -> tuple[dict[str, pd.DataFrame], pd.DataFrame]:
    """Load a complete Date/Asset panel without aggregation or implicit defaults."""

    raw = _read_csv(source)
    required = {"Date", "Asset", "AsOfTimestamp", *value_columns}
    if set(map(str, raw.columns)) != required:
        raise ValueError(
            f"{label} CSV must contain exactly {sorted(required)!r}."
        )
    if raw.empty:
        raise ValueError(f"{label} CSV is empty.")
    if len(raw) > 5_000_000:
        raise ValueError(f"{label} CSV exceeds the 5,000,000-row safety limit.")

    parsed_dates = pd.to_datetime(raw["Date"], errors="coerce", utc=False)
    if parsed_dates.isna().any():
        raise ValueError(f"{label} CSV contains invalid or missing Date values.")
    try:
        dates = pd.DatetimeIndex(parsed_dates).tz_localize(None).normalize()
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} CSV contains incompatible Date values.") from exc
    assets = raw["Asset"].map(lambda value: str(value).strip())
    if assets.eq("").any() or raw["Asset"].isna().any():
        raise ValueError(f"{label} CSV contains a missing or blank Asset value.")
    _validated_value_columns(pd.Index(assets.unique()), label=f"{label} CSV")

    expected_dates = pd.DatetimeIndex(expected_index).tz_localize(None).normalize()
    expected_assets = pd.Index([str(column) for column in expected_columns])
    if expected_dates.has_duplicates or expected_assets.has_duplicates:
        raise ValueError(f"{label} expected axes must be unique.")
    actual_keys = pd.MultiIndex.from_arrays([dates, assets], names=["Date", "Asset"])
    if actual_keys.has_duplicates:
        raise ValueError(f"{label} CSV contains duplicate Date/Asset rows.")
    expected_keys = pd.MultiIndex.from_product(
        [expected_dates, expected_assets], names=["Date", "Asset"]
    )
    missing = expected_keys.difference(actual_keys)
    unexpected = actual_keys.difference(expected_keys)
    if len(missing) or len(unexpected) or len(actual_keys) != len(expected_keys):
        raise ValueError(
            f"{label} CSV must contain exactly one row for every expected session/asset "
            f"pair (missing={len(missing)}, unexpected={len(unexpected)})."
        )

    # Require the source text to carry Z or an offset before parsing; otherwise
    # pandas could silently interpret a naive timestamp as UTC.
    as_of_text = raw["AsOfTimestamp"].astype(str).str.strip()
    explicit_offset = as_of_text.str.contains(r"(?:Z|[+-]\d{2}:?\d{2})$", regex=True)
    if not bool(explicit_offset.all()):
        raise ValueError(f"{label} AsOfTimestamp must include an explicit UTC offset.")
    # ``format='mixed'`` parses each ISO-8601 value independently.  Without it,
    # pandas may infer the first row's whole-second format and coerce a valid
    # nanosecond-bearing row to NaT before the exact cutoff comparison can reject it.
    as_of = pd.to_datetime(
        raw["AsOfTimestamp"], errors="coerce", utc=True, format="mixed"
    )
    if as_of.isna().any():
        raise ValueError(
            f"{label} AsOfTimestamp values must be valid timezone-aware timestamps."
        )
    as_of_ny = pd.DatetimeIndex(as_of).tz_convert("America/New_York")
    as_of_dates = as_of_ny.tz_localize(None).normalize()
    as_of_seconds = as_of_ny.hour * 3600 + as_of_ny.minute * 60 + as_of_ny.second
    after_exact_cutoff = (as_of_seconds > 9 * 3600 + 30 * 60) | (
        (as_of_seconds == 9 * 3600 + 30 * 60)
        & ((as_of_ny.microsecond > 0) | (as_of_ny.nanosecond > 0))
    )
    row_dates = pd.DatetimeIndex(dates)
    if bool((as_of_dates > row_dates).any()) or bool(
        ((as_of_dates == row_dates) & after_exact_cutoff).any()
    ):
        raise ValueError(
            f"{label} contains information timestamped after its session's 09:30 "
            "America/New_York decision cutoff."
        )
    if require_same_session_as_of and not bool((as_of_dates == row_dates).all()):
        raise ValueError(
            f"{label} AsOfTimestamp must be from the same session date as each row."
        )

    working = raw.copy()
    working["Date"] = dates
    working["Asset"] = assets
    working["AsOfTimestamp"] = pd.Series(as_of, index=working.index).map(
        lambda value: value.isoformat()
    )
    indexed = working.set_index(["Date", "Asset"]).reindex(expected_keys)
    panels = {
        value: indexed[value].unstack("Asset").reindex(
            index=expected_dates, columns=expected_assets
        )
        for value in value_columns
    }
    as_of_panel = indexed["AsOfTimestamp"].unstack("Asset").reindex(
        index=expected_dates, columns=expected_assets
    )
    for frame in (*panels.values(), as_of_panel):
        frame.index.name = "Date"
    return panels, as_of_panel


def _strict_boolean_frame(frame: pd.DataFrame, *, label: str) -> pd.DataFrame:
    def parse(value: object) -> bool:
        if isinstance(value, (bool, np.bool_)):
            return bool(value)
        text = str(value).strip().lower()
        if text == "true":
            return True
        if text == "false":
            return False
        raise ValueError(f"{label} values must be exactly true or false.")

    return frame.map(parse).astype(bool)


def load_corporate_action_csv(
    source: BinaryIO | bytes,
    *,
    expected_index: pd.Index,
    expected_columns: pd.Index,
) -> CorporateActionData:
    """Load a complete, as-of-stamped split and cash-distribution panel.

    Sparse event files are deliberately rejected: sealed evidence must distinguish
    an explicit neutral observation from a vendor omission. No value is filled,
    aggregated, clipped, or inferred.
    """

    panels, as_of = _strict_long_panel(
        source,
        label="Corporate-action data",
        value_columns=("SplitRatio", "CashDistributionPerPreActionShare"),
        expected_index=expected_index,
        expected_columns=expected_columns,
        require_same_session_as_of=True,
    )
    split = panels["SplitRatio"].apply(pd.to_numeric, errors="coerce")
    cash = panels["CashDistributionPerPreActionShare"].apply(
        pd.to_numeric, errors="coerce"
    )
    if split.isna().any().any() or not np.isfinite(split.to_numpy(dtype=float)).all():
        raise ValueError("Corporate-action SplitRatio must be complete and finite.")
    if cash.isna().any().any() or not np.isfinite(cash.to_numpy(dtype=float)).all():
        raise ValueError(
            "Corporate-action CashDistributionPerPreActionShare must be complete and finite."
        )
    if bool(split.le(0.0).any().any()):
        raise ValueError("Corporate-action SplitRatio must be strictly positive.")
    if bool(cash.lt(0.0).any().any()):
        raise ValueError(
            "Corporate-action CashDistributionPerPreActionShare must be non-negative."
        )
    return CorporateActionData(
        split_ratio=split.astype(float),
        cash_distribution=cash.astype(float),
        as_of_timestamp=as_of,
    )


def load_borrow_csv(
    source: BinaryIO | bytes,
    *,
    expected_index: pd.Index,
    expected_columns: pd.Index,
) -> BorrowData:
    """Load complete point-in-time availability, rate, and recall evidence."""

    panels, as_of = _strict_long_panel(
        source,
        label="Borrow data",
        value_columns=("Available", "AnnualRate", "Recall"),
        expected_index=expected_index,
        expected_columns=expected_columns,
        require_same_session_as_of=True,
    )
    availability = _strict_boolean_frame(panels["Available"], label="Borrow Available")
    recall = _strict_boolean_frame(panels["Recall"], label="Borrow Recall")
    rate = panels["AnnualRate"].apply(pd.to_numeric, errors="coerce")
    if rate.isna().any().any() or not np.isfinite(rate.to_numpy(dtype=float)).all():
        raise ValueError("Borrow AnnualRate must be complete and finite.")
    if bool(rate.lt(0.0).any().any()) or bool(rate.gt(10.0).any().any()):
        raise ValueError("Borrow AnnualRate must be between 0 and 10 (0%-1000%).")
    if bool((recall & availability).any().any()):
        raise ValueError("A recalled borrow row cannot simultaneously be Available=true.")
    return BorrowData(
        availability=availability,
        annual_rate=rate.astype(float),
        recall=recall,
        as_of_timestamp=as_of,
    )


def validate_daily_dollar_volume_frame(
    frame: pd.DataFrame,
    *,
    label: str = "Daily dollar-volume data",
    expected_index: pd.Index | None = None,
) -> pd.DataFrame:
    """Validate raw daily dollar volume without filling, clipping, or aggregation.

    Values must be dollar notionals (price multiplied by shares/contracts) in the same
    currency as configured AUM, not raw share volume.  Missing observations are
    preserved so the backtest can identify a traded asset without lagged ADV.  Every
    non-missing observation must be numeric, finite, and strictly positive.
    """
    if not isinstance(frame, pd.DataFrame):
        raise ValueError(f"{label} must be a pandas DataFrame.")
    if frame.empty:
        raise ValueError(f"{label} is empty.")
    if frame.index.has_duplicates:
        raise ValueError(f"{label} index must not contain duplicate dates.")
    if frame.columns.has_duplicates:
        raise ValueError(f"{label} asset columns must be unique.")
    if not isinstance(frame.index, pd.DatetimeIndex):
        raise ValueError(f"{label} must use a DatetimeIndex.")
    if not frame.index.is_monotonic_increasing:
        raise ValueError(f"{label} timestamps must be sorted in increasing order.")
    validate_daily_session_index(frame.index, label=label)
    if expected_index is not None and not frame.index.equals(expected_index):
        raise ValueError(
            f"{label} must have exactly the same sorted index as backtest prices."
        )

    numeric = frame.apply(pd.to_numeric, errors="coerce")
    invalid_numeric = frame.notna() & numeric.isna()
    if bool(invalid_numeric.any().any()):
        raise ValueError(f"{label} contains nonnumeric non-missing observations.")
    values = numeric.to_numpy(dtype=float)
    invalid_values = (~np.isfinite(values) & ~np.isnan(values)) | (
        np.isfinite(values) & (values <= 0.0)
    )
    if np.any(invalid_values):
        raise ValueError(
            f"Every non-missing {label.lower()} value must be finite and strictly positive."
        )
    return numeric.astype(float).copy()


def load_dollar_volume_csv(
    source: BinaryIO | bytes,
) -> tuple[pd.DataFrame, DataQualityReport]:
    """Load wide raw daily dollar volume and preserve every missing observation.

    The first/date-like column is the session date.  Remaining columns must contain
    daily traded *dollar* notional for each asset.  This loader never forward-fills,
    replaces, clips, drops, or averages liquidity observations; causal trailing ADV is
    constructed later by the backtest from sessions completed before each trade.
    """
    raw = _read_csv(source)
    if raw.empty or raw.shape[1] < 3:
        raise ValueError(
            "Dollar-volume CSV needs a date column and at least two asset columns."
        )
    date_candidates = [
        column
        for column in raw.columns
        if str(column).strip().lower() in {"date", "datetime", "timestamp"}
    ]
    date_col = date_candidates[0] if date_candidates else raw.columns[0]
    parsed_dates = pd.to_datetime(raw[date_col], errors="coerce", utc=False)
    if parsed_dates.isna().any():
        raise ValueError(
            "Dollar-volume CSV contains invalid timestamps; silent date deletion is "
            "not permitted."
        )
    raw = raw.copy()
    raw.index = _normalized_daily_index(
        parsed_dates,
        label="Dollar-volume CSV",
    )
    raw = raw.drop(columns=[date_col])
    raw.columns = _validated_value_columns(
        raw.columns,
        label="Dollar-volume CSV",
    )
    numeric = validate_daily_dollar_volume_frame(
        raw,
        label="Dollar-volume CSV",
    )
    years = max((numeric.index[-1] - numeric.index[0]).days / 365.25, 0.0)
    report = DataQualityReport(
        rows=len(numeric),
        assets=numeric.shape[1],
        start=pd.Timestamp(numeric.index[0]),
        end=pd.Timestamp(numeric.index[-1]),
        missing_fraction_before_fill=float(numeric.isna().mean().mean()),
        duplicate_dates_removed=0,
        nonpositive_values_removed=0,
        longest_history_years=years,
        annualized_observation_rate=validate_daily_session_index(
            numeric.index,
            label="Clean dollar-volume CSV",
        ),
    )
    numeric.index.name = "Date"
    return numeric, report


def load_execution_window_dollar_volume_csv(
    source: BinaryIO | bytes,
) -> tuple[pd.DataFrame, DataQualityReport]:
    """Load dollar notional traded only in the certified 09:30-09:35 window.

    This intentionally reuses the strict wide-panel parser. The semantic distinction
    is enforced by the signed manifest provenance and by the sealed app, which never
    treats unrestricted full-session ADV as capacity available to a 09:35 VWAP fill.
    """

    return load_dollar_volume_csv(source)


def load_price_csv(source: BinaryIO | bytes) -> tuple[pd.DataFrame, DataQualityReport]:
    """Load a wide price CSV: one date column, then one adjusted-close column per asset."""
    raw = _read_csv(source)
    if raw.empty or raw.shape[1] < 3:
        raise ValueError("CSV needs a date column and at least two asset columns.")

    date_candidates = [c for c in raw.columns if str(c).strip().lower() in {"date", "datetime", "timestamp"}]
    date_col = date_candidates[0] if date_candidates else raw.columns[0]

    parsed_dates = pd.to_datetime(raw[date_col], errors="coerce", utc=False)
    valid_date = parsed_dates.notna()
    invalid_date_count = int((~valid_date).sum())
    if invalid_date_count:
        raise ValueError(
            f"Price CSV contains {invalid_date_count} invalid timestamp row(s); "
            "silent date deletion is not permitted."
        )
    raw = raw.loc[valid_date].copy()
    parsed_dates = parsed_dates.loc[valid_date]
    if raw.empty:
        raise ValueError("No valid dates were found in the CSV.")

    raw.index = _normalized_daily_index(parsed_dates, label="Price CSV")
    raw = raw.drop(columns=[date_col])
    raw.columns = _validated_value_columns(raw.columns, label="Price CSV")

    numeric = raw.apply(pd.to_numeric, errors="coerce")
    invalid_numeric = raw.notna() & numeric.isna()
    if bool(invalid_numeric.any().any()):
        raise ValueError(
            "Price CSV contains nonnumeric non-missing price observations."
        )
    nonpositive_mask = numeric.le(0) & numeric.notna()
    nonpositive_values_removed = int(nonpositive_mask.sum().sum())
    if nonpositive_values_removed:
        raise ValueError(
            "Price CSV contains explicit non-positive observations; use a missing value "
            "only when the point-in-time source truly has no valid mark."
        )

    before_dupes = len(numeric)
    numeric = numeric.groupby(level=0).last().sort_index()
    duplicate_dates_removed = before_dupes - len(numeric)

    # Use an absolute usability floor rather than a fraction of the full sample.
    # Fractional full-sample filters erase assets that delisted part-way through a long
    # history and therefore introduce a particularly direct form of survivorship bias.
    minimum_valid_observations = min(100, len(numeric))
    numeric = numeric.loc[:, numeric.notna().sum() >= minimum_valid_observations]
    if numeric.shape[1] < 2:
        raise ValueError("Fewer than two assets have sufficient valid observations.")

    missing_before = float(numeric.isna().mean().mean())
    # Preserve raw gaps. The backtest uses observed closes for both marks and signals;
    # silently filling here could fabricate returns or cross-sectional ranks.
    numeric = numeric.dropna(how="all")

    # Recheck the absolute history floor after removing unusable calendar rows.
    numeric = numeric.loc[:, numeric.notna().sum() >= minimum_valid_observations]
    if numeric.shape[1] < 2:
        raise ValueError("Not enough overlapping price history remains after cleaning.")

    years = max((numeric.index[-1] - numeric.index[0]).days / 365.25, 0.0)
    report = DataQualityReport(
        rows=len(numeric),
        assets=numeric.shape[1],
        start=numeric.index[0],
        end=numeric.index[-1],
        missing_fraction_before_fill=missing_before,
        duplicate_dates_removed=duplicate_dates_removed,
        nonpositive_values_removed=nonpositive_values_removed,
        longest_history_years=years,
        annualized_observation_rate=validate_daily_session_index(
            numeric.index, label="Clean price CSV"
        ),
    )
    numeric.index.name = "Date"
    return numeric.astype(float), report


def load_execution_price_csv(
    source: BinaryIO | bytes,
) -> tuple[pd.DataFrame, DataQualityReport]:
    """Load observed execution prices without filling any missing timestamp.

    Execution prices must represent prices that were actually observable and tradable
    at the configured decision latency (for example, next-session 09:35 VWAP). Forward
    filling such a series would fabricate fills, so this loader deliberately preserves
    every gap for the backtester to reject or treat conservatively.
    """
    raw = _read_csv(source)
    if raw.empty or raw.shape[1] < 3:
        raise ValueError("Execution CSV needs a date column and at least two asset columns.")

    date_candidates = [
        column
        for column in raw.columns
        if str(column).strip().lower() in {"date", "datetime", "timestamp"}
    ]
    date_col = date_candidates[0] if date_candidates else raw.columns[0]
    parsed_dates = pd.to_datetime(raw[date_col], errors="coerce", utc=False)
    valid_date = parsed_dates.notna()
    invalid_date_count = int((~valid_date).sum())
    if invalid_date_count:
        raise ValueError(
            "Execution-price CSV contains "
            f"{invalid_date_count} invalid timestamp row(s); silent date deletion "
            "is not permitted."
        )
    raw = raw.loc[valid_date].copy()
    parsed_dates = parsed_dates.loc[valid_date]
    if raw.empty:
        raise ValueError("No valid execution-price dates were found in the CSV.")

    raw.index = _normalized_daily_index(parsed_dates, label="Execution-price CSV")
    raw = raw.drop(columns=[date_col])
    raw.columns = _validated_value_columns(
        raw.columns, label="Execution-price CSV"
    )
    numeric = raw.apply(pd.to_numeric, errors="coerce")
    invalid_numeric = raw.notna() & numeric.isna()
    if bool(invalid_numeric.any().any()):
        raise ValueError(
            "Execution-price CSV contains nonnumeric non-missing observations."
        )
    nonpositive_mask = numeric.le(0) & numeric.notna()
    nonpositive_values_removed = int(nonpositive_mask.sum().sum())
    if nonpositive_values_removed:
        raise ValueError(
            "Execution-price CSV contains explicit non-positive observations."
        )
    before_dupes = len(numeric)
    numeric = numeric.groupby(level=0).last().sort_index()
    duplicate_dates_removed = before_dupes - len(numeric)
    numeric = numeric.dropna(how="all")
    usable = numeric.columns[numeric.notna().sum() >= min(100, len(numeric))]
    numeric = numeric.loc[:, usable]
    if numeric.shape[1] < 2:
        raise ValueError("Fewer than two execution-price assets have sufficient observations.")

    years = max((numeric.index[-1] - numeric.index[0]).days / 365.25, 0.0)
    report = DataQualityReport(
        rows=len(numeric),
        assets=numeric.shape[1],
        start=numeric.index[0],
        end=numeric.index[-1],
        missing_fraction_before_fill=float(numeric.isna().mean().mean()),
        duplicate_dates_removed=duplicate_dates_removed,
        nonpositive_values_removed=nonpositive_values_removed,
        longest_history_years=years,
        annualized_observation_rate=validate_daily_session_index(
            numeric.index, label="Clean execution-price CSV"
        ),
    )
    numeric.index.name = "Date"
    return numeric.astype(float), report


def quality_report_for_dataframe(prices: pd.DataFrame) -> DataQualityReport:
    if prices.empty:
        raise ValueError("Price data are empty.")
    years = max((prices.index[-1] - prices.index[0]).days / 365.25, 0.0)
    return DataQualityReport(
        rows=len(prices),
        assets=prices.shape[1],
        start=pd.Timestamp(prices.index[0]),
        end=pd.Timestamp(prices.index[-1]),
        missing_fraction_before_fill=float(prices.isna().mean().mean()),
        duplicate_dates_removed=0,
        nonpositive_values_removed=0,
        longest_history_years=years,
        annualized_observation_rate=validate_daily_session_index(
            prices.index, label="Price data"
        ),
    )
