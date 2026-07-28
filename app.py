from __future__ import annotations

import json
import inspect
import os
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from quant_app.attribution import FactorRegressionResult, factor_regression
from quant_app.backtest import BacktestResult, run_backtest
from quant_app.config import (
    AppConfig,
    CostConfig,
    PortfolioConfig,
    RegimeConfig,
    RiskConfig,
    SignalConfig,
)
from quant_app.data import (
    BorrowData,
    CorporateActionData,
    DataQualityReport,
    generate_demo_prices,
    load_borrow_csv,
    load_corporate_action_csv,
    load_exchange_session_calendar_csv,
    load_execution_window_dollar_volume_csv,
    load_execution_price_csv,
    load_price_csv,
    quality_report_for_dataframe,
    validate_exchange_session_alignment,
)
from quant_app.experiment import (
    CLOSE_HOLDOUT_IDENTITY_VERSION,
    DATAFRAME_FINGERPRINT_VERSION,
    ResearchLedger,
    fingerprint_config,
    fingerprint_holdout_outcomes,
    fingerprint_prices,
)
from quant_app.governance import (
    SEALED_BORROW_AS_OF_CUTOFF,
    SEALED_BORROW_RATE_DEFINITION,
    SEALED_CORPORATE_ACTION_AS_OF_CUTOFF,
    SEALED_CORPORATE_ACTION_CASH_DEFINITION,
    SEALED_CORPORATE_ACTION_SPLIT_DEFINITION,
    SEALED_DECISION_INFORMATION_CUTOFF,
    SEALED_EXECUTION_PRICE_DEFINITION,
    SEALED_EXECUTION_PRICE_ROW_LABEL,
    SEALED_INTERVAL_TIMEZONE,
    SEALED_LIQUIDITY_DEFINITION,
    SEALED_LIQUIDITY_WINDOW,
    SEALED_RETURN_INTERVAL,
    SEALED_RETURN_ROW_LABEL,
    certification_context_hash,
    certification_payload_is_current,
    load_factor_return_csv,
    load_trusted_key_registry,
    research_runtime_identity,
    sha256_bytes,
    verify_sealed_manifest,
)
from quant_app.metrics import (
    annual_performance,
    drawdown_series,
    equity_from_returns,
    metrics_from_returns,
    regime_performance,
    rolling_metrics,
)
from quant_app.reporting import build_result_bundle
from quant_app.validation import (
    MAX_CERTIFIED_DAILY_OBSERVATION_RATE,
    MIN_CERTIFIED_DAILY_OBSERVATION_RATE,
    MIN_PERTURBATION_CAGR_TARGET_RETENTION,
    MIN_PERTURBATION_PASS_RATE,
    MIN_PERTURBATION_SHARPE,
    MIN_PERTURBATION_UNIVERSE_RETENTION,
    PARAMETER_PERTURBATION_FAMILY_ID,
    PARAMETER_PERTURBATION_VARIANT_COUNT,
    PATH_AWARE_BOOTSTRAP_METHOD_ID,
    PATH_AWARE_BOOTSTRAP_PATHS,
    PATH_AWARE_BOOTSTRAP_POLICY_SHA256,
    PATH_AWARE_BOOTSTRAP_SEED,
    BootstrapSummary,
    block_bootstrap_validation,
    certification_table,
    doubled_cost_config,
    parameter_perturbation_gate,
    parameter_perturbation_specification_hash,
    path_aware_block_bootstrap_validation,
    rolling_target_pass_rate,
    run_parameter_perturbations,
    sealed_daily_observation_rate_is_valid,
    sharpe_probability_diagnostics,
    split_index,
)

st.set_page_config(
    page_title="Quant Strategy Research Lab",
    page_icon="📈",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .block-container {padding-top: 1.4rem; padding-bottom: 2.5rem;}
    .small-note {font-size: 0.88rem; opacity: 0.78;}
    .status-box {padding: 0.8rem 1rem; border-radius: 0.45rem; border: 1px solid rgba(128,128,128,.35);}
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_data(show_spinner=False)
def cached_demo_prices(n_assets: int, years: int, seed: int) -> pd.DataFrame:
    return generate_demo_prices(n_assets=n_assets, years=years, seed=seed)


@st.cache_data(show_spinner=False)
def cached_backtest(
    prices: pd.DataFrame,
    config: AppConfig,
    research_software_sha256: str,
    execution_prices: pd.DataFrame | None = None,
    execution_window_dollar_volume: pd.DataFrame | None = None,
    corporate_actions: CorporateActionData | None = None,
    borrow_data: BorrowData | None = None,
    borrow_rate_stress_multiplier: float = 1.0,
) -> BacktestResult:
    if (
        len(research_software_sha256) != 64
        or any(character not in "0123456789abcdef" for character in research_software_sha256)
    ):
        raise ValueError("The research-software backtest cache identity is invalid.")
    # Live plans are formed after a completed close and executed the next session.
    # Without aligned execution prices, use the conservative full-bar latency proxy
    # rather than crediting the strategy with an untradeable overnight return.
    semantics = "next_open_to_open" if execution_prices is not None else "next_close_proxy"
    if "execution_window_dollar_volume" not in inspect.signature(run_backtest).parameters:
        if corporate_actions is not None or borrow_data is not None:
            raise ValueError(
                "This research engine build does not yet consume the required "
                "corporate-action and point-in-time borrow panels. Sealed validation "
                "fails closed."
            )
        return run_backtest(
            prices,
            config,
            execution_return_semantics=semantics,
            execution_prices=execution_prices,
            daily_dollar_volume=execution_window_dollar_volume,
        )
    return run_backtest(
        prices,
        config,
        execution_return_semantics=semantics,
        execution_prices=execution_prices,
        execution_window_dollar_volume=execution_window_dollar_volume,
        corporate_action_split_ratios=(
            corporate_actions.split_ratio if corporate_actions is not None else None
        ),
        corporate_action_cash_distributions=(
            corporate_actions.cash_distribution
            if corporate_actions is not None
            else None
        ),
        borrow_availability=(
            borrow_data.availability if borrow_data is not None else None
        ),
        annual_borrow_rates=(
            borrow_data.annual_rate if borrow_data is not None else None
        ),
        borrow_recalls=borrow_data.recall if borrow_data is not None else None,
        borrow_rate_stress_multiplier=borrow_rate_stress_multiplier,
    )


@st.cache_data(show_spinner=False)
def cached_path_aware_bootstrap(
    prices: pd.DataFrame,
    config: AppConfig,
    in_sample_fraction: float,
    horizon_days: int,
    block_size: int,
    target_cagr: float,
    max_drawdown: float,
    research_software_sha256: str,
    execution_prices: pd.DataFrame,
    execution_window_dollar_volume: pd.DataFrame,
    corporate_actions: CorporateActionData,
    borrow_data: BorrowData,
) -> BootstrapSummary:
    if (
        len(research_software_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in research_software_sha256
        )
    ):
        raise ValueError("The path-bootstrap software identity is invalid.")
    split = split_index(prices.index, in_sample_fraction)
    return path_aware_block_bootstrap_validation(
        prices,
        config,
        prices.index[split:],
        horizon_days=horizon_days,
        block_size=block_size,
        target_cagr=target_cagr,
        max_drawdown=max_drawdown,
        n_paths=PATH_AWARE_BOOTSTRAP_PATHS,
        seed=PATH_AWARE_BOOTSTRAP_SEED,
        execution_return_semantics="next_open_to_open",
        execution_prices=execution_prices,
        execution_window_dollar_volume=execution_window_dollar_volume,
        corporate_action_split_ratios=corporate_actions.split_ratio,
        corporate_action_cash_distributions=corporate_actions.cash_distribution,
        borrow_availability=borrow_data.availability,
        annual_borrow_rates=borrow_data.annual_rate,
        borrow_recalls=borrow_data.recall,
    )


@st.cache_data(show_spinner=False)
def cached_perturbations(
    prices: pd.DataFrame,
    config: AppConfig,
    in_sample_fraction: float,
    perturbation_family_id: str,
    perturbation_specification_sha256: str,
    research_software_sha256: str,
    execution_prices: pd.DataFrame | None = None,
    execution_window_dollar_volume: pd.DataFrame | None = None,
    corporate_actions: CorporateActionData | None = None,
    borrow_data: BorrowData | None = None,
) -> pd.DataFrame:
    if perturbation_family_id != PARAMETER_PERTURBATION_FAMILY_ID:
        raise ValueError("The cached perturbation family identity is stale.")
    if (
        perturbation_specification_sha256
        != parameter_perturbation_specification_hash(config)
    ):
        raise ValueError("The cached perturbation specification identity is stale.")
    if (
        len(research_software_sha256) != 64
        or any(character not in "0123456789abcdef" for character in research_software_sha256)
    ):
        raise ValueError("The research-software cache identity is invalid.")
    semantics = "next_open_to_open" if execution_prices is not None else "next_close_proxy"
    return run_parameter_perturbations(
        prices,
        config,
        in_sample_fraction,
        execution_return_semantics=semantics,
        execution_prices=execution_prices,
        execution_window_dollar_volume=execution_window_dollar_volume,
        corporate_action_split_ratios=(
            corporate_actions.split_ratio if corporate_actions is not None else None
        ),
        corporate_action_cash_distributions=(
            corporate_actions.cash_distribution
            if corporate_actions is not None
            else None
        ),
        borrow_availability=(
            borrow_data.availability if borrow_data is not None else None
        ),
        annual_borrow_rates=(
            borrow_data.annual_rate if borrow_data is not None else None
        ),
        borrow_recalls=borrow_data.recall if borrow_data is not None else None,
    )


@st.cache_resource(show_spinner=False)
def research_ledger(path: str) -> ResearchLedger:
    return ResearchLedger(path)


def pct(value: float | None, digits: int = 2) -> str:
    if value is None or not np.isfinite(value):
        return "N/A"
    return f"{value:.{digits}%}"


def number(value: float | None, digits: int = 2) -> str:
    if value is None or not np.isfinite(value):
        return "N/A"
    return f"{value:.{digits}f}"


def quality_summary(report: DataQualityReport) -> None:
    cols = st.columns(6)
    cols[0].metric("Rows", f"{report.rows:,}")
    cols[1].metric("Assets", f"{report.assets:,}")
    cols[2].metric("History", f"{report.longest_history_years:.1f} years")
    cols[3].metric("Start", report.start.strftime("%Y-%m-%d"))
    cols[4].metric("End", report.end.strftime("%Y-%m-%d"))
    cols[5].metric("Obs/year", number(report.annualized_observation_rate, 1))


def halt_consumed_research_run(stage: str, exc: Exception) -> None:
    """Fail visibly while preserving the already-recorded holdout consumption."""
    st.error(
        f"Research run stopped during {stage}: {exc}. The holdout claim remains "
        "consumed in the persistent ledger; correct the input outside this holdout "
        "and use a genuinely new governed experiment rather than retrying it."
    )
    st.stop()


def metric_grid(metrics: dict[str, Any]) -> None:
    first = st.columns(5)
    first[0].metric("CAGR", pct(metrics.get("CAGR")))
    first[1].metric("Max drawdown", pct(metrics.get("Max Drawdown")))
    first[2].metric("Sharpe", number(metrics.get("Sharpe Ratio")))
    first[3].metric("Calmar", number(metrics.get("Calmar Ratio")))
    first[4].metric("Annual volatility", pct(metrics.get("Annualized Volatility")))

    second = st.columns(5)
    second[0].metric("Hit rate", pct(metrics.get("Hit Rate")))
    second[1].metric("Profit factor", number(metrics.get("Profit Factor")))
    second[2].metric("Average gross", pct(metrics.get("Average Gross Exposure")))
    second[3].metric("Max gross", pct(metrics.get("Maximum Gross Exposure")))
    second[4].metric("Shutdown events", str(metrics.get("Shutdown Events", "N/A")))


def line_chart(frame: pd.DataFrame, title: str, yaxis_title: str, height: int = 420) -> None:
    fig = go.Figure()
    for column in frame.columns:
        fig.add_trace(go.Scatter(x=frame.index, y=frame[column], mode="lines", name=str(column)))
    fig.update_layout(
        title=title,
        height=height,
        margin=dict(l=10, r=10, t=48, b=10),
        yaxis_title=yaxis_title,
        legend=dict(orientation="h"),
        hovermode="x unified",
    )
    st.plotly_chart(fig, width="stretch")


def display_certification(table: pd.DataFrame) -> pd.DataFrame:
    display = table.copy()
    observed: list[str] = []
    for test, row in display.iterrows():
        value = row["Observed"]
        lower = test.lower()
        if isinstance(value, str):
            observed.append(value)
        elif isinstance(value, (bool, np.bool_)):
            observed.append("Yes" if bool(value) else "No")
        elif any(
            term in lower
            for term in (
                "observation",
                "asset count",
                "asset breadth",
                "factor count",
                "trial count",
                "monte carlo paths",
                "horizon years",
                "block size",
            )
        ):
            observed.append(str(int(value)) if np.isfinite(value) else "N/A")
        elif any(
            term in lower
            for term in (
                "leverage",
                "calmar",
                "t-stat",
                "beta",
                "ratio",
                "bps",
                "elapsed",
            )
        ):
            observed.append(number(float(value)))
        elif "breach" in lower:
            observed.append(str(int(value)) if np.isfinite(value) else "N/A")
        else:
            observed.append(pct(float(value)))
    display["Observed"] = observed
    display["Pass"] = display["Pass"].map({True: "PASS", False: "FAIL"})
    return display


def bootstrap_or_nan(
    returns: pd.Series,
    n_paths: int,
    horizon_days: int,
    block_size: int,
    target_cagr: float,
    max_drawdown: float,
) -> tuple[BootstrapSummary, str | None]:
    try:
        return (
            block_bootstrap_validation(
                returns=returns,
                n_paths=n_paths,
                horizon_days=horizon_days,
                block_size=block_size,
                target_cagr=target_cagr,
                max_drawdown=max_drawdown,
            ),
            None,
        )
    except ValueError as exc:
        nan = float("nan")
        return (
            BootstrapSummary(
                paths=n_paths,
                horizon_days=horizon_days,
                probability_positive_cagr=nan,
                probability_cagr_target=nan,
                probability_drawdown_target=nan,
                probability_both_targets=nan,
                median_cagr=nan,
                fifth_percentile_cagr=nan,
                median_max_drawdown=nan,
                fifth_percentile_max_drawdown=nan,
                worst_max_drawdown=nan,
            ),
            str(exc),
        )


def unavailable_path_bootstrap(
    *,
    horizon_days: int,
    block_size: int,
) -> BootstrapSummary:
    nan = float("nan")
    return BootstrapSummary(
        paths=PATH_AWARE_BOOTSTRAP_PATHS,
        horizon_days=horizon_days,
        probability_positive_cagr=nan,
        probability_cagr_target=nan,
        probability_drawdown_target=nan,
        probability_both_targets=nan,
        median_cagr=nan,
        fifth_percentile_cagr=nan,
        median_max_drawdown=nan,
        fifth_percentile_max_drawdown=nan,
        worst_max_drawdown=nan,
        probability_both_targets_lower_95=nan,
        method_id=PATH_AWARE_BOOTSTRAP_METHOD_ID,
        seed=PATH_AWARE_BOOTSTRAP_SEED,
        block_size=block_size,
        sampling_plan_sha256="",
        policy_sha256=PATH_AWARE_BOOTSTRAP_POLICY_SHA256,
        state_machine_rerun=False,
        failed_paths=PATH_AWARE_BOOTSTRAP_PATHS,
        valid_path_fraction=0.0,
    )


ledger_path = Path(
    os.environ.get("RESEARCH_LEDGER_PATH", "runtime/research_trials.sqlite3")
).expanduser()
if not ledger_path.is_absolute():
    ledger_path = Path(__file__).resolve().parent / ledger_path
ledger = research_ledger(str(ledger_path.resolve(strict=False)))
if not ledger.verify_hash_chain():
    st.error(
        "The persistent research ledger failed its tamper-evident hash-chain check. "
        "Research execution is blocked until the ledger is independently reviewed."
    )
    st.stop()

st.title("Quant Strategy Research Lab")
st.caption(
    "Market-neutral multi-signal research with persistent experiment governance, "
    "causal validation, dynamic risk, and falsifiable performance targets."
)
st.warning(
    "This application produces hypothetical research results—not guaranteed returns. "
    "A strategy is marked certified only when every configured out-of-sample and stress criterion passes."
)

manifest_bytes: bytes | None = None
anchor_receipt_bytes: bytes | None = None
factor_returns: pd.DataFrame | None = None
factor_data_ack = False
execution_window_dollar_volume: pd.DataFrame | None = None
dollar_volume_report: DataQualityReport | None = None
dollar_volume_ack = False
corporate_actions: CorporateActionData | None = None
corporate_action_ack = False
borrow_data: BorrowData | None = None
borrow_data_ack = False
exchange_calendar: pd.DatetimeIndex | None = None
exchange_calendar_ack = False

with st.sidebar:
    st.header("1 · Data")
    source = st.radio("Price source", ["Synthetic demonstration", "Upload adjusted-close CSV"])

    mode_label = st.radio(
        "Experiment governance",
        ["Exploratory research", "Sealed final validation"],
        help=(
            "Every holdout view is written to a persistent ledger. A sealed validation "
            "is eligible only on the first view of a real-data holdout."
        ),
    )
    research_mode = "sealed_final" if mode_label == "Sealed final validation" else "exploratory"
    sealed_ack = False
    point_in_time_ack = False
    execution_cost_ack = False
    if research_mode == "sealed_final":
        st.warning(
            "A sealed holdout is single-use. Failed and interrupted evaluations still consume it."
        )
        sealed_ack = st.checkbox(
            "I froze the strategy specification before viewing this holdout",
            value=False,
        )
        point_in_time_ack = st.checkbox(
            "The upload is point-in-time and includes delistings/universe changes",
            value=False,
        )
        execution_cost_ack = st.checkbox(
            "Cost assumptions come from measured or broker-verified execution data",
            value=False,
        )
        factor_data_ack = st.checkbox(
            "Factor returns are point-in-time, frozen, and independent of this strategy",
            value=False,
        )
        dollar_volume_ack = st.checkbox(
            "Liquidity values are 09:30-09:35 dollar notional in the configured AUM currency",
            value=False,
        )
        corporate_action_ack = st.checkbox(
            "Corporate actions are point-in-time complete (explicit neutral rows included)",
            value=False,
        )
        borrow_data_ack = st.checkbox(
            "Borrow availability, rates, and recalls are security/date point-in-time observations",
            value=False,
        )
        exchange_calendar_ack = st.checkbox(
            "The session calendar is an independently retained authoritative exchange calendar",
            value=False,
        )
        exchange_calendar_upload = st.file_uploader(
            "Authoritative exchange-session calendar CSV (Date only)",
            type=["csv"],
            key="exchange_session_calendar_upload",
            help=(
                "The signed manifest binds this exact calendar and its vendor snapshot. "
                "Every sealed close, 09:35 execution, execution-window liquidity, "
                "corporate-action, borrow, and factor row must "
                "match these dates exactly; the app does not invent exchange holidays."
            ),
        )
        if exchange_calendar_upload is not None:
            try:
                exchange_calendar = load_exchange_session_calendar_csv(
                    exchange_calendar_upload.getvalue()
                )
            except ValueError as exc:
                st.error(f"Exchange-session calendar CSV: {exc}")
                st.stop()
        factor_upload = st.file_uploader(
            "Point-in-time factor-return CSV (Date plus at least two named factors)",
            type=["csv"],
            key="factor_return_upload",
            help=(
                "The signed manifest binds the exact parsed dataframe and names its "
                "market factor, vendor snapshot, and 09:35 America/New_York-to-next-"
                "09:35 interval. Each Date must label the session at the interval end, "
                "matching the strategy-return index. Missing factor observations are "
                "never filled."
            ),
        )
        if factor_upload is not None:
            try:
                factor_returns = load_factor_return_csv(factor_upload.getvalue())
            except ValueError as exc:
                st.error(f"Factor-return CSV: {exc}")
                st.stop()
        manifest_upload = st.file_uploader(
            "Signed sealed-research manifest JSON",
            type=["json"],
            key="sealed_governance_manifest",
            help=(
                "Must be signed by an active key in the deployment-pinned governance "
                "registry before the holdout is viewed."
            ),
        )
        if manifest_upload is not None:
            manifest_bytes = manifest_upload.getvalue()
        anchor_upload = st.file_uploader(
            "Signed external WORM preregistration receipt JSON",
            key="sealed_anchor_receipt",
            help=(
                "The receipt must use a trusted key distinct from the manifest signer and "
                "bind the exact ledger UUID/head/count, experiment, data, and specification."
            ),
        )
        if anchor_upload is not None:
            anchor_receipt_bytes = anchor_upload.getvalue()

    if source == "Synthetic demonstration":
        execution_prices = None
        execution_data_report = None
        demo_assets = st.slider("Synthetic assets", 8, 60, 30, 2)
        demo_years = st.slider("Synthetic history (years)", 3, 15, 8)
        demo_seed = st.number_input("Synthetic seed", min_value=1, max_value=1_000_000, value=7)
        prices = cached_demo_prices(demo_assets, demo_years, int(demo_seed))
        data_report = quality_report_for_dataframe(prices)
        st.caption("Synthetic data are for software demonstration only and cannot validate profitability.")
        st.download_button(
            "Download demonstration CSV",
            prices.to_csv().encode("utf-8"),
            file_name="synthetic_adjusted_close.csv",
            mime="text/csv",
        )
    else:
        upload = st.file_uploader("Wide CSV: Date, Asset_1, Asset_2, …", type=["csv"])
        if upload is None:
            st.info("Upload a CSV to enable the research controls.")
            st.stop()
        try:
            prices, data_report = load_price_csv(upload.getvalue())
        except ValueError as exc:
            st.error(str(exc))
            st.stop()

        execution_upload = st.file_uploader(
            "Aligned 09:35 America/New_York point-in-time VWAP CSV",
            type=["csv"],
            key="execution_price_upload",
            help=(
                "Use the same Date and asset columns as the adjusted-close file. Each row "
                "must be that session's 09:35 America/New_York point-in-time VWAP. Missing "
                "execution prices are never forward-filled. The signed manifest must identify "
                "the same-session price-row convention, venue, and vendor snapshot."
            ),
        )
        execution_prices = None
        execution_data_report = None
        if execution_upload is not None:
            try:
                raw_execution_prices, execution_data_report = load_execution_price_csv(
                    execution_upload.getvalue()
                )
                if not raw_execution_prices.index.equals(prices.index):
                    raise ValueError(
                        "Execution-price dates must exactly match adjusted-close dates."
                    )
                if set(raw_execution_prices.columns) != set(prices.columns):
                    raise ValueError(
                        "Execution-price asset columns must exactly match adjusted-close assets."
                    )
                execution_prices = raw_execution_prices.reindex(
                    index=prices.index,
                    columns=prices.columns,
                )
            except ValueError as exc:
                st.error(f"Execution-price CSV: {exc}")
                st.stop()

        if research_mode == "sealed_final":
            corporate_action_upload = st.file_uploader(
                "Complete point-in-time corporate-action CSV",
                type=["csv"],
                key="corporate_action_upload",
                help=(
                    "Exactly Date, Asset, AsOfTimestamp, SplitRatio, and "
                    "CashDistributionPerPreActionShare. Supply one row for every "
                    "session/asset, including explicit SplitRatio=1 and cash=0 rows. "
                    "Row t covers the prior 09:35-to-row-t 09:35 interval."
                ),
            )
            if corporate_action_upload is not None:
                try:
                    corporate_actions = load_corporate_action_csv(
                        corporate_action_upload.getvalue(),
                        expected_index=prices.index,
                        expected_columns=prices.columns,
                    )
                except ValueError as exc:
                    st.error(f"Corporate-action CSV: {exc}")
                    st.stop()

            borrow_upload = st.file_uploader(
                "Complete point-in-time borrow CSV",
                type=["csv"],
                key="borrow_data_upload",
                help=(
                    "Exactly Date, Asset, AsOfTimestamp, Available, AnnualRate, "
                    "and Recall. Supply every session/asset row. AsOfTimestamp must "
                    "be no later than that session's 09:30 America/New_York decision cutoff."
                ),
            )
            if borrow_upload is not None:
                try:
                    borrow_data = load_borrow_csv(
                        borrow_upload.getvalue(),
                        expected_index=prices.index,
                        expected_columns=prices.columns,
                    )
                except ValueError as exc:
                    st.error(f"Borrow CSV: {exc}")
                    st.stop()

        dollar_volume_upload = st.file_uploader(
            "09:30-09:35 execution-window dollar-volume CSV",
            type=["csv"],
            key="daily_dollar_volume_upload",
            help=(
                "Values must be traded dollar notional only in the same 09:30-09:35 "
                "window used for the fill, in the configured AUM currency. Full-session "
                "volume is not accepted as capacity for a 09:35 fill."
            ),
        )
        if dollar_volume_upload is not None:
            try:
                loaded_volume, dollar_volume_report = load_execution_window_dollar_volume_csv(
                    dollar_volume_upload.getvalue()
                )
                if not loaded_volume.index.equals(prices.index):
                    raise ValueError(
                        "Execution-window dollar-volume dates must exactly match adjusted-close dates."
                    )
                if set(loaded_volume.columns) != set(prices.columns):
                    raise ValueError(
                        "Execution-window dollar-volume asset columns must exactly match adjusted-close assets."
                    )
                execution_window_dollar_volume = loaded_volume.reindex(columns=prices.columns)
            except ValueError as exc:
                st.error(f"Execution-window dollar-volume CSV: {exc}")
                st.stop()

    exchange_calendar_exact_match = bool(
        exchange_calendar is not None and exchange_calendar.equals(prices.index)
    )
    factor_calendar_exact_match = bool(
        factor_returns is not None and factor_returns.index.equals(prices.index)
    )
    if exchange_calendar is not None:
        aligned_inputs = {"Adjusted-close data": prices}
        if execution_prices is not None:
            aligned_inputs["Execution-price data"] = execution_prices
        if execution_window_dollar_volume is not None:
            aligned_inputs["Execution-window dollar-volume data"] = (
                execution_window_dollar_volume
            )
        if corporate_actions is not None:
            aligned_inputs["Corporate-action split data"] = corporate_actions.split_ratio
            aligned_inputs["Corporate-action cash data"] = (
                corporate_actions.cash_distribution
            )
        if borrow_data is not None:
            aligned_inputs["Borrow availability data"] = borrow_data.availability
            aligned_inputs["Borrow rate data"] = borrow_data.annual_rate
            aligned_inputs["Borrow recall data"] = borrow_data.recall
        if factor_returns is not None:
            aligned_inputs["Factor-return data"] = factor_returns
        try:
            validate_exchange_session_alignment(
                exchange_calendar,
                **aligned_inputs,
            )
        except ValueError as exc:
            st.error(str(exc))
            st.stop()

    st.header("2 · Strategy")
    # Certification inputs must rerun immediately. Streamlit forms otherwise allow
    # changed client-side controls to coexist with an old server-side certification
    # until Submit is pressed, which is an unsafe stale-result presentation.
    with st.container(border=True):
        target_vol = st.slider("Target annual volatility", 0.04, 0.35, 0.10, 0.01, format="%.0f%%")
        max_gross = st.slider("Maximum gross leverage", 0.50, 5.00, 2.50, 0.10, format="%.2fx")
        max_position = st.slider("Maximum position (% NAV)", 0.01, 0.20, 0.08, 0.01, format="%.0f%%")
        if research_mode == "sealed_final":
            st.number_input(
                "Rebalance every N trading days",
                min_value=1,
                max_value=1,
                value=1,
                disabled=True,
                key="sealed_rebalance_every",
                help=(
                    "Sealed validation is fixed to daily rebalancing because governed "
                    "live execution has no authenticated cadence anchor for N > 1."
                ),
            )
            rebalance_every = 1
            st.caption("Sealed/deployable cadence is fixed at one trading session.")
        else:
            rebalance_every = st.slider(
                "Rebalance every N trading days",
                1,
                10,
                1,
                key="exploratory_rebalance_every",
            )

        with st.expander("Signal ensemble", expanded=False):
            rev3 = st.slider("3-day reversal weight", 0.0, 1.0, 0.25, 0.05)
            rev10 = st.slider("10-day reversal weight", 0.0, 1.0, 0.20, 0.05)
            residual_rev = st.slider("Residual reversal weight", 0.0, 1.0, 0.25, 0.05)
            mom63 = st.slider("63-day momentum weight", 0.0, 1.0, 0.15, 0.05)
            mom126 = st.slider("126-day momentum weight", 0.0, 1.0, 0.15, 0.05)

        with st.expander("Regime health", expanded=False):
            ic_window = st.slider("Rolling IC window", 20, 126, 60)
            favorable_t = st.slider("Favorable IC t-stat", -0.5, 2.5, 0.5, 0.1)
            invalid_t = st.slider("Invalid IC t-stat", -2.5, 0.0, -0.75, 0.05)
            neutral_multiplier = st.slider("Neutral-regime risk multiplier", 0.0, 1.0, 0.70, 0.05)
            degraded_multiplier = st.slider("Degraded-regime risk multiplier", 0.0, 0.75, 0.30, 0.05)

        with st.expander("Execution costs", expanded=False):
            transaction_bps = st.slider("One-way transaction cost (bps)", 0.0, 30.0, 3.0, 0.5)
            borrow_rate = st.slider("Annual short-borrow rate", 0.0, 0.30, 0.02, 0.005, format="%.1f%%")
            financing_rate = st.slider("Annual financing rate", 0.0, 0.30, 0.04, 0.005, format="%.1f%%")
            starting_capital = st.number_input(
                "Modeled AUM / starting capital",
                min_value=100_000.0,
                max_value=10_000_000_000.0,
                value=10_000_000.0,
                step=100_000.0,
                format="%.0f",
            )
            adv_lookback = st.slider("Lagged ADV lookback (sessions)", 2, 252, 20)
            max_participation = st.slider(
                "Maximum execution-window participation",
                0.001,
                0.100,
                0.010,
                0.001,
                format="%.1f%%",
            )
            impact_coefficient = st.slider(
                "Square-root impact coefficient",
                0.1,
                3.0,
                1.0,
                0.1,
            )
            impact_vol_floor = st.slider(
                "Daily volatility floor for impact",
                0.001,
                0.100,
                0.010,
                0.001,
                format="%.1f%%",
            )

        with st.expander("Strict shutdowns", expanded=False):
            flatten_dd = st.slider("Flatten portfolio at drawdown", 0.08, 0.20, 0.12, 0.01, format="%.0f%%")
            hard_dd = st.slider("Hard breach threshold", 0.10, 0.30, 0.15, 0.01, format="%.0f%%")
            cooldown = st.slider("Cooldown after flattening", 5, 60, 20)
            daily_loss = st.slider("Daily loss shock trigger", 0.005, 0.05, 0.02, 0.005, format="%.1f%%")
            five_day_loss = st.slider("Five-day loss shock trigger", 0.01, 0.10, 0.04, 0.005, format="%.1f%%")

        st.subheader("3 · Validation target")
        target_cagr = st.slider("Target CAGR", 0.05, 1.00, 0.60, 0.05, format="%.0f%%")
        target_max_dd = st.slider("Maximum allowed drawdown", 0.05, 0.30, 0.15, 0.01, format="%.0f%%")
        confidence = st.slider("Required evidence probability", 0.80, 0.99, 0.95, 0.01, format="%.0f%%")
        in_sample_fraction = st.slider("In-sample fraction", 0.50, 0.85, 0.70, 0.05, format="%.0f%%")
        bootstrap_paths = st.select_slider("Bootstrap paths", options=[500, 1_000, 2_000, 5_000], value=1_000)
        bootstrap_years = st.slider("Bootstrap horizon (years)", 1, 5, 3)
        block_size = st.slider("Bootstrap block size (days)", 5, 63, 20)
        run_perturbations = st.checkbox("Run parameter perturbation suite", value=False)

        submitted = st.button("Run research backtest", type="primary", width="stretch")

if research_mode == "sealed_final" and not ledger.close_holdout_identity_is_current():
    st.error(
        "Sealed validation is disabled for this non-empty legacy research ledger. "
        "Its historical records do not retain trustworthy OOS interval-overlap "
        "identity. Archive it for independent review and provision a "
        "fresh governed ledger; history is never silently treated as first use."
    )
    st.stop()

if flatten_dd >= hard_dd:
    st.error("Flatten drawdown must be below the hard breach threshold.")
    st.stop()
if sum([rev3, rev10, residual_rev, mom63, mom126]) <= 0:
    st.error("At least one signal weight must be positive.")
    st.stop()

# Derive intermediate risk thresholds so ordering cannot become invalid.
risk_config = RiskConfig(
    throttle_drawdown=flatten_dd * 0.42,
    defensive_drawdown=flatten_dd * 0.67,
    severe_drawdown=flatten_dd * 0.84,
    flatten_drawdown=flatten_dd,
    hard_drawdown_limit=hard_dd,
    cooldown_days=cooldown,
    daily_loss_trigger=daily_loss,
    five_day_loss_trigger=five_day_loss,
)
config = AppConfig(
    signals=SignalConfig(
        reversal_3_weight=rev3,
        reversal_10_weight=rev10,
        residual_reversal_weight=residual_rev,
        momentum_63_weight=mom63,
        momentum_126_weight=mom126,
    ),
    portfolio=PortfolioConfig(
        target_volatility=target_vol,
        max_gross_leverage=max_gross,
        max_position_weight=max_position,
        rebalance_every=rebalance_every,
    ),
    regime=RegimeConfig(
        ic_window=ic_window,
        favorable_ic_tstat=favorable_t,
        neutral_ic_tstat=0.0,
        invalid_ic_tstat=invalid_t,
        neutral_multiplier=neutral_multiplier,
        degraded_multiplier=degraded_multiplier,
    ),
    risk=risk_config,
    costs=CostConfig(
        transaction_cost_bps=transaction_bps,
        annual_short_borrow_rate=borrow_rate,
        annual_financing_rate=financing_rate,
        starting_capital=float(starting_capital),
        adv_lookback_days=adv_lookback,
        max_participation_rate=max_participation,
        square_root_impact_coefficient=impact_coefficient,
        impact_daily_volatility_floor=impact_vol_floor,
    ),
)
try:
    config.validate()
except ValueError as exc:
    st.error(f"Invalid strategy or risk configuration: {exc}")
    st.stop()
perturbation_specification_sha256 = (
    parameter_perturbation_specification_hash(config) if run_perturbations else ""
)

# Compute a complete run identity on every Streamlit rerun, not only after Submit.
# This prevents an earlier certification payload from surviving data, split, model,
# attestation, governance-key, or validation-control changes in the same session.
preview_split = split_index(prices.index, in_sample_fraction)
preview_oos_start = pd.Timestamp(prices.index[preview_split])
preview_oos_end = pd.Timestamp(prices.index[-1])
close_data_hash = fingerprint_prices(prices)
# First-use governance treats every overlapping OOS date interval or repeated
# canonical OOS outcome panel as consumed. The outcome hash intentionally ignores
# relabelable dates but retains canonical asset columns and values; the complete
# date-bound close-panel hash remains separate signed evidence.
holdout_data_hash = fingerprint_holdout_outcomes(prices.iloc[preview_split:])
execution_data_hash = (
    fingerprint_prices(execution_prices) if execution_prices is not None else ""
)
factor_data_hash = fingerprint_prices(factor_returns) if factor_returns is not None else ""
execution_window_dollar_volume_hash = (
    fingerprint_prices(execution_window_dollar_volume)
    if execution_window_dollar_volume is not None
    else ""
)
corporate_action_data_hash = (
    fingerprint_config(
        {
            "split_ratio": fingerprint_prices(corporate_actions.split_ratio),
            "cash_distribution": fingerprint_prices(
                corporate_actions.cash_distribution
            ),
            "as_of_timestamp": fingerprint_prices(
                corporate_actions.as_of_timestamp
            ),
        }
    )
    if corporate_actions is not None
    else ""
)
borrow_data_hash = (
    fingerprint_config(
        {
            "availability": fingerprint_prices(borrow_data.availability),
            "annual_rate": fingerprint_prices(borrow_data.annual_rate),
            "recall": fingerprint_prices(borrow_data.recall),
            "as_of_timestamp": fingerprint_prices(borrow_data.as_of_timestamp),
        }
    )
    if borrow_data is not None
    else ""
)
exchange_calendar_frame = (
    pd.DataFrame({"is_session": 1}, index=exchange_calendar)
    if exchange_calendar is not None
    else None
)
exchange_calendar_hash = (
    fingerprint_prices(exchange_calendar_frame)
    if exchange_calendar_frame is not None
    else ""
)
data_hash = fingerprint_config(
    {
        "close_prices": close_data_hash,
        "execution_prices": execution_data_hash,
        "factor_returns": factor_data_hash,
        "execution_window_dollar_volume": execution_window_dollar_volume_hash,
        "corporate_actions": corporate_action_data_hash,
        "point_in_time_borrow": borrow_data_hash,
        "exchange_session_calendar": exchange_calendar_hash,
    }
)
planned_effective_trials = (
    PARAMETER_PERTURBATION_VARIANT_COUNT if run_perturbations else 1
)
project_root = Path(__file__).resolve().parent
research_source_files = [project_root / "app.py", project_root / "requirements.lock"]
research_source_files.extend(sorted((project_root / "quant_app").glob("*.py")))
research_source_snapshot = {
    path.relative_to(project_root).as_posix(): path.read_bytes()
    for path in research_source_files
}
research_software_hash = fingerprint_config(
    {
        relative_name: sha256_bytes(source_bytes)
        for relative_name, source_bytes in research_source_snapshot.items()
    }
)
runtime_identity = research_runtime_identity()
research_specification = {
    "governance_version": 13,
    "research_software_sha256": research_software_hash,
    "runtime_identity": runtime_identity,
    "holdout_identity": {
        "policy": CLOSE_HOLDOUT_IDENTITY_VERSION,
        "dataframe_fingerprint": DATAFRAME_FINGERPRINT_VERSION,
        "oos_outcomes_sha256": holdout_data_hash,
        "close_panel_sha256": close_data_hash,
        "oos_start": preview_oos_start.isoformat(),
        "oos_end": preview_oos_end.isoformat(),
        "scope": "any_overlapping_oos_date_interval_or_repeated_outcomes",
    },
    "strategy": config.to_dict(),
    "validation": {
        "target_cagr": target_cagr,
        "target_max_drawdown": target_max_dd,
        "required_confidence": confidence,
        "in_sample_fraction": in_sample_fraction,
        "bootstrap_paths": bootstrap_paths,
        "bootstrap_horizon_years": bootstrap_years,
        "bootstrap_block_size_days": block_size,
        "parameter_perturbations_enabled": run_perturbations,
        "parameter_perturbation_family_id": (
            PARAMETER_PERTURBATION_FAMILY_ID if run_perturbations else ""
        ),
        "parameter_perturbation_variant_count": (
            PARAMETER_PERTURBATION_VARIANT_COUNT if run_perturbations else 0
        ),
        "parameter_perturbation_specification_sha256": (
            perturbation_specification_sha256 if run_perturbations else ""
        ),
        "parameter_perturbation_minimum_pass_rate": MIN_PERTURBATION_PASS_RATE,
        "parameter_perturbation_minimum_passing_variants": int(
            np.ceil(
                PARAMETER_PERTURBATION_VARIANT_COUNT
                * MIN_PERTURBATION_PASS_RATE
            )
        ),
        "parameter_perturbation_minimum_target_cagr_retention": (
            MIN_PERTURBATION_CAGR_TARGET_RETENTION
        ),
        "parameter_perturbation_minimum_sharpe": MIN_PERTURBATION_SHARPE,
        "parameter_perturbation_minimum_universe_retention": (
            MIN_PERTURBATION_UNIVERSE_RETENTION
        ),
        "execution_return_semantics": (
            SEALED_RETURN_INTERVAL if execution_prices is not None else "next_close_proxy"
        ),
        "execution_interval_timezone": SEALED_INTERVAL_TIMEZONE,
        "execution_price_row_label": (
            SEALED_EXECUTION_PRICE_ROW_LABEL if execution_prices is not None else ""
        ),
        "strategy_return_row_label": (
            SEALED_RETURN_ROW_LABEL if execution_prices is not None else ""
        ),
        "execution_price_definition": (
            SEALED_EXECUTION_PRICE_DEFINITION if execution_prices is not None else ""
        ),
        "decision_information_cutoff": (
            SEALED_DECISION_INFORMATION_CUTOFF if execution_prices is not None else ""
        ),
        "factor_return_interval": (
            SEALED_RETURN_INTERVAL if factor_returns is not None else ""
        ),
        "factor_return_row_label": (
            SEALED_RETURN_ROW_LABEL if factor_returns is not None else ""
        ),
        "factor_columns": (
            [str(column) for column in factor_returns.columns]
            if factor_returns is not None
            else []
        ),
        "liquidity_model": "causal_lagged_execution_window_volume_square_root_impact",
        "execution_liquidity_window": SEALED_LIQUIDITY_WINDOW,
        "execution_liquidity_definition": SEALED_LIQUIDITY_DEFINITION,
        "execution_window_dollar_volume_supplied": (
            execution_window_dollar_volume is not None
        ),
        "corporate_action_split_definition": (
            SEALED_CORPORATE_ACTION_SPLIT_DEFINITION
        ),
        "corporate_action_cash_definition": (
            SEALED_CORPORATE_ACTION_CASH_DEFINITION
        ),
        "corporate_action_as_of_cutoff": SEALED_CORPORATE_ACTION_AS_OF_CUTOFF,
        "corporate_action_data_supplied": corporate_actions is not None,
        "borrow_as_of_cutoff": SEALED_BORROW_AS_OF_CUTOFF,
        "borrow_rate_definition": SEALED_BORROW_RATE_DEFINITION,
        "point_in_time_borrow_data_supplied": borrow_data is not None,
        "exchange_calendar_required": research_mode == "sealed_final",
        "exchange_calendar_sha256": exchange_calendar_hash,
        "exchange_calendar_exact_match": exchange_calendar_exact_match,
    },
}
config_hash = fingerprint_config(research_specification)

registry_path_setting = os.environ.get("RESEARCH_GOVERNANCE_PUBLIC_KEYS_PATH", "").strip()
registry_path: Path | None = None
if registry_path_setting:
    registry_path = Path(registry_path_setting).expanduser()
    if not registry_path.is_absolute():
        registry_path = Path(__file__).resolve().parent / registry_path
trusted_registry = load_trusted_key_registry(
    registry_path,
    os.environ.get("RESEARCH_GOVERNANCE_PUBLIC_KEYS_SHA256"),
)
ledger_preclaim_state = ledger.preclaim_state()
if research_mode == "sealed_final":
    with st.expander("Exact research-ledger fields required in manifest v7", expanded=False):
        st.json(
            {
                "research_ledger_id": ledger_preclaim_state.ledger_id,
                "research_ledger_preclaim_sequence": (
                    ledger_preclaim_state.attempt_sequence
                ),
                "research_ledger_preclaim_head_sha256": (
                    ledger_preclaim_state.attempt_head_hash
                ),
                "research_ledger_prior_effective_trials": (
                    ledger_preclaim_state.total_planned_trials
                ),
                "planned_effective_trials": planned_effective_trials,
            }
        )
manifest_verification = verify_sealed_manifest(
    manifest_bytes,
    anchor_receipt_bytes,
    trusted_registry,
    expected_close_data_hash=close_data_hash,
    expected_execution_data_hash=execution_data_hash,
    expected_factor_data_hash=factor_data_hash,
    expected_execution_window_dollar_volume_hash=(
        execution_window_dollar_volume_hash
    ),
    expected_corporate_action_data_hash=corporate_action_data_hash,
    expected_borrow_data_hash=borrow_data_hash,
    expected_exchange_calendar_hash=exchange_calendar_hash,
    available_factor_columns=(
        tuple(str(column) for column in factor_returns.columns)
        if factor_returns is not None
        else ()
    ),
    expected_combined_data_hash=data_hash,
    expected_oos_start=preview_oos_start.isoformat(),
    expected_specification_hash=config_hash,
    expected_research_software_hash=research_software_hash,
    expected_research_ledger_id=ledger_preclaim_state.ledger_id,
    expected_research_ledger_preclaim_sequence=(
        ledger_preclaim_state.attempt_sequence
    ),
    expected_research_ledger_preclaim_head_hash=(
        ledger_preclaim_state.attempt_head_hash
    ),
    expected_research_ledger_prior_effective_trials=(
        ledger_preclaim_state.total_planned_trials
    ),
    expected_planned_effective_trials=planned_effective_trials,
)
current_context_hash = certification_context_hash(
    {
        "data_hash": data_hash,
        "holdout_data_hash": holdout_data_hash,
        "config_hash": config_hash,
        "source": source,
        "research_mode": research_mode,
        "sealed_ack": bool(sealed_ack),
        "point_in_time_ack": bool(point_in_time_ack),
        "execution_cost_ack": bool(execution_cost_ack),
        "factor_data_ack": bool(factor_data_ack),
        "dollar_volume_ack": bool(dollar_volume_ack),
        "corporate_action_ack": bool(corporate_action_ack),
        "borrow_data_ack": bool(borrow_data_ack),
        "exchange_calendar_ack": bool(exchange_calendar_ack),
        "manifest_input_hash": sha256_bytes(manifest_bytes or b""),
        "anchor_receipt_hash": sha256_bytes(anchor_receipt_bytes or b""),
        "trusted_registry_hash": trusted_registry.registry_hash,
        "trusted_registry_valid": trusted_registry.valid,
        "manifest_verified": manifest_verification.verified,
        "manifest_errors": manifest_verification.errors,
        "research_software_hash": research_software_hash,
        "research_ledger_id": ledger_preclaim_state.ledger_id,
        "research_ledger_preclaim_sequence": ledger_preclaim_state.attempt_sequence,
        "research_ledger_preclaim_head_hash": ledger_preclaim_state.attempt_head_hash,
        "research_ledger_prior_effective_trials": (
            ledger_preclaim_state.total_planned_trials
        ),
        "planned_effective_trials": planned_effective_trials,
    }
)
current_ledger_state_hash = ledger.governance_state_fingerprint()

existing_payload = st.session_state.get("research_payload")
if existing_payload is not None and not certification_payload_is_current(
    existing_payload,
    context_hash=current_context_hash,
    ledger_state_hash=current_ledger_state_hash,
):
    del st.session_state["research_payload"]
    st.warning(
        "The prior result was invalidated because research inputs or the persistent "
        "governance ledger changed. Submit a new run; no stale certification is displayed."
    )
    if not submitted:
        st.stop()

st.subheader("Data quality")
quality_summary(data_report)
if data_report.missing_fraction_before_fill > 0.05:
    st.warning(
        f"The input is {data_report.missing_fraction_before_fill:.1%} missing; gaps remain unfilled. "
        "Review universe membership and listing dates before relying on results."
    )

if not submitted and "research_payload" not in st.session_state:
    st.info("Configure the strategy in the sidebar, then run the research backtest.")
    st.stop()

if submitted:
    if research_mode == "sealed_final" and source == "Synthetic demonstration":
        st.error("Synthetic data can never be used for sealed validation.")
        st.stop()
    if research_mode == "sealed_final" and not sealed_ack:
        st.error("Freeze the specification and confirm it before consuming the sealed holdout.")
        st.stop()
    if research_mode == "sealed_final" and not manifest_verification.verified:
        st.error(
            "Sealed validation is unavailable because trusted preregistration verification "
            "failed: " + " | ".join(manifest_verification.errors)
        )
        st.stop()

    if research_mode == "sealed_final":
        # Verification above guarantees these signed identities are present and valid.
        assert manifest_verification.experiment_id is not None
        assert manifest_verification.data_family_id is not None
        assert manifest_verification.strategy_family_id is not None
        assert manifest_verification.research_ledger_id is not None
        assert manifest_verification.research_ledger_preclaim_sequence is not None
        assert manifest_verification.research_ledger_preclaim_head_hash is not None
        assert manifest_verification.research_ledger_prior_effective_trials is not None
        assert manifest_verification.planned_effective_trials is not None
        claim = ledger.claim_governed_holdout(
            holdout_data_hash=holdout_data_hash,
            oos_start=preview_oos_start.isoformat(),
            oos_end=preview_oos_end.isoformat(),
            config_hash=config_hash,
            mode=research_mode,
            planned_effective_trials=planned_effective_trials,
            manifest_hash=manifest_verification.manifest_hash,
            experiment_id=manifest_verification.experiment_id,
            data_family_id=manifest_verification.data_family_id,
            strategy_family_id=manifest_verification.strategy_family_id,
            overlap_group_ids=manifest_verification.overlap_group_ids,
            expected_ledger_id=manifest_verification.research_ledger_id,
            expected_preclaim_sequence=(
                manifest_verification.research_ledger_preclaim_sequence
            ),
            expected_preclaim_head_hash=(
                manifest_verification.research_ledger_preclaim_head_hash
            ),
            expected_prior_trials=(
                manifest_verification.research_ledger_prior_effective_trials
            ),
        )
    else:
        claim = ledger.claim_holdout(
            holdout_data_hash=holdout_data_hash,
            oos_start=preview_oos_start.isoformat(),
            oos_end=preview_oos_end.isoformat(),
            config_hash=config_hash,
            mode=research_mode,
            planned_effective_trials=planned_effective_trials,
        )
    governance_first_use = bool(getattr(claim, "governance_first_use", False))
    sealed_eligible = bool(
        research_mode == "sealed_final"
        and source == "Upload adjusted-close CSV"
        and sealed_ack
        and point_in_time_ack
        and execution_cost_ack
        and factor_data_ack
        and dollar_volume_ack
        and corporate_action_ack
        and borrow_data_ack
        and exchange_calendar_ack
        and execution_prices is not None
        and factor_returns is not None
        and execution_window_dollar_volume is not None
        and corporate_actions is not None
        and borrow_data is not None
        and exchange_calendar is not None
        and exchange_calendar_exact_match
        and factor_calendar_exact_match
        and config.portfolio.rebalance_every == 1
        and manifest_verification.verified
        and claim.holdout_identity_current
        and claim.first_use
        and governance_first_use
    )
    # Count the configured model plus a conservative allowance for the perturbation
    # family; under-counting researcher degrees of freedom would inflate Sharpe evidence.
    statistical_trial_count = claim.reserved_total_trials

    with st.spinner("Running causal backtest and stress validation…"):
        try:
            result = cached_backtest(
                prices,
                config,
                research_software_hash,
                execution_prices,
                execution_window_dollar_volume,
                corporate_actions,
                borrow_data,
            )
        except (ArithmeticError, ValueError) as exc:
            halt_consumed_research_run("price/liquidity alignment and base backtest", exc)
        split = split_index(result.strategy_returns.index, in_sample_fraction)
        oos_index = result.strategy_returns.index[split:]
        oos_start = oos_index[0]

        full_metrics = metrics_from_returns(result.strategy_returns, result.diagnostics)
        oos_metrics = metrics_from_returns(
            result.strategy_returns.reindex(oos_index),
            result.diagnostics.reindex(oos_index),
        )

        try:
            stressed_result = cached_backtest(
                prices,
                doubled_cost_config(config),
                research_software_hash,
                execution_prices,
                execution_window_dollar_volume,
                corporate_actions,
                borrow_data,
                borrow_rate_stress_multiplier=2.0,
            )
        except (ArithmeticError, ValueError) as exc:
            halt_consumed_research_run("double-cost liquidity stress", exc)
        double_cost_metrics = metrics_from_returns(
            stressed_result.strategy_returns.reindex(oos_index),
            stressed_result.diagnostics.reindex(oos_index),
        )

        oos_returns = result.strategy_returns.reindex(oos_index).dropna()
        if research_mode == "sealed_final":
            assert factor_returns is not None
            assert manifest_verification.market_factor_column is not None
            attribution_factors = factor_returns.reindex(oos_index)
            market_factor_column = manifest_verification.market_factor_column
        else:
            reference_prices = (
                execution_prices
                if execution_prices is not None
                else (
                    result.observed_prices
                    if result.observed_prices is not None
                    else result.prices
                )
            )
            reference_returns = (
                reference_prices.pct_change(fill_method=None)
                .mean(axis=1, skipna=True)
                .rename("equal_weight_market")
            )
            attribution_factors = reference_returns.to_frame().reindex(oos_index)
            market_factor_column = "equal_weight_market"
        try:
            attribution = factor_regression(oos_returns, attribution_factors)
        except (ArithmeticError, ValueError) as exc:
            halt_consumed_research_run("factor-data alignment and attribution", exc)
        return_only_bootstrap, return_only_bootstrap_error = bootstrap_or_nan(
            returns=oos_returns,
            n_paths=bootstrap_paths,
            horizon_days=bootstrap_years * 252,
            block_size=block_size,
            target_cagr=target_cagr,
            max_drawdown=target_max_dd,
        )
        path_bootstrap = unavailable_path_bootstrap(
            horizon_days=bootstrap_years * 252,
            block_size=block_size,
        )
        path_bootstrap_error: str | None = (
            "Path-aware state-machine bootstrap is reserved for sealed validation."
        )
        if research_mode == "sealed_final":
            if (
                execution_prices is None
                or execution_window_dollar_volume is None
                or corporate_actions is None
                or borrow_data is None
            ):
                path_bootstrap_error = (
                    "Path-aware bootstrap requires aligned execution prices, "
                    "window volume, corporate actions, and borrow evidence."
                )
            else:
                try:
                    path_bootstrap = cached_path_aware_bootstrap(
                        prices,
                        config,
                        in_sample_fraction,
                        bootstrap_years * 252,
                        block_size,
                        target_cagr,
                        target_max_dd,
                        research_software_hash,
                        execution_prices,
                        execution_window_dollar_volume,
                        corporate_actions,
                        borrow_data,
                    )
                    path_bootstrap_error = None
                except (ArithmeticError, ValueError) as exc:
                    path_bootstrap_error = str(exc)
        # ``bootstrap`` remains the compact payload/display name, but it now always
        # denotes the path-aware hard-gate evidence.  Return-only resampling is kept
        # separately and never enters ``certification_table``.
        bootstrap = path_bootstrap
        bootstrap_error = path_bootstrap_error
        rolling_pass, rolling_table = rolling_target_pass_rate(
            oos_returns,
            target_cagr=target_cagr,
            max_drawdown=target_max_dd,
        )
        sharpe_diagnostics = sharpe_probability_diagnostics(
            oos_returns,
            trial_count=max(statistical_trial_count, 1),
        )
        psr = sharpe_diagnostics.probability
        def model_consumed(column: str) -> bool:
            return bool(
                column in result.diagnostics
                and column in stressed_result.diagnostics
                and result.diagnostics[column].fillna(False).astype(bool).all()
                and stressed_result.diagnostics[column].fillna(False).astype(bool).all()
            )

        corporate_action_model_consumed = model_consumed(
            "corporate_action_model_active"
        )
        execution_window_liquidity_model_consumed = model_consumed(
            "execution_window_liquidity_model_active"
        )
        point_in_time_borrow_model_consumed = model_consumed(
            "point_in_time_borrow_model_active"
        )
        point_in_time_borrow_model_consumed = (
            point_in_time_borrow_model_consumed
            and "borrow_rate_stress_multiplier" in stressed_result.diagnostics
            and stressed_result.diagnostics[
                "borrow_rate_stress_multiplier"
            ].ge(2.0).all()
        )
        base_certified, certification = certification_table(
            oos_metrics=oos_metrics,
            bootstrap=bootstrap,
            double_cost_metrics=double_cost_metrics,
            rolling_pass_rate=rolling_pass,
            psr_probability=psr,
            max_gross_limit=max_gross,
            target_cagr=target_cagr,
            max_drawdown=target_max_dd,
            confidence=confidence,
            trial_count=max(statistical_trial_count, 1),
            bootstrap_block_size=block_size,
            corporate_action_model_consumed=corporate_action_model_consumed,
            execution_window_liquidity_model_consumed=(
                execution_window_liquidity_model_consumed
            ),
            point_in_time_borrow_model_consumed=(
                point_in_time_borrow_model_consumed
            ),
            rebalance_every=config.portfolio.rebalance_every,
        )

        oos_elapsed_years = (
            (pd.Timestamp(oos_returns.index[-1]) - pd.Timestamp(oos_returns.index[0])).days
            / 365.2425
            if len(oos_returns) >= 2
            else 0.0
        )
        factor_missing_fraction = float(attribution_factors.isna().mean().mean())
        factor_count = int(attribution_factors.shape[1])
        factor_observation_rate = float("nan")
        if factor_returns is not None and len(factor_returns.index) >= 2:
            factor_elapsed_years = (
                (
                    pd.Timestamp(factor_returns.index[-1])
                    - pd.Timestamp(factor_returns.index[0])
                ).days
                / 365.2425
            )
            if factor_elapsed_years > 0.0:
                factor_observation_rate = (len(factor_returns.index) - 1) / factor_elapsed_years
        market_beta = float(attribution.factor_betas.get(market_factor_column, float("nan")))
        governance_rows = pd.DataFrame(
            [
                ("Sealed first-use real-data holdout", sealed_eligible, "Yes", sealed_eligible),
                (
                    "Trusted signed preregistration manifest",
                    bool(manifest_verification.verified),
                    "Yes",
                    bool(manifest_verification.verified),
                ),
                (
                    "First-use experiment/data/overlap families",
                    governance_first_use,
                    "Yes",
                    governance_first_use,
                ),
                (
                    "Current close-holdout identity policy",
                    bool(claim.holdout_identity_current),
                    f"= {CLOSE_HOLDOUT_IDENTITY_VERSION}",
                    bool(claim.holdout_identity_current),
                ),
                ("Point-in-time data attestation", bool(point_in_time_ack), "Yes", bool(point_in_time_ack)),
                (
                    "Measured execution-cost attestation",
                    bool(execution_cost_ack),
                    "Yes",
                    bool(execution_cost_ack),
                ),
                (
                    "Point-in-time factor-data attestation",
                    bool(factor_data_ack),
                    "Yes",
                    bool(factor_data_ack),
                ),
                (
                    "Execution-window dollar-notional liquidity-data attestation",
                    bool(dollar_volume_ack),
                    "Yes",
                    bool(dollar_volume_ack),
                ),
                (
                    "Point-in-time corporate-action attestation",
                    bool(corporate_action_ack),
                    "Yes",
                    bool(corporate_action_ack),
                ),
                (
                    "Point-in-time borrow-data attestation",
                    bool(borrow_data_ack),
                    "Yes",
                    bool(borrow_data_ack),
                ),
                (
                    "Complete aligned corporate-action panel",
                    corporate_actions is not None,
                    "Yes; split/share and cash distribution",
                    bool(corporate_actions is not None),
                ),
                (
                    "Complete aligned security/date borrow panel",
                    borrow_data is not None,
                    "Yes; availability, rate, recall",
                    bool(borrow_data is not None),
                ),
                (
                    "Authoritative signed exchange-session calendar",
                    bool(
                        exchange_calendar_ack
                        and exchange_calendar is not None
                        and exchange_calendar_exact_match
                        and factor_calendar_exact_match
                    ),
                    "Yes; exact dates for all signed market/economic inputs",
                    bool(
                        exchange_calendar_ack
                        and exchange_calendar is not None
                        and exchange_calendar_exact_match
                        and factor_calendar_exact_match
                    ),
                ),
                (
                    "Aligned execution-price history",
                    execution_prices is not None,
                    "Yes",
                    execution_prices is not None,
                ),
                ("Out-of-sample observations", int(len(oos_returns)), ">= 756", len(oos_returns) >= 756),
                (
                    "Out-of-sample elapsed calendar years",
                    float(oos_elapsed_years),
                    ">= 3.0",
                    oos_elapsed_years >= 3.0,
                ),
                ("Asset count", int(prices.shape[1]), ">= 20", prices.shape[1] >= 20),
                (
                    "Input annualized observation rate",
                    float(data_report.annualized_observation_rate),
                    (
                        f"{MIN_CERTIFIED_DAILY_OBSERVATION_RATE:.0f}-"
                        f"{MAX_CERTIFIED_DAILY_OBSERVATION_RATE:.0f}/year"
                    ),
                    sealed_daily_observation_rate_is_valid(
                        data_report.annualized_observation_rate
                    ),
                ),
                (
                    "Input missing fraction",
                    float(data_report.missing_fraction_before_fill),
                    "<= 1%",
                    data_report.missing_fraction_before_fill <= 0.01,
                ),
                (
                    "Execution-price missing fraction",
                    (
                        float(execution_prices.isna().mean().mean())
                        if execution_prices is not None
                        else 1.0
                    ),
                    "<= 1%",
                    bool(
                        execution_prices is not None
                        and execution_prices.isna().mean().mean() <= 0.01
                    ),
                ),
                (
                    "Execution-price annualized observation rate",
                    (
                        float(execution_data_report.annualized_observation_rate)
                        if execution_data_report is not None
                        else float("nan")
                    ),
                    (
                        f"{MIN_CERTIFIED_DAILY_OBSERVATION_RATE:.0f}-"
                        f"{MAX_CERTIFIED_DAILY_OBSERVATION_RATE:.0f}/year"
                    ),
                    bool(
                        execution_data_report is not None
                        and sealed_daily_observation_rate_is_valid(
                            execution_data_report.annualized_observation_rate
                        )
                    ),
                ),
                (
                    "Aligned 09:30-09:35 dollar-volume history",
                    execution_window_dollar_volume is not None,
                    "Yes",
                    execution_window_dollar_volume is not None,
                ),
                (
                    "Dollar-volume annualized observation rate",
                    (
                        float(dollar_volume_report.annualized_observation_rate)
                        if dollar_volume_report is not None
                        else float("nan")
                    ),
                    (
                        f"{MIN_CERTIFIED_DAILY_OBSERVATION_RATE:.0f}-"
                        f"{MAX_CERTIFIED_DAILY_OBSERVATION_RATE:.0f}/year"
                    ),
                    bool(
                        dollar_volume_report is not None
                        and sealed_daily_observation_rate_is_valid(
                            dollar_volume_report.annualized_observation_rate
                        )
                    ),
                ),
                (
                    "Dollar-volume missing fraction",
                    (
                        float(dollar_volume_report.missing_fraction_before_fill)
                        if dollar_volume_report is not None
                        else 1.0
                    ),
                    "<= 1%",
                    bool(
                        dollar_volume_report is not None
                        and dollar_volume_report.missing_fraction_before_fill <= 0.01
                    ),
                ),
                (
                    "Named point-in-time factor count",
                    factor_count,
                    ">= 2",
                    factor_count >= 2,
                ),
                (
                    "Factor-return missing fraction",
                    factor_missing_fraction,
                    "<= 1%",
                    factor_missing_fraction <= 0.01,
                ),
                (
                    "Factor-return annualized observation rate",
                    factor_observation_rate,
                    (
                        f"{MIN_CERTIFIED_DAILY_OBSERVATION_RATE:.0f}-"
                        f"{MAX_CERTIFIED_DAILY_OBSERVATION_RATE:.0f}/year"
                    ),
                    bool(
                        sealed_daily_observation_rate_is_valid(
                            factor_observation_rate
                        )
                    ),
                ),
                (
                    "Path-aware state-machine bootstrap paths",
                    int(path_bootstrap.paths),
                    f"= {PATH_AWARE_BOOTSTRAP_PATHS:,} fixed paths",
                    bool(
                        path_bootstrap.paths == PATH_AWARE_BOOTSTRAP_PATHS
                        and path_bootstrap.state_machine_rerun
                        and path_bootstrap.failed_paths == 0
                    ),
                ),
                (
                    "Path-aware bootstrap horizon years",
                    int(path_bootstrap.horizon_days // 252),
                    ">= 3",
                    path_bootstrap.horizon_days >= 3 * 252,
                ),
                ("Required evidence confidence", float(confidence), ">= 95%", confidence >= 0.95),
                (
                    "Factor-adjusted annualized alpha",
                    float(attribution.annualized_alpha),
                    "> 0%",
                    attribution.annualized_alpha > 0.0,
                ),
                (
                    "Factor-adjusted alpha HAC t-stat",
                    float(attribution.alpha_tstat_hac),
                    ">= 2.0",
                    attribution.alpha_tstat_hac >= 2.0,
                ),
                (
                    "Realized market-factor beta",
                    abs(market_beta),
                    "<= 0.15",
                    bool(np.isfinite(market_beta) and abs(market_beta) <= 0.15),
                ),
                (
                    "Parameter stability suite executed",
                    bool(run_perturbations),
                    "Yes",
                    bool(run_perturbations),
                ),
            ],
            columns=["Test", "Observed", "Requirement", "Pass"],
        ).set_index("Test")
        certification = pd.concat([certification, governance_rows])
        certified = bool(base_certified and governance_rows["Pass"].all())

        if run_perturbations:
            try:
                perturbations = cached_perturbations(
                    prices,
                    config,
                    in_sample_fraction,
                    PARAMETER_PERTURBATION_FAMILY_ID,
                    perturbation_specification_sha256,
                    research_software_hash,
                    execution_prices,
                    execution_window_dollar_volume,
                    corporate_actions,
                    borrow_data,
                )
            except (ArithmeticError, ValueError) as exc:
                halt_consumed_research_run(
                    "parameter-perturbation price/liquidity alignment",
                    exc,
                )
        else:
            perturbations = pd.DataFrame()
        if run_perturbations:
            (
                perturbation_gate_passed,
                perturbation_pass_rate,
                stable_variants,
            ) = parameter_perturbation_gate(
                perturbations,
                config,
                max_drawdown=target_max_dd,
                prices=prices,
                in_sample_fraction=in_sample_fraction,
                target_cagr=target_cagr,
                execution_return_semantics=(
                    "next_open_to_open"
                    if execution_prices is not None
                    else "next_close_proxy"
                ),
                execution_prices=execution_prices,
                execution_window_dollar_volume=execution_window_dollar_volume,
                corporate_action_split_ratios=(
                    corporate_actions.split_ratio
                    if corporate_actions is not None
                    else None
                ),
                corporate_action_cash_distributions=(
                    corporate_actions.cash_distribution
                    if corporate_actions is not None
                    else None
                ),
                borrow_availability=(
                    borrow_data.availability if borrow_data is not None else None
                ),
                annual_borrow_rates=(
                    borrow_data.annual_rate if borrow_data is not None else None
                ),
                borrow_recalls=(borrow_data.recall if borrow_data is not None else None),
            )
        else:
            perturbation_gate_passed = False
            perturbation_pass_rate = float("nan")
            stable_variants = pd.Series(False, index=perturbations.index, dtype=bool)
        if not perturbations.empty:
            perturbations = perturbations.copy()
            perturbations["Pass"] = stable_variants.reindex(
                perturbations.index, fill_value=False
            )
        certification.loc["Parameter perturbation pass rate"] = [
            perturbation_pass_rate,
            (
                f">= {MIN_PERTURBATION_PASS_RATE:.0%} of the exact signed 25-member "
                "suite; each variant retains >= "
                f"{MIN_PERTURBATION_CAGR_TARGET_RETENTION:.0%} of the >=60% CAGR "
                f"target, Sharpe >= {MIN_PERTURBATION_SHARPE:.1f}, and retains "
                f">= {MIN_PERTURBATION_UNIVERSE_RETENTION:.0%} of base breadth"
            ),
            perturbation_gate_passed,
        ]
        certified = bool(certified and perturbation_gate_passed)

        trial_count = statistical_trial_count
        trial_result = {
            "oos_metrics": oos_metrics,
            "base_gate_passed": base_certified,
            "final_gate_passed": certified,
            "statistical_trial_count": statistical_trial_count,
            "planned_effective_trials": planned_effective_trials,
            "parameter_perturbation_family_id": (
                PARAMETER_PERTURBATION_FAMILY_ID if run_perturbations else ""
            ),
            "parameter_perturbation_variant_count": (
                PARAMETER_PERTURBATION_VARIANT_COUNT if run_perturbations else 0
            ),
            "parameter_perturbation_executed_variant_count": int(len(perturbations)),
            "parameter_perturbation_passed_variant_count": int(stable_variants.sum()),
            "parameter_perturbation_pass_rate": perturbation_pass_rate,
            "parameter_perturbation_specification_sha256": (
                perturbation_specification_sha256 if run_perturbations else ""
            ),
            "manifest_hash": manifest_verification.manifest_hash,
            "holdout_data_hash": holdout_data_hash,
            "holdout_identity_policy": CLOSE_HOLDOUT_IDENTITY_VERSION,
            "holdout_oos_end": preview_oos_end.isoformat(),
            "holdout_identity_current": claim.holdout_identity_current,
            "governance_first_use": governance_first_use,
            "research_ledger_id": claim.ledger_id,
            "research_ledger_attempt_sequence": claim.postclaim_sequence,
            "research_ledger_attempt_head_sha256": claim.postclaim_head_hash,
        }
        trial_source = (
            "synthetic" if source == "Synthetic demonstration" else "uploaded"
        )
        if research_mode == "sealed_final":
            try:
                finalization = ledger.finalize_governed_trial(
                    claim=claim,
                    data_hash=data_hash,
                    config_hash=config_hash,
                    source=trial_source,
                    mode=research_mode,
                    in_sample_fraction=in_sample_fraction,
                    oos_start=oos_start.isoformat(),
                    eligible_for_sealed_gate=sealed_eligible,
                    gate_passed=certified,
                    result=trial_result,
                )
            except (RuntimeError, TypeError, ValueError) as exc:
                halt_consumed_research_run(
                    "atomic research-ledger finalization", exc
                )
            trial_id = finalization.trial_id
            final_ledger_snapshot = finalization.ledger_snapshot
            final_ledger_state_hash = finalization.ledger_state_hash
        else:
            trial_id = ledger.record_trial(
                data_hash=data_hash,
                config_hash=config_hash,
                source=trial_source,
                mode=research_mode,
                in_sample_fraction=in_sample_fraction,
                oos_start=oos_start.isoformat(),
                first_holdout_use=claim.first_use,
                eligible_for_sealed_gate=sealed_eligible,
                gate_passed=certified,
                result=trial_result,
            )
            final_ledger_snapshot = ledger.governance_state_snapshot_bytes()
            final_ledger_state_hash = sha256_bytes(final_ledger_snapshot)
        payload = {
            "trial_id": trial_id,
            "trial_count": trial_count,
            "statistical_trial_count": statistical_trial_count,
            "research_mode": research_mode,
            "first_holdout_use": claim.first_use,
            "governance_first_use": governance_first_use,
            "sealed_eligible": sealed_eligible,
            "data_hash": data_hash,
            "holdout_data_hash": holdout_data_hash,
            "holdout_identity_policy": CLOSE_HOLDOUT_IDENTITY_VERSION,
            "holdout_oos_end": preview_oos_end.isoformat(),
            "holdout_identity_current": claim.holdout_identity_current,
            "close_data_hash": close_data_hash,
            "execution_data_hash": execution_data_hash,
            "factor_data_hash": factor_data_hash,
            "config_hash": config_hash,
            "research_specification": research_specification,
            "data_report": data_report,
            "execution_prices": execution_prices,
            "execution_data_report": execution_data_report,
            "execution_window_dollar_volume": execution_window_dollar_volume,
            "dollar_volume_report": dollar_volume_report,
            "execution_window_dollar_volume_hash": (
                execution_window_dollar_volume_hash
            ),
            "corporate_actions": corporate_actions,
            "corporate_action_data_hash": corporate_action_data_hash,
            "borrow_data": borrow_data,
            "borrow_data_hash": borrow_data_hash,
            "exchange_calendar": exchange_calendar_frame,
            "exchange_calendar_hash": exchange_calendar_hash,
            "factor_returns": factor_returns,
            "market_factor_column": market_factor_column,
            "manifest_hash": manifest_verification.manifest_hash,
            "manifest_key_id": manifest_verification.key_id,
            "manifest_payload": manifest_verification.payload,
            "manifest_envelope": manifest_verification.envelope,
            "manifest_bytes": manifest_bytes,
            "anchor_receipt_bytes": anchor_receipt_bytes,
            "anchor_receipt_hash": manifest_verification.anchor_receipt_hash,
            "trusted_registry_hash": manifest_verification.registry_hash,
            "research_software_hash": research_software_hash,
            "runtime_identity": runtime_identity,
            "certification_context_hash": current_context_hash,
            "ledger_state_hash": final_ledger_state_hash,
            "ledger_snapshot_bytes": final_ledger_snapshot,
            "trusted_registry_bytes": trusted_registry.raw_bytes,
            "research_source_snapshot": research_source_snapshot,
            "result": result,
            "stressed_result": stressed_result,
            "full_metrics": full_metrics,
            "oos_metrics": oos_metrics,
            "double_cost_metrics": double_cost_metrics,
            "bootstrap": bootstrap,
            "bootstrap_error": bootstrap_error,
            "path_bootstrap": path_bootstrap,
            "path_bootstrap_error": path_bootstrap_error,
            "return_only_bootstrap": return_only_bootstrap,
            "return_only_bootstrap_error": return_only_bootstrap_error,
            "rolling_pass": rolling_pass,
            "rolling_table": rolling_table,
            "psr": psr,
            "sharpe_diagnostics": sharpe_diagnostics,
            "attribution": attribution,
            "certified": certified,
            "certification": certification,
            "perturbations": perturbations,
            "perturbation_pass_rate": perturbation_pass_rate,
            "perturbation_gate_passed": perturbation_gate_passed,
            "perturbation_passed_variant_count": int(stable_variants.sum()),
            "perturbation_specification_sha256": (
                perturbation_specification_sha256
                if run_perturbations
                else ""
            ),
            "oos_start": oos_start,
            "target_cagr": target_cagr,
            "target_max_dd": target_max_dd,
            "confidence": confidence,
            "source": source,
        }
        st.session_state["research_payload"] = payload

payload = st.session_state["research_payload"]
result: BacktestResult = payload["result"]
full_metrics = payload["full_metrics"]
oos_metrics = payload["oos_metrics"]
double_cost_metrics = payload["double_cost_metrics"]
bootstrap: BootstrapSummary = payload["bootstrap"]
return_only_bootstrap: BootstrapSummary = payload["return_only_bootstrap"]
certification: pd.DataFrame = payload["certification"]
certified: bool = payload["certified"]
oos_start = pd.Timestamp(payload["oos_start"])
data_report = payload.get("data_report", data_report)
execution_prices = payload.get("execution_prices")
execution_data_report = payload.get("execution_data_report")
execution_window_dollar_volume = payload.get("execution_window_dollar_volume")
dollar_volume_report = payload.get("dollar_volume_report")
corporate_actions = payload.get("corporate_actions")
borrow_data = payload.get("borrow_data")

if int(payload.get("trial_count", 1)) > 1:
    st.warning(
        f"The persistent ledger has recorded {int(payload['trial_count'])} effective "
        "research trials, including planned perturbation variants and interrupted claims. "
        "Multiple-testing evidence is penalized accordingly."
    )

if payload.get("research_mode") == "exploratory":
    st.info(
        "Exploratory run: diagnostics are available, but certification is disabled and "
        "this holdout is now permanently recorded as viewed."
    )

if certified:
    st.success(
        "RESEARCH GATE PASSED for the configured sample and assumptions "
        f"(CAGR target >= {float(payload['target_cagr']):.0%}; maximum drawdown "
        f"<= {float(payload['target_max_dd']):.0%}; evidence confidence "
        f">= {float(payload['confidence']):.0%}). This remains hypothetical "
        "evidence—not a live-return guarantee."
    )
else:
    failed = int((~certification["Pass"]).sum())
    st.error(
        f"NOT CERTIFIED: {failed} of {len(certification)} required tests failed. "
        "The app will not label the strategy as a validated 60/15 system."
    )

overview_tab, curves_tab, controls_tab, validation_tab, data_tab, exports_tab = st.tabs(
    ["Overview", "Equity & drawdown", "Risk & regimes", "Validation", "Data audit", "Exports"]
)

with overview_tab:
    st.markdown(f"**Out-of-sample period begins:** `{oos_start.date()}`")
    st.subheader("Chronological holdout metrics")
    metric_grid(oos_metrics)

    st.subheader("Full-sample metrics")
    metric_grid(full_metrics)

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("#### Annual performance")
        yearly = annual_performance(result.strategy_returns)
        if yearly.empty:
            st.info("Not enough data for annual results.")
        else:
            st.dataframe(
                yearly.style.format(
                    {"Return": "{:.2%}", "Volatility": "{:.2%}", "Sharpe": "{:.2f}", "Max Drawdown": "{:.2%}"}
                ),
                width="stretch",
            )
    with c2:
        st.markdown("#### Regime performance")
        regimes = regime_performance(result.strategy_returns, result.diagnostics)
        if regimes.empty:
            st.info("No regime statistics available.")
        else:
            st.dataframe(
                regimes.style.format(
                    {
                        "Fraction": "{:.1%}",
                        "CAGR": "{:.2%}",
                        "Volatility": "{:.2%}",
                        "Sharpe": "{:.2f}",
                        "Max Drawdown": "{:.2%}",
                        "Average Gross": "{:.2f}x",
                    }
                ),
                width="stretch",
            )

with curves_tab:
    benchmark_prices = (
        result.observed_prices
        if result.observed_prices is not None
        else result.prices
    )
    benchmark_return = (
        benchmark_prices.pct_change(fill_method=None).mean(axis=1).fillna(0.0)
    )
    benchmark_equity = equity_from_returns(benchmark_return)
    comparison = pd.concat(
        [result.equity.rename("Strategy"), benchmark_equity.rename("Equal-weight reference")],
        axis=1,
    )
    line_chart(comparison, "Hypothetical equity curves", "Growth of 1.0")

    dd = pd.DataFrame(
        {
            "Strategy drawdown": drawdown_series(result.equity),
            "Configured flatten line": -result.config.risk.flatten_drawdown,
            "Hard breach line": -result.config.risk.hard_drawdown_limit,
        },
        index=result.equity.index,
    )
    line_chart(dd, "Drawdown and shutdown levels", "Drawdown")

    rolling = rolling_metrics(result.strategy_returns, window=252)
    c1, c2 = st.columns(2)
    with c1:
        line_chart(rolling[["Rolling Return", "Rolling Max Drawdown"]], "Rolling one-year return and drawdown", "Rate", 360)
    with c2:
        line_chart(rolling[["Rolling Volatility", "Rolling Sharpe"]], "Rolling one-year risk metrics", "Value", 360)

with controls_tab:
    exposure = result.diagnostics[["gross_exposure", "desired_gross"]].rename(
        columns={"gross_exposure": "Actual gross", "desired_gross": "Desired gross"}
    )
    line_chart(exposure, "Dynamic gross exposure", "Gross leverage")

    neutrality = result.diagnostics[["net_exposure", "beta_exposure"]].rename(
        columns={"net_exposure": "Net exposure", "beta_exposure": "Beta exposure"}
    )
    line_chart(neutrality, "Neutrality diagnostics", "Exposure")

    health = result.diagnostics[["ic_tstat", "regime_multiplier", "drawdown_multiplier", "loss_shock_multiplier"]].rename(
        columns={
            "ic_tstat": "Rolling IC t-stat",
            "regime_multiplier": "Regime multiplier",
            "drawdown_multiplier": "Drawdown multiplier",
            "loss_shock_multiplier": "Loss-shock multiplier",
        }
    )
    line_chart(health, "Signal health and risk multipliers", "Value")

    c1, c2, c3 = st.columns(3)
    shutdown_counts = result.diagnostics.loc[
        result.diagnostics["shutdown_reason"].astype(str).ne(""), "shutdown_reason"
    ].value_counts()
    c1.metric("Hard drawdown breaches", int(result.diagnostics["hard_drawdown_breach"].sum()))
    c2.metric("Days fully flat", int((result.diagnostics["gross_exposure"] <= 1e-8).sum()))
    c3.metric("Maximum gross", f"{result.diagnostics['gross_exposure'].max():.2f}x")
    st.markdown("#### Shutdown reason counts")
    st.dataframe(shutdown_counts.rename("Days"), width="stretch")

    cumulative_costs = result.diagnostics[
        [
            "linear_transaction_cost",
            "market_impact_cost",
            "borrow_cost",
            "financing_cost",
        ]
    ].cumsum()
    cumulative_costs.columns = ["Linear transaction", "Market impact", "Borrow", "Financing"]
    line_chart(cumulative_costs, "Cumulative modeled costs (% of capital units)", "Cumulative cost")

with validation_tab:
    st.subheader("Certification gate")
    st.dataframe(display_certification(certification), width="stretch")
    st.caption(
        "The Sharpe diagnostic is penalized for serial correlation and the persistent "
        "trial count. It remains conditional on the supplied data and execution model."
    )

    if payload["bootstrap_error"]:
        st.warning(payload["bootstrap_error"])
    bcols = st.columns(5)
    bcols[0].metric(
        "Path-aware P(CAGR target)", pct(bootstrap.probability_cagr_target)
    )
    bcols[1].metric(
        "Path-aware P(DD target)", pct(bootstrap.probability_drawdown_target)
    )
    bcols[2].metric(
        "Path-aware P(both)", pct(bootstrap.probability_both_targets)
    )
    bcols[3].metric(
        "95% lower bound P(both)",
        pct(bootstrap.probability_both_targets_lower_95),
        help=(
            "Wilson lower confidence bound across aligned-input state-machine "
            "reruns; this is the gate value."
        ),
    )
    bcols[4].metric("Trial-adjusted P(Sharpe > 0)", pct(payload["psr"]))

    bcols2 = st.columns(4)
    bcols2[0].metric("Median path CAGR", pct(bootstrap.median_cagr))
    bcols2[1].metric("5th percentile CAGR", pct(bootstrap.fifth_percentile_cagr))
    bcols2[2].metric("Median path max drawdown", pct(bootstrap.median_max_drawdown))
    bcols2[3].metric("5th percentile max DD", pct(bootstrap.fifth_percentile_max_drawdown))
    st.caption(
        f"Hard-gate resampler: {bootstrap.method_id}; fixed seed {bootstrap.seed}; "
        f"plan {bootstrap.sampling_plan_sha256 or 'unavailable'}; "
        f"valid paths {pct(bootstrap.valid_path_fraction)}."
    )

    if payload.get("return_only_bootstrap_error"):
        st.warning(payload["return_only_bootstrap_error"])
    st.markdown("#### Return-only bootstrap diagnostic (not a certification gate)")
    diagnostic_cols = st.columns(4)
    diagnostic_cols[0].metric(
        "Diagnostic P(CAGR target)",
        pct(return_only_bootstrap.probability_cagr_target),
    )
    diagnostic_cols[1].metric(
        "Diagnostic P(DD target)",
        pct(return_only_bootstrap.probability_drawdown_target),
    )
    diagnostic_cols[2].metric(
        "Diagnostic P(both)",
        pct(return_only_bootstrap.probability_both_targets),
    )
    diagnostic_cols[3].metric(
        "Diagnostic lower 95%",
        pct(return_only_bootstrap.probability_both_targets_lower_95),
    )

    sharpe_diagnostics = payload.get("sharpe_diagnostics")
    if sharpe_diagnostics is not None:
        st.markdown("#### Sharpe evidence diagnostics")
        st.dataframe(
            pd.DataFrame(
                {
                    "Value": [
                        sharpe_diagnostics.observations,
                        round(sharpe_diagnostics.effective_observations, 2),
                        sharpe_diagnostics.autocorrelation_lags,
                        sharpe_diagnostics.trial_count,
                        round(sharpe_diagnostics.adjusted_benchmark_daily_sharpe, 6),
                    ]
                },
                index=[
                    "Raw observations",
                    "HAC effective observations",
                    "Autocorrelation lags",
                    "Prior attempts plus current variants",
                    "Adjusted daily Sharpe benchmark",
                ],
            ),
            width="stretch",
        )
        st.caption(sharpe_diagnostics.assumptions)

    attribution: FactorRegressionResult | None = payload.get("attribution")
    if attribution is not None:
        st.markdown("#### OOS factor attribution")
        displayed_market_factor = str(
            payload.get("market_factor_column") or "equal_weight_market"
        )
        acols = st.columns(4)
        acols[0].metric("Annualized alpha", pct(attribution.annualized_alpha))
        acols[1].metric("Alpha HAC t-stat", number(attribution.alpha_tstat_hac))
        acols[2].metric(
            f"Market beta ({displayed_market_factor})",
            number(attribution.factor_betas.get(displayed_market_factor)),
        )
        acols[3].metric("Residual volatility", pct(attribution.residual_annualized_volatility))
        if payload.get("research_mode") == "sealed_final":
            st.caption(
                "Attribution uses the exact signed, point-in-time multi-factor dataset. "
                f"The preregistered market factor is {displayed_market_factor!r}."
            )
            st.dataframe(
                pd.DataFrame.from_dict(
                    attribution.factor_betas,
                    orient="index",
                    columns=["Realized beta"],
                ),
                width="stretch",
            )
        else:
            st.caption(
                "Exploratory reference factor is the equal-weight return of the research "
                "universe; this endogenous single-factor diagnostic cannot pass sealed validation."
            )

    st.markdown("#### OOS profit economics")
    break_even_bps = oos_metrics.get("Break-Even Transaction Cost Bps")
    break_even_label = (
        f"{float(break_even_bps):.2f} bps"
        if break_even_bps is not None and np.isfinite(float(break_even_bps))
        else "N/A"
    )
    pcols = st.columns(5)
    pcols[0].metric("Pre-cost return", pct(oos_metrics.get("Annualized Pre-Cost Return")))
    pcols[1].metric("Net CAGR", pct(oos_metrics.get("CAGR")))
    pcols[2].metric("Modeled annual cost", pct(oos_metrics.get("Annualized Total Modeled Cost")))
    pcols[3].metric("Cost coverage", number(oos_metrics.get("Cost Coverage Ratio")))
    pcols[4].metric("Break-even cost", break_even_label)

    st.markdown("#### Double-cost stress test")
    metric_grid(double_cost_metrics)

    st.markdown("#### Rolling one-year target windows")
    rolling_table = payload["rolling_table"]
    if rolling_table.empty:
        st.info("The out-of-sample segment is too short for one-year rolling windows.")
    else:
        st.metric("Rolling target pass rate", pct(payload["rolling_pass"]))
        st.dataframe(
            rolling_table.style.format(
                {"CAGR": "{:.2%}", "Max Drawdown": "{:.2%}", "Calmar": "{:.2f}"}
            ),
            width="stretch",
        )

    perturbations = payload["perturbations"]
    if not perturbations.empty:
        st.markdown("#### Parameter perturbation suite")
        st.metric("Perturbation pass rate", pct(payload.get("perturbation_pass_rate")))
        st.dataframe(
            perturbations.style.format(
                {
                    "OOS CAGR": "{:.2%}",
                    "OOS Max Drawdown": "{:.2%}",
                    "OOS Sharpe": "{:.2f}",
                    "OOS Calmar": "{:.2f}",
                    "Max Gross": "{:.2f}x",
                }
            ),
            width="stretch",
        )

with data_tab:
    st.subheader("Input audit")
    audit = pd.DataFrame(
        {
            "Value": [
                f"{data_report.rows:,}",
                f"{data_report.assets:,}",
                data_report.start.strftime("%Y-%m-%d"),
                data_report.end.strftime("%Y-%m-%d"),
                f"{data_report.missing_fraction_before_fill:.2%}",
                f"{data_report.duplicate_dates_removed:,}",
                f"{data_report.nonpositive_values_removed:,}",
            ]
        },
        index=[
            "Rows",
            "Assets",
            "Start",
            "End",
            "Missing fraction before fill",
            "Duplicate dates removed",
            "Non-positive values removed",
        ],
    )
    st.dataframe(audit, width="stretch")
    if execution_prices is not None:
        st.markdown("#### Execution-price coverage")
        st.dataframe(
            pd.DataFrame(
                {
                    "Value": [
                        f"{execution_prices.notna().mean().mean():.2%}",
                        str(execution_prices.index.min().date()),
                        str(execution_prices.index.max().date()),
                    ]
                },
                index=["Observed cells", "Start", "End"],
            ),
            width="stretch",
        )
    if execution_window_dollar_volume is not None:
        st.markdown("#### 09:30-09:35 execution-window dollar-volume coverage")
        st.dataframe(
            pd.DataFrame(
                {
                    "Value": [
                        f"{execution_window_dollar_volume.notna().mean().mean():.2%}",
                        str(execution_window_dollar_volume.index.min().date()),
                        str(execution_window_dollar_volume.index.max().date()),
                        payload.get("execution_window_dollar_volume_hash", ""),
                    ]
                },
                index=["Observed cells", "Start", "End", "Parsed-data SHA-256"],
            ),
            width="stretch",
        )
    st.markdown("#### Price sample")
    observed_price_sample = (
        result.observed_prices
        if result.observed_prices is not None
        else result.prices
    )
    st.dataframe(observed_price_sample.tail(20), width="stretch")
    st.markdown("#### Weight sample")
    st.dataframe(result.weights.tail(20), width="stretch")
    st.markdown("#### Diagnostic sample")
    st.dataframe(result.diagnostics.tail(50), width="stretch")
    st.markdown("#### Persistent research-attempt registry")
    attempt_rows = pd.DataFrame(ledger.recent_attempts(100))
    if attempt_rows.empty:
        st.info("No persisted research attempts are available.")
    else:
        st.dataframe(attempt_rows, width="stretch", hide_index=True)

    st.markdown("#### Completed experiment ledger")
    trial_rows = pd.DataFrame(ledger.recent_trials(100))
    if trial_rows.empty:
        st.info("No persisted research trials are available.")
    else:
        st.dataframe(trial_rows, width="stretch", hide_index=True)

with exports_tab:
    validation_payload = {
        "bootstrap": bootstrap.to_dict(),
        "path_aware_bootstrap_gate": bootstrap.to_dict(),
        "return_only_bootstrap_diagnostic": return_only_bootstrap.to_dict(),
        "rolling_target_pass_rate": payload["rolling_pass"],
        "parameter_perturbation_pass_rate": payload.get("perturbation_pass_rate"),
        "parameter_perturbation_gate_passed": payload.get(
            "perturbation_gate_passed", False
        ),
        "parameter_perturbation_passed_variant_count": payload.get(
            "perturbation_passed_variant_count", 0
        ),
        "parameter_perturbation_variant_count": (
            PARAMETER_PERTURBATION_VARIANT_COUNT
            if payload.get("perturbation_specification_sha256")
            else 0
        ),
        "parameter_perturbation_specification_sha256": payload.get(
            "perturbation_specification_sha256", ""
        ),
        "probabilistic_sharpe_probability": payload["psr"],
        "sharpe_probability_diagnostics": (
            payload["sharpe_diagnostics"].to_dict()
            if payload.get("sharpe_diagnostics") is not None
            else None
        ),
        "factor_attribution": (
            payload["attribution"].to_dict()
            if payload.get("attribution") is not None
            else None
        ),
        "certified": certified,
        "out_of_sample_start": oos_start,
        "target_cagr": payload["target_cagr"],
        "maximum_drawdown": payload["target_max_dd"],
        "required_confidence": payload["confidence"],
        "data_source": payload["source"],
        "research_mode": payload.get("research_mode"),
        "trial_id": payload.get("trial_id"),
        "persistent_trial_count": payload.get("trial_count"),
        "statistical_trial_count": payload.get("statistical_trial_count"),
        "first_holdout_use": payload.get("first_holdout_use"),
        "governance_first_use": payload.get("governance_first_use"),
        "sealed_eligible": payload.get("sealed_eligible"),
        "holdout_data_hash": payload.get("holdout_data_hash"),
        "holdout_identity_policy": payload.get("holdout_identity_policy"),
        "holdout_oos_end": payload.get("holdout_oos_end"),
        "holdout_identity_current": payload.get("holdout_identity_current"),
        "manifest_hash": payload.get("manifest_hash"),
        "manifest_key_id": payload.get("manifest_key_id"),
        "manifest_payload": payload.get("manifest_payload"),
        "manifest_envelope": payload.get("manifest_envelope"),
        "anchor_receipt_hash": payload.get("anchor_receipt_hash"),
        "trusted_registry_hash": payload.get("trusted_registry_hash"),
        "research_software_hash": payload.get("research_software_hash"),
        "runtime_identity": payload.get("runtime_identity"),
        "certification_context_hash": payload.get("certification_context_hash"),
        "ledger_state_hash": payload.get("ledger_state_hash"),
        "market_factor_column": payload.get("market_factor_column"),
        "data_hash": payload.get("data_hash"),
        "close_data_hash": payload.get("close_data_hash"),
        "execution_data_hash": payload.get("execution_data_hash"),
        "factor_data_hash": payload.get("factor_data_hash"),
        "execution_window_dollar_volume_hash": payload.get(
            "execution_window_dollar_volume_hash"
        ),
        "corporate_action_data_hash": payload.get("corporate_action_data_hash"),
        "borrow_data_hash": payload.get("borrow_data_hash"),
        "exchange_calendar_hash": payload.get("exchange_calendar_hash"),
        "config_hash": payload.get("config_hash"),
        "research_specification": payload.get("research_specification"),
    }
    bundle = build_result_bundle(
        result=result,
        full_metrics=full_metrics,
        oos_metrics=oos_metrics,
        validation_payload=validation_payload,
        certification=certification,
        execution_prices=payload.get("execution_prices"),
        execution_window_dollar_volume=payload.get(
            "execution_window_dollar_volume"
        ),
        corporate_action_split_ratios=(
            corporate_actions.split_ratio if corporate_actions is not None else None
        ),
        corporate_action_cash_distributions=(
            corporate_actions.cash_distribution
            if corporate_actions is not None
            else None
        ),
        corporate_action_as_of_timestamps=(
            corporate_actions.as_of_timestamp
            if corporate_actions is not None
            else None
        ),
        borrow_availability=(
            borrow_data.availability if borrow_data is not None else None
        ),
        annual_borrow_rates=(
            borrow_data.annual_rate if borrow_data is not None else None
        ),
        borrow_recalls=borrow_data.recall if borrow_data is not None else None,
        borrow_as_of_timestamps=(
            borrow_data.as_of_timestamp if borrow_data is not None else None
        ),
        factor_returns=payload.get("factor_returns"),
        exchange_session_calendar=payload.get("exchange_calendar"),
        stressed_result=payload.get("stressed_result"),
        rolling_validation=payload.get("rolling_table"),
        parameter_perturbations=payload.get("perturbations"),
        governance_ledger_snapshot=payload.get("ledger_snapshot_bytes"),
        trusted_registry_bytes=payload.get("trusted_registry_bytes"),
        research_source_snapshot=payload.get("research_source_snapshot"),
        signed_manifest_bytes=payload.get("manifest_bytes"),
        anchor_receipt_bytes=payload.get("anchor_receipt_bytes"),
    )
    st.download_button(
        "Download complete research bundle (.zip)",
        data=bundle,
        file_name="quant_strategy_research_results.zip",
        mime="application/zip",
        type="primary",
    )
    c1, c2, c3 = st.columns(3)
    c1.download_button(
        "Equity CSV",
        result.equity.to_csv().encode("utf-8"),
        file_name="equity.csv",
        mime="text/csv",
    )
    c2.download_button(
        "Weights CSV",
        result.weights.to_csv().encode("utf-8"),
        file_name="weights.csv",
        mime="text/csv",
    )
    c3.download_button(
        "Diagnostics CSV",
        result.diagnostics.to_csv().encode("utf-8"),
        file_name="diagnostics.csv",
        mime="text/csv",
    )
    st.code(json.dumps(result.config.to_dict(), indent=2), language="json")

st.markdown(
    "<p class='small-note'>Research safeguards: no backward filling, conservative execution-latency proxy, holdings-drift accounting, modeled turnover/borrow/financing costs, leverage caps, beta and dollar neutrality, signed preregistration manifests, data-family/overlap claims, multi-factor attribution, persistent effective-trial accounting, stale-result invalidation, block bootstrap, and cost stress. These controls do not establish a proprietary edge or guarantee live returns.</p>",
    unsafe_allow_html=True,
)
