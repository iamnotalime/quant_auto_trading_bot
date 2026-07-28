from __future__ import annotations

import hmac
import json
import os
from pathlib import Path

import pandas as pd
import streamlit as st

from auto_trader.controls import merge_control_marker
from auto_trader.store import StateStore


ROOT = Path(__file__).resolve().parent


def _path_from_env(name: str, default: str) -> Path:
    path = Path(os.environ.get(name, default)).expanduser()
    if not path.is_absolute():
        path = ROOT / path
    return path.resolve(strict=False)


def _bool_label(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _mode_label() -> str:
    explicit = os.environ.get("BOT_MODE_LABEL", "").strip()
    if explicit:
        return explicit
    broker = os.environ.get("BROKER", "unknown").strip().lower()
    execution = _bool_label("EXECUTION_ENABLED", False)
    if broker == "simulated":
        return "simulated-execution" if execution else "simulated-plan-only"
    if broker == "alpaca":
        paper = _bool_label("ALPACA_PAPER", True)
        prefix = "alpaca-paper" if paper else "alpaca-live"
        return prefix if execution else f"{prefix}-plan-only"
    return "configured externally"


database_path = _path_from_env("DATABASE_PATH", "runtime/auto_trader.sqlite3")
kill_switch_path = _path_from_env("KILL_SWITCH_PATH", "runtime/KILL_SWITCH")
kill_switch_ack_path = _path_from_env("KILL_SWITCH_ACK_PATH", "runtime/KILL_SWITCH.ack.json")
control_token = os.environ.get("DASHBOARD_CONTROL_TOKEN", "")
execution_enabled = _bool_label("EXECUTION_ENABLED", False)
broker_name = os.environ.get("BROKER", "unknown").strip().lower()
paper_mode = _bool_label("ALPACA_PAPER", True)

st.set_page_config(page_title="Quant Auto Trader", page_icon="⚙️", layout="wide")
st.title("Quant Auto Trader — Operations Console")
st.caption(
    "Read-only operational dashboard plus an authenticated emergency halt control. "
    "The always-on daemon is a separate process and continues running if this browser closes."
)

store: StateStore | None = None
store_error: Exception | None = None
try:
    # This is a SQLite mode=ro observer. It cannot bootstrap, repair, checkpoint,
    # or persist controls into the daemon's authoritative trading database.
    store = StateStore.open_read_only(database_path)
except Exception as exc:
    store_error = exc

summary: dict = {}
if store is not None:
    try:
        summary = store.summary()
    except Exception as exc:
        store_error = exc
        store = None

halt = summary.get("halt") or {}
latest_equity = summary.get("latest_equity") or {}
latest_plan = summary.get("latest_plan") or {}
heartbeat = None
if store is not None:
    try:
        heartbeat = store.get_state("daemon_heartbeat", None)
    except Exception as exc:
        store_error = exc
        store = None

mode_col, state_col, equity_col, dd_col, heartbeat_col = st.columns(5)
mode_col.metric("Mode", _mode_label())
state_col.metric(
    "State",
    "STATE UNAVAILABLE" if store is None else ("HALTED" if halt.get("active") else "RUNNING"),
)
equity_col.metric("Latest equity", f"{float(latest_equity.get('equity', 0.0)):,.2f}")
dd_col.metric("Latest drawdown", f"{100 * float(latest_equity.get('drawdown', 0.0)):.2f}%")
heartbeat_col.metric("Daemon heartbeat", str(heartbeat)[11:19] if heartbeat else "not available")

if store_error is not None:
    st.error(
        "Persistent state is unavailable. Read-only data may be incomplete, but the "
        f"filesystem emergency control remains usable. Detail: {type(store_error).__name__}: {store_error}"
    )
if not execution_enabled:
    st.warning(
        "Order submission is disabled. The daemon can calculate and preview plans but cannot trade or flatten positions."
    )
elif broker_name == "alpaca" and not paper_mode:
    st.error("LIVE BROKER MODE IS ENABLED. Confirm account isolation and risk limits outside this dashboard.")
if halt.get("active"):
    st.error(f"Persistent halt active: {halt.get('reason', 'unspecified')}")

with st.expander("Emergency kill switch", expanded=bool(halt.get("active") or store_error)):
    st.write(
        "The control atomically creates the filesystem kill switch. The daemon observes "
        "that marker independently of the database and begins its emergency procedure."
    )
    if not control_token:
        st.warning(
            "Emergency control is disabled because DASHBOARD_CONTROL_TOKEN is not configured. "
            "Use the local CLI kill command or create the kill-switch file directly."
        )
    confirmation = st.text_input("Type HALT", type="password", key="halt_confirmation")
    supplied_token = st.text_input(
        "Control token", type="password", key="halt_control_token", disabled=not bool(control_token)
    )
    authorized = bool(control_token) and hmac.compare_digest(supplied_token, control_token)
    if st.button(
        "Activate emergency halt",
        type="primary",
        disabled=confirmation != "HALT" or not authorized,
    ):
        acknowledgement_warning: Exception | None = None
        try:
            # Remove a stale acknowledgement before publishing the new request. If
            # this cleanup fails, emergency availability still takes precedence.
            kill_switch_ack_path.unlink(missing_ok=True)
        except OSError as exc:
            acknowledgement_warning = exc
        merge_control_marker(
            kill_switch_path,
            "dashboard_emergency_halt",
            flatten=True,
        )
        if acknowledgement_warning is None:
            st.success(
                "Kill switch created. The daemon will persist the halt and publish "
                "an acknowledgement after broker reconciliation."
            )
        else:
            st.warning(
                "Kill switch created, but a stale acknowledgement could not be removed. "
                "Verify the daemon acknowledgement timestamp and broker positions "
                f"immediately. Detail: {acknowledgement_warning}"
            )
        st.rerun()
    st.caption(
        "Resumption is intentionally CLI-only: python bot.py resume --ack RESUME_AUTOMATED_TRADING"
    )

if store is None:
    st.stop()

st.subheader("Equity and risk")
equity_rows = store.recent_equity(1000)
if equity_rows:
    equity = pd.DataFrame(equity_rows)
    equity["timestamp"] = pd.to_datetime(equity["timestamp"], utc=True, errors="coerce")
    equity = equity.set_index("timestamp")
    st.line_chart(equity[["equity"]])
    with st.expander("Equity snapshots"):
        st.dataframe(equity.tail(200), width="stretch")
else:
    st.info("No equity snapshots have been recorded yet. Run `python bot.py monitor` or start the daemon.")

st.subheader("Latest target plan")
if latest_plan:
    left, right = st.columns(2)
    left.json(
        {
            "plan_id": latest_plan.get("plan_id"),
            "as_of": latest_plan.get("as_of"),
            "status": latest_plan.get("status"),
            "regime": latest_plan.get("regime"),
            "desired_gross": latest_plan.get("desired_gross"),
            "forecast_volatility": latest_plan.get("forecast_volatility"),
            "execution_message": latest_plan.get("execution_message"),
        }
    )
    try:
        weights = json.loads(latest_plan.get("target_weights_json", "{}"))
        weights_frame = pd.DataFrame(
            sorted(weights.items(), key=lambda item: abs(item[1]), reverse=True),
            columns=["symbol", "target_weight"],
        )
        right.dataframe(weights_frame, width="stretch", hide_index=True)
    except json.JSONDecodeError:
        right.warning("The stored target weights could not be decoded.")
else:
    st.info("No target plan has been generated.")

orders_tab, events_tab, runs_tab, plans_tab = st.tabs(["Orders", "Events", "Runs", "Plans"])
with orders_tab:
    orders = pd.DataFrame(store.recent_orders(300))
    st.dataframe(orders, width="stretch", hide_index=True) if not orders.empty else st.info("No orders recorded.")
with events_tab:
    events = pd.DataFrame(store.recent_events(300))
    st.dataframe(events, width="stretch", hide_index=True) if not events.empty else st.info("No events recorded.")
with runs_tab:
    runs = pd.DataFrame(store.recent_runs(200))
    st.dataframe(runs, width="stretch", hide_index=True) if not runs.empty else st.info("No runs recorded.")
with plans_tab:
    plans = pd.DataFrame(store.list_plans(100))
    st.dataframe(plans, width="stretch", hide_index=True) if not plans.empty else st.info("No plans recorded.")

st.caption(
    "This software automates a public-methodology research strategy. It cannot reproduce Renaissance Technologies' proprietary models, "
    "and it does not guarantee profitability, a 60% CAGR, or a 15% live drawdown ceiling."
)
