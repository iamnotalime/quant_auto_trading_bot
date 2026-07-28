from __future__ import annotations

import json
import hashlib
import logging
import os
import sqlite3
from dataclasses import replace
from datetime import datetime, time, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from auto_trader.config import BotConfig, LIVE_ACK_TEXT, PROJECT_ROOT
from auto_trader.controls import (
    encode_control_marker,
    merge_control_marker,
    parse_control_marker,
)
from auto_trader.daemon import (
    DaemonHealthThresholdError,
    LockUnavailableError,
    ProcessLock,
    TradingDaemon,
)
from auto_trader.factory import build_engine
from auto_trader.emergency_journal import EmergencyJournal
from auto_trader.models import (
    ExecutionSummary,
    MarketClock,
    OrderReceipt,
    OrderSide,
    PositionSnapshot,
    RiskDecision,
)
from auto_trader.store import SCHEMA_VERSION, StateStore
from bot import _validate_health


_TEST_PLAN_AUTHENTICATION_KEY = hashlib.sha256(
    b"operational-safety-test-plan-authentication-key"
).hexdigest()
_TEST_EMERGENCY_AUTHENTICATION_KEY = hashlib.sha256(
    b"operational-safety-test-emergency-authentication-key"
).hexdigest()


def test_relative_runtime_paths_are_anchored_to_project_not_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for key in (
        "DATABASE_PATH",
        "LOG_PATH",
        "KILL_SWITCH_PATH",
        "PROCESS_LOCK_PATH",
        "OPERATION_LOCK_PATH",
        "KILL_SWITCH_ACK_PATH",
        "DAEMON_HEALTH_PATH",
        "SIMULATED_PRICES_PATH",
        "SIMULATED_STATE_PATH",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.chdir(tmp_path)

    config = BotConfig.from_env(None)

    assert config.database_path == (PROJECT_ROOT / "runtime/auto_trader.sqlite3").resolve()
    assert config.simulated_prices_path == (PROJECT_ROOT / "sample_prices.csv").resolve()
    assert config.database_path.is_absolute()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("simulated_starting_cash", float("nan"), "SIMULATED_STARTING_CASH must be finite"),
        ("simulated_slippage_bps", float("inf"), "SIMULATED_SLIPPAGE_BPS must be finite"),
        ("poll_seconds", 0, "POLL_SECONDS must be between"),
        ("order_fill_timeout_seconds", -1, "ORDER_FILL_TIMEOUT_SECONDS must be between"),
        ("max_execution_price_age_seconds", 0, "MAX_EXECUTION_PRICE_AGE_SECONDS must be"),
        ("max_execution_spread_bps", float("nan"), "MAX_EXECUTION_SPREAD_BPS must be finite"),
        ("marketable_limit_collar_bps", 0.0, "MARKETABLE_LIMIT_COLLAR_BPS must be"),
        ("health_failure_threshold", 0, "HEALTH_FAILURE_THRESHOLD must be between"),
        (
            "daemon_watchdog_timeout_seconds",
            119,
            "DAEMON_WATCHDOG_TIMEOUT_SECONDS must be between",
        ),
        ("actual_gross_exposure_tolerance", float("nan"), "ACTUAL_GROSS_EXPOSURE_TOLERANCE must be finite"),
        ("actual_net_exposure_limit", 0.0, "ACTUAL_NET_EXPOSURE_LIMIT must be"),
        ("actual_beta_exposure_limit", float("inf"), "ACTUAL_BETA_EXPOSURE_LIMIT must be finite"),
        ("actual_position_weight_tolerance", 1.1, "ACTUAL_POSITION_WEIGHT_TOLERANCE must be"),
    ],
)
def test_numeric_configuration_rejects_nonfinite_and_unsafe_values(
    field: str, value: object, message: str
) -> None:
    config = replace(BotConfig(), **{field: value})
    with pytest.raises(ValueError, match=message):
        config.validate()


def test_risk_thresholds_must_be_strictly_ordered() -> None:
    base = BotConfig()
    unsafe_risk = replace(base.strategy.risk, flatten_drawdown=0.08)
    unsafe = replace(base, strategy=replace(base.strategy, risk=unsafe_risk))
    with pytest.raises(ValueError, match="strictly increasing"):
        unsafe.validate()


def test_order_collar_must_cover_half_the_accepted_quote_spread() -> None:
    unsafe = replace(
        BotConfig(),
        max_execution_spread_bps=50.0,
        marketable_limit_collar_bps=24.9,
    )
    with pytest.raises(ValueError, match="must be at least half"):
        unsafe.validate()


def _alpaca_plan_only_config(**overrides) -> BotConfig:
    base = BotConfig(
        broker="alpaca",
        execution_enabled=False,
        alpaca_api_key="key",
        alpaca_secret_key="secret",
        alpaca_account_id="account-test-0001",
        plan_authentication_key=_TEST_PLAN_AUTHENTICATION_KEY,
        emergency_authentication_key=_TEST_EMERGENCY_AUTHENTICATION_KEY,
    )
    return replace(base, **overrides)


def test_alpaca_plan_only_requires_independent_strong_plan_authentication_key() -> None:
    with pytest.raises(ValueError, match="PLAN_AUTHENTICATION_KEY"):
        replace(
            _alpaca_plan_only_config(),
            plan_authentication_key=BotConfig().plan_authentication_key,
        ).validate()
    with pytest.raises(ValueError, match="64 lowercase hexadecimal"):
        replace(
            _alpaca_plan_only_config(),
            plan_authentication_key="not-a-key",
        ).validate()


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"timezone": "UTC"}, "STRATEGY_TIMEZONE=America/New_York"),
        ({"plan_time": time(16, 0)}, "PLAN_TIME at or after 16:05"),
        ({"execution_time": time(9, 29)}, "EXECUTION_TIME at or after"),
        (
            {"execution_time": time(15, 45), "execution_window_minutes": 11},
            "execution window to end by 15:55",
        ),
    ],
)
def test_alpaca_schedule_is_bound_to_completed_regular_sessions(
    overrides: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _alpaca_plan_only_config(**overrides).validate()


def test_alpaca_paper_execution_requires_a_dedicated_account() -> None:
    config = replace(_alpaca_plan_only_config(), execution_enabled=True)
    with pytest.raises(ValueError, match="including paper trading"):
        config.validate()


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"execution_time": time(9, 31)}, "EXECUTION_TIME=09:30"),
        ({"execution_window_minutes": 6}, "EXECUTION_WINDOW_MINUTES=5"),
        ({"minimum_assets": 19}, "MINIMUM_ASSETS>=20"),
    ],
)
def test_governed_alpaca_execution_is_bound_to_sealed_window_and_breadth(
    overrides: dict[str, object],
    message: str,
) -> None:
    config = replace(
        _alpaca_plan_only_config(),
        execution_enabled=True,
        dedicated_account=True,
        **overrides,
    )
    with pytest.raises(ValueError, match=message):
        config.validate()


def test_governed_alpaca_execution_rejects_unanchored_rebalance_cadence() -> None:
    base = _alpaca_plan_only_config()
    slower = replace(
        base.strategy,
        portfolio=replace(base.strategy.portfolio, rebalance_every=2),
    )
    with pytest.raises(ValueError, match="REBALANCE_EVERY=1"):
        replace(base, execution_enabled=True, strategy=slower).validate()


def test_dollar_neutral_strategy_rejects_shorting_disabled_configuration() -> None:
    with pytest.raises(ValueError, match="incompatible with the configured dollar-neutral"):
        replace(BotConfig(), allow_shorting=False).validate()


def test_operation_paths_must_not_alias() -> None:
    base = BotConfig()
    unsafe = replace(base, operation_lock_path=base.database_path)
    with pytest.raises(ValueError, match="Operational paths must be distinct"):
        unsafe.validate()


def test_process_lock_uses_kernel_lock_not_pid_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "daemon.lock"
    path.write_text("999999", encoding="utf-8")

    def forbidden_kill(*_args, **_kwargs):
        raise AssertionError("PID probing must never be used")

    monkeypatch.setattr(os, "kill", forbidden_kill)
    with ProcessLock(path, purpose="test"):
        pass
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["pid"] == os.getpid()


def test_process_lock_excludes_a_second_owner(tmp_path: Path) -> None:
    path = tmp_path / "operation.lock"
    with ProcessLock(path, purpose="test"):
        with pytest.raises(LockUnavailableError, match="owns the test lock"):
            with ProcessLock(path, timeout_seconds=0, purpose="test"):
                pass


def test_missing_database_with_identity_marker_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    store = StateStore(path)
    identity_path = store.identity_path
    assert identity_path.exists()
    path.unlink()

    with pytest.raises(RuntimeError, match="Refusing to initialize empty state"):
        StateStore(path)


def test_existing_only_store_never_initializes_missing_state(tmp_path: Path) -> None:
    path = tmp_path / "missing-parent" / "state.sqlite3"

    with pytest.raises(RuntimeError, match="Existing persistent state is required"):
        StateStore(path, require_existing=True)

    assert not path.parent.exists()
    assert not path.exists()
    assert not path.with_suffix(path.suffix + ".identity").exists()


def test_existing_only_store_never_recreates_missing_identity(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    initialized = StateStore(path)
    initialized.identity_path.unlink()

    with pytest.raises(RuntimeError, match="Existing persistent state is required"):
        StateStore(path, require_existing=True)

    assert path.exists()
    assert not initialized.identity_path.exists()


def test_existing_only_store_accepts_valid_matching_state(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    initialized = StateStore(path)
    initialized.set_state("sentinel", {"value": 7})

    reopened = StateStore(path, require_existing=True)

    assert reopened.get_state("sentinel") == {"value": 7}


def test_read_only_store_cannot_initialize_or_mutate_trading_state(tmp_path: Path) -> None:
    missing = tmp_path / "missing-parent" / "state.sqlite3"
    with pytest.raises(RuntimeError, match="Existing persistent state is required"):
        StateStore.open_read_only(missing)
    assert not missing.parent.exists()

    path = tmp_path / "state.sqlite3"
    writer = StateStore(path)
    writer.set_state("sentinel", {"value": 7})
    before_database = path.read_bytes()
    before_identity = writer.identity_path.read_bytes()
    before_files = {item.name for item in tmp_path.iterdir()}
    before_mtime = path.stat().st_mtime_ns

    observer = StateStore.open_read_only(path)
    assert observer.read_only is True
    assert observer.get_state("sentinel") == {"value": 7}
    assert observer.summary()["latest_plan"] is None
    with observer.connection() as db:
        assert db.execute("PRAGMA query_only").fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            db.execute("UPDATE state SET value = 'tampered' WHERE key = 'sentinel'")
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        observer.set_state("sentinel", {"value": 999})

    assert path.read_bytes() == before_database
    assert writer.identity_path.read_bytes() == before_identity
    assert path.stat().st_mtime_ns == before_mtime
    assert {item.name for item in tmp_path.iterdir()} == before_files
    assert StateStore(path, require_existing=True).get_state("sentinel") == {"value": 7}


def test_malformed_persisted_json_never_returns_a_risk_default(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.set_state("halt", {"active": True, "reason": "incident", "flatten": True})
    with store.connection() as db:
        db.execute("UPDATE state SET value = ? WHERE key = 'halt'", ("{not-json",))

    with pytest.raises(ValueError, match="invalid JSON"):
        store.get_state("halt", {})
    with pytest.raises(ValueError, match="invalid JSON"):
        store.halt_state()


@pytest.mark.parametrize(
    ("key", "value", "reader"),
    [
        ("halt", [], "halt_state"),
        ("high_watermark", {"bad": 1}, "update_high_watermark"),
        ("cooldown_remaining", -1, "cooldown_remaining"),
        ("flatten_attempt", {"status": "unknown"}, "flatten_attempt_state"),
    ],
)
def test_semantically_invalid_risk_state_never_defaults_or_resets(
    tmp_path: Path, key: str, value: object, reader: str
) -> None:
    store = StateStore(tmp_path / f"{key}.sqlite3")
    store.set_state(key, value)

    with pytest.raises((TypeError, ValueError), match="Persisted|persisted"):
        if reader == "update_high_watermark":
            store.update_high_watermark(100_000.0)
        else:
            getattr(store, reader)()


def test_active_mandatory_flatten_cannot_be_downgraded_by_halt_only_request(
    tmp_path: Path,
) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.request_halt("risk_limit", flatten=True)

    store.request_halt("later_operator_halt_only", flatten=False)

    halt = store.halt_state()
    assert halt["active"] is True
    assert halt["flatten"] is True


def test_corrupt_halt_can_be_replaced_only_by_mandatory_failsafe(
    tmp_path: Path,
) -> None:
    store = StateStore(tmp_path / "state.sqlite3")
    store.set_state("halt", ["corrupt"])

    store.request_halt("replacement_halt_only", flatten=False)

    halt = store.halt_state()
    assert halt["active"] is True
    assert halt["flatten"] is True
    assert halt["recovered_invalid_prior_state"] is True


def test_control_marker_is_backward_compatible_and_malformed_json_flattens() -> None:
    legacy = parse_control_marker("operator_emergency\n")
    halt_only = parse_control_marker(
        encode_control_marker("operator_pause", flatten=False)
    )
    malformed = parse_control_marker('{"schema_version":1,"flatten":false')

    assert legacy.reason == "operator_emergency" and legacy.flatten is True
    assert halt_only.reason == "operator_pause" and halt_only.flatten is False
    assert malformed.reason == "malformed_filesystem_kill_switch"
    assert malformed.flatten is True


def test_control_marker_merge_is_monotonic_and_preserves_incident_reasons(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "KILL_SWITCH"
    merge_control_marker(marker, "operator_pause", flatten=False)
    mandatory = merge_control_marker(marker, "daemon_watchdog", flatten=True)
    later_halt_only = merge_control_marker(marker, "second_operator", flatten=False)

    persisted = parse_control_marker(marker.read_text(encoding="utf-8"))
    assert mandatory.flatten is True
    assert later_halt_only.flatten is True
    assert persisted.flatten is True
    assert persisted.reason == "operator_pause | daemon_watchdog | second_operator"


def test_v1_control_marker_upgrade_preserves_incident_uuid_across_rewrites(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "KILL_SWITCH"
    marker.write_text(
        '{"flatten":false,"reason":"legacy_pause","schema_version":1}\n',
        encoding="utf-8",
    )

    upgraded = merge_control_marker(marker, "daemon_escalation", flatten=True)
    rewritten = merge_control_marker(marker, "watchdog_confirmation", flatten=False)
    persisted = parse_control_marker(marker.read_text(encoding="utf-8"))

    assert upgraded.incident_id is not None
    assert rewritten.incident_id == upgraded.incident_id == persisted.incident_id
    assert persisted.flatten is True
    assert json.loads(marker.read_text(encoding="utf-8"))["schema_version"] == 2


def test_emergency_journal_wrong_key_cannot_mint_replacement_ids(
    tmp_path: Path,
) -> None:
    marker = merge_control_marker(tmp_path / "KILL_SWITCH", "test", flatten=True)
    assert marker.incident_id is not None
    journal_path = tmp_path / "EMERGENCY_JOURNAL.json"
    first = EmergencyJournal(journal_path, b"a" * 32, "account-scope")
    prepared = first.prepare_submission(
        marker.incident_id,
        symbol="SPY",
        current_qty=2.0,
        side="sell",
        qty=2.0,
    )

    wrong = EmergencyJournal(journal_path, b"b" * 32, "account-scope")
    with pytest.raises(RuntimeError, match="authentication failed"):
        wrong.prepare_submission(
            marker.incident_id,
            symbol="SPY",
            current_qty=2.0,
            side="sell",
            qty=2.0,
        )

    retried = first.prepare_submission(
        marker.incident_id,
        symbol="SPY",
        current_qty=2.0,
        side="sell",
        qty=2.0,
    )
    assert retried.client_order_id == prepared.client_order_id


def test_emergency_journal_deletion_is_rejected_while_identity_survives(
    tmp_path: Path,
) -> None:
    path = tmp_path / "EMERGENCY_JOURNAL.json"
    journal = EmergencyJournal(path, b"j" * 32, "account-scope")
    journal.verify()
    marker = merge_control_marker(tmp_path / "KILL_SWITCH", "incident", flatten=True)
    assert marker.incident_id is not None
    journal.prepare_submission(
        marker.incident_id,
        symbol="SPY",
        current_qty=2.0,
        side="sell",
        qty=2.0,
    )
    assert journal.identity_path.exists() and journal.checkpoint_path.exists()

    path.unlink()

    with pytest.raises(RuntimeError, match="identity sentinel"):
        journal.verify()


def test_emergency_journal_valid_older_file_replay_fails_tail_checkpoint(
    tmp_path: Path,
) -> None:
    path = tmp_path / "EMERGENCY_JOURNAL.json"
    journal = EmergencyJournal(path, b"k" * 32, "account-scope")
    journal.verify()
    older_valid_journal = path.read_bytes()
    marker = merge_control_marker(tmp_path / "KILL_SWITCH", "incident", flatten=True)
    assert marker.incident_id is not None
    journal.prepare_submission(
        marker.incident_id,
        symbol="SPY",
        current_qty=2.0,
        side="sell",
        qty=2.0,
    )

    # The replayed bytes contain a valid journal HMAC, but the independent current
    # checkpoint commits the later ambiguous intent and must reject the rollback.
    path.write_bytes(older_valid_journal)

    with pytest.raises(RuntimeError, match="keyed tail checkpoint"):
        journal.verify()


def test_authenticated_journal_rebinds_rewritten_marker_to_active_incident(
    tmp_path: Path,
) -> None:
    marker_path = tmp_path / "KILL_SWITCH"
    journal = EmergencyJournal(
        tmp_path / "EMERGENCY_JOURNAL.json", b"m" * 32, "account-scope"
    )
    journal.verify()
    original = merge_control_marker(marker_path, "incident", flatten=True)
    assert original.incident_id is not None
    prepared = journal.prepare_submission(
        original.incident_id,
        symbol="SPY",
        current_qty=2.0,
        side="sell",
        qty=2.0,
    )
    rewritten_id = str(uuid4())
    marker_path.write_text(
        encode_control_marker(
            "rewritten",
            flatten=True,
            incident_id=rewritten_id,
        ),
        encoding="utf-8",
    )

    resolved = journal.resolve_incident(rewritten_id)
    rebound = merge_control_marker(
        marker_path,
        "journal_reconciliation",
        flatten=True,
        authoritative_incident_id=resolved,
    )
    retried = journal.prepare_submission(
        resolved,
        symbol="SPY",
        current_qty=2.0,
        side="sell",
        qty=2.0,
    )

    assert resolved == original.incident_id
    assert rebound.incident_id == original.incident_id
    assert retried.client_order_id == prepared.client_order_id


def test_emergency_journal_active_incident_introspection_is_authenticated(
    tmp_path: Path,
) -> None:
    path = tmp_path / "EMERGENCY_JOURNAL.json"
    journal = EmergencyJournal(path, b"n" * 32, "account-scope")
    journal.verify()
    assert journal.active_incident_id() is None
    marker = merge_control_marker(tmp_path / "KILL_SWITCH", "incident", flatten=True)
    assert marker.incident_id is not None
    prepared = journal.prepare_submission(
        marker.incident_id,
        symbol="SPY",
        current_qty=2.0,
        side="sell",
        qty=2.0,
    )
    assert journal.active_incident_id() == marker.incident_id
    journal.record_receipt(
        marker.incident_id,
        OrderReceipt(
            broker_order_id="broker-terminal",
            client_order_id=prepared.client_order_id,
            symbol="SPY",
            qty=2.0,
            side="sell",
            status="filled",
            submitted_at=datetime.now(timezone.utc),
            filled_qty=2.0,
            filled_avg_price=100.0,
        ),
    )
    journal.complete_incident(marker.incident_id, [{}, {}], [[], []])
    assert journal.active_incident_id() is None

    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["incidents"][marker.incident_id]["status"] = "active"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(RuntimeError, match="authentication failed"):
        journal.active_incident_id()


def test_emergency_journal_404_never_authorizes_incident_completion(
    tmp_path: Path,
) -> None:
    path = tmp_path / "EMERGENCY_JOURNAL.json"
    journal = EmergencyJournal(path, b"q" * 32, "account-scope")
    journal.verify()
    marker = merge_control_marker(tmp_path / "KILL_SWITCH", "incident", flatten=True)
    assert marker.incident_id is not None
    prepared = journal.prepare_submission(
        marker.incident_id,
        symbol="SPY",
        current_qty=2.0,
        side="sell",
        qty=2.0,
    )

    with pytest.raises(RuntimeError, match="terminal broker receipt"):
        journal.complete_incident(marker.incident_id, [{}, {}], [[], []])

    journal.record_not_found(marker.incident_id, prepared.client_order_id)
    with pytest.raises(RuntimeError, match="not_found"):
        journal.complete_incident(marker.incident_id, [{}, {}], [[], []])
    assert journal.active_incident_id() == marker.incident_id

    # A later broker lookup may overturn the provisional 404. Only its terminal
    # receipt, reflected in both flat snapshots, releases the incident.
    journal.record_receipt(
        marker.incident_id,
        OrderReceipt(
            broker_order_id="late-broker-order",
            client_order_id=prepared.client_order_id,
            symbol="SPY",
            qty=2.0,
            side="sell",
            status="filled",
            submitted_at=datetime.now(timezone.utc),
            filled_qty=2.0,
            filled_avg_price=100.0,
        ),
    )
    journal.complete_incident(marker.incident_id, [{}, {}], [[], []])
    assert journal.active_incident_id() is None


def test_emergency_journal_rolls_forward_crash_between_journal_and_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "EMERGENCY_JOURNAL.json"
    key = b"r" * 32
    journal = EmergencyJournal(path, key, "account-scope")
    journal.verify()
    marker = merge_control_marker(tmp_path / "KILL_SWITCH", "incident", flatten=True)
    assert marker.incident_id is not None

    def crash_before_checkpoint(_payload) -> None:
        raise OSError("simulated power loss before checkpoint rename")

    monkeypatch.setattr(journal, "_write_checkpoint", crash_before_checkpoint)
    with pytest.raises(OSError, match="simulated power loss"):
        journal.prepare_submission(
            marker.incident_id,
            symbol="SPY",
            current_qty=2.0,
            side="sell",
            qty=2.0,
        )

    interrupted = json.loads(path.read_text(encoding="utf-8"))
    client_order_id = interrupted["incidents"][marker.incident_id]["intents"][0][
        "client_order_id"
    ]
    assert journal.transaction_path.exists()

    recovered = EmergencyJournal(path, key, "account-scope")
    recovered.verify()
    assert not recovered.transaction_path.exists()
    assert recovered.active_incident_id() == marker.incident_id
    replay = recovered.prepare_submission(
        marker.incident_id,
        symbol="SPY",
        current_qty=2.0,
        side="sell",
        qty=2.0,
    )
    assert replay.reused is True
    assert replay.client_order_id == client_order_id


def test_operations_dashboard_cannot_bootstrap_empty_live_volume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from streamlit.testing.v1 import AppTest

    runtime = tmp_path / "empty-live-volume"
    database_path = runtime / "auto_trader.sqlite3"
    monkeypatch.setenv("DATABASE_PATH", str(database_path))
    monkeypatch.setenv("KILL_SWITCH_PATH", str(runtime / "KILL_SWITCH"))
    monkeypatch.setenv("KILL_SWITCH_ACK_PATH", str(runtime / "KILL_SWITCH.ack.json"))
    monkeypatch.setenv("BROKER", "alpaca")
    monkeypatch.setenv("ALPACA_PAPER", "false")
    monkeypatch.setenv("EXECUTION_ENABLED", "true")
    monkeypatch.setenv("DASHBOARD_CONTROL_TOKEN", "")

    app = AppTest.from_file(str(PROJECT_ROOT / "bot_dashboard.py")).run(timeout=15)

    assert not app.exception
    assert any("Persistent state is unavailable" in item.value for item in app.error)
    assert not runtime.exists()
    assert not database_path.exists()
    assert not database_path.with_suffix(database_path.suffix + ".identity").exists()


def test_dashboard_kill_works_without_state_and_only_writes_control_volume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from streamlit.testing.v1 import AppTest

    state = tmp_path / "read-only-state"
    control = tmp_path / "writable-control"
    database_path = state / "auto_trader.sqlite3"
    kill_path = control / "KILL_SWITCH"
    monkeypatch.setenv("DATABASE_PATH", str(database_path))
    monkeypatch.setenv("KILL_SWITCH_PATH", str(kill_path))
    monkeypatch.setenv("KILL_SWITCH_ACK_PATH", str(control / "KILL_SWITCH.ack.json"))
    monkeypatch.setenv("DASHBOARD_CONTROL_TOKEN", "test-control-secret")

    app = AppTest.from_file(str(PROJECT_ROOT / "bot_dashboard.py")).run(timeout=15)
    app.text_input[0].input("HALT")
    app.text_input[1].input("test-control-secret")
    app.button[0].click().run(timeout=15)

    assert not app.exception
    request = parse_control_marker(kill_path.read_text(encoding="utf-8"))
    assert request.reason == "dashboard_emergency_halt"
    assert request.flatten is True
    assert not state.exists()
    assert not database_path.exists()
    assert not database_path.with_suffix(database_path.suffix + ".identity").exists()


def test_compose_keeps_emergency_idempotency_journal_bot_only() -> None:
    compose = (PROJECT_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    bot_dockerfile = (PROJECT_ROOT / "Dockerfile.bot").read_text(encoding="utf-8")
    bot_section, remainder = compose.split("  operations-dashboard:", maxsplit=1)
    dashboard_section, _research = remainder.split(
        "  research-dashboard:", maxsplit=1
    )

    assert "EMERGENCY_JOURNAL_PATH: /app/emergency/EMERGENCY_JOURNAL.json" in bot_section
    assert "quant_emergency:/app/emergency" in bot_section
    assert "quant_control:/app/control" in dashboard_section
    assert "quant_emergency" not in dashboard_section
    assert "EMERGENCY_JOURNAL" not in dashboard_section
    assert "mkdir -p /app/runtime /app/state /app/control /app/emergency" in bot_dockerfile


def test_replaced_database_identity_is_rejected(tmp_path: Path) -> None:
    first_path = tmp_path / "first.sqlite3"
    second_path = tmp_path / "second.sqlite3"
    first = StateStore(first_path)
    second = StateStore(second_path)
    second.path.unlink()
    first.path.replace(second.path)

    with pytest.raises(RuntimeError, match="identity does not match"):
        StateStore(second_path)


def test_newer_database_schema_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    StateStore(path)
    with sqlite3.connect(path) as db:
        db.execute(
            "UPDATE store_metadata SET value = ? WHERE key = 'schema_version'",
            (str(SCHEMA_VERSION + 1),),
        )

    with pytest.raises(RuntimeError, match="newer than supported"):
        StateStore(path)


def test_live_execution_refuses_to_initialize_missing_state(tmp_path: Path) -> None:
    config = BotConfig(
        broker="alpaca",
        execution_enabled=True,
        alpaca_paper=False,
        alpaca_api_key="paperless-key",
        alpaca_secret_key="paperless-secret",
        alpaca_account_id="account-test-0001",
        plan_authentication_key=_TEST_PLAN_AUTHENTICATION_KEY,
        emergency_authentication_key=_TEST_EMERGENCY_AUTHENTICATION_KEY,
        live_ack=LIVE_ACK_TEXT,
        dedicated_account=True,
        covariance_evidence_path=tmp_path / "covariance-envelope.json",
        covariance_execution_prices_path=tmp_path / "covariance-vwap.csv",
        covariance_corporate_actions_path=tmp_path / "covariance-actions.csv",
        covariance_public_keys_path=tmp_path / "covariance-keys.json",
        covariance_public_keys_sha256="a" * 64,
        covariance_provider_id="vendor-feed-2026",
        covariance_venue_id="consolidated-us-equities",
        borrow_evidence_path=tmp_path / "borrow-envelope.json",
        borrow_terms_path=tmp_path / "borrow-terms.csv",
        borrow_public_keys_path=tmp_path / "borrow-keys.json",
        borrow_public_keys_sha256="b" * 64,
        borrow_provider_id="borrow-provider-2026",
        borrow_venue_id="consolidated-us-equities",
        database_path=tmp_path / "missing-live-state.sqlite3",
        log_path=tmp_path / "live.log",
    )
    with pytest.raises(RuntimeError, match="refuses to initialize replacement state"):
        build_engine(config)


def test_healthcheck_fails_after_repeated_cycle_errors(tmp_path: Path) -> None:
    config = replace(BotConfig(), health_failure_threshold=3)
    health = {
        "heartbeat": datetime.now(timezone.utc).isoformat(),
        "last_cycle_status": "failed",
        "last_error": "broker unavailable",
        "consecutive_failures": 3,
    }
    with pytest.raises(RuntimeError, match="consecutive broker/cycle failures"):
        _validate_health(config, health)


def test_healthcheck_rejects_stale_heartbeat() -> None:
    config = replace(BotConfig(), poll_seconds=10)
    health = {
        "heartbeat": (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(),
        "last_cycle_status": "ok",
        "consecutive_failures": 0,
    }
    with pytest.raises(RuntimeError, match="heartbeat is stale"):
        _validate_health(config, health)


def test_watchdog_timeout_must_cover_bounded_order_reconciliation() -> None:
    config = replace(
        BotConfig(),
        order_fill_timeout_seconds=300,
        daemon_watchdog_timeout_seconds=900,
    )
    with pytest.raises(ValueError, match="must be at least 1020"):
        config.validate()


class _UnavailableStore:
    def request_halt(self, *_args, **_kwargs):
        raise sqlite3.OperationalError("database unavailable")


class _PositionBroker:
    def __init__(self) -> None:
        self.cancellation_calls = 0

    def get_positions(self):
        return {
            "SPY": PositionSnapshot(
                symbol="SPY", qty=2.0, market_value=1000.0, current_price=500.0
            )
        }

    @staticmethod
    def list_open_orders(_symbols=None):
        return []

    def cancel_orders_and_wait(self, *_args, **_kwargs):
        self.cancellation_calls += 1
        return []


class _OutOfBandEngine:
    def __init__(self, config: BotConfig) -> None:
        self.config = config
        self.store = _UnavailableStore()
        self.broker = _PositionBroker()
        self.logger = logging.getLogger("test_out_of_band_kill")


def test_daemon_recovers_failure_streak_from_db_when_health_sidecar_is_malformed(
    tmp_path: Path,
) -> None:
    config = replace(
        BotConfig(),
        health_failure_threshold=3,
        database_path=tmp_path / "state.sqlite3",
        daemon_health_path=tmp_path / "health.json",
    )
    config.daemon_health_path.write_text('{"consecutive_failures":', encoding="utf-8")
    store = StateStore(config.database_path)
    store.set_state("daemon_consecutive_failures", 2)
    engine = _OutOfBandEngine(config)
    engine.store = store

    daemon = TradingDaemon(engine)  # type: ignore[arg-type]

    assert daemon.consecutive_failures == 2
    assert daemon._failure_recovery_error == ""


def test_invalid_persisted_daemon_failure_streak_trips_mandatory_failsafe(
    tmp_path: Path,
) -> None:
    config = replace(
        BotConfig(),
        execution_enabled=False,
        health_failure_threshold=3,
        database_path=tmp_path / "state.sqlite3",
        kill_switch_path=tmp_path / "KILL_SWITCH",
        kill_switch_ack_path=tmp_path / "KILL_SWITCH.ack.json",
        daemon_health_path=tmp_path / "health.json",
        operation_lock_path=tmp_path / "operation.lock",
    )
    config.daemon_health_path.write_text("not-json", encoding="utf-8")
    store = StateStore(config.database_path)
    store.set_state("daemon_consecutive_failures", True)
    engine = _OutOfBandEngine(config)
    engine.store = store
    daemon = TradingDaemon(engine)  # type: ignore[arg-type]

    assert daemon.consecutive_failures == config.health_failure_threshold
    assert "invalid persisted daemon failure state" in daemon._failure_recovery_error
    with pytest.raises(DaemonHealthThresholdError):
        daemon._trip_health_failsafe(daemon._failure_recovery_error)

    request = parse_control_marker(config.kill_switch_path.read_text(encoding="utf-8"))
    assert request.flatten is True
    assert "daemon_health_failure_threshold" in request.reason


def test_replacement_daemon_cannot_follow_halt_only_marker_after_persisted_escalation(
    tmp_path: Path,
) -> None:
    config = replace(
        BotConfig(),
        database_path=tmp_path / "state.sqlite3",
        kill_switch_path=tmp_path / "KILL_SWITCH",
        daemon_health_path=tmp_path / "health.json",
    )
    config.kill_switch_path.write_text(
        encode_control_marker("operator_pause", flatten=False),
        encoding="utf-8",
    )
    store = StateStore(config.database_path)
    store.request_halt("daemon_health_failure_threshold", flatten=True)
    engine = _OutOfBandEngine(config)
    engine.store = store

    request = TradingDaemon(engine)._kill_request()  # type: ignore[arg-type]

    assert request is not None and request.flatten is True
    assert request.reason == "operator_pause | daemon_health_failure_threshold"


def test_daemon_acknowledges_kill_switch_when_database_is_unavailable(tmp_path: Path) -> None:
    config = replace(
        BotConfig(),
        execution_enabled=False,
        kill_switch_path=tmp_path / "KILL_SWITCH",
        kill_switch_ack_path=tmp_path / "KILL_SWITCH.ack.json",
        daemon_health_path=tmp_path / "health.json",
    )
    config.kill_switch_path.write_text("operator_test\n", encoding="utf-8")
    daemon = TradingDaemon(_OutOfBandEngine(config))  # type: ignore[arg-type]

    result = daemon._observe_kill_switch()

    assert result is not None
    assert result["status"] == "execution_disabled"
    acknowledgement = json.loads(config.kill_switch_ack_path.read_text(encoding="utf-8"))
    assert acknowledgement["reason"] == "operator_test"
    assert daemon.engine.broker.cancellation_calls == 1


def test_structured_halt_only_marker_never_liquidates_positions(tmp_path: Path) -> None:
    broker = _KillReconciliationBroker(position_qty=2.0, manual_open_order=True)
    config = replace(
        BotConfig(),
        execution_enabled=True,
        dedicated_account=True,
        kill_switch_path=tmp_path / "KILL_SWITCH",
        kill_switch_ack_path=tmp_path / "KILL_SWITCH.ack.json",
        daemon_health_path=tmp_path / "health.json",
    )
    config.kill_switch_path.write_text(
        encode_control_marker("operator_pause", flatten=False),
        encoding="utf-8",
    )
    daemon = TradingDaemon(_FallbackKillEngine(config, broker))  # type: ignore[arg-type]

    result = daemon._observe_kill_switch()

    assert result is not None and result["status"] == "halt_only"
    assert result["flatten_requested"] is False
    assert broker.get_positions()["SPY"].qty == pytest.approx(2.0)
    assert broker.list_open_orders(None) == []
    assert result["canceled_orders"] == ["manual-client-order"]


def test_malformed_structured_marker_fails_safe_to_flatten(tmp_path: Path) -> None:
    broker = _KillReconciliationBroker(position_qty=2.0)
    daemon = _fallback_kill_daemon(tmp_path, broker)
    daemon.config.kill_switch_path.write_text('{"flatten":false', encoding="utf-8")

    result = daemon._observe_kill_switch()

    assert result is not None and result["status"] == "flattened"
    assert result["reason"] == "malformed_filesystem_kill_switch"
    assert broker.get_positions() == {}


def test_liveness_watchdog_escalates_existing_incident_and_exits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = replace(
        BotConfig(),
        kill_switch_path=tmp_path / "KILL_SWITCH",
        kill_switch_ack_path=tmp_path / "KILL_SWITCH.ack.json",
        daemon_health_path=tmp_path / "health.json",
    )
    config.kill_switch_path.write_text(
        encode_control_marker("operator_pause", flatten=False),
        encoding="utf-8",
    )
    config.kill_switch_ack_path.write_text("stale acknowledgement\n", encoding="utf-8")
    daemon = TradingDaemon(_OutOfBandEngine(config))  # type: ignore[arg-type]

    def fake_exit(code: int) -> None:
        raise SystemExit(code)

    monkeypatch.setattr(os, "_exit", fake_exit)
    with pytest.raises(SystemExit) as exc_info:
        daemon._force_restart_for_stall(901.5)

    assert exc_info.value.code == 70
    request = parse_control_marker(config.kill_switch_path.read_text(encoding="utf-8"))
    assert request.flatten is True
    assert request.reason == "operator_pause | daemon_liveness_watchdog_timeout"
    assert not config.kill_switch_ack_path.exists()
    health = json.loads(config.daemon_health_path.read_text(encoding="utf-8"))
    assert health["last_cycle_status"] == "watchdog_timeout"
    assert health["watchdog_elapsed_seconds"] == 901.5


def test_watchdog_marker_failure_remains_failsafe_across_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = replace(
        BotConfig(),
        health_failure_threshold=3,
        database_path=tmp_path / "state.sqlite3",
        kill_switch_path=tmp_path / "KILL_SWITCH",
        kill_switch_ack_path=tmp_path / "KILL_SWITCH.ack.json",
        daemon_health_path=tmp_path / "health.json",
    )
    engine = _OutOfBandEngine(config)
    engine.store = StateStore(config.database_path)
    daemon = TradingDaemon(engine)  # type: ignore[arg-type]

    def marker_failure(*_args, **_kwargs):
        raise OSError("control volume unavailable")

    def fake_exit(code: int) -> None:
        raise SystemExit(code)

    monkeypatch.setattr("auto_trader.daemon.merge_control_marker", marker_failure)
    monkeypatch.setattr(os, "_exit", fake_exit)
    with pytest.raises(SystemExit) as exc_info:
        daemon._force_restart_for_stall(901.5)

    assert exc_info.value.code == 70
    assert not config.kill_switch_path.exists()
    health = json.loads(config.daemon_health_path.read_text(encoding="utf-8"))
    assert health["last_cycle_status"] == "watchdog_timeout"
    assert health["consecutive_failures"] == config.health_failure_threshold
    assert "kill marker persistence failed" in health["last_error"]

    replacement_engine = _OutOfBandEngine(config)
    replacement_engine.store = engine.store
    replacement = TradingDaemon(replacement_engine)  # type: ignore[arg-type]
    assert replacement.consecutive_failures == config.health_failure_threshold
    assert "watchdog_timeout" in replacement._failure_recovery_error


class _KillReconciliationBroker:
    def __init__(
        self,
        *,
        position_qty: float = 0.0,
        manual_open_order: bool = False,
        apply_fill: bool = True,
    ) -> None:
        self.positions = (
            {
                "SPY": PositionSnapshot(
                    symbol="SPY",
                    qty=position_qty,
                    market_value=position_qty * 500.0,
                    current_price=500.0,
                )
            }
            if position_qty
            else {}
        )
        self.orders: dict[str, OrderReceipt] = {}
        self.apply_fill = apply_fill
        self.cancel_scopes: list[tuple[list[str] | None, str | None]] = []
        self.get_order_calls = 0
        if manual_open_order:
            self.orders["manual-open"] = OrderReceipt(
                broker_order_id="manual-open",
                client_order_id="manual-client-order",
                symbol="SPY",
                qty=1.0,
                side="buy",
                status="accepted",
                submitted_at=datetime.now(timezone.utc),
            )

    def get_positions(self):
        return dict(self.positions)

    def list_open_orders(self, symbols=None):
        allowed = set(symbols) if symbols else None
        return [
            receipt
            for receipt in self.orders.values()
            if receipt.status not in {"filled", "canceled", "rejected"}
            and (allowed is None or receipt.symbol in allowed)
        ]

    def cancel_orders_and_wait(
        self,
        symbols,
        *,
        client_prefix,
        timeout_seconds,
        poll_seconds,
    ):
        del timeout_seconds, poll_seconds
        self.cancel_scopes.append((symbols, client_prefix))
        canceled = []
        for order_id, receipt in list(self.orders.items()):
            if symbols is not None and receipt.symbol not in set(symbols):
                continue
            if client_prefix is not None and not receipt.client_order_id.startswith(
                client_prefix
            ):
                continue
            if receipt.status in {"filled", "canceled", "rejected"}:
                continue
            current = replace(receipt, status="canceled")
            self.orders[order_id] = current
            canceled.append(current)
        return canceled

    def submit_emergency_market_order(
        self,
        symbol: str,
        qty: float,
        side: OrderSide,
        client_order_id: str,
    ) -> OrderReceipt:
        existing = next(
            (
                receipt
                for receipt in self.orders.values()
                if receipt.client_order_id == client_order_id
            ),
            None,
        )
        if existing is not None:
            return existing
        order_id = f"emergency-{len(self.orders)}"
        receipt = OrderReceipt(
            broker_order_id=order_id,
            client_order_id=client_order_id,
            symbol=symbol,
            qty=qty,
            side=side.value,
            status="accepted",
            submitted_at=datetime.now(timezone.utc),
        )
        self.orders[order_id] = receipt
        return receipt

    def get_order(self, broker_order_id: str) -> OrderReceipt:
        self.get_order_calls += 1
        receipt = self.orders[broker_order_id]
        filled = replace(
            receipt,
            status="filled",
            filled_qty=receipt.qty,
            filled_avg_price=500.0,
        )
        self.orders[broker_order_id] = filled
        if self.apply_fill:
            self.positions.pop(receipt.symbol, None)
        return filled

    def cancel_order_and_wait(self, broker_order_id: str, **_kwargs) -> OrderReceipt:
        receipt = replace(self.orders[broker_order_id], status="canceled")
        self.orders[broker_order_id] = receipt
        return receipt


class _FallbackKillEngine:
    def __init__(self, config: BotConfig, broker: _KillReconciliationBroker) -> None:
        self.config = config
        self.store = _UnavailableStore()
        self.broker = broker
        self.logger = logging.getLogger("test_fallback_kill")

    @staticmethod
    def emergency_flatten(*_args, **_kwargs):
        raise sqlite3.OperationalError("database-backed flatten unavailable")


def _fallback_kill_daemon(
    tmp_path: Path, broker: _KillReconciliationBroker
) -> TradingDaemon:
    config = replace(
        BotConfig(),
        execution_enabled=True,
        dedicated_account=True,
        order_fill_timeout_seconds=1,
        order_poll_seconds=1,
        kill_switch_path=tmp_path / "KILL_SWITCH",
        kill_switch_ack_path=tmp_path / "KILL_SWITCH.ack.json",
        daemon_health_path=tmp_path / "health.json",
    )
    config.kill_switch_path.write_text("operator_emergency\n", encoding="utf-8")
    return TradingDaemon(_FallbackKillEngine(config, broker))  # type: ignore[arg-type]


def test_dedicated_kill_cancels_manual_order_before_acknowledging_flat(
    tmp_path: Path,
) -> None:
    broker = _KillReconciliationBroker(manual_open_order=True)
    daemon = _fallback_kill_daemon(tmp_path, broker)

    result = daemon._observe_kill_switch()

    assert result is not None
    assert result["status"] == "flattened"
    assert broker.cancel_scopes[0] == (None, None)
    assert broker.list_open_orders(None) == []
    acknowledgement = json.loads(
        daemon.config.kill_switch_ack_path.read_text(encoding="utf-8")
    )
    assert acknowledgement["status"] == "flattened"


def test_broker_only_kill_waits_for_terminal_fill_and_final_flat_snapshot(
    tmp_path: Path,
) -> None:
    broker = _KillReconciliationBroker(position_qty=2.0)
    daemon = _fallback_kill_daemon(tmp_path, broker)

    result = daemon._observe_kill_switch()

    assert result is not None
    assert result["status"] == "flattened"
    assert broker.get_order_calls >= 1
    assert broker.get_positions() == {}
    assert broker.list_open_orders(None) == []
    assert set(result["terminal_orders"].values()) == {"filled"}


def test_health_threshold_durably_halts_flattens_and_forces_restart(
    tmp_path: Path,
) -> None:
    broker = _KillReconciliationBroker(position_qty=2.0)
    config = replace(
        BotConfig(),
        execution_enabled=True,
        dedicated_account=True,
        health_failure_threshold=1,
        order_fill_timeout_seconds=1,
        order_poll_seconds=1,
        kill_switch_path=tmp_path / "KILL_SWITCH",
        kill_switch_ack_path=tmp_path / "KILL_SWITCH.ack.json",
        daemon_health_path=tmp_path / "health.json",
        operation_lock_path=tmp_path / "operation.lock",
    )
    daemon = TradingDaemon(_FallbackKillEngine(config, broker))  # type: ignore[arg-type]

    with pytest.raises(DaemonHealthThresholdError, match="forces restart|cycle failures"):
        daemon._record_cycle_failure("broker unavailable")

    request = parse_control_marker(config.kill_switch_path.read_text(encoding="utf-8"))
    assert request.flatten is True
    assert request.reason == "daemon_health_failure_threshold"
    assert broker.get_positions() == {}
    acknowledgement = json.loads(config.kill_switch_ack_path.read_text(encoding="utf-8"))
    assert acknowledgement["reason"] == "daemon_health_failure_threshold"
    assert acknowledgement["status"] == "flattened"
    health = json.loads(config.daemon_health_path.read_text(encoding="utf-8"))
    assert health["last_cycle_status"] == "failsafe_triggered"
    assert health["consecutive_failures"] >= 1


def test_health_threshold_escalates_operator_halt_only_before_reconciliation(
    tmp_path: Path,
) -> None:
    broker = _KillReconciliationBroker(position_qty=2.0)
    config = replace(
        BotConfig(),
        execution_enabled=True,
        dedicated_account=True,
        health_failure_threshold=1,
        kill_switch_path=tmp_path / "KILL_SWITCH",
        kill_switch_ack_path=tmp_path / "KILL_SWITCH.ack.json",
        daemon_health_path=tmp_path / "health.json",
        operation_lock_path=tmp_path / "operation.lock",
    )
    config.kill_switch_path.write_text(
        encode_control_marker("operator_pause", flatten=False),
        encoding="utf-8",
    )
    daemon = TradingDaemon(_FallbackKillEngine(config, broker))  # type: ignore[arg-type]

    with pytest.raises(DaemonHealthThresholdError):
        daemon._record_cycle_failure("broker unavailable")

    request = parse_control_marker(config.kill_switch_path.read_text(encoding="utf-8"))
    assert request.flatten is True
    assert request.reason == "operator_pause | daemon_health_failure_threshold"
    acknowledgement = json.loads(config.kill_switch_ack_path.read_text(encoding="utf-8"))
    assert acknowledgement["reason"] == request.reason
    assert acknowledgement["status"] == "flattened"
    assert broker.get_positions() == {}


def test_kill_does_not_acknowledge_ambiguous_fill_and_unchanged_position(
    tmp_path: Path,
) -> None:
    broker = _KillReconciliationBroker(position_qty=2.0, apply_fill=False)
    daemon = _fallback_kill_daemon(tmp_path, broker)

    with pytest.raises(RuntimeError, match="did not show sufficient directional progress"):
        daemon._observe_kill_switch()

    assert not daemon.config.kill_switch_ack_path.exists()


def test_execution_disabled_kill_still_cancels_account_orders(tmp_path: Path) -> None:
    broker = _KillReconciliationBroker(manual_open_order=True)
    config = replace(
        BotConfig(),
        execution_enabled=False,
        dedicated_account=True,
        kill_switch_path=tmp_path / "KILL_SWITCH",
        kill_switch_ack_path=tmp_path / "KILL_SWITCH.ack.json",
        daemon_health_path=tmp_path / "health.json",
    )
    config.kill_switch_path.write_text("operator_cancel_only\n", encoding="utf-8")
    daemon = TradingDaemon(_FallbackKillEngine(config, broker))  # type: ignore[arg-type]

    result = daemon._observe_kill_switch()

    assert result is not None
    assert result["status"] == "already_flat"
    assert broker.cancel_scopes == [(None, None), (None, None)]
    assert broker.list_open_orders(None) == []


def test_broker_only_restart_reuses_incident_order_id_without_duplicate_submission(
    tmp_path: Path,
) -> None:
    broker = _KillReconciliationBroker(position_qty=2.0, apply_fill=False)
    daemon = _fallback_kill_daemon(tmp_path, broker)

    with pytest.raises(RuntimeError, match="directional progress"):
        daemon._observe_kill_switch()
    first_client_ids = {receipt.client_order_id for receipt in broker.orders.values()}
    assert len(first_client_ids) == 1

    # A replacement process observes the same persistent marker. The stable incident
    # identity resolves the accepted terminal broker order instead of submitting a
    # second close from the lagging position snapshot.
    restarted = TradingDaemon(
        _FallbackKillEngine(daemon.config, broker)  # type: ignore[arg-type]
    )
    with pytest.raises(RuntimeError, match="directional progress"):
        restarted._observe_kill_switch()

    assert {receipt.client_order_id for receipt in broker.orders.values()} == first_client_ids
    assert len(broker.orders) == 1


def test_broker_only_fallback_reuses_active_id_after_marker_uuid_rewrite(
    tmp_path: Path,
) -> None:
    broker = _KillReconciliationBroker(position_qty=2.0, apply_fill=False)
    daemon = _fallback_kill_daemon(tmp_path, broker)

    with pytest.raises(RuntimeError, match="directional progress"):
        daemon._observe_kill_switch()
    first_client_ids = {receipt.client_order_id for receipt in broker.orders.values()}
    assert len(first_client_ids) == 1

    daemon.config.kill_switch_path.write_text(
        encode_control_marker(
            "rewritten_during_ambiguous_fill",
            flatten=True,
            incident_id=str(uuid4()),
        ),
        encoding="utf-8",
    )
    restarted = TradingDaemon(
        _FallbackKillEngine(daemon.config, broker)  # type: ignore[arg-type]
    )

    with pytest.raises(RuntimeError, match="directional progress"):
        restarted._observe_kill_switch()

    rebound = parse_control_marker(
        daemon.config.kill_switch_path.read_text(encoding="utf-8")
    )
    assert {receipt.client_order_id for receipt in broker.orders.values()} == first_client_ids
    assert len(broker.orders) == 1
    assert rebound.incident_id is not None
    assert next(iter(first_client_ids)).startswith(
        "qauto-emg-" + rebound.incident_id.replace("-", "")[:8]
    )


def test_broker_only_kill_never_acknowledges_nonfinite_position_quantity(
    tmp_path: Path,
) -> None:
    broker = _KillReconciliationBroker()
    broker.positions["SPY"] = PositionSnapshot(
        "SPY", float("nan"), float("nan"), 500.0
    )
    daemon = _fallback_kill_daemon(tmp_path, broker)

    with pytest.raises(RuntimeError, match="non-finite position quantities"):
        daemon._observe_kill_switch()

    assert not daemon.config.kill_switch_ack_path.exists()


class _MemoryStore:
    def __init__(self) -> None:
        self.state: dict[str, object] = {}
        self.events: list[tuple] = []

    def get_state(self, key: str, default=None):
        return self.state.get(key, default)

    def set_state(self, key: str, value) -> None:
        self.state[key] = value

    def record_event(self, *args, **_kwargs) -> None:
        self.events.append(args)


class _ClockBroker:
    def __init__(self, timestamp: datetime) -> None:
        self.timestamp = timestamp

    def get_market_clock(self) -> MarketClock:
        return MarketClock(
            timestamp=self.timestamp,
            is_open=True,
            next_open=self.timestamp + timedelta(days=1),
            next_close=self.timestamp.replace(hour=16),
        )


class _PartialExecutionEngine:
    def __init__(self, config: BotConfig, timestamp: datetime) -> None:
        self.config = config
        self.store = _MemoryStore()
        self.broker = _ClockBroker(timestamp)
        self.logger = logging.getLogger("test_partial_scheduler")

    @staticmethod
    def _local_time(value: datetime) -> datetime:
        return value

    @staticmethod
    def recover_incomplete_execution() -> bool:
        return False

    @staticmethod
    def monitor() -> RiskDecision:
        return RiskDecision(True, False, False, "ok", 0.0, 0.0, 0.0)

    @staticmethod
    def generate_plan():  # pragma: no cover - plan is deliberately not due
        raise AssertionError("plan generation should not be due")

    @staticmethod
    def execute_latest_plan() -> ExecutionSummary:
        return ExecutionSummary(
            plan_id="partial-plan",
            status="partial",
            submitted_orders=2,
            filled_orders=1,
            residual_notional=500.0,
            message="residual exposure remains",
        )


def test_scheduler_does_not_mark_partial_live_execution_success(tmp_path: Path) -> None:
    timestamp = datetime(2026, 7, 10, 9, 40, tzinfo=timezone.utc)
    config = replace(
        BotConfig(),
        execution_enabled=True,
        plan_time=time(23, 59),
        execution_time=time(9, 35),
        execution_window_minutes=25,
        daemon_health_path=tmp_path / "health.json",
    )
    engine = _PartialExecutionEngine(config, timestamp)
    daemon = TradingDaemon(engine)  # type: ignore[arg-type]

    errors = daemon._run_cycle()

    assert errors == [
        "scheduled_execution: reconciliation incomplete with status partial: residual exposure remains"
    ]
    assert "scheduler_last_execution_success" not in engine.store.state
    assert any(event[1] == "SCHEDULED_EXECUTION_INCOMPLETE" for event in engine.store.events)


def test_scheduler_never_starts_or_retries_routine_execution_at_0935(
    tmp_path: Path,
) -> None:
    timestamp = datetime(2026, 7, 10, 9, 35, tzinfo=timezone.utc)
    config = replace(
        BotConfig(),
        execution_enabled=True,
        plan_time=time(23, 59),
        execution_time=time(9, 30),
        execution_window_minutes=5,
        daemon_health_path=tmp_path / "deadline-health.json",
    )
    engine = _PartialExecutionEngine(config, timestamp)
    called = False

    def execute_latest_plan() -> ExecutionSummary:
        nonlocal called
        called = True
        raise AssertionError("09:35 is an exclusive scheduler boundary")

    engine.execute_latest_plan = execute_latest_plan  # type: ignore[method-assign]
    errors = TradingDaemon(engine)._run_cycle()  # type: ignore[arg-type]

    assert errors == []
    assert called is False
