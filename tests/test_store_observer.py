from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

import pytest

from auto_trader.models import AccountSnapshot, OrderReceipt, TargetPlan
from auto_trader.store import (
    AUTHENTICATION_INVENTORY_SCHEMA_VERSION,
    SCHEMA_VERSION,
    StateStore,
)
from datetime import date, datetime, timezone


def test_read_only_observer_and_writer_serialize_without_write_failure(
    tmp_path: Path,
) -> None:
    """A short dashboard read may delay, but must not break, a daemon commit."""
    path = tmp_path / "state.sqlite3"
    writer = StateStore(path)
    writer.set_state("value", 1)
    observer = StateStore.open_read_only(path)

    with ThreadPoolExecutor(max_workers=1) as executor:
        with observer.connection() as read_connection:
            read_connection.execute("BEGIN")
            assert read_connection.execute(
                "SELECT value FROM state WHERE key = 'value'"
            ).fetchone() is not None
            pending_write = executor.submit(writer.set_state, "value", 2)
            time.sleep(0.1)
            assert not pending_write.done()

        pending_write.result(timeout=5)

    assert observer.get_state("value") == 2


def test_authenticated_state_and_equity_rows_reject_validly_formed_sql_rewrites(
    tmp_path: Path,
) -> None:
    key = bytes(range(32))
    store = StateStore(tmp_path / "authenticated.sqlite3", authentication_key=key)
    store.set_state("halt", {"active": True, "reason": "risk", "flatten": True})
    store.record_equity(
        AccountSnapshot(
            timestamp=datetime(2026, 7, 13, 15, 0, tzinfo=timezone.utc),
            equity=100_000.0,
            cash=50_000.0,
            buying_power=100_000.0,
            last_equity=100_000.0,
            external_cash_activities=(),
        ),
        date(2026, 7, 13),
        drawdown=0.0,
        daily_return=0.0,
        five_day_return=0.0,
    )

    with store.connection() as db:
        db.execute(
            "UPDATE state SET value = ? WHERE key = 'halt'",
            ('{"active":false,"reason":"forged"}',),
        )
        db.execute(
            "UPDATE equity_snapshots SET equity = 200000 WHERE session_date = ?",
            ("2026-07-13",),
        )

    with pytest.raises(
        (ValueError, RuntimeError), match="keyed authentication|external checkpoint"
    ):
        store.halt_state()
    store.request_halt("tamper_recovered", flatten=True)
    with pytest.raises(ValueError, match="keyed authentication"):
        store.get_session_open_equity(date(2026, 7, 13))

    # A read-only observer can display state without receiving the HMAC secret, while
    # the trading process remains the enforcement boundary.
    observer = StateStore.open_read_only(store.path)
    assert observer.get_state("halt")["active"] is True


def test_authenticated_monotonic_halt_update_refreshes_mac_and_recovers_tampering(
    tmp_path: Path,
) -> None:
    store = StateStore(
        tmp_path / "authenticated-halt.sqlite3",
        authentication_key=bytes(range(32)),
    )
    store.clear_halt()
    store.request_halt("operator_halt", flatten=False)
    halt = store.halt_state()
    assert halt["active"] is True
    assert halt["flatten"] is False

    with store.connection() as db:
        db.execute(
            "UPDATE state SET value = ? WHERE key = 'halt'",
            ('{"active":true,"flatten":false,"reason":"forged"}',),
        )

    # A control writer must be able to recover a corrupt latch, but it must fail
    # closed to mandatory flattening and replace it with a newly authenticated row.
    store.request_halt("health_failsafe", flatten=False)
    recovered = store.halt_state()
    assert recovered["active"] is True
    assert recovered["flatten"] is True
    assert recovered["recovered_invalid_prior_state"] is True


def test_plan_only_schema_upgrade_authenticates_existing_state(tmp_path: Path) -> None:
    path = tmp_path / "upgrade.sqlite3"
    legacy = StateStore(path)
    legacy.set_state("high_watermark", 100_000.0)
    with legacy.connection() as db:
        db.execute(
            "UPDATE store_metadata SET value = '1' WHERE key = 'schema_version'"
        )
        db.execute("UPDATE state SET value_mac = ''")

    authenticated = StateStore(path, authentication_key=b"a" * 32)
    assert authenticated.get_state("high_watermark") == 100_000.0
    with authenticated.connection() as db:
        version = db.execute(
            "SELECT value FROM store_metadata WHERE key = 'schema_version'"
        ).fetchone()[0]
        value_mac = db.execute(
            "SELECT value_mac FROM state WHERE key = 'high_watermark'"
        ).fetchone()[0]
    assert version == str(SCHEMA_VERSION)
    assert len(value_mac) == 64


def test_external_checkpoint_rejects_valid_row_replay_and_deletion(tmp_path: Path) -> None:
    key = b"c" * 32
    store = StateStore(tmp_path / "checkpoint.sqlite3", authentication_key=key)
    store.clear_halt()
    store.set_state("cooldown_remaining", 20)
    with store.connection() as db:
        inactive = db.execute(
            "SELECT value, value_mac FROM state WHERE key = 'halt'"
        ).fetchone()

    store.request_halt("mandatory_incident", flatten=True)
    with store.connection() as db:
        db.execute(
            "UPDATE state SET value = ?, value_mac = ? WHERE key = 'halt'",
            (inactive["value"], inactive["value_mac"]),
        )
    with pytest.raises(RuntimeError, match="external checkpoint"):
        store.halt_state()

    # The only safe automatic recovery is to replace a halt-only mismatch with a
    # newly authenticated mandatory halt. Other rollback/deletion is never blessed.
    store.request_halt("replay_detected", flatten=False)
    assert store.halt_state()["flatten"] is True

    with store.connection() as db:
        db.execute("DELETE FROM state WHERE key = 'cooldown_remaining'")
    with pytest.raises(RuntimeError, match="external checkpoint"):
        store.cooldown_remaining()


def test_plan_lifecycle_is_authenticated_and_terminal_transitions_are_monotonic(
    tmp_path: Path,
) -> None:
    store = StateStore(
        tmp_path / "lifecycle.sqlite3", authentication_key=b"d" * 32
    )
    plan = TargetPlan(
        plan_id="plan-authenticated-lifecycle",
        as_of=date(2026, 7, 10),
        created_at=datetime(2026, 7, 10, 20, 0, tzinfo=timezone.utc),
        regime="neutral",
        regime_multiplier=1.0,
        desired_gross=0.5,
        forecast_volatility=0.1,
        target_weights={"SPY": 0.1},
        metadata={},
    )
    assert store.save_plan(plan)
    store.mark_plan_status(plan.plan_id, "executing")
    store.mark_plan_status(plan.plan_id, "executed")
    with pytest.raises(ValueError, match="forbidden"):
        store.mark_plan_status(plan.plan_id, "approved")

    with store.connection() as db:
        db.execute(
            "UPDATE plans SET status = 'approved' WHERE plan_id = ?", (plan.plan_id,)
        )
    with pytest.raises(RuntimeError, match="external checkpoint"):
        store.latest_plan(statuses=("approved",))


def test_wrong_state_key_cannot_open_or_reanchor_existing_database(tmp_path: Path) -> None:
    path = tmp_path / "wrong-key.sqlite3"
    original = StateStore(path, authentication_key=b"e" * 32)
    original.clear_halt()

    with pytest.raises(RuntimeError, match="keyed verification"):
        StateStore(path, authentication_key=b"f" * 32)


def test_equity_chain_and_checkpoint_reject_history_deletion(tmp_path: Path) -> None:
    store = StateStore(
        tmp_path / "equity-chain.sqlite3", authentication_key=b"g" * 32
    )
    for day, equity in ((13, 100_000.0), (14, 99_000.0)):
        store.record_equity(
            AccountSnapshot(
                timestamp=datetime(2026, 7, day, 15, 0, tzinfo=timezone.utc),
                equity=equity,
                cash=equity,
                buying_power=equity,
                last_equity=100_000.0,
                external_cash_activities=(),
            ),
            date(2026, 7, day),
            drawdown=equity / 100_000.0 - 1.0,
            daily_return=0.0,
            five_day_return=0.0,
        )
    with store.connection() as db:
        db.execute("DELETE FROM equity_snapshots WHERE session_date = '2026-07-13'")

    with pytest.raises(RuntimeError, match="external checkpoint"):
        store.get_daily_closing_equities()
    with pytest.raises(RuntimeError, match="external checkpoint"):
        store.request_halt("equity_history_tamper", flatten=True)


def _seed_authenticated_operational_history(
    tmp_path: Path,
) -> tuple[StateStore, str, OrderReceipt]:
    store = StateStore(
        tmp_path / "operational-auth.sqlite3", authentication_key=b"h" * 32
    )
    run_id = store.start_run("execute", {"plan_id": "plan-1"})
    store.record_event("info", "RUN_STARTED", "execution started", {"run_id": run_id})
    accepted = OrderReceipt(
        broker_order_id="broker-order-1",
        client_order_id="client-order-1",
        symbol="SPY",
        qty=3.0,
        side="buy",
        status="accepted",
        submitted_at=datetime(2026, 7, 13, 15, 0, tzinfo=timezone.utc),
        raw={"status": "accepted"},
    )
    store.record_order(None, "rebalance", accepted)
    store.finish_run(run_id, "success", "execution complete", {"orders": 1})
    store.record_order(
        None,
        "rebalance",
        replace(
            accepted,
            status="filled",
            filled_qty=3.0,
            filled_avg_price=625.25,
            raw={"status": "filled"},
        ),
    )
    store.verify_authentication_anchor()
    return store, run_id, accepted


@pytest.mark.parametrize(
    ("table", "rewrite"),
    (
        ("orders", "UPDATE orders SET status = 'canceled'"),
        ("events", "UPDATE events SET code = 'FORGED_EVENT'"),
        ("runs", "UPDATE runs SET status = 'running', ended_at = NULL"),
    ),
)
def test_operational_checkpoint_rejects_in_place_row_mutation(
    tmp_path: Path, table: str, rewrite: str
) -> None:
    store, _, _ = _seed_authenticated_operational_history(tmp_path)

    with store.connection() as db:
        db.execute(rewrite)

    with pytest.raises(RuntimeError, match="external checkpoint"):
        store.verify_authentication_anchor()


@pytest.mark.parametrize("table", ("orders", "events", "runs"))
def test_operational_checkpoint_rejects_row_deletion(
    tmp_path: Path, table: str
) -> None:
    store, _, _ = _seed_authenticated_operational_history(tmp_path)

    with store.connection() as db:
        db.execute(f"DELETE FROM {table}")

    with pytest.raises(RuntimeError, match="external checkpoint"):
        store.verify_authentication_anchor()


@pytest.mark.parametrize("table", ("orders", "events", "runs"))
def test_operational_checkpoint_rejects_valid_prior_state_replay(
    tmp_path: Path, table: str
) -> None:
    store = StateStore(
        tmp_path / f"{table}-replay.sqlite3", authentication_key=b"i" * 32
    )

    if table == "orders":
        accepted = OrderReceipt(
            broker_order_id="broker-order-replay",
            client_order_id="client-order-replay",
            symbol="QQQ",
            qty=2.0,
            side="sell",
            status="accepted",
            submitted_at=datetime(2026, 7, 13, 15, 0, tzinfo=timezone.utc),
            raw={"status": "accepted"},
        )
        store.record_order(None, "rebalance", accepted)
        with store.connection() as db:
            prior = dict(db.execute("SELECT * FROM orders").fetchone())
        store.record_order(
            None,
            "rebalance",
            replace(
                accepted,
                status="filled",
                filled_qty=2.0,
                filled_avg_price=510.0,
                raw={"status": "filled"},
            ),
        )
        with store.connection() as db:
            db.execute(
                """
                UPDATE orders SET broker_order_id = ?, status = ?, updated_at = ?,
                    filled_qty = ?, filled_avg_price = ?, raw_json = ?
                WHERE client_order_id = ?
                """,
                (
                    prior["broker_order_id"],
                    prior["status"],
                    prior["updated_at"],
                    prior["filled_qty"],
                    prior["filled_avg_price"],
                    prior["raw_json"],
                    prior["client_order_id"],
                ),
            )
    elif table == "events":
        store.record_event("info", "FIRST", "first event")
        with store.connection() as db:
            prior_tail = int(db.execute("SELECT MAX(id) FROM events").fetchone()[0])
        store.record_event("info", "SECOND", "second event")
        with store.connection() as db:
            db.execute("DELETE FROM events WHERE id > ?", (prior_tail,))
    else:
        run_id = store.start_run("monitor", {"attempt": 1})
        with store.connection() as db:
            prior = dict(
                db.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
            )
        store.finish_run(run_id, "success", "done", {"attempt": 1})
        with store.connection() as db:
            db.execute(
                """
                UPDATE runs SET ended_at = ?, status = ?, message = ?, payload_json = ?
                WHERE run_id = ?
                """,
                (
                    prior["ended_at"],
                    prior["status"],
                    prior["message"],
                    prior["payload_json"],
                    run_id,
                ),
            )

    with pytest.raises(RuntimeError, match="external checkpoint"):
        store.verify_authentication_anchor()


def _replace_checkpoint_with_valid_v1_anchor(store: StateStore) -> None:
    inventory = store._authentication_inventory(schema_version=1)
    document = {
        **inventory,
        "anchor_hmac_sha256": store._authentication_anchor_hmac(inventory),
    }
    store.authentication_anchor_path.write_text(
        json.dumps(document, allow_nan=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def test_empty_legacy_authentication_inventory_upgrades_only_after_verification(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-empty.sqlite3"
    key = b"j" * 32
    store = StateStore(path, authentication_key=key)
    store.set_state("cooldown_remaining", 3)
    _replace_checkpoint_with_valid_v1_anchor(store)

    reopened = StateStore(path, authentication_key=key)

    checkpoint = json.loads(reopened.authentication_anchor_path.read_text(encoding="utf-8"))
    assert checkpoint["schema_version"] == AUTHENTICATION_INVENTORY_SCHEMA_VERSION
    assert set(checkpoint["operational_table_macs"]) == {"orders", "events", "runs"}
    reopened.verify_authentication_anchor()


def test_nonempty_legacy_operational_history_is_never_silently_baselined(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-nonempty.sqlite3"
    key = b"k" * 32
    store = StateStore(path, authentication_key=key)
    store.record_event("warning", "LEGACY", "previously unauthenticated history")
    _replace_checkpoint_with_valid_v1_anchor(store)

    with pytest.raises(RuntimeError, match="Refusing to bless it automatically"):
        StateStore(path, authentication_key=key)

    checkpoint = json.loads(store.authentication_anchor_path.read_text(encoding="utf-8"))
    assert checkpoint["schema_version"] == 1


def test_invalid_legacy_checkpoint_fails_before_empty_history_upgrade(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy-tampered.sqlite3"
    key = b"l" * 32
    store = StateStore(path, authentication_key=key)
    store.set_state("cooldown_remaining", 7)
    _replace_checkpoint_with_valid_v1_anchor(store)
    with store.connection() as db:
        db.execute(
            "UPDATE state SET value = '0' WHERE key = 'cooldown_remaining'"
        )

    with pytest.raises(RuntimeError, match="external checkpoint"):
        StateStore(path, authentication_key=key)

    checkpoint = json.loads(store.authentication_anchor_path.read_text(encoding="utf-8"))
    assert checkpoint["schema_version"] == 1


@pytest.mark.parametrize(
    "tamper",
    (
        "UPDATE orders SET status = 'canceled'",
        "UPDATE events SET code = 'FORGED_EVENT'",
        "UPDATE runs SET status = 'running', ended_at = NULL",
    ),
)
def test_monotonic_halt_recovery_never_blesses_operational_table_tampering(
    tmp_path: Path, tamper: str
) -> None:
    store, _, _ = _seed_authenticated_operational_history(tmp_path)
    with store.connection() as db:
        db.execute(tamper)

    with pytest.raises(RuntimeError, match="external checkpoint"):
        store.request_halt("tamper_detected", flatten=True)

    with pytest.raises(RuntimeError, match="external checkpoint"):
        store.verify_authentication_anchor()


def test_concurrent_operational_writers_leave_one_complete_valid_checkpoint(
    tmp_path: Path,
) -> None:
    store = StateStore(
        tmp_path / "concurrent-operational.sqlite3", authentication_key=b"m" * 32
    )

    def record(index: int) -> None:
        store.record_event("info", f"EVENT_{index}", "concurrent writer")

    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(record, range(12)))

    store.verify_authentication_anchor()
    assert len(store.recent_events(limit=20)) == 12


def test_committed_database_successor_recovers_when_anchor_promotion_crashes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "post-commit-crash.sqlite3"
    key = b"n" * 32
    store = StateStore(path, authentication_key=key)
    original_anchor = store.authentication_anchor_path.read_bytes()

    def crash_before_promotion() -> None:
        raise RuntimeError("simulated post-commit crash")

    monkeypatch.setattr(
        store, "_promote_staged_authentication_anchor", crash_before_promotion
    )
    with pytest.raises(RuntimeError, match="post-commit crash"):
        store.record_event("warning", "COMMITTED", "database commit survived")

    assert store.authentication_anchor_path.read_bytes() == original_anchor
    assert store.authentication_pending_path.exists()
    reopened = StateStore(path, authentication_key=key)
    assert reopened.recent_events(5)[0]["code"] == "COMMITTED"
    assert not reopened.authentication_pending_path.exists()
    reopened.verify_authentication_anchor()


def test_promoted_anchor_recovers_when_pending_cleanup_crashes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "post-promotion-crash.sqlite3"
    key = b"o" * 32
    store = StateStore(path, authentication_key=key)

    def crash_before_cleanup() -> None:
        raise RuntimeError("simulated post-promotion crash")

    monkeypatch.setattr(
        store, "_remove_pending_authentication_transition", crash_before_cleanup
    )
    with pytest.raises(RuntimeError, match="post-promotion crash"):
        store.record_event("info", "PROMOTED", "anchor replacement survived")

    assert store.authentication_pending_path.exists()
    reopened = StateStore(path, authentication_key=key)
    assert reopened.recent_events(5)[0]["code"] == "PROMOTED"
    assert not reopened.authentication_pending_path.exists()
    reopened.verify_authentication_anchor()


def test_rolled_back_database_discards_precommit_pending_successor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "precommit-crash.sqlite3"
    key = b"p" * 32
    store = StateStore(path, authentication_key=key)
    original_stage = store._stage_authentication_anchor

    def stage_then_crash(db: object) -> bool:
        original_stage(db)  # type: ignore[arg-type]
        raise RuntimeError("simulated precommit crash")

    monkeypatch.setattr(store, "_stage_authentication_anchor", stage_then_crash)
    with pytest.raises(RuntimeError, match="precommit crash"):
        store.record_event("error", "ROLLED_BACK", "must not survive")

    assert store.authentication_pending_path.exists()
    reopened = StateStore(path, authentication_key=key)
    assert reopened.recent_events(5) == []
    assert not reopened.authentication_pending_path.exists()
    reopened.verify_authentication_anchor()


def test_tampered_or_replayed_pending_successor_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "pending-tamper.sqlite3"
    key = b"q" * 32
    store = StateStore(path, authentication_key=key)

    monkeypatch.setattr(
        store,
        "_promote_staged_authentication_anchor",
        lambda: (_ for _ in ()).throw(RuntimeError("leave pending")),
    )
    with pytest.raises(RuntimeError, match="leave pending"):
        store.record_event("info", "PENDING", "pending successor")
    transition = json.loads(store.authentication_pending_path.read_text(encoding="utf-8"))
    transition["next_anchor"]["equity_tail"]["count"] += 1
    store.authentication_pending_path.write_text(
        json.dumps(transition, sort_keys=True) + "\n", encoding="utf-8"
    )

    with pytest.raises(RuntimeError, match="keyed verification"):
        StateStore(path, authentication_key=key)


def test_valid_old_pending_successor_cannot_be_replayed_after_anchor_advances(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "pending-replay.sqlite3"
    key = b"w" * 32
    store = StateStore(path, authentication_key=key)
    original_promote = store._promote_staged_authentication_anchor
    monkeypatch.setattr(
        store,
        "_promote_staged_authentication_anchor",
        lambda: (_ for _ in ()).throw(RuntimeError("leave replayable pending")),
    )
    with pytest.raises(RuntimeError, match="leave replayable pending"):
        store.record_event("info", "FIRST", "first successor")
    old_pending = store.authentication_pending_path.read_bytes()

    recovered = StateStore(path, authentication_key=key)
    monkeypatch.setattr(store, "_promote_staged_authentication_anchor", original_promote)
    recovered.record_event("info", "SECOND", "advance checkpoint again")
    recovered.authentication_pending_path.write_bytes(old_pending)

    with pytest.raises(RuntimeError, match="unique successor"):
        StateStore(path, authentication_key=key)


def _replace_checkpoint_with_valid_v2_anchor(store: StateStore) -> None:
    inventory = store._authentication_inventory(schema_version=2)
    document = {
        **inventory,
        "anchor_hmac_sha256": store._authentication_anchor_hmac(inventory),
    }
    with store.connection() as db:
        for table in ("orders", "events", "runs"):
            for operation in ("insert", "update", "delete"):
                db.execute(
                    f'DROP TRIGGER "operational_authentication_dirty_{table}_{operation}"'
                )
        db.execute("DROP TABLE operational_authentication_rows")
        db.execute("DROP TABLE operational_authentication_state")
    store.authentication_anchor_path.write_text(
        json.dumps(document, allow_nan=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def test_v2_inventory_full_verifies_then_migrates_to_incremental_authentication(
    tmp_path: Path,
) -> None:
    path = tmp_path / "v2-migration.sqlite3"
    key = b"r" * 32
    store = StateStore(path, authentication_key=key)
    store.record_event("info", "LEGACY_V2", "authenticated legacy row")
    _replace_checkpoint_with_valid_v2_anchor(store)

    reopened = StateStore(path, authentication_key=key)
    document = json.loads(reopened.authentication_anchor_path.read_text(encoding="utf-8"))
    assert document["schema_version"] == AUTHENTICATION_INVENTORY_SCHEMA_VERSION
    assert reopened.recent_events(5)[0]["code"] == "LEGACY_V2"
    reopened.verify_authentication_anchor()


def test_v2_migration_rejects_tampered_operational_history_before_backfill(
    tmp_path: Path,
) -> None:
    path = tmp_path / "v2-migration-tamper.sqlite3"
    key = b"x" * 32
    store = StateStore(path, authentication_key=key)
    store.record_event("info", "LEGACY_VALID", "must remain immutable")
    _replace_checkpoint_with_valid_v2_anchor(store)
    with store.connection() as db:
        db.execute("UPDATE events SET code = 'LEGACY_FORGED'")

    with pytest.raises(RuntimeError, match="external checkpoint"):
        StateStore(path, authentication_key=key)
    document = json.loads(store.authentication_anchor_path.read_text(encoding="utf-8"))
    assert document["schema_version"] == 2


def test_v2_migration_failure_rolls_back_auxiliary_schema_and_retries_safely(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "v2-migration-rollback.sqlite3"
    key = b"s" * 32
    store = StateStore(path, authentication_key=key)
    store.record_event("info", "LEGACY_ROLLBACK", "migration must be atomic")
    _replace_checkpoint_with_valid_v2_anchor(store)
    original_stage = StateStore._stage_authentication_anchor

    def stage_then_fail(self: StateStore, db: object) -> bool:
        original_stage(self, db)  # type: ignore[arg-type]
        raise RuntimeError("simulated migration failure")

    monkeypatch.setattr(StateStore, "_stage_authentication_anchor", stage_then_fail)
    with pytest.raises(RuntimeError, match="migration failure"):
        StateStore(path, authentication_key=key)

    document = json.loads(store.authentication_anchor_path.read_text(encoding="utf-8"))
    assert document["schema_version"] == 2
    with store.connection() as db:
        auxiliary = db.execute(
            "SELECT name FROM sqlite_master WHERE name LIKE 'operational_authentication_%'"
        ).fetchall()
    assert auxiliary == []
    assert store.authentication_pending_path.exists()

    monkeypatch.setattr(StateStore, "_stage_authentication_anchor", original_stage)
    reopened = StateStore(path, authentication_key=key)
    assert reopened.recent_events(5)[0]["code"] == "LEGACY_ROLLBACK"
    reopened.verify_authentication_anchor()


def test_normal_operational_paths_never_issue_full_history_authentication_queries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = StateStore(tmp_path / "bounded-queries.sqlite3", authentication_key=b"t" * 32)
    run_id = store.start_run("bounded")
    receipt = OrderReceipt(
        broker_order_id="broker-bounded",
        client_order_id="client-bounded",
        symbol="SPY",
        qty=1.0,
        side="buy",
        status="accepted",
        submitted_at=datetime(2026, 7, 13, 15, 0, tzinfo=timezone.utc),
        raw={},
    )
    store.record_order(None, "rebalance", receipt)
    statements: list[str] = []
    original_connection = store.connection
    original_heads = store._incremental_operational_authentication_heads

    @contextmanager
    def traced_connection():
        with original_connection() as db:
            db.set_trace_callback(statements.append)
            yield db

    def reject_exhaustive(db: object, *, exhaustive: bool):
        assert exhaustive is False
        return original_heads(db, exhaustive=exhaustive)  # type: ignore[arg-type]

    monkeypatch.setattr(store, "connection", traced_connection)
    monkeypatch.setattr(
        store, "_incremental_operational_authentication_heads", reject_exhaustive
    )
    store.record_event("info", "BOUNDED", "bounded mutation")
    store.finish_run(run_id, "success")
    assert store.recent_events(5)[0]["code"] == "BOUNDED"
    assert store.order_record_by_client_order_id("client-bounded") is not None

    normalized = [" ".join(statement.upper().split()) for statement in statements]
    for table in ("ORDERS", "EVENTS", "RUNS"):
        assert not any(
            f"FROM {table} ORDER BY" in statement and "LIMIT" not in statement
            for statement in normalized
        )


def test_exact_order_lookup_verifies_target_row_mac_after_head_check(
    tmp_path: Path,
) -> None:
    store = StateStore(tmp_path / "exact-order.sqlite3", authentication_key=b"u" * 32)
    receipt = OrderReceipt(
        broker_order_id="broker-exact",
        client_order_id="client-exact",
        symbol="QQQ",
        qty=2.5,
        side="sell",
        status="accepted",
        submitted_at=datetime(2026, 7, 13, 15, 0, tzinfo=timezone.utc),
        raw={},
    )
    store.record_order(None, "rebalance", receipt)
    record = store.order_record_by_client_order_id("client-exact")
    assert record is not None
    assert (record["broker_order_id"], record["symbol"], record["side"], record["qty"]) == (
        "broker-exact",
        "QQQ",
        "sell",
        2.5,
    )

    with store.connection() as db:
        db.execute(
            "UPDATE orders SET status = 'filled' WHERE client_order_id = 'client-exact'"
        )
        # Simulate a hostile attempt to hide the trigger evidence. The external head
        # now matches, but the target row still cannot pass its keyed row record.
        db.execute(
            "UPDATE operational_authentication_state "
            "SET dirty_sequence = mutation_sequence WHERE table_name = 'orders'"
        )
    with pytest.raises(RuntimeError, match="authenticated row index"):
        store.order_record_by_client_order_id("client-exact")
    with pytest.raises(RuntimeError, match="authenticated row index"):
        StateStore(store.path, authentication_key=b"u" * 32)


def test_compare_and_clear_halt_is_exact_authenticated_cas(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "halt-cas.sqlite3", authentication_key=b"v" * 32)
    store.request_halt("incident", flatten=True)
    reviewed = store.halt_state()
    stale = dict(reviewed)
    stale["reason"] = "older-incident"
    assert store.clear_halt_if_unchanged(stale) is False
    assert store.halt_state()["active"] is True

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(lambda _: store.clear_halt_if_unchanged(reviewed), range(2))
        )
    assert sorted(results) == [False, True]
    assert store.halt_state()["active"] is False
    store.verify_authentication_anchor()
