from __future__ import annotations

import json
import math
import os
import signal
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, BinaryIO
from zoneinfo import ZoneInfo

from auto_trader.controls import ControlRequest, merge_control_marker, parse_control_marker
from auto_trader.engine import AutomationEngine, EmergencyPrimarySubmissionError
from auto_trader.emergency_journal import EmergencyJournal
from auto_trader.models import OrderReceipt, OrderSide, TERMINAL_ORDER_STATUSES


class LockUnavailableError(RuntimeError):
    """Raised when another process owns an OS-level lock."""


class DaemonHealthThresholdError(RuntimeError):
    """Raised after repeated cycle failures have activated the fail-safe."""


class ProcessLock:
    """Cross-platform advisory lock held by an open file descriptor.

    This intentionally does not probe a PID. In particular, ``os.kill(pid, 0)`` is
    not a safe liveness check on Windows, where it may terminate the target process.
    A stale lock file is harmless because ownership is maintained by the kernel and
    released automatically when the process exits.
    """

    def __init__(
        self,
        path: Path,
        *,
        timeout_seconds: float = 0.0,
        purpose: str = "process",
    ) -> None:
        self.path = Path(path).expanduser().resolve(strict=False)
        self.timeout_seconds = max(float(timeout_seconds), 0.0)
        self.purpose = purpose
        self._handle: BinaryIO | None = None

    @staticmethod
    def _lock(handle: BinaryIO) -> None:
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    @staticmethod
    def _unlock(handle: BinaryIO) -> None:
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def __enter__(self) -> "ProcessLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            handle = self.path.open("r+b", buffering=0)
        except FileNotFoundError:
            try:
                handle = self.path.open("x+b", buffering=0)
            except FileExistsError:
                handle = self.path.open("r+b", buffering=0)
        if self.path.stat().st_size == 0:
            handle.write(b"\n")
            handle.flush()
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            try:
                self._lock(handle)
                break
            except (BlockingIOError, OSError) as exc:
                if time.monotonic() >= deadline:
                    handle.close()
                    raise LockUnavailableError(
                        f"Another process owns the {self.purpose} lock at {self.path}."
                    ) from exc
                time.sleep(min(0.05, max(deadline - time.monotonic(), 0.0)))

        metadata = json.dumps(
            {
                "pid": os.getpid(),
                "purpose": self.purpose,
                "acquired_at": datetime.now().astimezone().isoformat(),
            },
            sort_keys=True,
        ).encode("utf-8")
        handle.seek(0)
        handle.write(metadata)
        handle.truncate()
        handle.flush()
        self._handle = handle
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        handle = self._handle
        self._handle = None
        if handle is None:
            return
        try:
            self._unlock(handle)
        finally:
            handle.close()


def atomic_write_text(path: Path, text: str) -> None:
    """Replace a small operational marker without exposing partial contents."""
    path = Path(path).expanduser().resolve(strict=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(text, encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    atomic_write_text(path, json.dumps(payload, indent=2, default=str, sort_keys=True) + "\n")


class TradingDaemon:
    def __init__(self, engine: AutomationEngine) -> None:
        self.engine = engine
        self.config = engine.config
        self.tz = ZoneInfo(self.config.timezone)
        self.running = True
        self.emergency_journal = getattr(engine, "emergency_journal", None) or EmergencyJournal(
            self.config.effective_emergency_journal_path,
            self.config.emergency_authentication_key_bytes,
            self.config.emergency_journal_scope,
        )
        self._ensure_active_incident_control()
        (
            self.consecutive_failures,
            self._failure_recovery_error,
        ) = self._load_failure_count()
        self.last_success_at: str | None = None
        self._last_progress_monotonic = time.monotonic()
        self._watchdog_stop = threading.Event()
        progress_setter = getattr(self.engine, "set_progress_callback", None)
        if callable(progress_setter):
            progress_setter(self._mark_progress)
        else:
            broker_setter = getattr(self.engine.broker, "set_progress_callback", None)
            if callable(broker_setter):
                broker_setter(self._mark_progress)

    def _ensure_active_incident_control(self) -> str | None:
        """Recreate/escalate the marker for the authenticated unresolved incident."""

        self.emergency_journal.verify()
        incident_id = self.emergency_journal.active_incident_id()
        if incident_id is None:
            return None
        control = merge_control_marker(
            self.config.kill_switch_path,
            "startup_recovery_active_emergency_incident",
            flatten=True,
            authoritative_incident_id=incident_id,
        )
        self._safe_store("request_halt", control.reason, flatten=True)
        return incident_id

    @staticmethod
    def _strict_failure_count(value: Any, source: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(
                f"{source} consecutive failure count must be a non-negative integer."
            )
        return value

    def _load_failure_count(self) -> tuple[int, str]:
        sidecar_count: int | None = None
        sidecar_invalid = ""
        sidecar_failsafe = ""
        try:
            payload = json.loads(self.config.daemon_health_path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("Daemon health sidecar must contain a JSON object.")
            sidecar_count = self._strict_failure_count(
                payload.get("consecutive_failures", 0), "Health sidecar"
            )
            sidecar_status = str(payload.get("last_cycle_status", ""))
            if sidecar_status in {"watchdog_timeout", "failsafe_triggered"}:
                # The health sidecar is the watchdog's independent restart handoff if
                # the control marker could not be written. Never interpret such a
                # terminal status as a clean zero-failure startup.
                sidecar_count = max(
                    sidecar_count,
                    self.config.health_failure_threshold,
                )
                sidecar_failsafe = (
                    f"persisted daemon {sidecar_status} requires mandatory reconciliation"
                )
        except FileNotFoundError:
            pass
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            sidecar_invalid = f"invalid daemon health sidecar: {exc}"

        missing = object()
        try:
            reader = getattr(self.engine.store, "get_state")
            persisted = reader("daemon_consecutive_failures", missing)
            persisted_count = (
                None
                if persisted is missing
                else self._strict_failure_count(persisted, "Persisted daemon state")
            )
        except Exception as exc:
            # Authenticated state corruption or an unavailable DB is not evidence of
            # a clean failure streak. Enter the threshold state so startup performs
            # mandatory reconciliation before any normal cycle.
            return (
                self.config.health_failure_threshold,
                f"invalid persisted daemon failure state: {exc}",
            )

        if persisted_count is not None:
            # The authenticated DB survives a malformed/lost sidecar. If both exist,
            # retain the larger streak so a stale sidecar cannot roll failures back.
            recovered = max(persisted_count, sidecar_count or 0)
            recovery_error = sidecar_failsafe
            if recovered >= self.config.health_failure_threshold and not recovery_error:
                recovery_error = (
                    "persisted daemon failure threshold requires mandatory reconciliation"
                )
            return recovered, recovery_error
        if sidecar_failsafe:
            return sidecar_count or self.config.health_failure_threshold, sidecar_failsafe
        if sidecar_invalid:
            return self.config.health_failure_threshold, sidecar_invalid
        return sidecar_count or 0, ""

    def stop(self, *_args) -> None:
        self.running = False

    @staticmethod
    def _minutes(value) -> int:
        return value.hour * 60 + value.minute

    def _retry_allowed(self, state_key: str, now: datetime) -> bool:
        raw = self.engine.store.get_state(state_key, None)
        if not raw:
            return True
        try:
            previous = datetime.fromisoformat(str(raw))
            if previous.tzinfo is None:
                previous = previous.replace(tzinfo=self.tz)
            previous = previous.astimezone(self.tz)
        except (TypeError, ValueError):
            return True
        return (now - previous).total_seconds() >= self.config.scheduler_retry_minutes * 60

    def _safe_store(self, method: str, *args, **kwargs) -> bool:
        try:
            getattr(self.engine.store, method)(*args, **kwargs)
            return True
        except Exception as exc:
            self.engine.logger.error("State store %s failed: %s", method, exc)
            return False

    def _health_payload(self, status: str, error: str = "") -> dict[str, Any]:
        now = datetime.now(self.tz).isoformat()
        return {
            "daemon_pid": os.getpid(),
            "heartbeat": now,
            "last_cycle_status": status,
            "last_error": error,
            "consecutive_failures": self.consecutive_failures,
            "failure_threshold": self.config.health_failure_threshold,
            "watchdog_timeout_seconds": self.config.daemon_watchdog_timeout_seconds,
            "last_success_at": self.last_success_at,
            "kill_switch_present": self.config.kill_switch_path.exists(),
            "mode": self.config.mode_label,
        }

    def _publish_health(self, status: str, error: str = "") -> None:
        if status == "ok":
            self.consecutive_failures = 0
            self.last_success_at = datetime.now(self.tz).isoformat()
        elif status == "failed":
            self.consecutive_failures += 1

        payload = self._health_payload(status, error)
        try:
            atomic_write_json(self.config.daemon_health_path, payload)
        except (OSError, RuntimeError) as exc:
            self.engine.logger.error("Could not publish daemon health file: %s", exc)

        # These writes are best-effort; the health sidecar remains available when
        # SQLite is locked, corrupt, missing, or mounted read-only.
        self._safe_store("set_state", "daemon_heartbeat", payload["heartbeat"])
        self._safe_store("set_state", "daemon_pid", os.getpid())
        self._safe_store("set_state", "daemon_last_cycle_status", status)
        self._safe_store("set_state", "daemon_last_cycle_error", error)
        self._safe_store("set_state", "daemon_consecutive_failures", self.consecutive_failures)
        if self.last_success_at:
            self._safe_store("set_state", "daemon_last_success_at", self.last_success_at)

    def _trip_health_failsafe(self, error: str) -> None:
        """Halt, reconcile exposure, and force a supervisor restart.

        Merely reporting an unhealthy container is insufficient: Docker restart
        policies react to process exits, not health-state transitions.  The
        filesystem marker is therefore made durable before any database or broker
        operation.  It remains present across restart so a replacement daemon
        cannot resume trading and will retry emergency reconciliation first.
        """
        if self.consecutive_failures < self.config.health_failure_threshold:
            return

        reason = "daemon_health_failure_threshold"
        marker_error: Exception | None = None
        reconciliation_error: Exception | None = None
        try:
            merge_control_marker(
                self.config.kill_switch_path,
                reason,
                flatten=True,
            )
            self.config.kill_switch_ack_path.unlink(missing_ok=True)
        except (OSError, RuntimeError) as exc:
            marker_error = exc
            self.engine.logger.critical(
                "Could not persist the daemon health fail-safe marker: %s", exc
            )

        self._safe_store("request_halt", reason, flatten=True)
        self._safe_store(
            "record_event",
            "CRITICAL",
            "DAEMON_HEALTH_FAILSAFE_TRIGGERED",
            error,
            {
                "consecutive_failures": self.consecutive_failures,
                "failure_threshold": self.config.health_failure_threshold,
                "kill_switch_path": str(self.config.kill_switch_path),
                "marker_persisted": marker_error is None,
            },
        )
        self._publish_health("failsafe_triggered", error)

        # Attempt liquidation now rather than relying only on the replacement
        # process.  A failed/contended attempt is still safe: the durable marker is
        # observed before normal work on the next supervisor restart.
        if marker_error is None:
            try:
                with ProcessLock(
                    self.config.operation_lock_path,
                    timeout_seconds=0,
                    purpose="trading operation",
                ):
                    self._observe_kill_switch()
            except Exception as exc:
                reconciliation_error = exc
                self.engine.logger.exception(
                    "Daemon health fail-safe reconciliation failed: %s", exc
                )

        details = [
            f"{self.consecutive_failures} consecutive cycle failures reached "
            f"threshold {self.config.health_failure_threshold}",
        ]
        if marker_error is not None:
            details.append(f"kill marker persistence failed: {marker_error}")
        if reconciliation_error is not None:
            details.append(f"emergency reconciliation failed: {reconciliation_error}")
        raise DaemonHealthThresholdError("; ".join(details))

    def _record_cycle_failure(self, error: str) -> None:
        self._safe_store("record_event", "ERROR", "DAEMON_CYCLE_FAILED", error)
        self._publish_health("failed", error)
        self._trip_health_failsafe(error)

    def _mark_progress(self) -> None:
        self._last_progress_monotonic = time.monotonic()

    def _force_restart_for_stall(self, elapsed_seconds: float) -> None:
        """Last-resort liveness breaker used when the main daemon thread is stuck.

        No database or broker call is attempted from the watchdog thread because the
        main thread may be holding their locks.  The replacement process observes the
        durable marker and performs serialized emergency reconciliation.
        """
        reason = "daemon_liveness_watchdog_timeout"
        marker_error = ""
        try:
            merge_control_marker(
                self.config.kill_switch_path,
                reason,
                flatten=True,
            )
            self.config.kill_switch_ack_path.unlink(missing_ok=True)
        except (OSError, RuntimeError) as exc:
            marker_error = f"; kill marker persistence failed: {exc}"
        # Persist the mandatory-reconciliation state in the independently replaced
        # health sidecar too. On restart, `_load_failure_count` treats the watchdog
        # status itself as threshold state, so a marker-lock/path failure cannot be
        # mistaken for a clean daemon and followed by routine trading.
        self.consecutive_failures = max(
            self.consecutive_failures,
            self.config.health_failure_threshold,
        )
        message = (
            f"No daemon-loop progress for {elapsed_seconds:.1f}s "
            f"(watchdog {self.config.daemon_watchdog_timeout_seconds}s){marker_error}"
        )
        payload = self._health_payload("watchdog_timeout", message)
        payload["watchdog_elapsed_seconds"] = elapsed_seconds
        try:
            atomic_write_json(self.config.daemon_health_path, payload)
        except OSError:
            pass
        # Graceful shutdown cannot recover a stuck Python/broker call. Exit code 70
        # deliberately engages Docker/systemd restart policy.
        os._exit(70)

    def _watchdog_loop(self) -> None:
        interval = min(
            30.0,
            max(float(self.config.daemon_watchdog_timeout_seconds) / 10.0, 1.0),
        )
        while not self._watchdog_stop.wait(interval):
            elapsed = time.monotonic() - self._last_progress_monotonic
            if elapsed >= self.config.daemon_watchdog_timeout_seconds:
                self._force_restart_for_stall(elapsed)
                return

    def _kill_request(self) -> ControlRequest | None:
        if not self.config.kill_switch_path.exists():
            return None
        try:
            marker = self.config.kill_switch_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            marker = ""
        request = parse_control_marker(marker)
        halt_reader = getattr(self.engine.store, "halt_state", None)
        if not callable(halt_reader):
            return request
        try:
            halt = halt_reader()
        except Exception:
            return ControlRequest(
                f"{request.reason} | invalid_persisted_halt_state",
                True,
            )
        if halt.get("active") and halt.get("flatten") is True:
            persisted_reason = str(halt.get("reason", "persisted_mandatory_halt")).strip()
            combined = request.reason
            if persisted_reason and persisted_reason not in combined.split(" | "):
                combined = f"{combined} | {persisted_reason}"
            return ControlRequest(combined, True)
        return request

    def _kill_reason(self) -> str | None:
        request = self._kill_request()
        return request.reason if request is not None else None

    def _managed_fallback_symbols(self, positions: dict[str, Any]) -> set[str]:
        if self.config.dedicated_account:
            return set(positions)
        return set(self.config.symbols).intersection(positions)

    def _fallback_order_scope(self) -> tuple[list[str] | None, str | None]:
        if self.config.dedicated_account:
            # Every order can mutate account exposure while an account-wide kill is
            # active, including an order placed manually or by another client.
            return None, None
        return sorted(set(self.config.symbols)), "qauto-"

    def _fallback_open_orders(self) -> list[OrderReceipt]:
        symbols, client_prefix = self._fallback_order_scope()
        orders = self.engine.broker.list_open_orders(symbols)
        self._mark_progress()
        if client_prefix is None:
            return orders
        return [
            order for order in orders if order.client_order_id.startswith(client_prefix)
        ]

    def _fallback_exposure(self) -> tuple[dict[str, Any], list[OrderReceipt]]:
        positions = self.engine.broker.get_positions()
        self._mark_progress()
        scoped_symbols = self._managed_fallback_symbols(positions)
        nonfinite = sorted(
            symbol
            for symbol in scoped_symbols
            if not math.isfinite(float(positions[symbol].qty))
        )
        if nonfinite:
            raise RuntimeError(
                "Broker-only kill cannot prove exposure from non-finite position "
                "quantities: " + ", ".join(nonfinite)
            )
        managed = {
            symbol: positions[symbol]
            for symbol in scoped_symbols
            if abs(float(positions[symbol].qty)) > 1e-10
        }
        return managed, self._fallback_open_orders()

    def _wait_for_fallback_receipts(
        self, receipts: list[OrderReceipt]
    ) -> list[OrderReceipt]:
        """Resolve every fallback liquidation receipt to a terminal broker state."""

        latest = {receipt.broker_order_id: receipt for receipt in receipts}
        deadline = time.monotonic() + max(
            float(self.config.order_fill_timeout_seconds), 0.0
        )
        while True:
            nonterminal = []
            for order_id, prior in list(latest.items()):
                current = prior
                if current.status.lower() not in TERMINAL_ORDER_STATUSES:
                    current = self.engine.broker.get_order(order_id)
                    self._mark_progress()
                    AutomationEngine._validate_receipt_transition(prior, current)
                    latest[order_id] = current
                if current.status.lower() not in TERMINAL_ORDER_STATUSES:
                    nonterminal.append(order_id)
            if not nonterminal:
                return list(latest.values())
            if time.monotonic() >= deadline:
                break
            time.sleep(min(max(float(self.config.order_poll_seconds), 0.01), 1.0))

        for order_id in nonterminal:
            previous = latest[order_id]
            current = self.engine.broker.cancel_order_and_wait(
                order_id,
                timeout_seconds=self.config.order_fill_timeout_seconds,
                poll_seconds=self.config.order_poll_seconds,
            )
            self._mark_progress()
            AutomationEngine._validate_receipt_transition(previous, current)
            latest[order_id] = current
        unresolved = [
            receipt.client_order_id
            for receipt in latest.values()
            if receipt.status.lower() not in TERMINAL_ORDER_STATUSES
        ]
        if unresolved:
            raise RuntimeError(
                "Broker-only emergency orders did not reach terminal states: "
                + ", ".join(unresolved)
            )
        return list(latest.values())

    def _fallback_emergency_flatten(
        self,
        reason: str,
        primary_error: Exception,
        incident_id: str | None = None,
    ) -> dict[str, Any]:
        """Broker-only last resort when persistent state cannot be used.

        In a dedicated account all positions are in scope. Otherwise only configured
        symbols are touched because the database-managed universe is unavailable.
        Cancellations must disappear from the broker before close orders are sent.
        """
        if incident_id is None:
            control = merge_control_marker(
                self.config.kill_switch_path,
                reason,
                flatten=True,
            )
            incident_id = control.incident_id
        if incident_id is None:
            raise RuntimeError("Emergency control marker has no stable incident UUID.")
        resolved_incident_id = self.emergency_journal.resolve_incident(incident_id)
        if resolved_incident_id != incident_id:
            control = merge_control_marker(
                self.config.kill_switch_path,
                reason,
                flatten=True,
                authoritative_incident_id=resolved_incident_id,
            )
            reason = control.reason
        incident_id = resolved_incident_id
        result: dict[str, Any] = {
            "observed_at": datetime.now(self.tz).isoformat(),
            "reason": reason,
            "status": "observed",
            "database_error": str(primary_error),
            "scope": "dedicated_account" if self.config.dedicated_account else "configured_symbols",
            "submitted_orders": [],
        }
        order_scope, client_prefix = self._fallback_order_scope()
        terminal_orders: list[OrderReceipt] = []
        canceled_orders: list[OrderReceipt] = []
        max_submission_rounds = 3
        submission_round = 0
        flat_position_snapshots: list[dict[str, float]] = []
        flat_order_snapshots: list[list[str]] = []
        for _reconciliation_round in range(max_submission_rounds + 2):
            newly_canceled = self.engine.broker.cancel_orders_and_wait(
                order_scope,
                client_prefix=client_prefix,
                timeout_seconds=self.config.order_fill_timeout_seconds,
                poll_seconds=self.config.order_poll_seconds,
            )
            self._mark_progress()
            if newly_canceled:
                flat_position_snapshots.clear()
                flat_order_snapshots.clear()
                canceled_orders.extend(newly_canceled)
            positions, remaining_open = self._fallback_exposure()
            if remaining_open:
                raise RuntimeError(
                    "Broker-only emergency cancellation returned while relevant orders "
                    "were still open: "
                    + ", ".join(order.client_order_id for order in remaining_open)
                )
            if not positions:
                flat_position_snapshots.append(
                    {
                        symbol: float(position.qty)
                        for symbol, position in positions.items()
                    }
                )
                flat_order_snapshots.append(
                    [order.client_order_id for order in remaining_open]
                )
                if len(flat_position_snapshots) < 2:
                    if self.config.broker != "simulated":
                        time.sleep(
                            min(max(float(self.config.order_poll_seconds), 0.05), 1.0)
                        )
                    continue
                result["status"] = (
                    "flattened"
                    if result["submitted_orders"] or canceled_orders
                    else "already_flat"
                )
                result["terminal_orders"] = {
                    receipt.client_order_id: receipt.status
                    for receipt in terminal_orders + canceled_orders
                }
                self.emergency_journal.complete_incident(
                    incident_id,
                    flat_position_snapshots[-2:],
                    flat_order_snapshots[-2:],
                )
                return result
            flat_position_snapshots.clear()
            flat_order_snapshots.clear()
            if not self.config.execution_enabled:
                result["status"] = "execution_disabled"
                result["positions_remaining"] = sorted(positions)
                result["terminal_orders"] = {
                    receipt.client_order_id: receipt.status for receipt in canceled_orders
                }
                return result
            if submission_round >= max_submission_rounds:
                break

            before_quantities: dict[str, float] = {}
            round_receipts: list[OrderReceipt] = []
            round_submitted = False
            for symbol, position in sorted(positions.items()):
                quantity = abs(float(position.qty))
                side = OrderSide.SELL if position.qty > 0 else OrderSide.BUY
                prepared = self.emergency_journal.prepare_submission(
                    incident_id,
                    symbol=symbol,
                    current_qty=float(position.qty),
                    side=side.value,
                    qty=quantity,
                )
                baseline_tolerance = max(
                    1e-8, abs(float(prepared.baseline_qty)) * 1e-8
                )
                if prepared.reused and not math.isclose(
                    float(position.qty),
                    float(prepared.baseline_qty),
                    abs_tol=baseline_tolerance,
                ):
                    receipt = self.engine._resolve_stale_emergency_intent(
                        prepared,
                        current_qty=float(position.qty),
                        managed_symbols=self._managed_fallback_symbols(positions),
                    )
                    if receipt is None:
                        continue
                    before_quantities[symbol] = prepared.baseline_qty
                    round_receipts.append(receipt)
                    continue
                before_quantities[symbol] = prepared.baseline_qty
                quantity = prepared.qty
                side = OrderSide(prepared.side)
                receipt = self.engine.broker.submit_emergency_market_order(
                    symbol=symbol,
                    qty=quantity,
                    side=side,
                    client_order_id=prepared.client_order_id,
                )
                round_submitted = True
                AutomationEngine._validate_order_receipt(
                    receipt,
                    symbol=symbol,
                    qty=quantity,
                    side=side,
                    client_order_id=prepared.client_order_id,
                )
                self.emergency_journal.record_receipt(incident_id, receipt)
                result["submitted_orders"].append(receipt.client_order_id)
                round_receipts.append(receipt)
                self._mark_progress()
            if round_submitted:
                submission_round += 1
            if not round_receipts:
                continue

            final_receipts = self._wait_for_fallback_receipts(round_receipts)
            for receipt in final_receipts:
                self.emergency_journal.record_receipt(incident_id, receipt)
            terminal_orders.extend(final_receipts)
            positions_after, remaining_open = self._fallback_exposure()
            AutomationEngine._require_emergency_fill_progress(
                before_quantities,
                positions_after,
                final_receipts,
            )
            if not positions_after and not remaining_open:
                flat_position_snapshots.append(
                    {
                        symbol: float(position.qty)
                        for symbol, position in positions_after.items()
                    }
                )
                flat_order_snapshots.append(
                    [order.client_order_id for order in remaining_open]
                )
                if self.config.broker != "simulated":
                    time.sleep(
                        min(max(float(self.config.order_poll_seconds), 0.05), 1.0)
                    )
                continue
            if remaining_open:
                # The next round will use cancel_orders_and_wait before it takes a
                # replacement position snapshot.
                continue

        positions, remaining_open = self._fallback_exposure()
        raise RuntimeError(
            "Broker-only emergency flatten did not reconcile within three rounds; "
            f"positions={sorted(positions)}, "
            f"open_orders={[order.client_order_id for order in remaining_open]}"
        )

    def _observe_kill_switch(self) -> dict[str, Any] | None:
        request = self._kill_request()
        if request is None:
            return None
        # Every legacy/v1 marker is atomically upgraded before reconciliation. The
        # generated incident UUID then survives all later reason merges/escalations.
        request = merge_control_marker(
            self.config.kill_switch_path,
            request.reason,
            flatten=request.flatten,
        )
        if request.incident_id is None:
            raise RuntimeError("Emergency control marker has no stable incident UUID.")
        reason = request.reason

        # Persist the halt when possible, but inspect the broker even if SQLite fails.
        self._safe_store("request_halt", reason, flatten=request.flatten)
        if not request.flatten:
            order_scope, client_prefix = self._fallback_order_scope()
            canceled = self.engine.broker.cancel_orders_and_wait(
                order_scope,
                client_prefix=client_prefix,
                timeout_seconds=self.config.order_fill_timeout_seconds,
                poll_seconds=self.config.order_poll_seconds,
            )
            self._mark_progress()
            positions, remaining_open = self._fallback_exposure()
            if remaining_open:
                self._safe_store(
                    "request_halt",
                    f"halt_only_order_cancellation_unconfirmed:{reason}",
                    flatten=True,
                )
                raise RuntimeError(
                    "Halt-only cancellation returned while relevant orders remained open."
                )
            result = {
                "observed_at": datetime.now(self.tz).isoformat(),
                "reason": reason,
                "status": "halt_only",
                "flatten_requested": False,
                "positions_remaining": sorted(positions),
                "canceled_orders": [order.client_order_id for order in canceled],
            }
            atomic_write_json(self.config.kill_switch_ack_path, result)
            return result
        positions, open_orders = self._fallback_exposure()
        if not self.config.execution_enabled:
            order_scope, client_prefix = self._fallback_order_scope()
            canceled: list[OrderReceipt] = []
            for confirmation_pass in range(2):
                canceled.extend(
                    self.engine.broker.cancel_orders_and_wait(
                        order_scope,
                        client_prefix=client_prefix,
                        timeout_seconds=self.config.order_fill_timeout_seconds,
                        poll_seconds=self.config.order_poll_seconds,
                    )
                )
                self._mark_progress()
                positions, open_orders = self._fallback_exposure()
                if open_orders:
                    raise RuntimeError(
                        "Kill cancellation returned while relevant orders remained open."
                    )
                if positions or confirmation_pass == 1:
                    break
                if self.config.broker != "simulated":
                    time.sleep(
                        min(max(float(self.config.order_poll_seconds), 0.05), 1.0)
                    )
            result = {
                "observed_at": datetime.now(self.tz).isoformat(),
                "reason": reason,
                "status": "execution_disabled" if positions else "already_flat",
                "positions_remaining": sorted(positions),
                "open_orders_remaining": [],
                "canceled_orders": [order.client_order_id for order in canceled],
            }
            atomic_write_json(self.config.kill_switch_ack_path, result)
            return result

        try:
            receipts = self.engine.emergency_flatten(reason, persist_halt=True)
            positions_after, open_orders_after = self._fallback_exposure()
            if positions_after or open_orders_after:
                raise RuntimeError(
                    "Database-backed emergency flatten returned before final broker "
                    "reconciliation: "
                    f"positions={sorted(positions_after)}, "
                    f"open_orders={[order.client_order_id for order in open_orders_after]}"
                )
            result = {
                "observed_at": datetime.now(self.tz).isoformat(),
                "reason": reason,
                "status": (
                    "already_flat"
                    if not positions and not open_orders and not receipts
                    else "flattened"
                ),
                "submitted_orders": [receipt.client_order_id for receipt in receipts],
            }
        except EmergencyPrimarySubmissionError:
            # A terminal fill with a lagging position must be retried with the same
            # deterministic ID. The same holds for any error after a primary submit
            # may have reached the broker, including a state-persistence failure.
            raise
        except Exception as exc:
            self.engine.logger.exception(
                "Database-backed emergency flatten failed; using broker-only fallback: %s", exc
            )
            result = self._fallback_emergency_flatten(reason, exc, request.incident_id)
        atomic_write_json(self.config.kill_switch_ack_path, result)
        return result

    def _run_cycle(self) -> list[str]:
        errors: list[str] = []
        clock = self.engine.broker.get_market_clock()
        now = self.engine._local_time(clock.timestamp)
        today = now.date().isoformat()

        self.engine.recover_incomplete_execution()
        monitor_decision = self.engine.monitor()
        halted = monitor_decision.halt

        plan_due = self._minutes(now.time()) >= self._minutes(self.config.plan_time)
        plan_success = self.engine.store.get_state("scheduler_last_plan_success", None)
        if (
            not halted
            and plan_due
            and plan_success != today
            and self._retry_allowed("scheduler_last_plan_attempt_at", now)
        ):
            self.engine.store.set_state("scheduler_last_plan_attempt_at", now.isoformat())
            try:
                self.engine.generate_plan()
            except Exception as exc:
                message = f"scheduled_plan: {type(exc).__name__}: {exc}"
                errors.append(message)
                self.engine.logger.exception("Scheduled plan generation failed: %s", exc)
            else:
                self.engine.store.set_state("scheduler_last_plan_success", today)

        start = self._minutes(self.config.execution_time)
        current = self._minutes(now.time())
        # The benchmark endpoint is exclusive.  At 09:35 the engine may reconcile
        # or cancel an already-submitted child, but the scheduler must never start or
        # retry routine execution.
        in_execution_window = start <= current < start + self.config.execution_window_minutes
        execution_success = self.engine.store.get_state("scheduler_last_execution_success", None)
        if (
            not halted
            and clock.is_open
            and in_execution_window
            and execution_success != today
            and self._retry_allowed("scheduler_last_execution_attempt_at", now)
        ):
            self.engine.store.set_state("scheduler_last_execution_attempt_at", now.isoformat())
            try:
                execution_summary = self.engine.execute_latest_plan()
            except Exception as exc:
                message = f"scheduled_execution: {type(exc).__name__}: {exc}"
                errors.append(message)
                self.engine.logger.exception("Scheduled execution failed: %s", exc)
            else:
                if self.config.execution_enabled and execution_summary.status != "executed":
                    message = (
                        "scheduled_execution: reconciliation incomplete with status "
                        f"{execution_summary.status}: {execution_summary.message}"
                    )
                    errors.append(message)
                    self.engine.store.record_event(
                        "ERROR",
                        "SCHEDULED_EXECUTION_INCOMPLETE",
                        message,
                    )
                else:
                    self.engine.store.set_state("scheduler_last_execution_success", today)
        return errors

    def _sleep(self) -> None:
        slept = 0
        while self.running and slept < self.config.poll_seconds:
            time.sleep(min(1, self.config.poll_seconds - slept))
            slept += 1
            self._mark_progress()

    def run_forever(self) -> None:
        signal.signal(signal.SIGTERM, self.stop)
        signal.signal(signal.SIGINT, self.stop)
        with ProcessLock(self.config.process_lock_path, purpose="daemon"):
            self._mark_progress()
            self._watchdog_stop.clear()
            watchdog = threading.Thread(
                target=self._watchdog_loop,
                name="daemon-liveness-watchdog",
                daemon=True,
            )
            watchdog.start()
            self._safe_store(
                "record_event",
                "INFO",
                "DAEMON_STARTED",
                f"Always-on daemon started in {self.config.mode_label} mode.",
            )
            if self._failure_recovery_error:
                self._trip_health_failsafe(self._failure_recovery_error)
            self._publish_health("starting")
            try:
                while self.running:
                    self._mark_progress()
                    self._publish_health("running")
                    try:
                        with ProcessLock(
                            self.config.operation_lock_path,
                            timeout_seconds=0,
                            purpose="trading operation",
                        ):
                            self._ensure_active_incident_control()
                            self._observe_kill_switch()
                            errors = self._run_cycle()
                        if errors:
                            message = "; ".join(errors)
                            self._record_cycle_failure(message)
                        else:
                            self._publish_health("ok")
                    except LockUnavailableError:
                        # A serialized CLI operation is active. This is expected and does not
                        # reset or increment the consecutive broker/cycle failure count.
                        self._publish_health("operation_lock_busy")
                    except DaemonHealthThresholdError:
                        # Deliberately escape the daemon loop with a non-zero process exit;
                        # Docker/systemd restart policies only act on process lifecycle.
                        raise
                    except Exception as exc:
                        message = f"{type(exc).__name__}: {exc}"
                        self.engine.logger.exception("Daemon cycle failed: %s", exc)
                        self._record_cycle_failure(message)
                    self._mark_progress()
                    self._sleep()
            finally:
                self._watchdog_stop.set()
                watchdog.join(timeout=1.0)

            stopped_at = datetime.now(self.tz).isoformat()
            self._safe_store("set_state", "daemon_stopped_at", stopped_at)
            self._safe_store("record_event", "INFO", "DAEMON_STOPPED", "Always-on daemon stopped.")
            payload = self._health_payload("stopped")
            payload["stopped_at"] = stopped_at
            try:
                atomic_write_json(self.config.daemon_health_path, payload)
            except OSError as exc:
                self.engine.logger.error("Could not publish stopped daemon health: %s", exc)
