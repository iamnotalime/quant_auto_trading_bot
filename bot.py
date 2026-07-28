from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from auto_trader.config import BotConfig, RESUME_ACK_TEXT, emergency_control_paths
from auto_trader.controls import merge_control_marker
from auto_trader.daemon import (
    LockUnavailableError,
    ProcessLock,
    TradingDaemon,
)
from auto_trader.factory import build_engine


# A durable control marker is not proof that broker-side risk reduction completed.
# Keep that distinction machine-readable for service managers and incident tooling.
EMERGENCY_ACTION_PENDING_EXIT_CODE = 2


def _json_default(value):
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "value"):
        return value.value
    return str(value)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Always-on quantitative trading automation service."
    )
    result.add_argument("--env-file", default=".env", help="Environment file path.")
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("daemon", help="Run the always-on scheduler and risk monitor.")

    plan = commands.add_parser("plan", help="Generate and persist the latest target plan.")
    plan.add_argument("--force", action="store_true")

    execute = commands.add_parser("execute", help="Execute the newest approved plan.")
    execute.add_argument("--force", action="store_true", help="Allow same-session execution in simulation only.")

    commands.add_parser("cycle", help="Generate then execute once; intended for simulation tests.")
    commands.add_parser("monitor", help="Run one risk-monitor cycle.")
    commands.add_parser("doctor", help="Validate broker, data, database, and asset eligibility.")
    status = commands.add_parser("status", help="Print persisted daemon status as JSON.")
    status.add_argument(
        "--healthcheck",
        action="store_true",
        help="Exit non-zero when the daemon heartbeat is stale.",
    )

    kill = commands.add_parser("kill", help="Activate the persistent kill switch.")
    kill.add_argument("--reason", default="manual_kill_switch")
    kill.add_argument("--no-flatten", action="store_true")

    resume = commands.add_parser("resume", help="Clear halt and cooldown after human review.")
    resume.add_argument("--ack", required=True, help=f"Must equal {RESUME_ACK_TEXT!r}.")
    return result


def _read_health_file(config: BotConfig) -> dict[str, Any]:
    try:
        payload = json.loads(config.daemon_health_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        raise RuntimeError(
            f"Daemon health file {config.daemon_health_path} is unreadable or invalid."
        ) from exc
    if not isinstance(payload, dict):
        raise RuntimeError("Daemon health file must contain a JSON object.")
    return payload


def _validate_health(config: BotConfig, health: dict[str, Any]) -> None:
    heartbeat = health.get("heartbeat")
    if not heartbeat:
        raise RuntimeError("No daemon health heartbeat has been recorded.")
    try:
        heartbeat_dt = datetime.fromisoformat(str(heartbeat))
    except ValueError as exc:
        raise RuntimeError("Daemon health heartbeat is invalid.") from exc
    if heartbeat_dt.tzinfo is None:
        heartbeat_dt = heartbeat_dt.replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - heartbeat_dt.astimezone(timezone.utc)).total_seconds()
    maximum_age = max(config.poll_seconds * 3 + 30, 90)
    if age < -30:
        raise RuntimeError(f"Daemon heartbeat is {abs(age):.0f}s in the future.")
    if age > maximum_age:
        raise RuntimeError(f"Daemon heartbeat is stale ({age:.0f}s; limit {maximum_age}s).")
    status = str(health.get("last_cycle_status", "unknown"))
    if status == "stopped":
        raise RuntimeError("Daemon reported that it has stopped.")
    try:
        failures = int(health.get("consecutive_failures", 0))
    except (TypeError, ValueError) as exc:
        raise RuntimeError("Daemon consecutive failure count is invalid.") from exc
    if failures >= config.health_failure_threshold:
        detail = str(health.get("last_error", "unspecified cycle failure"))
        raise RuntimeError(
            f"Daemon has {failures} consecutive broker/cycle failures "
            f"(threshold {config.health_failure_threshold}): {detail}"
        )


def _operation_lock(config: BotConfig) -> ProcessLock:
    return ProcessLock(
        config.operation_lock_path,
        timeout_seconds=config.operation_lock_timeout_seconds,
        purpose="trading operation",
    )


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        exit_code = 0
        kill_marker_written = args.command == "kill"
        flatten_requested = bool(kill_marker_written and not args.no_flatten)
        bootstrap_kill_path: Path | None = None
        bootstrap_ack_path: Path | None = None
        if kill_marker_written:
            # Resolve only the two control paths before parsing any strategy, schedule,
            # quote-collar, or governance setting. A malformed routine knob must never
            # prevent the durable emergency signal.
            bootstrap_kill_path, bootstrap_ack_path = emergency_control_paths(args.env_file)
            control_request = merge_control_marker(
                bootstrap_kill_path,
                args.reason,
                flatten=flatten_requested,
            )
            # An existing mandatory incident is monotonic. A later --no-flatten
            # invocation must join that liquidation rather than weakening it.
            flatten_requested = control_request.flatten
            bootstrap_ack_path.unlink(missing_ok=True)

        try:
            config = BotConfig.from_env(args.env_file)
        except Exception as config_exc:
            if not kill_marker_written:
                raise
            try:
                config = BotConfig.emergency_from_env(args.env_file)
            except Exception as emergency_exc:
                print(
                    json.dumps(
                        {
                            "halted": True,
                            "flatten_requested": flatten_requested,
                            "reason": args.reason,
                            "filesystem_kill_switch": str(bootstrap_kill_path),
                            "status": "accepted_emergency_configuration_unavailable",
                            "warning": (
                                f"Routine configuration failed ({type(config_exc).__name__}: "
                                f"{config_exc}); minimal emergency recovery also failed "
                                f"({type(emergency_exc).__name__}: {emergency_exc})."
                            ),
                        },
                        indent=2,
                        sort_keys=True,
                    )
                )
                return EMERGENCY_ACTION_PENDING_EXIT_CODE

        try:
            # Governance can block every risk-increasing action, but it must never
            # trap exposure. A kill process gets a broker connection whose routine
            # order path remains disabled while emergency liquidation stays usable.
            engine = build_engine(config, emergency_only=args.command == "kill")
        except Exception as exc:
            if kill_marker_written:
                print(
                    json.dumps(
                        {
                            "halted": True,
                            "flatten_requested": flatten_requested,
                            "reason": args.reason,
                            "filesystem_kill_switch": str(config.kill_switch_path),
                            "status": "accepted_state_or_broker_unavailable",
                            "warning": (
                                "Immediate broker risk reduction could not start: "
                                f"{type(exc).__name__}: {exc}"
                            ),
                        },
                        indent=2,
                        sort_keys=True,
                    )
                )
                return EMERGENCY_ACTION_PENDING_EXIT_CODE
            raise

        if args.command == "daemon":
            TradingDaemon(engine).run_forever()
            return 0
        if args.command == "status":
            output = {"mode": config.mode_label, **engine.store.summary()}
            health = _read_health_file(config)
            heartbeat = health.get("heartbeat") or engine.store.get_state("daemon_heartbeat", None)
            output["daemon_health"] = health or None
            output["daemon_heartbeat"] = heartbeat
            output["daemon_pid"] = engine.store.get_state("daemon_pid", None)
            if args.healthcheck:
                if not health:
                    health = {
                        "heartbeat": heartbeat,
                        "last_cycle_status": engine.store.get_state(
                            "daemon_last_cycle_status", "unknown"
                        ),
                        "last_error": engine.store.get_state("daemon_last_cycle_error", ""),
                        "consecutive_failures": engine.store.get_state(
                            "daemon_consecutive_failures", 0
                        ),
                    }
                _validate_health(config, health)
                output["healthcheck"] = "ok"
        elif args.command == "kill":
            if not flatten_requested:
                try:
                    with ProcessLock(
                        config.operation_lock_path,
                        timeout_seconds=0,
                        purpose="trading operation",
                    ):
                        engine.request_kill(args.reason, flatten=False)
                except LockUnavailableError:
                    # The early marker is already durable and broker pre-submit checks
                    # can see it. Cancellation has not been confirmed, so report a
                    # pending halt instead of claiming the account is frozen.
                    try:
                        engine.store.request_halt(args.reason, flatten=False)
                        engine.store.record_event(
                            "CRITICAL",
                            "MANUAL_KILL_REQUESTED",
                            args.reason,
                            {"flatten_requested": False, "operation_lock_busy": True},
                        )
                    except Exception:
                        pass
                    output = {
                        "halted": True,
                        "flatten_requested": False,
                        "reason": args.reason,
                        "status": "accepted_pending_order_cancellation",
                    }
                    exit_code = EMERGENCY_ACTION_PENDING_EXIT_CODE
                else:
                    output = {
                        "halted": True,
                        "flatten_requested": False,
                        "reason": args.reason,
                        "status": "halt_only_orders_canceled",
                    }
            else:
                try:
                    with ProcessLock(
                        config.operation_lock_path,
                        timeout_seconds=0,
                        purpose="trading operation",
                    ):
                        engine.request_kill(args.reason, flatten=True)
                except LockUnavailableError:
                    # The atomic marker is already durable. Persisting the halt is safe
                    # under SQLite concurrency and helps the active operation stop sooner.
                    try:
                        engine.store.request_halt(args.reason, flatten=True)
                        engine.store.record_event(
                            "CRITICAL",
                            "MANUAL_KILL_REQUESTED",
                            args.reason,
                            {"flatten_requested": True, "operation_lock_busy": True},
                        )
                    except Exception:
                        pass
                    output = {
                        "halted": True,
                        "flatten_requested": True,
                        "reason": args.reason,
                        "status": "accepted_active_operation_will_observe_marker",
                    }
                    exit_code = EMERGENCY_ACTION_PENDING_EXIT_CODE
                else:
                    output = {
                        "halted": True,
                        "flatten_requested": True,
                        "reason": args.reason,
                        "status": "flatten_requested",
                    }
        else:  # pragma: no cover
            with _operation_lock(config):
                if args.command == "plan":
                    output = engine.generate_plan(force=args.force).to_dict()
                elif args.command == "execute":
                    if args.force and config.broker != "simulated":
                        raise ValueError("--force execution is restricted to the simulated broker.")
                    output = asdict(engine.execute_latest_plan(force=args.force))
                elif args.command == "cycle":
                    if config.broker != "simulated":
                        raise ValueError("The cycle command is restricted to the simulated broker.")
                    plan = engine.generate_plan(force=True)
                    execution = engine.execute_latest_plan(force=True)
                    output = {"plan": plan.to_dict(), "execution": asdict(execution)}
                elif args.command == "monitor":
                    output = asdict(engine.monitor())
                elif args.command == "doctor":
                    output = engine.doctor()
                elif args.command == "resume":
                    if args.ack != RESUME_ACK_TEXT:
                        raise ValueError(
                            f"Resume acknowledgement must exactly equal {RESUME_ACK_TEXT!r}."
                        )
                    engine.resume()
                    config.kill_switch_ack_path.unlink(missing_ok=True)
                    output = {"halted": False, "message": "Manual resume completed."}
                else:  # pragma: no cover
                    raise ValueError(f"Unknown command {args.command}.")

        print(json.dumps(output, indent=2, default=_json_default, sort_keys=True))
        return exit_code
    except Exception as exc:
        print(json.dumps({"error": type(exc).__name__, "message": str(exc)}, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
