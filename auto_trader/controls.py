from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID, uuid4


@dataclass(frozen=True)
class ControlRequest:
    reason: str
    flatten: bool
    incident_id: str | None = None


def _fsync_parent(path: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(str(path.parent), flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def encode_control_marker(
    reason: str,
    *,
    flatten: bool,
    incident_id: str | None = None,
) -> str:
    normalized = " ".join(str(reason).splitlines()).strip()
    if not normalized:
        normalized = "manual_kill_switch" if flatten else "manual_halt_only"
    incident_id = str(uuid4()) if incident_id is None else str(incident_id)
    try:
        parsed = UUID(incident_id)
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError("Control incident identity must be a UUID.") from exc
    if str(parsed) != incident_id:
        raise ValueError("Control incident UUID must use canonical lowercase form.")
    return json.dumps(
        {
            "schema_version": 2,
            "incident_id": incident_id,
            "reason": normalized,
            "flatten": bool(flatten),
        },
        separators=(",", ":"),
        sort_keys=True,
    ) + "\n"


def _strict_json(text: str) -> object:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-standard JSON constant {value}")

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    return json.loads(
        text,
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )


def parse_control_marker(text: str) -> ControlRequest:
    """Parse v1/v2 controls while preserving legacy plain-text flatten markers.

    Anything that looks structured but is malformed is a flatten request. This keeps
    corruption or a partial manual write from weakening an emergency control.
    """

    stripped = str(text).strip()
    if not stripped:
        return ControlRequest("filesystem_kill_switch", True)
    if not stripped.startswith(("{", "[")):
        return ControlRequest(stripped, True)
    try:
        payload = _strict_json(stripped)
    except (TypeError, ValueError, json.JSONDecodeError):
        return ControlRequest("malformed_filesystem_kill_switch", True)
    if not isinstance(payload, dict):
        return ControlRequest("malformed_filesystem_kill_switch", True)
    version = payload.get("schema_version")
    expected = (
        {"schema_version", "reason", "flatten", "incident_id"}
        if version == 2
        else {"schema_version", "reason", "flatten"}
    )
    if (
        set(payload) != expected
        or version not in {1, 2}
        or not isinstance(payload.get("reason"), str)
        or not payload["reason"].strip()
        or not isinstance(payload.get("flatten"), bool)
    ):
        return ControlRequest("malformed_filesystem_kill_switch", True)
    incident_id = payload.get("incident_id")
    if version == 2:
        try:
            parsed = UUID(str(incident_id))
        except (TypeError, ValueError, AttributeError):
            return ControlRequest("malformed_filesystem_kill_switch", True)
        if str(parsed) != incident_id:
            return ControlRequest("malformed_filesystem_kill_switch", True)
    return ControlRequest(payload["reason"].strip(), payload["flatten"], incident_id)


def _combine_reasons(existing: str, requested: str) -> str:
    parts: list[str] = []
    for value in (existing, requested):
        for part in str(value).split(" | "):
            normalized = " ".join(part.splitlines()).strip()
            if normalized and normalized not in parts:
                parts.append(normalized)
    return " | ".join(parts) or "filesystem_kill_switch"


def _lock_control_file(handle) -> None:
    handle.seek(0)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock_control_file(handle) -> None:
    handle.seek(0)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def merge_control_marker(
    path: Path,
    reason: str,
    *,
    flatten: bool,
    timeout_seconds: float = 2.0,
    authoritative_incident_id: str | None = None,
) -> ControlRequest:
    """Atomically publish a control without weakening an existing incident.

    Every application writer uses the same advisory marker lock. Once any writer
    requests liquidation, later halt-only requests preserve ``flatten=True`` until
    an explicitly reviewed resume removes the marker. The rename keeps readers from
    observing a partially written JSON document.
    """

    marker_path = Path(path).expanduser().resolve(strict=False)
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = marker_path.with_name(f".{marker_path.name}.control.lock")
    try:
        handle = lock_path.open("r+b", buffering=0)
    except FileNotFoundError:
        try:
            handle = lock_path.open("x+b", buffering=0)
        except FileExistsError:
            handle = lock_path.open("r+b", buffering=0)
    if lock_path.stat().st_size == 0:
        handle.write(b"\n")
        handle.flush()

    deadline = time.monotonic() + max(float(timeout_seconds), 0.0)
    acquired = False
    try:
        while True:
            try:
                _lock_control_file(handle)
                acquired = True
                break
            except (BlockingIOError, OSError):
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        f"Could not serialize control marker update at {marker_path}."
                    )
                time.sleep(min(0.01, max(deadline - time.monotonic(), 0.0)))

        try:
            existing_text = marker_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            existing = None
        except (OSError, UnicodeDecodeError):
            # An unreadable existing control is already unsafe and must never be
            # interpreted as permission to publish a weaker halt-only request.
            existing = ControlRequest("unreadable_filesystem_kill_switch", True)
        else:
            existing = parse_control_marker(existing_text)

        requested_reason = " ".join(str(reason).splitlines()).strip()
        if not requested_reason:
            requested_reason = "manual_kill_switch" if flatten else "manual_halt_only"
        if authoritative_incident_id is not None:
            try:
                parsed_authoritative = UUID(str(authoritative_incident_id))
            except (TypeError, ValueError, AttributeError) as exc:
                raise ValueError("Authoritative control incident identity must be a UUID.") from exc
            if str(parsed_authoritative) != authoritative_incident_id:
                raise ValueError(
                    "Authoritative control incident UUID must use canonical lowercase form."
                )
        effective = ControlRequest(
            _combine_reasons(existing.reason if existing else "", requested_reason),
            bool(flatten) or bool(existing and existing.flatten),
            authoritative_incident_id
            or (existing.incident_id if existing and existing.incident_id else str(uuid4())),
        )
        temporary = marker_path.with_name(
            f".{marker_path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        try:
            with temporary.open("w", encoding="utf-8", newline="\n") as output:
                output.write(
                    encode_control_marker(
                        effective.reason,
                        flatten=effective.flatten,
                        incident_id=effective.incident_id,
                    )
                )
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, marker_path)
            _fsync_parent(marker_path)
        finally:
            temporary.unlink(missing_ok=True)
        return effective
    finally:
        if acquired:
            try:
                _unlock_control_file(handle)
            finally:
                handle.close()
        else:
            handle.close()


def remove_control_marker_if_unchanged(
    path: Path,
    expected: bytes | None,
    *,
    timeout_seconds: float = 2.0,
) -> bool:
    """Remove only the exact reviewed marker while holding the writer lock.

    This is the resume-side counterpart to :func:`merge_control_marker`. It closes
    the check/unlink race in which a watchdog could publish a new flatten request
    after manual review but immediately before an unconditional unlink.
    """

    marker_path = Path(path).expanduser().resolve(strict=False)
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = marker_path.with_name(f".{marker_path.name}.control.lock")
    try:
        handle = lock_path.open("r+b", buffering=0)
    except FileNotFoundError:
        try:
            handle = lock_path.open("x+b", buffering=0)
        except FileExistsError:
            handle = lock_path.open("r+b", buffering=0)
    if lock_path.stat().st_size == 0:
        handle.write(b"\n")
        handle.flush()

    deadline = time.monotonic() + max(float(timeout_seconds), 0.0)
    acquired = False
    try:
        while True:
            try:
                _lock_control_file(handle)
                acquired = True
                break
            except (BlockingIOError, OSError):
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        f"Could not serialize control marker removal at {marker_path}."
                    )
                time.sleep(min(0.01, max(deadline - time.monotonic(), 0.0)))
        try:
            current = marker_path.read_bytes()
        except FileNotFoundError:
            current = None
        except OSError as exc:
            raise RuntimeError("Could not read the control marker before removal.") from exc
        if current != expected:
            return False
        if current is not None:
            marker_path.unlink()
            _fsync_parent(marker_path)
        return True
    finally:
        if acquired:
            try:
                _unlock_control_file(handle)
            finally:
                handle.close()
        else:
            handle.close()
