from __future__ import annotations

import copy
import hashlib
import hmac
import json
import math
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence
from uuid import UUID


_AUTH_FIELD = "authentication_hmac_sha256"
_CHECKPOINT_AUTH_FIELD = "checkpoint_hmac_sha256"
_TRANSACTION_AUTH_FIELD = "transaction_hmac_sha256"
_BROKER_TERMINAL = frozenset(
    {
        "filled",
        "canceled",
        "cancelled",
        "rejected",
        "expired",
        "failed",
        "done_for_day",
    }
)
_TERMINAL = _BROKER_TERMINAL | {"not_found"}


@dataclass(frozen=True)
class PreparedEmergencyOrder:
    incident_id: str
    client_order_id: str
    symbol: str
    side: str
    qty: float
    baseline_qty: float
    generation: int
    ordinal: int
    reused: bool = False


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


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


def _lock(handle) -> None:
    handle.seek(0)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock(handle) -> None:
    handle.seek(0)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _fsync_parent(path: Path) -> None:
    """Durably publish a rename/link on POSIX; file fsync alone is insufficient."""

    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(str(path.parent), flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class EmergencyJournal:
    """Authenticated, SQLite-independent emergency order idempotency journal.

    The journal is deliberately colocated with the durable control marker, not the
    strategy database.  Every order intent is fsync'd as ambiguous before a broker
    call, so a crash, lost response, or authoritative-state failure can only retry the
    same client ID.
    """

    def __init__(self, path: Path, authentication_key: bytes, scope: str) -> None:
        self.path = Path(path).expanduser().resolve(strict=False)
        self.key = bytes(authentication_key)
        if len(self.key) != 32:
            raise ValueError("Emergency journal authentication requires a 256-bit key.")
        self.scope = str(scope).strip()
        if not self.scope:
            raise ValueError("Emergency journal scope is required.")
        self.lock_path = self.path.with_name(f".{self.path.name}.lock")
        self.identity_path = self.path.with_suffix(self.path.suffix + ".identity")
        self.checkpoint_path = self.path.with_suffix(self.path.suffix + ".checkpoint.json")
        self.transaction_path = self.path.with_suffix(
            self.path.suffix + ".transaction.json"
        )

    @staticmethod
    def _valid_incident_id(value: str) -> str:
        try:
            parsed = UUID(str(value))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ValueError("Emergency incident identity is not a valid UUID.") from exc
        canonical = str(parsed)
        if canonical != str(value):
            raise ValueError("Emergency incident UUID must use canonical lowercase form.")
        return canonical

    def _mac(self, payload: dict[str, Any]) -> str:
        unsigned = {key: value for key, value in payload.items() if key != _AUTH_FIELD}
        return hmac.new(self.key, _canonical_json(unsigned), hashlib.sha256).hexdigest()

    def _new_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": 1,
            "scope": self.scope,
            "incidents": {},
        }
        payload[_AUTH_FIELD] = self._mac(payload)
        return payload

    def _validated_payload(self, payload: object) -> dict[str, Any]:
        if (
            not isinstance(payload, dict)
            or set(payload) != {"schema_version", "scope", "incidents", _AUTH_FIELD}
            or payload.get("schema_version") != 1
            or not isinstance(payload.get("scope"), str)
            or not isinstance(payload.get("incidents"), dict)
            or not isinstance(payload.get(_AUTH_FIELD), str)
        ):
            raise RuntimeError(
                "Emergency journal has an invalid schema; refusing new order IDs."
            )
        if not hmac.compare_digest(str(payload[_AUTH_FIELD]), self._mac(payload)):
            raise RuntimeError(
                "Emergency journal authentication failed; the key is wrong or the "
                "journal was modified."
            )
        if not hmac.compare_digest(payload["scope"], self.scope):
            raise RuntimeError(
                "Emergency journal belongs to a different broker account/configuration scope."
            )
        return payload

    def _read_existing_payload(self) -> dict[str, Any]:
        try:
            raw = self.path.read_text(encoding="utf-8")
            payload = _strict_json(raw)
        except FileNotFoundError:
            raise
        except (OSError, UnicodeDecodeError, ValueError, TypeError) as exc:
            raise RuntimeError(
                "Emergency journal is malformed; refusing new order IDs."
            ) from exc
        return self._validated_payload(payload)

    def _load(self) -> dict[str, Any]:
        try:
            return self._read_existing_payload()
        except FileNotFoundError:
            if self.identity_path.exists():
                raise RuntimeError(
                    "Emergency journal is missing while its keyed identity sentinel "
                    "still exists; refusing replacement order IDs."
                )
            return self._new_payload()

    def _identity_payload(self) -> dict[str, Any]:
        unsigned = {"schema_version": 1, "scope": self.scope}
        mac = hmac.new(
            self.key,
            b"emergency-journal-identity-v1\0" + _canonical_json(unsigned),
            hashlib.sha256,
        ).hexdigest()
        return {**unsigned, "authentication_hmac_sha256": mac}

    def _checkpoint_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        journal_sha256 = hashlib.sha256(_canonical_json(payload)).hexdigest()
        unsigned = {
            "schema_version": 1,
            "scope": self.scope,
            "journal_sha256": journal_sha256,
        }
        mac = hmac.new(
            self.key,
            b"emergency-journal-checkpoint-v1\0" + _canonical_json(unsigned),
            hashlib.sha256,
        ).hexdigest()
        return {**unsigned, _CHECKPOINT_AUTH_FIELD: mac}

    def _verify_checkpoint(self, payload: dict[str, Any]) -> None:
        expected = self._checkpoint_payload(payload)
        try:
            actual = _strict_json(self.checkpoint_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise RuntimeError(
                "Emergency journal checkpoint is missing; refusing replacement order IDs."
            ) from exc
        except (OSError, UnicodeDecodeError, ValueError, TypeError) as exc:
            raise RuntimeError("Emergency journal checkpoint is invalid.") from exc
        if not isinstance(actual, dict) or not hmac.compare_digest(
            _canonical_json(actual), _canonical_json(expected)
        ):
            raise RuntimeError(
                "Emergency journal differs from its keyed tail checkpoint; refusing "
                "replayed or replacement order IDs."
            )

    def _write_checkpoint(self, payload: dict[str, Any]) -> None:
        document = self._checkpoint_payload(payload)
        temporary = self.checkpoint_path.with_name(
            f".{self.checkpoint_path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        try:
            with temporary.open("wb") as output:
                output.write(_canonical_json(document) + b"\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.checkpoint_path)
            _fsync_parent(self.checkpoint_path)
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _document_sha256(document: object) -> str:
        return hashlib.sha256(_canonical_json(document)).hexdigest()

    def _transaction_mac(self, document: Mapping[str, Any]) -> str:
        unsigned = {
            key: value
            for key, value in document.items()
            if key != _TRANSACTION_AUTH_FIELD
        }
        return hmac.new(
            self.key,
            b"emergency-journal-transaction-v1\0" + _canonical_json(unsigned),
            hashlib.sha256,
        ).hexdigest()

    def _transaction_document(
        self,
        *,
        previous_payload: dict[str, Any] | None,
        next_payload: dict[str, Any],
    ) -> dict[str, Any]:
        previous_checkpoint = (
            self._checkpoint_payload(previous_payload)
            if previous_payload is not None
            else None
        )
        document: dict[str, Any] = {
            "schema_version": 1,
            "scope": self.scope,
            "previous_journal_sha256": (
                self._document_sha256(previous_payload)
                if previous_payload is not None
                else None
            ),
            "previous_checkpoint_sha256": (
                self._document_sha256(previous_checkpoint)
                if previous_checkpoint is not None
                else None
            ),
            "next_journal": next_payload,
            "next_journal_sha256": self._document_sha256(next_payload),
        }
        document[_TRANSACTION_AUTH_FIELD] = self._transaction_mac(document)
        return document

    def _write_transaction(
        self,
        *,
        previous_payload: dict[str, Any] | None,
        next_payload: dict[str, Any],
    ) -> None:
        document = self._transaction_document(
            previous_payload=previous_payload,
            next_payload=next_payload,
        )
        temporary = self.transaction_path.with_name(
            f".{self.transaction_path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        try:
            with temporary.open("wb") as output:
                output.write(_canonical_json(document) + b"\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.transaction_path)
            # The recovery intent must be durable before either member of the
            # journal/checkpoint pair can advance.
            _fsync_parent(self.transaction_path)
        finally:
            temporary.unlink(missing_ok=True)

    def _load_transaction(self) -> dict[str, Any]:
        try:
            decoded = _strict_json(self.transaction_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise
        except (OSError, UnicodeDecodeError, ValueError, TypeError) as exc:
            raise RuntimeError(
                "Emergency journal recovery transaction is invalid."
            ) from exc
        required = {
            "schema_version",
            "scope",
            "previous_journal_sha256",
            "previous_checkpoint_sha256",
            "next_journal",
            "next_journal_sha256",
            _TRANSACTION_AUTH_FIELD,
        }
        if (
            not isinstance(decoded, dict)
            or set(decoded) != required
            or decoded.get("schema_version") != 1
            or decoded.get("scope") != self.scope
            or not isinstance(decoded.get(_TRANSACTION_AUTH_FIELD), str)
        ):
            raise RuntimeError(
                "Emergency journal recovery transaction has an invalid schema."
            )
        if not hmac.compare_digest(
            str(decoded[_TRANSACTION_AUTH_FIELD]), self._transaction_mac(decoded)
        ):
            raise RuntimeError(
                "Emergency journal recovery transaction failed keyed authentication."
            )
        previous_journal = decoded.get("previous_journal_sha256")
        previous_checkpoint = decoded.get("previous_checkpoint_sha256")
        for label, value in (
            ("previous journal", previous_journal),
            ("previous checkpoint", previous_checkpoint),
            ("next journal", decoded.get("next_journal_sha256")),
        ):
            if value is not None and (
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise RuntimeError(
                    f"Emergency journal recovery {label} digest is invalid."
                )
        if (previous_journal is None) != (previous_checkpoint is None):
            raise RuntimeError(
                "Emergency journal recovery transaction has an incomplete prior pair."
            )
        next_payload = self._validated_payload(decoded.get("next_journal"))
        if not hmac.compare_digest(
            str(decoded["next_journal_sha256"]),
            self._document_sha256(next_payload),
        ):
            raise RuntimeError(
                "Emergency journal recovery transaction does not match its next payload."
            )
        return decoded

    def _clear_transaction(self) -> None:
        try:
            self.transaction_path.unlink()
        except FileNotFoundError:
            return
        _fsync_parent(self.transaction_path)

    def _recover_transaction(self) -> None:
        """Roll forward only a fully authenticated interrupted pair update."""

        if not self.transaction_path.exists():
            return
        transaction = self._load_transaction()
        previous_journal = transaction.get("previous_journal_sha256")
        previous_checkpoint = transaction.get("previous_checkpoint_sha256")
        next_payload = self._validated_payload(transaction["next_journal"])
        next_journal = str(transaction["next_journal_sha256"])
        next_checkpoint_document = self._checkpoint_payload(next_payload)
        next_checkpoint = self._document_sha256(next_checkpoint_document)

        if self.path.exists():
            current_payload = self._read_existing_payload()
            current_journal = self._document_sha256(current_payload)
            allowed_journals = {next_journal}
            if isinstance(previous_journal, str):
                allowed_journals.add(previous_journal)
            if current_journal not in allowed_journals:
                raise RuntimeError(
                    "Emergency journal does not match either side of its authenticated "
                    "recovery transaction."
                )
        elif previous_journal is not None:
            raise RuntimeError(
                "Emergency journal disappeared during an authenticated pair update."
            )

        if self.checkpoint_path.exists():
            try:
                checkpoint_document = _strict_json(
                    self.checkpoint_path.read_text(encoding="utf-8")
                )
            except (OSError, UnicodeDecodeError, ValueError, TypeError) as exc:
                raise RuntimeError(
                    "Emergency journal checkpoint is invalid during recovery."
                ) from exc
            current_checkpoint = self._document_sha256(checkpoint_document)
            allowed_checkpoints = {next_checkpoint}
            if isinstance(previous_checkpoint, str):
                allowed_checkpoints.add(previous_checkpoint)
            if current_checkpoint not in allowed_checkpoints:
                raise RuntimeError(
                    "Emergency checkpoint does not match either side of its authenticated "
                    "recovery transaction."
                )
        elif previous_checkpoint is not None:
            raise RuntimeError(
                "Emergency checkpoint disappeared during an authenticated pair update."
            )

        # Rewriting both members is idempotent. It handles a crash before the journal,
        # between journal and checkpoint, or after both renames but before cleanup.
        self._write(copy.deepcopy(next_payload))
        self._write_checkpoint(next_payload)
        self._ensure_identity()
        self._clear_transaction()

    def _ensure_identity(self) -> None:
        expected = self._identity_payload()
        if self.identity_path.exists():
            try:
                actual = _strict_json(self.identity_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, ValueError, TypeError) as exc:
                raise RuntimeError("Emergency journal identity is invalid.") from exc
            if not isinstance(actual, dict) or not hmac.compare_digest(
                _canonical_json(actual), _canonical_json(expected)
            ):
                raise RuntimeError(
                    "Emergency journal identity failed keyed scope verification."
                )
            return
        temporary = self.identity_path.with_name(
            f".{self.identity_path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        try:
            with temporary.open("wb") as output:
                output.write(_canonical_json(expected) + b"\n")
                output.flush()
                os.fsync(output.fileno())
            try:
                os.link(temporary, self.identity_path)
            except FileExistsError:
                pass
            except OSError:
                # Atomic replacement is safe only while the journal lock is held;
                # another legitimate writer would produce identical keyed bytes.
                os.replace(temporary, self.identity_path)
            _fsync_parent(self.identity_path)
        finally:
            temporary.unlink(missing_ok=True)
        # Authenticate a concurrently created identity before returning.
        actual = _strict_json(self.identity_path.read_text(encoding="utf-8"))
        if not isinstance(actual, dict) or not hmac.compare_digest(
            _canonical_json(actual), _canonical_json(expected)
        ):
            raise RuntimeError("Emergency journal identity verification failed.")

    def _write(self, payload: dict[str, Any]) -> None:
        payload[_AUTH_FIELD] = self._mac(payload)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(
            f".{self.path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        try:
            with temporary.open("wb") as output:
                output.write(_canonical_json(payload) + b"\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.path)
            _fsync_parent(self.path)
        finally:
            temporary.unlink(missing_ok=True)

    def _with_lock(self, callback):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            handle = self.lock_path.open("r+b", buffering=0)
        except FileNotFoundError:
            try:
                handle = self.lock_path.open("x+b", buffering=0)
            except FileExistsError:
                handle = self.lock_path.open("r+b", buffering=0)
        if self.lock_path.stat().st_size == 0:
            handle.write(b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        deadline = time.monotonic() + 5.0
        acquired = False
        try:
            while True:
                try:
                    _lock(handle)
                    acquired = True
                    break
                except (BlockingIOError, OSError):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Could not serialize emergency journal update.")
                    time.sleep(0.01)
            self._recover_transaction()
            payload = self._load()
            journal_existed = self.path.exists()
            checkpoint_existed = self.checkpoint_path.exists()
            if journal_existed:
                if not checkpoint_existed:
                    raise RuntimeError(
                        "Emergency journal checkpoint is missing; refusing replacement "
                        "order IDs."
                    )
                self._verify_checkpoint(payload)
            elif checkpoint_existed:
                raise RuntimeError(
                    "Emergency journal is missing while its checkpoint exists; refusing "
                    "replacement order IDs."
                )
            previous_payload = copy.deepcopy(payload) if journal_existed else None
            result, changed = callback(payload)
            if changed:
                # Authenticate the exact next payload before publishing the recovery
                # intent. A crash can then only roll this keyed transaction forward.
                payload[_AUTH_FIELD] = self._mac(payload)
                self._write_transaction(
                    previous_payload=previous_payload,
                    next_payload=copy.deepcopy(payload),
                )
                self._write(payload)
                self._write_checkpoint(payload)
                self._ensure_identity()
                self._clear_transaction()
            elif self.path.exists():
                self._ensure_identity()
            return result
        finally:
            if acquired:
                try:
                    _unlock(handle)
                finally:
                    handle.close()
            else:
                handle.close()

    def verify(self) -> None:
        """Authenticate an existing journal without creating or changing it."""

        def inspect(_payload: dict[str, Any]):
            # Governed startup materializes an authenticated empty journal. Its
            # separate sentinel makes later single-file deletion fail closed.
            return None, not self.path.exists()

        self._with_lock(inspect)

    def resolve_incident(self, requested_incident_id: str) -> str:
        """Preserve one unresolved incident across marker rewrites or rollback."""

        requested = self._valid_incident_id(requested_incident_id)

        def inspect(payload: dict[str, Any]):
            active = self._active_incidents(payload)
            return (active[0] if active else requested), False

        return str(self._with_lock(inspect))

    @classmethod
    def _active_incidents(cls, payload: dict[str, Any]) -> list[str]:
        """Validate and return the authenticated unresolved incident inventory."""

        active: list[str] = []
        for raw_incident_id, incident in payload["incidents"].items():
            try:
                incident_id = cls._valid_incident_id(str(raw_incident_id))
            except ValueError as exc:
                raise RuntimeError(
                    "Emergency journal contains an invalid incident identity."
                ) from exc
            if not isinstance(incident, dict) or not isinstance(
                incident.get("intents"), list
            ):
                raise RuntimeError("Emergency journal incident is malformed.")
            status = incident.get("status")
            if status not in {"active", "completed"}:
                raise RuntimeError("Emergency journal incident has an invalid status.")
            if status == "active":
                active.append(incident_id)
        active.sort()
        if len(active) > 1:
            raise RuntimeError(
                "Emergency journal contains multiple active incidents; refusing new IDs."
            )
        return active

    def active_incident_id(self) -> str | None:
        """Return the sole authenticated unresolved incident, if one exists."""

        def inspect(payload: dict[str, Any]):
            active = self._active_incidents(payload)
            return (active[0] if active else None), False

        result = self._with_lock(inspect)
        return None if result is None else str(result)

    @staticmethod
    def _reflected(intent: dict[str, Any], current_qty: float) -> bool:
        status = str(intent.get("status", "ambiguous")).lower()
        if status not in _TERMINAL:
            return False
        baseline = float(intent["baseline_qty"])
        filled = float(intent.get("filled_qty", 0.0))
        tolerance = max(1e-8, abs(baseline) * 1e-8)
        if filled <= tolerance:
            return True
        required = min(abs(baseline), filled)
        if str(intent["side"]) == "sell":
            return current_qty >= -tolerance and current_qty <= baseline - required + tolerance
        return current_qty <= tolerance and current_qty >= baseline + required - tolerance

    @staticmethod
    def _prepared(
        incident_id: str,
        intent: dict[str, Any],
        *,
        reused: bool = False,
    ) -> PreparedEmergencyOrder:
        return PreparedEmergencyOrder(
            incident_id=incident_id,
            client_order_id=str(intent["client_order_id"]),
            symbol=str(intent["symbol"]),
            side=str(intent["side"]),
            qty=float(intent["qty"]),
            baseline_qty=float(intent["baseline_qty"]),
            generation=int(intent["generation"]),
            ordinal=int(intent["ordinal"]),
            reused=reused,
        )

    def prepare_submission(
        self,
        incident_id: str,
        *,
        symbol: str,
        current_qty: float,
        side: str,
        qty: float,
    ) -> PreparedEmergencyOrder:
        """Durably return the only client ID allowed for this emergency intent."""

        incident_id = self._valid_incident_id(incident_id)
        symbol = str(symbol).upper()
        side = str(side).lower()
        current_qty = float(current_qty)
        qty = float(qty)
        if (
            not symbol
            or side not in {"buy", "sell"}
            or not math.isfinite(current_qty)
            or not math.isfinite(qty)
            or qty <= 0.0
        ):
            raise ValueError("Emergency journal intent is not finite and economically valid.")

        def update(payload: dict[str, Any]):
            incidents = payload["incidents"]
            incident = incidents.get(incident_id)
            if incident is None:
                incident = {
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "generation": 0,
                    "status": "active",
                    "intents": [],
                }
                incidents[incident_id] = incident
            if not isinstance(incident, dict) or not isinstance(incident.get("intents"), list):
                raise RuntimeError("Emergency journal incident is malformed.")
            if incident.get("status") == "completed":
                incident["generation"] = int(incident.get("generation", 0)) + 1
                incident["status"] = "active"
                incident.pop("completed_at", None)
            generation = int(incident.get("generation", 0))
            candidates = [
                item
                for item in incident["intents"]
                if isinstance(item, dict)
                and item.get("symbol") == symbol
                and int(item.get("generation", -1)) == generation
            ]
            if candidates:
                latest = max(candidates, key=lambda item: int(item.get("ordinal", -1)))
                if not self._reflected(latest, current_qty):
                    # The broker outcome is unknown or a reported fill is not visible in
                    # positions. Reuse the exact old economics and client ID; the broker
                    # adapter must resolve it by client ID instead of mutating twice.
                    return self._prepared(incident_id, latest, reused=True), False
            ordinal = 1 + max(
                (
                    int(item.get("ordinal", -1))
                    for item in incident["intents"]
                    if isinstance(item, dict)
                    and item.get("symbol") == symbol
                    and int(item.get("generation", -1)) == generation
                ),
                default=-1,
            )
            intent_payload = "|".join(
                (
                    self.scope,
                    incident_id,
                    str(generation),
                    str(ordinal),
                    symbol,
                    format(current_qty, ".12g"),
                    side,
                    format(qty, ".12g"),
                )
            )
            digest = hmac.new(
                self.key, intent_payload.encode("utf-8"), hashlib.sha256
            ).hexdigest()[:16]
            safe_symbol = "".join(ch for ch in symbol if ch.isalnum())[:8]
            client_order_id = f"qauto-emg-{incident_id.replace('-', '')[:8]}-{safe_symbol}-{digest}"[:48]
            intent = {
                "baseline_qty": current_qty,
                "client_order_id": client_order_id,
                "filled_qty": 0.0,
                "generation": generation,
                "ordinal": ordinal,
                "prepared_at": datetime.now(timezone.utc).isoformat(),
                "qty": qty,
                "side": side,
                "status": "ambiguous",
                "symbol": symbol,
            }
            incident["intents"].append(intent)
            return self._prepared(incident_id, intent), True

        return self._with_lock(update)

    def record_not_found(self, incident_id: str, client_order_id: str) -> None:
        """Retire an ambiguous intent after the broker twice proves its ID absent.

        Callers must not use this as a generic error path. It exists only for the
        stale-economics interlock: after two authoritative client-ID 404 responses and
        a stable position/order snapshot, a later reconciliation round may mint fresh
        economics without ever dispatching the obsolete quantity.
        """

        incident_id = self._valid_incident_id(incident_id)
        client_order_id = str(client_order_id)

        def update(payload: dict[str, Any]):
            incident = payload["incidents"].get(incident_id)
            if not isinstance(incident, dict) or not isinstance(
                incident.get("intents"), list
            ):
                raise RuntimeError("Missing emergency incident for absent broker order.")
            matches = [
                intent
                for intent in incident["intents"]
                if isinstance(intent, dict)
                and intent.get("client_order_id") == client_order_id
            ]
            if len(matches) != 1:
                raise RuntimeError(
                    "Absent emergency client ID is missing or duplicated in journal."
                )
            intent = matches[0]
            if str(intent.get("status", "ambiguous")).lower() != "ambiguous":
                raise RuntimeError(
                    "Only an unresolved emergency intent can be marked not found."
                )
            if intent.get("broker_order_id") is not None or abs(
                float(intent.get("filled_qty", 0.0))
            ) > 1e-10:
                raise RuntimeError(
                    "A broker-identified or filled emergency intent cannot be marked absent."
                )
            intent["status"] = "not_found"
            intent["not_found_at"] = datetime.now(timezone.utc).isoformat()
            return None, True

        self._with_lock(update)

    def record_receipt(self, incident_id: str, receipt: Any) -> None:
        incident_id = self._valid_incident_id(incident_id)

        def update(payload: dict[str, Any]):
            incident = payload["incidents"].get(incident_id)
            if not isinstance(incident, dict) or not isinstance(incident.get("intents"), list):
                raise RuntimeError("Emergency receipt has no authenticated journal incident.")
            matches = [
                item
                for item in incident["intents"]
                if isinstance(item, dict)
                and item.get("client_order_id") == receipt.client_order_id
            ]
            if len(matches) != 1:
                raise RuntimeError("Emergency receipt client ID is absent or duplicated in journal.")
            intent = matches[0]
            tolerance = max(1e-8, abs(float(intent["qty"])) * 1e-8)
            receipt_filled = float(receipt.filled_qty)
            previous_filled = float(intent.get("filled_qty", 0.0))
            receipt_status = str(receipt.status).lower()
            if (
                str(receipt.symbol).upper() != intent["symbol"]
                or str(receipt.side).lower() != intent["side"]
                or abs(float(receipt.qty) - float(intent["qty"])) > tolerance
                or not math.isfinite(receipt_filled)
                or receipt_filled < -tolerance
                or receipt_filled > float(intent["qty"]) + tolerance
                or receipt_filled + tolerance < previous_filled
            ):
                raise RuntimeError("Emergency receipt does not match authenticated journal intent.")
            prior_broker_id = intent.get("broker_order_id")
            if prior_broker_id is not None and not hmac.compare_digest(
                str(prior_broker_id), str(receipt.broker_order_id)
            ):
                raise RuntimeError("Emergency broker order identity changed in journal.")
            prior_status = str(intent.get("status", "ambiguous")).lower()
            if prior_status in _BROKER_TERMINAL and receipt_status != prior_status:
                raise RuntimeError("Emergency terminal broker status regressed in journal.")
            if receipt_status == "filled" and abs(
                receipt_filled - float(intent["qty"])
            ) > tolerance:
                raise RuntimeError("Emergency order was marked filled without full quantity.")
            intent.update(
                {
                    "broker_order_id": str(receipt.broker_order_id),
                    "filled_qty": receipt_filled,
                    "receipt_at": datetime.now(timezone.utc).isoformat(),
                    "status": receipt_status,
                }
            )
            return None, True

        self._with_lock(update)

    def complete_incident(
        self,
        incident_id: str,
        position_quantity_snapshots: Sequence[Mapping[str, float]],
        open_order_client_id_snapshots: Sequence[Sequence[str]],
    ) -> None:
        """Complete only after every prepared intent has a reflected broker receipt.

        A client-ID 404 is evidence for avoiding an obsolete resubmission, not causal
        proof that a delayed broker request can never appear. Such ``not_found`` intents
        deliberately keep the incident active until a later broker receipt is reconciled.
        """

        incident_id = self._valid_incident_id(incident_id)
        if (
            not isinstance(position_quantity_snapshots, Sequence)
            or isinstance(position_quantity_snapshots, (str, bytes))
            or not isinstance(open_order_client_id_snapshots, Sequence)
            or isinstance(open_order_client_id_snapshots, (str, bytes))
            or len(position_quantity_snapshots) < 2
            or len(open_order_client_id_snapshots) != len(position_quantity_snapshots)
        ):
            raise ValueError(
                "Emergency completion requires two matching broker position/order snapshots."
            )
        normalized_snapshots: list[dict[str, float]] = []
        for raw_snapshot in position_quantity_snapshots:
            if not isinstance(raw_snapshot, Mapping):
                raise ValueError(
                    "Emergency completion requires broker position quantities."
                )
            normalized: dict[str, float] = {}
            for raw_symbol, raw_quantity in raw_snapshot.items():
                symbol = str(raw_symbol).upper()
                quantity = float(raw_quantity)
                if not symbol or not math.isfinite(quantity):
                    raise ValueError(
                        "Emergency completion position quantities must be finite."
                    )
                normalized[symbol] = quantity
            if any(abs(quantity) > 1e-10 for quantity in normalized.values()):
                raise RuntimeError(
                    "Emergency incident cannot complete while a confirmed position remains."
                )
            normalized_snapshots.append(normalized)
        stable_symbols = set().union(*(snapshot.keys() for snapshot in normalized_snapshots))
        for symbol in stable_symbols:
            values = [snapshot.get(symbol, 0.0) for snapshot in normalized_snapshots]
            if any(
                not math.isclose(value, values[0], abs_tol=1e-10)
                for value in values[1:]
            ):
                raise RuntimeError(
                    "Emergency completion broker position snapshots are not stable."
                )
        for raw_orders in open_order_client_id_snapshots:
            if (
                not isinstance(raw_orders, Sequence)
                or isinstance(raw_orders, (str, bytes))
                or any(not isinstance(item, str) or not item for item in raw_orders)
            ):
                raise ValueError(
                    "Emergency completion open-order evidence is invalid."
                )
            if raw_orders:
                raise RuntimeError(
                    "Emergency incident cannot complete while a confirmed order remains open."
                )
        normalized_quantities = normalized_snapshots[-1]

        def update(payload: dict[str, Any]):
            incident = payload["incidents"].get(incident_id)
            if incident is None:
                # A flat incident can legitimately have no submissions; retain it so a
                # later reopened position cannot reuse an earlier generation.
                incident = {
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "generation": 0,
                    "intents": [],
                }
                payload["incidents"][incident_id] = incident
            if not isinstance(incident, dict) or not isinstance(
                incident.get("intents"), list
            ):
                raise RuntimeError("Emergency journal incident is malformed.")
            blockers: list[str] = []
            for intent in incident["intents"]:
                if not isinstance(intent, dict):
                    raise RuntimeError("Emergency journal intent is malformed.")
                client_order_id = str(intent.get("client_order_id", "<missing>"))
                status = str(intent.get("status", "ambiguous")).lower()
                broker_order_id = intent.get("broker_order_id")
                receipt_at = intent.get("receipt_at")
                if (
                    status not in _BROKER_TERMINAL
                    or not isinstance(broker_order_id, str)
                    or not broker_order_id.strip()
                    or not isinstance(receipt_at, str)
                    or not receipt_at.strip()
                ):
                    blockers.append(f"{client_order_id}:{status}")
                    continue
                symbol = str(intent.get("symbol", "")).upper()
                current_qty = normalized_quantities.get(symbol, 0.0)
                try:
                    reflected = self._reflected(intent, current_qty)
                except (KeyError, TypeError, ValueError, OverflowError) as exc:
                    raise RuntimeError("Emergency journal intent is malformed.") from exc
                if not reflected:
                    blockers.append(f"{client_order_id}:receipt_not_reflected")
            if blockers:
                raise RuntimeError(
                    "Emergency incident remains active until every intent has a terminal "
                    "broker receipt reflected in positions: " + ", ".join(blockers)
                )
            incident["status"] = "completed"
            incident["completed_at"] = datetime.now(timezone.utc).isoformat()
            return None, True

        self._with_lock(update)
