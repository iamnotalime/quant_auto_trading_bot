from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import math
import re
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Mapping, Sequence
from zoneinfo import ZoneInfo

from quant_app.governance import (
    SEALED_BORROW_AS_OF_CUTOFF,
    SEALED_BORROW_RATE_DEFINITION,
    SEALED_INTERVAL_TIMEZONE,
    TrustedKeyRegistry,
    _SIGNATURE_ALGORITHM,
    _decode_base64,
    _decode_base64url,
    _verify_rsa_pkcs1_v15_sha256,
    canonical_json,
    load_trusted_key_registry,
    sha256_bytes,
    strict_json_loads,
)

if TYPE_CHECKING:
    from auto_trader.store import StateStore


BORROW_EVIDENCE_SCHEMA_VERSION = 1
BORROW_EVIDENCE_PURPOSE = "governed_live_borrow_evidence_v1"
BORROW_AVAILABILITY_DEFINITION = (
    "account_bound_point_in_time_locate_available_through_available_quantity_shares"
)
BORROW_RECALL_DEFINITION = "point_in_time_lender_recall_or_mandatory_buy_in"
BORROW_EVIDENCE_ANCHOR_KEY = "live_borrow_evidence_anchor"
MAX_BORROW_EVIDENCE_LIFETIME = timedelta(hours=24)
MAX_BORROW_TERM_AGE_SECONDS = 300
BORROW_AUTHORIZATION_FRESHNESS_MARGIN_SECONDS = 1.0
_MAX_ENVELOPE_BYTES = 1_000_000
_MAX_TERMS_BYTES = 32_000_000
_MAX_ROWS = 20_000
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{7,127}$")
_SYMBOL_RE = re.compile(r"^[A-Z][A-Z0-9./-]{0,14}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_CSV_HEADER = (
    "Session",
    "Symbol",
    "AsOfTimestamp",
    "Available",
    "AvailableQuantity",
    "AnnualRate",
    "Recalled",
)
_PAYLOAD_FIELDS = {
    "schema_version",
    "purpose",
    "snapshot_id",
    "provider_id",
    "venue_id",
    "account_id",
    "intended_session",
    "issued_at",
    "expires_at",
    "timezone",
    "decision_cutoff",
    "availability_definition",
    "annual_rate_definition",
    "recall_definition",
    "row_count",
    "symbols",
    "terms_sha256",
}


class BorrowEvidenceError(RuntimeError):
    """Live borrow evidence is missing, stale, unauthenticated, or malformed."""


class LiveBorrowPolicyError(BorrowEvidenceError):
    """One or more current/planned shorts violate authenticated borrow terms."""

    def __init__(self, violations: Mapping[str, str]) -> None:
        self.violations = dict(sorted(violations.items()))
        details = ", ".join(
            f"{symbol}:{reason}" for symbol, reason in self.violations.items()
        )
        super().__init__("Authenticated live borrow policy rejected shorts: " + details)


@dataclass(frozen=True)
class LiveBorrowTerm:
    symbol: str
    available: bool
    available_quantity: float
    annual_rate: float
    recalled: bool
    as_of: datetime


@dataclass(frozen=True)
class VerifiedBorrowEvidence:
    intended_session: date
    terms: Mapping[str, LiveBorrowTerm]
    provenance: Mapping[str, str]

    def require_fresh(
        self,
        *,
        now: datetime,
        max_term_age_seconds: int,
        minimum_remaining_seconds: float = (
            BORROW_AUTHORIZATION_FRESHNESS_MARGIN_SECONDS
        ),
    ) -> None:
        """Recheck term age/expiry cheaply at the final mutation boundary."""

        if now.tzinfo is None or now.utcoffset() is None:
            raise BorrowEvidenceError("Borrow freshness recheck requires an absolute clock.")
        if (
            isinstance(max_term_age_seconds, bool)
            or not isinstance(max_term_age_seconds, int)
            or not 1 <= max_term_age_seconds <= MAX_BORROW_TERM_AGE_SECONDS
        ):
            raise BorrowEvidenceError("Borrow freshness age policy is invalid.")
        try:
            margin = float(minimum_remaining_seconds)
        except (TypeError, ValueError) as exc:
            raise BorrowEvidenceError("Borrow freshness margin is invalid.") from exc
        if not math.isfinite(margin) or margin < 0.0:
            raise BorrowEvidenceError("Borrow freshness margin is invalid.")
        current = now.astimezone(timezone.utc)
        expires = _parse_timestamp(self.provenance.get("expires_at"), field="expires_at")
        if expires <= current + timedelta(seconds=margin):
            raise BorrowEvidenceError(
                "Borrow evidence expires before the final authorization safety margin."
            )
        stale = sorted(
            term.symbol
            for term in self.terms.values()
            if (current - term.as_of).total_seconds() + margin
            > max_term_age_seconds
        )
        future = sorted(
            term.symbol
            for term in self.terms.values()
            if (current - term.as_of).total_seconds() < -5.0
        )
        if future:
            raise BorrowEvidenceError(
                "Borrow terms are future-dated at final authorization: "
                + ", ".join(future)
                + "."
            )
        if stale:
            raise BorrowEvidenceError(
                "Borrow terms aged out before final authorization: "
                + ", ".join(stale)
                + "."
            )

    def require_eligible_shorts(
        self,
        symbols: Sequence[str],
        *,
        max_annual_rate: float,
        required_quantities: Mapping[str, float] | None = None,
    ) -> None:
        """Reject missing locates, recalls, high rates, and insufficient locate size."""

        try:
            ceiling = float(max_annual_rate)
        except (TypeError, ValueError) as exc:
            raise BorrowEvidenceError(
                "Maximum live annual borrow rate must be numeric."
            ) from exc
        if not math.isfinite(ceiling) or not 0.0 <= ceiling <= 10.0:
            raise BorrowEvidenceError(
                "Maximum live annual borrow rate must be finite and between 0 and 10."
            )
        violations: dict[str, str] = {}
        normalized: set[str] = set()
        for value in symbols:
            symbol = str(value)
            if not _SYMBOL_RE.fullmatch(symbol):
                violations[symbol or "<missing>"] = "invalid_symbol"
                continue
            normalized.add(symbol)
        required: dict[str, float] = {}
        for raw_symbol, raw_quantity in (required_quantities or {}).items():
            symbol = str(raw_symbol)
            if not _SYMBOL_RE.fullmatch(symbol):
                violations[symbol or "<missing>"] = "invalid_symbol"
                continue
            try:
                quantity = float(raw_quantity)
            except (TypeError, ValueError):
                violations[symbol] = "invalid_required_quantity"
                continue
            if not math.isfinite(quantity) or quantity < 0.0:
                violations[symbol] = "invalid_required_quantity"
                continue
            normalized.add(symbol)
            required[symbol] = max(required.get(symbol, 0.0), quantity)
        for symbol in sorted(normalized):
            term = self.terms.get(symbol)
            if term is None:
                violations[symbol] = "missing_term"
            elif term.recalled:
                violations[symbol] = "recalled"
            elif not term.available:
                violations[symbol] = "unavailable"
            elif term.annual_rate > ceiling + 1e-12:
                violations[symbol] = "annual_rate_above_deployment_ceiling"
            elif term.available_quantity + 1e-8 < required.get(symbol, 0.0):
                violations[symbol] = "available_quantity_below_required_short"
        if violations:
            raise LiveBorrowPolicyError(violations)


def _read_bounded(path: str | Path | None, *, label: str, maximum: int) -> bytes:
    if path is None:
        raise BorrowEvidenceError(f"{label} path is not configured.")
    candidate = Path(path).expanduser()
    try:
        size = candidate.stat().st_size
        if size <= 0:
            raise BorrowEvidenceError(f"{label} is empty.")
        if size > maximum:
            raise BorrowEvidenceError(f"{label} exceeds the {maximum}-byte limit.")
        raw = candidate.read_bytes()
    except BorrowEvidenceError:
        raise
    except OSError as exc:
        raise BorrowEvidenceError(f"{label} is unreadable: {exc}") from exc
    if len(raw) != size:
        raise BorrowEvidenceError(
            f"{label} changed size while being read; use an atomic snapshot publish."
        )
    return raw


def _parse_timestamp(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise BorrowEvidenceError(
            f"Borrow evidence {field} must be an ISO-8601 timestamp with an offset."
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BorrowEvidenceError(
            f"Borrow evidence {field} must be a valid ISO-8601 timestamp."
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise BorrowEvidenceError(
            f"Borrow evidence {field} must include an explicit UTC offset."
        )
    return parsed.astimezone(timezone.utc)


def _parse_session(value: Any, *, field: str) -> date:
    if not isinstance(value, str) or not _DATE_RE.fullmatch(value):
        raise BorrowEvidenceError(
            f"Borrow evidence {field} must be an exact YYYY-MM-DD session."
        )
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise BorrowEvidenceError(
            f"Borrow evidence {field} is not a valid calendar date."
        ) from exc
    if parsed.isoformat() != value:
        raise BorrowEvidenceError(f"Borrow evidence {field} is not canonical.")
    return parsed


def _bound_identity(value: Any, expected: str, *, field: str) -> str:
    if not isinstance(expected, str) or not _IDENTIFIER_RE.fullmatch(expected):
        raise BorrowEvidenceError(f"Configured borrow {field} is missing or invalid.")
    if not isinstance(value, str) or not hmac.compare_digest(value, expected):
        raise BorrowEvidenceError(
            f"Borrow evidence {field} does not match the deployment identity."
        )
    return value


def _validate_symbols(value: Any, expected_symbols: Sequence[str]) -> tuple[str, ...]:
    expected = tuple(str(symbol) for symbol in expected_symbols)
    if (
        not expected
        or len(expected) > _MAX_ROWS
        or len(set(expected)) != len(expected)
        or any(not _SYMBOL_RE.fullmatch(symbol) for symbol in expected)
    ):
        raise BorrowEvidenceError(
            "Requested borrow universe must contain unique canonical broker symbols."
        )
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise BorrowEvidenceError("Borrow evidence symbols must be an ordered string array.")
    supplied = tuple(value)
    if supplied != expected:
        raise BorrowEvidenceError(
            "Borrow evidence symbols do not exactly match the requested ordered universe."
        )
    return supplied


def _verify_signature(
    envelope: Mapping[str, Any],
    payload: Mapping[str, Any],
    registry: TrustedKeyRegistry,
) -> tuple[str, bytes]:
    signature_object = envelope.get("signature")
    if not isinstance(signature_object, dict) or set(signature_object) != {
        "algorithm",
        "key_id",
        "value",
    }:
        raise BorrowEvidenceError(
            "Borrow evidence signature must contain exactly algorithm, key_id, and value."
        )
    if signature_object.get("algorithm") != _SIGNATURE_ALGORITHM:
        raise BorrowEvidenceError(
            f"Borrow evidence signature algorithm must be {_SIGNATURE_ALGORITHM}."
        )
    key_id = signature_object.get("key_id")
    if not isinstance(key_id, str) or not _IDENTIFIER_RE.fullmatch(key_id):
        raise BorrowEvidenceError("Borrow evidence signing key_id is invalid.")
    if not registry.valid:
        detail = "; ".join(registry.errors) or "unknown validation error"
        raise BorrowEvidenceError(
            "Borrow evidence trusted-key registry is invalid: " + detail
        )
    if key_id not in registry.keys:
        raise BorrowEvidenceError(
            "Borrow evidence key_id is not in the deployment-pinned registry."
        )
    key = registry.keys[key_id]
    if key.get("status") != "active" or key.get("algorithm") != _SIGNATURE_ALGORITHM:
        raise BorrowEvidenceError("Borrow evidence signing key is not active and compatible.")
    try:
        modulus = int.from_bytes(_decode_base64url(key.get("modulus_base64url")), "big")
        exponent = int(key.get("exponent"))
        signature = _decode_base64(signature_object.get("value"))
    except (TypeError, ValueError, OverflowError) as exc:
        raise BorrowEvidenceError(
            f"Borrow evidence signing key or signature is invalid: {exc}"
        ) from exc
    if not _verify_rsa_pkcs1_v15_sha256(
        message=canonical_json(payload),
        signature=signature,
        modulus=modulus,
        exponent=exponent,
    ):
        raise BorrowEvidenceError("Borrow evidence RSA/SHA-256 signature verification failed.")
    return key_id, signature


def _parse_boolean(value: str, *, field: str, symbol: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise BorrowEvidenceError(
        f"Borrow term {field} for {symbol} must be exactly 'true' or 'false'."
    )


def _parse_terms(
    raw: bytes,
    *,
    symbols: tuple[str, ...],
    intended_session: date,
    current: datetime,
    max_term_age_seconds: int,
) -> Mapping[str, LiveBorrowTerm]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise BorrowEvidenceError("Borrow terms CSV must be strict UTF-8.") from exc
    if text.startswith("\ufeff") or "\x00" in text:
        raise BorrowEvidenceError("Borrow terms CSV contains a forbidden BOM or NUL byte.")
    try:
        reader = csv.reader(io.StringIO(text, newline=""), strict=True)
        rows = list(reader)
    except csv.Error as exc:
        raise BorrowEvidenceError(f"Borrow terms CSV is malformed: {exc}") from exc
    if not rows or tuple(rows[0]) != _CSV_HEADER:
        raise BorrowEvidenceError(
            "Borrow terms CSV header must exactly match " + ",".join(_CSV_HEADER) + "."
        )
    if len(rows) - 1 != len(symbols):
        raise BorrowEvidenceError(
            "Borrow terms CSV must contain exactly one row for every signed symbol."
        )
    if len(rows) - 1 > _MAX_ROWS:
        raise BorrowEvidenceError("Borrow terms CSV exceeds the row safety limit.")

    ny = ZoneInfo(SEALED_INTERVAL_TIMEZONE)
    cutoff = datetime.combine(intended_session, time(9, 30), tzinfo=ny).astimezone(
        timezone.utc
    )
    terms: dict[str, LiveBorrowTerm] = {}
    supplied_order: list[str] = []
    for number, row in enumerate(rows[1:], start=2):
        if len(row) != len(_CSV_HEADER):
            raise BorrowEvidenceError(
                f"Borrow terms CSV row {number} does not have seven fields."
            )
        (
            session_raw,
            symbol,
            as_of_raw,
            available_raw,
            available_quantity_raw,
            rate_raw,
            recalled_raw,
        ) = row
        session = _parse_session(session_raw, field=f"CSV row {number} Session")
        if session != intended_session:
            raise BorrowEvidenceError(
                f"Borrow term {symbol or number} is not bound to the intended session."
            )
        if not _SYMBOL_RE.fullmatch(symbol):
            raise BorrowEvidenceError(f"Borrow terms CSV row {number} has an invalid symbol.")
        if symbol in terms:
            raise BorrowEvidenceError(f"Borrow terms CSV contains duplicate symbol {symbol}.")
        as_of = _parse_timestamp(as_of_raw, field=f"CSV row {number} AsOfTimestamp")
        local_as_of = as_of.astimezone(ny)
        if local_as_of.date() != intended_session or as_of > cutoff:
            raise BorrowEvidenceError(
                f"Borrow term {symbol} is after its session's 09:30 decision cutoff."
            )
        age_seconds = (current - as_of).total_seconds()
        if age_seconds < -5.0:
            raise BorrowEvidenceError(f"Borrow term {symbol} is timestamped in the future.")
        if age_seconds > max_term_age_seconds:
            raise BorrowEvidenceError(f"Borrow term {symbol} is stale for live execution.")
        available = _parse_boolean(available_raw, field="Available", symbol=symbol)
        recalled = _parse_boolean(recalled_raw, field="Recalled", symbol=symbol)
        if recalled and available:
            raise BorrowEvidenceError(
                f"Borrow term {symbol} cannot be both recalled and available."
            )
        try:
            available_quantity = float(available_quantity_raw)
        except (TypeError, ValueError) as exc:
            raise BorrowEvidenceError(
                f"Borrow term AvailableQuantity for {symbol} must be numeric."
            ) from exc
        if (
            not math.isfinite(available_quantity)
            or available_quantity < 0.0
            or available_quantity > 1e15
        ):
            raise BorrowEvidenceError(
                f"Borrow term AvailableQuantity for {symbol} must be finite and between 0 and 1e15."
            )
        if available and available_quantity <= 0.0:
            raise BorrowEvidenceError(
                f"Borrow term {symbol} is available but has no positive locate quantity."
            )
        if not available and available_quantity > 0.0:
            raise BorrowEvidenceError(
                f"Borrow term {symbol} is unavailable but has positive locate quantity."
            )
        try:
            annual_rate = float(rate_raw)
        except (TypeError, ValueError) as exc:
            raise BorrowEvidenceError(
                f"Borrow term AnnualRate for {symbol} must be numeric."
            ) from exc
        if not math.isfinite(annual_rate) or not 0.0 <= annual_rate <= 10.0:
            raise BorrowEvidenceError(
                f"Borrow term AnnualRate for {symbol} must be finite and between 0 and 10."
            )
        supplied_order.append(symbol)
        terms[symbol] = LiveBorrowTerm(
            symbol=symbol,
            available=available,
            available_quantity=available_quantity,
            annual_rate=annual_rate,
            recalled=recalled,
            as_of=as_of,
        )
    if tuple(supplied_order) != symbols:
        raise BorrowEvidenceError(
            "Borrow terms CSV rows do not exactly match the signed ordered universe."
        )
    return MappingProxyType(terms)


def load_signed_borrow_evidence(
    *,
    envelope_path: str | Path | None,
    terms_path: str | Path | None,
    public_keys_path: str | Path | None,
    public_keys_sha256: str | None,
    expected_provider_id: str,
    expected_venue_id: str,
    expected_account_id: str,
    expected_symbols: Sequence[str],
    intended_session: date,
    max_term_age_seconds: int = MAX_BORROW_TERM_AGE_SECONDS,
    now: datetime | None = None,
) -> VerifiedBorrowEvidence:
    """Verify an exact-session, account-bound PIT locate/rate/recall snapshot."""

    if not isinstance(intended_session, date) or isinstance(intended_session, datetime):
        raise BorrowEvidenceError("Borrow intended_session must be a calendar date.")
    if (
        isinstance(max_term_age_seconds, bool)
        or not isinstance(max_term_age_seconds, int)
        or not 1 <= max_term_age_seconds <= MAX_BORROW_TERM_AGE_SECONDS
    ):
        raise BorrowEvidenceError(
            "Borrow max_term_age_seconds must be an integer between 1 and 300."
        )
    current_value = now or datetime.now(timezone.utc)
    if current_value.tzinfo is None or current_value.utcoffset() is None:
        raise BorrowEvidenceError("Borrow evidence verification now must be timezone-aware.")
    current = current_value.astimezone(timezone.utc)
    local_current = current.astimezone(ZoneInfo(SEALED_INTERVAL_TIMEZONE))
    if local_current.date() != intended_session or not (
        time(9, 30) <= local_current.time().replace(tzinfo=None) < time(9, 35)
    ):
        raise BorrowEvidenceError(
            "Borrow evidence is valid only during its exact 09:30<=time<09:35 execution session."
        )

    envelope_raw = _read_bounded(
        envelope_path,
        label="Borrow evidence envelope",
        maximum=_MAX_ENVELOPE_BYTES,
    )
    terms_raw = _read_bounded(
        terms_path,
        label="Borrow terms CSV",
        maximum=_MAX_TERMS_BYTES,
    )
    try:
        envelope = strict_json_loads(envelope_raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise BorrowEvidenceError(
            f"Borrow evidence envelope is not strict UTF-8 JSON: {exc}"
        ) from exc
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
        raise BorrowEvidenceError(
            "Borrow evidence envelope must contain exactly payload and signature."
        )
    payload = envelope.get("payload")
    if not isinstance(payload, dict) or set(payload) != _PAYLOAD_FIELDS:
        raise BorrowEvidenceError(
            "Borrow evidence payload fields do not exactly match schema version 1."
        )
    if payload.get("schema_version") != BORROW_EVIDENCE_SCHEMA_VERSION:
        raise BorrowEvidenceError("Borrow evidence schema_version must equal 1.")
    if payload.get("purpose") != BORROW_EVIDENCE_PURPOSE:
        raise BorrowEvidenceError(
            f"Borrow evidence purpose must equal {BORROW_EVIDENCE_PURPOSE}."
        )
    snapshot_id = payload.get("snapshot_id")
    if not isinstance(snapshot_id, str) or not _IDENTIFIER_RE.fullmatch(snapshot_id):
        raise BorrowEvidenceError("Borrow evidence snapshot_id is invalid.")
    provider_id = _bound_identity(
        payload.get("provider_id"), expected_provider_id, field="provider_id"
    )
    venue_id = _bound_identity(
        payload.get("venue_id"), expected_venue_id, field="venue_id"
    )
    account_id = _bound_identity(
        payload.get("account_id"), expected_account_id, field="account_id"
    )
    signed_session = _parse_session(
        payload.get("intended_session"), field="intended_session"
    )
    if signed_session != intended_session:
        raise BorrowEvidenceError(
            "Borrow evidence intended_session does not match routine execution."
        )
    fixed = {
        "timezone": SEALED_INTERVAL_TIMEZONE,
        "decision_cutoff": SEALED_BORROW_AS_OF_CUTOFF,
        "availability_definition": BORROW_AVAILABILITY_DEFINITION,
        "annual_rate_definition": SEALED_BORROW_RATE_DEFINITION,
        "recall_definition": BORROW_RECALL_DEFINITION,
    }
    for field, expected in fixed.items():
        if payload.get(field) != expected:
            raise BorrowEvidenceError(
                f"Borrow evidence {field} must equal {expected!r}."
            )
    symbols = _validate_symbols(payload.get("symbols"), expected_symbols)
    row_count = payload.get("row_count")
    if isinstance(row_count, bool) or not isinstance(row_count, int) or row_count != len(symbols):
        raise BorrowEvidenceError(
            "Borrow evidence row_count must equal the exact signed universe size."
        )

    registry = load_trusted_key_registry(public_keys_path, public_keys_sha256)
    key_id, signature = _verify_signature(envelope, payload, registry)
    terms_hash = payload.get("terms_sha256")
    if not isinstance(terms_hash, str) or not _SHA256_RE.fullmatch(terms_hash):
        raise BorrowEvidenceError(
            "Borrow evidence terms_sha256 must be a lowercase SHA-256 digest."
        )
    if not hmac.compare_digest(terms_hash, sha256_bytes(terms_raw)):
        raise BorrowEvidenceError(
            "Borrow evidence terms_sha256 does not match the exact file bytes."
        )

    issued = _parse_timestamp(payload.get("issued_at"), field="issued_at")
    expires = _parse_timestamp(payload.get("expires_at"), field="expires_at")
    if issued > current + timedelta(seconds=5):
        raise BorrowEvidenceError("Borrow evidence issued_at is in the future.")
    if expires <= current:
        raise BorrowEvidenceError("Borrow evidence has expired.")
    if expires <= issued or expires - issued > MAX_BORROW_EVIDENCE_LIFETIME:
        raise BorrowEvidenceError(
            "Borrow evidence expiry must follow issuance by no more than 24 hours."
        )
    endpoint = datetime.combine(
        intended_session,
        time(9, 35),
        tzinfo=ZoneInfo(SEALED_INTERVAL_TIMEZONE),
    ).astimezone(timezone.utc)
    if expires <= endpoint:
        raise BorrowEvidenceError(
            "Borrow evidence must remain valid beyond the signed 09:35 endpoint."
        )

    terms = _parse_terms(
        terms_raw,
        symbols=symbols,
        intended_session=intended_session,
        current=current,
        max_term_age_seconds=max_term_age_seconds,
    )
    latest_as_of = max(term.as_of for term in terms.values())
    earliest_as_of = min(term.as_of for term in terms.values())
    if issued < latest_as_of:
        raise BorrowEvidenceError(
            "Borrow evidence was issued before its latest signed term snapshot."
        )
    symbol_hash = sha256_bytes(canonical_json(list(symbols)))
    provenance = {
        "snapshot_id": snapshot_id,
        "provider_id": provider_id,
        "venue_id": venue_id,
        "account_id": account_id,
        "intended_session": intended_session.isoformat(),
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "earliest_term_as_of": earliest_as_of.isoformat(),
        "latest_term_as_of": latest_as_of.isoformat(),
        # Retain the exact per-symbol observation clocks, not merely their range. The
        # authenticated state anchor can then reject a later-issued envelope that rolls
        # back one hard-to-borrow name while advancing another name's timestamp.
        "term_as_of_by_symbol_json": canonical_json(
            {
                symbol: terms[symbol].as_of.isoformat()
                for symbol in symbols
            }
        ).decode("utf-8"),
        # A timestamp-only anchor would still allow a later-issued envelope to
        # rewrite a locate, recall, quantity, or rate while reusing that symbol's
        # observation clock.  Bind the normalized economic value for every name so
        # same-clock corrections fail closed unless the schema later introduces an
        # explicit signed correction sequence.
        "term_value_sha256_by_symbol_json": canonical_json(
            {
                symbol: sha256_bytes(
                    canonical_json(
                        {
                            "symbol": symbol,
                            "available": terms[symbol].available,
                            "available_quantity": terms[symbol].available_quantity,
                            "annual_rate": terms[symbol].annual_rate,
                            "recalled": terms[symbol].recalled,
                        }
                    )
                )
                for symbol in symbols
            }
        ).decode("utf-8"),
        "envelope_sha256": sha256_bytes(envelope_raw),
        "payload_sha256": sha256_bytes(canonical_json(payload)),
        "terms_sha256": sha256_bytes(terms_raw),
        "symbols_sha256": symbol_hash,
        "trusted_key_registry_sha256": registry.registry_hash,
        "signing_key_id": key_id,
        "signature_sha256": hashlib.sha256(signature).hexdigest(),
        "decision_cutoff": SEALED_BORROW_AS_OF_CUTOFF,
        "annual_rate_definition": SEALED_BORROW_RATE_DEFINITION,
        "max_term_age_seconds": str(max_term_age_seconds),
    }
    return VerifiedBorrowEvidence(
        intended_session=intended_session,
        terms=terms,
        provenance=MappingProxyType(provenance),
    )


@dataclass(frozen=True)
class SignedBorrowEvidenceProvider:
    envelope_path: Path | None
    terms_path: Path | None
    public_keys_path: Path | None
    public_keys_sha256: str
    provider_id: str
    venue_id: str
    account_id: str
    max_term_age_seconds: int = MAX_BORROW_TERM_AGE_SECONDS

    def load(
        self,
        symbols: Sequence[str],
        intended_session: date,
        *,
        now: datetime | None = None,
    ) -> VerifiedBorrowEvidence:
        return load_signed_borrow_evidence(
            envelope_path=self.envelope_path,
            terms_path=self.terms_path,
            public_keys_path=self.public_keys_path,
            public_keys_sha256=self.public_keys_sha256,
            expected_provider_id=self.provider_id,
            expected_venue_id=self.venue_id,
            expected_account_id=self.account_id,
            expected_symbols=symbols,
            intended_session=intended_session,
            max_term_age_seconds=self.max_term_age_seconds,
            now=now,
        )


def _normalized_anchor(provenance: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "intended_session",
        "issued_at",
        "snapshot_id",
        "payload_sha256",
        "terms_sha256",
        "account_id",
        "symbols_sha256",
        "earliest_term_as_of",
        "latest_term_as_of",
        "term_as_of_by_symbol_json",
        "term_value_sha256_by_symbol_json",
    }
    if not isinstance(provenance, Mapping) or not required.issubset(provenance):
        raise BorrowEvidenceError("Borrow evidence provenance lacks anti-rollback fields.")
    session = _parse_session(provenance.get("intended_session"), field="anchor session")
    issued = _parse_timestamp(provenance.get("issued_at"), field="anchor issued_at")
    result = {
        "intended_session": session.isoformat(),
        "issued_at": issued.isoformat(),
        "earliest_term_as_of": _parse_timestamp(
            provenance.get("earliest_term_as_of"), field="anchor earliest_term_as_of"
        ).isoformat(),
        "latest_term_as_of": _parse_timestamp(
            provenance.get("latest_term_as_of"), field="anchor latest_term_as_of"
        ).isoformat(),
    }
    for field in ("snapshot_id", "account_id"):
        value = provenance.get(field)
        if not isinstance(value, str) or not _IDENTIFIER_RE.fullmatch(value):
            raise BorrowEvidenceError(f"Borrow evidence anchor {field} is invalid.")
        result[field] = value
    for field in ("payload_sha256", "terms_sha256", "symbols_sha256"):
        value = provenance.get(field)
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            raise BorrowEvidenceError(f"Borrow evidence anchor {field} is invalid.")
        result[field] = value
    raw_term_clocks = provenance.get("term_as_of_by_symbol_json")
    if not isinstance(raw_term_clocks, str) or not raw_term_clocks:
        raise BorrowEvidenceError(
            "Borrow evidence anchor per-symbol term clocks are missing."
        )
    try:
        parsed_term_clocks = strict_json_loads(raw_term_clocks.encode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise BorrowEvidenceError(
            "Borrow evidence anchor per-symbol term clocks are invalid JSON."
        ) from exc
    if (
        not isinstance(parsed_term_clocks, dict)
        or not parsed_term_clocks
        or len(parsed_term_clocks) > _MAX_ROWS
        or any(not isinstance(symbol, str) or not _SYMBOL_RE.fullmatch(symbol)
               for symbol in parsed_term_clocks)
    ):
        raise BorrowEvidenceError(
            "Borrow evidence anchor per-symbol term clocks are malformed."
        )
    normalized_term_clocks = {
        symbol: _parse_timestamp(value, field=f"anchor term_as_of[{symbol}]").isoformat()
        for symbol, value in sorted(parsed_term_clocks.items())
    }
    earliest = min(datetime.fromisoformat(value) for value in normalized_term_clocks.values())
    latest = max(datetime.fromisoformat(value) for value in normalized_term_clocks.values())
    if earliest.isoformat() != result["earliest_term_as_of"] or latest.isoformat() != result[
        "latest_term_as_of"
    ]:
        raise BorrowEvidenceError(
            "Borrow evidence anchor term-clock range does not match its per-symbol clocks."
        )
    # Keep the normalized form self-describing and idempotent: this exact dictionary is
    # persisted in StateStore and must pass through this validator again on the next run.
    result["term_as_of_by_symbol_json"] = canonical_json(
        normalized_term_clocks
    ).decode("utf-8")
    raw_term_values = provenance.get("term_value_sha256_by_symbol_json")
    if not isinstance(raw_term_values, str) or not raw_term_values:
        raise BorrowEvidenceError(
            "Borrow evidence anchor per-symbol term values are missing."
        )
    try:
        parsed_term_values = strict_json_loads(raw_term_values.encode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise BorrowEvidenceError(
            "Borrow evidence anchor per-symbol term values are invalid JSON."
        ) from exc
    if (
        not isinstance(parsed_term_values, dict)
        or set(parsed_term_values) != set(normalized_term_clocks)
        or any(
            not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest)
            for digest in parsed_term_values.values()
        )
    ):
        raise BorrowEvidenceError(
            "Borrow evidence anchor per-symbol term values are malformed."
        )
    result["term_value_sha256_by_symbol_json"] = canonical_json(
        {symbol: parsed_term_values[symbol] for symbol in sorted(parsed_term_values)}
    ).decode("utf-8")
    return result


def anchor_borrow_evidence(
    store: StateStore,
    provenance: Mapping[str, Any],
) -> dict[str, Any]:
    """Persist a keyed, monotonic anti-rollback anchor in authenticated state.

    The engine's cross-process operation lock serializes routine executions. StateStore
    authenticates this value and commits it into its external inventory checkpoint, so
    deletion or an unauthenticated rewrite fails the next critical integrity check.
    """

    if getattr(store, "authentication_key", None) is None:
        raise BorrowEvidenceError(
            "Borrow evidence anti-rollback requires authenticated StateStore state."
        )
    candidate = _normalized_anchor(provenance)

    def monotonic_update(prior_raw: Any | None) -> dict[str, Any]:
        if prior_raw is None:
            return candidate
        prior = _normalized_anchor(prior_raw)
        candidate_session = date.fromisoformat(candidate["intended_session"])
        prior_session = date.fromisoformat(prior["intended_session"])
        candidate_issued = datetime.fromisoformat(candidate["issued_at"])
        prior_issued = datetime.fromisoformat(prior["issued_at"])
        if candidate_session < prior_session or (
            candidate_session == prior_session and candidate_issued < prior_issued
        ):
            raise BorrowEvidenceError(
                "Signed borrow evidence rollback was rejected by the authenticated anchor."
            )
        if candidate_session == prior_session:
            candidate_clocks = strict_json_loads(
                candidate["term_as_of_by_symbol_json"].encode("utf-8")
            )
            prior_clocks = strict_json_loads(
                prior["term_as_of_by_symbol_json"].encode("utf-8")
            )
            candidate_values = strict_json_loads(
                candidate["term_value_sha256_by_symbol_json"].encode("utf-8")
            )
            prior_values = strict_json_loads(
                prior["term_value_sha256_by_symbol_json"].encode("utf-8")
            )
            if (
                set(candidate_clocks) != set(prior_clocks)
                or set(candidate_values) != set(prior_values)
                or set(candidate_clocks) != set(candidate_values)
            ):
                raise BorrowEvidenceError(
                    "Signed borrow evidence changed its anchored session universe."
                )
            regressed = sorted(
                symbol
                for symbol in candidate_clocks
                if datetime.fromisoformat(candidate_clocks[symbol])
                < datetime.fromisoformat(prior_clocks[symbol])
            )
            if regressed:
                raise BorrowEvidenceError(
                    "Signed borrow evidence rolled back per-symbol term clocks: "
                    + ", ".join(regressed)
                    + "."
                )
            same_clock_rewrites = sorted(
                symbol
                for symbol in candidate_clocks
                if candidate_clocks[symbol] == prior_clocks[symbol]
                and not hmac.compare_digest(
                    candidate_values[symbol], prior_values[symbol]
                )
            )
            if same_clock_rewrites:
                raise BorrowEvidenceError(
                    "Signed borrow evidence rewrote same-clock term values: "
                    + ", ".join(same_clock_rewrites)
                    + "."
                )
        identity_fields = (
            "snapshot_id",
            "payload_sha256",
            "terms_sha256",
            "account_id",
            "symbols_sha256",
        )
        if candidate_session == prior_session and candidate_issued == prior_issued and any(
            not hmac.compare_digest(candidate[field], prior[field])
            for field in identity_fields
        ):
            raise BorrowEvidenceError(
                "Signed borrow evidence reused an issue time with different identity."
            )
        return candidate

    try:
        return store.atomic_authenticated_state_update(
            BORROW_EVIDENCE_ANCHOR_KEY,
            monotonic_update,
        )
    except BorrowEvidenceError:
        raise
    except (TypeError, ValueError, RuntimeError) as exc:
        raise BorrowEvidenceError(
            f"Borrow evidence anchor transition failed authenticated storage: {exc}"
        ) from exc
