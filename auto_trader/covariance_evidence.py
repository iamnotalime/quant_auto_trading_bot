from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence
from zoneinfo import ZoneInfo

import numpy as np
import pandas as pd

from quant_app.data import load_corporate_action_csv, load_execution_price_csv
from quant_app.governance import (
    SEALED_CORPORATE_ACTION_AS_OF_CUTOFF,
    SEALED_CORPORATE_ACTION_CASH_DEFINITION,
    SEALED_CORPORATE_ACTION_SPLIT_DEFINITION,
    SEALED_DECISION_INFORMATION_CUTOFF,
    SEALED_EXECUTION_PRICE_DEFINITION,
    SEALED_EXECUTION_PRICE_ROW_LABEL,
    SEALED_INTERVAL_TIMEZONE,
    SEALED_RETURN_ROW_LABEL,
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


COVARIANCE_EVIDENCE_SCHEMA_VERSION = 2
COVARIANCE_EVIDENCE_PURPOSE = "governed_covariance_evidence_v2"
COVARIANCE_RETURN_SEMANTICS = (
    "signed_09:30-09:35_America/New_York_vwap_to_vwap"
)
MINIMUM_COMPLETE_OBSERVATIONS = 253
MAX_EVIDENCE_LIFETIME = timedelta(days=7)
_MAX_ENVELOPE_BYTES = 1_000_000
_MAX_DATA_FILE_BYTES = 512_000_000
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{7,127}$")
_SYMBOL_RE = re.compile(r"^[A-Z][A-Z0-9./-]{0,14}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

_PAYLOAD_FIELDS = {
    "schema_version",
    "purpose",
    "snapshot_id",
    "provider_id",
    "venue_id",
    "issued_at",
    "expires_at",
    "timezone",
    "decision_cutoff",
    "execution_window_start",
    "execution_window_end",
    "execution_price_definition",
    "execution_price_row_label",
    "return_semantics",
    "return_row_label",
    "corporate_action_split_definition",
    "corporate_action_cash_definition",
    "corporate_action_as_of_cutoff",
    "first_session",
    "latest_session",
    "next_session",
    "observation_count",
    "symbols",
    "execution_prices_sha256",
    "corporate_actions_sha256",
}
_FIXED_SEMANTICS = {
    "timezone": SEALED_INTERVAL_TIMEZONE,
    "decision_cutoff": SEALED_DECISION_INFORMATION_CUTOFF,
    "execution_window_start": "09:30:00",
    "execution_window_end": "09:35:00",
    "execution_price_definition": SEALED_EXECUTION_PRICE_DEFINITION,
    "execution_price_row_label": SEALED_EXECUTION_PRICE_ROW_LABEL,
    "return_semantics": COVARIANCE_RETURN_SEMANTICS,
    "return_row_label": SEALED_RETURN_ROW_LABEL,
    "corporate_action_split_definition": SEALED_CORPORATE_ACTION_SPLIT_DEFINITION,
    "corporate_action_cash_definition": SEALED_CORPORATE_ACTION_CASH_DEFINITION,
    "corporate_action_as_of_cutoff": SEALED_CORPORATE_ACTION_AS_OF_CUTOFF,
}


class CovarianceEvidenceError(RuntimeError):
    """Signed covariance evidence is missing, unauthenticated, stale, or malformed."""


@dataclass(frozen=True)
class VerifiedCovarianceEvidence:
    execution_prices: pd.DataFrame
    split_ratios: pd.DataFrame
    cash_distributions: pd.DataFrame
    intended_execution_date: date
    provenance: Mapping[str, str]


def _read_bounded(path: str | Path | None, *, label: str, maximum: int) -> bytes:
    if path is None:
        raise CovarianceEvidenceError(f"{label} path is not configured.")
    candidate = Path(path).expanduser()
    try:
        size = candidate.stat().st_size
        if size <= 0:
            raise CovarianceEvidenceError(f"{label} is empty.")
        if size > maximum:
            raise CovarianceEvidenceError(
                f"{label} exceeds the {maximum}-byte safety limit."
            )
        raw = candidate.read_bytes()
        if len(raw) <= 0:
            raise CovarianceEvidenceError(f"{label} is empty after reading.")
        if len(raw) > maximum:
            raise CovarianceEvidenceError(
                f"{label} exceeded the {maximum}-byte safety limit while being read."
            )
        if len(raw) != size:
            raise CovarianceEvidenceError(
                f"{label} changed size while it was being read; retry from a stable snapshot."
            )
        return raw
    except CovarianceEvidenceError:
        raise
    except OSError as exc:
        raise CovarianceEvidenceError(f"{label} is unreadable: {exc}") from exc


def _parse_utc(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise CovarianceEvidenceError(
            f"Covariance evidence {field} must be an ISO-8601 timestamp with an offset."
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CovarianceEvidenceError(
            f"Covariance evidence {field} must be a valid ISO-8601 timestamp."
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CovarianceEvidenceError(
            f"Covariance evidence {field} must include an explicit UTC offset."
        )
    return parsed.astimezone(timezone.utc)


def _parse_session(value: Any, *, field: str) -> date:
    if not isinstance(value, str) or not _DATE_RE.fullmatch(value):
        raise CovarianceEvidenceError(
            f"Covariance evidence {field} must be an exact YYYY-MM-DD session date."
        )
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise CovarianceEvidenceError(
            f"Covariance evidence {field} is not a valid calendar date."
        ) from exc


def _validate_symbols(value: Any, expected_symbols: Sequence[str]) -> tuple[str, ...]:
    expected = tuple(str(symbol) for symbol in expected_symbols)
    if (
        not expected
        or len(set(expected)) != len(expected)
        or any(not _SYMBOL_RE.fullmatch(symbol) for symbol in expected)
    ):
        raise CovarianceEvidenceError(
            "Requested covariance symbols must be non-empty, unique broker symbols."
        )
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise CovarianceEvidenceError(
            "Covariance evidence symbols must be an ordered string array."
        )
    supplied = tuple(value)
    if supplied != expected:
        raise CovarianceEvidenceError(
            "Covariance evidence symbols do not exactly match the requested ordered universe."
        )
    return supplied


def _validate_bound_identity(value: Any, expected: str, *, field: str) -> str:
    if not isinstance(expected, str) or not _IDENTIFIER_RE.fullmatch(expected):
        raise CovarianceEvidenceError(
            f"Configured covariance {field} is missing or invalid."
        )
    if not isinstance(value, str) or not hmac.compare_digest(value, expected):
        raise CovarianceEvidenceError(
            f"Covariance evidence {field} does not match the configured deployment identity."
        )
    return value


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
        raise CovarianceEvidenceError(
            "Covariance evidence signature must contain exactly algorithm, key_id, and value."
        )
    if signature_object.get("algorithm") != _SIGNATURE_ALGORITHM:
        raise CovarianceEvidenceError(
            f"Covariance evidence signature algorithm must be {_SIGNATURE_ALGORITHM}."
        )
    key_id = signature_object.get("key_id")
    if not isinstance(key_id, str) or not _IDENTIFIER_RE.fullmatch(key_id):
        raise CovarianceEvidenceError("Covariance evidence signing key_id is invalid.")
    if not registry.valid:
        detail = "; ".join(registry.errors) or "unknown registry validation error"
        raise CovarianceEvidenceError(
            "Covariance evidence trusted-key registry is invalid: " + detail
        )
    if key_id not in registry.keys:
        raise CovarianceEvidenceError(
            "Covariance evidence key_id is not in the deployment-pinned registry."
        )
    key = registry.keys[key_id]
    if key.get("status") != "active":
        raise CovarianceEvidenceError("Covariance evidence signing key is not active.")
    if key.get("algorithm") != _SIGNATURE_ALGORITHM:
        raise CovarianceEvidenceError(
            "Covariance evidence signing key has the wrong algorithm."
        )
    try:
        modulus = int.from_bytes(_decode_base64url(key.get("modulus_base64url")), "big")
        exponent = int(key.get("exponent"))
        signature = _decode_base64(signature_object.get("value"))
    except (TypeError, ValueError, OverflowError) as exc:
        raise CovarianceEvidenceError(
            f"Covariance evidence signing key or signature is invalid: {exc}"
        ) from exc
    if not _verify_rsa_pkcs1_v15_sha256(
        message=canonical_json(payload),
        signature=signature,
        modulus=modulus,
        exponent=exponent,
    ):
        raise CovarianceEvidenceError(
            "Covariance evidence RSA/SHA-256 signature verification failed."
        )
    return key_id, signature


def load_signed_covariance_evidence(
    *,
    envelope_path: str | Path | None,
    execution_prices_path: str | Path | None,
    corporate_actions_path: str | Path | None,
    public_keys_path: str | Path | None,
    public_keys_sha256: str | None,
    expected_provider_id: str,
    expected_venue_id: str,
    expected_symbols: Sequence[str],
    history_bars: int,
    latest_allowed_date: date,
    max_data_age_days: int,
    now: datetime | None = None,
) -> VerifiedCovarianceEvidence:
    """Authenticate and load a point-in-time execution covariance snapshot.

    All three evidence files are read once. Their exact bytes, panel axes, economics,
    time semantics, universe, and freshness are validated before any frame is returned.
    Any ambiguity raises ``CovarianceEvidenceError``; there is no close-price fallback.
    """

    if isinstance(history_bars, bool) or not isinstance(history_bars, int):
        raise CovarianceEvidenceError("Covariance history_bars must be an integer.")
    if not MINIMUM_COMPLETE_OBSERVATIONS <= history_bars <= 20_000:
        raise CovarianceEvidenceError(
            "Covariance history_bars must be between 253 and 20,000."
        )
    if isinstance(max_data_age_days, bool) or not isinstance(max_data_age_days, int):
        raise CovarianceEvidenceError("Covariance max_data_age_days must be an integer.")
    if not 0 <= max_data_age_days <= 30:
        raise CovarianceEvidenceError(
            "Covariance max_data_age_days must be between 0 and 30."
        )
    if not isinstance(latest_allowed_date, date) or isinstance(
        latest_allowed_date, datetime
    ):
        raise CovarianceEvidenceError("latest_allowed_date must be a calendar date.")

    envelope_raw = _read_bounded(
        envelope_path,
        label="Covariance evidence envelope",
        maximum=_MAX_ENVELOPE_BYTES,
    )
    execution_raw = _read_bounded(
        execution_prices_path,
        label="Covariance execution-price CSV",
        maximum=_MAX_DATA_FILE_BYTES,
    )
    actions_raw = _read_bounded(
        corporate_actions_path,
        label="Covariance corporate-action CSV",
        maximum=_MAX_DATA_FILE_BYTES,
    )
    try:
        decoded = strict_json_loads(envelope_raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CovarianceEvidenceError(
            f"Covariance evidence envelope is not strict UTF-8 JSON: {exc}"
        ) from exc
    if not isinstance(decoded, dict) or set(decoded) != {"payload", "signature"}:
        raise CovarianceEvidenceError(
            "Covariance evidence envelope must contain exactly payload and signature."
        )
    payload = decoded.get("payload")
    if not isinstance(payload, dict) or set(payload) != _PAYLOAD_FIELDS:
        raise CovarianceEvidenceError(
            "Covariance evidence payload fields do not exactly match schema version 2."
        )
    if payload.get("schema_version") != COVARIANCE_EVIDENCE_SCHEMA_VERSION:
        raise CovarianceEvidenceError(
            "Covariance evidence schema_version must equal 2."
        )
    if payload.get("purpose") != COVARIANCE_EVIDENCE_PURPOSE:
        raise CovarianceEvidenceError(
            f"Covariance evidence purpose must be {COVARIANCE_EVIDENCE_PURPOSE}."
        )
    snapshot_id = payload.get("snapshot_id")
    if not isinstance(snapshot_id, str) or not _IDENTIFIER_RE.fullmatch(snapshot_id):
        raise CovarianceEvidenceError("Covariance evidence snapshot_id is invalid.")
    provider_id = _validate_bound_identity(
        payload.get("provider_id"), expected_provider_id, field="provider_id"
    )
    venue_id = _validate_bound_identity(
        payload.get("venue_id"), expected_venue_id, field="venue_id"
    )
    for field, expected in _FIXED_SEMANTICS.items():
        if payload.get(field) != expected:
            raise CovarianceEvidenceError(
                f"Covariance evidence {field} must equal {expected!r}."
            )
    symbols = _validate_symbols(payload.get("symbols"), expected_symbols)

    registry = load_trusted_key_registry(public_keys_path, public_keys_sha256)
    key_id, signature = _verify_signature(decoded, payload, registry)

    for field, raw in (
        ("execution_prices_sha256", execution_raw),
        ("corporate_actions_sha256", actions_raw),
    ):
        expected_hash = payload.get(field)
        if not isinstance(expected_hash, str) or not _SHA256_RE.fullmatch(expected_hash):
            raise CovarianceEvidenceError(
                f"Covariance evidence {field} must be a lowercase SHA-256 digest."
            )
        if not hmac.compare_digest(expected_hash, sha256_bytes(raw)):
            raise CovarianceEvidenceError(
                f"Covariance evidence {field} does not match the exact file bytes."
            )

    current_value = now or datetime.now(timezone.utc)
    if current_value.tzinfo is None or current_value.utcoffset() is None:
        raise CovarianceEvidenceError(
            "Covariance evidence verification now must be timezone-aware."
        )
    current = current_value.astimezone(timezone.utc)
    issued = _parse_utc(payload.get("issued_at"), field="issued_at")
    expires = _parse_utc(payload.get("expires_at"), field="expires_at")
    if issued > current + timedelta(minutes=5):
        raise CovarianceEvidenceError("Covariance evidence issued_at is in the future.")
    if expires <= current:
        raise CovarianceEvidenceError("Covariance evidence has expired.")
    if expires <= issued:
        raise CovarianceEvidenceError(
            "Covariance evidence expires_at must be after issued_at."
        )
    if expires - issued > MAX_EVIDENCE_LIFETIME:
        raise CovarianceEvidenceError(
            "Covariance evidence lifetime must not exceed seven days."
        )

    first_session = _parse_session(payload.get("first_session"), field="first_session")
    latest_session = _parse_session(
        payload.get("latest_session"), field="latest_session"
    )
    next_session = _parse_session(payload.get("next_session"), field="next_session")
    if first_session > latest_session:
        raise CovarianceEvidenceError(
            "Covariance evidence first_session must not follow latest_session."
        )
    if latest_session > latest_allowed_date:
        raise CovarianceEvidenceError(
            "Covariance evidence latest_session is later than the planning cutoff."
        )
    if (latest_allowed_date - latest_session).days > max_data_age_days:
        raise CovarianceEvidenceError(
            "Covariance evidence latest_session is stale for this deployment."
        )
    if next_session <= latest_session:
        raise CovarianceEvidenceError(
            "Covariance evidence next_session must follow latest_session."
        )
    if (next_session - latest_session).days > 7 or next_session.weekday() >= 5:
        raise CovarianceEvidenceError(
            "Covariance evidence next_session is not a plausible next exchange session."
        )
    endpoint = datetime.combine(
        latest_session,
        time(9, 35),
        tzinfo=ZoneInfo(SEALED_INTERVAL_TIMEZONE),
    ).astimezone(timezone.utc)
    if issued < endpoint:
        raise CovarianceEvidenceError(
            "Covariance evidence was issued before its latest 09:35 VWAP completed."
        )
    next_endpoint = datetime.combine(
        next_session,
        time(9, 35),
        tzinfo=ZoneInfo(SEALED_INTERVAL_TIMEZONE),
    ).astimezone(timezone.utc)
    if expires <= next_endpoint:
        raise CovarianceEvidenceError(
            "Covariance evidence must remain valid beyond its signed next-session "
            "09:35 VWAP benchmark endpoint."
        )

    count = payload.get("observation_count")
    if isinstance(count, bool) or not isinstance(count, int):
        raise CovarianceEvidenceError(
            "Covariance evidence observation_count must be an integer."
        )
    required_count = max(MINIMUM_COMPLETE_OBSERVATIONS, history_bars)
    if count < required_count:
        raise CovarianceEvidenceError(
            f"Covariance evidence requires at least {required_count} complete observations."
        )

    try:
        execution_prices, execution_report = load_execution_price_csv(execution_raw)
    except (TypeError, ValueError) as exc:
        raise CovarianceEvidenceError(
            f"Covariance execution-price CSV is invalid: {exc}"
        ) from exc
    if execution_report.duplicate_dates_removed:
        raise CovarianceEvidenceError(
            "Covariance execution-price CSV must not contain duplicate sessions."
        )
    if tuple(map(str, execution_prices.columns)) != symbols:
        raise CovarianceEvidenceError(
            "Covariance execution-price columns do not exactly match signed symbols."
        )
    values = execution_prices.to_numpy(dtype=float)
    if (
        execution_prices.shape != (count, len(symbols))
        or not np.isfinite(values).all()
        or np.any(values <= 0.0)
    ):
        raise CovarianceEvidenceError(
            "Covariance execution prices must be a complete finite positive signed panel."
        )
    actual_first = pd.Timestamp(execution_prices.index[0]).date()
    actual_latest = pd.Timestamp(execution_prices.index[-1]).date()
    if actual_first != first_session or actual_latest != latest_session:
        raise CovarianceEvidenceError(
            "Covariance execution-price axes do not match signed session bindings."
        )

    try:
        actions = load_corporate_action_csv(
            actions_raw,
            expected_index=execution_prices.index,
            expected_columns=execution_prices.columns,
        )
    except (TypeError, ValueError) as exc:
        raise CovarianceEvidenceError(
            f"Covariance corporate-action CSV is invalid: {exc}"
        ) from exc
    split_values = actions.split_ratio.to_numpy(dtype=float)
    cash_values = actions.cash_distribution.to_numpy(dtype=float)
    if (
        actions.split_ratio.shape != execution_prices.shape
        or actions.cash_distribution.shape != execution_prices.shape
        or not np.isfinite(split_values).all()
        or not np.isfinite(cash_values).all()
        or np.any(split_values <= 0.0)
        or np.any(cash_values < 0.0)
    ):
        raise CovarianceEvidenceError(
            "Covariance corporate actions must be complete finite split/cash panels."
        )

    tail = execution_prices.tail(history_bars).copy()
    tail_splits = actions.split_ratio.reindex_like(tail).astype(float)
    tail_cash = actions.cash_distribution.reindex_like(tail).astype(float)
    if len(tail) != history_bars:
        raise CovarianceEvidenceError(
            "Covariance evidence cannot satisfy the requested history length."
        )
    provenance = {
        "snapshot_id": snapshot_id,
        "provider_id": provider_id,
        "venue_id": venue_id,
        "envelope_sha256": sha256_bytes(envelope_raw),
        "payload_sha256": sha256_bytes(canonical_json(payload)),
        "execution_prices_sha256": sha256_bytes(execution_raw),
        "corporate_actions_sha256": sha256_bytes(actions_raw),
        "trusted_key_registry_sha256": registry.registry_hash,
        "signing_key_id": key_id,
        "signature_sha256": hashlib.sha256(signature).hexdigest(),
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "first_session": first_session.isoformat(),
        "latest_session": latest_session.isoformat(),
        "next_session": next_session.isoformat(),
        "return_semantics": COVARIANCE_RETURN_SEMANTICS,
        "corporate_action_as_of_panel_sha256": sha256_bytes(
            actions.as_of_timestamp.to_csv(
                index=True,
                date_format="%Y-%m-%d",
                lineterminator="\n",
            ).encode("utf-8")
        ),
    }
    if any(
        not isinstance(value, str) or not value
        for value in provenance.values()
    ):
        raise CovarianceEvidenceError(
            "Covariance evidence provenance could not be constructed completely."
        )
    return VerifiedCovarianceEvidence(
        execution_prices=tail,
        split_ratios=tail_splits,
        cash_distributions=tail_cash,
        intended_execution_date=next_session,
        provenance=provenance,
    )


@dataclass(frozen=True)
class SignedCovarianceEvidenceProvider:
    envelope_path: Path | None
    execution_prices_path: Path | None
    corporate_actions_path: Path | None
    public_keys_path: Path | None
    public_keys_sha256: str
    provider_id: str
    venue_id: str
    max_data_age_days: int

    def load(
        self,
        symbols: Sequence[str],
        history_bars: int,
        latest_allowed_date: date,
        *,
        now: datetime | None = None,
    ) -> VerifiedCovarianceEvidence:
        return load_signed_covariance_evidence(
            envelope_path=self.envelope_path,
            execution_prices_path=self.execution_prices_path,
            corporate_actions_path=self.corporate_actions_path,
            public_keys_path=self.public_keys_path,
            public_keys_sha256=self.public_keys_sha256,
            expected_provider_id=self.provider_id,
            expected_venue_id=self.venue_id,
            expected_symbols=symbols,
            history_bars=history_bars,
            latest_allowed_date=latest_allowed_date,
            max_data_age_days=self.max_data_age_days,
            now=now,
        )
