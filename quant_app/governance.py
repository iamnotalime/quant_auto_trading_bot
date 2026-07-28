from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import platform
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from typing import Any, Mapping

import numpy as np
import pandas as pd
import scipy

from quant_app.data import validate_daily_session_index


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{7,127}$")
_RSA_SHA256_DIGEST_INFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)
_SIGNATURE_ALGORITHM = "RSASSA-PKCS1-v1_5-SHA256"
_FACTOR_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:/ -]{0,63}$")
SEALED_MANIFEST_SCHEMA_VERSION = 7
SEALED_MANIFEST_PURPOSE = "sealed_final_validation_v7"
SEALED_INTERVAL_TIMEZONE = "America/New_York"
SEALED_RETURN_INTERVAL = "09:35:00_to_next_session_09:35:00"
SEALED_EXECUTION_PRICE_DEFINITION = "point_in_time_09_35_vwap"
SEALED_EXECUTION_PRICE_ROW_LABEL = "same_session_date"
SEALED_DECISION_INFORMATION_CUTOFF = "same_session_09:30:00_before_execution_window"
SEALED_RETURN_ROW_LABEL = "interval_end_session_date"
SEALED_LIQUIDITY_WINDOW = "09:30:00_to_09:35:00"
SEALED_LIQUIDITY_DEFINITION = "traded_dollar_notional_in_execution_window"
SEALED_CORPORATE_ACTION_SPLIT_DEFINITION = "shares_after_per_share_before"
SEALED_CORPORATE_ACTION_CASH_DEFINITION = "cash_per_pre_action_share"
SEALED_CORPORATE_ACTION_AS_OF_CUTOFF = "same_session_at_or_before_09:30:00"
SEALED_BORROW_AS_OF_CUTOFF = "same_session_at_or_before_09:30:00"
SEALED_BORROW_RATE_DEFINITION = "annualized_security_specific_rate"
SEALED_WORM_RECEIPT_PURPOSE = "research_preregistration_worm_anchor_v1"


def research_runtime_identity() -> dict[str, Any]:
    """Return reproducibility-relevant runtime identity without host/user secrets."""
    blas: dict[str, str] = {}
    build_dependencies = getattr(np.__config__, "CONFIG", {}).get(
        "Build Dependencies", {}
    )
    for dependency in ("blas", "lapack"):
        details = build_dependencies.get(dependency, {})
        if not isinstance(details, dict):
            continue
        for field in ("name", "version", "openblas configuration"):
            value = details.get(field)
            if isinstance(value, str) and value.strip():
                blas[f"{dependency}_{field.replace(' ', '_')}"] = value.strip()
    if not blas:
        get_info = getattr(np.__config__, "get_info", None)
        legacy = get_info("blas_opt_info") if callable(get_info) else {}
        libraries = legacy.get("libraries", []) if isinstance(legacy, dict) else []
        if libraries:
            blas["libraries"] = ",".join(sorted(map(str, libraries)))

    return {
        "python_implementation": platform.python_implementation(),
        "python_version": ".".join(map(str, sys.version_info[:3])),
        "operating_system": platform.system(),
        "operating_system_release": platform.release(),
        "machine_architecture": platform.machine(),
        "numpy_version": np.__version__,
        "pandas_version": pd.__version__,
        "scipy_version": scipy.__version__,
        "blas_lapack": blas,
    }


def canonical_json(value: Any) -> bytes:
    """Serialize a signed governance value without representation ambiguity."""
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON numeric constant {value!r} is forbidden")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key {key!r} is forbidden")
        result[key] = value
    return result


def strict_json_loads(value: bytes) -> Any:
    """Parse trust material with no duplicate keys or non-standard constants."""
    text = value.decode("utf-8", errors="strict")
    return json.loads(
        text,
        object_pairs_hook=_unique_json_object,
        parse_constant=_reject_json_constant,
    )


@dataclass(frozen=True)
class TrustedKeyRegistry:
    valid: bool
    registry_hash: str
    keys: Mapping[str, Mapping[str, Any]]
    errors: tuple[str, ...]
    raw_bytes: bytes = b""


@dataclass(frozen=True)
class ManifestVerification:
    verified: bool
    manifest_hash: str
    registry_hash: str
    key_id: str | None
    experiment_id: str | None
    data_family_id: str | None
    strategy_family_id: str | None
    overlap_group_ids: tuple[str, ...]
    market_factor_column: str | None
    research_ledger_id: str | None
    research_ledger_preclaim_sequence: int | None
    research_ledger_preclaim_head_hash: str | None
    research_ledger_prior_effective_trials: int | None
    planned_effective_trials: int | None
    anchor_receipt_hash: str
    payload: Mapping[str, Any] | None
    envelope: Mapping[str, Any] | None
    errors: tuple[str, ...]


def load_factor_return_csv(source: bytes) -> pd.DataFrame:
    """Load named, daily point-in-time factor returns without filling missing values."""
    try:
        raw = pd.read_csv(BytesIO(source))
    except UnicodeDecodeError as exc:
        raise ValueError("Factor-return CSV must be UTF-8 encoded.") from exc
    except Exception as exc:  # pragma: no cover - pandas exposes many parser errors
        raise ValueError(f"Could not parse factor-return CSV: {exc}") from exc
    if raw.empty or raw.shape[1] < 3:
        raise ValueError("Factor-return CSV needs a date column and at least two factors.")
    date_candidates = [
        column
        for column in raw.columns
        if str(column).strip().lower() in {"date", "datetime", "timestamp"}
    ]
    date_column = date_candidates[0] if date_candidates else raw.columns[0]
    parsed_dates = pd.to_datetime(raw[date_column], errors="coerce", utc=False)
    if parsed_dates.isna().any():
        raise ValueError("Factor-return CSV contains invalid or missing dates.")
    try:
        index = pd.DatetimeIndex(parsed_dates).tz_localize(None).normalize()
    except (TypeError, ValueError) as exc:
        raise ValueError("Factor-return CSV contains incompatible timestamps.") from exc
    if index.duplicated().any():
        raise ValueError("Factor-return CSV contains duplicate session dates.")

    frame = raw.drop(columns=[date_column]).copy()
    frame.columns = [str(column).strip() for column in frame.columns]
    if frame.columns.duplicated().any():
        raise ValueError("Factor names must remain unique after surrounding whitespace is removed.")
    invalid_names = [
        column
        for column in frame.columns
        if not _FACTOR_NAME_RE.fullmatch(column) or column.startswith(("=", "+", "-", "@"))
    ]
    if invalid_names:
        raise ValueError(
            "Factor names must start with a letter, be at most 64 safe characters, "
            "and must not be spreadsheet formulas."
        )
    if frame.shape[1] < 2:
        raise ValueError("At least two named factors are required.")
    frame = frame.apply(pd.to_numeric, errors="coerce")
    values = frame.to_numpy(dtype=float)
    if not np.isfinite(values).all():
        raise ValueError("Factor-return CSV contains missing, non-numeric, or non-finite values.")
    if np.abs(values).max(initial=0.0) > 1.0:
        raise ValueError("Factor-return CSV contains an implausible daily return beyond +/-100%.")
    if frame.notna().sum().min() < 60:
        raise ValueError("Every factor needs at least 60 valid daily observations.")
    frame.index = index
    frame = frame.sort_index()
    validate_daily_session_index(frame.index, label="Factor-return CSV")
    frame.index.name = "Date"
    return frame


def load_trusted_key_registry(
    path: str | Path | None,
    expected_sha256: str | None,
) -> TrustedKeyRegistry:
    """Load a deployment-pinned public-key registry, failing closed on any ambiguity.

    The registry hash must be supplied independently (for example by immutable
    deployment configuration). Merely placing another public key beside the app is
    therefore insufficient to make that key trusted.
    """
    errors: list[str] = []
    expected = str(expected_sha256 or "").strip().lower()
    if not path:
        errors.append("RESEARCH_GOVERNANCE_PUBLIC_KEYS_PATH is not configured")
    if not _SHA256_RE.fullmatch(expected):
        errors.append("RESEARCH_GOVERNANCE_PUBLIC_KEYS_SHA256 is not a pinned SHA-256 digest")
    if errors:
        return TrustedKeyRegistry(False, "", {}, tuple(errors), b"")

    try:
        raw = Path(path).expanduser().read_bytes()
    except OSError as exc:
        return TrustedKeyRegistry(
            False,
            "",
            {},
            (f"cannot read trusted key registry: {exc}",),
            b"",
        )

    actual = sha256_bytes(raw)
    if not hmac.compare_digest(actual, expected):
        errors.append("trusted key registry does not match its deployment-pinned digest")
    try:
        document = strict_json_loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        errors.append(f"trusted key registry is not valid UTF-8 JSON: {exc}")
        document = {}

    if not isinstance(document, dict) or set(document) != {"schema_version", "keys"}:
        errors.append("trusted key registry must contain exactly schema_version and keys")
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        errors.append("trusted key registry schema_version must equal 1")
    keys = document.get("keys", {}) if isinstance(document, dict) else {}
    if not isinstance(keys, dict) or not keys:
        errors.append("trusted key registry must contain a non-empty keys object")
        keys = {}

    normalized: dict[str, Mapping[str, Any]] = {}
    for key_id, value in keys.items():
        if not isinstance(key_id, str) or not _IDENTIFIER_RE.fullmatch(key_id):
            errors.append("trusted key registry contains an invalid key_id")
            continue
        if not isinstance(value, dict):
            errors.append(f"trusted key {key_id!r} is not an object")
            continue
        if set(value) != {"algorithm", "status", "modulus_base64url", "exponent"}:
            errors.append(f"trusted key {key_id!r} has unexpected or missing fields")
            continue
        normalized[key_id] = value

    return TrustedKeyRegistry(not errors, actual, normalized, tuple(errors), raw)


def _decode_base64url(value: Any) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("value is not a non-empty base64url string")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("base64url value contains invalid characters")
    if len(value) > 1_400:
        raise ValueError("base64url value is unreasonably large")
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, binascii.Error) as exc:
        raise ValueError("invalid base64url value") from exc


def _decode_base64(value: Any) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("signature is not a non-empty base64 string")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError, binascii.Error) as exc:
        raise ValueError("signature is not valid base64") from exc


def _verify_rsa_pkcs1_v15_sha256(
    *,
    message: bytes,
    signature: bytes,
    modulus: int,
    exponent: int,
) -> bool:
    """Verify an RSA/SHA-256 signature using only public, standard-library math."""
    modulus_size = (modulus.bit_length() + 7) // 8
    if not 2048 <= modulus.bit_length() <= 8192 or exponent != 65537:
        return False
    if len(signature) != modulus_size:
        return False
    signature_integer = int.from_bytes(signature, "big")
    if signature_integer >= modulus:
        return False
    recovered = pow(signature_integer, exponent, modulus).to_bytes(modulus_size, "big")
    digest_info = _RSA_SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(message).digest()
    padding_length = modulus_size - len(digest_info) - 3
    if padding_length < 8:
        return False
    expected = b"\x00\x01" + (b"\xff" * padding_length) + b"\x00" + digest_info
    return hmac.compare_digest(recovered, expected)


def _parse_utc(value: Any, field: str, errors: list[str]) -> datetime | None:
    if not isinstance(value, str):
        errors.append(f"{field} must be an ISO-8601 UTC timestamp")
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"{field} must be an ISO-8601 UTC timestamp")
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        errors.append(f"{field} must include a UTC offset")
        return None
    return parsed.astimezone(timezone.utc)


def _valid_identifier(value: Any, field: str, errors: list[str]) -> str | None:
    if not isinstance(value, str) or not _IDENTIFIER_RE.fullmatch(value):
        errors.append(
            f"{field} must be 8-128 characters using letters, digits, '.', '_', ':', '/', or '-'"
        )
        return None
    return value


def _verify_signed_anchor_receipt(
    raw_receipt: bytes,
    *,
    registry: TrustedKeyRegistry,
    manifest_payload: Mapping[str, Any],
    manifest_key_id: str | None,
    errors: list[str],
) -> Mapping[str, Any] | None:
    """Verify a distinct-key, provider-bound immutable-ledger receipt."""

    if not raw_receipt:
        errors.append("signed external WORM anchor receipt is required")
        return None
    if len(raw_receipt) > 1_000_000:
        errors.append("external WORM anchor receipt exceeds the size limit")
        return None
    try:
        envelope = strict_json_loads(raw_receipt)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        errors.append(f"external WORM anchor receipt is not strict UTF-8 JSON: {exc}")
        return None
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
        errors.append("external WORM anchor receipt must contain exactly payload and signature")
        return None
    payload = envelope.get("payload")
    required = {
        "schema_version",
        "purpose",
        "provider",
        "record_id",
        "committed_at",
        "experiment_id",
        "combined_data_sha256",
        "research_specification_sha256",
        "research_ledger_id",
        "research_ledger_preclaim_sequence",
        "research_ledger_preclaim_head_sha256",
        "research_ledger_prior_effective_trials",
        "planned_effective_trials",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        errors.append("external WORM anchor receipt payload has the wrong schema")
        return None
    if payload.get("schema_version") != 1:
        errors.append("external WORM anchor receipt schema_version must equal 1")
    if payload.get("purpose") != SEALED_WORM_RECEIPT_PURPOSE:
        errors.append(
            f"external WORM anchor receipt purpose must equal {SEALED_WORM_RECEIPT_PURPOSE}"
        )

    anchor = manifest_payload.get("anchor")
    expected = {
        "provider": anchor.get("provider") if isinstance(anchor, dict) else None,
        "record_id": anchor.get("record_id") if isinstance(anchor, dict) else None,
        "committed_at": anchor.get("committed_at") if isinstance(anchor, dict) else None,
        "experiment_id": manifest_payload.get("experiment_id"),
        "combined_data_sha256": manifest_payload.get("combined_data_sha256"),
        "research_specification_sha256": manifest_payload.get(
            "research_specification_sha256"
        ),
        "research_ledger_id": manifest_payload.get("research_ledger_id"),
        "research_ledger_preclaim_sequence": manifest_payload.get(
            "research_ledger_preclaim_sequence"
        ),
        "research_ledger_preclaim_head_sha256": manifest_payload.get(
            "research_ledger_preclaim_head_sha256"
        ),
        "research_ledger_prior_effective_trials": manifest_payload.get(
            "research_ledger_prior_effective_trials"
        ),
        "planned_effective_trials": manifest_payload.get("planned_effective_trials"),
    }
    for field, value in expected.items():
        if payload.get(field) != value:
            errors.append(
                f"external WORM anchor receipt {field} does not match the signed manifest"
            )

    signature_object = envelope.get("signature")
    if not isinstance(signature_object, dict) or set(signature_object) != {
        "algorithm",
        "key_id",
        "value",
    }:
        errors.append(
            "external WORM anchor receipt signature must contain algorithm, key_id, and value"
        )
        return payload
    if signature_object.get("algorithm") != _SIGNATURE_ALGORITHM:
        errors.append(
            f"external WORM anchor receipt algorithm must be {_SIGNATURE_ALGORITHM}"
        )
    receipt_key_id = signature_object.get("key_id")
    if not isinstance(receipt_key_id, str) or receipt_key_id not in registry.keys:
        errors.append("external WORM anchor receipt key_id is not trusted")
        return payload
    if manifest_key_id is not None and hmac.compare_digest(receipt_key_id, manifest_key_id):
        errors.append(
            "external WORM anchor receipt must use a key distinct from the manifest signer"
        )
    key = registry.keys[receipt_key_id]
    if key.get("status") != "active" or key.get("algorithm") != _SIGNATURE_ALGORITHM:
        errors.append("external WORM anchor receipt signing key is not active and compatible")
        return payload
    try:
        modulus = int.from_bytes(_decode_base64url(key.get("modulus_base64url")), "big")
        exponent = int(key.get("exponent"))
        signature = _decode_base64(signature_object.get("value"))
        if not _verify_rsa_pkcs1_v15_sha256(
            message=canonical_json(payload),
            signature=signature,
            modulus=modulus,
            exponent=exponent,
        ):
            errors.append("external WORM anchor receipt signature verification failed")
    except (TypeError, ValueError, OverflowError) as exc:
        errors.append(f"external WORM anchor receipt signature is invalid: {exc}")
    return payload


def verify_sealed_manifest(
    manifest_bytes: bytes | None,
    anchor_receipt_bytes: bytes | None,
    registry: TrustedKeyRegistry,
    *,
    expected_close_data_hash: str,
    expected_execution_data_hash: str,
    expected_factor_data_hash: str,
    expected_execution_window_dollar_volume_hash: str,
    expected_corporate_action_data_hash: str,
    expected_borrow_data_hash: str,
    expected_exchange_calendar_hash: str,
    available_factor_columns: tuple[str, ...],
    expected_combined_data_hash: str,
    expected_oos_start: str,
    expected_specification_hash: str,
    expected_research_software_hash: str,
    expected_research_ledger_id: str,
    expected_research_ledger_preclaim_sequence: int,
    expected_research_ledger_preclaim_head_hash: str,
    expected_research_ledger_prior_effective_trials: int,
    expected_planned_effective_trials: int,
    now: datetime | None = None,
) -> ManifestVerification:
    """Verify a pre-registered sealed-research manifest against the exact run.

    The detached signature establishes that a key in the deployment-pinned governance
    registry approved the manifest. The manifest also commits to an externally retained
    anchor receipt. No verification, no sealed eligibility: errors are returned rather
    than silently downgrading the checks.
    """
    errors: list[str] = list(registry.errors)
    raw_manifest = bytes(manifest_bytes or b"")
    raw_receipt = bytes(anchor_receipt_bytes or b"")
    raw_manifest_hash = sha256_bytes(raw_manifest) if raw_manifest else ""
    receipt_hash = sha256_bytes(raw_receipt) if raw_receipt else ""
    envelope: Mapping[str, Any] | None = None
    payload: Mapping[str, Any] | None = None
    key_id: str | None = None
    experiment_id: str | None = None
    data_family_id: str | None = None
    strategy_family_id: str | None = None
    overlap_group_ids: tuple[str, ...] = ()
    market_factor_column: str | None = None
    research_ledger_id: str | None = None
    research_ledger_preclaim_sequence: int | None = None
    research_ledger_preclaim_head_hash: str | None = None
    research_ledger_prior_effective_trials: int | None = None
    planned_effective_trials: int | None = None

    if not raw_manifest:
        errors.append("signed governance manifest is required")
    else:
        try:
            decoded = strict_json_loads(raw_manifest)
            if not isinstance(decoded, dict):
                raise ValueError("top level is not an object")
            envelope = decoded
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"governance manifest is not valid UTF-8 JSON: {exc}")

    if not raw_receipt:
        errors.append("external anchor receipt is required")
    if envelope is not None:
        if set(envelope) != {"payload", "signature"}:
            errors.append("manifest envelope must contain exactly payload and signature")
        candidate_payload = envelope.get("payload")
        signature_object = envelope.get("signature")
        if isinstance(candidate_payload, dict):
            payload = candidate_payload
        else:
            errors.append("manifest payload must be an object")
        if not isinstance(signature_object, dict):
            errors.append("manifest signature must be an object")
            signature_object = {}
        elif set(signature_object) != {"algorithm", "key_id", "value"}:
            errors.append("manifest signature must contain exactly algorithm, key_id, and value")

        algorithm = signature_object.get("algorithm")
        key_id = signature_object.get("key_id") if isinstance(signature_object.get("key_id"), str) else None
        if algorithm != _SIGNATURE_ALGORITHM:
            errors.append(f"manifest signature algorithm must be {_SIGNATURE_ALGORITHM}")
        if key_id is None or key_id not in registry.keys:
            errors.append("manifest key_id is not present in the trusted key registry")
        elif registry.valid:
            key = registry.keys[key_id]
            if key.get("status") != "active":
                errors.append("manifest signing key is not active")
            if key.get("algorithm") != _SIGNATURE_ALGORITHM:
                errors.append("manifest signing key has the wrong algorithm")
            try:
                modulus_bytes = _decode_base64url(key.get("modulus_base64url"))
                modulus = int.from_bytes(modulus_bytes, "big")
                exponent = int(key.get("exponent"))
                signature = _decode_base64(signature_object.get("value"))
                if payload is not None and not _verify_rsa_pkcs1_v15_sha256(
                    message=canonical_json(payload),
                    signature=signature,
                    modulus=modulus,
                    exponent=exponent,
                ):
                    errors.append("manifest signature verification failed")
            except (TypeError, ValueError, OverflowError) as exc:
                errors.append(f"manifest signing key or signature is invalid: {exc}")

    if payload is not None:
        required_fields = {
            "schema_version",
            "purpose",
            "experiment_id",
            "data_family_id",
            "strategy_family_id",
            "overlap_group_ids",
            "issued_at",
            "expires_at",
            "close_data_sha256",
            "execution_data_sha256",
            "factor_data_sha256",
            "execution_window_dollar_volume_data_sha256",
            "corporate_action_data_sha256",
            "borrow_data_sha256",
            "exchange_calendar_sha256",
            "market_factor_column",
            "combined_data_sha256",
            "oos_start",
            "research_specification_sha256",
            "research_software_sha256",
            "research_ledger_id",
            "research_ledger_preclaim_sequence",
            "research_ledger_preclaim_head_sha256",
            "research_ledger_prior_effective_trials",
            "planned_effective_trials",
            "interval_provenance",
            "anchor",
        }
        if set(payload) != required_fields:
            errors.append(
                f"manifest payload fields do not exactly match schema version "
                f"{SEALED_MANIFEST_SCHEMA_VERSION}"
            )
        if payload.get("schema_version") != SEALED_MANIFEST_SCHEMA_VERSION:
            errors.append(
                f"manifest schema_version must equal {SEALED_MANIFEST_SCHEMA_VERSION}"
            )
        if payload.get("purpose") != SEALED_MANIFEST_PURPOSE:
            errors.append(f"manifest purpose must be {SEALED_MANIFEST_PURPOSE}")

        experiment_id = _valid_identifier(payload.get("experiment_id"), "experiment_id", errors)
        data_family_id = _valid_identifier(payload.get("data_family_id"), "data_family_id", errors)
        strategy_family_id = _valid_identifier(
            payload.get("strategy_family_id"), "strategy_family_id", errors
        )
        groups = payload.get("overlap_group_ids")
        if not isinstance(groups, list) or not groups:
            errors.append("overlap_group_ids must be a non-empty list")
        else:
            validated_groups = [
                _valid_identifier(value, "overlap_group_ids entry", errors) for value in groups
            ]
            overlap_group_ids = tuple(value for value in validated_groups if value is not None)
            if len(set(overlap_group_ids)) != len(overlap_group_ids):
                errors.append("overlap_group_ids must be unique")

        exact_bindings = {
            "close_data_sha256": expected_close_data_hash,
            "execution_data_sha256": expected_execution_data_hash,
            "factor_data_sha256": expected_factor_data_hash,
            "execution_window_dollar_volume_data_sha256": (
                expected_execution_window_dollar_volume_hash
            ),
            "corporate_action_data_sha256": expected_corporate_action_data_hash,
            "borrow_data_sha256": expected_borrow_data_hash,
            "exchange_calendar_sha256": expected_exchange_calendar_hash,
            "combined_data_sha256": expected_combined_data_hash,
            "oos_start": expected_oos_start,
            "research_specification_sha256": expected_specification_hash,
            "research_software_sha256": expected_research_software_hash,
        }
        for field, expected in exact_bindings.items():
            if payload.get(field) != expected:
                errors.append(f"manifest {field} does not match the exact current run")

        research_ledger_id = _valid_identifier(
            payload.get("research_ledger_id"), "research_ledger_id", errors
        )
        sequence_value = payload.get("research_ledger_preclaim_sequence")
        prior_trials_value = payload.get("research_ledger_prior_effective_trials")
        planned_trials_value = payload.get("planned_effective_trials")
        head_value = payload.get("research_ledger_preclaim_head_sha256")
        if (
            isinstance(sequence_value, bool)
            or not isinstance(sequence_value, int)
            or sequence_value < 0
        ):
            errors.append("research_ledger_preclaim_sequence must be a non-negative integer")
        else:
            research_ledger_preclaim_sequence = sequence_value
        if (
            not isinstance(head_value, str)
            or not _SHA256_RE.fullmatch(head_value)
        ):
            errors.append("research_ledger_preclaim_head_sha256 must be a lowercase SHA-256")
        else:
            research_ledger_preclaim_head_hash = head_value
        if (
            isinstance(prior_trials_value, bool)
            or not isinstance(prior_trials_value, int)
            or prior_trials_value < 0
        ):
            errors.append(
                "research_ledger_prior_effective_trials must be a non-negative integer"
            )
        else:
            research_ledger_prior_effective_trials = prior_trials_value
        if (
            isinstance(planned_trials_value, bool)
            or not isinstance(planned_trials_value, int)
            or planned_trials_value < 1
        ):
            errors.append("planned_effective_trials must be a positive integer")
        else:
            planned_effective_trials = planned_trials_value
        ledger_bindings = {
            "research_ledger_id": expected_research_ledger_id,
            "research_ledger_preclaim_sequence": (
                expected_research_ledger_preclaim_sequence
            ),
            "research_ledger_preclaim_head_sha256": (
                expected_research_ledger_preclaim_head_hash
            ),
            "research_ledger_prior_effective_trials": (
                expected_research_ledger_prior_effective_trials
            ),
            "planned_effective_trials": expected_planned_effective_trials,
        }
        for field, expected in ledger_bindings.items():
            if payload.get(field) != expected:
                errors.append(f"manifest {field} does not match the exact current ledger/run")

        market_factor_column = payload.get("market_factor_column")
        if not isinstance(market_factor_column, str) or market_factor_column not in set(
            available_factor_columns
        ):
            errors.append("manifest market_factor_column is absent from factor-return data")
            market_factor_column = None

        interval_provenance = payload.get("interval_provenance")
        required_provenance_fields = {
            "timezone",
            "strategy_return_interval",
            "strategy_return_row_label",
            "factor_return_interval",
            "factor_return_row_label",
            "execution_price_definition",
            "execution_price_row_label",
            "decision_information_cutoff",
            "execution_venue_id",
            "execution_vendor_snapshot_id",
            "factor_vendor_snapshot_id",
            "exchange_calendar_id",
            "exchange_calendar_vendor_snapshot_id",
            "execution_liquidity_window",
            "execution_liquidity_definition",
            "execution_liquidity_row_label",
            "execution_liquidity_vendor_snapshot_id",
            "corporate_action_interval",
            "corporate_action_split_definition",
            "corporate_action_cash_definition",
            "corporate_action_as_of_cutoff",
            "corporate_action_vendor_snapshot_id",
            "borrow_as_of_cutoff",
            "borrow_rate_definition",
            "borrow_vendor_snapshot_id",
        }
        if not isinstance(interval_provenance, dict) or set(
            interval_provenance
        ) != required_provenance_fields:
            errors.append(
                "manifest interval_provenance must contain exactly timezone, strategy/factor "
                "intervals and row labels, execution definition/row label/venue, and "
                "execution/factor snapshots and exchange-calendar identity"
            )
        else:
            exact_provenance = {
                "timezone": SEALED_INTERVAL_TIMEZONE,
                "strategy_return_interval": SEALED_RETURN_INTERVAL,
                "strategy_return_row_label": SEALED_RETURN_ROW_LABEL,
                "factor_return_interval": SEALED_RETURN_INTERVAL,
                "factor_return_row_label": SEALED_RETURN_ROW_LABEL,
                "execution_price_definition": SEALED_EXECUTION_PRICE_DEFINITION,
                "execution_price_row_label": SEALED_EXECUTION_PRICE_ROW_LABEL,
                "decision_information_cutoff": (
                    SEALED_DECISION_INFORMATION_CUTOFF
                ),
                "execution_liquidity_window": SEALED_LIQUIDITY_WINDOW,
                "execution_liquidity_definition": SEALED_LIQUIDITY_DEFINITION,
                "execution_liquidity_row_label": SEALED_EXECUTION_PRICE_ROW_LABEL,
                "corporate_action_interval": SEALED_RETURN_INTERVAL,
                "corporate_action_split_definition": (
                    SEALED_CORPORATE_ACTION_SPLIT_DEFINITION
                ),
                "corporate_action_cash_definition": (
                    SEALED_CORPORATE_ACTION_CASH_DEFINITION
                ),
                "corporate_action_as_of_cutoff": (
                    SEALED_CORPORATE_ACTION_AS_OF_CUTOFF
                ),
                "borrow_as_of_cutoff": SEALED_BORROW_AS_OF_CUTOFF,
                "borrow_rate_definition": SEALED_BORROW_RATE_DEFINITION,
            }
            for field, expected in exact_provenance.items():
                if interval_provenance.get(field) != expected:
                    errors.append(
                        f"manifest interval_provenance.{field} must equal {expected}"
                    )
            for field in (
                "execution_venue_id",
                "execution_vendor_snapshot_id",
                "factor_vendor_snapshot_id",
                "exchange_calendar_id",
                "exchange_calendar_vendor_snapshot_id",
                "execution_liquidity_vendor_snapshot_id",
                "corporate_action_vendor_snapshot_id",
                "borrow_vendor_snapshot_id",
            ):
                _valid_identifier(
                    interval_provenance.get(field),
                    f"interval_provenance.{field}",
                    errors,
                )

        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        issued = _parse_utc(payload.get("issued_at"), "issued_at", errors)
        expires = _parse_utc(payload.get("expires_at"), "expires_at", errors)
        if issued is not None and issued > current + timedelta(minutes=5):
            errors.append("manifest issued_at is in the future")
        if expires is not None and expires <= current:
            errors.append("manifest has expired")
        if issued is not None and expires is not None and expires <= issued:
            errors.append("manifest expires_at must be after issued_at")

        anchor = payload.get("anchor")
        if not isinstance(anchor, dict) or set(anchor) != {
            "provider",
            "record_id",
            "committed_at",
            "receipt_sha256",
        }:
            errors.append("manifest anchor must contain provider, record_id, committed_at, and receipt_sha256")
        else:
            _valid_identifier(anchor.get("provider"), "anchor.provider", errors)
            _valid_identifier(anchor.get("record_id"), "anchor.record_id", errors)
            committed = _parse_utc(anchor.get("committed_at"), "anchor.committed_at", errors)
            if anchor.get("receipt_sha256") != receipt_hash:
                errors.append("external anchor receipt does not match the signed receipt digest")
            if committed is not None and committed > current + timedelta(minutes=5):
                errors.append("anchor.committed_at is in the future")
            if committed is not None and issued is not None and committed > issued:
                errors.append("anchor commitment must not post-date manifest issuance")

        _verify_signed_anchor_receipt(
            raw_receipt,
            registry=registry,
            manifest_payload=payload,
            manifest_key_id=key_id,
            errors=errors,
        )

    canonical_manifest_hash = (
        sha256_bytes(canonical_json(envelope)) if envelope is not None else raw_manifest_hash
    )
    return ManifestVerification(
        verified=bool(registry.valid and not errors),
        manifest_hash=canonical_manifest_hash,
        registry_hash=registry.registry_hash,
        key_id=key_id,
        experiment_id=experiment_id,
        data_family_id=data_family_id,
        strategy_family_id=strategy_family_id,
        overlap_group_ids=overlap_group_ids,
        market_factor_column=market_factor_column,
        research_ledger_id=research_ledger_id,
        research_ledger_preclaim_sequence=research_ledger_preclaim_sequence,
        research_ledger_preclaim_head_hash=research_ledger_preclaim_head_hash,
        research_ledger_prior_effective_trials=(
            research_ledger_prior_effective_trials
        ),
        planned_effective_trials=planned_effective_trials,
        anchor_receipt_hash=receipt_hash,
        payload=payload,
        envelope=envelope,
        errors=tuple(errors),
    )


def certification_context_hash(context: Mapping[str, Any]) -> str:
    """Fingerprint every value that can affect whether a displayed result is valid."""
    return sha256_bytes(canonical_json(context))


def certification_payload_is_current(
    payload: Mapping[str, Any],
    *,
    context_hash: str,
    ledger_state_hash: str,
) -> bool:
    return bool(
        payload.get("certification_context_hash") == context_hash
        and payload.get("ledger_state_hash") == ledger_state_hash
    )
