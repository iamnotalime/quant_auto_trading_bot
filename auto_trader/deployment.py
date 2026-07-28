from __future__ import annotations

import hmac
import json
import math
import re
from dataclasses import asdict, dataclass, fields, is_dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, TYPE_CHECKING

from quant_app.config import (
    AppConfig,
    CostConfig,
    PortfolioConfig,
    RegimeConfig,
    RiskConfig,
    SignalConfig,
)
from quant_app.governance import (
    TrustedKeyRegistry,
    _SIGNATURE_ALGORITHM,
    _decode_base64,
    _decode_base64url,
    _verify_rsa_pkcs1_v15_sha256,
    canonical_json,
    load_trusted_key_registry,
    research_runtime_identity,
    sha256_bytes,
    strict_json_loads,
)

if TYPE_CHECKING:  # pragma: no cover - imports only support static analysis
    from auto_trader.config import BotConfig


PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SHA256_FIELDS = {
    "strategy_config_sha256",
    "bot_config_sha256",
    "research_software_sha256",
    "deployment_software_sha256",
    "deployment_runtime_sha256",
    "deployment_descriptors_sha256",
    "dependency_lock_sha256",
}
_CERTIFICATION_HASH_FIELDS = {
    "sealed_manifest_sha256",
    "result_bundle_sha256",
    "research_specification_sha256",
}
_APP_CONFIG_CLASSES = {
    "signals": SignalConfig,
    "portfolio": PortfolioConfig,
    "regime": RegimeConfig,
    "risk": RiskConfig,
    "costs": CostConfig,
}
_BOT_CONFIG_EXCLUDED_FIELDS = {
    # Secrets and human acknowledgements never enter a governance artifact.
    "alpaca_api_key",
    "alpaca_secret_key",
    "live_ack",
    "plan_authentication_key",
    "emergency_authentication_key",
    # Trust locators authenticate the approval but are not execution policy.
    "deployment_approval_path",
    "deployment_public_keys_path",
    "deployment_public_keys_sha256",
}
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{7,127}$")
_CONTAINER_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_DEPLOYMENT_APPROVAL_LIFETIME = timedelta(days=7)


@dataclass(frozen=True)
class DeploymentApprovalVerification:
    verified: bool
    approval_hash: str
    registry_hash: str
    key_id: str | None
    approval_id: str | None
    account_id: str | None
    expires_at: datetime | None
    payload: Mapping[str, Any] | None
    errors: tuple[str, ...]


def _normalize_config_value(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return _normalize_config_value(asdict(value))
    if isinstance(value, Path):
        return str(value.expanduser().resolve(strict=False))
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("configuration datetime must be timezone-aware")
        return value.astimezone(timezone.utc).isoformat()
    if hasattr(value, "isoformat") and callable(value.isoformat):
        return value.isoformat()
    if isinstance(value, tuple):
        return [_normalize_config_value(item) for item in value]
    if isinstance(value, list):
        return [_normalize_config_value(item) for item in value]
    if isinstance(value, Mapping):
        return {
            str(key): _normalize_config_value(item)
            for key, item in value.items()
        }
    if isinstance(value, bool) or value is None or isinstance(value, (str, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("configuration contains a non-finite number")
        return value
    raise TypeError(f"unsupported configuration value {type(value).__name__}")


def strategy_config_hash(config: AppConfig) -> str:
    """Fingerprint the complete strategy dataclass with canonical JSON."""

    return sha256_bytes(canonical_json(_normalize_config_value(config.to_dict())))


def bot_config_binding(config: "BotConfig") -> dict[str, Any]:
    """Return every non-secret daemon setting that can affect Alpaca behavior.

    Runtime paths are intentionally included: a signed deployment is approved for the
    exact state, kill-switch, log, and lock locations it was reviewed with. Only API
    secrets, the human live acknowledgement, and the approval's own trust locators are
    excluded.
    """

    result: dict[str, Any] = {}
    for field in fields(config):
        if field.name in _BOT_CONFIG_EXCLUDED_FIELDS:
            continue
        result[field.name] = _normalize_config_value(getattr(config, field.name))
    # Bind key rotation without ever serializing the raw authentication secret into
    # a signed approval or diagnostic configuration payload.
    result["plan_authentication_key_sha256"] = config.plan_authentication_key_sha256
    result["emergency_authentication_key_sha256"] = (
        config.emergency_authentication_key_sha256
    )
    result["effective_emergency_journal_path"] = str(
        config.effective_emergency_journal_path
    )
    return result


def bot_config_hash(config: "BotConfig") -> str:
    return sha256_bytes(canonical_json(bot_config_binding(config)))


def target_plan_deployment_binding(
    config: "BotConfig",
    approval: DeploymentApprovalVerification | None = None,
    *,
    authorized_account_id: str = "",
) -> dict[str, Any]:
    """Build the exact deployment identity committed into every persisted plan."""

    return {
        "schema_version": 1,
        "strategy_config_sha256": strategy_config_hash(config.strategy),
        "bot_config_sha256": bot_config_hash(config),
        "approved_symbols": list(config.symbols),
        "approval_hash": approval.approval_hash if approval is not None else "",
        "approval_id": approval.approval_id if approval is not None else "",
        "authorized_account_id": str(authorized_account_id or ""),
    }


def _source_tree_hash(paths: list[Path], *, root: Path) -> str:
    inventory: dict[str, str] = {}
    for path in sorted(paths, key=lambda item: item.as_posix()):
        if not path.is_file():
            raise RuntimeError(f"deployment source file is missing: {path}")
        inventory[path.relative_to(root).as_posix()] = sha256_bytes(path.read_bytes())
    return sha256_bytes(canonical_json(inventory))


def research_software_hash(root: Path = PROJECT_ROOT) -> str:
    """Reproduce the research dashboard's exact source/dependency fingerprint."""

    files = [root / "app.py", root / "requirements.lock"]
    files.extend((root / "quant_app").glob("*.py"))
    return _source_tree_hash(files, root=root)


def deployment_software_hash(root: Path = PROJECT_ROOT) -> str:
    """Fingerprint every Python source file used by the broker daemon."""

    files = [root / "bot.py"]
    files.extend((root / "auto_trader").rglob("*.py"))
    files.extend((root / "quant_app").glob("*.py"))
    return _source_tree_hash(files, root=root)


def dependency_lock_hash(root: Path = PROJECT_ROOT) -> str:
    path = root / "requirements.lock"
    if not path.is_file():
        raise RuntimeError(f"dependency lock is missing: {path}")
    return sha256_bytes(path.read_bytes())


def deployment_runtime_hash() -> str:
    """Bind the interpreter, numerical stack, OS, architecture, and BLAS/LAPACK."""

    return sha256_bytes(canonical_json(research_runtime_identity()))


def deployment_descriptors_hash(root: Path = PROJECT_ROOT) -> str:
    """Bind the reviewed container, Compose, and systemd deployment definitions."""

    return _source_tree_hash(
        [
            root / "Dockerfile.bot",
            root / "docker-compose.yml",
            root / "deploy" / "quant-auto-trader.service",
        ],
        root=root,
    )


def container_base_image_digest(root: Path = PROJECT_ROOT) -> str:
    dockerfile = root / "Dockerfile.bot"
    try:
        text = dockerfile.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"cannot read pinned bot Dockerfile: {exc}") from exc
    matches = re.findall(r"(?im)^FROM\s+[^\s@]+@(sha256:[0-9a-f]{64})(?:\s|$)", text)
    if len(matches) != 1 or not _CONTAINER_DIGEST_RE.fullmatch(matches[0]):
        raise RuntimeError("Dockerfile.bot must contain exactly one pinned SHA-256 base image")
    return matches[0]


def _typed_dataclass_value(value: Any, default: Any, path: str) -> Any:
    if isinstance(default, bool):
        if not isinstance(value, bool):
            raise ValueError(f"{path} must be a JSON boolean")
        return value
    if isinstance(default, int):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{path} must be a JSON integer")
        return value
    if isinstance(default, float):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{path} must be a JSON number")
        number = float(value)
        if not math.isfinite(number):
            raise ValueError(f"{path} must be finite")
        return number
    raise TypeError(f"unsupported AppConfig field type at {path}")


def app_config_from_mapping(value: Any) -> AppConfig:
    """Parse an exact, fully enumerated AppConfig object with no implicit defaults."""

    if not isinstance(value, dict) or set(value) != set(_APP_CONFIG_CLASSES):
        raise ValueError(
            "strategy_config must contain exactly signals, portfolio, regime, risk, and costs"
        )
    groups: dict[str, Any] = {}
    for group_name, group_class in _APP_CONFIG_CLASSES.items():
        raw_group = value[group_name]
        expected_fields = {field.name for field in fields(group_class)}
        if not isinstance(raw_group, dict) or set(raw_group) != expected_fields:
            raise ValueError(
                f"strategy_config.{group_name} must contain every exact AppConfig field"
            )
        default_group = group_class()
        parsed = {
            field.name: _typed_dataclass_value(
                raw_group[field.name],
                getattr(default_group, field.name),
                f"strategy_config.{group_name}.{field.name}",
            )
            for field in fields(group_class)
        }
        groups[group_name] = group_class(**parsed)
    config = AppConfig(**groups)
    config.validate()
    return config


def load_approved_strategy(path: str | Path) -> AppConfig:
    """Load the exact strategy from an approval; signature checks happen in factory."""

    try:
        raw = Path(path).expanduser().read_bytes()
        envelope = strict_json_loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"DEPLOYMENT_APPROVAL_PATH is unreadable or invalid: {exc}") from exc
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
        raise ValueError("deployment approval must contain exactly payload and signature")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("deployment approval payload must be an object")
    return app_config_from_mapping(payload.get("strategy_config"))


def _parse_utc(value: Any, field: str, errors: list[str]) -> datetime | None:
    if not isinstance(value, str):
        errors.append(f"deployment approval {field} must be an ISO-8601 UTC timestamp")
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"deployment approval {field} must be an ISO-8601 UTC timestamp")
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        errors.append(f"deployment approval {field} must include a UTC offset")
        return None
    return parsed.astimezone(timezone.utc)


def _valid_identifier(value: Any) -> bool:
    return isinstance(value, str) and bool(_IDENTIFIER_RE.fullmatch(value))


def _verify_signature(
    envelope: Mapping[str, Any],
    payload: Mapping[str, Any] | None,
    registry: TrustedKeyRegistry,
    errors: list[str],
) -> str | None:
    signature_object = envelope.get("signature")
    if not isinstance(signature_object, dict):
        errors.append("deployment approval signature must be an object")
        return None
    if set(signature_object) != {"algorithm", "key_id", "value"}:
        errors.append(
            "deployment approval signature must contain exactly algorithm, key_id, and value"
        )
    if signature_object.get("algorithm") != _SIGNATURE_ALGORITHM:
        errors.append(
            f"deployment approval signature algorithm must be {_SIGNATURE_ALGORITHM}"
        )
    key_id = signature_object.get("key_id")
    if not isinstance(key_id, str) or key_id not in registry.keys:
        errors.append("deployment approval key_id is not in the pinned trusted registry")
        return key_id if isinstance(key_id, str) else None
    if not registry.valid:
        return key_id
    key = registry.keys[key_id]
    if key.get("status") != "active":
        errors.append("deployment approval signing key is not active")
    if key.get("algorithm") != _SIGNATURE_ALGORITHM:
        errors.append("deployment approval signing key has the wrong algorithm")
    try:
        modulus = int.from_bytes(_decode_base64url(key.get("modulus_base64url")), "big")
        exponent = int(key.get("exponent"))
        signature = _decode_base64(signature_object.get("value"))
        if payload is None or not _verify_rsa_pkcs1_v15_sha256(
            message=canonical_json(payload),
            signature=signature,
            modulus=modulus,
            exponent=exponent,
        ):
            errors.append("deployment approval signature verification failed")
    except (TypeError, ValueError, OverflowError) as exc:
        errors.append(f"deployment approval signing key or signature is invalid: {exc}")
    return key_id


def verify_deployment_approval(
    config: "BotConfig",
    *,
    actual_account_id: str | None = None,
    now: datetime | None = None,
    root: Path = PROJECT_ROOT,
) -> DeploymentApprovalVerification:
    """Authenticate and bind the authorization required for Alpaca order execution."""

    errors: list[str] = []
    approval_path = getattr(config, "deployment_approval_path", None)
    registry = load_trusted_key_registry(
        getattr(config, "deployment_public_keys_path", None),
        getattr(config, "deployment_public_keys_sha256", None),
    )
    errors.extend(registry.errors)
    raw = b""
    envelope: Mapping[str, Any] | None = None
    payload: Mapping[str, Any] | None = None
    if approval_path is None:
        errors.append("DEPLOYMENT_APPROVAL_PATH is required for Alpaca execution")
    else:
        try:
            raw = Path(approval_path).expanduser().read_bytes()
            decoded = strict_json_loads(raw)
            if not isinstance(decoded, dict):
                raise ValueError("top level is not an object")
            envelope = decoded
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"deployment approval is unreadable or invalid UTF-8 JSON: {exc}")

    key_id: str | None = None
    if envelope is not None:
        if set(envelope) != {"payload", "signature"}:
            errors.append("deployment approval must contain exactly payload and signature")
        candidate = envelope.get("payload")
        if isinstance(candidate, dict):
            payload = candidate
        else:
            errors.append("deployment approval payload must be an object")
        key_id = _verify_signature(envelope, payload, registry, errors)

    approval_id: str | None = None
    account_id: str | None = None
    expires: datetime | None = None
    if payload is not None:
        required = {
            "schema_version",
            "purpose",
            "approval_id",
            "issued_at",
            "expires_at",
            "broker",
            "strategy_config",
            "strategy_config_sha256",
            "bot_config_sha256",
            "research_software_sha256",
            "deployment_software_sha256",
            "deployment_runtime_sha256",
            "deployment_descriptors_sha256",
            "container_base_image_digest",
            "dependency_lock_sha256",
            "certification",
        }
        if set(payload) != required:
            errors.append("deployment approval payload fields do not exactly match schema version 2")
        if payload.get("schema_version") != 2:
            errors.append("deployment approval schema_version must equal 2")
        if payload.get("purpose") != "approved_broker_deployment_v2":
            errors.append("deployment approval purpose must be approved_broker_deployment_v2")
        approval_value = payload.get("approval_id")
        if _valid_identifier(approval_value):
            approval_id = approval_value
        else:
            errors.append("deployment approval approval_id is invalid")

        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        issued = _parse_utc(payload.get("issued_at"), "issued_at", errors)
        expires = _parse_utc(payload.get("expires_at"), "expires_at", errors)
        if issued is not None and issued > current + timedelta(minutes=5):
            errors.append("deployment approval issued_at is in the future")
        if expires is not None and expires <= current:
            errors.append("deployment approval has expired")
        if issued is not None and expires is not None and expires <= issued:
            errors.append("deployment approval expires_at must be after issued_at")
        if (
            issued is not None
            and expires is not None
            and expires - issued > MAX_DEPLOYMENT_APPROVAL_LIFETIME
        ):
            errors.append("deployment approval lifetime must not exceed 7 days")

        broker = payload.get("broker")
        if not isinstance(broker, dict) or set(broker) != {
            "adapter",
            "environment",
            "account_id",
        }:
            errors.append(
                "deployment approval broker must contain exactly adapter, environment, and account_id"
            )
        else:
            if broker.get("adapter") != "alpaca":
                errors.append("deployment approval is not for the Alpaca adapter")
            expected_environment = "paper" if config.alpaca_paper else "live"
            if broker.get("environment") != expected_environment:
                errors.append("deployment approval broker environment does not match ALPACA_PAPER")
            account_value = broker.get("account_id")
            if _valid_identifier(account_value):
                account_id = account_value
            else:
                errors.append("deployment approval broker account_id is invalid")
            configured_account_id = str(
                getattr(config, "alpaca_account_id", "") or ""
            ).strip()
            if (
                not _valid_identifier(configured_account_id)
                or account_id is None
                or not hmac.compare_digest(configured_account_id, account_id)
            ):
                errors.append(
                    "deployment approval broker account_id does not match ALPACA_ACCOUNT_ID"
                )
            if actual_account_id is not None:
                normalized_actual = str(actual_account_id)
                if (
                    not _valid_identifier(normalized_actual)
                    or account_id is None
                    or not hmac.compare_digest(normalized_actual, account_id)
                ):
                    errors.append("connected Alpaca account does not match deployment approval")

        try:
            approved_strategy = app_config_from_mapping(payload.get("strategy_config"))
        except (TypeError, ValueError) as exc:
            errors.append(f"deployment approval strategy_config is invalid: {exc}")
            approved_strategy = None
        if approved_strategy is not None:
            approved_strategy_hash = strategy_config_hash(approved_strategy)
            if payload.get("strategy_config_sha256") != approved_strategy_hash:
                errors.append("deployment approval strategy_config_sha256 is internally inconsistent")
            if not hmac.compare_digest(approved_strategy_hash, strategy_config_hash(config.strategy)):
                errors.append("deployed AppConfig does not match deployment approval")

        exact_hashes = {
            "bot_config_sha256": bot_config_hash(config),
            "research_software_sha256": research_software_hash(root),
            "deployment_software_sha256": deployment_software_hash(root),
            "deployment_runtime_sha256": deployment_runtime_hash(),
            "deployment_descriptors_sha256": deployment_descriptors_hash(root),
            "dependency_lock_sha256": dependency_lock_hash(root),
        }
        for field, expected in exact_hashes.items():
            value = payload.get(field)
            if not isinstance(value, str) or len(value) != 64:
                errors.append(f"deployment approval {field} is not a SHA-256 digest")
            elif not hmac.compare_digest(value, expected):
                errors.append(f"deployment approval {field} does not match this deployment")
        strategy_digest = payload.get("strategy_config_sha256")
        if not isinstance(strategy_digest, str) or len(strategy_digest) != 64:
            errors.append("deployment approval strategy_config_sha256 is not a SHA-256 digest")
        image_digest = payload.get("container_base_image_digest")
        expected_image_digest = container_base_image_digest(root)
        if (
            not isinstance(image_digest, str)
            or not _CONTAINER_DIGEST_RE.fullmatch(image_digest)
            or not hmac.compare_digest(image_digest, expected_image_digest)
        ):
            errors.append(
                "deployment approval container_base_image_digest does not match Dockerfile.bot"
            )

        certification = payload.get("certification")
        if not isinstance(certification, dict) or set(certification) != {
            "status",
            "certified_at",
            "sealed_manifest_sha256",
            "result_bundle_sha256",
            "research_specification_sha256",
        }:
            errors.append(
                "deployment approval certification evidence has unexpected or missing fields"
            )
        else:
            if certification.get("status") != "passed":
                errors.append("deployment approval certification status must be passed")
            certified = _parse_utc(certification.get("certified_at"), "certification.certified_at", errors)
            if certified is not None and certified > current + timedelta(minutes=5):
                errors.append("deployment approval certification time is in the future")
            if certified is not None and issued is not None and certified > issued:
                errors.append("certification must precede deployment approval issuance")
            for field in _CERTIFICATION_HASH_FIELDS:
                value = certification.get(field)
                if not isinstance(value, str) or len(value) != 64 or any(
                    character not in "0123456789abcdef" for character in value
                ):
                    errors.append(f"deployment approval certification {field} is invalid")

        for field in _SHA256_FIELDS:
            value = payload.get(field)
            if not isinstance(value, str) or len(value) != 64 or any(
                character not in "0123456789abcdef" for character in value
            ):
                errors.append(f"deployment approval {field} must be lowercase SHA-256")

    approval_hash = (
        sha256_bytes(canonical_json(envelope)) if envelope is not None else sha256_bytes(raw)
    )
    return DeploymentApprovalVerification(
        verified=bool(registry.valid and payload is not None and not errors),
        approval_hash=approval_hash,
        registry_hash=registry.registry_hash,
        key_id=key_id,
        approval_id=approval_id,
        account_id=account_id,
        expires_at=expires,
        payload=payload,
        errors=tuple(errors),
    )
