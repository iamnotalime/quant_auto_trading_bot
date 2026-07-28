from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from datetime import datetime, time, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from auto_trader.brokers.alpaca import AlpacaBroker
from auto_trader.config import BotConfig
from auto_trader.controls import merge_control_marker, parse_control_marker
from auto_trader.deployment import (
    bot_config_binding,
    bot_config_hash,
    container_base_image_digest,
    dependency_lock_hash,
    deployment_descriptors_hash,
    deployment_runtime_hash,
    deployment_software_hash,
    research_software_hash,
    strategy_config_hash,
    verify_deployment_approval,
)
from auto_trader.factory import build_engine
from auto_trader.emergency_journal import EmergencyJournal
from auto_trader.daemon import ProcessLock
from auto_trader.models import (
    AccountSnapshot,
    MarketClock,
    OrderSide,
    PositionSnapshot,
    RiskDecision,
    TargetPlan,
)
from auto_trader.strategy import seal_target_plan
from quant_app.governance import canonical_json, sha256_bytes
from bot import EMERGENCY_ACTION_PENDING_EXIT_CODE, main as bot_main
from auto_trader.store import StateStore


# Test-only RSA material. It is unrelated to any deployment key.
_RSA_N = int(
    "aea270ff85b3be3b111971e6c2dc36f0811ad5f9ecf95992aee45211f9c7236f"
    "a760220ad8eb1647af72bf3ad941e743eb10afa9a5029bb7c836b1334c3a14d8"
    "428c1a173a0b94603e3af8e4fbea1dc3a100063c66682896c7bd6b41735dc437"
    "ab02b749363812d7fd2f1b81fbef867575612ba01acb26937123bbb7105217ba"
    "c78575f872e590e1c99761d6ff95f17669e76a1464a7393dd3dafaea8458b580"
    "879cb6c21dc2c6bc8eeb653c2100d8876def8157e529fe42cb2bdc12d170dce8"
    "06a83dc6e29a2ebbdbf0588c7931fef4f02b20ba865b3a322fa872e80cfd89fd"
    "be9cd23c4a02683c4996b5ac4dd2be2d312c587c1bec2128c82840bc4e11fc2b",
    16,
)
_RSA_D = int(
    "06fd859c6a290467af8adf33a77fd275d4bfd2ea35817dae661b1eeb37f3b008"
    "1b7663a674d70edb4110a2204eeb5915da3b9ec1cc5320673e37c23c156f0b15"
    "3a5a0aa95204d34ef999640bcbc7014e000c7f88bcbdfff1ee7e37398acea963"
    "63bb0619d8cbc1d0022dcd376a1d9a64ea95407e76296f9a88a02f8c12612c30"
    "980cb4b0dd908078f8839dac0d80062d31ea7a290cceaca62be8fd8d30ec0359"
    "9860bfdeb28216bd4ad3bb534a8fc3b0c2c4e682bd02054624eea55d468969e3"
    "ecec1b8e1d7a4b329edd4360a718da39c6400fd8dfeff07f9b014b9360f963eb"
    "13e4da424db4c5e6b62dda6cfc6fb9621b701aa2b4dbf257daa1e9156a3ecf31",
    16,
)
_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
_TEST_PLAN_AUTHENTICATION_KEY = hashlib.sha256(
    b"deployment-approval-test-plan-authentication-key"
).hexdigest()
_TEST_EMERGENCY_AUTHENTICATION_KEY = hashlib.sha256(
    b"deployment-approval-test-emergency-authentication-key"
).hexdigest()


def _sign(payload: dict[str, object]) -> str:
    size = (_RSA_N.bit_length() + 7) // 8
    digest_info = _DIGEST_INFO_PREFIX + hashlib.sha256(canonical_json(payload)).digest()
    encoded = b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3) + b"\x00" + digest_info
    signature = pow(int.from_bytes(encoded, "big"), _RSA_D, _RSA_N).to_bytes(size, "big")
    return base64.b64encode(signature).decode("ascii")


def _registry(tmp_path: Path) -> tuple[Path, str]:
    modulus = _RSA_N.to_bytes((_RSA_N.bit_length() + 7) // 8, "big")
    document = {
        "schema_version": 1,
        "keys": {
            "deployment-key-2026": {
                "algorithm": "RSASSA-PKCS1-v1_5-SHA256",
                "status": "active",
                "modulus_base64url": base64.urlsafe_b64encode(modulus)
                .decode("ascii")
                .rstrip("="),
                "exponent": 65537,
            }
        },
    }
    raw = canonical_json(document)
    path = tmp_path / "deployment-keys.json"
    path.write_bytes(raw)
    return path, sha256_bytes(raw)


def _config(tmp_path: Path, *, account_id: str = "account-approved-0001") -> BotConfig:
    registry_path, registry_hash = _registry(tmp_path)
    borrow_registry_path = tmp_path / "borrow-keys.json"
    borrow_registry_path.write_bytes(registry_path.read_bytes())
    return BotConfig(
        broker="alpaca",
        execution_enabled=True,
        alpaca_paper=True,
        alpaca_api_key="paper-key",
        alpaca_secret_key="paper-secret",
        alpaca_account_id=account_id,
        dedicated_account=True,
        deployment_approval_path=tmp_path / "deployment-approval.json",
        deployment_public_keys_path=registry_path,
        deployment_public_keys_sha256=registry_hash,
        covariance_evidence_path=tmp_path / "covariance-envelope.json",
        covariance_execution_prices_path=tmp_path / "covariance-vwap.csv",
        covariance_corporate_actions_path=tmp_path / "covariance-actions.csv",
        covariance_public_keys_path=registry_path,
        covariance_public_keys_sha256=registry_hash,
        covariance_provider_id="vendor-feed-2026",
        covariance_venue_id="consolidated-us-equities",
        borrow_evidence_path=tmp_path / "borrow-envelope.json",
        borrow_terms_path=tmp_path / "borrow-terms.csv",
        borrow_public_keys_path=borrow_registry_path,
        borrow_public_keys_sha256=registry_hash,
        borrow_provider_id="borrow-provider-2026",
        borrow_venue_id="consolidated-us-equities",
        borrow_max_term_age_seconds=300,
        max_live_annual_borrow_rate=0.02,
        plan_authentication_key=_TEST_PLAN_AUTHENTICATION_KEY,
        emergency_authentication_key=_TEST_EMERGENCY_AUTHENTICATION_KEY,
        database_path=tmp_path / "trading.sqlite3",
        log_path=tmp_path / "trading.log",
        kill_switch_path=tmp_path / "KILL_SWITCH",
        process_lock_path=tmp_path / "process.lock",
        operation_lock_path=tmp_path / "operation.lock",
        kill_switch_ack_path=tmp_path / "KILL_SWITCH.ack.json",
        daemon_health_path=tmp_path / "health.json",
        simulated_state_path=tmp_path / "simulated.json",
    )


def _payload(
    config: BotConfig,
    *,
    account_id: str = "account-approved-0001",
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> dict[str, object]:
    issued = issued_at or datetime.now(timezone.utc) - timedelta(minutes=1)
    expires = expires_at or issued + timedelta(days=6)
    return {
        "schema_version": 2,
        "purpose": "approved_broker_deployment_v2",
        "approval_id": "approval-2026-0001",
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "broker": {
            "adapter": "alpaca",
            "environment": "paper" if config.alpaca_paper else "live",
            "account_id": account_id,
        },
        "strategy_config": config.strategy.to_dict(),
        "strategy_config_sha256": strategy_config_hash(config.strategy),
        "bot_config_sha256": bot_config_hash(config),
        "research_software_sha256": research_software_hash(),
        "deployment_software_sha256": deployment_software_hash(),
        "deployment_runtime_sha256": deployment_runtime_hash(),
        "deployment_descriptors_sha256": deployment_descriptors_hash(),
        "container_base_image_digest": container_base_image_digest(),
        "dependency_lock_sha256": dependency_lock_hash(),
        "certification": {
            "status": "passed",
            "certified_at": (issued - timedelta(minutes=1)).isoformat(),
            "sealed_manifest_sha256": "a" * 64,
            "result_bundle_sha256": "b" * 64,
            "research_specification_sha256": "c" * 64,
        },
    }


def _write_approval(config: BotConfig, payload: dict[str, object] | None = None) -> bytes:
    signed_payload = payload or _payload(config)
    envelope = {
        "payload": signed_payload,
        "signature": {
            "algorithm": "RSASSA-PKCS1-v1_5-SHA256",
            "key_id": "deployment-key-2026",
            "value": _sign(signed_payload),
        },
    }
    raw = canonical_json(envelope)
    assert config.deployment_approval_path is not None
    config.deployment_approval_path.write_bytes(raw)
    return raw


def test_plan_authentication_secret_is_excluded_but_fingerprint_is_bound(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)
    binding = bot_config_binding(config)

    assert "plan_authentication_key" not in binding
    assert "emergency_authentication_key" not in binding
    assert binding["plan_authentication_key_sha256"] == config.plan_authentication_key_sha256
    assert binding["emergency_authentication_key_sha256"] == (
        config.emergency_authentication_key_sha256
    )
    assert config.plan_authentication_key not in json.dumps(binding, sort_keys=True)
    assert config.emergency_authentication_key not in json.dumps(binding, sort_keys=True)


def test_signed_borrow_config_is_complete_rate_bounded_and_deployment_bound(
    tmp_path: Path,
) -> None:
    config = _config(tmp_path)

    config.validate()
    binding = bot_config_binding(config)

    assert binding["borrow_evidence_path"] == str(config.borrow_evidence_path.resolve())
    assert binding["borrow_terms_path"] == str(config.borrow_terms_path.resolve())
    assert binding["borrow_public_keys_path"] == str(
        config.borrow_public_keys_path.resolve()
    )
    assert binding["borrow_public_keys_sha256"] == config.borrow_public_keys_sha256
    assert binding["borrow_provider_id"] == "borrow-provider-2026"
    assert binding["borrow_venue_id"] == "consolidated-us-equities"
    assert binding["borrow_max_term_age_seconds"] == 300
    assert binding["max_live_annual_borrow_rate"] == 0.02

    with pytest.raises(ValueError, match="BORROW_TERMS_PATH"):
        replace(config, borrow_terms_path=None).validate()

    with pytest.raises(ValueError, match="cannot exceed the annual short-borrow rate"):
        replace(config, max_live_annual_borrow_rate=0.020001).validate()

    changed = replace(config, borrow_provider_id="borrow-provider-2027")
    assert bot_config_hash(changed) != bot_config_hash(config)


def test_all_signed_borrow_environment_fields_are_loaded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = {
        "BORROW_EVIDENCE_PATH": tmp_path / "borrow-envelope.json",
        "BORROW_TERMS_PATH": tmp_path / "borrow-terms.csv",
        "BORROW_GOVERNANCE_PUBLIC_KEYS_PATH": tmp_path / "borrow-keys.json",
    }
    for name, path in paths.items():
        monkeypatch.setenv(name, str(path))
    monkeypatch.setenv("BORROW_GOVERNANCE_PUBLIC_KEYS_SHA256", "A" * 64)
    monkeypatch.setenv("BORROW_PROVIDER_ID", "borrow-provider-2026")
    monkeypatch.setenv("BORROW_VENUE_ID", "consolidated-us-equities")
    monkeypatch.setenv("BORROW_MAX_TERM_AGE_SECONDS", "123")
    monkeypatch.setenv("MAX_LIVE_ANNUAL_BORROW_RATE", "0.015")

    loaded = BotConfig.from_env(None)

    assert loaded.borrow_evidence_path == paths["BORROW_EVIDENCE_PATH"].resolve()
    assert loaded.borrow_terms_path == paths["BORROW_TERMS_PATH"].resolve()
    assert loaded.borrow_public_keys_path == paths[
        "BORROW_GOVERNANCE_PUBLIC_KEYS_PATH"
    ].resolve()
    assert loaded.borrow_public_keys_sha256 == "a" * 64
    assert loaded.borrow_provider_id == "borrow-provider-2026"
    assert loaded.borrow_venue_id == "consolidated-us-equities"
    assert loaded.borrow_max_term_age_seconds == 123
    assert loaded.max_live_annual_borrow_rate == 0.015


def test_valid_approval_binds_strategy_software_lock_mode_and_certification(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _write_approval(config)

    result = verify_deployment_approval(
        config,
        actual_account_id="account-approved-0001",
    )

    assert result.verified is True
    assert result.approval_id == "approval-2026-0001"
    assert result.account_id == "account-approved-0001"
    assert result.expires_at is not None


def test_missing_tampered_and_duplicate_key_approvals_fail_closed(tmp_path: Path) -> None:
    config = _config(tmp_path)
    missing = verify_deployment_approval(config)
    assert missing.verified is False
    assert any("DEPLOYMENT_APPROVAL_PATH is required" in error or "unreadable" in error for error in missing.errors)

    raw = _write_approval(config)
    tampered = raw.replace(b'"status":"passed"', b'"status":"failed"')
    assert config.deployment_approval_path is not None
    config.deployment_approval_path.write_bytes(tampered)
    result = verify_deployment_approval(config)
    assert result.verified is False
    assert any("signature verification failed" in error for error in result.errors)

    duplicate = raw.replace(b'"schema_version":2', b'"schema_version":2,"schema_version":2')
    config.deployment_approval_path.write_bytes(duplicate)
    result = verify_deployment_approval(config)
    assert result.verified is False
    assert any("duplicate JSON object key" in error for error in result.errors)


def test_expiry_account_config_and_software_mismatches_fail_closed(tmp_path: Path) -> None:
    config = _config(tmp_path)
    expired_payload = _payload(
        config,
        issued_at=datetime.now(timezone.utc) - timedelta(days=2),
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    _write_approval(config, expired_payload)
    expired = verify_deployment_approval(config)
    assert expired.verified is False
    assert any("has expired" in error for error in expired.errors)

    overlong = _payload(
        config,
        issued_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        expires_at=datetime.now(timezone.utc) + timedelta(days=8),
    )
    _write_approval(config, overlong)
    result = verify_deployment_approval(config)
    assert result.verified is False
    assert any("lifetime must not exceed 7 days" in error for error in result.errors)

    _write_approval(config)
    wrong_account = verify_deployment_approval(config, actual_account_id="account-other-0002")
    assert wrong_account.verified is False
    assert any("account does not match" in error for error in wrong_account.errors)

    wrong_pin = verify_deployment_approval(
        replace(config, alpaca_account_id="account-other-0002")
    )
    assert wrong_pin.verified is False
    assert any("does not match ALPACA_ACCOUNT_ID" in error for error in wrong_pin.errors)

    changed_strategy = replace(
        config.strategy,
        signals=replace(config.strategy.signals, signal_clip=2.5),
    )
    changed_config = replace(config, strategy=changed_strategy)
    changed = verify_deployment_approval(changed_config)
    assert changed.verified is False
    assert any("AppConfig does not match" in error for error in changed.errors)

    wrong_software = _payload(config)
    wrong_software["deployment_software_sha256"] = "0" * 64
    _write_approval(config, wrong_software)
    changed = verify_deployment_approval(config)
    assert changed.verified is False
    assert any("deployment_software_sha256 does not match" in error for error in changed.errors)

    wrong_lock = _payload(config)
    wrong_lock["dependency_lock_sha256"] = "0" * 64
    _write_approval(config, wrong_lock)
    changed = verify_deployment_approval(config)
    assert changed.verified is False
    assert any("dependency_lock_sha256 does not match" in error for error in changed.errors)

    wrong_runtime = _payload(config)
    wrong_runtime["deployment_runtime_sha256"] = "0" * 64
    _write_approval(config, wrong_runtime)
    changed = verify_deployment_approval(config)
    assert changed.verified is False
    assert any("deployment_runtime_sha256 does not match" in error for error in changed.errors)

    wrong_descriptors = _payload(config)
    wrong_descriptors["deployment_descriptors_sha256"] = "0" * 64
    _write_approval(config, wrong_descriptors)
    changed = verify_deployment_approval(config)
    assert changed.verified is False
    assert any("deployment_descriptors_sha256 does not match" in error for error in changed.errors)

    wrong_mode = _payload(config)
    wrong_mode["broker"] = {
        "adapter": "alpaca",
        "environment": "live",
        "account_id": "account-approved-0001",
    }
    _write_approval(config, wrong_mode)
    changed = verify_deployment_approval(config)
    assert changed.verified is False
    assert any("environment does not match" in error for error in changed.errors)


def test_factory_requires_approval_and_checks_connected_account_before_state_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)
    with pytest.raises(RuntimeError, match="valid signed deployment approval"):
        build_engine(config)
    assert not config.database_path.exists()

    _write_approval(config)

    class WrongAccountBroker:
        def __init__(self, **_kwargs) -> None:
            pass

        def get_account_identity(self) -> str:
            return "account-other-0002"

    monkeypatch.setattr("auto_trader.factory.AlpacaBroker", WrongAccountBroker)
    with pytest.raises(RuntimeError, match="independently pinned"):
        build_engine(config)
    assert not config.database_path.exists()

    class ApprovedAccountBroker:
        authorized_until: datetime | None = None

        def __init__(self, **kwargs) -> None:
            type(self).authorized_until = kwargs["routine_execution_authorized_until"]
            self.authorization_check = kwargs["routine_authorization_check"]

        def get_account_identity(self) -> str:
            return "account-approved-0001"

    monkeypatch.setattr("auto_trader.factory.AlpacaBroker", ApprovedAccountBroker)
    engine = build_engine(config)
    assert engine.config == config
    assert config.database_path.exists()
    assert ApprovedAccountBroker.authorized_until is not None
    assert ApprovedAccountBroker.authorized_until > datetime.now(timezone.utc)
    assert engine.broker.authorization_check is not None

    # Replacing/revoking the pinned registry after startup blocks the next routine
    # submission authorization check rather than remaining trusted until restart.
    assert config.deployment_public_keys_path is not None
    config.deployment_public_keys_path.write_text('{"schema_version":1,"keys":{}}', encoding="utf-8")
    with pytest.raises(RuntimeError, match="revoked or changed"):
        engine.broker.authorization_check()


def test_approval_swap_after_planning_rejects_old_plan_before_broker_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    _write_approval(config)

    class TrackingBroker:
        mutated = False

        def __init__(self, **_kwargs) -> None:
            pass

        def get_account_identity(self) -> str:
            return "account-approved-0001"

        def get_market_clock(self) -> MarketClock:
            now = datetime.now(timezone.utc)
            return MarketClock(now, True, now + timedelta(days=1), now + timedelta(hours=6))

        def cancel_orders_and_wait(self, *_args, **_kwargs):
            type(self).mutated = True
            return []

        def submit_market_order(self, *_args, **_kwargs):
            type(self).mutated = True
            raise AssertionError("stale plan must not submit")

    monkeypatch.setattr("auto_trader.factory.AlpacaBroker", TrackingBroker)
    engine = build_engine(config)
    plan = TargetPlan(
        plan_id="",
        as_of=datetime.now(timezone.utc).date(),
        created_at=datetime.now(timezone.utc),
        regime="neutral",
        regime_multiplier=1.0,
        desired_gross=0.0,
        forecast_volatility=0.1,
        target_weights={},
        metadata={"assets": list(config.symbols), "asset_beta": {}},
    )
    plan = seal_target_plan(
        plan,
        engine._current_plan_binding(),
        config.plan_authentication_key_bytes,
    )
    assert engine.store.save_plan(plan)

    replacement = _payload(config)
    replacement["approval_id"] = "approval-2026-0002"
    _write_approval(config, replacement)

    with pytest.raises(RuntimeError, match="changed since engine startup"):
        engine.execute_latest_plan(force=True)
    assert TrackingBroker.mutated is False


def test_approval_swap_after_plan_preflight_is_rejected_by_submission_authorizer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    _write_approval(config)

    class ApprovalAwareBroker:
        def __init__(self, **kwargs) -> None:
            self.authorization_check = kwargs["routine_authorization_check"]

        def get_account_identity(self) -> str:
            return "account-approved-0001"

    monkeypatch.setattr("auto_trader.factory.AlpacaBroker", ApprovalAwareBroker)
    engine = build_engine(config)

    # This is the execution preflight boundary. A replacement after this point must
    # still be rejected by the adapter's immediately-before-submit callback.
    preflight_binding = engine._current_plan_binding()
    assert preflight_binding["approval_id"] == "approval-2026-0001"

    replacement = _payload(config)
    replacement["approval_id"] = "approval-2026-0002"
    _write_approval(config, replacement)

    with pytest.raises(RuntimeError, match="changed since engine startup"):
        engine.broker.authorization_check()


def test_pre_submit_authorizer_rechecks_actual_account_and_concurrent_kill(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    _write_approval(config)

    class SwitchableAccountBroker:
        account_id = "account-approved-0001"

        def __init__(self, **kwargs) -> None:
            self.authorization_check = kwargs["routine_authorization_check"]

        def get_account_identity(self) -> str:
            return type(self).account_id

    monkeypatch.setattr("auto_trader.factory.AlpacaBroker", SwitchableAccountBroker)
    engine = build_engine(config)

    SwitchableAccountBroker.account_id = "account-switched-0002"
    with pytest.raises(RuntimeError, match="account identity changed"):
        engine.broker.authorization_check()

    SwitchableAccountBroker.account_id = "account-approved-0001"
    config.kill_switch_path.write_text("operator_halt\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="filesystem kill switch"):
        engine.broker.authorization_check()


def test_pre_submit_authorizer_uses_refreshed_equity_and_final_limit_economics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    _write_approval(config)
    execution_session = (
        datetime.now(ZoneInfo("America/New_York")) + timedelta(days=1)
    ).date()
    execution_timestamp = datetime.combine(
        execution_session,
        time(9, 31),
        tzinfo=ZoneInfo("America/New_York"),
    ).astimezone(timezone.utc)

    class RiskRefreshBroker:
        equity = 100_000.0
        account_reads = 0
        position_qty = 0.0

        def __init__(self, **kwargs) -> None:
            self.authorization_check = kwargs["routine_authorization_check"]

        def get_account_identity(self) -> str:
            return "account-approved-0001"

        def get_account(self) -> AccountSnapshot:
            type(self).account_reads += 1
            now = datetime.now(timezone.utc)
            return AccountSnapshot(
                timestamp=now,
                equity=type(self).equity,
                cash=type(self).equity,
                buying_power=type(self).equity,
                last_equity=type(self).equity,
                external_cash_activities=(),
            )

        def get_positions(self) -> dict[str, PositionSnapshot]:
            if abs(type(self).position_qty) <= 1e-12:
                return {}
            return {
                "SPY": PositionSnapshot(
                    symbol="SPY",
                    qty=type(self).position_qty,
                    market_value=type(self).position_qty * 100.0,
                    current_price=100.0,
                )
            }

        def list_open_orders(self, _symbols=None):
            return []

        def get_market_clock(self) -> MarketClock:
            return MarketClock(
                execution_timestamp,
                True,
                execution_timestamp,
                execution_timestamp + timedelta(hours=6),
            )

    monkeypatch.setattr("auto_trader.factory.AlpacaBroker", RiskRefreshBroker)
    engine = build_engine(config)
    engine._wall_clock_provider = lambda: execution_timestamp
    engine.store.clear_halt()
    engine._active_routine_execution_date = execution_session
    engine._active_routine_plan = seal_target_plan(
        TargetPlan(
            plan_id="",
            as_of=execution_session - timedelta(days=1),
            created_at=datetime.now(timezone.utc),
            regime="neutral",
            regime_multiplier=1.0,
            desired_gross=0.0,
            forecast_volatility=0.1,
            target_weights={},
            metadata={"assets": list(config.symbols)},
        ),
        engine._current_plan_binding(),
        config.plan_authentication_key_bytes,
    )
    borrow_boundaries: list[dict[str, object]] = []
    monkeypatch.setattr(
        engine,
        "_enforce_governed_borrow_or_emergency_reduce",
        lambda *_args, **kwargs: borrow_boundaries.append(dict(kwargs)),
    )
    freshness_boundaries: list[dict[str, object]] = []

    def authorize_freshness(*_args, **kwargs):
        freshness_boundaries.append(dict(kwargs))
        return execution_timestamp

    monkeypatch.setattr(
        engine,
        "_enforce_governed_borrow_freshness_or_emergency_reduce",
        authorize_freshness,
    )
    monkeypatch.setattr(
        engine,
        "_evaluate_risk",
        lambda *_args: RiskDecision(True, False, False, "safe", 0.0, 0.0, 0.0),
    )

    engine.broker.authorization_check("SPY", 50.0, OrderSide.BUY, 100.0)
    engine.broker.authorization_check("SPY", 1.0, OrderSide.SELL, 100.0)
    RiskRefreshBroker.equity = 50_000.0
    with pytest.raises(RuntimeError, match="refreshed child cap"):
        engine.broker.authorization_check("SPY", 50.0, OrderSide.BUY, 100.0)
    RiskRefreshBroker.equity = 100_000.0
    RiskRefreshBroker.position_qty = 0.00005
    with pytest.raises(RuntimeError, match="would cross zero"):
        engine.broker.authorization_check("SPY", 0.0001, OrderSide.SELL, 100.0)

    race_reads = 0

    def raced_positions() -> dict[str, PositionSnapshot]:
        nonlocal race_reads
        race_reads += 1
        if race_reads == 1:
            return {
                "SPY": PositionSnapshot(
                    symbol="SPY",
                    qty=100.0,
                    market_value=10_000.0,
                    current_price=100.0,
                )
            }
        return {}

    emergency_reconciliations: list[str] = []
    monkeypatch.setattr(engine.broker, "get_positions", raced_positions)
    monkeypatch.setattr(
        engine,
        "emergency_flatten",
        lambda reason, persist_halt=True: emergency_reconciliations.append(reason) or [],
    )
    with pytest.raises(RuntimeError, match="position quantities changed"):
        engine.broker.authorization_check("SPY", 100.0, OrderSide.SELL, 100.0)

    assert RiskRefreshBroker.account_reads == 5
    assert race_reads == 2
    assert emergency_reconciliations == [
        "routine_position_changed_during_final_authorization"
    ]
    assert len(borrow_boundaries) == 2
    assert borrow_boundaries[0]["projected_short_symbols"] == []
    assert borrow_boundaries[1]["projected_short_symbols"] == ["SPY"]
    assert borrow_boundaries[0]["projected_short_quantities"] == {}
    assert borrow_boundaries[1]["projected_short_quantities"] == {"SPY": 81.0}
    assert [boundary["stage"] for boundary in borrow_boundaries] == [
        "final_child:SPY:buy",
        "final_child:SPY:sell",
    ]
    assert [boundary["stage"] for boundary in freshness_boundaries] == [
        "final_child:SPY:buy:post_verification_freshness",
        "final_child:SPY:sell:post_verification_freshness",
    ]


def test_pre_submit_authorizer_never_uses_stale_non_child_position_marks(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    _write_approval(config)

    class FreshMarkBroker:
        fresh_prices: dict[str, float] = {}
        requested_symbols: list[list[str]] = []

        def __init__(self, **kwargs) -> None:
            self.authorization_check = kwargs["routine_authorization_check"]

        def get_account_identity(self) -> str:
            return "account-approved-0001"

        def get_account(self) -> AccountSnapshot:
            now = datetime.now(timezone.utc)
            return AccountSnapshot(
                timestamp=now,
                equity=100_000.0,
                cash=100_000.0,
                buying_power=100_000.0,
                last_equity=100_000.0,
                external_cash_activities=(),
            )

        def get_positions(self) -> dict[str, PositionSnapshot]:
            return {
                "QQQ": PositionSnapshot(
                    symbol="QQQ",
                    qty=200.0,
                    market_value=200.0,
                    # This stale low mark would make the account look harmless if the
                    # final boundary trusted PositionSnapshot.current_price.
                    current_price=1.0,
                )
            }

        def list_open_orders(self, _symbols=None):
            return []

        def get_latest_prices(self, symbols: list[str]) -> dict[str, float]:
            type(self).requested_symbols.append(list(symbols))
            return dict(type(self).fresh_prices)

    monkeypatch.setattr("auto_trader.factory.AlpacaBroker", FreshMarkBroker)
    engine = build_engine(config)
    engine.store.clear_halt()
    monkeypatch.setattr(
        engine,
        "_evaluate_risk",
        lambda *_args: RiskDecision(True, False, False, "safe", 0.0, 0.0, 0.0),
    )

    with pytest.raises(RuntimeError, match="lacks fresh quote-compliant prices"):
        engine.broker.authorization_check("SPY", 1.0, OrderSide.BUY, 100.0)

    FreshMarkBroker.fresh_prices = {"QQQ": 1_000.0}
    with pytest.raises(RuntimeError, match="projected gross exposure"):
        engine.broker.authorization_check("SPY", 1.0, OrderSide.BUY, 100.0)

    assert FreshMarkBroker.requested_symbols == [["QQQ"], ["QQQ"]]


def test_signed_approval_is_the_single_source_for_every_app_config_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)
    approved = replace(
        config.strategy,
        signals=replace(config.strategy.signals, reversal_3_weight=0.61),
        regime=replace(config.strategy.regime, ic_window=77),
        costs=replace(config.strategy.costs, adv_lookback_days=31),
    )
    approval_config = replace(config, strategy=approved)
    _write_approval(approval_config)
    monkeypatch.setenv("DEPLOYMENT_APPROVAL_PATH", str(config.deployment_approval_path))
    monkeypatch.setenv("REVERSAL_3_WEIGHT", "9.9")

    loaded = BotConfig.from_env(None)

    assert loaded.strategy == approved


def test_corrupt_approval_cannot_block_out_of_band_config_for_kill(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    corrupt = tmp_path / "corrupt-approval.json"
    corrupt.write_text('{"payload":', encoding="utf-8")
    kill_path = tmp_path / "KILL_SWITCH"
    monkeypatch.setenv("DEPLOYMENT_APPROVAL_PATH", str(corrupt))
    monkeypatch.setenv("KILL_SWITCH_PATH", str(kill_path))

    loaded = BotConfig.from_env(None)

    assert loaded.deployment_approval_path == corrupt.resolve()
    assert loaded.kill_switch_path == kill_path.resolve()
    assert loaded.strategy == BotConfig().strategy
    with pytest.raises(RuntimeError, match="valid signed deployment approval"):
        build_engine(
            replace(
                loaded,
                broker="alpaca",
                execution_enabled=True,
                alpaca_api_key="key",
                alpaca_secret_key="secret",
                    alpaca_account_id="account-approved-0001",
                    plan_authentication_key=_TEST_PLAN_AUTHENTICATION_KEY,
                    emergency_authentication_key=_TEST_EMERGENCY_AUTHENTICATION_KEY,
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
                    max_live_annual_borrow_rate=0.02,
                )
        )


def test_emergency_only_factory_bypasses_bad_approval_without_authorizing_routine_orders(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    assert config.deployment_approval_path is not None
    config.deployment_approval_path.write_text("not-json", encoding="utf-8")

    class EmergencyBroker:
        authorized_until: datetime | None = datetime.max.replace(tzinfo=timezone.utc)

        def __init__(self, **kwargs) -> None:
            type(self).authorized_until = kwargs["routine_execution_authorized_until"]

        def get_account_identity(self) -> str:
            return "account-approved-0001"

    monkeypatch.setattr("auto_trader.factory.AlpacaBroker", EmergencyBroker)

    engine = build_engine(config, emergency_only=True)

    assert isinstance(engine.broker, EmergencyBroker)
    assert EmergencyBroker.authorized_until is None
    recovery = config.database_path.with_name(
        config.database_path.name + ".emergency-recovery.sqlite3"
    )
    assert engine.store.path == recovery.resolve()
    assert recovery.exists()
    assert not config.database_path.exists()


def test_emergency_only_refuses_wrong_connected_account_before_state_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)

    class WrongEmergencyBroker:
        def __init__(self, **_kwargs) -> None:
            pass

        def get_account_identity(self) -> str:
            return "account-other-0002"

    monkeypatch.setattr("auto_trader.factory.AlpacaBroker", WrongEmergencyBroker)

    with pytest.raises(RuntimeError, match="independently pinned"):
        build_engine(config, emergency_only=True)
    assert not config.database_path.exists()


def test_live_emergency_uses_isolated_recovery_state_when_authoritative_state_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = replace(
        _config(tmp_path),
        alpaca_paper=False,
        live_ack="I_UNDERSTAND_LIVE_TRADING_CAN_LOSE_MONEY",
    )
    assert not config.database_path.exists()

    class EmergencyBroker:
        def __init__(self, **_kwargs) -> None:
            pass

        def get_account_identity(self) -> str:
            return "account-approved-0001"

    monkeypatch.setattr("auto_trader.factory.AlpacaBroker", EmergencyBroker)

    engine = build_engine(config, emergency_only=True)
    recovery = config.database_path.with_name(
        config.database_path.name + ".emergency-recovery.sqlite3"
    )

    assert engine.store.path == recovery.resolve()
    assert recovery.exists()
    assert not config.database_path.exists()
    with pytest.raises(RuntimeError, match="refuses to initialize replacement state"):
        build_engine(config)


def test_emergency_lifecycle_anchor_failure_switches_state_without_changing_journal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    StateStore(
        config.database_path,
        authentication_key=config.plan_authentication_key_bytes,
    )
    identity = config.database_path.with_suffix(config.database_path.suffix + ".identity")
    identity.write_text("tampered-anchor\n", encoding="utf-8")
    marker = merge_control_marker(config.kill_switch_path, "anchor_test", flatten=True)
    assert marker.incident_id is not None
    journal = EmergencyJournal(
        config.effective_emergency_journal_path,
        config.emergency_authentication_key_bytes,
        config.emergency_journal_scope,
    )
    original = journal.prepare_submission(
        marker.incident_id,
        symbol="SPY",
        current_qty=3.0,
        side="sell",
        qty=3.0,
    )

    class EmergencyBroker:
        def __init__(self, **_kwargs) -> None:
            pass

        @staticmethod
        def get_account_identity() -> str:
            return "account-approved-0001"

    monkeypatch.setattr("auto_trader.factory.AlpacaBroker", EmergencyBroker)
    engine = build_engine(config, emergency_only=True)
    recovery = config.database_path.with_name(
        config.database_path.name + ".emergency-recovery.sqlite3"
    )

    assert engine.store.path == recovery.resolve()
    retried = engine.emergency_journal.prepare_submission(
        marker.incident_id,
        symbol="SPY",
        current_qty=3.0,
        side="sell",
        qty=3.0,
    )
    assert retried.client_order_id == original.client_order_id


def test_expired_approval_blocks_routine_orders_but_preserves_emergency_path() -> None:
    broker = AlpacaBroker.__new__(AlpacaBroker)
    broker._routine_execution_authorized_until = datetime.now(timezone.utc) - timedelta(seconds=1)
    with pytest.raises(RuntimeError, match="missing or expired"):
        broker._authorize_routine_submission("SPY", 1.0, OrderSide.BUY, 100.0)

    broker._submit_order = lambda **kwargs: kwargs  # type: ignore[method-assign]
    result = broker.submit_emergency_market_order(
        "SPY", 1.0, OrderSide.SELL, "emergency-still-allowed"
    )
    assert result["emergency"] is True


def _minimal_kill_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "BROKER": "alpaca",
        "ALPACA_PAPER": "true",
        "ALPACA_API_KEY": "paper-key",
        "ALPACA_SECRET_KEY": "paper-secret",
        "ALPACA_ACCOUNT_ID": "account-approved-0001",
        "KILL_SWITCH_PATH": str(tmp_path / "KILL_SWITCH"),
        "KILL_SWITCH_ACK_PATH": str(tmp_path / "KILL_SWITCH.ack.json"),
        "DATABASE_PATH": str(tmp_path / "state.sqlite3"),
        "LOG_PATH": str(tmp_path / "bot.log"),
        "PROCESS_LOCK_PATH": str(tmp_path / "process.lock"),
        "OPERATION_LOCK_PATH": str(tmp_path / "operation.lock"),
        "DAEMON_HEALTH_PATH": str(tmp_path / "health.json"),
        "SIMULATED_STATE_PATH": str(tmp_path / "simulated.json"),
        # Every value below is invalid for routine configuration and must be ignored
        # by the explicit emergency path.
        "SYMBOLS": "@@@,",
        "TARGET_VOLATILITY": "not-a-number",
        "PLAN_TIME": "not-a-clock",
        "MARKETABLE_LIMIT_COLLAR_BPS": "not-a-number",
        "LIVE_TRADING_ACK": "invalid",
        "PLAN_AUTHENTICATION_KEY": "malformed-routine-secret",
        "EMERGENCY_AUTHENTICATION_KEY": _TEST_EMERGENCY_AUTHENTICATION_KEY,
        "EMERGENCY_JOURNAL_PATH": str(tmp_path / "EMERGENCY_JOURNAL.json"),
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("DEPLOYMENT_APPROVAL_PATH", raising=False)


def test_flatten_kill_survives_malformed_routine_config_and_reaches_pinned_account(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _minimal_kill_environment(tmp_path, monkeypatch)

    class EmergencyBroker:
        identity_checks = 0

        def __init__(self, **_kwargs) -> None:
            pass

        def get_account_identity(self) -> str:
            type(self).identity_checks += 1
            return "account-approved-0001"

        def cancel_orders_and_wait(self, *_args, **_kwargs):
            return []

        def get_positions(self):
            return {}

        def list_open_orders(self, *_args, **_kwargs):
            return []

    monkeypatch.setattr("auto_trader.factory.AlpacaBroker", EmergencyBroker)

    result = bot_main(["--env-file", str(tmp_path / "missing.env"), "kill", "--reason", "test"])

    assert result == 0
    assert EmergencyBroker.identity_checks == 1
    request = parse_control_marker((tmp_path / "KILL_SWITCH").read_text(encoding="utf-8"))
    assert request.flatten is True


def test_halt_only_marker_precedes_and_survives_corrupt_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _minimal_kill_environment(tmp_path, monkeypatch)

    class EmergencyBroker:
        identity_checks = 0
        cancellation_calls: list[tuple[object, object]] = []

        def __init__(self, **_kwargs) -> None:
            pass

        def get_account_identity(self) -> str:
            type(self).identity_checks += 1
            return "account-approved-0001"

        def cancel_orders_and_wait(self, symbols, *, client_prefix, **_kwargs):
            type(self).cancellation_calls.append((symbols, client_prefix))
            return []

        def list_open_orders(self, *_args, **_kwargs):
            return []

    monkeypatch.setattr("auto_trader.factory.AlpacaBroker", EmergencyBroker)

    result = bot_main(
        ["--env-file", str(tmp_path / "missing.env"), "kill", "--no-flatten", "--reason", "pause"]
    )

    assert result == 0
    assert EmergencyBroker.identity_checks == 1
    assert EmergencyBroker.cancellation_calls == [(None, None)]
    request = parse_control_marker((tmp_path / "KILL_SWITCH").read_text(encoding="utf-8"))
    assert request.reason == "pause"
    assert request.flatten is False


def test_kill_returns_pending_when_broker_risk_reduction_cannot_start(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _minimal_kill_environment(tmp_path, monkeypatch)

    def unavailable_engine(*_args, **_kwargs):
        raise ConnectionError("broker unavailable")

    monkeypatch.setattr("bot.build_engine", unavailable_engine)

    result = bot_main(
        ["--env-file", str(tmp_path / "missing.env"), "kill", "--reason", "incident"]
    )

    output = json.loads(capsys.readouterr().out)
    assert result == EMERGENCY_ACTION_PENDING_EXIT_CODE
    assert output["status"] == "accepted_state_or_broker_unavailable"
    assert output["halted"] is True and output["flatten_requested"] is True
    request = parse_control_marker((tmp_path / "KILL_SWITCH").read_text(encoding="utf-8"))
    assert request.reason == "incident" and request.flatten is True


def test_missing_plan_key_emergency_restart_reuses_authenticated_recovery_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _minimal_kill_environment(tmp_path, monkeypatch)
    monkeypatch.delenv("PLAN_AUTHENTICATION_KEY", raising=False)
    config = BotConfig.emergency_from_env(tmp_path / "missing.env")

    class EmergencyBroker:
        def __init__(self, **_kwargs) -> None:
            pass

        def get_account_identity(self) -> str:
            return "account-approved-0001"

    monkeypatch.setattr("auto_trader.factory.AlpacaBroker", EmergencyBroker)

    first = build_engine(config, emergency_only=True)
    first_attempt = first.store.begin_flatten_attempt("restart-safe-emergency")
    first_path = first.store.path
    second = build_engine(config, emergency_only=True)
    second_attempt = second.store.begin_flatten_attempt("restart-safe-emergency")

    assert first_path == second.store.path
    assert first_path.name.endswith(".emergency-recovery.sqlite3")
    assert first_path != config.database_path.resolve()
    assert first_attempt == second_attempt
    assert first.store.authentication_key == second.store.authentication_key


def test_halt_only_lock_busy_reports_pending_without_claiming_cancellation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _minimal_kill_environment(tmp_path, monkeypatch)

    class EmergencyBroker:
        cancellation_calls = 0

        def __init__(self, **_kwargs) -> None:
            pass

        @staticmethod
        def get_account_identity() -> str:
            return "account-approved-0001"

        def cancel_orders_and_wait(self, *_args, **_kwargs):
            type(self).cancellation_calls += 1
            return []

        @staticmethod
        def list_open_orders(*_args, **_kwargs):
            return []

    monkeypatch.setattr("auto_trader.factory.AlpacaBroker", EmergencyBroker)
    with ProcessLock(
        tmp_path / "operation.lock",
        timeout_seconds=0,
        purpose="test active operation",
    ):
        result = bot_main(
            [
                "--env-file",
                str(tmp_path / "missing.env"),
                "kill",
                "--no-flatten",
                "--reason",
                "pause",
            ]
        )

    output = json.loads(capsys.readouterr().out)
    assert result == EMERGENCY_ACTION_PENDING_EXIT_CODE
    assert EmergencyBroker.cancellation_calls == 0
    assert output["status"] == "accepted_pending_order_cancellation"
    assert output["flatten_requested"] is False
    request = parse_control_marker((tmp_path / "KILL_SWITCH").read_text(encoding="utf-8"))
    assert request.reason == "pause" and request.flatten is False
