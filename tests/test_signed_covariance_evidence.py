from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import numpy as np
import pandas as pd
import pytest

from auto_trader.covariance_evidence import (
    COVARIANCE_EVIDENCE_PURPOSE,
    COVARIANCE_EVIDENCE_SCHEMA_VERSION,
    COVARIANCE_RETURN_SEMANTICS,
    CovarianceEvidenceError,
    SignedCovarianceEvidenceProvider,
)
from auto_trader.brokers.alpaca import AlpacaBroker
from auto_trader.brokers.base import GovernedCovarianceEvidence
from auto_trader.config import BotConfig
from auto_trader.deployment import bot_config_binding, bot_config_hash
from auto_trader.store import StateStore
from quant_app.governance import (
    SEALED_CORPORATE_ACTION_AS_OF_CUTOFF,
    SEALED_CORPORATE_ACTION_CASH_DEFINITION,
    SEALED_CORPORATE_ACTION_SPLIT_DEFINITION,
    SEALED_DECISION_INFORMATION_CUTOFF,
    SEALED_EXECUTION_PRICE_DEFINITION,
    SEALED_EXECUTION_PRICE_ROW_LABEL,
    SEALED_INTERVAL_TIMEZONE,
    SEALED_RETURN_ROW_LABEL,
    canonical_json,
    sha256_bytes,
)


# Test-only RSA material, unrelated to any deployment key.
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
_SYMBOLS = ("AAA", "BBB", "CCC", "DDD")


def _sign(payload: dict[str, object]) -> str:
    size = (_RSA_N.bit_length() + 7) // 8
    digest_info = _DIGEST_INFO_PREFIX + hashlib.sha256(canonical_json(payload)).digest()
    encoded = (
        b"\x00\x01"
        + b"\xff" * (size - len(digest_info) - 3)
        + b"\x00"
        + digest_info
    )
    signature = pow(int.from_bytes(encoded, "big"), _RSA_D, _RSA_N).to_bytes(
        size, "big"
    )
    return base64.b64encode(signature).decode("ascii")


def _registry(tmp_path: Path) -> tuple[Path, str]:
    modulus = _RSA_N.to_bytes((_RSA_N.bit_length() + 7) // 8, "big")
    document = {
        "schema_version": 1,
        "keys": {
            "covariance-key-2026": {
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
    path = tmp_path / "covariance-public-keys.json"
    path.write_bytes(raw)
    return path, sha256_bytes(raw)


def _snapshot(
    tmp_path: Path,
    *,
    periods: int = 260,
    payload_overrides: dict[str, object] | None = None,
    remove_action_row: bool = False,
    late_action_as_of: bool = False,
) -> tuple[SignedCovarianceEvidenceProvider, dict[str, Path | datetime | date]]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    index = pd.bdate_range("2025-01-02", periods=periods, name="Date")
    values = np.arange(periods, dtype=float)[:, None] * 0.07
    execution = pd.DataFrame(
        values + np.array([[100.0, 110.0, 120.0, 130.0]]),
        index=index,
        columns=_SYMBOLS,
    )
    execution.loc[index[-20]:, "BBB"] /= 2.0
    execution_raw = execution.to_csv(
        index=True,
        float_format="%.8f",
        lineterminator="\n",
    ).encode("utf-8")
    execution_path = tmp_path / "execution-window-vwap.csv"
    execution_path.write_bytes(execution_raw)

    rows: list[dict[str, object]] = []
    ny = ZoneInfo("America/New_York")
    for session in index:
        for symbol in _SYMBOLS:
            # Even one microsecond after 09:30:00 is unavailable to the decision.
            as_of_clock = time(9, 30, 0, 1) if late_action_as_of else time(9, 30)
            as_of = datetime.combine(session.date(), as_of_clock, tzinfo=ny)
            rows.append(
                {
                    "Date": session.date().isoformat(),
                    "Asset": symbol,
                    "AsOfTimestamp": as_of.isoformat(),
                    "SplitRatio": (
                        2.0 if session == index[-20] and symbol == "BBB" else 1.0
                    ),
                    "CashDistributionPerPreActionShare": (
                        0.35 if session == index[-20] and symbol == "BBB" else 0.0
                    ),
                }
            )
    actions = pd.DataFrame(rows)
    if remove_action_row:
        actions = actions.iloc[:-1].copy()
    actions_raw = actions.to_csv(index=False, lineterminator="\n").encode("utf-8")
    actions_path = tmp_path / "corporate-actions.csv"
    actions_path.write_bytes(actions_raw)

    latest_session = index[-1].date()
    next_session = (pd.Timestamp(latest_session) + pd.offsets.BDay(1)).date()
    issued = datetime.combine(latest_session, time(10, 0), tzinfo=ny).astimezone(
        timezone.utc
    )
    next_endpoint = datetime.combine(next_session, time(9, 35), tzinfo=ny).astimezone(
        timezone.utc
    )
    expires = max(issued + timedelta(days=2), next_endpoint + timedelta(hours=1))
    payload: dict[str, object] = {
        "schema_version": COVARIANCE_EVIDENCE_SCHEMA_VERSION,
        "purpose": COVARIANCE_EVIDENCE_PURPOSE,
        "snapshot_id": "covariance-snapshot-2026-0001",
        "provider_id": "vendor-feed-2026",
        "venue_id": "consolidated-us-equities",
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "timezone": SEALED_INTERVAL_TIMEZONE,
        "decision_cutoff": SEALED_DECISION_INFORMATION_CUTOFF,
        "execution_window_start": "09:30:00",
        "execution_window_end": "09:35:00",
        "execution_price_definition": SEALED_EXECUTION_PRICE_DEFINITION,
        "execution_price_row_label": SEALED_EXECUTION_PRICE_ROW_LABEL,
        "return_semantics": COVARIANCE_RETURN_SEMANTICS,
        "return_row_label": SEALED_RETURN_ROW_LABEL,
        "corporate_action_split_definition": (
            SEALED_CORPORATE_ACTION_SPLIT_DEFINITION
        ),
        "corporate_action_cash_definition": SEALED_CORPORATE_ACTION_CASH_DEFINITION,
        "corporate_action_as_of_cutoff": SEALED_CORPORATE_ACTION_AS_OF_CUTOFF,
        "first_session": index[0].date().isoformat(),
        "latest_session": latest_session.isoformat(),
        "next_session": next_session.isoformat(),
        "observation_count": periods,
        "symbols": list(_SYMBOLS),
        "execution_prices_sha256": sha256_bytes(execution_raw),
        "corporate_actions_sha256": sha256_bytes(actions_raw),
    }
    payload.update(payload_overrides or {})
    envelope = {
        "payload": payload,
        "signature": {
            "algorithm": "RSASSA-PKCS1-v1_5-SHA256",
            "key_id": "covariance-key-2026",
            "value": _sign(payload),
        },
    }
    envelope_path = tmp_path / "covariance-envelope.json"
    envelope_path.write_bytes(canonical_json(envelope))
    registry_path, registry_hash = _registry(tmp_path)
    provider = SignedCovarianceEvidenceProvider(
        envelope_path=envelope_path,
        execution_prices_path=execution_path,
        corporate_actions_path=actions_path,
        public_keys_path=registry_path,
        public_keys_sha256=registry_hash,
        provider_id="vendor-feed-2026",
        venue_id="consolidated-us-equities",
        max_data_age_days=3,
    )
    return provider, {
        "envelope": envelope_path,
        "execution": execution_path,
        "actions": actions_path,
        "registry": registry_path,
        "issued": issued,
        "expires": expires,
        "latest_session": latest_session,
        "next_session": next_session,
    }


def _load(
    provider: SignedCovarianceEvidenceProvider,
    context: dict[str, Path | datetime | date],
    *,
    symbols: tuple[str, ...] = _SYMBOLS,
    history_bars: int = 253,
    latest_allowed_date: date | None = None,
):
    issued = context["issued"]
    latest = context["latest_session"]
    assert isinstance(issued, datetime)
    assert isinstance(latest, date)
    return provider.load(
        symbols,
        history_bars,
        latest_allowed_date or latest,
        now=issued + timedelta(hours=1),
    )


def test_valid_signed_snapshot_loads_exact_pit_panels_and_provenance(
    tmp_path: Path,
) -> None:
    provider, context = _snapshot(tmp_path)
    evidence_files = {
        name: path.read_bytes()
        for name in ("envelope", "execution", "actions", "registry")
        if isinstance((path := context[name]), Path)
    }

    evidence = _load(provider, context)

    assert evidence.execution_prices.shape == (253, 4)
    assert evidence.execution_prices.index.equals(evidence.split_ratios.index)
    assert evidence.execution_prices.columns.equals(evidence.cash_distributions.columns)
    assert np.isfinite(evidence.execution_prices.to_numpy()).all()
    assert float(evidence.split_ratios.loc[evidence.split_ratios.index[-20], "BBB"]) == 2.0
    assert float(
        evidence.cash_distributions.loc[evidence.cash_distributions.index[-20], "BBB"]
    ) == pytest.approx(0.35)
    for field in (
        "envelope_sha256",
        "payload_sha256",
        "execution_prices_sha256",
        "corporate_actions_sha256",
        "trusted_key_registry_sha256",
        "signature_sha256",
        "corporate_action_as_of_panel_sha256",
    ):
        assert len(evidence.provenance[field]) == 64
    assert evidence.provenance["signing_key_id"] == "covariance-key-2026"
    assert evidence.provenance["return_semantics"] == COVARIANCE_RETURN_SEMANTICS
    assert evidence.provenance["provider_id"] == "vendor-feed-2026"
    assert evidence.provenance["venue_id"] == "consolidated-us-equities"
    assert evidence.intended_execution_date == context["next_session"]
    assert evidence.provenance["next_session"] == evidence.intended_execution_date.isoformat()
    for name, before in evidence_files.items():
        path = context[name]
        assert isinstance(path, Path)
        assert path.read_bytes() == before


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"return_semantics": "daily_close_proxy"}, "return_semantics"),
        ({"provider_id": "different-vendor-2026"}, "provider_id"),
        ({"venue_id": "different-us-venue"}, "venue_id"),
        ({"symbols": ["BBB", "AAA", "CCC", "DDD"]}, "requested ordered universe"),
        ({"latest_session": "2025-12-30"}, "signed session bindings"),
        ({"next_session": "2025-12-31"}, "must follow latest_session"),
    ],
)
def test_signed_snapshot_revalidates_semantic_universe_and_session_bindings(
    tmp_path: Path,
    override: dict[str, object],
    message: str,
) -> None:
    provider, context = _snapshot(tmp_path, payload_overrides=override)

    with pytest.raises(CovarianceEvidenceError, match=message):
        _load(provider, context)


def test_exact_file_hash_and_registry_digest_are_pinned(tmp_path: Path) -> None:
    provider, context = _snapshot(tmp_path)
    execution_path = context["execution"]
    assert isinstance(execution_path, Path)
    execution_path.write_bytes(execution_path.read_bytes() + b"\n")
    with pytest.raises(CovarianceEvidenceError, match="exact file bytes"):
        _load(provider, context)

    provider, context = _snapshot(tmp_path / "registry-mismatch")
    provider = SignedCovarianceEvidenceProvider(
        envelope_path=provider.envelope_path,
        execution_prices_path=provider.execution_prices_path,
        corporate_actions_path=provider.corporate_actions_path,
        public_keys_path=provider.public_keys_path,
        public_keys_sha256="0" * 64,
        provider_id=provider.provider_id,
        venue_id=provider.venue_id,
        max_data_age_days=provider.max_data_age_days,
    )
    with pytest.raises(CovarianceEvidenceError, match="deployment-pinned digest"):
        _load(provider, context)


def test_expiry_freshness_and_minimum_history_fail_closed(tmp_path: Path) -> None:
    provider, context = _snapshot(tmp_path / "expired")
    expires = context["expires"]
    latest = context["latest_session"]
    assert isinstance(expires, datetime)
    assert isinstance(latest, date)
    with pytest.raises(CovarianceEvidenceError, match="expired"):
        provider.load(_SYMBOLS, 253, latest, now=expires)

    provider, context = _snapshot(tmp_path / "stale")
    latest = context["latest_session"]
    issued = context["issued"]
    assert isinstance(latest, date)
    assert isinstance(issued, datetime)
    with pytest.raises(CovarianceEvidenceError, match="stale"):
        provider.load(
            _SYMBOLS,
            253,
            latest + timedelta(days=4),
            now=issued + timedelta(hours=1),
        )

    provider, context = _snapshot(tmp_path / "short", periods=252)
    with pytest.raises(CovarianceEvidenceError, match="at least 253"):
        _load(provider, context)

    provider, context = _snapshot(tmp_path / "naive-now")
    latest = context["latest_session"]
    assert isinstance(latest, date)
    with pytest.raises(CovarianceEvidenceError, match="timezone-aware"):
        provider.load(_SYMBOLS, 253, latest, now=datetime(2026, 1, 1, 12, 0))

    provider, context = _snapshot(tmp_path / "expires-before-benchmark")
    next_session = context["next_session"]
    issued = context["issued"]
    assert isinstance(next_session, date)
    assert isinstance(issued, datetime)
    signed_endpoint = datetime.combine(
        next_session,
        time(9, 35),
        tzinfo=ZoneInfo("America/New_York"),
    ).astimezone(timezone.utc)
    provider, context = _snapshot(
        tmp_path / "expires-at-benchmark",
        payload_overrides={"expires_at": signed_endpoint.isoformat()},
    )
    with pytest.raises(CovarianceEvidenceError, match="beyond.*09:35"):
        _load(provider, context)


@pytest.mark.parametrize(
    ("remove_row", "late_as_of", "message"),
    [
        (True, False, "exactly one row"),
        (False, True, "after its session's 09:30"),
    ],
)
def test_corporate_actions_are_complete_and_known_by_the_decision_cutoff(
    tmp_path: Path,
    remove_row: bool,
    late_as_of: bool,
    message: str,
) -> None:
    provider, context = _snapshot(
        tmp_path,
        remove_action_row=remove_row,
        late_action_as_of=late_as_of,
    )

    with pytest.raises(CovarianceEvidenceError, match=message):
        _load(provider, context)


def test_signature_and_strict_envelope_schema_fail_closed(tmp_path: Path) -> None:
    provider, context = _snapshot(tmp_path / "signature")
    envelope_path = context["envelope"]
    assert isinstance(envelope_path, Path)
    raw = envelope_path.read_bytes()
    envelope = json.loads(raw)
    envelope["payload"]["snapshot_id"] = "covariance-snapshot-tampered"
    envelope_path.write_bytes(canonical_json(envelope))
    with pytest.raises(CovarianceEvidenceError, match="signature verification failed"):
        _load(provider, context)

    provider, context = _snapshot(tmp_path / "schema")
    envelope_path = context["envelope"]
    assert isinstance(envelope_path, Path)
    envelope = json.loads(envelope_path.read_bytes())
    envelope["unexpected"] = True
    envelope_path.write_bytes(canonical_json(envelope))
    with pytest.raises(CovarianceEvidenceError, match="exactly payload and signature"):
        _load(provider, context)


def test_config_env_paths_identities_and_registry_pin_are_deployment_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    configured = {
        "COVARIANCE_EVIDENCE_PATH": tmp_path / "envelope.json",
        "COVARIANCE_EXECUTION_PRICES_PATH": tmp_path / "vwap.csv",
        "COVARIANCE_CORPORATE_ACTIONS_PATH": tmp_path / "actions.csv",
        "COVARIANCE_GOVERNANCE_PUBLIC_KEYS_PATH": tmp_path / "keys.json",
    }
    for name, path in configured.items():
        monkeypatch.setenv(name, str(path))
    monkeypatch.setenv("COVARIANCE_GOVERNANCE_PUBLIC_KEYS_SHA256", "a" * 64)
    monkeypatch.setenv("COVARIANCE_PROVIDER_ID", "vendor-feed-2026")
    monkeypatch.setenv("COVARIANCE_VENUE_ID", "consolidated-us-equities")

    config = BotConfig.from_env(None)
    binding = bot_config_binding(config)

    assert config.covariance_evidence_path == configured[
        "COVARIANCE_EVIDENCE_PATH"
    ].resolve()
    assert config.covariance_execution_prices_path == configured[
        "COVARIANCE_EXECUTION_PRICES_PATH"
    ].resolve()
    assert config.covariance_corporate_actions_path == configured[
        "COVARIANCE_CORPORATE_ACTIONS_PATH"
    ].resolve()
    assert config.covariance_public_keys_path == configured[
        "COVARIANCE_GOVERNANCE_PUBLIC_KEYS_PATH"
    ].resolve()
    assert binding["covariance_public_keys_sha256"] == "a" * 64
    assert binding["covariance_provider_id"] == "vendor-feed-2026"
    assert binding["covariance_venue_id"] == "consolidated-us-equities"
    assert bot_config_hash(config) != bot_config_hash(
        replace(config, covariance_venue_id="different-us-venue")
    )


def test_incomplete_covariance_config_and_252_bar_boundary_are_rejected(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="configuration is incomplete"):
        BotConfig(covariance_evidence_path=tmp_path / "only-envelope.json").validate()
    with pytest.raises(ValueError, match="HISTORY_BARS must be between 253"):
        BotConfig(history_bars=252).validate()
    with pytest.raises(ValueError, match="requires all seven signed covariance"):
        BotConfig(
            broker="alpaca",
            execution_enabled=True,
            alpaca_api_key="paper-key",
            alpaca_secret_key="paper-secret",
            alpaca_account_id="paper-account-0001",
            dedicated_account=True,
            plan_authentication_key=hashlib.sha256(
                b"required-covariance-plan-key"
            ).hexdigest(),
            emergency_authentication_key=hashlib.sha256(
                b"required-covariance-emergency-key"
            ).hexdigest(),
        ).validate()


def test_alpaca_getter_returns_only_verified_evidence_and_missing_provider_blocks(
    tmp_path: Path,
) -> None:
    provider, context = _snapshot(tmp_path)
    issued = context["issued"]
    latest = context["latest_session"]
    assert isinstance(issued, datetime)
    assert isinstance(latest, date)

    class FixedNowProvider:
        @staticmethod
        def load(symbols, history_bars, latest_allowed_date):
            return provider.load(
                symbols,
                history_bars,
                latest_allowed_date,
                now=issued + timedelta(hours=1),
            )

    broker = AlpacaBroker.__new__(AlpacaBroker)
    broker._covariance_evidence_provider = FixedNowProvider()
    evidence = broker.get_governed_covariance_evidence(
        list(_SYMBOLS), 253, latest
    )

    assert isinstance(evidence, GovernedCovarianceEvidence)
    assert evidence.execution_prices.shape == (253, 4)
    assert evidence.provenance["provider_id"] == "vendor-feed-2026"
    assert evidence.intended_execution_date == context["next_session"]

    broker._covariance_evidence_provider = None
    with pytest.raises(RuntimeError, match="daily closes cannot be substituted"):
        broker.get_governed_covariance_evidence(list(_SYMBOLS), 253, latest)


def test_authenticated_covariance_anchor_rejects_signed_snapshot_rollback(
    tmp_path: Path,
) -> None:
    store = StateStore(
        tmp_path / "state.sqlite3",
        authentication_key=hashlib.sha256(b"covariance-anchor-test-key").digest(),
    )
    initial = {
        "latest_session": "2026-07-10",
        "issued_at": "2026-07-10T14:00:00+00:00",
        "snapshot_id": "snapshot-2026-07-10-a",
        "payload_sha256": "a" * 64,
    }

    assert store.anchor_covariance_evidence(initial) == initial
    assert store.anchor_covariance_evidence(initial) == initial
    assert store.get_state(StateStore.COVARIANCE_EVIDENCE_ANCHOR_KEY) == initial

    with pytest.raises(RuntimeError, match="rollback"):
        store.anchor_covariance_evidence(
            {
                **initial,
                "latest_session": "2026-07-09",
                "issued_at": "2026-07-09T14:00:00+00:00",
            }
        )
    with pytest.raises(RuntimeError, match="rollback"):
        store.anchor_covariance_evidence(
            {**initial, "issued_at": "2026-07-10T13:59:59+00:00"}
        )
    with pytest.raises(RuntimeError, match="different payload identity"):
        store.anchor_covariance_evidence(
            {
                **initial,
                "snapshot_id": "snapshot-2026-07-10-b",
                "payload_sha256": "b" * 64,
            }
        )

    revised = {
        **initial,
        "issued_at": "2026-07-10T14:01:00+00:00",
        "snapshot_id": "snapshot-2026-07-10-b",
        "payload_sha256": "b" * 64,
    }
    assert store.anchor_covariance_evidence(revised) == revised
    assert store.get_state(StateStore.COVARIANCE_EVIDENCE_ANCHOR_KEY) == revised

    unauthenticated = StateStore(tmp_path / "unauthenticated.sqlite3")
    with pytest.raises(RuntimeError, match="requires authenticated StateStore"):
        unauthenticated.anchor_covariance_evidence(initial)
