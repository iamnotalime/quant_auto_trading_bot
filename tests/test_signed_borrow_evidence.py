from __future__ import annotations

import base64
import csv
import hashlib
import io
import threading
from dataclasses import replace
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import pytest
import pandas as pd

from auto_trader.brokers.simulated import SimulatedBroker
from auto_trader.config import BotConfig
from auto_trader.engine import AutomationEngine
from auto_trader.models import (
    AccountSnapshot,
    MarketClock,
    OrderSide,
    PositionSnapshot,
    RiskDecision,
    TargetPlan,
)
from auto_trader.strategy import seal_target_plan
from auto_trader.borrow_evidence import (
    BORROW_AVAILABILITY_DEFINITION,
    BORROW_EVIDENCE_PURPOSE,
    BORROW_EVIDENCE_SCHEMA_VERSION,
    BORROW_RECALL_DEFINITION,
    BorrowEvidenceError,
    LiveBorrowPolicyError,
    SignedBorrowEvidenceProvider,
    anchor_borrow_evidence,
)
from auto_trader.store import StateStore
from quant_app.governance import (
    SEALED_BORROW_AS_OF_CUTOFF,
    SEALED_BORROW_RATE_DEFINITION,
    SEALED_INTERVAL_TIMEZONE,
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
_SESSION = date(2026, 7, 13)
_NY = ZoneInfo("America/New_York")


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
            "live-borrow-key-2026": {
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
    path = tmp_path / "borrow-public-keys.json"
    path.write_bytes(raw)
    return path, sha256_bytes(raw)


def _snapshot(
    tmp_path: Path,
    *,
    row_overrides: dict[str, dict[str, str]] | None = None,
    omit_symbol: str | None = None,
    payload_overrides: dict[str, object] | None = None,
) -> tuple[SignedBorrowEvidenceProvider, dict[str, Any]]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    now = datetime.combine(_SESSION, time(9, 31), tzinfo=_NY).astimezone(timezone.utc)
    issued = datetime.combine(_SESSION, time(9, 30, 30), tzinfo=_NY).astimezone(
        timezone.utc
    )
    expires = datetime.combine(_SESSION, time(9, 36), tzinfo=_NY).astimezone(
        timezone.utc
    )
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        [
            "Session",
            "Symbol",
            "AsOfTimestamp",
            "Available",
            "AvailableQuantity",
            "AnnualRate",
            "Recalled",
        ]
    )
    for symbol in _SYMBOLS:
        if symbol == omit_symbol:
            continue
        row = {
            "Session": _SESSION.isoformat(),
            "Symbol": symbol,
            "AsOfTimestamp": datetime.combine(
                _SESSION, time(9, 29, 45), tzinfo=_NY
            ).isoformat(),
            "Available": "true",
            "AvailableQuantity": "1000000",
            "AnnualRate": "0.015",
            "Recalled": "false",
        }
        row.update((row_overrides or {}).get(symbol, {}))
        writer.writerow(
            [
                row["Session"],
                row["Symbol"],
                row["AsOfTimestamp"],
                row["Available"],
                row["AvailableQuantity"],
                row["AnnualRate"],
                row["Recalled"],
            ]
        )
    terms_raw = buffer.getvalue().encode("utf-8")
    terms_path = tmp_path / "live-borrow-terms.csv"
    terms_path.write_bytes(terms_raw)
    payload: dict[str, object] = {
        "schema_version": BORROW_EVIDENCE_SCHEMA_VERSION,
        "purpose": BORROW_EVIDENCE_PURPOSE,
        "snapshot_id": "live-borrow-snapshot-2026-07-13-0001",
        "provider_id": "borrow-provider-2026",
        "venue_id": "consolidated-us-equities",
        "account_id": "alpaca-account-0001",
        "intended_session": _SESSION.isoformat(),
        "issued_at": issued.isoformat(),
        "expires_at": expires.isoformat(),
        "timezone": SEALED_INTERVAL_TIMEZONE,
        "decision_cutoff": SEALED_BORROW_AS_OF_CUTOFF,
        "availability_definition": BORROW_AVAILABILITY_DEFINITION,
        "annual_rate_definition": SEALED_BORROW_RATE_DEFINITION,
        "recall_definition": BORROW_RECALL_DEFINITION,
        "row_count": len(_SYMBOLS),
        "symbols": list(_SYMBOLS),
        "terms_sha256": sha256_bytes(terms_raw),
    }
    payload.update(payload_overrides or {})
    envelope = {
        "payload": payload,
        "signature": {
            "algorithm": "RSASSA-PKCS1-v1_5-SHA256",
            "key_id": "live-borrow-key-2026",
            "value": _sign(payload),
        },
    }
    envelope_path = tmp_path / "live-borrow-envelope.json"
    envelope_path.write_bytes(canonical_json(envelope))
    registry_path, registry_hash = _registry(tmp_path)
    provider = SignedBorrowEvidenceProvider(
        envelope_path=envelope_path,
        terms_path=terms_path,
        public_keys_path=registry_path,
        public_keys_sha256=registry_hash,
        provider_id="borrow-provider-2026",
        venue_id="consolidated-us-equities",
        account_id="alpaca-account-0001",
        max_term_age_seconds=300,
    )
    return provider, {
        "now": now,
        "issued": issued,
        "expires": expires,
        "envelope": envelope_path,
        "terms": terms_path,
        "registry": registry_path,
    }


def _load(provider: SignedBorrowEvidenceProvider, context: dict[str, Any]):
    return provider.load(_SYMBOLS, _SESSION, now=context["now"])


def test_valid_signed_execution_day_borrow_snapshot_is_exact_and_policy_bound(
    tmp_path: Path,
) -> None:
    provider, context = _snapshot(tmp_path)
    before = {name: context[name].read_bytes() for name in ("envelope", "terms", "registry")}

    evidence = _load(provider, context)
    evidence.require_eligible_shorts(["BBB", "DDD"], max_annual_rate=0.02)

    assert evidence.intended_session == _SESSION
    assert tuple(evidence.terms) == _SYMBOLS
    assert evidence.terms["AAA"].annual_rate == pytest.approx(0.015)
    assert evidence.terms["AAA"].available_quantity == pytest.approx(1_000_000.0)
    assert evidence.provenance["account_id"] == "alpaca-account-0001"
    assert evidence.provenance["intended_session"] == _SESSION.isoformat()
    for field in (
        "envelope_sha256",
        "payload_sha256",
        "terms_sha256",
        "symbols_sha256",
        "trusted_key_registry_sha256",
        "signature_sha256",
    ):
        assert len(evidence.provenance[field]) == 64
    for name, raw in before.items():
        assert context[name].read_bytes() == raw


@pytest.mark.parametrize(
    ("case", "message"),
    [
        ("missing", "exactly one row"),
        ("wrong_symbol", "invalid symbol|ordered universe"),
        ("post_cutoff", "after its session's 09:30"),
        ("stale", "stale for live execution"),
        ("wrong_session", "not bound to the intended session"),
        ("wrong_account", "account_id does not match"),
        ("expired", "expired"),
        ("wrong_provider", "provider_id does not match"),
        ("wrong_venue", "venue_id does not match"),
        ("reordered_universe", "ordered universe"),
        ("future_issued", "issued_at is in the future"),
        ("issued_before_term", "issued before its latest"),
        ("endpoint_expiry", "beyond the signed 09:35 endpoint"),
        ("duplicate", "duplicate symbol"),
        ("invalid_boolean", "must be exactly 'true' or 'false'"),
        ("quantity_inconsistent", "unavailable but has positive locate quantity"),
    ],
)
def test_missing_stale_wrong_symbol_post_cutoff_and_binding_fail_closed(
    tmp_path: Path,
    case: str,
    message: str,
) -> None:
    row_overrides: dict[str, dict[str, str]] = {}
    omit_symbol = None
    payload_overrides: dict[str, object] = {}
    if case == "missing":
        omit_symbol = "DDD"
    elif case == "wrong_symbol":
        row_overrides["BBB"] = {"Symbol": "bad symbol"}
    elif case == "post_cutoff":
        row_overrides["BBB"] = {
            "AsOfTimestamp": datetime.combine(
                _SESSION, time(9, 30, 0, 1), tzinfo=_NY
            ).isoformat()
        }
    elif case == "stale":
        row_overrides["BBB"] = {
            "AsOfTimestamp": datetime.combine(
                _SESSION, time(9, 25, 59), tzinfo=_NY
            ).isoformat()
        }
    elif case == "wrong_session":
        row_overrides["BBB"] = {"Session": "2026-07-10"}
    elif case == "wrong_account":
        payload_overrides["account_id"] = "different-account-0001"
    elif case == "expired":
        payload_overrides["expires_at"] = datetime.combine(
            _SESSION, time(9, 30, 59), tzinfo=_NY
        ).astimezone(timezone.utc).isoformat()
    elif case == "wrong_provider":
        payload_overrides["provider_id"] = "different-provider-2026"
    elif case == "wrong_venue":
        payload_overrides["venue_id"] = "different-us-equities"
    elif case == "reordered_universe":
        payload_overrides["symbols"] = list(reversed(_SYMBOLS))
    elif case == "future_issued":
        payload_overrides["issued_at"] = datetime.combine(
            _SESSION, time(9, 31, 6), tzinfo=_NY
        ).astimezone(timezone.utc).isoformat()
    elif case == "issued_before_term":
        payload_overrides["issued_at"] = datetime.combine(
            _SESSION, time(9, 29, 40), tzinfo=_NY
        ).astimezone(timezone.utc).isoformat()
    elif case == "endpoint_expiry":
        payload_overrides["expires_at"] = datetime.combine(
            _SESSION, time(9, 35), tzinfo=_NY
        ).astimezone(timezone.utc).isoformat()
    elif case == "duplicate":
        row_overrides["DDD"] = {"Symbol": "BBB"}
    elif case == "invalid_boolean":
        row_overrides["BBB"] = {"Available": "TRUE"}
    elif case == "quantity_inconsistent":
        row_overrides["BBB"] = {"Available": "false"}
    provider, context = _snapshot(
        tmp_path / case,
        row_overrides=row_overrides,
        omit_symbol=omit_symbol,
        payload_overrides=payload_overrides,
    )

    with pytest.raises(BorrowEvidenceError, match=message):
        _load(provider, context)


def test_signed_borrow_evidence_is_unusable_outside_exact_execution_window(
    tmp_path: Path,
) -> None:
    provider, context = _snapshot(tmp_path / "outside-window")
    endpoint = datetime.combine(
        _SESSION, time(9, 35), tzinfo=_NY
    ).astimezone(timezone.utc)

    with pytest.raises(BorrowEvidenceError, match="09:30<=time<09:35"):
        provider.load(_SYMBOLS, _SESSION, now=endpoint)


def test_exact_file_hash_signature_and_pinned_registry_fail_closed(tmp_path: Path) -> None:
    provider, context = _snapshot(tmp_path / "missing")
    provider = SignedBorrowEvidenceProvider(
        envelope_path=None,
        terms_path=provider.terms_path,
        public_keys_path=provider.public_keys_path,
        public_keys_sha256=provider.public_keys_sha256,
        provider_id=provider.provider_id,
        venue_id=provider.venue_id,
        account_id=provider.account_id,
    )
    with pytest.raises(BorrowEvidenceError, match="not configured"):
        _load(provider, context)

    provider, context = _snapshot(tmp_path / "file")
    context["terms"].write_bytes(context["terms"].read_bytes() + b"\n")
    with pytest.raises(BorrowEvidenceError, match="exact file bytes"):
        _load(provider, context)

    provider, context = _snapshot(tmp_path / "signature")
    envelope = __import__("json").loads(context["envelope"].read_bytes())
    envelope["payload"]["snapshot_id"] = "live-borrow-snapshot-tampered"
    context["envelope"].write_bytes(canonical_json(envelope))
    with pytest.raises(BorrowEvidenceError, match="signature verification failed"):
        _load(provider, context)

    provider, context = _snapshot(tmp_path / "registry")
    provider = SignedBorrowEvidenceProvider(
        envelope_path=provider.envelope_path,
        terms_path=provider.terms_path,
        public_keys_path=provider.public_keys_path,
        public_keys_sha256="0" * 64,
        provider_id=provider.provider_id,
        venue_id=provider.venue_id,
        account_id=provider.account_id,
    )
    with pytest.raises(BorrowEvidenceError, match="deployment-pinned digest"):
        _load(provider, context)


@pytest.mark.parametrize(
    ("override", "ceiling", "reason"),
    [
        (
            {"Available": "false", "AvailableQuantity": "0"},
            0.02,
            "unavailable",
        ),
        (
            {
                "Available": "false",
                "AvailableQuantity": "0",
                "Recalled": "true",
            },
            0.02,
            "recalled",
        ),
        ({"AnnualRate": "0.021"}, 0.02, "annual_rate_above_deployment_ceiling"),
    ],
)
def test_unavailable_recall_and_high_rate_short_are_explicit_policy_incidents(
    tmp_path: Path,
    override: dict[str, str],
    ceiling: float,
    reason: str,
) -> None:
    provider, context = _snapshot(
        tmp_path / reason,
        row_overrides={"BBB": override},
    )
    evidence = _load(provider, context)

    with pytest.raises(LiveBorrowPolicyError) as error:
        evidence.require_eligible_shorts(["BBB"], max_annual_rate=ceiling)

    assert error.value.violations == {"BBB": reason}


def test_signed_locate_quantity_must_cover_the_required_short(tmp_path: Path) -> None:
    provider, context = _snapshot(
        tmp_path / "quantity",
        row_overrides={"BBB": {"AvailableQuantity": "9.5"}},
    )
    evidence = _load(provider, context)

    evidence.require_eligible_shorts(
        ["BBB"],
        max_annual_rate=0.02,
        required_quantities={"BBB": 9.5},
    )
    with pytest.raises(LiveBorrowPolicyError) as error:
        evidence.require_eligible_shorts(
            ["BBB"],
            max_annual_rate=0.02,
            required_quantities={"BBB": 9.5001},
        )

    assert error.value.violations == {
        "BBB": "available_quantity_below_required_short"
    }


def test_authenticated_anchor_rejects_rollback_and_same_time_equivocation(
    tmp_path: Path,
) -> None:
    store = StateStore(
        tmp_path / "borrow-anchor.sqlite3",
        authentication_key=hashlib.sha256(b"borrow-anchor-test-key").digest(),
    )

    def provenance(session: str, issued: str, suffix: str) -> dict[str, str]:
        term_clock = datetime.combine(
            date.fromisoformat(session), time(9, 29, 45), tzinfo=_NY
        ).astimezone(timezone.utc).isoformat()
        term_clocks = {symbol: term_clock for symbol in _SYMBOLS}
        term_values = {
            symbol: hashlib.sha256(f"term-value-{symbol}".encode("ascii")).hexdigest()
            for symbol in _SYMBOLS
        }
        return {
            "intended_session": session,
            "issued_at": issued,
            "snapshot_id": f"borrow-snapshot-{suffix}",
            "payload_sha256": ("a" if suffix == "one" else "b") * 64,
            "terms_sha256": ("c" if suffix == "one" else "d") * 64,
            "symbols_sha256": "e" * 64,
            "account_id": "alpaca-account-0001",
            "earliest_term_as_of": term_clock,
            "latest_term_as_of": term_clock,
            "term_as_of_by_symbol_json": canonical_json(term_clocks).decode("utf-8"),
            "term_value_sha256_by_symbol_json": canonical_json(term_values).decode(
                "utf-8"
            ),
        }

    first = provenance("2026-07-13", "2026-07-13T13:30:30+00:00", "one")
    second = provenance("2026-07-14", "2026-07-14T13:30:30+00:00", "two")
    assert anchor_borrow_evidence(store, first)["snapshot_id"] == "borrow-snapshot-one"

    regressed = provenance(
        "2026-07-13", "2026-07-13T13:31:00+00:00", "two"
    )
    clocks = __import__("json").loads(regressed["term_as_of_by_symbol_json"])
    clocks["BBB"] = "2026-07-13T13:29:44+00:00"
    regressed["earliest_term_as_of"] = clocks["BBB"]
    regressed["term_as_of_by_symbol_json"] = canonical_json(clocks).decode("utf-8")
    with pytest.raises(BorrowEvidenceError, match="per-symbol term clocks"):
        anchor_borrow_evidence(store, regressed)

    same_clock_rewrite = provenance(
        "2026-07-13", "2026-07-13T13:31:00+00:00", "two"
    )
    rewritten_values = __import__("json").loads(
        same_clock_rewrite["term_value_sha256_by_symbol_json"]
    )
    rewritten_values["BBB"] = "f" * 64
    same_clock_rewrite["term_value_sha256_by_symbol_json"] = canonical_json(
        rewritten_values
    ).decode("utf-8")
    with pytest.raises(BorrowEvidenceError, match="same-clock term values"):
        anchor_borrow_evidence(store, same_clock_rewrite)

    assert anchor_borrow_evidence(store, second)["snapshot_id"] == "borrow-snapshot-two"
    with pytest.raises(BorrowEvidenceError, match="rollback"):
        anchor_borrow_evidence(store, first)

    equivocation = dict(second)
    equivocation["terms_sha256"] = "f" * 64
    with pytest.raises(BorrowEvidenceError, match="different identity"):
        anchor_borrow_evidence(store, equivocation)

    unauthenticated = StateStore(tmp_path / "unauthenticated.sqlite3")
    with pytest.raises(BorrowEvidenceError, match="authenticated StateStore"):
        anchor_borrow_evidence(unauthenticated, first)


def test_authenticated_anchor_concurrent_transition_cannot_overwrite_newer_evidence(
    tmp_path: Path,
) -> None:
    key = hashlib.sha256(b"borrow-anchor-concurrency-key").digest()
    path = tmp_path / "borrow-anchor-concurrent.sqlite3"
    first_store = StateStore(path, authentication_key=key)
    second_store = StateStore(path, require_existing=True, authentication_key=key)

    def provenance(issued: str, snapshot: str, clock_second: int) -> dict[str, str]:
        term_clock = datetime(
            2026, 7, 13, 13, 29, clock_second, tzinfo=timezone.utc
        ).isoformat()
        clocks = {symbol: term_clock for symbol in _SYMBOLS}
        values = {
            symbol: hashlib.sha256(f"stable-{symbol}".encode("ascii")).hexdigest()
            for symbol in _SYMBOLS
        }
        return {
            "intended_session": "2026-07-13",
            "issued_at": issued,
            "snapshot_id": snapshot,
            "payload_sha256": hashlib.sha256(snapshot.encode("ascii")).hexdigest(),
            "terms_sha256": hashlib.sha256((snapshot + "-terms").encode("ascii")).hexdigest(),
            "symbols_sha256": "e" * 64,
            "account_id": "alpaca-account-0001",
            "earliest_term_as_of": term_clock,
            "latest_term_as_of": term_clock,
            "term_as_of_by_symbol_json": canonical_json(clocks).decode("utf-8"),
            "term_value_sha256_by_symbol_json": canonical_json(values).decode("utf-8"),
        }

    older = provenance(
        "2026-07-13T13:30:30+00:00", "borrow-snapshot-concurrent-old", 40
    )
    newer = provenance(
        "2026-07-13T13:31:00+00:00", "borrow-snapshot-concurrent-new", 50
    )
    barrier = threading.Barrier(2)
    failures: list[Exception] = []

    def publish(store: StateStore, candidate: dict[str, str]) -> None:
        barrier.wait(timeout=5.0)
        try:
            anchor_borrow_evidence(store, candidate)
        except BorrowEvidenceError as exc:
            failures.append(exc)

    old_thread = threading.Thread(target=publish, args=(first_store, older))
    new_thread = threading.Thread(target=publish, args=(second_store, newer))
    old_thread.start()
    new_thread.start()
    old_thread.join(timeout=10.0)
    new_thread.join(timeout=10.0)

    assert not old_thread.is_alive()
    assert not new_thread.is_alive()
    assert all("rollback" in str(error) for error in failures)
    anchored = first_store.get_state("live_borrow_evidence_anchor")
    assert anchored["snapshot_id"] == "borrow-snapshot-concurrent-new"


class _SignedBorrowBroker:
    def __init__(
        self,
        provider: SignedBorrowEvidenceProvider,
        now: datetime,
    ) -> None:
        self.provider = provider
        self.now = now
        self.loads = 0

    def get_governed_borrow_evidence(
        self,
        symbols: list[str],
        intended_session: date,
        *,
        now: datetime | None = None,
    ):
        self.loads += 1
        return self.provider.load(symbols, intended_session, now=now or self.now)


def _engine_for_signed_borrow(
    tmp_path: Path,
    provider: SignedBorrowEvidenceProvider,
    now: datetime,
) -> tuple[AutomationEngine, _SignedBorrowBroker, TargetPlan]:
    config = BotConfig(
        symbols=_SYMBOLS,
        max_live_annual_borrow_rate=0.02,
        database_path=tmp_path / "engine.sqlite3",
        kill_switch_path=tmp_path / "KILL_SWITCH",
        emergency_journal_path=tmp_path / "EMERGENCY_JOURNAL.json",
    )
    store = StateStore(
        config.database_path,
        authentication_key=config.plan_authentication_key_bytes,
    )
    broker = _SignedBorrowBroker(provider, now)
    engine = AutomationEngine(config, broker, store)
    engine._wall_clock_provider = lambda: now
    plan = TargetPlan(
        plan_id="authenticated-live-borrow-plan",
        as_of=_SESSION - timedelta(days=1),
        created_at=now - timedelta(hours=12),
        regime="neutral",
        regime_multiplier=1.0,
        desired_gross=0.2,
        forecast_volatility=0.1,
        target_weights={"AAA": 0.1, "BBB": -0.1, "CCC": 0.1, "DDD": -0.1},
        metadata={"assets": list(_SYMBOLS)},
    )
    return engine, broker, plan


def test_engine_authenticates_plan_and_current_shorts_and_persists_provenance(
    tmp_path: Path,
) -> None:
    provider, context = _snapshot(tmp_path / "engine-success")
    engine, broker, plan = _engine_for_signed_borrow(
        tmp_path / "engine-success", provider, context["now"]
    )
    positions = {
        "CCC": PositionSnapshot("CCC", -5.0, -500.0, 100.0),
    }

    evidence = engine._revalidate_governed_borrow_evidence(
        plan,
        intended_session=_SESSION,
        current_positions=positions,
        projected_short_symbols=("AAA",),
        projected_short_quantities={"AAA": 10.0},
        clock_timestamp=context["now"],
        stage="hostile_test_boundary",
    )

    assert broker.loads == 1
    assert evidence.provenance["snapshot_id"].startswith("live-borrow-snapshot")
    active = engine.store.get_state("active_live_borrow_execution")
    assert active["short_symbols"] == ["AAA", "BBB", "CCC", "DDD"]
    assert active["required_short_quantities"] == {"AAA": 10.0, "CCC": 5.0}
    assert active["provenance"]["terms_sha256"] == evidence.provenance["terms_sha256"]
    events = engine.store.recent_events(5)
    assert any(event["code"] == "LIVE_BORROW_EVIDENCE_REVALIDATED" for event in events)
    engine.store.verify_critical_integrity()


def test_engine_borrow_violation_latches_halt_and_uses_evidence_independent_emergency(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, context = _snapshot(
        tmp_path / "engine-recall",
        row_overrides={
            "BBB": {
                "AsOfTimestamp": datetime.combine(
                    _SESSION, time(9, 29, 55), tzinfo=_NY
                ).isoformat(),
                "Available": "false",
                "AvailableQuantity": "0",
                "Recalled": "true",
            }
        },
    )
    engine, broker, plan = _engine_for_signed_borrow(
        tmp_path / "engine-recall", provider, context["now"]
    )
    emergency_calls: list[tuple[str, bool]] = []
    monkeypatch.setattr(
        engine,
        "emergency_flatten",
        lambda reason, persist_halt=True: emergency_calls.append(
            (reason, persist_halt)
        )
        or [],
    )

    with pytest.raises(RuntimeError, match="emergency exposure reduction completed"):
        engine._enforce_governed_borrow_or_emergency_reduce(
            plan,
            intended_session=_SESSION,
            current_positions={},
            clock_timestamp=context["now"],
            stage="before_first_routine_mutation",
        )

    assert broker.loads == 1
    assert emergency_calls == [("authenticated_live_borrow_policy_incident", True)]
    halt = engine.store.halt_state()
    assert halt is not None and halt["active"] is True and halt["flatten"] is True
    assert engine._routine_emergency_triggered is True
    incident = engine.store.get_state("active_live_borrow_execution")
    assert incident["authorization_status"] == "rejected"
    assert incident["policy_violations"] == {"BBB": "recalled"}
    assert incident["verified_provenance"]["terms_sha256"] == sha256_bytes(
        context["terms"].read_bytes()
    )


def test_live_borrow_freshness_rejects_broker_process_clock_divergence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, context = _snapshot(tmp_path / "clock-skew")
    engine, broker, plan = _engine_for_signed_borrow(
        tmp_path / "clock-skew", provider, context["now"]
    )
    engine._wall_clock_provider = lambda: context["now"] + timedelta(seconds=6)
    emergency_calls: list[str] = []
    monkeypatch.setattr(
        engine,
        "emergency_flatten",
        lambda reason, persist_halt=True: emergency_calls.append(reason) or [],
    )

    with pytest.raises(RuntimeError, match="emergency exposure reduction completed"):
        engine._enforce_governed_borrow_or_emergency_reduce(
            plan,
            intended_session=_SESSION,
            current_positions={},
            clock_timestamp=context["now"],
            stage="clock_skew",
        )

    assert broker.loads == 0
    assert emergency_calls == ["authenticated_live_borrow_policy_incident"]
    incident = engine.store.get_state("active_live_borrow_execution")
    assert incident["verified_provenance"] is None
    assert "clock skew" in incident["error"]


def test_terms_that_age_out_during_verification_trigger_emergency_before_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, context = _snapshot(tmp_path / "ages-out")
    provider = replace(provider, max_term_age_seconds=76)
    engine, broker, plan = _engine_for_signed_borrow(
        tmp_path / "ages-out", provider, context["now"]
    )
    engine.config = replace(engine.config, borrow_max_term_age_seconds=76)
    emergency_calls: list[str] = []
    monkeypatch.setattr(
        engine,
        "emergency_flatten",
        lambda reason, persist_halt=True: emergency_calls.append(reason) or [],
    )

    evidence = engine._enforce_governed_borrow_or_emergency_reduce(
        plan,
        intended_session=_SESSION,
        current_positions={},
        clock_timestamp=context["now"],
        stage="before_verification_work",
    )
    after_verification = context["now"] + timedelta(seconds=2)
    engine._wall_clock_provider = lambda: after_verification

    with pytest.raises(RuntimeError, match="emergency exposure reduction completed"):
        engine._enforce_governed_borrow_freshness_or_emergency_reduce(
            plan,
            evidence,
            intended_session=_SESSION,
            clock_timestamp=after_verification,
            stage="post_verification_freshness",
        )

    assert broker.loads == 1
    assert emergency_calls == ["authenticated_live_borrow_policy_incident"]
    incident = engine.store.get_state("active_live_borrow_execution")
    assert incident["stage"] == "post_verification_freshness"
    assert "aged out" in incident["error"]
    assert incident["verified_provenance"] == dict(evidence.provenance)


def test_actual_emergency_reconciliation_never_requires_borrow_provider(
    tmp_path: Path,
) -> None:
    dates = pd.bdate_range("2026-07-09", periods=3)
    prices = pd.DataFrame(
        {symbol: [100.0, 100.0, 100.0] for symbol in _SYMBOLS},
        index=dates,
    )
    config = BotConfig(
        symbols=_SYMBOLS,
        broker="simulated",
        execution_enabled=True,
        dedicated_account=True,
        database_path=tmp_path / "emergency.sqlite3",
        kill_switch_path=tmp_path / "KILL_SWITCH",
        emergency_journal_path=tmp_path / "EMERGENCY_JOURNAL.json",
        simulated_prices_path=tmp_path / "unused.csv",
        simulated_state_path=tmp_path / "simulated.json",
        simulated_market_always_open=True,
    )
    broker = SimulatedBroker(
        prices_path=config.simulated_prices_path,
        state_path=config.simulated_state_path,
        starting_cash=100_000.0,
        market_always_open=True,
        prices=prices,
    )
    store = StateStore(
        config.database_path,
        authentication_key=config.plan_authentication_key_bytes,
    )
    engine = AutomationEngine(config, broker, store)
    engine._wall_clock_provider = lambda: datetime.combine(
        _SESSION, time(9, 31), tzinfo=_NY
    ).astimezone(timezone.utc)
    context_now = datetime.combine(
        _SESSION, time(8, 0), tzinfo=_NY
    ).astimezone(timezone.utc)
    plan = TargetPlan(
        plan_id="emergency-without-borrow-provider",
        as_of=_SESSION - timedelta(days=1),
        created_at=context_now,
        regime="neutral",
        regime_multiplier=1.0,
        desired_gross=0.1,
        forecast_volatility=0.1,
        target_weights={"BBB": -0.1},
        metadata={"assets": list(_SYMBOLS)},
    )
    broker.submit_market_order("BBB", 5.0, OrderSide.SELL, "manual-short")
    assert broker.get_positions()["BBB"].qty == pytest.approx(-5.0)

    with pytest.raises(RuntimeError, match="emergency exposure reduction completed"):
        engine._enforce_governed_borrow_or_emergency_reduce(
            plan,
            intended_session=_SESSION,
            current_positions=broker.get_positions(),
            clock_timestamp=engine._wall_clock_provider(),
            stage="provider_absent",
        )

    assert context_now.tzinfo is not None
    assert broker.get_positions() == {}
    assert store.halt_state()["flatten"] is True


def test_final_child_boundaries_reload_terms_and_observe_new_recall(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid_provider, context = _snapshot(tmp_path / "child-valid")
    recalled_provider, _ = _snapshot(
        tmp_path / "child-recalled",
        row_overrides={
            "BBB": {
                "AsOfTimestamp": datetime.combine(
                    _SESSION, time(9, 29, 55), tzinfo=_NY
                ).isoformat(),
                "Available": "false",
                "AvailableQuantity": "0",
                "Recalled": "true",
            }
        },
        payload_overrides={
            "snapshot_id": "live-borrow-snapshot-2026-07-13-recall",
            "issued_at": datetime.combine(
                _SESSION, time(9, 30, 40), tzinfo=_NY
            ).astimezone(timezone.utc).isoformat(),
        },
    )
    engine, broker, plan = _engine_for_signed_borrow(
        tmp_path / "child-engine", valid_provider, context["now"]
    )
    emergency_calls: list[str] = []
    monkeypatch.setattr(
        engine,
        "emergency_flatten",
        lambda reason, persist_halt=True: emergency_calls.append(reason) or [],
    )

    engine._enforce_governed_borrow_or_emergency_reduce(
        plan,
        intended_session=_SESSION,
        current_positions={},
        projected_short_symbols=("BBB",),
        clock_timestamp=context["now"],
        stage="final_child:AAA:buy",
    )
    broker.provider = recalled_provider

    with pytest.raises(RuntimeError, match="emergency exposure reduction completed"):
        engine._enforce_governed_borrow_or_emergency_reduce(
            plan,
            intended_session=_SESSION,
            current_positions={},
            projected_short_symbols=("BBB",),
            clock_timestamp=context["now"],
            stage="final_child:BBB:sell",
        )

    incident = engine.store.get_state("active_live_borrow_execution")
    assert incident["stage"] == "final_child:BBB:sell"
    assert incident["authorization_status"] == "rejected"
    assert incident["policy_violations"] == {"BBB": "recalled"}
    assert incident["verified_provenance"]["snapshot_id"].endswith("recall")

    # Once the adverse signed snapshot has been seen, replaying the older favorable
    # snapshot cannot authorize a resumed process.
    broker.provider = valid_provider
    with pytest.raises(RuntimeError, match="emergency exposure reduction completed"):
        engine._enforce_governed_borrow_or_emergency_reduce(
            plan,
            intended_session=_SESSION,
            current_positions={},
            projected_short_symbols=("BBB",),
            clock_timestamp=context["now"],
            stage="final_child:BBB:replay",
        )

    assert broker.loads == 3
    assert emergency_calls == [
        "authenticated_live_borrow_policy_incident",
        "authenticated_live_borrow_policy_incident",
    ]


def test_governed_alpaca_requires_complete_borrow_trust_and_sealed_rate_ceiling(
    tmp_path: Path,
) -> None:
    config = BotConfig(
        broker="alpaca",
        execution_enabled=True,
        alpaca_paper=True,
        alpaca_api_key="paper-key",
        alpaca_secret_key="paper-secret",
        alpaca_account_id="alpaca-account-0001",
        dedicated_account=True,
        plan_authentication_key=hashlib.sha256(
            b"signed-borrow-config-plan-key"
        ).hexdigest(),
        emergency_authentication_key=hashlib.sha256(
            b"signed-borrow-config-emergency-key"
        ).hexdigest(),
        covariance_evidence_path=tmp_path / "covariance-envelope.json",
        covariance_execution_prices_path=tmp_path / "covariance-vwap.csv",
        covariance_corporate_actions_path=tmp_path / "covariance-actions.csv",
        covariance_public_keys_path=tmp_path / "covariance-keys.json",
        covariance_public_keys_sha256="a" * 64,
        covariance_provider_id="covariance-provider-2026",
        covariance_venue_id="consolidated-us-equities",
        borrow_evidence_path=tmp_path / "borrow-envelope.json",
        borrow_terms_path=tmp_path / "borrow-terms.csv",
        borrow_public_keys_path=tmp_path / "borrow-keys.json",
        borrow_public_keys_sha256="b" * 64,
        borrow_provider_id="borrow-provider-2026",
        borrow_venue_id="consolidated-us-equities",
        max_live_annual_borrow_rate=0.02,
        database_path=tmp_path / "state.sqlite3",
        log_path=tmp_path / "bot.log",
        kill_switch_path=tmp_path / "KILL_SWITCH",
        process_lock_path=tmp_path / "process.lock",
        operation_lock_path=tmp_path / "operation.lock",
        kill_switch_ack_path=tmp_path / "KILL_SWITCH.ack.json",
        daemon_health_path=tmp_path / "health.json",
        emergency_journal_path=tmp_path / "emergency.json",
        simulated_state_path=tmp_path / "simulated.json",
    )
    config.validate()

    with pytest.raises(ValueError, match="live-borrow evidence configuration is incomplete"):
        replace(config, borrow_terms_path=None).validate()
    with pytest.raises(ValueError, match="cannot exceed the annual short-borrow rate"):
        replace(config, max_live_annual_borrow_rate=0.0201).validate()


def test_missing_borrow_evidence_halts_before_first_routine_broker_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pre-cancel check is functional, not merely a provider unit test."""

    symbols = tuple(f"S{index:02d}" for index in range(20))
    session = date(2026, 7, 13)
    clock_timestamp = datetime.combine(
        session,
        time(9, 31),
        tzinfo=ZoneInfo("America/New_York"),
    ).astimezone(timezone.utc)
    events: list[str] = []

    class ReadOnlyUntilBorrowBroker:
        def get_market_clock(self) -> MarketClock:
            return MarketClock(
                timestamp=clock_timestamp,
                is_open=True,
                next_open=clock_timestamp,
                next_close=clock_timestamp + timedelta(hours=6),
            )

        def get_account(self) -> AccountSnapshot:
            return AccountSnapshot(
                timestamp=clock_timestamp,
                equity=100_000.0,
                cash=100_000.0,
                buying_power=200_000.0,
                last_equity=100_000.0,
                external_cash_activities=(),
            )

        @staticmethod
        def get_positions() -> dict[str, PositionSnapshot]:
            return {}

        @staticmethod
        def get_asset_info(_symbols):
            return {}

        @staticmethod
        def list_open_orders(_symbols=None):
            return []

        def get_governed_borrow_evidence(
            self,
            _symbols,
            _intended_session,
            *,
            now=None,
        ):
            events.append("borrow_check")
            return None

        def cancel_orders_and_wait(self, *_args, **_kwargs):
            events.append("routine_cancel")
            raise AssertionError(
                "routine cancellation must not precede live-borrow authorization"
            )

    config = BotConfig(
        broker="alpaca",
        execution_enabled=True,
        symbols=symbols,
        minimum_assets=20,
        dedicated_account=True,
        database_path=tmp_path / "pre-cancel.sqlite3",
        kill_switch_path=tmp_path / "KILL_SWITCH",
        emergency_journal_path=tmp_path / "EMERGENCY_JOURNAL.json",
    )
    store = StateStore(
        config.database_path,
        authentication_key=config.plan_authentication_key_bytes,
    )
    broker = ReadOnlyUntilBorrowBroker()
    engine = AutomationEngine(config, broker, store)
    engine._wall_clock_provider = lambda: clock_timestamp
    plan = seal_target_plan(
        TargetPlan(
            plan_id="",
            as_of=session - timedelta(days=3),
            created_at=clock_timestamp - timedelta(hours=12),
            regime="neutral",
            regime_multiplier=1.0,
            desired_gross=0.02,
            forecast_volatility=0.1,
            target_weights={
                symbol: (-0.01 if index == 1 else 0.01 if index == 0 else 0.0)
                for index, symbol in enumerate(symbols)
            },
            metadata={"assets": list(symbols)},
        ),
        engine._current_plan_binding(),
        config.plan_authentication_key_bytes,
    )
    assert store.save_plan(plan)

    monkeypatch.setattr(
        engine,
        "_governed_plan_contract",
        lambda _plan: (session, {}, list(symbols)),
    )
    monkeypatch.setattr(
        engine,
        "_revalidate_governed_covariance_evidence",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        engine,
        "_evaluate_risk",
        lambda *_args, **_kwargs: RiskDecision(
            True, False, False, "safe", 0.0, 0.0, 0.0
        ),
    )
    monkeypatch.setattr(
        engine,
        "_execution_prices",
        lambda requested, _positions, **_kwargs: {
            symbol: 100.0 for symbol in requested
        },
    )
    monkeypatch.setattr(
        engine,
        "_target_quantities",
        lambda *_args, **_kwargs: {
            symbol: (-10.0 if index == 1 else 0.0)
            for index, symbol in enumerate(symbols)
        },
    )
    monkeypatch.setattr(
        engine,
        "_build_order_intents",
        lambda *_args, **_kwargs: ([], []),
    )
    monkeypatch.setattr(
        engine,
        "_validate_projected_portfolio",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        engine,
        "emergency_flatten",
        lambda reason, persist_halt=True: events.append(
            f"emergency:{reason}:{persist_halt}"
        )
        or [],
    )

    with pytest.raises(RuntimeError, match="emergency exposure reduction completed"):
        engine.execute_latest_plan()

    assert events == [
        "borrow_check",
        "emergency:authenticated_live_borrow_policy_incident:True",
    ]
    assert store.get_plan(plan.plan_id).status == "halted"
    halt = store.halt_state()
    assert halt is not None and halt["active"] is True and halt["flatten"] is True
