from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import pytest

from quant_app.governance import (
    SEALED_BORROW_AS_OF_CUTOFF,
    SEALED_BORROW_RATE_DEFINITION,
    SEALED_CORPORATE_ACTION_AS_OF_CUTOFF,
    SEALED_CORPORATE_ACTION_CASH_DEFINITION,
    SEALED_CORPORATE_ACTION_SPLIT_DEFINITION,
    SEALED_DECISION_INFORMATION_CUTOFF,
    SEALED_EXECUTION_PRICE_DEFINITION,
    SEALED_EXECUTION_PRICE_ROW_LABEL,
    SEALED_INTERVAL_TIMEZONE,
    SEALED_LIQUIDITY_DEFINITION,
    SEALED_LIQUIDITY_WINDOW,
    SEALED_MANIFEST_PURPOSE,
    SEALED_MANIFEST_SCHEMA_VERSION,
    SEALED_RETURN_INTERVAL,
    SEALED_RETURN_ROW_LABEL,
    SEALED_WORM_RECEIPT_PURPOSE,
    canonical_json,
    certification_context_hash,
    certification_payload_is_current,
    load_factor_return_csv,
    load_trusted_key_registry,
    research_runtime_identity,
    sha256_bytes,
    verify_sealed_manifest,
)


# Test-only RSA key material. It has no relationship to any deployment key.
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


def _sign(payload: dict[str, object]) -> str:
    size = (_RSA_N.bit_length() + 7) // 8
    digest_info = _DIGEST_INFO_PREFIX + hashlib.sha256(canonical_json(payload)).digest()
    encoded = b"\x00\x01" + b"\xff" * (size - len(digest_info) - 3) + b"\x00" + digest_info
    signature = pow(int.from_bytes(encoded, "big"), _RSA_D, _RSA_N).to_bytes(size, "big")
    return base64.b64encode(signature).decode("ascii")


def _registry(tmp_path: Path):
    modulus = _RSA_N.to_bytes((_RSA_N.bit_length() + 7) // 8, "big")
    document = {
        "schema_version": 1,
        "keys": {
            "research-key-2026": {
                "algorithm": "RSASSA-PKCS1-v1_5-SHA256",
                "status": "active",
                "modulus_base64url": base64.urlsafe_b64encode(modulus)
                .decode("ascii")
                .rstrip("="),
                "exponent": 65537,
            },
            "worm-anchor-key-2026": {
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
    path = tmp_path / "trusted-keys.json"
    path.write_bytes(raw)
    return load_trusted_key_registry(path, sha256_bytes(raw))


def _signed_anchor_receipt() -> bytes:
    payload = {
        "schema_version": 1,
        "purpose": SEALED_WORM_RECEIPT_PURPOSE,
        "provider": "governance-authority",
        "record_id": "anchor-record-0001",
        "committed_at": "2026-06-30T23:59:00Z",
        "experiment_id": "experiment-2026-0001",
        "combined_data_sha256": "d" * 64,
        "research_specification_sha256": "e" * 64,
        "research_ledger_id": "123e4567-e89b-12d3-a456-426614174000",
        "research_ledger_preclaim_sequence": 0,
        "research_ledger_preclaim_head_sha256": "0" * 64,
        "research_ledger_prior_effective_trials": 0,
        "planned_effective_trials": 25,
    }
    return canonical_json(
        {
            "payload": payload,
            "signature": {
                "algorithm": "RSASSA-PKCS1-v1_5-SHA256",
                "key_id": "worm-anchor-key-2026",
                "value": _sign(payload),
            },
        }
    )


def _signed_manifest(receipt: bytes) -> tuple[bytes, dict[str, object]]:
    payload: dict[str, object] = {
        "schema_version": SEALED_MANIFEST_SCHEMA_VERSION,
        "purpose": SEALED_MANIFEST_PURPOSE,
        "experiment_id": "experiment-2026-0001",
        "data_family_id": "vendor-snapshot-family-01",
        "strategy_family_id": "market-neutral-family-01",
        "overlap_group_ids": ["us-equities-2020-2026", "vendor-release-0042"],
        "issued_at": "2026-07-01T00:00:00Z",
        "expires_at": "2027-07-01T00:00:00Z",
        "close_data_sha256": "a" * 64,
        "execution_data_sha256": "b" * 64,
        "factor_data_sha256": "c" * 64,
        "execution_window_dollar_volume_data_sha256": "1" * 64,
        "corporate_action_data_sha256": "3" * 64,
        "borrow_data_sha256": "4" * 64,
        "exchange_calendar_sha256": "2" * 64,
        "market_factor_column": "MKT",
        "combined_data_sha256": "d" * 64,
        "oos_start": "2023-01-03T00:00:00",
        "research_specification_sha256": "e" * 64,
        "research_software_sha256": "f" * 64,
        "research_ledger_id": "123e4567-e89b-12d3-a456-426614174000",
        "research_ledger_preclaim_sequence": 0,
        "research_ledger_preclaim_head_sha256": "0" * 64,
        "research_ledger_prior_effective_trials": 0,
        "planned_effective_trials": 25,
        "interval_provenance": {
            "timezone": SEALED_INTERVAL_TIMEZONE,
            "strategy_return_interval": SEALED_RETURN_INTERVAL,
            "strategy_return_row_label": SEALED_RETURN_ROW_LABEL,
            "factor_return_interval": SEALED_RETURN_INTERVAL,
            "factor_return_row_label": SEALED_RETURN_ROW_LABEL,
            "execution_price_definition": SEALED_EXECUTION_PRICE_DEFINITION,
            "execution_price_row_label": SEALED_EXECUTION_PRICE_ROW_LABEL,
            "decision_information_cutoff": SEALED_DECISION_INFORMATION_CUTOFF,
            "execution_venue_id": "consolidated-us-equities",
            "execution_vendor_snapshot_id": "execution-snapshot-0001",
            "factor_vendor_snapshot_id": "factor-snapshot-0001",
            "exchange_calendar_id": "xnys-official-sessions",
            "exchange_calendar_vendor_snapshot_id": "calendar-snapshot-0001",
            "execution_liquidity_window": SEALED_LIQUIDITY_WINDOW,
            "execution_liquidity_definition": SEALED_LIQUIDITY_DEFINITION,
            "execution_liquidity_row_label": SEALED_EXECUTION_PRICE_ROW_LABEL,
            "execution_liquidity_vendor_snapshot_id": "liquidity-snapshot-0001",
            "corporate_action_interval": SEALED_RETURN_INTERVAL,
            "corporate_action_split_definition": (
                SEALED_CORPORATE_ACTION_SPLIT_DEFINITION
            ),
            "corporate_action_cash_definition": (
                SEALED_CORPORATE_ACTION_CASH_DEFINITION
            ),
            "corporate_action_as_of_cutoff": SEALED_CORPORATE_ACTION_AS_OF_CUTOFF,
            "corporate_action_vendor_snapshot_id": "actions-snapshot-0001",
            "borrow_as_of_cutoff": SEALED_BORROW_AS_OF_CUTOFF,
            "borrow_rate_definition": SEALED_BORROW_RATE_DEFINITION,
            "borrow_vendor_snapshot_id": "borrow-snapshot-0001",
        },
        "anchor": {
            "provider": "governance-authority",
            "record_id": "anchor-record-0001",
            "committed_at": "2026-06-30T23:59:00Z",
            "receipt_sha256": sha256_bytes(receipt),
        },
    }
    envelope = {
        "payload": payload,
        "signature": {
            "algorithm": "RSASSA-PKCS1-v1_5-SHA256",
            "key_id": "research-key-2026",
            "value": _sign(payload),
        },
    }
    return canonical_json(envelope), payload


def _verify(manifest: bytes, receipt: bytes, registry):
    return verify_sealed_manifest(
        manifest,
        receipt,
        registry,
        expected_close_data_hash="a" * 64,
        expected_execution_data_hash="b" * 64,
        expected_factor_data_hash="c" * 64,
        expected_execution_window_dollar_volume_hash="1" * 64,
        expected_corporate_action_data_hash="3" * 64,
        expected_borrow_data_hash="4" * 64,
        expected_exchange_calendar_hash="2" * 64,
        available_factor_columns=("MKT", "VALUE", "MOMENTUM"),
        expected_combined_data_hash="d" * 64,
        expected_oos_start="2023-01-03T00:00:00",
        expected_specification_hash="e" * 64,
        expected_research_software_hash="f" * 64,
        expected_research_ledger_id="123e4567-e89b-12d3-a456-426614174000",
        expected_research_ledger_preclaim_sequence=0,
        expected_research_ledger_preclaim_head_hash="0" * 64,
        expected_research_ledger_prior_effective_trials=0,
        expected_planned_effective_trials=25,
        now=datetime(2026, 7, 12, tzinfo=timezone.utc),
    )


def test_signed_manifest_binds_exact_run_factor_data_and_anchor(tmp_path: Path) -> None:
    receipt = _signed_anchor_receipt()
    manifest, _ = _signed_manifest(receipt)
    verification = _verify(manifest, receipt, _registry(tmp_path))

    assert verification.verified is True
    assert verification.experiment_id == "experiment-2026-0001"
    assert verification.overlap_group_ids == (
        "us-equities-2020-2026",
        "vendor-release-0042",
    )
    assert verification.market_factor_column == "MKT"

    wrong_receipt = _verify(manifest, b"forged receipt", _registry(tmp_path))
    assert wrong_receipt.verified is False
    assert any("receipt" in error for error in wrong_receipt.errors)

    envelope = json.loads(manifest)
    envelope["payload"]["exchange_calendar_sha256"] = "3" * 64
    envelope["signature"]["value"] = _sign(envelope["payload"])
    wrong_calendar = _verify(
        canonical_json(envelope), receipt, _registry(tmp_path)
    )
    assert wrong_calendar.verified is False
    assert any("exchange_calendar_sha256" in error for error in wrong_calendar.errors)


def test_worm_receipt_requires_distinct_signer_and_exact_ledger_commitment(
    tmp_path: Path,
) -> None:
    registry = _registry(tmp_path)
    valid_receipt = _signed_anchor_receipt()
    manifest, _ = _signed_manifest(valid_receipt)
    assert _verify(manifest, valid_receipt, registry).verified is True

    same_signer = json.loads(valid_receipt)
    same_signer["signature"]["key_id"] = "research-key-2026"
    same_signer["signature"]["value"] = _sign(same_signer["payload"])
    same_signer_raw = canonical_json(same_signer)
    same_signer_manifest = json.loads(manifest)
    same_signer_manifest["payload"]["anchor"]["receipt_sha256"] = sha256_bytes(
        same_signer_raw
    )
    same_signer_manifest["signature"]["value"] = _sign(
        same_signer_manifest["payload"]
    )
    verification = _verify(
        canonical_json(same_signer_manifest), same_signer_raw, registry
    )
    assert verification.verified is False
    assert any("distinct" in error for error in verification.errors)

    stale_receipt = json.loads(valid_receipt)
    stale_receipt["payload"]["research_ledger_prior_effective_trials"] = 99
    stale_receipt["signature"]["value"] = _sign(stale_receipt["payload"])
    stale_receipt_raw = canonical_json(stale_receipt)
    stale_manifest = json.loads(manifest)
    stale_manifest["payload"]["anchor"]["receipt_sha256"] = sha256_bytes(
        stale_receipt_raw
    )
    stale_manifest["signature"]["value"] = _sign(stale_manifest["payload"])
    verification = _verify(canonical_json(stale_manifest), stale_receipt_raw, registry)
    assert verification.verified is False
    assert any(
        "research_ledger_prior_effective_trials" in error
        for error in verification.errors
    )


def test_manifest_tampering_and_unpinned_key_registry_fail_closed(tmp_path: Path) -> None:
    receipt = _signed_anchor_receipt()
    manifest, _ = _signed_manifest(receipt)
    envelope = json.loads(manifest)
    envelope["payload"]["oos_start"] = "2024-01-03T00:00:00"
    tampered = _verify(canonical_json(envelope), receipt, _registry(tmp_path))
    assert tampered.verified is False
    assert any("signature verification failed" in error for error in tampered.errors)
    assert any("oos_start" in error for error in tampered.errors)

    unpinned = load_trusted_key_registry(tmp_path / "missing.json", None)
    no_trust = _verify(manifest, receipt, unpinned)
    assert no_trust.verified is False
    assert any("pinned SHA-256" in error for error in no_trust.errors)


def test_trust_json_rejects_duplicate_keys_for_registry_and_manifest(tmp_path: Path) -> None:
    duplicate_registry = (
        b'{"schema_version":1,"schema_version":1,"keys":{"research-key-2026":{}}}'
    )
    path = tmp_path / "duplicate-registry.json"
    path.write_bytes(duplicate_registry)
    registry = load_trusted_key_registry(path, sha256_bytes(duplicate_registry))
    assert registry.valid is False
    assert any("duplicate JSON object key" in error for error in registry.errors)

    receipt = _signed_anchor_receipt()
    manifest, _ = _signed_manifest(receipt)
    duplicate_manifest = manifest.replace(
        b'"purpose":"sealed_final_validation_v7"',
        b'"purpose":"sealed_final_validation_v7","purpose":"sealed_final_validation_v7"',
        1,
    )
    verification = _verify(duplicate_manifest, receipt, _registry(tmp_path))
    assert verification.verified is False
    assert any("duplicate JSON object key" in error for error in verification.errors)


def test_signed_manifest_requires_exact_interval_provenance(tmp_path: Path) -> None:
    receipt = _signed_anchor_receipt()
    manifest, _ = _signed_manifest(receipt)
    envelope = json.loads(manifest)
    envelope["payload"]["interval_provenance"]["factor_return_interval"] = (
        "close_to_close"
    )
    envelope["signature"]["value"] = _sign(envelope["payload"])
    verification = _verify(canonical_json(envelope), receipt, _registry(tmp_path))
    assert verification.verified is False
    assert any("factor_return_interval" in error for error in verification.errors)

    manifest, _ = _signed_manifest(receipt)
    envelope = json.loads(manifest)
    envelope["payload"]["interval_provenance"]["factor_return_row_label"] = (
        "interval_start_session_date"
    )
    envelope["signature"]["value"] = _sign(envelope["payload"])
    verification = _verify(canonical_json(envelope), receipt, _registry(tmp_path))
    assert verification.verified is False
    assert any("factor_return_row_label" in error for error in verification.errors)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("corporate_action_data_sha256", "9" * 64),
        ("borrow_data_sha256", "8" * 64),
        ("execution_window_dollar_volume_data_sha256", "7" * 64),
    ],
)
def test_manifest_binds_all_economic_evidence_panels(
    tmp_path: Path,
    field: str,
    replacement: str,
) -> None:
    receipt = _signed_anchor_receipt()
    manifest, _ = _signed_manifest(receipt)
    envelope = json.loads(manifest)
    envelope["payload"][field] = replacement
    envelope["signature"]["value"] = _sign(envelope["payload"])
    verification = _verify(canonical_json(envelope), receipt, _registry(tmp_path))
    assert verification.verified is False
    assert any(field in error for error in verification.errors)


def test_old_manifest_schema_and_full_session_liquidity_provenance_fail_closed(
    tmp_path: Path,
) -> None:
    receipt = _signed_anchor_receipt()
    manifest, _ = _signed_manifest(receipt)
    envelope = json.loads(manifest)
    envelope["payload"]["schema_version"] = SEALED_MANIFEST_SCHEMA_VERSION - 1
    envelope["payload"]["interval_provenance"]["execution_liquidity_window"] = (
        "full_session"
    )
    envelope["signature"]["value"] = _sign(envelope["payload"])
    verification = _verify(canonical_json(envelope), receipt, _registry(tmp_path))
    assert verification.verified is False
    assert any("schema_version" in error for error in verification.errors)
    assert any("execution_liquidity_window" in error for error in verification.errors)


def test_certification_payload_reuse_requires_exact_context_and_ledger_state() -> None:
    first = certification_context_hash({"data": "v1", "split": 0.7, "cost": 3.0})
    changed_data = certification_context_hash({"data": "v2", "split": 0.7, "cost": 3.0})
    changed_split = certification_context_hash({"data": "v1", "split": 0.75, "cost": 3.0})
    payload = {"certification_context_hash": first, "ledger_state_hash": "ledger-1"}

    assert certification_payload_is_current(
        payload, context_hash=first, ledger_state_hash="ledger-1"
    )
    assert not certification_payload_is_current(
        payload, context_hash=changed_data, ledger_state_hash="ledger-1"
    )
    assert not certification_payload_is_current(
        payload, context_hash=changed_split, ledger_state_hash="ledger-1"
    )
    assert not certification_payload_is_current(
        payload, context_hash=first, ledger_state_hash="ledger-2"
    )


def test_runtime_identity_is_reproducible_and_excludes_host_identity() -> None:
    first = research_runtime_identity()
    second = research_runtime_identity()
    assert first == second
    assert set(first) == {
        "python_implementation",
        "python_version",
        "operating_system",
        "operating_system_release",
        "machine_architecture",
        "numpy_version",
        "pandas_version",
        "scipy_version",
        "blas_lapack",
    }
    assert all(first[name] for name in ("python_version", "numpy_version", "pandas_version", "scipy_version"))
    serialized = canonical_json(first).decode("utf-8").lower()
    assert "hostname" not in serialized
    assert "username" not in serialized


def test_factor_return_loader_requires_named_daily_multifactor_data() -> None:
    dates = pd.bdate_range("2025-01-02", periods=80)
    valid = pd.DataFrame(
        {"Date": dates, "MKT": 0.001, "VALUE": -0.0002, "MOM": 0.0001}
    ).to_csv(index=False).encode()
    loaded = load_factor_return_csv(valid)
    assert list(loaded.columns) == ["MKT", "VALUE", "MOM"]
    assert loaded.shape == (80, 3)

    one_factor = pd.DataFrame({"Date": dates, "MKT": 0.001}).to_csv(index=False).encode()
    with pytest.raises(ValueError, match="at least two factors"):
        load_factor_return_csv(one_factor)

    formula_name = pd.DataFrame(
        {"Date": dates, "MKT": 0.001, "=DANGEROUS()": 0.002}
    ).to_csv(index=False).encode()
    with pytest.raises(ValueError, match="spreadsheet formulas"):
        load_factor_return_csv(formula_name)

    nonfinite = pd.DataFrame({"Date": dates, "MKT": 0.001, "VALUE": 0.002})
    nonfinite.loc[4, "VALUE"] = float("nan")
    with pytest.raises(ValueError, match="non-finite"):
        load_factor_return_csv(nonfinite.to_csv(index=False).encode())

    absurd = pd.DataFrame({"Date": dates, "MKT": 0.001, "VALUE": 0.002})
    absurd.loc[4, "VALUE"] = 1.01
    with pytest.raises(ValueError, match="implausible daily return"):
        load_factor_return_csv(absurd.to_csv(index=False).encode())


def test_research_dashboard_initial_render_is_fail_closed_and_exception_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from streamlit.testing.v1 import AppTest

    project_root = Path(__file__).resolve().parents[1]
    monkeypatch.setenv("RESEARCH_LEDGER_PATH", str(tmp_path / "research.sqlite3"))
    monkeypatch.delenv("RESEARCH_GOVERNANCE_PUBLIC_KEYS_PATH", raising=False)
    monkeypatch.delenv("RESEARCH_GOVERNANCE_PUBLIC_KEYS_SHA256", raising=False)

    app = AppTest.from_file(str(project_root / "app.py")).run(timeout=30)
    assert not app.exception
    assert any("Configure the strategy" in item.value for item in app.info)


def test_material_widget_change_clears_completed_research_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from streamlit.testing.v1 import AppTest

    project_root = Path(__file__).resolve().parents[1]
    monkeypatch.setenv("RESEARCH_LEDGER_PATH", str(tmp_path / "research.sqlite3"))
    monkeypatch.delenv("RESEARCH_GOVERNANCE_PUBLIC_KEYS_PATH", raising=False)
    monkeypatch.delenv("RESEARCH_GOVERNANCE_PUBLIC_KEYS_SHA256", raising=False)
    app = AppTest.from_file(str(project_root / "app.py")).run(timeout=30)

    def by_label(elements, label: str):
        return next(element for element in elements if element.label == label)

    # Keep the integration regression fast while still producing a complete payload.
    by_label(app.slider, "Synthetic assets").set_value(8)
    by_label(app.slider, "Synthetic history (years)").set_value(3)
    by_label(app.select_slider, "Bootstrap paths").set_value(500)
    by_label(app.button, "Run research backtest").click()
    app.run(timeout=120)

    assert not app.exception
    assert any("NOT CERTIFIED" in item.value for item in app.error)
    assert app.session_state["research_payload"]["certified"] is False

    # Widgets are deliberately outside a Streamlit form, so this material cost change
    # reruns immediately and the server clears the old payload before rendering it.
    by_label(app.slider, "One-way transaction cost (bps)").set_value(3.5)
    app.run(timeout=30)

    assert not app.exception
    assert any("prior result was invalidated" in item.value for item in app.warning)
    assert not any("NOT CERTIFIED" in item.value for item in app.error)
    assert not any("RESEARCH GATE PASSED" in item.value for item in app.success)
    with pytest.raises(KeyError):
        _ = app.session_state["research_payload"]
