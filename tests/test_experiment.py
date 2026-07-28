from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pandas as pd
import pytest

from quant_app.experiment import (
    CLOSE_HOLDOUT_IDENTITY_VERSION,
    LEGACY_CLOSE_PANEL_IDENTITY_VERSION,
    LEGACY_CLOSE_HOLDOUT_IDENTITY_VERSION,
    ResearchLedger,
    fingerprint_config,
    fingerprint_holdout_outcomes,
    fingerprint_prices,
)
from quant_app.validation import PARAMETER_PERTURBATION_VARIANT_COUNT


def test_price_and_config_fingerprints_are_deterministic_and_sensitive() -> None:
    prices = pd.DataFrame(
        {"A": [100.0, 101.0], "B": [50.0, 49.0]},
        index=pd.date_range("2025-01-01", periods=2, freq="B"),
    )
    assert fingerprint_prices(prices) == fingerprint_prices(prices.copy())
    changed = prices.copy()
    changed.iloc[-1, -1] += 0.01
    assert fingerprint_prices(prices) != fingerprint_prices(changed)
    shifted_dates = prices.copy()
    shifted_dates.index = shifted_dates.index + pd.DateOffset(years=1)
    assert fingerprint_holdout_outcomes(prices) == fingerprint_holdout_outcomes(
        shifted_dates
    )
    assert fingerprint_holdout_outcomes(prices) == fingerprint_holdout_outcomes(
        prices[list(reversed(prices.columns))]
    )
    assert fingerprint_holdout_outcomes(prices) == fingerprint_holdout_outcomes(
        prices.iloc[::-1]
    )
    assert fingerprint_config({"a": 1, "b": 2}) == fingerprint_config({"b": 2, "a": 1})
    assert fingerprint_config({"a": 1}) != fingerprint_config({"a": 2})
    with pytest.raises(ValueError, match="must not be empty"):
        fingerprint_prices(prices.iloc[0:0])
    duplicate_columns = prices.copy()
    duplicate_columns.columns = ["A", "A"]
    with pytest.raises(ValueError, match="axes must be unique"):
        fingerprint_holdout_outcomes(duplicate_columns)
    mixed = pd.DataFrame(
        {
            "integer": [1, 2],
            "boolean": [True, False],
            "timestamp": pd.to_datetime(["2025-01-01", "2025-01-02"]),
            "duration": pd.to_timedelta([1, 2], unit="D"),
            "text": ["alpha", "beta"],
            "bytes": [b"a", b"b"],
        },
        index=pd.date_range("2025-02-01", periods=2, freq="D"),
    )
    assert fingerprint_prices(mixed) == fingerprint_prices(mixed.copy())


def test_holdout_claim_is_persistent_and_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "research.sqlite3"
    ledger = ResearchLedger(path)
    first = ledger.claim_holdout(
        holdout_data_hash="data-1",
        oos_start="2024-01-02",
        oos_end="2024-12-31",
        config_hash="config-1",
        mode="sealed_final",
    )
    assert first.first_use is True
    assert first.prior_trials == 0

    # A new object simulates a dashboard/process restart. The holdout remains consumed
    # even though no successful trial was recorded after the first claim.
    restarted = ResearchLedger(path)
    second = restarted.claim_holdout(
        holdout_data_hash="data-1",
        oos_start="2024-01-02",
        oos_end="2024-12-31",
        config_hash="config-2",
        mode="sealed_final",
    )
    assert second.first_use is False
    # The interrupted first evaluation still revealed/consumed the holdout and is
    # therefore counted as a research attempt.
    assert second.prior_trials == 1
    attempts = restarted.recent_attempts()
    assert len(attempts) == 2
    assert attempts[0]["first_holdout_use"] == 0


def test_exploratory_close_holdout_cannot_be_recertified_with_enriched_evidence_or_resplit(
    tmp_path: Path,
) -> None:
    prices = pd.DataFrame(
        {"A": [100.0, 101.0, 102.0], "B": [50.0, 49.0, 48.0]},
        index=pd.date_range("2024-01-02", periods=3, freq="B"),
    )
    holdout_data_hash = fingerprint_holdout_outcomes(prices.iloc[1:])
    exploratory_evidence_hash = fingerprint_config(
        {"close_prices": holdout_data_hash, "factor_returns": ""}
    )
    sealed_evidence_hash = fingerprint_config(
        {"close_prices": holdout_data_hash, "factor_returns": "signed-factor-panel"}
    )
    assert exploratory_evidence_hash != sealed_evidence_hash

    ledger = ResearchLedger(tmp_path / "cross-mode.sqlite3")
    exploratory = ledger.claim_holdout(
        holdout_data_hash=holdout_data_hash,
        oos_start="2024-01-03",
        oos_end="2024-01-04",
        config_hash=exploratory_evidence_hash,
        mode="exploratory",
    )
    assert ledger.close_holdout_identity_is_current() is True
    assert exploratory.first_use is True
    assert exploratory.holdout_identity_current is True

    def governed_claim(*, oos_start: str, ordinal: int):
        signed = ledger.preclaim_state()
        return ledger.claim_governed_holdout(
            holdout_data_hash=holdout_data_hash,
            oos_start=oos_start,
            oos_end="2024-01-04",
            config_hash=sealed_evidence_hash,
            mode="sealed_final",
            planned_effective_trials=1,
            manifest_hash=f"manifest-cross-mode-{ordinal:04d}",
            experiment_id=f"experiment-cross-mode-{ordinal:04d}",
            data_family_id=f"data-family-cross-mode-{ordinal:04d}",
            strategy_family_id="strategy-family-cross-mode-0001",
            overlap_group_ids=(f"overlap-cross-mode-{ordinal:04d}",),
            expected_ledger_id=signed.ledger_id,
            expected_preclaim_sequence=signed.attempt_sequence,
            expected_preclaim_head_hash=signed.attempt_head_hash,
            expected_prior_trials=signed.total_planned_trials,
        )

    same_split = governed_claim(oos_start="2024-01-03", ordinal=1)
    changed_split = governed_claim(oos_start="2024-01-04", ordinal=2)
    for claim in (same_split, changed_split):
        assert claim.holdout_identity_current is True
        assert claim.first_use is False
        assert claim.governance_first_use is False

    changed_prices = prices.copy()
    changed_prices.iloc[0, 0] += 0.01
    assert fingerprint_holdout_outcomes(changed_prices.iloc[1:]) == holdout_data_hash
    edited_in_sample = ledger.claim_holdout(
        holdout_data_hash=fingerprint_holdout_outcomes(changed_prices.iloc[1:]),
        oos_start="2024-01-03",
        oos_end="2024-01-04",
        config_hash="different-close-panel-config",
        mode="exploratory",
    )
    assert edited_in_sample.first_use is False

    relabeled_dates = ledger.claim_holdout(
        holdout_data_hash=holdout_data_hash,
        oos_start="2026-01-02",
        oos_end="2026-01-05",
        config_hash="date-relabel-config",
        mode="exploratory",
    )
    assert relabeled_dates.first_use is False

    genuinely_nonoverlapping = ledger.claim_holdout(
        holdout_data_hash="future-independent-close-panel",
        oos_start="2025-01-02",
        oos_end="2025-12-31",
        config_hash="future-independent-config",
        mode="exploratory",
    )
    assert genuinely_nonoverlapping.first_use is True
    assert ledger.verify_hash_chain() is True

    with sqlite3.connect(ledger.path) as db:
        db.execute(
            "UPDATE holdout_uses SET oos_end = '2030-12-31T00:00:00' "
            "WHERE data_hash = ?",
            (holdout_data_hash,),
        )
        db.commit()
    assert ledger.verify_hash_chain() is False


def test_nonempty_prior_policy_ledger_cannot_claim_fresh_sealed_holdout_identity(
    tmp_path: Path,
) -> None:
    path = tmp_path / "legacy.sqlite3"
    ledger = ResearchLedger(path)
    ledger.claim_holdout(
        holdout_data_hash="legacy-aggregate-evidence-hash",
        oos_start="2024-01-03",
        oos_end="2024-12-31",
        config_hash="legacy-config",
        mode="exploratory",
    )
    with sqlite3.connect(path) as db:
        db.row_factory = sqlite3.Row
        attempt = db.execute(
            "SELECT * FROM research_attempts WHERE attempt_id = 1"
        ).fetchone()
        assert attempt is not None
        legacy_hash = ResearchLedger._hash_trial(
            "",
            ResearchLedger._attempt_hash_values(
                attempt, include_oos_end=False
            ),
        )
        db.execute("UPDATE holdout_uses SET oos_end = ''")
        db.execute("UPDATE research_attempts SET oos_end = '', record_hash = ?", (legacy_hash,))
        db.execute(
            "UPDATE ledger_metadata SET value = ? WHERE key = 'holdout_identity_version'",
            (LEGACY_CLOSE_PANEL_IDENTITY_VERSION,),
        )
        db.commit()

    migrated = ResearchLedger(path)
    assert migrated.verify_hash_chain() is True
    with sqlite3.connect(path) as db:
        version = db.execute(
            "SELECT value FROM ledger_metadata WHERE key = 'holdout_identity_version'"
        ).fetchone()[0]
    assert version == LEGACY_CLOSE_PANEL_IDENTITY_VERSION
    assert version != LEGACY_CLOSE_HOLDOUT_IDENTITY_VERSION
    assert version != CLOSE_HOLDOUT_IDENTITY_VERSION
    assert migrated.close_holdout_identity_is_current() is False

    signed = migrated.preclaim_state()
    claim = migrated.claim_governed_holdout(
        holdout_data_hash="otherwise-fresh-close-panel",
        oos_start="2025-01-03",
        oos_end="2025-12-31",
        config_hash="sealed-config-after-upgrade",
        mode="sealed_final",
        planned_effective_trials=1,
        manifest_hash="manifest-after-legacy-upgrade",
        experiment_id="experiment-after-legacy-upgrade",
        data_family_id="data-family-after-legacy-upgrade",
        strategy_family_id="strategy-family-after-legacy-upgrade",
        overlap_group_ids=("overlap-after-legacy-upgrade",),
        expected_ledger_id=signed.ledger_id,
        expected_preclaim_sequence=signed.attempt_sequence,
        expected_preclaim_head_hash=signed.attempt_head_hash,
        expected_prior_trials=signed.total_planned_trials,
    )
    assert claim.holdout_identity_current is False
    assert claim.first_use is False
    assert claim.governance_first_use is False


def test_trial_ledger_is_append_only_and_counts_prior_trials(tmp_path: Path) -> None:
    ledger = ResearchLedger(tmp_path / "research.sqlite3")
    claim = ledger.claim_holdout(
        holdout_data_hash="data-1",
        oos_start="2024-01-02",
        oos_end="2024-12-31",
        config_hash="config-1",
        mode="exploratory",
    )
    trial_id = ledger.record_trial(
        data_hash="data-1",
        config_hash="config-1",
        source="uploaded",
        mode="exploratory",
        in_sample_fraction=0.70,
        oos_start="2024-01-02",
        first_holdout_use=claim.first_use,
        eligible_for_sealed_gate=False,
        gate_passed=False,
        result={"CAGR": 0.1},
    )
    assert trial_id == 1
    rows = ledger.recent_trials()
    assert len(rows) == 1
    assert rows[0]["gate_passed"] == 0
    assert ledger.verify_hash_chain() is True

    next_claim = ledger.claim_holdout(
        holdout_data_hash="data-1",
        oos_start="2024-01-02",
        oos_end="2024-12-31",
        config_hash="config-2",
        mode="exploratory",
    )
    assert next_claim.first_use is False
    assert next_claim.prior_trials == 1

    # Trials on another universe/holdout still represent researcher degrees of
    # freedom and must not disappear from the multiple-testing penalty.
    other_holdout = ledger.claim_holdout(
        holdout_data_hash="different-data",
        oos_start="2025-01-02",
        oos_end="2025-12-31",
        config_hash="config-3",
        mode="sealed_final",
    )
    assert other_holdout.first_use is True
    assert other_holdout.prior_trials == 2


def test_trial_hash_chain_detects_database_tampering(tmp_path: Path) -> None:
    path = tmp_path / "research.sqlite3"
    ledger = ResearchLedger(path)
    claim = ledger.claim_holdout(
        holdout_data_hash="data-1",
        oos_start="2024-01-02",
        oos_end="2024-12-31",
        config_hash="config-1",
        mode="sealed_final",
    )
    ledger.record_trial(
        data_hash="data-1",
        config_hash="config-1",
        source="uploaded",
        mode="sealed_final",
        in_sample_fraction=0.7,
        oos_start="2024-01-02",
        first_holdout_use=claim.first_use,
        eligible_for_sealed_gate=True,
        gate_passed=False,
        result={"CAGR": 0.1},
    )
    with sqlite3.connect(path) as db:
        db.execute("UPDATE research_trials SET result_json = ? WHERE trial_id = 1", ('{"CAGR": 9}',))
        db.commit()

    restarted = ResearchLedger(path)
    assert restarted.verify_hash_chain() is False


def test_interrupted_perturbation_claim_retains_all_planned_trial_weight(tmp_path: Path) -> None:
    ledger = ResearchLedger(tmp_path / "research.sqlite3")
    first = ledger.claim_holdout(
        holdout_data_hash="data-1",
        oos_start="2024-01-02",
        oos_end="2024-12-31",
        config_hash="config-1",
        mode="exploratory",
        planned_effective_trials=PARAMETER_PERTURBATION_VARIANT_COUNT,
    )
    assert first.prior_trials == 0

    # Simulate a crash before record_trial. The next run must still pay the full
    # multiple-testing penalty that was planned before the holdout was revealed.
    second = ResearchLedger(ledger.path).claim_holdout(
        holdout_data_hash="data-2",
        oos_start="2025-01-02",
        oos_end="2025-12-31",
        config_hash="config-2",
        mode="exploratory",
        planned_effective_trials=1,
    )
    assert second.prior_trials == PARAMETER_PERTURBATION_VARIANT_COUNT
    assert (
        ledger.recent_attempts(2)[1]["planned_effective_trials"]
        == PARAMETER_PERTURBATION_VARIANT_COUNT
    )


def test_governed_claim_blocks_trivial_data_split_and_family_relabeling(tmp_path: Path) -> None:
    ledger = ResearchLedger(tmp_path / "research.sqlite3")

    def signed_preclaim() -> dict[str, object]:
        state = ledger.preclaim_state()
        return {
            "expected_ledger_id": state.ledger_id,
            "expected_preclaim_sequence": state.attempt_sequence,
            "expected_preclaim_head_hash": state.attempt_head_hash,
            "expected_prior_trials": state.total_planned_trials,
        }

    before = ledger.governance_state_fingerprint()
    first = ledger.claim_governed_holdout(
        holdout_data_hash="exact-data-v1",
        oos_start="2023-01-03",
        oos_end="2023-12-31",
        config_hash="config-v1",
        mode="sealed_final",
        planned_effective_trials=1,
        manifest_hash="manifest-v1",
        experiment_id="experiment-0001",
        data_family_id="data-family-0001",
        strategy_family_id="strategy-family-0001",
        overlap_group_ids=("overlap-period-0001",),
        **signed_preclaim(),
    )
    assert first.governance_first_use is True
    assert ledger.governance_state_fingerprint() != before

    edited_and_resplit = ledger.claim_governed_holdout(
        holdout_data_hash="exact-data-v2-one-cell-edit",
        oos_start="2024-01-03",
        oos_end="2024-12-31",
        config_hash="config-v2-new-split",
        mode="sealed_final",
        planned_effective_trials=1,
        manifest_hash="manifest-v2",
        experiment_id="experiment-0002",
        data_family_id="data-family-0001",
        strategy_family_id="strategy-family-0001",
        overlap_group_ids=("overlap-period-0001",),
        **signed_preclaim(),
    )
    assert edited_and_resplit.first_use is True
    assert edited_and_resplit.data_family_first_use is False
    assert edited_and_resplit.overlap_groups_first_use is False
    assert edited_and_resplit.governance_first_use is False

    relabeled_family = ledger.claim_governed_holdout(
        holdout_data_hash="exact-data-v3",
        oos_start="2025-01-03",
        oos_end="2025-12-31",
        config_hash="config-v3",
        mode="sealed_final",
        planned_effective_trials=1,
        manifest_hash="manifest-v3",
        experiment_id="experiment-0003",
        data_family_id="renamed-data-family-0002",
        strategy_family_id="strategy-family-0001",
        overlap_group_ids=("overlap-period-0001",),
        **signed_preclaim(),
    )
    assert relabeled_family.data_family_first_use is True
    assert relabeled_family.overlap_groups_first_use is False
    assert relabeled_family.governance_first_use is False

    snapshot = ledger.governance_state_snapshot_bytes()
    assert hashlib.sha256(snapshot).hexdigest() == ledger.governance_state_fingerprint()
    assert b"research_attempts" in snapshot
    assert b"sealed_overlap_claims" in snapshot


def test_governed_claim_compare_and_swap_rejects_race_and_swapped_ledger(
    tmp_path: Path,
) -> None:
    ledger = ResearchLedger(tmp_path / "governed.sqlite3")
    signed = ledger.preclaim_state()
    ledger.claim_holdout(
        holdout_data_hash="competing-data",
        oos_start="2024-01-02",
        oos_end="2024-12-31",
        config_hash="competing-config",
        mode="exploratory",
        planned_effective_trials=7,
    )
    with pytest.raises(RuntimeError, match="changed after the signed preregistration"):
        ledger.claim_governed_holdout(
            holdout_data_hash="sealed-data",
            oos_start="2024-01-02",
            oos_end="2024-12-31",
            config_hash="sealed-config",
            mode="sealed_final",
            planned_effective_trials=25,
            manifest_hash="manifest-sealed-race",
            experiment_id="experiment-sealed-race",
            data_family_id="data-family-sealed-race",
            strategy_family_id="strategy-family-sealed-race",
            overlap_group_ids=("overlap-sealed-race",),
            expected_ledger_id=signed.ledger_id,
            expected_preclaim_sequence=signed.attempt_sequence,
            expected_preclaim_head_hash=signed.attempt_head_hash,
            expected_prior_trials=signed.total_planned_trials,
        )
    assert len(ledger.recent_attempts(10)) == 1

    replacement = ResearchLedger(tmp_path / "replacement.sqlite3")
    replacement_state = replacement.preclaim_state()
    assert replacement_state.ledger_id != signed.ledger_id
    with pytest.raises(RuntimeError, match="changed after the signed preregistration"):
        replacement.claim_governed_holdout(
            holdout_data_hash="sealed-data",
            oos_start="2024-01-02",
            oos_end="2024-12-31",
            config_hash="sealed-config",
            mode="sealed_final",
            planned_effective_trials=25,
            manifest_hash="manifest-sealed-swap",
            experiment_id="experiment-sealed-swap",
            data_family_id="data-family-sealed-swap",
            strategy_family_id="strategy-family-sealed-swap",
            overlap_group_ids=("overlap-sealed-swap",),
            expected_ledger_id=signed.ledger_id,
            expected_preclaim_sequence=signed.attempt_sequence,
            expected_preclaim_head_hash=signed.attempt_head_hash,
            expected_prior_trials=signed.total_planned_trials,
        )
    assert replacement.recent_attempts(10) == []


def test_governed_finalization_rejects_concurrent_attempt_without_recording_result(
    tmp_path: Path,
) -> None:
    ledger = ResearchLedger(tmp_path / "finalize.sqlite3")
    signed = ledger.preclaim_state()
    claim = ledger.claim_governed_holdout(
        holdout_data_hash="sealed-data",
        oos_start="2024-01-02",
        oos_end="2024-12-31",
        config_hash="sealed-config",
        mode="sealed_final",
        planned_effective_trials=25,
        manifest_hash="manifest-finalize-0001",
        experiment_id="experiment-finalize-0001",
        data_family_id="data-family-finalize-0001",
        strategy_family_id="strategy-family-finalize-0001",
        overlap_group_ids=("overlap-finalize-0001",),
        expected_ledger_id=signed.ledger_id,
        expected_preclaim_sequence=signed.attempt_sequence,
        expected_preclaim_head_hash=signed.attempt_head_hash,
        expected_prior_trials=signed.total_planned_trials,
    )
    ledger.claim_holdout(
        holdout_data_hash="concurrent-data",
        oos_start="2025-01-02",
        oos_end="2025-12-31",
        config_hash="concurrent-config",
        mode="exploratory",
        planned_effective_trials=3,
    )

    with pytest.raises(RuntimeError, match="statistics are stale"):
        ledger.finalize_governed_trial(
            claim=claim,
            data_hash="sealed-data",
            config_hash="sealed-config",
            source="uploaded",
            mode="sealed_final",
            in_sample_fraction=0.6,
            oos_start="2024-01-02",
            eligible_for_sealed_gate=True,
            gate_passed=True,
            result={"statistical_trial_count": claim.reserved_total_trials},
        )
    assert ledger.recent_trials(10) == []


def test_governed_finalization_returns_atomic_ledger_snapshot(tmp_path: Path) -> None:
    ledger = ResearchLedger(tmp_path / "finalize-success.sqlite3")
    signed = ledger.preclaim_state()
    claim = ledger.claim_governed_holdout(
        holdout_data_hash="sealed-data-success",
        oos_start="2024-01-02",
        oos_end="2024-12-31",
        config_hash="sealed-config-success",
        mode="sealed_final",
        planned_effective_trials=25,
        manifest_hash="manifest-finalize-success",
        experiment_id="experiment-finalize-success",
        data_family_id="data-family-finalize-success",
        strategy_family_id="strategy-family-finalize-success",
        overlap_group_ids=("overlap-finalize-success",),
        expected_ledger_id=signed.ledger_id,
        expected_preclaim_sequence=signed.attempt_sequence,
        expected_preclaim_head_hash=signed.attempt_head_hash,
        expected_prior_trials=signed.total_planned_trials,
    )
    finalized = ledger.finalize_governed_trial(
        claim=claim,
        data_hash="sealed-data-success",
        config_hash="sealed-config-success",
        source="uploaded",
        mode="sealed_final",
        in_sample_fraction=0.6,
        oos_start="2024-01-02",
        eligible_for_sealed_gate=True,
        gate_passed=False,
        result={"statistical_trial_count": claim.reserved_total_trials},
    )

    assert finalized.total_planned_trials == 25
    assert finalized.attempt_sequence == claim.postclaim_sequence
    assert finalized.attempt_head_hash == claim.postclaim_head_hash
    assert finalized.ledger_state_hash == hashlib.sha256(
        finalized.ledger_snapshot
    ).hexdigest()
    assert finalized.ledger_snapshot == ledger.governance_state_snapshot_bytes()
