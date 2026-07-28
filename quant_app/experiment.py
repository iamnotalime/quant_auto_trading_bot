from __future__ import annotations

import hashlib
import json
import struct
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from numbers import Integral, Real
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd


CLOSE_HOLDOUT_IDENTITY_VERSION = "close_oos_interval_or_outcomes_v2"
LEGACY_INTERVAL_ONLY_IDENTITY_VERSION = "close_oos_interval_overlap_v2"
LEGACY_CLOSE_PANEL_IDENTITY_VERSION = "close_panel_any_split_v1"
LEGACY_CLOSE_HOLDOUT_IDENTITY_VERSION = "legacy_combined_evidence_v0"
_HOLDOUT_IDENTITY_METADATA_KEY = "holdout_identity_version"
DATAFRAME_FINGERPRINT_VERSION = "typed_dataframe_sha256_v2"


def _update_length_prefixed(digest: Any, payload: bytes) -> None:
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)


def _update_canonical_scalar(digest: Any, value: Any) -> None:
    try:
        missing = bool(pd.isna(value))
    except (TypeError, ValueError):
        missing = False
    if value is None or missing:
        digest.update(b"N")
    elif isinstance(value, (bool, np.bool_)):
        digest.update(b"B1" if value else b"B0")
    elif isinstance(value, Integral):
        digest.update(b"I")
        _update_length_prefixed(digest, str(int(value)).encode("ascii"))
    elif isinstance(value, Real):
        digest.update(b"F")
        digest.update(struct.pack(">d", float(value)))
    elif isinstance(value, (pd.Timestamp, datetime, date, np.datetime64)):
        digest.update(b"T")
        _update_length_prefixed(digest, pd.Timestamp(value).isoformat().encode("utf-8"))
    elif isinstance(value, (pd.Timedelta, timedelta, np.timedelta64)):
        digest.update(b"D")
        _update_length_prefixed(digest, str(pd.Timedelta(value).value).encode("ascii"))
    elif isinstance(value, str):
        digest.update(b"S")
        _update_length_prefixed(digest, value.encode("utf-8"))
    elif isinstance(value, (bytes, bytearray, memoryview)):
        digest.update(b"Y")
        _update_length_prefixed(digest, bytes(value))
    else:
        raise TypeError(
            f"Unsupported dataframe fingerprint scalar type: {type(value).__qualname__}"
        )


def _update_frame_columns(digest: Any, frame: pd.DataFrame) -> None:
    digest.update(len(frame.columns).to_bytes(8, "big"))
    for column in frame.columns:
        _update_canonical_scalar(digest, column)


def _validate_fingerprint_frame(frame: pd.DataFrame) -> None:
    if not isinstance(frame, pd.DataFrame):
        raise TypeError("frame must be a pandas DataFrame.")
    if frame.empty:
        raise ValueError("fingerprinted dataframe must not be empty.")
    if not frame.index.is_unique or not frame.columns.is_unique:
        raise ValueError("fingerprinted dataframe axes must be unique.")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def fingerprint_prices(prices: pd.DataFrame) -> str:
    """Return a deterministic fingerprint of the complete research data set."""

    _validate_fingerprint_frame(prices)
    frame = prices.sort_index().copy()
    digest = hashlib.sha256()
    digest.update(b"typed-dataframe-sha256-v2\0")
    digest.update(len(frame.index).to_bytes(8, "big"))
    _update_frame_columns(digest, frame)
    for index_value, row in frame.iterrows():
        _update_canonical_scalar(digest, index_value)
        for value in row.array:
            _update_canonical_scalar(digest, value)
    return digest.hexdigest()


def fingerprint_holdout_outcomes(prices: pd.DataFrame) -> str:
    """Fingerprint the OOS outcome multiset independently of dates and row order."""

    _validate_fingerprint_frame(prices)
    ordered_columns = sorted(prices.columns, key=lambda value: (type(value).__name__, str(value)))
    frame = prices.loc[:, ordered_columns].copy()
    digest = hashlib.sha256()
    digest.update(b"close-oos-outcomes-v2\0")
    digest.update(len(frame.index).to_bytes(8, "big"))
    _update_frame_columns(digest, frame)
    row_digests: list[bytes] = []
    for row in frame.itertuples(index=False, name=None):
        row_digest = hashlib.sha256()
        row_digest.update(b"close-oos-row-v2\0")
        for value in row:
            _update_canonical_scalar(row_digest, value)
        row_digests.append(row_digest.digest())
    for row_digest in sorted(row_digests):
        digest.update(row_digest)
    return digest.hexdigest()


def fingerprint_config(config: dict[str, Any]) -> str:
    payload = json.dumps(config, default=str, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class HoldoutClaim:
    first_use: bool
    holdout_identity_current: bool
    prior_trials: int
    attempt_id: int
    ledger_id: str
    preclaim_sequence: int
    preclaim_head_hash: str
    postclaim_sequence: int
    postclaim_head_hash: str
    reserved_total_trials: int


@dataclass(frozen=True)
class GovernedHoldoutClaim(HoldoutClaim):
    experiment_first_use: bool
    data_family_first_use: bool
    overlap_groups_first_use: bool

    @property
    def governance_first_use(self) -> bool:
        return bool(
            self.first_use
            and self.experiment_first_use
            and self.data_family_first_use
            and self.overlap_groups_first_use
        )


@dataclass(frozen=True)
class LedgerPreclaimState:
    ledger_id: str
    attempt_sequence: int
    attempt_head_hash: str
    total_planned_trials: int


@dataclass(frozen=True)
class GovernedTrialFinalization:
    trial_id: int
    ledger_snapshot: bytes
    ledger_state_hash: str
    total_planned_trials: int
    attempt_sequence: int
    attempt_head_hash: str


class ResearchLedger:
    """Persistent, append-only experiment and holdout-use ledger.

    A holdout is considered consumed as soon as a run claims it. Failed runs remain
    consumed deliberately: otherwise an analyst could repeatedly inspect failures and
    retain only a favorable evaluation.
    """

    GENESIS_ATTEMPT_HEAD = "0" * 64

    def __init__(self, path: str | Path = "runtime/research_trials.sqlite3") -> None:
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30.0)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode = WAL")
        db.execute("PRAGMA busy_timeout = 30000")
        return db

    def _initialize(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS holdout_uses (
                    data_hash TEXT NOT NULL,
                    oos_start TEXT NOT NULL,
                    oos_end TEXT NOT NULL,
                    first_claimed_at TEXT NOT NULL,
                    first_config_hash TEXT NOT NULL,
                    first_mode TEXT NOT NULL,
                    PRIMARY KEY(data_hash, oos_start)
                );

                CREATE TABLE IF NOT EXISTS ledger_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS research_trials (
                    trial_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    data_hash TEXT NOT NULL,
                    config_hash TEXT NOT NULL,
                    source TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    in_sample_fraction REAL NOT NULL,
                    oos_start TEXT NOT NULL,
                    first_holdout_use INTEGER NOT NULL,
                    eligible_for_sealed_gate INTEGER NOT NULL,
                    gate_passed INTEGER NOT NULL,
                    result_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL DEFAULT '',
                    record_hash TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_research_trials_data
                    ON research_trials(data_hash, oos_start, trial_id);

                CREATE TABLE IF NOT EXISTS research_attempts (
                    attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    claimed_at TEXT NOT NULL,
                    data_hash TEXT NOT NULL,
                    oos_start TEXT NOT NULL,
                    oos_end TEXT NOT NULL,
                    config_hash TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    first_holdout_use INTEGER NOT NULL,
                    planned_effective_trials INTEGER NOT NULL DEFAULT 1,
                    manifest_hash TEXT NOT NULL DEFAULT '',
                    experiment_id TEXT NOT NULL DEFAULT '',
                    data_family_id TEXT NOT NULL DEFAULT '',
                    strategy_family_id TEXT NOT NULL DEFAULT '',
                    overlap_group_ids_json TEXT NOT NULL DEFAULT '[]',
                    governance_first_use INTEGER NOT NULL DEFAULT 0,
                    previous_hash TEXT NOT NULL DEFAULT '',
                    record_hash TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS sealed_experiment_claims (
                    experiment_id TEXT PRIMARY KEY,
                    manifest_hash TEXT NOT NULL UNIQUE,
                    first_claimed_at TEXT NOT NULL,
                    data_hash TEXT NOT NULL,
                    oos_start TEXT NOT NULL,
                    config_hash TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sealed_data_family_claims (
                    data_family_id TEXT PRIMARY KEY,
                    experiment_id TEXT NOT NULL,
                    manifest_hash TEXT NOT NULL,
                    first_claimed_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sealed_overlap_claims (
                    overlap_group_id TEXT PRIMARY KEY,
                    experiment_id TEXT NOT NULL,
                    manifest_hash TEXT NOT NULL,
                    first_claimed_at TEXT NOT NULL
                );
                """
            )
            db.execute(
                "INSERT OR IGNORE INTO ledger_metadata(key, value) VALUES ('ledger_id', ?)",
                (str(uuid.uuid4()),),
            )
            identity_policy = db.execute(
                "SELECT value FROM ledger_metadata WHERE key = ?",
                (_HOLDOUT_IDENTITY_METADATA_KEY,),
            ).fetchone()
            history_exists = any(
                int(db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in (
                    "holdout_uses",
                    "research_attempts",
                    "research_trials",
                    "sealed_experiment_claims",
                    "sealed_data_family_claims",
                    "sealed_overlap_claims",
                )
            )
            if identity_policy is None:
                # Older ledgers keyed first use by a combined evidence hash. That hash
                # changed when sealed-only panels were added, so its prior rows cannot
                # be safely translated into the stable close-panel identity. Never
                # silently treat a non-empty legacy ledger as fresh.
                db.execute(
                    "INSERT INTO ledger_metadata(key, value) VALUES (?, ?)",
                    (
                        _HOLDOUT_IDENTITY_METADATA_KEY,
                        (
                            LEGACY_CLOSE_HOLDOUT_IDENTITY_VERSION
                            if history_exists
                            else CLOSE_HOLDOUT_IDENTITY_VERSION
                        ),
                    ),
                )
            elif (
                str(identity_policy["value"])
                in {
                    LEGACY_INTERVAL_ONLY_IDENTITY_VERSION,
                    LEGACY_CLOSE_PANEL_IDENTITY_VERSION,
                }
                and not history_exists
            ):
                db.execute(
                    "UPDATE ledger_metadata SET value = ? WHERE key = ?",
                    (CLOSE_HOLDOUT_IDENTITY_VERSION, _HOLDOUT_IDENTITY_METADATA_KEY),
                )
            holdout_columns = {
                str(row["name"])
                for row in db.execute("PRAGMA table_info(holdout_uses)").fetchall()
            }
            if "oos_end" not in holdout_columns:
                db.execute(
                    "ALTER TABLE holdout_uses ADD COLUMN oos_end TEXT NOT NULL DEFAULT ''"
                )
            columns = {
                str(row["name"])
                for row in db.execute("PRAGMA table_info(research_trials)").fetchall()
            }
            if "previous_hash" not in columns:
                db.execute(
                    "ALTER TABLE research_trials ADD COLUMN previous_hash TEXT NOT NULL DEFAULT ''"
                )
            if "record_hash" not in columns:
                db.execute(
                    "ALTER TABLE research_trials ADD COLUMN record_hash TEXT NOT NULL DEFAULT ''"
                )
            attempt_columns = {
                str(row["name"])
                for row in db.execute("PRAGMA table_info(research_attempts)").fetchall()
            }
            attempt_migrations = {
                "oos_end": (
                    "ALTER TABLE research_attempts ADD COLUMN "
                    "oos_end TEXT NOT NULL DEFAULT ''"
                ),
                "planned_effective_trials": (
                    "ALTER TABLE research_attempts ADD COLUMN "
                    "planned_effective_trials INTEGER NOT NULL DEFAULT 1"
                ),
                "manifest_hash": (
                    "ALTER TABLE research_attempts ADD COLUMN "
                    "manifest_hash TEXT NOT NULL DEFAULT ''"
                ),
                "experiment_id": (
                    "ALTER TABLE research_attempts ADD COLUMN "
                    "experiment_id TEXT NOT NULL DEFAULT ''"
                ),
                "data_family_id": (
                    "ALTER TABLE research_attempts ADD COLUMN "
                    "data_family_id TEXT NOT NULL DEFAULT ''"
                ),
                "strategy_family_id": (
                    "ALTER TABLE research_attempts ADD COLUMN "
                    "strategy_family_id TEXT NOT NULL DEFAULT ''"
                ),
                "overlap_group_ids_json": (
                    "ALTER TABLE research_attempts ADD COLUMN "
                    "overlap_group_ids_json TEXT NOT NULL DEFAULT '[]'"
                ),
                "governance_first_use": (
                    "ALTER TABLE research_attempts ADD COLUMN "
                    "governance_first_use INTEGER NOT NULL DEFAULT 0"
                ),
                "previous_hash": (
                    "ALTER TABLE research_attempts ADD COLUMN "
                    "previous_hash TEXT NOT NULL DEFAULT ''"
                ),
                "record_hash": (
                    "ALTER TABLE research_attempts ADD COLUMN "
                    "record_hash TEXT NOT NULL DEFAULT ''"
                ),
            }
            for column, statement in attempt_migrations.items():
                if column not in attempt_columns:
                    db.execute(statement)
            self._backfill_hash_chain(db)
            # Legacy ledgers had only completed trials and first-use claims. Seed the
            # attempt registry once so the multiple-testing count cannot reset merely
            # because the software was upgraded.
            attempt_count = int(
                db.execute("SELECT COUNT(*) FROM research_attempts").fetchone()[0]
            )
            if attempt_count == 0:
                db.execute(
                    """
                    INSERT INTO research_attempts(
                        claimed_at, data_hash, oos_start, oos_end, config_hash, mode,
                        first_holdout_use
                    )
                    SELECT created_at, data_hash, oos_start, '', config_hash, mode,
                           first_holdout_use
                    FROM research_trials ORDER BY trial_id
                    """
                )
                db.execute(
                    """
                    INSERT INTO research_attempts(
                        claimed_at, data_hash, oos_start, oos_end, config_hash, mode,
                        first_holdout_use
                    )
                    SELECT h.first_claimed_at, h.data_hash, h.oos_start, h.oos_end,
                           h.first_config_hash, h.first_mode, 1
                    FROM holdout_uses h
                    WHERE NOT EXISTS (
                        SELECT 1 FROM research_attempts a
                        WHERE a.data_hash = h.data_hash
                          AND a.oos_start = h.oos_start
                    )
                    """
                )
            self._backfill_attempt_hash_chain(db)

    @staticmethod
    def _close_holdout_identity_version(db: sqlite3.Connection) -> str:
        row = db.execute(
            "SELECT value FROM ledger_metadata WHERE key = ?",
            (_HOLDOUT_IDENTITY_METADATA_KEY,),
        ).fetchone()
        value = str(row["value"]) if row is not None else ""
        if value not in {
            CLOSE_HOLDOUT_IDENTITY_VERSION,
            LEGACY_INTERVAL_ONLY_IDENTITY_VERSION,
            LEGACY_CLOSE_PANEL_IDENTITY_VERSION,
            LEGACY_CLOSE_HOLDOUT_IDENTITY_VERSION,
        }:
            raise RuntimeError(
                "Research ledger holdout-identity policy is missing or invalid."
            )
        return value

    @classmethod
    def _close_holdout_identity_is_current(cls, db: sqlite3.Connection) -> bool:
        return cls._close_holdout_identity_version(db) == CLOSE_HOLDOUT_IDENTITY_VERSION

    @staticmethod
    def _validated_oos_interval(oos_start: str, oos_end: str) -> tuple[str, str]:
        if not isinstance(oos_start, str) or not oos_start:
            raise ValueError("oos_start must be a non-empty timestamp string.")
        if not isinstance(oos_end, str) or not oos_end:
            raise ValueError("oos_end must be a non-empty timestamp string.")
        try:
            start = pd.Timestamp(oos_start)
            end = pd.Timestamp(oos_end)
            if pd.isna(start) or pd.isna(end):
                raise ValueError("OOS timestamps cannot be NaT.")
            if start.tz is not None or end.tz is not None:
                raise ValueError("OOS timestamps must be timezone-naive session labels.")
            if start != start.normalize() or end != end.normalize():
                raise ValueError("OOS timestamps must be normalized session dates.")
            if end < start:
                raise ValueError("oos_end must not precede oos_start.")
        except (TypeError, ValueError) as exc:
            raise ValueError("OOS holdout interval is invalid.") from exc
        return start.isoformat(), end.isoformat()

    def close_holdout_identity_is_current(self) -> bool:
        """Return whether this ledger can establish a new sealed first-use claim."""

        with self._connect() as db:
            return self._close_holdout_identity_is_current(db)

    @classmethod
    def _claim_close_holdout(
        cls,
        db: sqlite3.Connection,
        *,
        holdout_data_hash: str,
        oos_start: str,
        oos_end: str,
        config_hash: str,
        mode: str,
        claimed_at: str,
    ) -> tuple[bool, bool]:
        """Consume every overlapping OOS interval in one immediate transaction."""

        if not isinstance(holdout_data_hash, str) or not holdout_data_hash:
            raise ValueError("holdout_data_hash must be a non-empty string.")
        oos_start, oos_end = cls._validated_oos_interval(oos_start, oos_end)
        identity_current = cls._close_holdout_identity_is_current(db)
        previously_seen = db.execute(
            """
            SELECT 1 FROM holdout_uses
            WHERE (oos_start <= ? AND oos_end >= ?) OR data_hash = ?
            LIMIT 1
            """,
            (oos_end, oos_start, holdout_data_hash),
        ).fetchone()
        db.execute(
            """
            INSERT OR IGNORE INTO holdout_uses(
                data_hash, oos_start, oos_end, first_claimed_at,
                first_config_hash, first_mode
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (holdout_data_hash, oos_start, oos_end, claimed_at, config_hash, mode),
        )
        db.execute(
            """
            UPDATE holdout_uses
            SET oos_end = CASE WHEN oos_end < ? THEN ? ELSE oos_end END
            WHERE data_hash = ? AND oos_start = ?
            """,
            (oos_end, oos_end, holdout_data_hash, oos_start),
        )
        first_use = bool(identity_current and previously_seen is None)
        return first_use, identity_current

    @staticmethod
    def _validated_ledger_id(value: Any) -> str:
        if not isinstance(value, str):
            raise RuntimeError("Research ledger identity is missing or invalid.")
        try:
            parsed = uuid.UUID(value)
        except (ValueError, AttributeError) as exc:
            raise RuntimeError("Research ledger identity is missing or invalid.") from exc
        if str(parsed) != value:
            raise RuntimeError("Research ledger identity is not canonical.")
        return value

    def _preclaim_state_from_db(self, db: sqlite3.Connection) -> LedgerPreclaimState:
        identity = db.execute(
            "SELECT value FROM ledger_metadata WHERE key = 'ledger_id'"
        ).fetchone()
        ledger_id = self._validated_ledger_id(identity["value"] if identity else None)
        latest = db.execute(
            "SELECT attempt_id, record_hash FROM research_attempts "
            "ORDER BY attempt_id DESC LIMIT 1"
        ).fetchone()
        total = db.execute(
            "SELECT COALESCE(SUM(planned_effective_trials), 0) AS count "
            "FROM research_attempts"
        ).fetchone()
        return LedgerPreclaimState(
            ledger_id=ledger_id,
            attempt_sequence=int(latest["attempt_id"]) if latest else 0,
            attempt_head_hash=(
                str(latest["record_hash"])
                if latest
                else self.GENESIS_ATTEMPT_HEAD
            ),
            total_planned_trials=int(total["count"]),
        )

    def preclaim_state(self) -> LedgerPreclaimState:
        """Return the exact ledger identity/head a signed manifest must bind."""

        if not self.verify_hash_chain():
            raise RuntimeError(
                "Research ledger hash chain failed before preregistration."
            )
        with self._connect() as db:
            return self._preclaim_state_from_db(db)

    @staticmethod
    def _hash_trial(previous_hash: str, values: list[Any]) -> str:
        payload = json.dumps(values, default=str, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256((previous_hash + "\n" + payload).encode("utf-8")).hexdigest()

    def _backfill_hash_chain(self, db: sqlite3.Connection) -> None:
        rows = db.execute("SELECT * FROM research_trials ORDER BY trial_id").fetchall()
        # Only migrate a wholly legacy ledger. Once any hash exists, never rewrite the
        # chain automatically: doing so would hide later database tampering.
        if any(str(row["record_hash"]) for row in rows):
            return
        previous_hash = ""
        for row in rows:
            values = self._row_hash_values(row)
            record_hash = self._hash_trial(previous_hash, values)
            if row["previous_hash"] != previous_hash or row["record_hash"] != record_hash:
                db.execute(
                    """
                    UPDATE research_trials SET previous_hash = ?, record_hash = ?
                    WHERE trial_id = ?
                    """,
                    (previous_hash, record_hash, int(row["trial_id"])),
                )
            previous_hash = record_hash

    @staticmethod
    def _attempt_hash_values(
        row: sqlite3.Row, *, include_oos_end: bool
    ) -> list[Any]:
        values: list[Any] = [
            int(row["attempt_id"]),
            str(row["claimed_at"]),
            str(row["data_hash"]),
            str(row["oos_start"]),
        ]
        if include_oos_end:
            values.append(str(row["oos_end"]))
        values.extend(
            [
                str(row["config_hash"]),
                str(row["mode"]),
                int(row["first_holdout_use"]),
                int(row["planned_effective_trials"]),
                str(row["manifest_hash"]),
                str(row["experiment_id"]),
                str(row["data_family_id"]),
                str(row["strategy_family_id"]),
                str(row["overlap_group_ids_json"]),
                int(row["governance_first_use"]),
            ]
        )
        return values

    def _backfill_attempt_hash_chain(self, db: sqlite3.Connection) -> None:
        rows = db.execute("SELECT * FROM research_attempts ORDER BY attempt_id").fetchall()
        if any(str(row["record_hash"]) for row in rows):
            return
        include_oos_end = self._close_holdout_identity_version(db) in {
            CLOSE_HOLDOUT_IDENTITY_VERSION,
            LEGACY_INTERVAL_ONLY_IDENTITY_VERSION,
        }
        previous_hash = ""
        for row in rows:
            record_hash = self._hash_trial(
                previous_hash,
                self._attempt_hash_values(row, include_oos_end=include_oos_end),
            )
            db.execute(
                """
                UPDATE research_attempts SET previous_hash = ?, record_hash = ?
                WHERE attempt_id = ?
                """,
                (previous_hash, record_hash, int(row["attempt_id"])),
            )
            previous_hash = record_hash

    def _seal_latest_attempt_hash(self, db: sqlite3.Connection, attempt_id: int) -> None:
        previous = db.execute(
            """
            SELECT record_hash FROM research_attempts
            WHERE attempt_id < ? ORDER BY attempt_id DESC LIMIT 1
            """,
            (attempt_id,),
        ).fetchone()
        previous_hash = str(previous["record_hash"]) if previous else ""
        row = db.execute(
            "SELECT * FROM research_attempts WHERE attempt_id = ?",
            (attempt_id,),
        ).fetchone()
        if row is None:  # pragma: no cover - the row was inserted in this transaction
            raise RuntimeError("research attempt disappeared before hash sealing")
        include_oos_end = self._close_holdout_identity_version(db) in {
            CLOSE_HOLDOUT_IDENTITY_VERSION,
            LEGACY_INTERVAL_ONLY_IDENTITY_VERSION,
        }
        record_hash = self._hash_trial(
            previous_hash,
            self._attempt_hash_values(row, include_oos_end=include_oos_end),
        )
        db.execute(
            """
            UPDATE research_attempts SET previous_hash = ?, record_hash = ?
            WHERE attempt_id = ?
            """,
            (previous_hash, record_hash, attempt_id),
        )

    @staticmethod
    def _row_hash_values(row: sqlite3.Row) -> list[Any]:
        return [
            int(row["trial_id"]),
            str(row["created_at"]),
            str(row["data_hash"]),
            str(row["config_hash"]),
            str(row["source"]),
            str(row["mode"]),
            float(row["in_sample_fraction"]),
            str(row["oos_start"]),
            int(row["first_holdout_use"]),
            int(row["eligible_for_sealed_gate"]),
            int(row["gate_passed"]),
            str(row["result_json"]),
        ]

    def claim_holdout(
        self,
        *,
        holdout_data_hash: str,
        oos_start: str,
        oos_end: str,
        config_hash: str,
        mode: str,
        planned_effective_trials: int = 1,
    ) -> HoldoutClaim:
        """Atomically claim a close-data holdout across every chronological split.

        ``prior_trials`` is intentionally the program-wide sum of planned effective
        trials rather than a count limited to this exact fingerprint or to successful
        runs. Trying other universes, samples, validation splits, perturbation families,
        or an evaluation that crashes after revealing the holdout is still researcher
        freedom and must contribute to any later multiple-testing penalty.
        """
        if (
            isinstance(planned_effective_trials, bool)
            or not isinstance(planned_effective_trials, int)
            or planned_effective_trials < 1
        ):
            raise ValueError("planned_effective_trials must be an integer of at least one.")
        oos_start, oos_end = self._validated_oos_interval(oos_start, oos_end)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            preclaim = self._preclaim_state_from_db(db)
            claimed_at = _utc_now()
            first_use, identity_current = self._claim_close_holdout(
                db,
                holdout_data_hash=holdout_data_hash,
                oos_start=oos_start,
                oos_end=oos_end,
                config_hash=config_hash,
                mode=mode,
                claimed_at=claimed_at,
            )
            attempt_cursor = db.execute(
                """
                INSERT INTO research_attempts(
                    claimed_at, data_hash, oos_start, oos_end, config_hash, mode,
                    first_holdout_use, planned_effective_trials
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    claimed_at,
                    holdout_data_hash,
                    oos_start,
                    oos_end,
                    config_hash,
                    mode,
                    int(first_use),
                    planned_effective_trials,
                ),
            )
            attempt_id = int(attempt_cursor.lastrowid)
            self._seal_latest_attempt_hash(db, attempt_id)
            postclaim = self._preclaim_state_from_db(db)
            db.commit()
        return HoldoutClaim(
            first_use=first_use,
            holdout_identity_current=identity_current,
            prior_trials=preclaim.total_planned_trials,
            attempt_id=attempt_id,
            ledger_id=preclaim.ledger_id,
            preclaim_sequence=preclaim.attempt_sequence,
            preclaim_head_hash=preclaim.attempt_head_hash,
            postclaim_sequence=postclaim.attempt_sequence,
            postclaim_head_hash=postclaim.attempt_head_hash,
            reserved_total_trials=postclaim.total_planned_trials,
        )

    def claim_governed_holdout(
        self,
        *,
        holdout_data_hash: str,
        oos_start: str,
        oos_end: str,
        config_hash: str,
        mode: str,
        planned_effective_trials: int,
        manifest_hash: str,
        experiment_id: str,
        data_family_id: str,
        strategy_family_id: str,
        overlap_group_ids: tuple[str, ...],
        expected_ledger_id: str,
        expected_preclaim_sequence: int,
        expected_preclaim_head_hash: str,
        expected_prior_trials: int,
    ) -> GovernedHoldoutClaim:
        """Atomically consume exact, experiment, family, and overlap identities.

        All fresh identities are consumed even if another identity was already used.
        This prevents changing a split, one data cell, or one family label and then
        retrying with the remaining fresh identities after seeing the result.
        """
        if mode != "sealed_final":
            raise ValueError("governed holdout claims are reserved for sealed_final mode.")
        if (
            isinstance(planned_effective_trials, bool)
            or not isinstance(planned_effective_trials, int)
            or planned_effective_trials < 1
        ):
            raise ValueError("planned_effective_trials must be an integer of at least one.")
        if not all(
            isinstance(value, str) and value
            for value in (
                manifest_hash,
                experiment_id,
                data_family_id,
                strategy_family_id,
            )
        ):
            raise ValueError("governed holdout identity fields must be non-empty strings.")
        if not overlap_group_ids or len(set(overlap_group_ids)) != len(overlap_group_ids):
            raise ValueError("overlap_group_ids must be non-empty and unique.")
        oos_start, oos_end = self._validated_oos_interval(oos_start, oos_end)
        expected_ledger_id = self._validated_ledger_id(expected_ledger_id)
        if (
            isinstance(expected_preclaim_sequence, bool)
            or not isinstance(expected_preclaim_sequence, int)
            or expected_preclaim_sequence < 0
            or not isinstance(expected_preclaim_head_hash, str)
            or len(expected_preclaim_head_hash) != 64
            or any(
                character not in "0123456789abcdef"
                for character in expected_preclaim_head_hash
            )
            or isinstance(expected_prior_trials, bool)
            or not isinstance(expected_prior_trials, int)
            or expected_prior_trials < 0
        ):
            raise ValueError("governed holdout preclaim state is malformed.")

        claimed_at = _utc_now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            preclaim = self._preclaim_state_from_db(db)
            if (
                preclaim.ledger_id != expected_ledger_id
                or preclaim.attempt_sequence != expected_preclaim_sequence
                or preclaim.attempt_head_hash != expected_preclaim_head_hash
                or preclaim.total_planned_trials != expected_prior_trials
            ):
                raise RuntimeError(
                    "Research ledger changed after the signed preregistration state; "
                    "the governed holdout claim was not consumed."
                )
            exact_first_use, identity_current = self._claim_close_holdout(
                db,
                holdout_data_hash=holdout_data_hash,
                oos_start=oos_start,
                oos_end=oos_end,
                config_hash=config_hash,
                mode=mode,
                claimed_at=claimed_at,
            )
            experiment = db.execute(
                """
                INSERT OR IGNORE INTO sealed_experiment_claims(
                    experiment_id, manifest_hash, first_claimed_at,
                    data_hash, oos_start, config_hash
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    experiment_id,
                    manifest_hash,
                    claimed_at,
                    holdout_data_hash,
                    oos_start,
                    config_hash,
                ),
            )
            family = db.execute(
                """
                INSERT OR IGNORE INTO sealed_data_family_claims(
                    data_family_id, experiment_id, manifest_hash, first_claimed_at
                ) VALUES (?, ?, ?, ?)
                """,
                (data_family_id, experiment_id, manifest_hash, claimed_at),
            )
            overlap_first_use = True
            for group_id in overlap_group_ids:
                group = db.execute(
                    """
                    INSERT OR IGNORE INTO sealed_overlap_claims(
                        overlap_group_id, experiment_id, manifest_hash, first_claimed_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (group_id, experiment_id, manifest_hash, claimed_at),
                )
                overlap_first_use = bool(overlap_first_use and group.rowcount == 1)

            experiment_first_use = experiment.rowcount == 1
            family_first_use = family.rowcount == 1
            governance_first_use = bool(
                exact_first_use
                and experiment_first_use
                and family_first_use
                and overlap_first_use
            )
            attempt_cursor = db.execute(
                """
                INSERT INTO research_attempts(
                    claimed_at, data_hash, oos_start, oos_end, config_hash, mode,
                    first_holdout_use, planned_effective_trials, manifest_hash,
                    experiment_id, data_family_id, strategy_family_id,
                    overlap_group_ids_json, governance_first_use
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    claimed_at,
                    holdout_data_hash,
                    oos_start,
                    oos_end,
                    config_hash,
                    mode,
                    int(exact_first_use),
                    planned_effective_trials,
                    manifest_hash,
                    experiment_id,
                    data_family_id,
                    strategy_family_id,
                    json.dumps(overlap_group_ids, separators=(",", ":")),
                    int(governance_first_use),
                ),
            )
            attempt_id = int(attempt_cursor.lastrowid)
            self._seal_latest_attempt_hash(db, attempt_id)
            postclaim = self._preclaim_state_from_db(db)
            db.commit()
        return GovernedHoldoutClaim(
            first_use=exact_first_use,
            holdout_identity_current=identity_current,
            prior_trials=preclaim.total_planned_trials,
            attempt_id=attempt_id,
            ledger_id=preclaim.ledger_id,
            preclaim_sequence=preclaim.attempt_sequence,
            preclaim_head_hash=preclaim.attempt_head_hash,
            postclaim_sequence=postclaim.attempt_sequence,
            postclaim_head_hash=postclaim.attempt_head_hash,
            reserved_total_trials=postclaim.total_planned_trials,
            experiment_first_use=experiment_first_use,
            data_family_first_use=family_first_use,
            overlap_groups_first_use=overlap_first_use,
        )

    def _insert_trial(
        self,
        db: sqlite3.Connection,
        *,
        data_hash: str,
        config_hash: str,
        source: str,
        mode: str,
        in_sample_fraction: float,
        oos_start: str,
        first_holdout_use: bool,
        eligible_for_sealed_gate: bool,
        gate_passed: bool,
        result: dict[str, Any],
    ) -> int:
        previous = db.execute(
            "SELECT trial_id, record_hash FROM research_trials "
            "ORDER BY trial_id DESC LIMIT 1"
        ).fetchone()
        previous_hash = str(previous["record_hash"]) if previous else ""
        next_trial_id = int(previous["trial_id"]) + 1 if previous else 1
        created_at = _utc_now()
        result_json = json.dumps(result, default=str, sort_keys=True)
        values = [
            next_trial_id,
            created_at,
            data_hash,
            config_hash,
            source,
            mode,
            float(in_sample_fraction),
            oos_start,
            int(first_holdout_use),
            int(eligible_for_sealed_gate),
            int(gate_passed),
            result_json,
        ]
        record_hash = self._hash_trial(previous_hash, values)
        cursor = db.execute(
            """
            INSERT INTO research_trials(
                trial_id, created_at, data_hash, config_hash, source, mode,
                in_sample_fraction, oos_start, first_holdout_use,
                eligible_for_sealed_gate, gate_passed, result_json,
                previous_hash, record_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                next_trial_id,
                created_at,
                data_hash,
                config_hash,
                source,
                mode,
                float(in_sample_fraction),
                oos_start,
                int(first_holdout_use),
                int(eligible_for_sealed_gate),
                int(gate_passed),
                result_json,
                previous_hash,
                record_hash,
            ),
        )
        return int(cursor.lastrowid)

    def record_trial(
        self,
        *,
        data_hash: str,
        config_hash: str,
        source: str,
        mode: str,
        in_sample_fraction: float,
        oos_start: str,
        first_holdout_use: bool,
        eligible_for_sealed_gate: bool,
        gate_passed: bool,
        result: dict[str, Any],
    ) -> int:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            trial_id = self._insert_trial(
                db,
                data_hash=data_hash,
                config_hash=config_hash,
                source=source,
                mode=mode,
                in_sample_fraction=in_sample_fraction,
                oos_start=oos_start,
                first_holdout_use=first_holdout_use,
                eligible_for_sealed_gate=eligible_for_sealed_gate,
                gate_passed=gate_passed,
                result=result,
            )
            db.commit()
            return trial_id

    def finalize_governed_trial(
        self,
        *,
        claim: GovernedHoldoutClaim,
        data_hash: str,
        config_hash: str,
        source: str,
        mode: str,
        in_sample_fraction: float,
        oos_start: str,
        eligible_for_sealed_gate: bool,
        gate_passed: bool,
        result: dict[str, Any],
    ) -> GovernedTrialFinalization:
        """Atomically reject concurrent claims, record, and snapshot a sealed result."""

        if mode != "sealed_final":
            raise ValueError("governed trial finalization requires sealed_final mode.")
        if not isinstance(claim, GovernedHoldoutClaim):
            raise TypeError("governed trial finalization requires its exact holdout claim.")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            current = self._preclaim_state_from_db(db)
            if (
                current.ledger_id != claim.ledger_id
                or current.attempt_sequence != claim.postclaim_sequence
                or current.attempt_head_hash != claim.postclaim_head_hash
                or current.total_planned_trials != claim.reserved_total_trials
                or claim.attempt_id != claim.postclaim_sequence
            ):
                raise RuntimeError(
                    "Research attempts changed after this run reserved the holdout; "
                    "sealed statistics are stale and no certified trial was recorded."
                )
            trial_id = self._insert_trial(
                db,
                data_hash=data_hash,
                config_hash=config_hash,
                source=source,
                mode=mode,
                in_sample_fraction=in_sample_fraction,
                oos_start=oos_start,
                first_holdout_use=claim.first_use,
                eligible_for_sealed_gate=eligible_for_sealed_gate,
                gate_passed=gate_passed,
                result=result,
            )
            snapshot = self._governance_state_snapshot_bytes_from_db(db)
            db.commit()
        return GovernedTrialFinalization(
            trial_id=trial_id,
            ledger_snapshot=snapshot,
            ledger_state_hash=hashlib.sha256(snapshot).hexdigest(),
            total_planned_trials=current.total_planned_trials,
            attempt_sequence=current.attempt_sequence,
            attempt_head_hash=current.attempt_head_hash,
        )

    def recent_trials(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                """
                SELECT trial_id, created_at, data_hash, config_hash, source, mode,
                       in_sample_fraction, oos_start, first_holdout_use,
                       eligible_for_sealed_gate, gate_passed, record_hash
                FROM research_trials ORDER BY trial_id DESC LIMIT ?
                """,
                (max(1, int(limit)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def recent_attempts(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return claimed evaluations, including interrupted/failed evaluations."""
        with self._connect() as db:
            rows = db.execute(
                """
                SELECT attempt_id, claimed_at, data_hash, config_hash, mode,
                       oos_start, first_holdout_use, planned_effective_trials,
                       manifest_hash, experiment_id, data_family_id,
                       strategy_family_id, overlap_group_ids_json,
                       governance_first_use, previous_hash, record_hash
                FROM research_attempts
                ORDER BY attempt_id DESC LIMIT ?
                """,
                (max(1, int(limit)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def governance_state_fingerprint(self) -> str:
        """Fingerprint all governance registries used by a displayed certification.

        Streamlit sessions compare this value before reusing a result. A claim made in
        another process/session therefore invalidates an already-rendered payload.
        """
        payload = self.governance_state_snapshot_bytes()
        return hashlib.sha256(payload).hexdigest()

    def governance_state_snapshot_bytes(self) -> bytes:
        """Export every governance row in the same canonical form used by its hash."""

        with self._connect() as db:
            return self._governance_state_snapshot_bytes_from_db(db)

    @staticmethod
    def _governance_state_snapshot_bytes_from_db(db: sqlite3.Connection) -> bytes:
        tables = (
            ("ledger_metadata", "key"),
            ("holdout_uses", "data_hash, oos_start"),
            ("research_attempts", "attempt_id"),
            ("research_trials", "trial_id"),
            ("sealed_experiment_claims", "experiment_id"),
            ("sealed_data_family_claims", "data_family_id"),
            ("sealed_overlap_claims", "overlap_group_id"),
        )
        state: dict[str, list[dict[str, Any]]] = {}
        for table, ordering in tables:
            rows = db.execute(f"SELECT * FROM {table} ORDER BY {ordering}").fetchall()
            state[table] = [dict(row) for row in rows]
        payload = json.dumps(
            state,
            default=str,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return payload

    def verify_hash_chain(self) -> bool:
        previous_hash = ""
        with self._connect() as db:
            identity = db.execute(
                "SELECT value FROM ledger_metadata WHERE key = 'ledger_id'"
            ).fetchone()
            rows = db.execute("SELECT * FROM research_trials ORDER BY trial_id").fetchall()
            attempts = db.execute(
                "SELECT * FROM research_attempts ORDER BY attempt_id"
            ).fetchall()
            holdout_rows = [
                dict(row)
                for row in db.execute(
                    "SELECT data_hash, oos_start, oos_end FROM holdout_uses"
                )
            ]
            experiments = {
                str(row["experiment_id"]): dict(row)
                for row in db.execute("SELECT * FROM sealed_experiment_claims")
            }
            data_families = {
                str(row["data_family_id"]): dict(row)
                for row in db.execute("SELECT * FROM sealed_data_family_claims")
            }
            overlap_groups = {
                str(row["overlap_group_id"]): dict(row)
                for row in db.execute("SELECT * FROM sealed_overlap_claims")
            }
            identity_policy = db.execute(
                "SELECT value FROM ledger_metadata WHERE key = ?",
                (_HOLDOUT_IDENTITY_METADATA_KEY,),
            ).fetchone()
        try:
            self._validated_ledger_id(identity["value"] if identity else None)
        except RuntimeError:
            return False
        if identity_policy is None or str(identity_policy["value"]) not in {
            CLOSE_HOLDOUT_IDENTITY_VERSION,
            LEGACY_INTERVAL_ONLY_IDENTITY_VERSION,
            LEGACY_CLOSE_PANEL_IDENTITY_VERSION,
            LEGACY_CLOSE_HOLDOUT_IDENTITY_VERSION,
        }:
            return False
        identity_version = str(identity_policy["value"])
        include_oos_end = identity_version in {
            CLOSE_HOLDOUT_IDENTITY_VERSION,
            LEGACY_INTERVAL_ONLY_IDENTITY_VERSION,
        }
        for row in rows:
            expected = self._hash_trial(previous_hash, self._row_hash_values(row))
            if row["previous_hash"] != previous_hash or row["record_hash"] != expected:
                return False
            previous_hash = expected

        previous_hash = ""
        governed_attempts: list[dict[str, Any]] = []
        for row in attempts:
            expected = self._hash_trial(
                previous_hash,
                self._attempt_hash_values(row, include_oos_end=include_oos_end),
            )
            if row["previous_hash"] != previous_hash or row["record_hash"] != expected:
                return False
            previous_hash = expected
            if int(row["planned_effective_trials"]) < 1:
                return False
            matching_holdout = next(
                (
                    holdout
                    for holdout in holdout_rows
                    if str(holdout["data_hash"]) == str(row["data_hash"])
                    and str(holdout["oos_start"]) == str(row["oos_start"])
                ),
                None,
            )
            if matching_holdout is None:
                return False
            if include_oos_end:
                try:
                    attempt_start, attempt_end = self._validated_oos_interval(
                        str(row["oos_start"]), str(row["oos_end"])
                    )
                    holdout_start, holdout_end = self._validated_oos_interval(
                        str(matching_holdout["oos_start"]),
                        str(matching_holdout["oos_end"]),
                    )
                except ValueError:
                    return False
                if attempt_start != holdout_start or attempt_end > holdout_end:
                    return False
            experiment_id = str(row["experiment_id"])
            data_family_id = str(row["data_family_id"])
            strategy_family_id = str(row["strategy_family_id"])
            manifest_hash = str(row["manifest_hash"])
            try:
                groups = json.loads(str(row["overlap_group_ids_json"]))
            except json.JSONDecodeError:
                return False
            if experiment_id:
                if (
                    not manifest_hash
                    or not data_family_id
                    or not strategy_family_id
                    or not isinstance(groups, list)
                    or not groups
                    or experiment_id not in experiments
                    or data_family_id not in data_families
                    or any(not isinstance(group, str) or group not in overlap_groups for group in groups)
                ):
                    return False
                governed_attempts.append(dict(row))
            elif any(
                (
                    manifest_hash,
                    data_family_id,
                    strategy_family_id,
                    bool(groups),
                    int(row["governance_first_use"]),
                )
            ):
                return False

        for holdout in holdout_rows:
            matching_attempts = [
                row
                for row in attempts
                if str(row["data_hash"]) == str(holdout["data_hash"])
                and str(row["oos_start"]) == str(holdout["oos_start"])
            ]
            if not matching_attempts:
                return False
            if include_oos_end:
                try:
                    _, holdout_end = self._validated_oos_interval(
                        str(holdout["oos_start"]), str(holdout["oos_end"])
                    )
                    maximum_attempt_end = max(
                        self._validated_oos_interval(
                            str(row["oos_start"]), str(row["oos_end"])
                        )[1]
                        for row in matching_attempts
                    )
                except ValueError:
                    return False
                if holdout_end != maximum_attempt_end:
                    return False

        # Every sealed registry row must have originated in an atomically recorded
        # attempt. This catches deletion/insertion of family claims independently of
        # the hash-chained attempt log.
        for experiment_id, claim in experiments.items():
            if not any(
                str(attempt["experiment_id"]) == experiment_id
                and str(attempt["manifest_hash"]) == str(claim["manifest_hash"])
                for attempt in governed_attempts
            ):
                return False
        for data_family_id, claim in data_families.items():
            if not any(
                str(attempt["data_family_id"]) == data_family_id
                and str(attempt["experiment_id"]) == str(claim["experiment_id"])
                and str(attempt["manifest_hash"]) == str(claim["manifest_hash"])
                for attempt in governed_attempts
            ):
                return False
        for group_id, claim in overlap_groups.items():
            if not any(
                group_id in json.loads(str(attempt["overlap_group_ids_json"]))
                and str(attempt["experiment_id"]) == str(claim["experiment_id"])
                and str(attempt["manifest_hash"]) == str(claim["manifest_hash"])
                for attempt in governed_attempts
            ):
                return False
        return True
