from __future__ import annotations

import json
import hashlib
import hmac
import math
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from auto_trader.models import AccountSnapshot, CashActivity, OrderReceipt, TargetPlan


SCHEMA_VERSION = 4
AUTHENTICATION_INVENTORY_SCHEMA_VERSION = 3
_LEGACY_OPERATIONAL_AUTHENTICATION_SCHEMA_VERSION = 2
_MISSING_STATE = object()
_OPERATIONAL_AUTHENTICATION_COLUMNS: dict[str, tuple[str, ...]] = {
    "orders": (
        "id",
        "plan_id",
        "broker_order_id",
        "client_order_id",
        "symbol",
        "side",
        "qty",
        "phase",
        "status",
        "submitted_at",
        "updated_at",
        "filled_qty",
        "filled_avg_price",
        "raw_json",
    ),
    "events": ("id", "timestamp", "level", "code", "message", "payload_json"),
    "runs": (
        "run_id",
        "kind",
        "started_at",
        "ended_at",
        "status",
        "message",
        "payload_json",
    ),
}
_OPERATIONAL_AUTHENTICATION_ORDER_BY = {
    "orders": "id",
    "events": "id",
    "runs": "run_id COLLATE BINARY",
}
_OPERATIONAL_AUTHENTICATION_ROW_KEYS = {
    "orders": "client_order_id",
    "events": "id",
    "runs": "run_id",
}
_OPERATIONAL_AUTHENTICATION_STATE_TABLE = "operational_authentication_state"
_OPERATIONAL_AUTHENTICATION_ROWS_TABLE = "operational_authentication_rows"
_OPERATIONAL_AUTHENTICATION_TRIGGER_PREFIX = "operational_authentication_dirty"
_ZERO_SHA256 = "0" * 64
REQUIRED_TABLE_COLUMNS: dict[str, set[str]] = {
    "store_metadata": {"key", "value", "updated_at"},
    "state": {"key", "value", "value_mac", "updated_at"},
    "runs": {"run_id", "kind", "started_at", "status", "payload_json"},
    "plans": {
        "plan_id", "as_of", "created_at", "regime", "regime_multiplier",
        "desired_gross", "forecast_volatility", "target_weights_json",
        "metadata_json", "status",
        "lifecycle_sequence", "lifecycle_mac",
    },
    "orders": {
        "id", "broker_order_id", "client_order_id", "symbol", "side", "qty",
        "phase", "status", "submitted_at", "updated_at",
    },
    "equity_snapshots": {
        "id", "timestamp", "session_date", "equity", "cash", "buying_power",
        "drawdown", "daily_return", "five_day_return",
        "row_mac", "chain_mac",
    },
    "events": {"id", "timestamp", "level", "code", "message", "payload_json"},
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class StateStore:
    CASH_ACTIVITY_MONITOR_KEY = "external_cash_activity_monitor"
    COVARIANCE_EVIDENCE_ANCHOR_KEY = "covariance_evidence_anchor"

    def __init__(
        self,
        path: str | Path,
        *,
        require_existing: bool = False,
        read_only: bool = False,
        authentication_key: bytes | None = None,
    ) -> None:
        self.path = Path(path).expanduser().resolve(strict=False)
        self.identity_path = self.path.with_suffix(self.path.suffix + ".identity")
        self.authentication_anchor_path = self.path.with_suffix(
            self.path.suffix + ".auth.json"
        )
        self.authentication_pending_path = self.path.with_suffix(
            self.path.suffix + ".auth.pending.json"
        )
        self.authentication_lock_path = self.path.with_suffix(
            self.path.suffix + ".auth.lock"
        )
        self._authentication_lock_local = threading.local()
        self.read_only = bool(read_only)
        if authentication_key is not None and len(authentication_key) < 32:
            raise ValueError("State authentication key must contain at least 32 bytes.")
        self.authentication_key = bytes(authentication_key) if authentication_key else None
        # A read-only observer must never turn a missing mount into a fresh trading
        # database.  Make that invariant intrinsic to the store instead of relying
        # on each caller to remember a second flag.
        self.require_existing = bool(require_existing or self.read_only)
        if not self.require_existing:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        database_existed = self.path.exists()
        identity_existed = self.identity_path.exists()
        authentication_anchor_existed = self.authentication_anchor_path.exists()
        required_files = [
            (self.path, database_existed),
            (self.identity_path, identity_existed),
        ]
        if self.authentication_key is not None:
            required_files.append(
                (self.authentication_anchor_path, authentication_anchor_existed)
            )
        if self.require_existing and not all(exists for _, exists in required_files):
            missing = [
                str(candidate)
                for candidate, exists in required_files
                if not exists
            ]
            raise RuntimeError(
                "Existing persistent state is required; refusing to create or repair "
                "missing state files: " + ", ".join(missing)
            )
        if not database_existed and identity_existed:
            raise RuntimeError(
                f"State database {self.path} is missing while identity marker "
                f"{self.identity_path} still exists. Refusing to initialize empty state. "
                "Restore the database or deliberately remove both files after an audited reset."
            )
        if self.require_existing:
            self._validate_existing()
        else:
            self._initialize()
        self._verify_identity(identity_existed=identity_existed)
        if self.authentication_key is not None:
            with self._authentication_write_lock():
                self._recover_authentication_transition_locked()
                if self.authentication_anchor_path.exists():
                    verified_schema = self.verify_authentication_anchor()
                    self._verify_equity_chain()
                    if verified_schema < AUTHENTICATION_INVENTORY_SCHEMA_VERSION:
                        self._upgrade_authentication_anchor(verified_schema)
                else:
                    self._install_incremental_authentication()

    @classmethod
    def open_read_only(cls, path: str | Path) -> "StateStore":
        """Open a validated, non-initializing observer of persistent state.

        Connections created by this instance use SQLite's ``mode=ro`` URI and
        ``query_only`` defense in depth.  They never request WAL mode, commit, repair
        schema, create an identity marker, or create parent directories.
        """
        return cls(path, read_only=True)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        database: str | Path = self.path
        use_uri = False
        if self.require_existing:
            mode = "ro" if self.read_only else "rw"
            database = f"{self.path.as_uri()}?mode={mode}"
            use_uri = True
        connection = sqlite3.connect(database, timeout=30.0, uri=use_uri)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA trusted_schema = OFF")
        if self.read_only:
            connection.execute("PRAGMA query_only = ON")
        else:
            # Rollback-journal mode lets a second process mount the state volume
            # genuinely read-only. WAL readers may need to create or update -shm/-wal
            # sidecars when those files are absent, which violates the dashboard's
            # non-mutating filesystem boundary. Dashboard queries are deliberately
            # short, and the busy timeout bounds the corresponding writer wait.
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute("PRAGMA synchronous = FULL")
        try:
            yield connection
            if not self.read_only:
                connection.commit()
        finally:
            connection.close()

    @contextmanager
    def _validation_connection(self) -> Iterator[sqlite3.Connection]:
        """Open existing state without allowing validation to mutate or create it."""
        connection = sqlite3.connect(
            f"{self.path.as_uri()}?mode=ro",
            timeout=30.0,
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA query_only = ON")
        try:
            yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self.connection() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS store_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    value_mac TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    ended_at TEXT,
                    status TEXT NOT NULL,
                    message TEXT NOT NULL DEFAULT '',
                    payload_json TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS plans (
                    plan_id TEXT PRIMARY KEY,
                    as_of TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    regime TEXT NOT NULL,
                    regime_multiplier REAL NOT NULL,
                    desired_gross REAL NOT NULL,
                    forecast_volatility REAL NOT NULL,
                    target_weights_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    executed_at TEXT,
                    execution_message TEXT NOT NULL DEFAULT '',
                    lifecycle_sequence INTEGER NOT NULL DEFAULT 0,
                    lifecycle_mac TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS orders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    plan_id TEXT,
                    broker_order_id TEXT NOT NULL,
                    client_order_id TEXT NOT NULL UNIQUE,
                    symbol TEXT NOT NULL,
                    side TEXT NOT NULL,
                    qty REAL NOT NULL,
                    phase TEXT NOT NULL,
                    status TEXT NOT NULL,
                    submitted_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    filled_qty REAL NOT NULL DEFAULT 0,
                    filled_avg_price REAL,
                    raw_json TEXT NOT NULL DEFAULT '{}',
                    FOREIGN KEY(plan_id) REFERENCES plans(plan_id)
                );

                CREATE TABLE IF NOT EXISTS equity_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    session_date TEXT NOT NULL,
                    equity REAL NOT NULL,
                    cash REAL NOT NULL,
                    buying_power REAL NOT NULL,
                    drawdown REAL NOT NULL,
                    daily_return REAL NOT NULL,
                    five_day_return REAL NOT NULL
                    ,row_mac TEXT NOT NULL DEFAULT '',
                    chain_mac TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_equity_session_date
                    ON equity_snapshots(session_date, timestamp);

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    level TEXT NOT NULL,
                    code TEXT NOT NULL,
                    message TEXT NOT NULL,
                    payload_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
                """
            )
            self._validate_schema(db, allow_repair=True)

    def _validate_existing(self) -> None:
        with self._validation_connection() as db:
            self._validate_schema(db, allow_repair=False)

    def _validate_schema(
        self, db: sqlite3.Connection, *, allow_repair: bool
    ) -> None:
        quick_check = db.execute("PRAGMA quick_check").fetchone()
        if quick_check is None or str(quick_check[0]).lower() != "ok":
            detail = str(quick_check[0]) if quick_check else "no result"
            raise RuntimeError(f"SQLite integrity check failed for {self.path}: {detail}")

        if allow_repair:
            state_columns = {
                str(row["name"])
                for row in db.execute('PRAGMA table_info("state")').fetchall()
            }
            if "value_mac" not in state_columns:
                db.execute(
                    "ALTER TABLE state ADD COLUMN value_mac TEXT NOT NULL DEFAULT ''"
                )
            equity_columns = {
                str(row["name"])
                for row in db.execute(
                    'PRAGMA table_info("equity_snapshots")'
                ).fetchall()
            }
            if "row_mac" not in equity_columns:
                db.execute(
                    "ALTER TABLE equity_snapshots ADD COLUMN row_mac TEXT NOT NULL DEFAULT ''"
                )
            if "chain_mac" not in equity_columns:
                db.execute(
                    "ALTER TABLE equity_snapshots ADD COLUMN chain_mac TEXT NOT NULL DEFAULT ''"
                )
            plan_columns = {
                str(row["name"])
                for row in db.execute('PRAGMA table_info("plans")').fetchall()
            }
            if "lifecycle_sequence" not in plan_columns:
                db.execute(
                    "ALTER TABLE plans ADD COLUMN lifecycle_sequence "
                    "INTEGER NOT NULL DEFAULT 0"
                )
            if "lifecycle_mac" not in plan_columns:
                db.execute(
                    "ALTER TABLE plans ADD COLUMN lifecycle_mac TEXT NOT NULL DEFAULT ''"
                )

        for table, required in REQUIRED_TABLE_COLUMNS.items():
            columns = {
                str(row["name"])
                for row in db.execute(f'PRAGMA table_info("{table}")').fetchall()
            }
            missing = required - columns
            if missing:
                raise RuntimeError(
                    f"State database schema is incompatible: table {table!r} "
                    f"is missing columns {sorted(missing)!r}."
                )

        version_row = db.execute(
            "SELECT value FROM store_metadata WHERE key = 'schema_version'"
        ).fetchone()
        if version_row is not None:
            try:
                version = int(version_row["value"])
            except (TypeError, ValueError) as exc:
                raise RuntimeError("State database contains an invalid schema version.") from exc
            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"State database schema {version} is newer than supported "
                    f"schema {SCHEMA_VERSION}; refusing a destructive downgrade."
                )
            if version < SCHEMA_VERSION:
                if not allow_repair:
                    raise RuntimeError(
                        f"State database schema {version} requires migration to "
                        f"{SCHEMA_VERSION}; the existing-state reader cannot mutate it."
                    )
                self._migrate(db, version, SCHEMA_VERSION)
        elif allow_repair:
            self._migrate(db, 0, SCHEMA_VERSION)
        else:
            raise RuntimeError("Existing state database is missing its schema version.")

        store_id = db.execute(
            "SELECT value FROM store_metadata WHERE key = 'store_id'"
        ).fetchone()
        if store_id is None:
            if not allow_repair:
                raise RuntimeError("Existing state database is missing its store identity.")
            db.execute(
                "INSERT INTO store_metadata(key, value, updated_at) VALUES (?, ?, ?)",
                ("store_id", str(uuid.uuid4()), _utc_now().isoformat()),
            )

    def _migrate(self, db: sqlite3.Connection, from_version: int, to_version: int) -> None:
        """Apply explicit forward-only migrations inside the initialization transaction."""
        if from_version < 0 or from_version > to_version:
            raise RuntimeError(f"Unsupported schema migration {from_version} -> {to_version}.")
        # Version 1 formalizes the pre-versioned schema without changing its columns.
        if from_version < 1 <= to_version:
            db.execute(
                """
                INSERT INTO store_metadata(key, value, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
                """,
                ("schema_version", "1", _utc_now().isoformat()),
            )
        if from_version < 2 <= to_version:
            if self.authentication_key is not None:
                for row in db.execute("SELECT key, value FROM state").fetchall():
                    db.execute(
                        "UPDATE state SET value_mac = ? WHERE key = ?",
                        (self._state_mac(str(row["key"]), str(row["value"])), row["key"]),
                    )
                for row in db.execute("SELECT * FROM equity_snapshots").fetchall():
                    db.execute(
                        "UPDATE equity_snapshots SET row_mac = ? WHERE id = ?",
                        (self._equity_row_mac(row), row["id"]),
                    )
            db.execute(
                """
                INSERT INTO store_metadata(key, value, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
                """,
                ("schema_version", "2", _utc_now().isoformat()),
            )
        if from_version < 3 <= to_version:
            if self.authentication_key is not None:
                store_id_row = db.execute(
                    "SELECT value FROM store_metadata WHERE key = 'store_id'"
                ).fetchone()
                if store_id_row is None:
                    store_id = str(uuid.uuid4())
                    db.execute(
                        "INSERT INTO store_metadata(key, value, updated_at) VALUES (?, ?, ?)",
                        ("store_id", store_id, _utc_now().isoformat()),
                    )
                else:
                    store_id = str(store_id_row["value"])
                for row in db.execute("SELECT * FROM plans").fetchall():
                    sequence = int(row["lifecycle_sequence"] or 0)
                    db.execute(
                        "UPDATE plans SET lifecycle_mac = ? WHERE plan_id = ?",
                        (self._plan_lifecycle_mac(row, store_id=store_id), row["plan_id"]),
                    )
                previous_chain = ""
                for row in db.execute(
                    "SELECT * FROM equity_snapshots ORDER BY id"
                ).fetchall():
                    row_mac = str(row["row_mac"] or "")
                    if not row_mac:
                        row_mac = self._equity_row_mac(row)
                        db.execute(
                            "UPDATE equity_snapshots SET row_mac = ? WHERE id = ?",
                            (row_mac, row["id"]),
                        )
                    chain_mac = self._equity_chain_mac(
                        int(row["id"]), row_mac, previous_chain
                    )
                    db.execute(
                        "UPDATE equity_snapshots SET chain_mac = ? WHERE id = ?",
                        (chain_mac, row["id"]),
                    )
                    previous_chain = chain_mac
            db.execute(
                """
                INSERT INTO store_metadata(key, value, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
                """,
                ("schema_version", "3", _utc_now().isoformat()),
            )
        # Version 4 records that the external authenticated inventory commits the
        # mutable operational audit tables (orders, events, and runs). There is no
        # column rewrite: plan-only/paper initialization may advance metadata, while
        # require-existing live/read-only opens fail closed in _validate_schema.
        if from_version < 4 <= to_version:
            db.execute(
                """
                INSERT INTO store_metadata(key, value, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
                """,
                ("schema_version", "4", _utc_now().isoformat()),
            )

    def _metadata_value(self, key: str) -> str | None:
        with self.connection() as db:
            row = db.execute(
                "SELECT value FROM store_metadata WHERE key = ?", (key,)
            ).fetchone()
        return str(row["value"]) if row is not None else None

    def _read_identity(self) -> str:
        try:
            payload = json.loads(self.identity_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            raise RuntimeError(
                f"State identity marker {self.identity_path} is unreadable or invalid."
            ) from exc
        store_id = payload.get("store_id") if isinstance(payload, dict) else None
        if not isinstance(store_id, str) or not store_id.strip():
            raise RuntimeError(f"State identity marker {self.identity_path} has no valid store_id.")
        return store_id

    def _write_identity_once(self, store_id: str) -> None:
        payload = json.dumps(
            {
                "store_id": store_id,
                "database_name": self.path.name,
                "schema_version": SCHEMA_VERSION,
                "created_at": _utc_now().isoformat(),
            },
            indent=2,
            sort_keys=True,
        ) + "\n"
        try:
            descriptor = os.open(
                self.identity_path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
        except FileExistsError:
            return
        try:
            os.write(descriptor, payload.encode("utf-8"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _verify_identity(self, *, identity_existed: bool) -> None:
        database_id = self._metadata_value("store_id")
        if not database_id:
            raise RuntimeError("State database is missing its required store identity.")
        if not identity_existed:
            self._write_identity_once(database_id)
        marker_id = self._read_identity()
        if marker_id != database_id:
            raise RuntimeError(
                "State database identity does not match its sidecar marker. Refusing to "
                "operate on a replaced, copied, or incorrectly mounted database."
            )
        self.store_id = database_id

    @contextmanager
    def _authentication_write_lock(self) -> Iterator[None]:
        """Serialize SQLite commits and keyed successor transitions across processes."""

        if self.authentication_key is None:
            yield
            return
        depth = int(getattr(self._authentication_lock_local, "depth", 0))
        if depth:
            self._authentication_lock_local.depth = depth + 1
            try:
                yield
            finally:
                self._authentication_lock_local.depth = depth
            return
        self.authentication_lock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            handle = self.authentication_lock_path.open("r+b", buffering=0)
        except FileNotFoundError:
            try:
                handle = self.authentication_lock_path.open("x+b", buffering=0)
            except FileExistsError:
                handle = self.authentication_lock_path.open("r+b", buffering=0)
        if self.authentication_lock_path.stat().st_size == 0:
            handle.write(b"\n")
            handle.flush()
        deadline = time.monotonic() + 30.0
        acquired = False
        try:
            while True:
                try:
                    handle.seek(0)
                    if os.name == "nt":
                        import msvcrt

                        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    self._authentication_lock_local.depth = 1
                    break
                except (BlockingIOError, OSError) as exc:
                    if time.monotonic() >= deadline:
                        raise RuntimeError(
                            "Timed out serializing authenticated state checkpoint."
                        ) from exc
                    time.sleep(0.01)
            yield
        finally:
            self._authentication_lock_local.depth = 0
            if acquired:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()

    def _operational_row_key(
        self, table: str, row: sqlite3.Row | dict[str, Any]
    ) -> str:
        return str(row[_OPERATIONAL_AUTHENTICATION_ROW_KEYS[table]])

    def _operational_row_hmac(
        self, table: str, row: sqlite3.Row | dict[str, Any]
    ) -> str:
        if self.authentication_key is None:
            return ""
        columns = _OPERATIONAL_AUTHENTICATION_COLUMNS[table]
        encoded = json.dumps(
            [row[column] for column in columns],
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(
            self.authentication_key,
            b"state-operational-row-v2\0"
            + table.encode("ascii")
            + b"\0"
            + ",".join(columns).encode("ascii")
            + b"\0"
            + len(encoded).to_bytes(8, "big")
            + encoded,
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _xor_sha256(*digests: str) -> str:
        value = bytearray(32)
        for digest in digests:
            raw = bytes.fromhex(digest)
            if len(raw) != 32:
                raise RuntimeError("Operational authentication digest is invalid.")
            for index, byte in enumerate(raw):
                value[index] ^= byte
        return bytes(value).hex()

    def _legacy_operational_authentication_inventory(
        self, db: sqlite3.Connection
    ) -> dict[str, dict[str, Any]]:
        """Recompute the schema-2 full-table HMAC during verified migration only."""

        if self.authentication_key is None:
            return {}
        inventory: dict[str, dict[str, Any]] = {}
        for table, columns in _OPERATIONAL_AUTHENTICATION_COLUMNS.items():
            mac = hmac.new(
                self.authentication_key,
                b"state-operational-table-v1\0"
                + table.encode("ascii")
                + b"\0"
                + ",".join(columns).encode("ascii")
                + b"\0",
                hashlib.sha256,
            )
            count = 0
            rows = db.execute(
                f"SELECT {', '.join(columns)} FROM {table} "
                f"ORDER BY {_OPERATIONAL_AUTHENTICATION_ORDER_BY[table]}"
            )
            for row in rows:
                encoded = json.dumps(
                    [row[column] for column in columns],
                    allow_nan=False,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
                mac.update(len(encoded).to_bytes(8, "big"))
                mac.update(encoded)
                count += 1
            inventory[table] = {
                "count": count,
                "rows_hmac_sha256": mac.hexdigest(),
            }
        return inventory

    @staticmethod
    def _operational_trigger_name(table: str, operation: str) -> str:
        return f"{_OPERATIONAL_AUTHENTICATION_TRIGGER_PREFIX}_{table}_{operation}"

    def _operational_authentication_schema_identity(
        self, db: sqlite3.Connection
    ) -> str:
        object_names = {
            _OPERATIONAL_AUTHENTICATION_STATE_TABLE,
            _OPERATIONAL_AUTHENTICATION_ROWS_TABLE,
            *(
                self._operational_trigger_name(table, operation)
                for table in _OPERATIONAL_AUTHENTICATION_COLUMNS
                for operation in ("insert", "update", "delete")
            ),
        }
        placeholders = ",".join("?" for _ in object_names)
        rows = db.execute(
            f"SELECT type, name, tbl_name, sql FROM sqlite_master "
            f"WHERE name IN ({placeholders}) ORDER BY name COLLATE BINARY",
            tuple(sorted(object_names)),
        ).fetchall()
        payload = [
            [
                str(row["type"]),
                str(row["name"]),
                str(row["tbl_name"]),
                " ".join(str(row["sql"] or "").split()),
            ]
            for row in rows
        ]
        if {item[1] for item in payload} != object_names:
            raise RuntimeError(
                "Incremental operational authentication schema is missing or changed; "
                "external checkpoint verification failed."
            )
        return hashlib.sha256(
            json.dumps(
                payload,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

    def _create_incremental_authentication_schema(
        self, db: sqlite3.Connection
    ) -> None:
        for table in _OPERATIONAL_AUTHENTICATION_COLUMNS:
            for operation in ("insert", "update", "delete"):
                db.execute(
                    f'DROP TRIGGER IF EXISTS "{self._operational_trigger_name(table, operation)}"'
                )
        db.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {_OPERATIONAL_AUTHENTICATION_STATE_TABLE} (
                table_name TEXT PRIMARY KEY,
                row_count INTEGER NOT NULL,
                rows_xor_hmac_sha256 TEXT NOT NULL,
                mutation_sequence INTEGER NOT NULL,
                dirty_sequence INTEGER NOT NULL
            ) WITHOUT ROWID
            """
        )
        db.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {_OPERATIONAL_AUTHENTICATION_ROWS_TABLE} (
                table_name TEXT NOT NULL,
                row_key TEXT NOT NULL,
                row_hmac_sha256 TEXT NOT NULL,
                PRIMARY KEY(table_name, row_key)
            ) WITHOUT ROWID
            """
        )
        db.execute(f"DELETE FROM {_OPERATIONAL_AUTHENTICATION_ROWS_TABLE}")
        db.execute(f"DELETE FROM {_OPERATIONAL_AUTHENTICATION_STATE_TABLE}")
        for table, columns in _OPERATIONAL_AUTHENTICATION_COLUMNS.items():
            row_count = 0
            accumulator = _ZERO_SHA256
            rows = db.execute(
                f"SELECT {', '.join(columns)} FROM {table} "
                f"ORDER BY {_OPERATIONAL_AUTHENTICATION_ORDER_BY[table]}"
            ).fetchall()
            for row in rows:
                row_key = self._operational_row_key(table, row)
                row_hmac = self._operational_row_hmac(table, row)
                db.execute(
                    f"INSERT INTO {_OPERATIONAL_AUTHENTICATION_ROWS_TABLE}"
                    "(table_name, row_key, row_hmac_sha256) VALUES (?, ?, ?)",
                    (table, row_key, row_hmac),
                )
                accumulator = self._xor_sha256(accumulator, row_hmac)
                row_count += 1
            db.execute(
                f"INSERT INTO {_OPERATIONAL_AUTHENTICATION_STATE_TABLE}"
                "(table_name, row_count, rows_xor_hmac_sha256, "
                "mutation_sequence, dirty_sequence) VALUES (?, ?, ?, 0, 0)",
                (table, row_count, accumulator),
            )
        for table in _OPERATIONAL_AUTHENTICATION_COLUMNS:
            for operation in ("insert", "update", "delete"):
                trigger_name = self._operational_trigger_name(table, operation)
                db.execute(
                    f"""
                    CREATE TRIGGER "{trigger_name}"
                    AFTER {operation.upper()} ON "{table}"
                    BEGIN
                        UPDATE {_OPERATIONAL_AUTHENTICATION_STATE_TABLE}
                        SET dirty_sequence = dirty_sequence + 1
                        WHERE table_name = '{table}';
                    END
                    """
                )

    def _incremental_operational_authentication_heads(
        self,
        db: sqlite3.Connection,
        *,
        exhaustive: bool,
    ) -> tuple[dict[str, dict[str, Any]], str]:
        schema_sha256 = self._operational_authentication_schema_identity(db)
        state_rows = db.execute(
            f"SELECT table_name, row_count, rows_xor_hmac_sha256, "
            f"mutation_sequence, dirty_sequence "
            f"FROM {_OPERATIONAL_AUTHENTICATION_STATE_TABLE} ORDER BY table_name"
        ).fetchall()
        if {str(row["table_name"]) for row in state_rows} != set(
            _OPERATIONAL_AUTHENTICATION_COLUMNS
        ):
            raise RuntimeError(
                "Incremental operational authentication state is incomplete; external "
                "checkpoint verification failed."
            )
        heads: dict[str, dict[str, Any]] = {}
        for row in state_rows:
            table = str(row["table_name"])
            row_count = row["row_count"]
            mutation_sequence = row["mutation_sequence"]
            dirty_sequence = row["dirty_sequence"]
            digest = str(row["rows_xor_hmac_sha256"])
            if (
                isinstance(row_count, bool)
                or not isinstance(row_count, int)
                or row_count < 0
                or isinstance(mutation_sequence, bool)
                or not isinstance(mutation_sequence, int)
                or mutation_sequence < 0
                or isinstance(dirty_sequence, bool)
                or not isinstance(dirty_sequence, int)
                or dirty_sequence < 0
                or dirty_sequence != mutation_sequence
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
            ):
                raise RuntimeError(
                    "Incremental operational authentication state is invalid; external "
                    "checkpoint verification failed."
                )
            heads[table] = {
                "count": row_count,
                "rows_xor_hmac_sha256": digest,
                "mutation_sequence": mutation_sequence,
                "dirty_sequence": dirty_sequence,
            }
        if not exhaustive:
            return heads, schema_sha256

        for table, columns in _OPERATIONAL_AUTHENTICATION_COLUMNS.items():
            authenticated_rows = {
                str(row["row_key"]): str(row["row_hmac_sha256"])
                for row in db.execute(
                    f"SELECT row_key, row_hmac_sha256 "
                    f"FROM {_OPERATIONAL_AUTHENTICATION_ROWS_TABLE} "
                    "WHERE table_name = ? ORDER BY row_key COLLATE BINARY",
                    (table,),
                ).fetchall()
            }
            computed_rows: dict[str, str] = {}
            accumulator = _ZERO_SHA256
            rows = db.execute(
                f"SELECT {', '.join(columns)} FROM {table} "
                f"ORDER BY {_OPERATIONAL_AUTHENTICATION_ORDER_BY[table]}"
            )
            for operational_row in rows:
                row_key = self._operational_row_key(table, operational_row)
                row_hmac = self._operational_row_hmac(table, operational_row)
                computed_rows[row_key] = row_hmac
                accumulator = self._xor_sha256(accumulator, row_hmac)
            if authenticated_rows != computed_rows:
                raise RuntimeError(
                    f"Persistent {table} history differs from its authenticated row index; "
                    "external checkpoint verification failed."
                )
            if (
                heads[table]["count"] != len(computed_rows)
                or not hmac.compare_digest(
                    str(heads[table]["rows_xor_hmac_sha256"]), accumulator
                )
            ):
                raise RuntimeError(
                    f"Persistent {table} history differs from its authenticated aggregate; "
                    "external checkpoint verification failed."
                )
        return heads, schema_sha256

    def _authentication_inventory_from_connection(
        self,
        db: sqlite3.Connection,
        *,
        schema_version: int,
        exhaustive_operational: bool,
    ) -> dict[str, Any]:
        state_rows = db.execute(
            "SELECT key, value, value_mac FROM state ORDER BY key"
        ).fetchall()
        plan_rows = db.execute("SELECT * FROM plans ORDER BY plan_id").fetchall()
        equity_count = int(
            db.execute("SELECT COUNT(*) FROM equity_snapshots").fetchone()[0]
        )
        equity_tail = db.execute(
            "SELECT id, chain_mac FROM equity_snapshots ORDER BY id DESC LIMIT 1"
        ).fetchone()
        inventory: dict[str, Any] = {
            "schema_version": schema_version,
            "store_id": self.store_id,
            "state_macs": {
                str(row["key"]): (
                    self._state_mac(str(row["key"]), str(row["value"]))
                    + ":"
                    + str(row["value_mac"] or "")
                )
                for row in state_rows
            },
            "plan_lifecycle_macs": {
                str(row["plan_id"]): (
                    self._plan_lifecycle_mac(row)
                    + ":"
                    + str(row["lifecycle_mac"] or "")
                )
                for row in plan_rows
            },
            "equity_tail": {
                "count": equity_count,
                "last_id": int(equity_tail["id"]) if equity_tail else 0,
                "chain_mac": str(equity_tail["chain_mac"] or "")
                if equity_tail
                else "",
            },
        }
        if schema_version == _LEGACY_OPERATIONAL_AUTHENTICATION_SCHEMA_VERSION:
            inventory["operational_table_macs"] = (
                self._legacy_operational_authentication_inventory(db)
            )
        elif schema_version == AUTHENTICATION_INVENTORY_SCHEMA_VERSION:
            heads, schema_sha256 = self._incremental_operational_authentication_heads(
                db,
                exhaustive=exhaustive_operational,
            )
            inventory["operational_table_macs"] = heads
            inventory["operational_authentication_schema_sha256"] = schema_sha256
        return inventory

    def _authentication_inventory(
        self,
        *,
        schema_version: int = AUTHENTICATION_INVENTORY_SCHEMA_VERSION,
        exhaustive_operational: bool = True,
        db: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        if self.authentication_key is None:
            return {}
        if schema_version not in (
            1,
            _LEGACY_OPERATIONAL_AUTHENTICATION_SCHEMA_VERSION,
            AUTHENTICATION_INVENTORY_SCHEMA_VERSION,
        ):
            raise RuntimeError(
                f"Unsupported authenticated state checkpoint schema {schema_version}."
            )
        if db is not None:
            return self._authentication_inventory_from_connection(
                db,
                schema_version=schema_version,
                exhaustive_operational=exhaustive_operational,
            )
        with self.connection() as connection:
            return self._authentication_inventory_from_connection(
                connection,
                schema_version=schema_version,
                exhaustive_operational=exhaustive_operational,
            )

    @staticmethod
    def _canonical_json_bytes(value: Any) -> bytes:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    def _authentication_anchor_hmac(self, inventory: dict[str, Any]) -> str:
        if self.authentication_key is None:
            return ""
        schema_version = int(inventory.get("schema_version", 0))
        if schema_version not in (
            1,
            _LEGACY_OPERATIONAL_AUTHENTICATION_SCHEMA_VERSION,
            AUTHENTICATION_INVENTORY_SCHEMA_VERSION,
        ):
            raise RuntimeError(
                f"Unsupported authenticated state checkpoint schema {schema_version}."
            )
        return hmac.new(
            self.authentication_key,
            f"state-authentication-anchor-v{schema_version}\0".encode("ascii")
            + self._canonical_json_bytes(inventory),
            hashlib.sha256,
        ).hexdigest()

    def _anchor_document(self, inventory: dict[str, Any]) -> dict[str, Any]:
        return {
            **inventory,
            "anchor_hmac_sha256": self._authentication_anchor_hmac(inventory),
        }

    def _anchor_document_sha256(self, document: dict[str, Any]) -> str:
        return hashlib.sha256(self._canonical_json_bytes(document)).hexdigest()

    def _validate_authentication_anchor_document(
        self, document: Any
    ) -> dict[str, Any]:
        if not isinstance(document, dict):
            raise RuntimeError("Authenticated state checkpoint has an invalid schema.")
        schema_version = document.get("schema_version")
        common_fields = {
            "schema_version",
            "store_id",
            "state_macs",
            "plan_lifecycle_macs",
            "equity_tail",
            "anchor_hmac_sha256",
        }
        expected_fields = set(common_fields)
        if schema_version in (
            _LEGACY_OPERATIONAL_AUTHENTICATION_SCHEMA_VERSION,
            AUTHENTICATION_INVENTORY_SCHEMA_VERSION,
        ):
            expected_fields.add("operational_table_macs")
        if schema_version == AUTHENTICATION_INVENTORY_SCHEMA_VERSION:
            expected_fields.add("operational_authentication_schema_sha256")
        operational_tables = document.get("operational_table_macs")
        valid_operational = True
        if schema_version == _LEGACY_OPERATIONAL_AUTHENTICATION_SCHEMA_VERSION:
            valid_operational = bool(
                isinstance(operational_tables, dict)
                and set(operational_tables) == set(_OPERATIONAL_AUTHENTICATION_COLUMNS)
                and all(
                    isinstance(commitment, dict)
                    and set(commitment) == {"count", "rows_hmac_sha256"}
                    and not isinstance(commitment.get("count"), bool)
                    and isinstance(commitment.get("count"), int)
                    and commitment["count"] >= 0
                    and isinstance(commitment.get("rows_hmac_sha256"), str)
                    and len(commitment["rows_hmac_sha256"]) == 64
                    for commitment in operational_tables.values()
                )
            )
        elif schema_version == AUTHENTICATION_INVENTORY_SCHEMA_VERSION:
            valid_operational = bool(
                isinstance(operational_tables, dict)
                and set(operational_tables) == set(_OPERATIONAL_AUTHENTICATION_COLUMNS)
                and all(
                    isinstance(commitment, dict)
                    and set(commitment)
                    == {
                        "count",
                        "rows_xor_hmac_sha256",
                        "mutation_sequence",
                        "dirty_sequence",
                    }
                    and not isinstance(commitment.get("count"), bool)
                    and isinstance(commitment.get("count"), int)
                    and commitment["count"] >= 0
                    and isinstance(commitment.get("rows_xor_hmac_sha256"), str)
                    and len(commitment["rows_xor_hmac_sha256"]) == 64
                    and not isinstance(commitment.get("mutation_sequence"), bool)
                    and isinstance(commitment.get("mutation_sequence"), int)
                    and commitment["mutation_sequence"] >= 0
                    and commitment.get("dirty_sequence")
                    == commitment.get("mutation_sequence")
                    for commitment in operational_tables.values()
                )
                and isinstance(
                    document.get("operational_authentication_schema_sha256"), str
                )
                and len(document["operational_authentication_schema_sha256"]) == 64
            )
        if (
            schema_version
            not in (
                1,
                _LEGACY_OPERATIONAL_AUTHENTICATION_SCHEMA_VERSION,
                AUTHENTICATION_INVENTORY_SCHEMA_VERSION,
            )
            or set(document) != expected_fields
            or document.get("store_id") != self.store_id
            or not isinstance(document.get("state_macs"), dict)
            or not isinstance(document.get("plan_lifecycle_macs"), dict)
            or not isinstance(document.get("equity_tail"), dict)
            or not valid_operational
        ):
            raise RuntimeError("Authenticated state checkpoint has an invalid schema.")
        inventory = {
            key: value for key, value in document.items() if key != "anchor_hmac_sha256"
        }
        expected_hmac = self._authentication_anchor_hmac(inventory)
        supplied_hmac = document.get("anchor_hmac_sha256")
        if (
            not isinstance(supplied_hmac, str)
            or not hmac.compare_digest(expected_hmac, supplied_hmac)
        ):
            raise RuntimeError(
                "Authenticated state checkpoint failed keyed verification."
            )
        return dict(document)

    def _load_authentication_anchor_document(self) -> dict[str, Any]:
        if self.authentication_key is None:
            return {}
        try:
            document = json.loads(
                self.authentication_anchor_path.read_text(encoding="utf-8")
            )
        except (OSError, TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                "Authenticated state checkpoint is missing, unreadable, or invalid."
            ) from exc
        return self._validate_authentication_anchor_document(document)

    def _load_authentication_anchor(self) -> dict[str, Any]:
        document = self._load_authentication_anchor_document()
        return {
            key: value for key, value in document.items() if key != "anchor_hmac_sha256"
        }

    def _transition_hmac(self, transition: dict[str, Any]) -> str:
        if self.authentication_key is None:
            return ""
        return hmac.new(
            self.authentication_key,
            b"state-authentication-transition-v1\0"
            + self._canonical_json_bytes(transition),
            hashlib.sha256,
        ).hexdigest()

    def _validate_authentication_transition(self, document: Any) -> dict[str, Any]:
        if not isinstance(document, dict):
            raise RuntimeError("Authenticated checkpoint transition is invalid.")
        required = {
            "schema_version",
            "store_id",
            "previous_anchor_sha256",
            "next_anchor_sha256",
            "next_anchor",
            "transition_hmac_sha256",
        }
        unsigned = {
            key: value for key, value in document.items() if key != "transition_hmac_sha256"
        }
        next_anchor = self._validate_authentication_anchor_document(
            document.get("next_anchor")
        )
        if (
            set(document) != required
            or document.get("schema_version") != 1
            or document.get("store_id") != self.store_id
            or not isinstance(document.get("previous_anchor_sha256"), str)
            or len(document["previous_anchor_sha256"]) not in (0, 64)
            or not isinstance(document.get("next_anchor_sha256"), str)
            or len(document["next_anchor_sha256"]) != 64
            or document["next_anchor_sha256"]
            != self._anchor_document_sha256(next_anchor)
            or not isinstance(document.get("transition_hmac_sha256"), str)
            or not hmac.compare_digest(
                self._transition_hmac(unsigned), document["transition_hmac_sha256"]
            )
        ):
            raise RuntimeError(
                "Authenticated checkpoint transition failed keyed verification."
            )
        return dict(document)

    def _load_authentication_transition(self) -> dict[str, Any]:
        try:
            document = json.loads(
                self.authentication_pending_path.read_text(encoding="utf-8")
            )
        except (OSError, TypeError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                "Authenticated checkpoint transition is unreadable or invalid."
            ) from exc
        return self._validate_authentication_transition(document)

    @staticmethod
    def _fsync_parent(path: Path) -> None:
        if os.name == "nt":
            return
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _write_json_atomically(self, path: Path, document: dict[str, Any]) -> None:
        temporary = path.with_name(
            f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        try:
            with temporary.open("w", encoding="utf-8", newline="\n") as output:
                json.dump(document, output, allow_nan=False, sort_keys=True)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
            self._fsync_parent(path)
        finally:
            temporary.unlink(missing_ok=True)

    def _write_authentication_anchor_document(
        self, document: dict[str, Any]
    ) -> None:
        validated = self._validate_authentication_anchor_document(document)
        self._write_json_atomically(self.authentication_anchor_path, validated)

    def _remove_pending_authentication_transition(self) -> None:
        self.authentication_pending_path.unlink(missing_ok=True)
        self._fsync_parent(self.authentication_pending_path)

    def _document_matches_database(
        self, document: dict[str, Any], *, exhaustive_operational: bool
    ) -> bool:
        inventory = {
            key: value for key, value in document.items() if key != "anchor_hmac_sha256"
        }
        try:
            actual = self._authentication_inventory(
                schema_version=int(inventory["schema_version"]),
                exhaustive_operational=exhaustive_operational,
            )
        except (RuntimeError, sqlite3.DatabaseError, ValueError):
            return False
        return inventory == actual

    def _recover_authentication_transition_locked(self) -> None:
        if (
            self.authentication_key is None
            or not self.authentication_pending_path.exists()
        ):
            return
        transition = self._load_authentication_transition()
        candidate = dict(transition["next_anchor"])
        next_digest = str(transition["next_anchor_sha256"])
        previous_digest = str(transition["previous_anchor_sha256"])
        current: dict[str, Any] | None = None
        current_digest = ""
        if self.authentication_anchor_path.exists():
            current = self._load_authentication_anchor_document()
            current_digest = self._anchor_document_sha256(current)

        if current_digest == next_digest:
            if not self._document_matches_database(
                candidate, exhaustive_operational=True
            ):
                raise RuntimeError(
                    "Committed authenticated checkpoint does not match persistent state."
                )
            self._remove_pending_authentication_transition()
            return
        if current_digest != previous_digest:
            raise RuntimeError(
                "Authenticated checkpoint transition is not the unique successor of "
                "the external checkpoint."
            )
        if self._document_matches_database(candidate, exhaustive_operational=True):
            self._write_authentication_anchor_document(candidate)
            self._remove_pending_authentication_transition()
            return
        if current is not None and self._document_matches_database(
            current, exhaustive_operational=True
        ):
            # The process stopped after preparing the keyed successor but before its
            # SQLite transaction committed. The old checkpoint is still authoritative.
            self._remove_pending_authentication_transition()
            return
        raise RuntimeError(
            "Neither side of the authenticated checkpoint transition matches persistent "
            "state; refusing recovery."
        )

    def _stage_authentication_anchor(self, db: sqlite3.Connection) -> bool:
        if self.authentication_key is None:
            return False
        inventory = self._authentication_inventory(
            schema_version=AUTHENTICATION_INVENTORY_SCHEMA_VERSION,
            exhaustive_operational=False,
            db=db,
        )
        candidate = self._anchor_document(inventory)
        previous_digest = ""
        if self.authentication_anchor_path.exists():
            previous = self._load_authentication_anchor_document()
            previous_digest = self._anchor_document_sha256(previous)
            if candidate == previous:
                return False
        unsigned_transition = {
            "schema_version": 1,
            "store_id": self.store_id,
            "previous_anchor_sha256": previous_digest,
            "next_anchor_sha256": self._anchor_document_sha256(candidate),
            "next_anchor": candidate,
        }
        transition = {
            **unsigned_transition,
            "transition_hmac_sha256": self._transition_hmac(unsigned_transition),
        }
        self._write_json_atomically(self.authentication_pending_path, transition)
        return True

    def _promote_staged_authentication_anchor(self) -> None:
        if self.authentication_key is None:
            return
        transition = self._load_authentication_transition()
        candidate = dict(transition["next_anchor"])
        current_digest = ""
        if self.authentication_anchor_path.exists():
            current_digest = self._anchor_document_sha256(
                self._load_authentication_anchor_document()
            )
        if current_digest != transition["previous_anchor_sha256"]:
            raise RuntimeError(
                "Authenticated checkpoint changed before its unique successor was promoted."
            )
        if not self._document_matches_database(
            candidate, exhaustive_operational=False
        ):
            raise RuntimeError(
                "Authenticated checkpoint successor does not match the committed database."
            )
        self._write_authentication_anchor_document(candidate)
        self._remove_pending_authentication_transition()

    def _install_incremental_authentication(self) -> None:
        staged = False
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            self._create_incremental_authentication_schema(db)
            staged = self._stage_authentication_anchor(db)
        if staged:
            self._promote_staged_authentication_anchor()

    def _verify_authentication_head_locked(
        self, db: sqlite3.Connection | None = None
    ) -> int:
        if self.authentication_key is None:
            return AUTHENTICATION_INVENTORY_SCHEMA_VERSION
        self._recover_authentication_transition_locked()
        expected = self._load_authentication_anchor()
        schema_version = int(expected["schema_version"])
        actual = self._authentication_inventory(
            schema_version=schema_version,
            exhaustive_operational=(
                schema_version < AUTHENTICATION_INVENTORY_SCHEMA_VERSION
            ),
            db=db,
        )
        if expected != actual:
            raise RuntimeError(
                "Persistent state differs from its authenticated external checkpoint; "
                "refusing automatic repair or broker mutation."
            )
        return schema_version

    def _verify_authentication_head(self) -> int:
        with self._authentication_write_lock():
            return self._verify_authentication_head_locked()

    @contextmanager
    def _authenticated_read_connection(self) -> Iterator[sqlite3.Connection]:
        """Read one SQLite snapshot after a bounded authenticated-head check."""

        with self._authentication_write_lock():
            if self.authentication_key is not None:
                self._recover_authentication_transition_locked()
            with self.connection() as db:
                db.execute("BEGIN")
                if self.authentication_key is not None:
                    self._verify_authentication_head_locked(db)
                yield db

    @contextmanager
    def _authenticated_write_transaction(self) -> Iterator[sqlite3.Connection]:
        """Commit SQLite and its unique authenticated successor crash-safely.

        The keyed pending transition is durably installed before SQLite commits.
        Recovery can therefore identify exactly one permissible successor without
        accepting an arbitrary re-anchor after a crash.
        """

        staged = False
        with self._authentication_write_lock():
            if self.authentication_key is not None:
                self._recover_authentication_transition_locked()
            with self.connection() as db:
                db.execute("BEGIN IMMEDIATE")
                if self.authentication_key is not None:
                    self._verify_authentication_head_locked(db)
                yield db
                if self.authentication_key is not None:
                    staged = self._stage_authentication_anchor(db)
            if staged:
                self._promote_staged_authentication_anchor()

    def _verify_operational_rows(
        self,
        db: sqlite3.Connection,
        table: str,
        rows: Iterable[sqlite3.Row | dict[str, Any]],
    ) -> None:
        """Verify only the operational rows returned by a bounded application query."""

        if self.authentication_key is None:
            return
        if table not in _OPERATIONAL_AUTHENTICATION_COLUMNS:
            raise ValueError(f"Unknown operational table {table!r}.")
        materialized = list(rows)
        expected: dict[str, str] = {}
        for row in materialized:
            row_key = self._operational_row_key(table, row)
            if row_key in expected:
                raise RuntimeError(
                    f"Persistent {table} history contains a duplicate logical row key."
                )
            expected[row_key] = self._operational_row_hmac(table, row)
        if not expected:
            return
        placeholders = ",".join("?" for _ in expected)
        supplied = {
            str(row["row_key"]): str(row["row_hmac_sha256"])
            for row in db.execute(
                f"SELECT row_key, row_hmac_sha256 "
                f"FROM {_OPERATIONAL_AUTHENTICATION_ROWS_TABLE} "
                f"WHERE table_name = ? AND row_key IN ({placeholders})",
                (table, *expected),
            ).fetchall()
        }
        if set(supplied) != set(expected) or any(
            not hmac.compare_digest(expected[row_key], supplied[row_key])
            for row_key in expected
        ):
            raise RuntimeError(
                f"Persistent {table} row differs from its authenticated row index; "
                "external checkpoint verification failed."
            )

    def _update_operational_authentication(
        self,
        db: sqlite3.Connection,
        table: str,
        prior: sqlite3.Row | dict[str, Any] | None,
        current: sqlite3.Row | dict[str, Any] | None,
    ) -> None:
        """Advance one table head after exactly one trigger-observed row mutation."""

        if self.authentication_key is None:
            return
        if prior is None and current is None:
            raise ValueError("An operational authentication update needs a row mutation.")
        prior_key = self._operational_row_key(table, prior) if prior is not None else None
        current_key = (
            self._operational_row_key(table, current) if current is not None else None
        )
        keys = tuple(dict.fromkeys(key for key in (prior_key, current_key) if key is not None))
        placeholders = ",".join("?" for _ in keys)
        supplied = {
            str(row["row_key"]): str(row["row_hmac_sha256"])
            for row in db.execute(
                f"SELECT row_key, row_hmac_sha256 "
                f"FROM {_OPERATIONAL_AUTHENTICATION_ROWS_TABLE} "
                f"WHERE table_name = ? AND row_key IN ({placeholders})",
                (table, *keys),
            ).fetchall()
        }
        prior_hmac = self._operational_row_hmac(table, prior) if prior is not None else None
        current_hmac = (
            self._operational_row_hmac(table, current) if current is not None else None
        )
        if prior_key is None:
            if current_key in supplied:
                raise RuntimeError(
                    f"Authenticated {table} row index contains an unexpected existing key."
                )
        elif prior_key not in supplied or not hmac.compare_digest(
            str(prior_hmac), supplied[prior_key]
        ):
            raise RuntimeError(
                f"Persistent {table} row differs from its authenticated row index; "
                "external checkpoint verification failed."
            )
        if current_key != prior_key and current_key in supplied:
            raise RuntimeError(
                f"Authenticated {table} row index contains a conflicting logical key."
            )

        head = db.execute(
            f"SELECT row_count, rows_xor_hmac_sha256, mutation_sequence, dirty_sequence "
            f"FROM {_OPERATIONAL_AUTHENTICATION_STATE_TABLE} WHERE table_name = ?",
            (table,),
        ).fetchone()
        if head is None or int(head["dirty_sequence"]) != int(
            head["mutation_sequence"]
        ) + 1:
            raise RuntimeError(
                f"Persistent {table} mutation count differs from its authenticated head; "
                "external checkpoint verification failed."
            )
        row_count = int(head["row_count"])
        accumulator = str(head["rows_xor_hmac_sha256"])
        if prior_hmac is not None:
            accumulator = self._xor_sha256(accumulator, prior_hmac)
            row_count -= 1
            db.execute(
                f"DELETE FROM {_OPERATIONAL_AUTHENTICATION_ROWS_TABLE} "
                "WHERE table_name = ? AND row_key = ?",
                (table, prior_key),
            )
        if current_hmac is not None:
            accumulator = self._xor_sha256(accumulator, current_hmac)
            row_count += 1
            db.execute(
                f"INSERT INTO {_OPERATIONAL_AUTHENTICATION_ROWS_TABLE}"
                "(table_name, row_key, row_hmac_sha256) VALUES (?, ?, ?)",
                (table, current_key, current_hmac),
            )
        if row_count < 0:
            raise RuntimeError("Authenticated operational row count became invalid.")
        db.execute(
            f"UPDATE {_OPERATIONAL_AUTHENTICATION_STATE_TABLE} "
            "SET row_count = ?, rows_xor_hmac_sha256 = ?, "
            "mutation_sequence = dirty_sequence WHERE table_name = ?",
            (row_count, accumulator, table),
        )

    def verify_authentication_anchor(self) -> int:
        """Exhaustively detect deletion, rewrite, replay, or lifecycle tampering."""

        if self.authentication_key is None:
            return AUTHENTICATION_INVENTORY_SCHEMA_VERSION
        with self._authentication_write_lock():
            self._recover_authentication_transition_locked()
            expected = self._load_authentication_anchor()
            schema_version = int(expected["schema_version"])
            actual = self._authentication_inventory(
                schema_version=schema_version,
                exhaustive_operational=True,
            )
            if expected != actual:
                raise RuntimeError(
                    "Persistent state differs from its authenticated external checkpoint; "
                    "refusing automatic repair or broker mutation."
                )
            return schema_version

    def _upgrade_authentication_anchor(self, from_schema: int) -> None:
        """Migrate only a previously verified legacy checkpoint under the file lock."""

        if from_schema not in (1, _LEGACY_OPERATIONAL_AUTHENTICATION_SCHEMA_VERSION):
            raise RuntimeError(
                f"Unsupported authenticated state checkpoint migration {from_schema} -> "
                f"{AUTHENTICATION_INVENTORY_SCHEMA_VERSION}."
            )
        if from_schema == 1:
            with self.connection() as db:
                nonempty = sorted(
                    table
                    for table in _OPERATIONAL_AUTHENTICATION_COLUMNS
                    if db.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone()
                    is not None
                )
            if nonempty:
                raise RuntimeError(
                    "Authenticated state checkpoint schema 1 predates operational-table "
                    "authentication and the database contains unauthenticated history in: "
                    + ", ".join(nonempty)
                    + ". Refusing to bless it automatically; perform an explicit audited "
                    "offline migration before enabling broker mutation."
                )
        self._install_incremental_authentication()

    def verify_critical_integrity(self) -> None:
        """Verify the external tail plus the complete authenticated equity chain."""

        self.verify_authentication_anchor()
        self._verify_equity_chain()

    def set_state(self, key: str, value: Any) -> None:
        serialized = json.dumps(value, default=str, sort_keys=True)
        value_mac = self._state_mac(key, serialized) if self.authentication_key else ""
        now = _utc_now().isoformat()
        with self._authenticated_write_transaction() as db:
            db.execute(
                """
                INSERT INTO state(key, value, value_mac, updated_at) VALUES (?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value=excluded.value,
                    value_mac=excluded.value_mac, updated_at=excluded.updated_at
                """,
                (key, serialized, value_mac, now),
            )

    def atomic_authenticated_state_update(
        self,
        key: str,
        update: Callable[[Any | None], Any],
    ) -> Any:
        """Authenticate, compare, and update one state value in one transaction.

        Monotonic evidence anchors must not implement their comparison as a public
        ``get_state`` followed by ``set_state``: another process can advance the
        anchor between those calls and then be overwritten by the older candidate.
        This helper holds the cross-process authentication lock and a SQLite
        ``BEGIN IMMEDIATE`` transaction across the authenticated read, policy
        callback, and conditional write.  The external checkpoint is replaced only
        after SQLite commits.

        The callback is trusted in-process policy code.  It receives ``None`` when
        the key is absent and must return a JSON-serializable replacement value.
        Returning a value with identical canonical serialization is a no-op.
        """

        if self.authentication_key is None:
            raise RuntimeError(
                "Atomic authenticated state updates require a state authentication key."
            )
        if not isinstance(key, str) or not key:
            raise ValueError("Authenticated state key must be a non-empty string.")
        if not callable(update):
            raise TypeError("Authenticated state update policy must be callable.")

        replacement: Any = None
        with self._authenticated_write_transaction() as db:
            row = db.execute(
                "SELECT value, value_mac FROM state WHERE key = ?", (key,)
            ).fetchone()
            prior: Any | None = None
            prior_serialized: str | None = None
            if row is not None:
                prior_serialized = str(row["value"])
                expected = self._state_mac(key, prior_serialized)
                supplied = str(row["value_mac"] or "")
                if not hmac.compare_digest(expected, supplied):
                    raise ValueError(
                        f"Persisted state {key!r} failed keyed authentication."
                    )
                try:
                    prior = json.loads(prior_serialized)
                except (TypeError, json.JSONDecodeError) as exc:
                    raise ValueError(
                        f"Persisted state {key!r} contains invalid JSON."
                    ) from exc

            replacement = update(prior)
            serialized = json.dumps(replacement, default=str, sort_keys=True)
            if prior_serialized != serialized:
                now = _utc_now().isoformat()
                value_mac = self._state_mac(key, serialized)
                db.execute(
                    """
                    INSERT INTO state(key, value, value_mac, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value,
                        value_mac=excluded.value_mac, updated_at=excluded.updated_at
                    """,
                    (key, serialized, value_mac, now),
                )
        return replacement

    def get_state(self, key: str, default: Any = None) -> Any:
        with self._authenticated_read_connection() as db:
            row = db.execute(
                "SELECT value, value_mac FROM state WHERE key = ?", (key,)
            ).fetchone()
        if row is None:
            return default
        if self.authentication_key is not None:
            expected = self._state_mac(key, str(row["value"]))
            supplied = str(row["value_mac"] or "")
            if not hmac.compare_digest(expected, supplied):
                raise ValueError(
                    f"Persisted state {key!r} failed keyed authentication."
                )
        try:
            return json.loads(row["value"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError(
                f"Persisted state {key!r} contains invalid JSON; refusing a default."
            ) from exc

    @staticmethod
    def _normalized_covariance_evidence_anchor(
        provenance: Any,
    ) -> dict[str, str]:
        if not isinstance(provenance, dict):
            raise ValueError("Covariance evidence provenance must be an object.")
        required = {
            "latest_session",
            "issued_at",
            "snapshot_id",
            "payload_sha256",
        }
        if not required.issubset(provenance):
            raise ValueError(
                "Covariance evidence provenance is missing anti-rollback fields."
            )
        latest_raw = provenance.get("latest_session")
        if not isinstance(latest_raw, str):
            raise ValueError("Covariance evidence latest_session is invalid.")
        try:
            latest = date.fromisoformat(latest_raw)
        except ValueError as exc:
            raise ValueError("Covariance evidence latest_session is invalid.") from exc
        if latest.isoformat() != latest_raw:
            raise ValueError("Covariance evidence latest_session is not canonical.")

        issued_raw = provenance.get("issued_at")
        if not isinstance(issued_raw, str):
            raise ValueError("Covariance evidence issued_at is invalid.")
        try:
            issued = datetime.fromisoformat(issued_raw.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("Covariance evidence issued_at is invalid.") from exc
        if issued.tzinfo is None or issued.utcoffset() is None:
            raise ValueError("Covariance evidence issued_at must be timezone-aware.")
        issued_utc = issued.astimezone(timezone.utc).isoformat()

        snapshot_id = provenance.get("snapshot_id")
        if (
            not isinstance(snapshot_id, str)
            or not 8 <= len(snapshot_id) <= 128
            or any(character.isspace() for character in snapshot_id)
        ):
            raise ValueError("Covariance evidence snapshot_id is invalid.")
        payload_sha256 = provenance.get("payload_sha256")
        if (
            not isinstance(payload_sha256, str)
            or len(payload_sha256) != 64
            or any(character not in "0123456789abcdef" for character in payload_sha256)
        ):
            raise ValueError("Covariance evidence payload_sha256 is invalid.")
        return {
            "latest_session": latest.isoformat(),
            "issued_at": issued_utc,
            "snapshot_id": snapshot_id,
            "payload_sha256": payload_sha256,
        }

    def anchor_covariance_evidence(self, provenance: dict[str, Any]) -> dict[str, str]:
        """Atomically reject signed-snapshot rollback and authenticate the new anchor."""

        if self.authentication_key is None:
            raise RuntimeError(
                "Covariance evidence anti-rollback requires authenticated StateStore state."
            )
        candidate = self._normalized_covariance_evidence_anchor(provenance)
        key = self.COVARIANCE_EVIDENCE_ANCHOR_KEY
        serialized = json.dumps(candidate, default=str, sort_keys=True)
        value_mac = self._state_mac(key, serialized)
        now = _utc_now().isoformat()
        changed = True
        with self._authenticated_write_transaction() as db:
            row = db.execute(
                "SELECT value, value_mac FROM state WHERE key = ?", (key,)
            ).fetchone()
            if row is not None:
                prior_serialized = str(row["value"])
                if not hmac.compare_digest(
                    self._state_mac(key, prior_serialized),
                    str(row["value_mac"] or ""),
                ):
                    raise ValueError(
                        "Persisted covariance evidence anchor failed keyed authentication."
                    )
                try:
                    prior = self._normalized_covariance_evidence_anchor(
                        json.loads(prior_serialized)
                    )
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise ValueError(
                        "Persisted covariance evidence anchor is invalid."
                    ) from exc
                candidate_session = date.fromisoformat(candidate["latest_session"])
                prior_session = date.fromisoformat(prior["latest_session"])
                candidate_issued = datetime.fromisoformat(candidate["issued_at"])
                prior_issued = datetime.fromisoformat(prior["issued_at"])
                if candidate_session < prior_session or (
                    candidate_session == prior_session
                    and candidate_issued < prior_issued
                ):
                    raise RuntimeError(
                        "Signed covariance evidence rollback was rejected by the "
                        "authenticated monotonic anchor."
                    )
                if (
                    candidate_session == prior_session
                    and candidate_issued == prior_issued
                    and (
                        not hmac.compare_digest(
                            candidate["payload_sha256"], prior["payload_sha256"]
                        )
                        or not hmac.compare_digest(
                            candidate["snapshot_id"], prior["snapshot_id"]
                        )
                    )
                ):
                    raise RuntimeError(
                        "Signed covariance evidence reused an issue time with "
                        "different payload identity."
                    )
                changed = candidate != prior
            if changed:
                db.execute(
                    """
                    INSERT INTO state(key, value, value_mac, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value,
                        value_mac=excluded.value_mac, updated_at=excluded.updated_at
                    """,
                    (key, serialized, value_mac, now),
                )
        return candidate

    def _state_mac(self, key: str, serialized: str) -> str:
        if self.authentication_key is None:
            return ""
        message = b"state-v1\0" + key.encode("utf-8") + b"\0" + serialized.encode("utf-8")
        return hmac.new(self.authentication_key, message, hashlib.sha256).hexdigest()

    def _equity_row_mac(self, row: sqlite3.Row | dict[str, Any]) -> str:
        if self.authentication_key is None:
            return ""
        fields = (
            "timestamp",
            "session_date",
            "equity",
            "cash",
            "buying_power",
            "drawdown",
            "daily_return",
            "five_day_return",
        )
        payload = json.dumps(
            [row[field] for field in fields],
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(
            self.authentication_key,
            b"equity-v1\0" + payload,
            hashlib.sha256,
        ).hexdigest()

    def _verify_equity_row(self, row: sqlite3.Row) -> None:
        if self.authentication_key is None:
            return
        expected = self._equity_row_mac(row)
        supplied = str(row["row_mac"] or "")
        if not hmac.compare_digest(expected, supplied):
            raise ValueError("Persisted equity snapshot failed keyed authentication.")

    def _equity_chain_mac(
        self, row_id: int, row_mac: str, previous_chain_mac: str
    ) -> str:
        if self.authentication_key is None:
            return ""
        message = (
            b"equity-chain-v1\0"
            + str(int(row_id)).encode("ascii")
            + b"\0"
            + previous_chain_mac.encode("ascii")
            + b"\0"
            + row_mac.encode("ascii")
        )
        return hmac.new(self.authentication_key, message, hashlib.sha256).hexdigest()

    def _verify_equity_chain(self) -> None:
        if self.authentication_key is None:
            return
        with self.connection() as db:
            rows = db.execute(
                "SELECT * FROM equity_snapshots ORDER BY id"
            ).fetchall()
        previous = ""
        for row in rows:
            self._verify_equity_row(row)
            expected = self._equity_chain_mac(
                int(row["id"]), str(row["row_mac"]), previous
            )
            supplied = str(row["chain_mac"] or "")
            if not hmac.compare_digest(expected, supplied):
                raise ValueError("Persisted equity history chain failed authentication.")
            previous = supplied

    def _plan_lifecycle_mac(
        self,
        row: sqlite3.Row | dict[str, Any],
        *,
        store_id: str | None = None,
    ) -> str:
        if self.authentication_key is None:
            return ""
        payload = json.dumps(
            [
                store_id or self.store_id,
                str(row["plan_id"]),
                str(row["status"]),
                row["executed_at"],
                str(row["execution_message"] or ""),
                int(row["lifecycle_sequence"]),
            ],
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(
            self.authentication_key,
            b"plan-lifecycle-v1\0" + payload,
            hashlib.sha256,
        ).hexdigest()

    def _verify_plan_lifecycle_row(self, row: sqlite3.Row) -> None:
        if self.authentication_key is None:
            return
        expected = self._plan_lifecycle_mac(row)
        supplied = str(row["lifecycle_mac"] or "")
        if not hmac.compare_digest(expected, supplied):
            raise ValueError(
                f"Persisted plan {row['plan_id']!s} lifecycle failed keyed authentication."
            )

    @staticmethod
    def _validate_plan_transition(current: str, requested: str) -> None:
        statuses = {
            "approved",
            "previewed",
            "partial",
            "executing",
            "executed",
            "dry_run",
            "failed",
            "halted",
            "expired",
        }
        if requested not in statuses:
            raise ValueError(f"Unsupported plan lifecycle status {requested!r}.")
        if current == requested:
            return
        allowed = {
            "approved": {"previewed", "executing", "dry_run", "failed", "halted", "expired"},
            "previewed": {"executing", "dry_run", "failed", "halted", "expired"},
            "partial": {"executing", "failed", "halted", "expired"},
            "executing": {"executed", "partial", "failed", "halted"},
            "executed": set(),
            "dry_run": set(),
            "failed": set(),
            "halted": set(),
            "expired": set(),
        }
        if current not in allowed or requested not in allowed[current]:
            raise ValueError(
                f"Plan lifecycle transition {current!r} -> {requested!r} is forbidden."
            )

    @staticmethod
    def _cash_activity_records(
        activities: tuple[CashActivity, ...],
    ) -> dict[str, dict[str, Any]]:
        records: dict[str, dict[str, Any]] = {}
        for activity in activities:
            if activity.activity_id in records:
                raise ValueError("Cash-activity evidence contains duplicate IDs.")
            records[activity.activity_id] = activity.to_dict()
        return records

    def cash_activity_monitor_state(self) -> dict[str, Any] | None:
        raw = self.get_state(self.CASH_ACTIVITY_MONITOR_KEY, _MISSING_STATE)
        if raw is _MISSING_STATE:
            return None
        if (
            not isinstance(raw, dict)
            or raw.get("version") != 1
            or not isinstance(raw.get("initialized"), bool)
            or not isinstance(raw.get("incident_active"), bool)
            or not isinstance(raw.get("activities"), dict)
            or not isinstance(raw.get("incident_activity_ids", []), list)
        ):
            raise ValueError("Persisted cash-activity monitor state is invalid.")
        for activity_id, record in raw["activities"].items():
            if (
                not isinstance(activity_id, str)
                or not activity_id
                or not isinstance(record, dict)
                or record.get("activity_id") != activity_id
            ):
                raise ValueError("Persisted cash-activity records are invalid.")
        return raw

    def initialize_cash_activity_monitor(
        self,
        activities: tuple[CashActivity, ...],
    ) -> None:
        """Establish a reviewed baseline while broker execution is disabled."""

        prior = self.cash_activity_monitor_state()
        if prior is not None and (
            prior.get("initialized")
            or prior.get("incident_reason") != "cash_activity_monitor_uninitialized"
        ):
            raise RuntimeError("Cash-activity monitoring is already initialized.")
        now = _utc_now().isoformat()
        self.set_state(
            self.CASH_ACTIVITY_MONITOR_KEY,
            {
                "version": 1,
                "initialized": True,
                "initialized_at": now,
                "incident_active": False,
                "incident_detected_at": None,
                "incident_activity_ids": [],
                "activities": self._cash_activity_records(activities),
            },
        )

    def record_cash_activity_incident(
        self,
        activities: tuple[CashActivity, ...],
        incident_activity_ids: list[str],
        *,
        reason: str,
    ) -> None:
        """Persist cash evidence and a non-resumable reconciliation incident."""

        prior = self.cash_activity_monitor_state()
        now = _utc_now().isoformat()
        prior_ids = (
            list(prior.get("incident_activity_ids", [])) if prior is not None else []
        )
        combined_ids = sorted(
            {
                str(value)
                for value in prior_ids + list(incident_activity_ids)
                if str(value)
            }
        )
        self.set_state(
            self.CASH_ACTIVITY_MONITOR_KEY,
            {
                "version": 1,
                "initialized": bool(prior and prior.get("initialized")),
                "initialized_at": prior.get("initialized_at") if prior else None,
                "incident_active": True,
                "incident_detected_at": (
                    prior.get("incident_detected_at") if prior else None
                )
                or now,
                "incident_reason": reason,
                "incident_activity_ids": combined_ids,
                "activities": self._cash_activity_records(activities),
            },
        )

    @staticmethod
    def _validated_halt_state(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict) or not isinstance(value.get("active"), bool):
            raise ValueError("Persisted halt state is semantically invalid.")
        if value["active"] and (
            not isinstance(value.get("reason"), str)
            or not value["reason"].strip()
            or not isinstance(value.get("flatten"), bool)
        ):
            raise ValueError("Active persisted halt state is semantically invalid.")
        return dict(value)

    def request_halt(self, reason: str, flatten: bool = True) -> None:
        # Serialize read/modify/write across processes. Without BEGIN IMMEDIATE, a
        # simultaneous halt-only writer could overwrite a just-persisted flatten.
        now = _utc_now().isoformat()
        staged = False
        with self._authentication_write_lock():
            checkpoint_halt_only_mismatch = False
            if self.authentication_key is not None:
                self._recover_authentication_transition_locked()
            with self.connection() as db:
                db.execute("BEGIN IMMEDIATE")
                if self.authentication_key is not None:
                    try:
                        self._verify_authentication_head_locked(db)
                    except RuntimeError:
                        expected_inventory = self._load_authentication_anchor()
                        actual_inventory = self._authentication_inventory(
                            exhaustive_operational=True, db=db
                        )
                        expected_states = expected_inventory["state_macs"]
                        actual_states = actual_inventory["state_macs"]
                        differing_state_keys = {
                            key
                            for key in set(expected_states).union(actual_states)
                            if expected_states.get(key) != actual_states.get(key)
                        }
                        expected_nonstate = dict(expected_inventory)
                        actual_nonstate = dict(actual_inventory)
                        expected_nonstate.pop("state_macs", None)
                        actual_nonstate.pop("state_macs", None)
                        checkpoint_halt_only_mismatch = (
                            differing_state_keys <= {"halt"}
                            and expected_nonstate == actual_nonstate
                        )
                        if not checkpoint_halt_only_mismatch:
                            # Never bless rollback/deletion of other risk or lifecycle
                            # records merely because a halt write was requested.
                            raise
                row = db.execute(
                    "SELECT value, value_mac FROM state WHERE key = 'halt'"
                ).fetchone()
                prior_state_invalid = checkpoint_halt_only_mismatch
                if checkpoint_halt_only_mismatch:
                    current = {}
                    flatten = True
                elif row is None:
                    current: dict[str, Any] = {}
                else:
                    try:
                        if self.authentication_key is not None:
                            expected_mac = self._state_mac("halt", str(row["value"]))
                            if not hmac.compare_digest(
                                expected_mac, str(row["value_mac"] or "")
                            ):
                                raise ValueError(
                                    "Persisted halt state failed keyed authentication."
                                )
                        current = self._validated_halt_state(json.loads(row["value"]))
                    except (TypeError, ValueError, json.JSONDecodeError):
                        # Corruption must not prevent a replacement emergency control.
                        current = {}
                        prior_state_invalid = True
                        flatten = True
                active = bool(current.get("active", False))
                payload = {
                    "active": True,
                    "reason": reason,
                    # A mandatory liquidation is monotonic for the life of an incident.
                    # A later halt-only request must never downgrade it.
                    "flatten": bool(flatten) or (active and bool(current.get("flatten"))),
                    "timestamp": current.get("timestamp", now) if active else now,
                    "updated_at": now,
                    "incident_id": (
                        current.get("incident_id")
                        if active and current.get("incident_id")
                        else uuid.uuid4().hex[:16]
                    ),
                    "recovered_invalid_prior_state": prior_state_invalid,
                }
                serialized = json.dumps(payload, sort_keys=True)
                value_mac = (
                    self._state_mac("halt", serialized)
                    if self.authentication_key is not None
                    else ""
                )
                db.execute(
                    """
                    INSERT INTO state(key, value, value_mac, updated_at)
                    VALUES ('halt', ?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET value=excluded.value,
                        value_mac=excluded.value_mac, updated_at=excluded.updated_at
                    """,
                    (serialized, value_mac, now),
                )
                if self.authentication_key is not None:
                    staged = self._stage_authentication_anchor(db)
            if staged:
                self._promote_staged_authentication_anchor()

    def clear_halt(self) -> None:
        self.set_state(
            "halt",
            {"active": False, "reason": "manual_resume", "timestamp": _utc_now().isoformat()},
        )

    def clear_halt_if_unchanged(self, expected_payload: dict[str, Any]) -> bool:
        """Clear exactly the halt incident the caller reviewed, never a newer one."""

        if self.authentication_key is None:
            raise RuntimeError(
                "Compare-and-clear halt requires an authenticated StateStore."
            )
        expected = self._validated_halt_state(expected_payload)
        if not expected.get("active"):
            raise ValueError("Compare-and-clear halt requires an active expected payload.")
        with self._authenticated_write_transaction() as db:
            row = db.execute(
                "SELECT value, value_mac FROM state WHERE key = 'halt'"
            ).fetchone()
            if row is None:
                return False
            serialized = str(row["value"])
            if not hmac.compare_digest(
                self._state_mac("halt", serialized), str(row["value_mac"] or "")
            ):
                raise ValueError("Persisted halt state failed keyed authentication.")
            try:
                current = self._validated_halt_state(json.loads(serialized))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ValueError("Persisted halt state is invalid.") from exc
            if current != expected:
                return False
            replacement = {
                "active": False,
                "reason": "manual_resume",
                "timestamp": _utc_now().isoformat(),
            }
            replacement_serialized = json.dumps(replacement, sort_keys=True)
            db.execute(
                "UPDATE state SET value = ?, value_mac = ?, updated_at = ? "
                "WHERE key = 'halt'",
                (
                    replacement_serialized,
                    self._state_mac("halt", replacement_serialized),
                    replacement["timestamp"],
                ),
            )
            return True

    def cooldown_remaining(self) -> int:
        raw = self.get_state("cooldown_remaining", _MISSING_STATE)
        if raw is _MISSING_STATE:
            return 0
        if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
            raise ValueError("Persisted cooldown state must be a non-negative integer.")
        return raw

    def high_watermark_state(self) -> float | None:
        raw = self.get_state("high_watermark", _MISSING_STATE)
        if raw is _MISSING_STATE:
            return None
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise ValueError("Persisted high-water mark must be a positive finite number.")
        value = float(raw)
        if not math.isfinite(value) or value <= 0.0:
            raise ValueError("Persisted high-water mark must be a positive finite number.")
        return value

    def flatten_attempt_state(self) -> dict[str, Any] | None:
        current = self.get_state("flatten_attempt", _MISSING_STATE)
        if current is _MISSING_STATE:
            return None
        if (
            not isinstance(current, dict)
            or current.get("status") not in {"in_progress", "completed", "failed"}
            or not isinstance(current.get("attempt_id"), str)
            or not current["attempt_id"].strip()
            or not isinstance(current.get("reason"), str)
            or not current["reason"].strip()
            or not isinstance(current.get("started_at"), str)
            or not current["started_at"].strip()
        ):
            raise ValueError("Persisted flatten-attempt state is semantically invalid.")
        return dict(current)

    def begin_flatten_attempt(self, reason: str) -> str:
        """Return a crash-safe ID for one portfolio-flatten attempt.

        An in-progress ID is reused after a process restart so broker client-order IDs
        remain idempotent. Completed or failed attempts receive a new ID, allowing the
        bot to flatten positions that were reopened during an existing halt.
        """
        current = self.flatten_attempt_state() or {}
        if (
            isinstance(current, dict)
            and current.get("status") == "in_progress"
            and current.get("attempt_id")
        ):
            return str(current["attempt_id"])
        attempt_id = uuid.uuid4().hex[:16]
        self.set_state(
            "flatten_attempt",
            {
                "attempt_id": attempt_id,
                "reason": reason,
                "status": "in_progress",
                "started_at": _utc_now().isoformat(),
            },
        )
        return attempt_id

    def finish_flatten_attempt(
        self,
        attempt_id: str,
        status: str,
        message: str = "",
    ) -> None:
        current = self.flatten_attempt_state()
        if current is None:
            return
        if current.get("attempt_id") != attempt_id:
            return
        current = dict(current)
        current.update(
            {
                "status": status,
                "message": message,
                "finished_at": _utc_now().isoformat(),
            }
        )
        self.set_state("flatten_attempt", current)

    def finish_active_flatten_attempt(self, status: str, message: str = "") -> None:
        current = self.flatten_attempt_state()
        if current is None:
            return
        if (
            current.get("status") == "in_progress"
            and current.get("attempt_id")
        ):
            self.finish_flatten_attempt(str(current["attempt_id"]), status, message)

    def halt_state(self) -> dict[str, Any]:
        value = self.get_state("halt", _MISSING_STATE)
        if value is _MISSING_STATE:
            return {}
        return self._validated_halt_state(value)

    def is_halted(self) -> bool:
        return bool(self.halt_state().get("active", False))

    def start_run(self, kind: str, payload: dict[str, Any] | None = None) -> str:
        run_id = str(uuid.uuid4())
        with self._authenticated_write_transaction() as db:
            db.execute(
                "INSERT INTO runs(run_id, kind, started_at, status, payload_json) VALUES (?, ?, ?, ?, ?)",
                (
                    run_id,
                    kind,
                    _utc_now().isoformat(),
                    "running",
                    json.dumps(payload or {}, default=str),
                ),
            )
            current = db.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            self._update_operational_authentication(db, "runs", None, current)
        return run_id

    def finish_run(
        self,
        run_id: str,
        status: str,
        message: str = "",
        payload: dict[str, Any] | None = None,
    ) -> None:
        with self._authenticated_write_transaction() as db:
            prior = db.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if prior is None:
                raise KeyError(f"Unknown run {run_id!r}.")
            db.execute(
                """
                UPDATE runs
                SET ended_at = ?, status = ?, message = ?, payload_json = ?
                WHERE run_id = ?
                """,
                (
                    _utc_now().isoformat(),
                    status,
                    message,
                    json.dumps(payload or {}, default=str),
                    run_id,
                ),
            )
            current = db.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            self._update_operational_authentication(db, "runs", prior, current)

    def record_event(
        self,
        level: str,
        code: str,
        message: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        with self._authenticated_write_transaction() as db:
            cursor = db.execute(
                "INSERT INTO events(timestamp, level, code, message, payload_json) VALUES (?, ?, ?, ?, ?)",
                (
                    _utc_now().isoformat(),
                    level.upper(),
                    code,
                    message,
                    json.dumps(payload or {}, default=str, sort_keys=True),
                ),
            )
            current = db.execute(
                "SELECT * FROM events WHERE id = ?", (int(cursor.lastrowid),)
            ).fetchone()
            self._update_operational_authentication(db, "events", None, current)

    def update_high_watermark(self, equity: float) -> float:
        existing = self.high_watermark_state() or 0.0
        high = max(existing, float(equity))
        if high != existing:
            self.set_state("high_watermark", high)
        return high

    def reset_high_watermark(self, equity: float) -> None:
        value = float(equity)
        if not math.isfinite(value) or value <= 0.0:
            raise ValueError("High-water mark must be a positive finite number.")
        self.set_state("high_watermark", value)

    def get_session_open_equity(self, session_date: date) -> float | None:
        self._verify_authentication_head()
        self._verify_equity_chain()
        with self.connection() as db:
            row = db.execute(
                """
                SELECT * FROM equity_snapshots
                WHERE session_date = ? ORDER BY timestamp ASC LIMIT 1
                """,
                (session_date.isoformat(),),
            ).fetchone()
        if row is None:
            return None
        self._verify_equity_row(row)
        equity = float(row["equity"])
        daily_return = float(row["daily_return"])
        denominator = 1.0 + daily_return
        if (
            not math.isfinite(equity)
            or equity <= 0.0
            or not math.isfinite(daily_return)
            or denominator <= 0.0
        ):
            raise ValueError("Earliest session snapshot cannot reconstruct a valid open equity.")
        session_open = equity / denominator
        if not math.isfinite(session_open) or session_open <= 0.0:
            raise ValueError("Reconstructed session-open equity is invalid.")
        return session_open

    def get_daily_closing_equities(self, limit: int = 6) -> list[float]:
        self._verify_authentication_head()
        self._verify_equity_chain()
        with self.connection() as db:
            rows = db.execute(
                """
                SELECT e.*
                FROM equity_snapshots e
                JOIN (
                    SELECT session_date, MAX(timestamp) AS max_timestamp
                    FROM equity_snapshots GROUP BY session_date
                ) latest
                ON e.session_date = latest.session_date AND e.timestamp = latest.max_timestamp
                ORDER BY e.session_date DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        for row in rows:
            self._verify_equity_row(row)
        return [float(row["equity"]) for row in reversed(rows)]

    def get_daily_closing_equities_before(
        self, session_date: date, limit: int = 5
    ) -> list[float]:
        """Return the latest completed session closes strictly before session_date."""
        self._verify_authentication_head()
        self._verify_equity_chain()
        with self.connection() as db:
            rows = db.execute(
                """
                SELECT e.*
                FROM equity_snapshots e
                JOIN (
                    SELECT session_date, MAX(timestamp) AS max_timestamp
                    FROM equity_snapshots
                    WHERE session_date < ?
                    GROUP BY session_date
                ) latest
                ON e.session_date = latest.session_date AND e.timestamp = latest.max_timestamp
                ORDER BY e.session_date DESC LIMIT ?
                """,
                (session_date.isoformat(), limit),
            ).fetchall()
        for row in rows:
            self._verify_equity_row(row)
        return [float(row["equity"]) for row in reversed(rows)]

    def record_equity(
        self,
        account: AccountSnapshot,
        session_date: date,
        drawdown: float,
        daily_return: float,
        five_day_return: float,
    ) -> None:
        values: dict[str, Any] = {
            "timestamp": account.timestamp.isoformat(),
            "session_date": session_date.isoformat(),
            "equity": float(account.equity),
            "cash": float(account.cash),
            "buying_power": float(account.buying_power),
            "drawdown": float(drawdown),
            "daily_return": float(daily_return),
            "five_day_return": float(five_day_return),
        }
        row_mac = self._equity_row_mac(values)
        with self._authenticated_write_transaction() as db:
            previous = db.execute(
                "SELECT chain_mac FROM equity_snapshots ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous_chain = str(previous["chain_mac"] or "") if previous else ""
            cursor = db.execute(
                """
                INSERT INTO equity_snapshots(
                    timestamp, session_date, equity, cash, buying_power,
                    drawdown, daily_return, five_day_return, row_mac, chain_mac
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '')
                """,
                (
                    values["timestamp"],
                    values["session_date"],
                    values["equity"],
                    values["cash"],
                    values["buying_power"],
                    values["drawdown"],
                    values["daily_return"],
                    values["five_day_return"],
                    row_mac,
                ),
            )
            row_id = int(cursor.lastrowid)
            chain_mac = self._equity_chain_mac(row_id, row_mac, previous_chain)
            db.execute(
                "UPDATE equity_snapshots SET chain_mac = ? WHERE id = ?",
                (chain_mac, row_id),
            )

    def save_plan(self, plan: TargetPlan) -> bool:
        self._validate_plan_transition(plan.status, plan.status)
        lifecycle = {
            "plan_id": plan.plan_id,
            "status": plan.status,
            "executed_at": None,
            "execution_message": "",
            "lifecycle_sequence": 0,
        }
        lifecycle_mac = self._plan_lifecycle_mac(lifecycle)
        with self._authenticated_write_transaction() as db:
            cursor = db.execute(
                """
                INSERT OR IGNORE INTO plans(
                    plan_id, as_of, created_at, regime, regime_multiplier,
                    desired_gross, forecast_volatility, target_weights_json,
                    metadata_json, status, lifecycle_sequence, lifecycle_mac
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    plan.plan_id,
                    plan.as_of.isoformat(),
                    plan.created_at.isoformat(),
                    plan.regime,
                    plan.regime_multiplier,
                    plan.desired_gross,
                    plan.forecast_volatility,
                    json.dumps(plan.target_weights, sort_keys=True),
                    json.dumps(plan.metadata, default=str, sort_keys=True),
                    plan.status,
                    0,
                    lifecycle_mac,
                ),
            )
            return cursor.rowcount == 1

    def get_plan_by_as_of(self, as_of: date) -> TargetPlan | None:
        with self._authenticated_read_connection() as db:
            row = db.execute(
                "SELECT * FROM plans WHERE as_of = ?", (as_of.isoformat(),)
            ).fetchone()
        return self._plan_from_row(row) if row else None

    def get_plan(self, plan_id: str) -> TargetPlan | None:
        with self._authenticated_read_connection() as db:
            row = db.execute(
                "SELECT * FROM plans WHERE plan_id = ?", (plan_id,)
            ).fetchone()
        return self._plan_from_row(row) if row else None

    def latest_plan(
        self,
        statuses: tuple[str, ...] | None = None,
        before_date: date | None = None,
    ) -> TargetPlan | None:
        where: list[str] = []
        params: list[Any] = []
        if statuses:
            where.append(f"status IN ({','.join('?' for _ in statuses)})")
            params.extend(statuses)
        if before_date:
            where.append("as_of < ?")
            params.append(before_date.isoformat())
        query = "SELECT * FROM plans"
        if where:
            query += " WHERE " + " AND ".join(where)
        query += " ORDER BY as_of DESC, created_at DESC LIMIT 1"
        with self._authenticated_read_connection() as db:
            row = db.execute(query, params).fetchone()
        return self._plan_from_row(row) if row else None

    def mark_plan_status(self, plan_id: str, status: str, message: str = "") -> None:
        with self._authenticated_write_transaction() as db:
            row = db.execute(
                "SELECT * FROM plans WHERE plan_id = ?", (plan_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"Unknown plan {plan_id!r}.")
            self._verify_plan_lifecycle_row(row)
            current = str(row["status"])
            self._validate_plan_transition(current, status)
            executed_at = row["executed_at"]
            if status in {"executed", "dry_run", "failed", "halted"}:
                executed_at = executed_at or _utc_now().isoformat()
            sequence = int(row["lifecycle_sequence"]) + 1
            lifecycle = {
                "plan_id": plan_id,
                "status": status,
                "executed_at": executed_at,
                "execution_message": message,
                "lifecycle_sequence": sequence,
            }
            lifecycle_mac = self._plan_lifecycle_mac(lifecycle)
            db.execute(
                """
                UPDATE plans SET status = ?, execution_message = ?,
                    executed_at = ?, lifecycle_sequence = ?, lifecycle_mac = ?
                WHERE plan_id = ? AND lifecycle_sequence = ?
                """,
                (
                    status,
                    message,
                    executed_at,
                    sequence,
                    lifecycle_mac,
                    plan_id,
                    int(row["lifecycle_sequence"]),
                ),
            )
            if db.execute("SELECT changes()").fetchone()[0] != 1:
                raise RuntimeError("Concurrent plan lifecycle transition was rejected.")

    def monitor_plan_candidates(
        self, limit: int = 250
    ) -> tuple[list[TargetPlan], list[str]]:
        """Return lifecycle-authenticated monitoring candidates and tamper evidence."""

        invalid: list[str] = []
        try:
            self._verify_authentication_head()
        except RuntimeError as exc:
            invalid.append(str(exc))
        with self.connection() as db:
            rows = db.execute(
                "SELECT * FROM plans ORDER BY as_of DESC, created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        plans: list[TargetPlan] = []
        for row in rows:
            try:
                self._verify_plan_lifecycle_row(row)
                plans.append(self._plan_from_row(row))
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                invalid.append(f"{row['plan_id']}: {exc}")
        return plans, invalid

    def record_order(self, plan_id: str | None, phase: str, receipt: OrderReceipt) -> None:
        now = _utc_now().isoformat()
        with self._authenticated_write_transaction() as db:
            prior = db.execute(
                "SELECT * FROM orders WHERE client_order_id = ?",
                (receipt.client_order_id,),
            ).fetchone()
            db.execute(
                """
                INSERT INTO orders(
                    plan_id, broker_order_id, client_order_id, symbol, side, qty,
                    phase, status, submitted_at, updated_at, filled_qty,
                    filled_avg_price, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(client_order_id) DO UPDATE SET
                    broker_order_id=excluded.broker_order_id,
                    status=excluded.status,
                    updated_at=excluded.updated_at,
                    filled_qty=excluded.filled_qty,
                    filled_avg_price=excluded.filled_avg_price,
                    raw_json=excluded.raw_json
                """,
                (
                    plan_id,
                    receipt.broker_order_id,
                    receipt.client_order_id,
                    receipt.symbol,
                    receipt.side,
                    receipt.qty,
                    phase,
                    receipt.status,
                    receipt.submitted_at.isoformat(),
                    now,
                    receipt.filled_qty,
                    receipt.filled_avg_price,
                    json.dumps(receipt.raw, default=str, sort_keys=True),
                ),
            )
            current = db.execute(
                "SELECT * FROM orders WHERE client_order_id = ?",
                (receipt.client_order_id,),
            ).fetchone()
            self._update_operational_authentication(db, "orders", prior, current)

    def order_records_by_client_order_ids(
        self, client_order_ids: Iterable[str]
    ) -> dict[str, dict[str, Any]]:
        """Return up to 250 exact order records after keyed per-row verification."""

        if isinstance(client_order_ids, (str, bytes)):
            raise TypeError("Client order IDs must be an iterable of strings.")
        identifiers: list[str] = []
        seen: set[str] = set()
        for supplied_count, identifier in enumerate(client_order_ids, start=1):
            if supplied_count > 250:
                raise ValueError(
                    "At most 250 client order IDs may be authenticated at once."
                )
            if not isinstance(identifier, str) or not identifier:
                raise ValueError("Client order IDs must be non-empty strings.")
            if identifier not in seen:
                identifiers.append(identifier)
                seen.add(identifier)
        if not identifiers:
            return {}
        placeholders = ",".join("?" for _ in identifiers)
        with self._authenticated_read_connection() as db:
            rows = db.execute(
                f"SELECT * FROM orders WHERE client_order_id IN ({placeholders})",
                identifiers,
            ).fetchall()
            self._verify_operational_rows(db, "orders", rows)
        return {str(row["client_order_id"]): dict(row) for row in rows}

    def order_record_by_client_order_id(
        self, client_order_id: str
    ) -> dict[str, Any] | None:
        """Return one exact authenticated order record by idempotency key."""

        records = self.order_records_by_client_order_ids((client_order_id,))
        return records.get(client_order_id)

    @staticmethod
    def _validated_query_limit(limit: int, *, maximum: int) -> int:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
            raise ValueError("Query limit must be a non-negative integer.")
        if limit > maximum:
            raise ValueError(f"Query limit must not exceed {maximum}.")
        return limit

    def managed_symbols(self) -> list[str]:
        symbols: set[str] = set()
        with self._authenticated_read_connection() as db:
            order_rows = db.execute("SELECT DISTINCT symbol FROM orders").fetchall()
            plan_rows = db.execute(
                "SELECT target_weights_json, metadata_json FROM plans ORDER BY as_of DESC LIMIT 250"
            ).fetchall()
        symbols.update(str(row["symbol"]) for row in order_rows if row["symbol"])
        for row in plan_rows:
            try:
                symbols.update(str(item) for item in json.loads(row["target_weights_json"]).keys())
            except (json.JSONDecodeError, AttributeError, TypeError):
                pass
            try:
                metadata = json.loads(row["metadata_json"])
                assets = metadata.get("assets", []) if isinstance(metadata, dict) else []
                symbols.update(str(item) for item in assets)
            except (json.JSONDecodeError, AttributeError, TypeError):
                pass
        return sorted(symbols)

    def recent_events(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = self._validated_query_limit(limit, maximum=10_000)
        with self._authenticated_read_connection() as db:
            rows = db.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            self._verify_operational_rows(db, "events", rows)
        return [dict(row) for row in rows]

    def recent_orders(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = self._validated_query_limit(limit, maximum=10_000)
        with self._authenticated_read_connection() as db:
            rows = db.execute(
                "SELECT * FROM orders ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            self._verify_operational_rows(db, "orders", rows)
        return [dict(row) for row in rows]

    def recent_equity(self, limit: int = 500) -> list[dict[str, Any]]:
        limit = self._validated_query_limit(limit, maximum=10_000)
        with self._authenticated_read_connection() as db:
            rows = db.execute(
                "SELECT * FROM equity_snapshots ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        for row in rows:
            self._verify_equity_row(row)
        return [dict(row) for row in reversed(rows)]

    def recent_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        limit = self._validated_query_limit(limit, maximum=10_000)
        with self._authenticated_read_connection() as db:
            rows = db.execute("SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
            self._verify_operational_rows(db, "runs", rows)
        return [dict(row) for row in rows]

    def list_plans(self, limit: int = 50) -> list[dict[str, Any]]:
        limit = self._validated_query_limit(limit, maximum=10_000)
        with self._authenticated_read_connection() as db:
            rows = db.execute("SELECT * FROM plans ORDER BY as_of DESC LIMIT ?", (limit,)).fetchall()
        for row in rows:
            self._verify_plan_lifecycle_row(row)
        return [dict(row) for row in rows]

    def summary(self) -> dict[str, Any]:
        halt = self.halt_state()
        with self._authenticated_read_connection() as db:
            latest_equity = db.execute(
                "SELECT * FROM equity_snapshots ORDER BY id DESC LIMIT 1"
            ).fetchone()
            latest_plan = db.execute("SELECT * FROM plans ORDER BY as_of DESC LIMIT 1").fetchone()
            latest_run = db.execute("SELECT * FROM runs ORDER BY started_at DESC LIMIT 1").fetchone()
            if latest_run is not None:
                self._verify_operational_rows(db, "runs", (latest_run,))
        if latest_equity is not None:
            self._verify_equity_row(latest_equity)
        if latest_plan is not None:
            self._verify_plan_lifecycle_row(latest_plan)
        return {
            "halt": halt,
            "high_watermark": self.get_state("high_watermark", None),
            "cooldown_remaining": self.get_state("cooldown_remaining", 0),
            "latest_equity": dict(latest_equity) if latest_equity else None,
            "latest_plan": dict(latest_plan) if latest_plan else None,
            "latest_run": dict(latest_run) if latest_run else None,
        }

    def _plan_from_row(self, row: sqlite3.Row) -> TargetPlan:
        self._verify_plan_lifecycle_row(row)
        return TargetPlan(
            plan_id=str(row["plan_id"]),
            as_of=date.fromisoformat(row["as_of"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            regime=str(row["regime"]),
            regime_multiplier=float(row["regime_multiplier"]),
            desired_gross=float(row["desired_gross"]),
            forecast_volatility=float(row["forecast_volatility"]),
            target_weights={
                str(k): float(v) for k, v in json.loads(row["target_weights_json"]).items()
            },
            metadata=json.loads(row["metadata_json"]),
            status=str(row["status"]),
        )
