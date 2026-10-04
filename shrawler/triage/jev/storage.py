"""Durable assessment store: ``<inventory-stem>.jev.db``.

Storage is versioned independently of the rule engine. Network waits are never
held inside a write transaction; callers commit bounded batches between them.

Schema version 2 adds:

* ``batch_directories``: a batch may carry more than one directory context.
* ``assessment_status_counts``: durable, transactionally maintained file-status
  counters so status queries never scan the whole ledger.
* ``request_batches.primary_directory_id`` (display/back-compat) replacing the
  single required ``directory_id``.
* ``assessment_runs.metrics_json``: phase timings and throughput counters.
* exact-request cache metadata on results (``decision_results.source``).

Version-1 databases migrate in one transaction; the migration leaves
``user_version`` unchanged if it fails.
"""

import hashlib
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from .config import canonical

SCHEMA_VERSION = 2

# A run lease heartbeats at this interval; another process may reclaim the run
# once the heartbeat is older than LEASE_TTL_SECONDS.
LEASE_TTL_SECONDS = 300

# Keep variable-length ``IN`` statements comfortably below SQLite's parameter
# limit; the configured question cap can exceed the historical 999-variable cap.
SQLITE_CHUNK = 900

RUNS_DDL = """
CREATE TABLE IF NOT EXISTS assessment_runs (
 id TEXT PRIMARY KEY,
 source_path TEXT NOT NULL,
 scan_id TEXT NOT NULL,
 scan_json TEXT NOT NULL,
 source_fingerprint TEXT NOT NULL,
 objective TEXT NOT NULL,
 config_json TEXT NOT NULL,
 config_fingerprint TEXT NOT NULL,
 deployment_revision TEXT NOT NULL,
 status TEXT NOT NULL,
 created_at TEXT NOT NULL,
 started_at TEXT,
 finished_at TEXT,
 heartbeat_at TEXT,
 lease_owner TEXT,
 owner_pid INTEGER,
 budget_seconds INTEGER NOT NULL DEFAULT 0,
 total_observed INTEGER NOT NULL DEFAULT 0,
 ledger_complete INTEGER NOT NULL DEFAULT 0,
 file_count INTEGER NOT NULL DEFAULT 0,
 context_count INTEGER NOT NULL DEFAULT 0,
 counters_json TEXT,
 metrics_json TEXT,
 error TEXT
);
"""

CONTEXTS_DDL = """
CREATE TABLE IF NOT EXISTS directory_contexts (
 run_id TEXT NOT NULL,
 directory_id INTEGER NOT NULL,
 host TEXT NOT NULL,
 share TEXT NOT NULL,
 parent TEXT NOT NULL,
 context_json TEXT NOT NULL,
 context_hash TEXT NOT NULL,
 observed_files INTEGER NOT NULL,
 context_tokens INTEGER NOT NULL,
 truncated INTEGER NOT NULL DEFAULT 0,
 omitted_json TEXT,
 enumeration TEXT NOT NULL DEFAULT 'observed listing complete',
 PRIMARY KEY(run_id, directory_id)
);
CREATE INDEX IF NOT EXISTS directory_contexts_group
 ON directory_contexts(run_id, host, share, parent);
"""

FILES_DDL = """
CREATE TABLE IF NOT EXISTS assessment_files (
 run_id TEXT NOT NULL,
 file_id TEXT NOT NULL,
 directory_id INTEGER NOT NULL,
 file_name TEXT NOT NULL,
 remote_path TEXT NOT NULL,
 unc_path TEXT NOT NULL,
 size_bytes INTEGER NOT NULL,
 mtime_utc TEXT,
 extension TEXT NOT NULL,
 feature_json TEXT NOT NULL,
 feature_hash TEXT NOT NULL,
 priority INTEGER NOT NULL DEFAULT 0,
 status TEXT NOT NULL,
 batch_id TEXT,
 result_id INTEGER,
 attempts INTEGER NOT NULL DEFAULT 0,
 error TEXT,
 updated_at TEXT NOT NULL,
 PRIMARY KEY(run_id, file_id)
);
CREATE INDEX IF NOT EXISTS assessment_files_pending
 ON assessment_files(run_id, status, directory_id, file_id);
CREATE INDEX IF NOT EXISTS assessment_files_batch
 ON assessment_files(run_id, batch_id, file_id);
-- Covering index for batch-scoped status counter reads and updates; without it
-- SQLite picks assessment_files_pending and scans the whole run per batch.
CREATE INDEX IF NOT EXISTS assessment_files_batch_status
 ON assessment_files(run_id, batch_id, status);
"""

# ``primary_directory_id`` is nullable and used only for display/back-compat.
REQUEST_BATCHES_DDL = """
CREATE TABLE IF NOT EXISTS request_batches (
 id TEXT PRIMARY KEY,
 run_id TEXT NOT NULL,
 primary_directory_id INTEGER,
 request_id TEXT NOT NULL,
 ordinal INTEGER NOT NULL,
 payload_json TEXT NOT NULL,
 payload_sha256 TEXT NOT NULL,
 input_tokens INTEGER NOT NULL,
 state_json TEXT NOT NULL,
 question_json TEXT NOT NULL,
 status TEXT NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL,
 dispatched_at TEXT,
 finished_at TEXT,
 error TEXT,
 usage_json TEXT,
 http_status INTEGER,
 remote_model TEXT,
 duration_ms INTEGER,
 cache_key TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS request_batches_run_status
 ON request_batches(run_id, status, ordinal);
CREATE INDEX IF NOT EXISTS request_batches_cache
 ON request_batches(run_id, cache_key);
"""

BATCH_DIRECTORIES_DDL = """
CREATE TABLE IF NOT EXISTS batch_directories (
 run_id TEXT NOT NULL,
 batch_id TEXT NOT NULL,
 directory_id INTEGER NOT NULL,
 ordinal INTEGER NOT NULL,
 context_hash TEXT NOT NULL,
 PRIMARY KEY (batch_id, directory_id)
);
CREATE INDEX IF NOT EXISTS batch_directories_run
 ON batch_directories(run_id, batch_id);
CREATE INDEX IF NOT EXISTS batch_directories_dir
 ON batch_directories(run_id, directory_id);
"""

BATCH_MEMBERS_DDL = """
CREATE TABLE IF NOT EXISTS batch_members (
 run_id TEXT NOT NULL,
 batch_id TEXT NOT NULL,
 file_id TEXT NOT NULL,
 ordinal INTEGER NOT NULL,
 PRIMARY KEY(batch_id, file_id)
);
CREATE INDEX IF NOT EXISTS batch_members_file ON batch_members(run_id, file_id);
"""

STATUS_COUNTS_DDL = """
CREATE TABLE IF NOT EXISTS assessment_status_counts (
 run_id TEXT NOT NULL,
 status TEXT NOT NULL,
 count INTEGER NOT NULL,
 PRIMARY KEY (run_id, status)
);
"""

RESULTS_DDL = """
CREATE TABLE IF NOT EXISTS decision_results (
 id INTEGER PRIMARY KEY,
 run_id TEXT NOT NULL,
 batch_id TEXT NOT NULL,
 request_id TEXT NOT NULL,
 file_id TEXT NOT NULL,
 choice TEXT NOT NULL,
 distribution_json TEXT,
 deployment_revision TEXT NOT NULL,
 model TEXT NOT NULL,
 adapter_version TEXT NOT NULL,
 rubric_version TEXT NOT NULL,
 context_hash TEXT NOT NULL,
 source TEXT NOT NULL DEFAULT 'model',
 created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS decision_results_file
 ON decision_results(run_id, file_id);
CREATE INDEX IF NOT EXISTS decision_results_batch
 ON decision_results(run_id, batch_id);
"""

LABELS_DDL = """
CREATE TABLE IF NOT EXISTS assessment_labels (
 id INTEGER PRIMARY KEY,
 run_id TEXT NOT NULL,
 file_id TEXT NOT NULL,
 label TEXT NOT NULL,
 source TEXT NOT NULL,
 note TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL
);
"""

# Durable counters are maintained set-wise in the same transaction as every
# status transition (see ``set_file_status``/``complete_batch``/``insert_files``).
# Triggers were removed at scale: one trigger invocation per row doubled
# statement counts and dominated planning/dispatch wall time for million-file
# inventories.
SCHEMA = (
    RUNS_DDL
    + CONTEXTS_DDL
    + FILES_DDL
    + REQUEST_BATCHES_DDL
    + BATCH_DIRECTORIES_DDL
    + BATCH_MEMBERS_DDL
    + STATUS_COUNTS_DDL
    + RESULTS_DDL
    + LABELS_DDL
)

# Explicit per-statement DDL used by the migration (``executescript`` would
# commit mid-transaction, defeating atomicity). Each constant is run one
# statement at a time below.
def _execute_statements(connection: sqlite3.Connection, script: str) -> None:
    for statement in script.split(";"):
        if statement.strip():
            connection.execute(statement)


class JevStoreError(ValueError):
    pass


class RunBusyError(JevStoreError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def assessment_path(database: Path) -> Path:
    return database.with_name(database.stem + ".jev.db")


def _chunked(values: Sequence[Any], size: int = SQLITE_CHUNK) -> Iterator[Sequence[Any]]:
    for start in range(0, len(values), size):
        yield values[start : start + size]


@contextmanager
def _NO_COMMIT() -> Iterator[None]:
    """No-op transaction scope: statements accumulate until an explicit commit.

    Used by high-volume planners that group many writes into one transaction
    and commit periodically, so a multi-batch plan does not pay one fsync per
    batch. An uncommitted tail is safe: those files remain ``pending`` and are
    re-selected on the next plan.
    """
    yield


class JevStore:
    """Owns the enrichment database for one inventory path."""

    def __init__(self, database: Path) -> None:
        self.database = database.resolve()
        self.path = assessment_path(database)
        self.connection = sqlite3.connect(self.path, timeout=30)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=NORMAL")
        self.connection.execute("PRAGMA busy_timeout=5000")
        self.connection.execute("PRAGMA foreign_keys=ON")
        version = self.connection.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1, SCHEMA_VERSION):
            raise JevStoreError(
                f"no migration path from assessment database version {version}"
            )
        if version == 1:
            self._migrate_v1_to_v2()
        self.connection.executescript(SCHEMA)
        self.connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        self.connection.commit()
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    # -- migration --------------------------------------------------------

    def _migrate_v1_to_v2(self) -> None:
        """Rebuild the batch table and backfill counters in one transaction.

        Runs with an explicit autocommit connection so DDL participates in the
        transaction; a failure rolls back and leaves ``user_version`` unchanged.
        """
        connection = self.connection
        previous = connection.isolation_level
        connection.isolation_level = None
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "ALTER TABLE request_batches RENAME TO request_batches_v1"
            )
            _execute_statements(connection, REQUEST_BATCHES_DDL)
            connection.execute(
                "INSERT INTO request_batches(id,run_id,primary_directory_id,request_id,"
                "ordinal,payload_json,payload_sha256,input_tokens,state_json,"
                "question_json,status,attempts,created_at,dispatched_at,finished_at,"
                "error,usage_json,http_status,remote_model,duration_ms,cache_key) "
                "SELECT id,run_id,directory_id,request_id,ordinal,payload_json,"
                "payload_sha256,input_tokens,state_json,question_json,status,attempts,"
                "created_at,dispatched_at,finished_at,error,usage_json,http_status,"
                "remote_model,duration_ms,cache_key FROM request_batches_v1"
            )
            connection.execute("DROP TABLE request_batches_v1")
            _execute_statements(connection, BATCH_DIRECTORIES_DDL)
            connection.execute(
                "INSERT OR IGNORE INTO batch_directories"
                "(run_id,batch_id,directory_id,ordinal,context_hash) "
                "SELECT b.run_id,b.id,b.primary_directory_id,0,"
                "COALESCE(dc.context_hash,'') FROM request_batches b "
                "LEFT JOIN directory_contexts dc ON dc.run_id=b.run_id "
                "AND dc.directory_id=b.primary_directory_id "
                "WHERE b.primary_directory_id IS NOT NULL"
            )
            _execute_statements(connection, STATUS_COUNTS_DDL)
            connection.execute(
                "INSERT OR REPLACE INTO assessment_status_counts(run_id,status,count) "
                "SELECT run_id,status,COUNT(*) FROM assessment_files "
                "GROUP BY run_id,status"
            )
            if not self._column_exists("assessment_runs", "metrics_json"):
                connection.execute(
                    "ALTER TABLE assessment_runs ADD COLUMN metrics_json TEXT"
                )
            if not self._column_exists("decision_results", "source"):
                connection.execute(
                    "ALTER TABLE decision_results ADD COLUMN source TEXT NOT NULL "
                    "DEFAULT 'model'"
                )
            # Drop legacy counters triggers if a version-1 database carried them
            # (version 1 had none; this is defensive for intermediate builds).
            for name in (
                "assessment_files_count_insert",
                "assessment_files_count_delete",
                "assessment_files_count_update",
            ):
                connection.execute(f"DROP TRIGGER IF EXISTS {name}")
            connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            connection.execute("COMMIT")
        except BaseException:
            connection.execute("ROLLBACK")
            raise
        finally:
            connection.isolation_level = previous

    def _column_exists(self, table: str, column: str) -> bool:
        rows = self.connection.execute(f"PRAGMA table_info({table})").fetchall()
        return any(str(row["name"]) == column for row in rows)

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "JevStore":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def commit(self) -> None:
        self.connection.commit()

    # -- runs -------------------------------------------------------------

    def create_run(
        self,
        scan: Dict[str, Any],
        source_fingerprint: str,
        config: Dict[str, Any],
    ) -> str:
        run_id = uuid.uuid4().hex
        self.connection.execute(
            "INSERT INTO assessment_runs(id,source_path,scan_id,scan_json,"
            "source_fingerprint,objective,config_json,config_fingerprint,"
            "deployment_revision,status,created_at,budget_seconds) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                run_id,
                str(self.database),
                str(scan["id"]),
                canonical(scan),
                source_fingerprint,
                str(config["objective"]),
                canonical(config),
                str(config["config_fingerprint"]),
                str(config["deployment_revision"]),
                "prepared",
                utc_now(),
                int(config.get("budget_seconds", 0)),
            ),
        )
        self.connection.commit()
        return run_id

    def select_run(self, run_id: Optional[str]) -> sqlite3.Row:
        if run_id:
            row = self.connection.execute(
                "SELECT * FROM assessment_runs WHERE id=?", (run_id,)
            ).fetchone()
        else:
            row = self.connection.execute(
                "SELECT * FROM assessment_runs ORDER BY created_at DESC, rowid DESC LIMIT 1"
            ).fetchone()
        if row is None:
            raise JevStoreError("no assessment run found; run 'triage jev prepare' first")
        return row

    def update_run(self, run_id: str, **values: Any) -> None:
        if not values:
            return
        columns = ", ".join(f"{name}=?" for name in values)
        self.connection.execute(
            f"UPDATE assessment_runs SET {columns} WHERE id=?",
            (*values.values(), run_id),
        )
        self.connection.commit()

    def set_run_metrics(self, run_id: str, metrics: Dict[str, Any]) -> None:
        self.update_run(run_id, metrics_json=canonical(metrics))

    # -- lease ------------------------------------------------------------

    def acquire_lease(self, run_id: str, owner: str, pid: int) -> None:
        """Atomically take the run. Fails if another live process holds it."""
        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(seconds=LEASE_TTL_SECONDS)).isoformat()
        with self.connection:
            cursor = self.connection.execute(
                "UPDATE assessment_runs SET lease_owner=?, owner_pid=?, "
                "heartbeat_at=?, status=CASE WHEN status IN ('prepared','paused',"
                "'partial','failed','interrupted') THEN 'running' ELSE status END "
                "WHERE id=? AND (lease_owner IS NULL OR heartbeat_at IS NULL "
                "OR heartbeat_at < ?)",
                (owner, pid, now.isoformat(), run_id, cutoff),
            )
            if cursor.rowcount != 1:
                row = self.connection.execute(
                    "SELECT status, lease_owner FROM assessment_runs WHERE id=?",
                    (run_id,),
                ).fetchone()
                detail = "unknown run"
                if row is not None:
                    detail = f"status={row['status']} owner={row['lease_owner']}"
                raise RunBusyError(f"assessment run is busy ({detail})")

    def heartbeat(self, run_id: str, owner: str) -> bool:
        with self.connection:
            cursor = self.connection.execute(
                "UPDATE assessment_runs SET heartbeat_at=? WHERE id=? AND lease_owner=?",
                (utc_now(), run_id, owner),
            )
            return cursor.rowcount == 1

    def release_lease(self, run_id: str, owner: str, status: str, error: Optional[str] = None) -> None:
        with self.connection:
            self.connection.execute(
                "UPDATE assessment_runs SET lease_owner=NULL, owner_pid=NULL, "
                "heartbeat_at=NULL, status=?, finished_at=?, error=? "
                "WHERE id=? AND lease_owner=?",
                (status, utc_now(), error, run_id, owner),
            )

    # -- directory contexts ----------------------------------------------

    def insert_contexts(self, run_id: str, rows: List[Tuple[Any, ...]]) -> None:
        self.connection.executemany(
            "INSERT OR REPLACE INTO directory_contexts(run_id,directory_id,host,"
            "share,parent,context_json,context_hash,observed_files,context_tokens,"
            "truncated,omitted_json,enumeration) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
        self.connection.commit()

    def context_rows(self, run_id: str) -> List[sqlite3.Row]:
        return list(
            self.connection.execute(
                "SELECT * FROM directory_contexts WHERE run_id=? ORDER BY directory_id",
                (run_id,),
            )
        )

    def context_for(self, run_id: str, directory_id: int) -> Optional[sqlite3.Row]:
        return self.connection.execute(
            "SELECT * FROM directory_contexts WHERE run_id=? AND directory_id=?",
            (run_id, directory_id),
        ).fetchone()

    # -- ledger -----------------------------------------------------------

    def insert_files(self, rows: List[Tuple[Any, ...]]) -> None:
        if not rows:
            return
        run_id = str(rows[0][0])
        self.connection.executemany(
            "INSERT OR REPLACE INTO assessment_files(run_id,file_id,directory_id,"
            "file_name,remote_path,unc_path,size_bytes,mtime_utc,extension,"
            "feature_json,feature_hash,priority,status,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
        # Staging writes a fresh run, so every row is new; maintain durable
        # counters by simple delta (no existence probe). A re-staged primary
        # key would be a new run ID and is therefore not a collision.
        adjustments: Dict[str, int] = {}
        for row in rows:
            status = str(row[12])
            adjustments[status] = adjustments.get(status, 0) + 1
        for status, delta in adjustments.items():
            self.connection.execute(
                "INSERT INTO assessment_status_counts(run_id,status,count) VALUES (?,?,?) "
                "ON CONFLICT(run_id,status) DO UPDATE SET count=count+?",
                (run_id, status, delta, delta),
            )

    def file_row(self, run_id: str, file_id: str) -> Optional[sqlite3.Row]:
        return self.connection.execute(
            "SELECT * FROM assessment_files WHERE run_id=? AND file_id=?",
            (run_id, file_id),
        ).fetchone()

    def attempts_for(self, run_id: str, file_ids: Sequence[str]) -> Dict[str, int]:
        """One query (chunked) for the attempt count of unresolved members."""
        attempts: Dict[str, int] = {}
        for chunk in _chunked(list(file_ids)):
            placeholders = ",".join("?" for _ in chunk)
            for row in self.connection.execute(
                f"SELECT file_id, attempts FROM assessment_files WHERE run_id=? "
                f"AND file_id IN ({placeholders})",
                (run_id, *chunk),
            ):
                attempts[str(row["file_id"])] = int(row["attempts"])
        return attempts

    def pending_files(
        self, run_id: str, directory_id: Optional[int] = None
    ) -> List[sqlite3.Row]:
        clause = " AND directory_id=?" if directory_id is not None else ""
        values: Tuple[Any, ...] = (run_id, directory_id) if clause else (run_id,)
        return list(
            self.connection.execute(
                "SELECT * FROM assessment_files WHERE run_id=? AND status IN "
                "('pending','failed','input-error')" + clause + " ORDER BY priority DESC, file_id",
                values,
            )
        )

    def set_file_status(self, run_id: str, file_ids: Iterable[str], status: str, **extra: Any) -> None:
        ids = list(file_ids)
        if not ids:
            return
        assignments = ["status=?", "updated_at=?", "error=?"]
        tail: List[Any] = [status, utc_now(), extra.get("error")]
        if "batch_id" in extra:
            assignments.append("batch_id=?")
            tail.append(extra["batch_id"])
        if extra.get("increment_attempt"):
            assignments.append("attempts=attempts+1")
        if "result_id" in extra:
            assignments.append("result_id=?")
            tail.append(extra["result_id"])
        # Whole-batch fast path: when the caller confirms the ID list is the
        # batch's complete membership, scope the UPDATE and counter pre-image
        # by the indexed batch key, keeping this O(batch) not O(files). Other
        # callers use the file-ID path so a partial list is always exact.
        scope_batch = extra.get("batch_id") if extra.get("claim_batch_scope") else None
        if scope_batch is not None:
            assignments_text = ", ".join(assignments)
            parameters = (*tail, run_id, scope_batch)
            rows = self.connection.execute(
                "SELECT status, COUNT(*) AS n FROM assessment_files WHERE run_id=? "
                "AND batch_id=? AND status<>? GROUP BY status",
                (run_id, scope_batch, status),
            )
            before = {str(row["status"]): int(row["n"]) for row in rows}
            self.connection.execute(
                f"UPDATE assessment_files SET {assignments_text} "
                "WHERE run_id=? AND batch_id=?",
                parameters,
            )
            adjustments = {status: len(ids)}
            for old_status, count in before.items():
                if old_status == status or count <= 0:
                    continue
                adjustments[old_status] = adjustments.get(old_status, 0) - count
            self._adjust_counts(run_id, adjustments)
            return
        # Known-source fast path: callers that select candidates by status can
        # assert the pre-image, avoiding a scan of the run ledger.
        assumed_from = extra.get("assume_from_status")
        prefix = (
            f"UPDATE assessment_files SET {', '.join(assignments)} "
            "WHERE run_id=? AND file_id IN "
        )
        if assumed_from is not None:
            for chunk in _chunked(ids):
                placeholders = ",".join("?" for _ in chunk)
                self.connection.execute(
                    prefix + f"({placeholders})", (*tail, run_id, *chunk)
                )
            self._adjust_counts(
                run_id, {assumed_from: -len(ids), status: len(ids)}
            )
            return
        for chunk in _chunked(ids):
            placeholders = ",".join("?" for _ in chunk)
            # Apply the status change and reconcile durable counters in the
            # same transaction, set-wise (no per-row trigger overhead).
            self._apply_status(
                run_id,
                chunk,
                status,
                prefix + f"({placeholders})",
                (*tail, run_id, *chunk),
            )

    def _apply_status(
        self,
        run_id: str,
        file_ids: Sequence[str],
        new_status: str,
        statement: str,
        parameters: Tuple[Any, ...],
    ) -> None:
        """Run one file-ID scoped status UPDATE and adjust counters by delta."""
        placeholders = ",".join("?" for _ in file_ids)
        rows = self.connection.execute(
            f"SELECT status, COUNT(*) AS n FROM assessment_files WHERE run_id=? "
            f"AND file_id IN ({placeholders}) GROUP BY status",
            (run_id, *file_ids),
        )
        before = {str(row["status"]): int(row["n"]) for row in rows}
        self.connection.execute(statement, parameters)
        adjustments = {new_status: len(file_ids)}
        for old_status, count in before.items():
            if old_status == new_status or count <= 0:
                continue
            adjustments[old_status] = adjustments.get(old_status, 0) - count
        self._adjust_counts(run_id, adjustments)

    def _adjust_counts(self, run_id: str, adjustments: Dict[str, int]) -> None:
        for status, delta in adjustments.items():
            if not delta:
                continue
            self.connection.execute(
                "INSERT INTO assessment_status_counts(run_id,status,count) VALUES (?,?,?) "
                "ON CONFLICT(run_id,status) DO UPDATE SET count=MAX(0,count+?)",
                (run_id, status, max(0, delta), delta),
            )

    # -- batches ----------------------------------------------------------

    def insert_batch(
        self,
        batch_id: str,
        run_id: str,
        primary_directory_id: Optional[int],
        request_id: str,
        ordinal: int,
        payload: Dict[str, Any],
        input_tokens: int,
        state: str,
        questions: Dict[str, Any],
        members: List[str],
        directories: List[Tuple[int, str]],
        cache_key: str,
        commit: bool = True,
    ) -> None:
        """Persist one complete batch and claim all of its members atomically.

        ``directories`` is an ordered list of ``(directory_id, context_hash)``
        pairs; every directory context referenced by the batch is recorded in
        ``batch_directories`` so membership survives resume and repacking.

        ``commit=False`` lets a planner batch many inserts into one transaction
        and commit periodically; uncommitted batches simply remain pending and
        are replanned after a crash.
        """
        payload_hash = hashlib.sha256(canonical(payload).encode()).hexdigest()
        transaction = self.connection if commit else _NO_COMMIT()
        with transaction:
            self.connection.execute(
                "INSERT INTO request_batches(id,run_id,primary_directory_id,request_id,"
                "ordinal,payload_json,payload_sha256,input_tokens,state_json,"
                "question_json,status,created_at,cache_key) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    batch_id,
                    run_id,
                    primary_directory_id,
                    request_id,
                    ordinal,
                    canonical(payload),
                    payload_hash,
                    input_tokens,
                    state,
                    canonical(questions),
                    "planned",
                    utc_now(),
                    cache_key,
                ),
            )
            if directories:
                self.connection.executemany(
                    "INSERT OR REPLACE INTO batch_directories"
                    "(run_id,batch_id,directory_id,ordinal,context_hash) VALUES (?,?,?,?,?)",
                    [
                        (run_id, batch_id, directory_id, index, context_hash)
                        for index, (directory_id, context_hash) in enumerate(directories)
                    ],
                )
            self.connection.executemany(
                "INSERT INTO batch_members(run_id,batch_id,file_id,ordinal) VALUES (?,?,?,?)",
                [(run_id, batch_id, file_id, index) for index, file_id in enumerate(members)],
            )
            self.set_file_status(
                run_id, members, "planned", batch_id=batch_id,
                assume_from_status="pending", error=None,
            )

    def mark_batch_dispatched(self, batch_id: str) -> None:
        with self.connection:
            self.connection.execute(
                "UPDATE request_batches SET status='in-flight', dispatched_at=?, "
                "attempts=attempts+1 WHERE id=?",
                (utc_now(), batch_id),
            )

    def claim_batch(self, run_id: str, batch_id: str, members: Sequence[str]) -> None:
        """Mark a batch and its members in-flight (one transaction)."""
        now = utc_now()
        with self.connection:
            self.connection.execute(
                "UPDATE request_batches SET status='in-flight', dispatched_at=?, "
                "attempts=attempts+1 WHERE id=?",
                (now, batch_id),
            )
            self.set_file_status(
                run_id, members, "in-flight", batch_id=batch_id,
                increment_attempt=True, claim_batch_scope=True, error=None,
            )

    def finish_batch(
        self,
        batch_id: str,
        status: str,
        usage: Optional[Dict[str, Any]] = None,
        http_status: Optional[int] = None,
        remote_model: Optional[str] = None,
        duration_ms: Optional[int] = None,
        error: Optional[str] = None,
    ) -> None:
        with self.connection:
            self.connection.execute(
                "UPDATE request_batches SET status=?, finished_at=?, usage_json=?, "
                "http_status=?, remote_model=?, duration_ms=?, error=? WHERE id=?",
                (
                    status,
                    utc_now(),
                    canonical(usage) if usage is not None else None,
                    http_status,
                    remote_model,
                    duration_ms,
                    error,
                    batch_id,
                ),
            )

    def release_batch_to_planned(self, run_id: str, batch_id: str, members: Sequence[str]) -> None:
        """Return a claimed batch to the planned queue without losing attempts."""
        with self.connection:
            self.connection.execute(
                "UPDATE request_batches SET status='planned' WHERE id=?", (batch_id,)
            )
            self.set_file_status(run_id, members, "pending", error=None)

    def complete_batch(
        self,
        run_id: str,
        batch_id: str,
        request_id: str,
        answers: List[Dict[str, Any]],
        retrying: Sequence[str],
        exhausted: Sequence[str],
        batch_status: str,
        context_hashes: Dict[str, str],
        usage: Optional[Dict[str, Any]] = None,
        http_status: Optional[int] = None,
        remote_model: Optional[str] = None,
        duration_ms: Optional[int] = None,
        error: Optional[str] = None,
        source: str = "model",
        commit: bool = True,
    ) -> int:
        """Persist answers and every member transition in one transaction.

        Each answer dict carries ``file_id``, ``choice``, ``distribution`` and
        result provenance. Returns the number of answers persisted.

        ``commit=False`` keeps the coordinator's per-wave group-commit pattern;
        the caller commits once after persisting a whole completion wave.
        """
        now = utc_now()
        with (self.connection if commit else _NO_COMMIT()):
            if answers:
                self.connection.executemany(
                    "INSERT INTO decision_results(run_id,batch_id,request_id,file_id,"
                    "choice,distribution_json,deployment_revision,model,adapter_version,"
                    "rubric_version,context_hash,source,created_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    [
                        (
                            run_id,
                            batch_id,
                            request_id,
                            str(answer["file_id"]),
                            str(answer["choice"]),
                            canonical(answer["distribution"])
                            if answer.get("distribution") is not None
                            else None,
                            str(answer["deployment_revision"]),
                            str(answer["model"]),
                            str(answer["adapter_version"]),
                            str(answer["rubric_version"]),
                            str(answer.get("context_hash", "")),
                            source,
                            now,
                        )
                        for answer in answers
                    ],
                )
                # One bulk update for every answered file. Both the counter
                # pre-image and the result_id mapping use the indexed batch
                # key rather than file-ID lists, keeping this O(batch).
                before = {
                    str(row["status"]): int(row["n"])
                    for row in self.connection.execute(
                        "SELECT status, COUNT(*) AS n FROM assessment_files "
                        "WHERE run_id=? AND batch_id=? AND status<>'assessed' "
                        "GROUP BY status",
                        (run_id, batch_id),
                    )
                }
                self.connection.execute(
                    "UPDATE assessment_files SET status='assessed', updated_at=?, "
                    "error=NULL, result_id=(SELECT d.id FROM decision_results d "
                    "WHERE d.run_id=assessment_files.run_id "
                    "AND d.batch_id=? AND d.file_id=assessment_files.file_id) "
                    "WHERE run_id=? AND batch_id=? AND status<>'assessed'",
                    (now, batch_id, run_id, batch_id),
                )
                adjustments: Dict[str, int] = {}
                transitioned = 0
                for old_status, count in before.items():
                    adjustments[old_status] = -count
                    transitioned += count
                if transitioned:
                    adjustments["assessed"] = transitioned
                self._adjust_counts(run_id, adjustments)
            if retrying:
                self.set_file_status(run_id, retrying, "pending", error=None)
            if exhausted:
                self.set_file_status(run_id, exhausted, "failed", error=error)
            self.connection.execute(
                "UPDATE request_batches SET status=?, finished_at=?, usage_json=?, "
                "http_status=?, remote_model=?, duration_ms=?, error=? WHERE id=?",
                (
                    batch_status,
                    now,
                    canonical(usage) if usage is not None else None,
                    http_status,
                    remote_model,
                    duration_ms,
                    error,
                    batch_id,
                ),
            )
        return len(answers)

    def fail_batch(
        self,
        run_id: str,
        batch_id: str,
        retrying: Sequence[str],
        exhausted: Sequence[str],
        batch_status: str,
        error: str,
    ) -> None:
        with self.connection:
            if retrying:
                self.set_file_status(run_id, retrying, "pending", error=None)
            if exhausted:
                self.set_file_status(run_id, exhausted, "failed", error=error)
            self.connection.execute(
                "UPDATE request_batches SET status=?, finished_at=?, error=? WHERE id=?",
                (batch_status, utc_now(), error, batch_id),
            )

    def mark_input_error(
        self, run_id: str, batch_id: str, members: Sequence[str], error: str
    ) -> None:
        with self.connection:
            self.connection.execute(
                "UPDATE request_batches SET status='input-error', finished_at=?, error=? "
                "WHERE id=?",
                (utc_now(), error, batch_id),
            )
            self.set_file_status(run_id, members, "input-error", error=error)

    def batch_rows(self, run_id: str, status: Optional[str] = None) -> List[sqlite3.Row]:
        clause = " AND status=?" if status else ""
        values: Tuple[Any, ...] = (run_id, status) if status else (run_id,)
        return list(
            self.connection.execute(
                "SELECT * FROM request_batches WHERE run_id=?" + clause + " ORDER BY ordinal",
                values,
            )
        )

    def next_planned_batch(self, run_id: str) -> Optional[sqlite3.Row]:
        # Only ``planned`` batches are selectable; ``in-flight`` batches are
        # owned by active workers and are recovered separately on resume.
        return self.connection.execute(
            "SELECT * FROM request_batches WHERE run_id=? AND status='planned' "
            "ORDER BY ordinal LIMIT 1",
            (run_id,),
        ).fetchone()

    def planned_batch_count(self, run_id: str) -> int:
        return int(
            self.connection.execute(
                "SELECT COUNT(*) FROM request_batches WHERE run_id=? AND status IN "
                "('planned','in-flight')",
                (run_id,),
            ).fetchone()[0]
        )

    def max_batch_ordinal(self, run_id: str) -> int:
        row = self.connection.execute(
            "SELECT COALESCE(MAX(ordinal),0) FROM request_batches WHERE run_id=?",
            (run_id,),
        ).fetchone()
        return int(row[0])

    def has_successful_batch(self, run_id: str) -> bool:
        return (
            self.connection.execute(
                "SELECT 1 FROM request_batches WHERE run_id=? AND status IN "
                "('completed','partial') LIMIT 1",
                (run_id,),
            ).fetchone()
            is not None
        )

    def batch_members(self, batch_id: str) -> List[str]:
        return [
            row["file_id"]
            for row in self.connection.execute(
                "SELECT file_id FROM batch_members WHERE batch_id=? ORDER BY ordinal",
                (batch_id,),
            )
        ]

    def batch_members_with_directory(self, batch_id: str) -> List[sqlite3.Row]:
        return list(
            self.connection.execute(
                "SELECT m.file_id, f.directory_id FROM batch_members m "
                "JOIN assessment_files f ON f.run_id=m.run_id AND f.file_id=m.file_id "
                "WHERE m.batch_id=? ORDER BY m.ordinal",
                (batch_id,),
            )
        )

    def batch_directory_hashes(self, batch_id: str) -> Dict[int, str]:
        return {
            int(row["directory_id"]): str(row["context_hash"])
            for row in self.connection.execute(
                "SELECT directory_id, context_hash FROM batch_directories "
                "WHERE batch_id=? ORDER BY ordinal",
                (batch_id,),
            )
        }

    def member_context_hashes(self, batch_id: str) -> Dict[str, str]:
        """One query: every member's file ID mapped to its directory hash."""
        return {
            str(row["file_id"]): str(row["context_hash"])
            for row in self.connection.execute(
                "SELECT m.file_id AS file_id, d.context_hash AS context_hash "
                "FROM batch_members m "
                "JOIN assessment_files f ON f.run_id=m.run_id AND f.file_id=m.file_id "
                "JOIN batch_directories d ON d.batch_id=m.batch_id "
                "AND d.directory_id=f.directory_id "
                "WHERE m.batch_id=? ORDER BY m.ordinal",
                (batch_id,),
            )
        }

    # -- results and cache ------------------------------------------------

    def record_result(
        self,
        run_id: str,
        batch_id: str,
        request_id: str,
        file_id: str,
        choice: str,
        distribution: Optional[Dict[str, Any]],
        deployment_revision: str,
        model: str,
        adapter_version: str,
        rubric_version: str,
        context_hash: str,
        source: str = "model",
    ) -> int:
        cursor = self.connection.execute(
            "INSERT INTO decision_results(run_id,batch_id,request_id,file_id,choice,"
            "distribution_json,deployment_revision,model,adapter_version,rubric_version,"
            "context_hash,source,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                run_id,
                batch_id,
                request_id,
                file_id,
                choice,
                canonical(distribution) if distribution is not None else None,
                deployment_revision,
                model,
                adapter_version,
                rubric_version,
                context_hash,
                source,
                utc_now(),
            ),
        )
        return int(cursor.lastrowid or 0)

    def cached_completed_batch(
        self, run_id: str, cache_key: str, exclude_batch_id: str
    ) -> Optional[sqlite3.Row]:
        """Most recent validated batch with the same exact cache identity."""
        if not cache_key:
            return None
        return self.connection.execute(
            "SELECT * FROM request_batches WHERE cache_key=? AND id<>? AND "
            "status IN ('completed','partial') AND EXISTS "
            "(SELECT 1 FROM decision_results d WHERE d.run_id=request_batches.run_id "
            "AND d.batch_id=request_batches.id) "
            "ORDER BY finished_at DESC, rowid DESC LIMIT 1",
            (cache_key, exclude_batch_id),
        ).fetchone()

    def results_for_batch(self, run_id: str, batch_id: str) -> List[sqlite3.Row]:
        return list(
            self.connection.execute(
                "SELECT * FROM decision_results WHERE run_id=? AND batch_id=? "
                "ORDER BY file_id",
                (run_id, batch_id),
            )
        )

    # -- coverage ---------------------------------------------------------

    def status_counts(self, run_id: str) -> Dict[str, int]:
        return {
            str(row["status"]): int(row["count"])
            for row in self.connection.execute(
                "SELECT status, count FROM assessment_status_counts "
                "WHERE run_id=? AND count<>0",
                (run_id,),
            )
        }

    def overall_counts(self, run_id: str) -> Dict[str, int]:
        """Back-compat alias over durable counters (no ledger scan)."""
        return self.status_counts(run_id)

    def batch_status_counts(self, run_id: str) -> Dict[str, int]:
        return {
            str(row["status"]): int(row["n"])
            for row in self.connection.execute(
                "SELECT status, COUNT(*) AS n FROM request_batches WHERE run_id=? "
                "GROUP BY status",
                (run_id,),
            )
        }

    def recent_durations(self, run_id: str, limit: int = 200) -> List[int]:
        """A bounded sample of recent request durations for status percentiles."""
        return [
            int(row["duration_ms"])
            for row in self.connection.execute(
                "SELECT duration_ms FROM request_batches WHERE run_id=? AND "
                "duration_ms IS NOT NULL ORDER BY ordinal DESC LIMIT ?",
                (run_id, limit),
            )
        ]

    def planned_batch_stats(self, run_id: str) -> Dict[str, Any]:
        """Aggregate stats for currently planned batches without loading payloads."""
        row = self.connection.execute(
            "SELECT COUNT(*) AS batches, COALESCE(SUM(input_tokens),0) AS tokens, "
            "COALESCE(MIN((SELECT COUNT(*) FROM batch_members m WHERE m.batch_id=b.id)),0) "
            "AS min_candidates, "
            "COALESCE(MAX((SELECT COUNT(*) FROM batch_members m WHERE m.batch_id=b.id)),0) "
            "AS max_candidates, "
            "COALESCE(AVG((SELECT COUNT(*) FROM batch_members m WHERE m.batch_id=b.id)),0) "
            "AS avg_candidates, "
            "COALESCE(MIN((SELECT COUNT(*) FROM batch_directories d WHERE d.batch_id=b.id)),0) "
            "AS min_dirs, "
            "COALESCE(MAX((SELECT COUNT(*) FROM batch_directories d WHERE d.batch_id=b.id)),0) "
            "AS max_dirs, "
            "COALESCE(AVG((SELECT COUNT(*) FROM batch_directories d WHERE d.batch_id=b.id)),0) "
            "AS avg_dirs FROM request_batches b WHERE b.run_id=? AND b.status IN "
            "('planned','in-flight')",
            (run_id,),
        ).fetchone()
        candidates = int(
            self.connection.execute(
                "SELECT COUNT(*) FROM batch_members m JOIN request_batches b "
                "ON b.id=m.batch_id WHERE b.run_id=? AND b.status IN "
                "('planned','in-flight')",
                (run_id,),
            ).fetchone()[0]
        )
        return {
            "batches": int(row["batches"]),
            "candidates": candidates,
            "input_tokens": int(row["tokens"]),
            "min_candidates": int(row["min_candidates"]),
            "max_candidates": int(row["max_candidates"]),
            "average_candidates": round(float(row["avg_candidates"]), 2),
            "min_directories": int(row["min_dirs"]),
            "max_directories": int(row["max_dirs"]),
            "average_directories": round(float(row["avg_dirs"]), 2),
        }

    def verify_status_counts(self, run_id: str) -> bool:
        """Compare durable counters with a direct ledger recount."""
        actual = {
            str(row["status"]): int(row["n"])
            for row in self.connection.execute(
                "SELECT status, COUNT(*) AS n FROM assessment_files WHERE run_id=? "
                "GROUP BY status",
                (run_id,),
            )
        }
        durable = {
            status: count
            for status, count in self.status_counts(run_id).items()
            if count
        }
        return actual == durable

    def rebuild_status_counts(self, run_id: str) -> None:
        with self.connection:
            self.connection.execute(
                "DELETE FROM assessment_status_counts WHERE run_id=?", (run_id,)
            )
            self.connection.execute(
                "INSERT INTO assessment_status_counts(run_id,status,count) "
                "SELECT run_id,status,COUNT(*) FROM assessment_files WHERE run_id=? "
                "GROUP BY run_id,status",
                (run_id,),
            )

    def directory_counts(self, run_id: str) -> List[sqlite3.Row]:
        return list(
            self.connection.execute(
                "SELECT directory_id, status, COUNT(*) AS n FROM assessment_files "
                "WHERE run_id=? GROUP BY directory_id, status ORDER BY directory_id",
                (run_id,),
            )
        )
