"""Durable assessment store: ``<inventory-stem>.jev.db``.

Storage is versioned independently of the rule engine. Network waits are never
held inside a write transaction; callers commit bounded batches between them.
"""

import hashlib
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .config import canonical

SCHEMA_VERSION = 1

# A run lease heartbeats at this interval; another process may reclaim the run
# once the heartbeat is older than LEASE_TTL_SECONDS.
LEASE_TTL_SECONDS = 300

SCHEMA = """
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
 error TEXT
);
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
CREATE TABLE IF NOT EXISTS request_batches (
 id TEXT PRIMARY KEY,
 run_id TEXT NOT NULL,
 directory_id INTEGER NOT NULL,
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
CREATE TABLE IF NOT EXISTS batch_members (
 run_id TEXT NOT NULL,
 batch_id TEXT NOT NULL,
 file_id TEXT NOT NULL,
 ordinal INTEGER NOT NULL,
 PRIMARY KEY(batch_id, file_id)
);
CREATE INDEX IF NOT EXISTS batch_members_file ON batch_members(run_id, file_id);
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
 created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS decision_results_file
 ON decision_results(run_id, file_id);
CREATE TABLE IF NOT EXISTS decision_cache (
 run_id TEXT NOT NULL,
 cache_key TEXT NOT NULL,
 batch_id TEXT NOT NULL,
 created_at TEXT NOT NULL,
 PRIMARY KEY(run_id, cache_key)
);
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


class JevStoreError(ValueError):
    pass


class RunBusyError(JevStoreError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def assessment_path(database: Path) -> Path:
    return database.with_name(database.stem + ".jev.db")


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
        if version not in (0, SCHEMA_VERSION):
            raise JevStoreError(
                f"no migration path from assessment database version {version}"
            )
        self.connection.executescript(SCHEMA)
        self.connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        self.connection.commit()
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "JevStore":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

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
        self.connection.executemany(
            "INSERT OR REPLACE INTO assessment_files(run_id,file_id,directory_id,"
            "file_name,remote_path,unc_path,size_bytes,mtime_utc,extension,"
            "feature_json,feature_hash,priority,status,updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )

    def commit(self) -> None:
        self.connection.commit()

    def file_row(self, run_id: str, file_id: str) -> Optional[sqlite3.Row]:
        return self.connection.execute(
            "SELECT * FROM assessment_files WHERE run_id=? AND file_id=?",
            (run_id, file_id),
        ).fetchone()

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

    def set_file_status(self, run_id: str, file_ids: List[str], status: str, **extra: Any) -> None:
        if not file_ids:
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
        placeholders = ",".join("?" for _ in file_ids)
        self.connection.execute(
            f"UPDATE assessment_files SET {', '.join(assignments)} WHERE run_id=? "
            f"AND file_id IN ({placeholders})",
            (*tail, run_id, *file_ids),
        )

    # -- batches ----------------------------------------------------------

    def insert_batch(
        self,
        batch_id: str,
        run_id: str,
        directory_id: int,
        request_id: str,
        ordinal: int,
        payload: Dict[str, Any],
        input_tokens: int,
        state: str,
        questions: Dict[str, Any],
        members: List[str],
        cache_key: str,
    ) -> None:
        payload_hash = hashlib.sha256(canonical(payload).encode()).hexdigest()
        with self.connection:
            self.connection.execute(
                "INSERT INTO request_batches(id,run_id,directory_id,request_id,ordinal,"
                "payload_json,payload_sha256,input_tokens,state_json,question_json,"
                "status,created_at,cache_key) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    batch_id,
                    run_id,
                    directory_id,
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
            self.connection.executemany(
                "INSERT INTO batch_members(run_id,batch_id,file_id,ordinal) VALUES (?,?,?,?)",
                [(run_id, batch_id, file_id, index) for index, file_id in enumerate(members)],
            )

    def mark_batch_dispatched(self, batch_id: str) -> None:
        with self.connection:
            self.connection.execute(
                "UPDATE request_batches SET status='in-flight', dispatched_at=?, "
                "attempts=attempts+1 WHERE id=?",
                (utc_now(), batch_id),
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

    def batch_rows(self, run_id: str, status: Optional[str] = None) -> List[sqlite3.Row]:
        clause = " AND status=?" if status else ""
        values: Tuple[Any, ...] = (run_id, status) if status else (run_id,)
        return list(
            self.connection.execute(
                "SELECT * FROM request_batches WHERE run_id=?" + clause + " ORDER BY ordinal",
                values,
            )
        )

    def batch_members(self, batch_id: str) -> List[str]:
        return [
            row["file_id"]
            for row in self.connection.execute(
                "SELECT file_id FROM batch_members WHERE batch_id=? ORDER BY ordinal",
                (batch_id,),
            )
        ]

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
    ) -> int:
        cursor = self.connection.execute(
            "INSERT INTO decision_results(run_id,batch_id,request_id,file_id,choice,"
            "distribution_json,deployment_revision,model,adapter_version,rubric_version,"
            "context_hash,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
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
                utc_now(),
            ),
        )
        return int(cursor.lastrowid or 0)

    def put_cache(self, run_id: str, cache_key: str, batch_id: str) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO decision_cache(run_id,cache_key,batch_id,created_at) "
            "VALUES (?,?,?,?)",
            (run_id, cache_key, batch_id, utc_now()),
        )

    def cache_hit(self, run_id: str, cache_key: str) -> Optional[str]:
        row = self.connection.execute(
            "SELECT batch_id FROM decision_cache WHERE run_id=? AND cache_key=?",
            (run_id, cache_key),
        ).fetchone()
        return row["batch_id"] if row else None

    # -- coverage ---------------------------------------------------------

    def overall_counts(self, run_id: str) -> Dict[str, int]:
        rows = self.connection.execute(
            "SELECT status, COUNT(*) AS n FROM assessment_files WHERE run_id=? GROUP BY status",
            (run_id,),
        )
        return {row["status"]: row["n"] for row in rows}

    def directory_counts(self, run_id: str) -> List[sqlite3.Row]:
        return list(
            self.connection.execute(
                "SELECT directory_id, status, COUNT(*) AS n FROM assessment_files "
                "WHERE run_id=? GROUP BY directory_id, status ORDER BY directory_id",
                (run_id,),
            )
        )

    def results_for_directory(self, run_id: str, directory_id: int) -> List[sqlite3.Row]:
        return list(
            self.connection.execute(
                "SELECT r.choice, r.distribution_json, r.deployment_revision, r.model, "
                "f.file_id, f.file_name, f.unc_path, f.extension, f.size_bytes, f.mtime_utc "
                "FROM assessment_files f LEFT JOIN decision_results r ON r.id=f.result_id "
                "WHERE f.run_id=? AND f.directory_id=? AND f.status='assessed' "
                "ORDER BY f.file_id",
                (run_id, directory_id),
            )
        )
