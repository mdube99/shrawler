"""Snapshot-based ranking persisted separately from the read-only inventory."""

import hashlib
import json
import os
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

from .engine import ENGINE_VERSION, Engine
from .rules import RuleSet
from .siblings import SiblingIndex

WEB_SORT_INDEXES = (
    (
        "triage_priority_web",
        "CREATE INDEX IF NOT EXISTS triage_priority_web ON triage_files(run_id, priority DESC, file_id DESC)",
    ),
    (
        "triage_category_web",
        "CREATE INDEX IF NOT EXISTS triage_category_web ON triage_categories(run_id, category, score DESC, file_id DESC)",
    ),
)

BATCH_SIZE = 10_000
SCHEMA_VERSION = 3

SCHEMA = """
CREATE TABLE IF NOT EXISTS triage_runs (
 id TEXT PRIMARY KEY, source_path TEXT NOT NULL, scan_id TEXT NOT NULL,
 started_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL,
 engine_version TEXT NOT NULL, rules_hash TEXT NOT NULL, rules_json TEXT NOT NULL,
 scan_json TEXT NOT NULL, inventory_hash TEXT, file_count INTEGER NOT NULL DEFAULT 0,
 error TEXT
);
CREATE TABLE IF NOT EXISTS triage_summaries (
 run_id TEXT PRIMARY KEY REFERENCES triage_runs(id), summary_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS triage_files (
 run_id TEXT NOT NULL REFERENCES triage_runs(id), file_id TEXT NOT NULL,
 priority INTEGER NOT NULL, metadata_json TEXT NOT NULL, result_json TEXT NOT NULL,
 PRIMARY KEY(run_id, file_id)
);
CREATE TABLE IF NOT EXISTS triage_categories (
 run_id TEXT NOT NULL, file_id TEXT NOT NULL, category TEXT NOT NULL,
 score INTEGER NOT NULL, PRIMARY KEY(run_id, file_id, category),
 FOREIGN KEY(run_id, file_id) REFERENCES triage_files(run_id, file_id)
);
CREATE INDEX IF NOT EXISTS triage_priority ON triage_files(run_id, priority DESC, file_id);
CREATE INDEX IF NOT EXISTS triage_category_score ON triage_categories(run_id, category, score DESC, file_id);
"""

# Ranking rows are staged here in observation order and moved into the real
# tables in public_id order at the end of the run. Inserting into the ranked
# tables (whose keys are the random opaque public_id) in sorted order turns
# scattered B-tree writes into sequential ones; measured ~6x on 2M rows. The
# staging tables are dropped when the run finishes.
STAGE_SCHEMA = """
CREATE TABLE IF NOT EXISTS triage_stage_files (
 file_id TEXT NOT NULL, priority INTEGER NOT NULL,
 metadata_json TEXT NOT NULL, result_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS triage_stage_categories (
 file_id TEXT NOT NULL, category TEXT NOT NULL, score INTEGER NOT NULL
);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cache_kib(env_name: str, default_mb: int) -> int:
    """Bounded page cache in KiB, overridable for measurement."""
    raw = os.environ.get(env_name)
    if raw:
        try:
            megabytes = int(raw)
        except ValueError:
            megabytes = 0
        if megabytes > 0:
            return megabytes * 1024
    return default_mb * 1024


def result_path(database: Path) -> Path:
    return database.with_name(database.stem + ".triage.db")


def connect_readonly(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    # Large streamed joins (observations, review build) benefit directly.
    connection.execute("PRAGMA cache_size=-262144")  # 256 MiB page cache
    connection.execute("PRAGMA mmap_size=1073741824")
    connection.execute("PRAGMA temp_store=MEMORY")
    return connection


def select_scan(
    connection: sqlite3.Connection, requested: Optional[str]
) -> sqlite3.Row:
    # Only scans with committed observations are candidates: an empty
    # "completed" scan (for example, a shares-only pass) must not shadow a
    # newer inventory that actually holds files.
    observed = "EXISTS (SELECT 1 FROM scan_files sf WHERE sf.scan_id=scans.id)"
    if requested:
        rows = list(
            connection.execute(
                "SELECT * FROM scans WHERE id=? OR short_id=?", (requested, requested)
            )
        )
    else:
        rows = list(
            connection.execute(
                "SELECT * FROM scans WHERE status='completed' AND mode IN ('spider', 'snaffle') "
                f"AND {observed} ORDER BY started_at_utc DESC, rowid DESC LIMIT 1"
            )
        )
        if not rows:
            # No completed scan holds observations; prefer the latest inventory
            # with files (partial/interrupted) so it can still be scored. The
            # source status is reported to the caller.
            rows = list(
                connection.execute(
                    "SELECT * FROM scans WHERE mode IN ('spider', 'snaffle') "
                    f"AND {observed} ORDER BY started_at_utc DESC, rowid DESC LIMIT 1"
                )
            )
    if len(rows) != 1:
        raise ValueError(
            "no matching scan; specify --scan with a full or short scan ID (default: latest completed inventory scan with observations)"
        )
    if rows[0]["mode"] not in {"spider", "snaffle"}:
        raise ValueError("triage requires a spider or snaffle inventory scan")
    return rows[0]


def observables(
    source: sqlite3.Connection, scan_id: str, skip: int = 0
) -> Iterator[Tuple[Dict[str, Any], str]]:
    """Stream (metadata, raw payload) pairs; raw bytes feed the digest without a re-serialize.

    `skip` discards the first N rows (already staged elsewhere) without parsing them.
    """
    rows = source.execute(
        "SELECT f.public_id, h.host, s.name AS share, sf.payload_json "
        "FROM scan_files sf JOIN files f ON f.id=sf.file_id "
        "JOIN shares s ON s.id=sf.share_id JOIN hosts h ON h.id=s.host_id "
        "WHERE sf.scan_id=? ORDER BY sf.file_id",
        (scan_id,),
    )
    for row in rows:
        if skip:
            skip -= 1
            continue
        payload = row["payload_json"]
        metadata = json.loads(payload)
        metadata.update(
            {"host": row["host"], "share": row["share"], "file_id": row["public_id"]}
        )
        for field in ("file_name", "remote_path", "unc_path"):
            if not isinstance(metadata.get(field), str):
                raise ValueError(f"invalid scan observation: missing {field}")
        if type(metadata.get("size_bytes")) is not int or metadata["size_bytes"] < 0:
            raise ValueError(
                "invalid scan observation: size_bytes must be a nonnegative integer"
            )
        yield metadata, payload


def observations(source: sqlite3.Connection, scan_id: str) -> Iterator[Dict[str, Any]]:
    for metadata, _raw in observables(source, scan_id):
        yield metadata


def digest_value(metadata: Dict[str, Any], raw: str) -> bytes:
    """Deterministic run digest: stored payload plus the injected keys, no re-serialize."""
    return (
        " ".join(
            (
                metadata["host"],
                metadata["share"],
                metadata["file_id"],
                raw,
            )
        ).encode()
        + b"\n"
    )


def _lean_zero_result(evaluated: Dict[str, Any]) -> str:
    """Minimal, valid result JSON for priority-0 files with no signals of their own.

    Derived snapshots stay rebuildable; the web views merge these keys exactly
    like a full result, and a later review event still lands via json_set.
    """
    return json.dumps(
        {
            "priority": 0,
            "category_scores": {},
            "evidence_type": "metadata_only",
            "signals": [],
            "contexts": [],
            "family_id": evaluated["family_id"],
            "review": evaluated["review"],
        },
        sort_keys=True,
        separators=(",", ":"),
    )



def rank(
    database: Path,
    rules: RuleSet,
    scan_id: Optional[str] = None,
    output: Optional[Path] = None,
    progress: Optional[Callable[[int], None]] = None,
    on_phase: Optional[Callable[[str, int], None]] = None,
    cancelled: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    destination = output or result_path(database)
    if destination.resolve() == database.resolve():
        raise ValueError("ranking results must be separate from the inventory")
    run_id = uuid.uuid4().hex
    count = 0
    digest = hashlib.sha256()
    summary: Dict[str, Any] = {"positive_files": 0, "rule_matches": {}, "samples": []}
    sample_groups: Set[Tuple[str, str, str]] = set()
    timings: Dict[str, float] = {}
    started = perf_counter()
    # BEGIN pins all scan observations to a single SQLite read snapshot.
    with closing(connect_readonly(database)) as source:
        source.execute("BEGIN")
        scan = select_scan(source, scan_id)
        scan_data = dict(scan)
        with closing(sqlite3.connect(destination)) as target:
            target.execute("PRAGMA foreign_keys=ON")
            target.execute("PRAGMA journal_mode=WAL")
            target.execute("PRAGMA synchronous=NORMAL")
            target.execute("PRAGMA busy_timeout=5000")
            # The writer previously used the default page cache. A bounded,
            # explicit cache keeps upper B-tree pages resident while inserting
            # rows keyed by random opaque file IDs.
            target.execute(
                f"PRAGMA cache_size=-{_cache_kib('SHRAWLER_TRIAGE_CACHE_MB', 128)}"
            )
            version = target.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1, 2, 3):
                raise ValueError(f"unsupported triage database version: {version}")
            target.executescript(SCHEMA)
            for _, statement in WEB_SORT_INDEXES:
                target.execute(statement)
            target.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            target.execute(
                "INSERT INTO triage_runs(id,source_path,scan_id,started_at,status,engine_version,rules_hash,rules_json,scan_json) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    run_id,
                    str(database.resolve()),
                    scan["id"],
                    utc_now(),
                    "running",
                    ENGINE_VERSION,
                    rules.digest,
                    rules.canonical,
                    json.dumps(scan_data, sort_keys=True),
                ),
            )
            target.commit()
            target.executescript(STAGE_SCHEMA)
            target.execute("DELETE FROM triage_stage_files")
            target.execute("DELETE FROM triage_stage_categories")
            target.commit()
            try:
                from .signals import InventorySignals

                sibling_index = SiblingIndex(target, rules)
                inventory_signals = InventorySignals(
                    target,
                    database,
                    any(
                        rule["id"].startswith("builtin.")
                        for rule in rules.document.get("rules", [])
                    ),
                )
                indexing_needed = bool(
                    sibling_index.contexts or inventory_signals.builtins
                )
                if indexing_needed and on_phase:
                    on_phase("indexing sibling names", 0)

                engine = Engine(rules, sibling_index.lookup)
                # Phase accounting. Timers are cheap relative to per-file work
                # (~160 us/file on the real 2.5M inventory) and let callers see
                # exactly where scoring time goes.
                metrics: Dict[str, float] = {
                    "read": 0.0,
                    "evaluate": 0.0,
                    "signals": 0.0,
                    "serialize": 0.0,
                    "row_build": 0.0,
                    "insert": 0.0,
                }
                timings["setup_seconds"] = perf_counter() - started

                def score(metadata: Dict[str, Any], raw: str) -> None:
                    nonlocal count
                    if cancelled and cancelled():
                        raise KeyboardInterrupt
                    mark = perf_counter()
                    digest.update(digest_value(metadata, raw))
                    evaluated = engine.evaluate(metadata)
                    after_evaluate = perf_counter()
                    inventory_signals.apply(metadata, evaluated)
                    after_signals = perf_counter()
                    if evaluated["priority"] > 0:
                        summary["positive_files"] += 1
                        group = (
                            metadata["host"],
                            metadata["share"],
                            metadata["remote_path"]
                            .replace("\\", "/")
                            .rsplit("/", 1)[0],
                        )
                        if group not in sample_groups and len(summary["samples"]) < 20:
                            summary["samples"].append(
                                {
                                    "file_id": metadata["file_id"],
                                    "unc_path": metadata["unc_path"],
                                    "priority": evaluated["priority"],
                                }
                            )
                            sample_groups.add(group)
                    for signal in evaluated["signals"]:
                        summary["rule_matches"][signal["rule_id"]] = (
                            summary["rule_matches"].get(signal["rule_id"], 0) + 1
                        )
                    if evaluated["priority"] == 0 and not evaluated["signals"]:
                        result_json = _lean_zero_result(evaluated)
                    else:
                        result_json = json.dumps(
                            evaluated, sort_keys=True, separators=(",", ":")
                        )
                    after_serialize = perf_counter()
                    file_rows.append(
                        (
                            metadata["file_id"],
                            evaluated["priority"],
                            ""
                            if output is None
                            else json.dumps(
                                metadata, sort_keys=True, separators=(",", ":")
                            ),
                            result_json,
                        )
                    )
                    category_rows.extend(
                        (
                            (metadata["file_id"], category, score_value)
                            for category, score_value in evaluated[
                                "category_scores"
                            ].items()
                        )
                    )
                    after_row = perf_counter()
                    metrics["evaluate"] += after_evaluate - mark
                    metrics["signals"] += after_signals - after_evaluate
                    metrics["serialize"] += after_serialize - after_signals
                    metrics["row_build"] += after_row - after_serialize
                    count += 1
                    if count % BATCH_SIZE == 0:
                        batch_write()
                        if progress:
                            progress(count)
                        if on_phase:
                            on_phase("scoring", count)

                def score_stream(iterator: Iterator[Tuple[Dict[str, Any], str]]) -> None:
                    """Score a stream, attributing time between rows to reading."""
                    last = perf_counter()
                    for metadata, raw in iterator:
                        now = perf_counter()
                        metrics["read"] += now - last
                        score(metadata, raw)
                        last = perf_counter()

                if on_phase:
                    on_phase("scoring", 0)
                file_rows = []
                category_rows = []

                def batch_write() -> None:
                    mark = perf_counter()
                    target.executemany(
                        "INSERT INTO triage_stage_files VALUES (?,?,?,?)", file_rows
                    )
                    target.executemany(
                        "INSERT INTO triage_stage_categories VALUES (?,?,?)",
                        category_rows,
                    )
                    file_rows.clear()
                    category_rows.clear()
                    target.execute(
                        "UPDATE triage_runs SET file_count=? WHERE id=?",
                        (count, run_id),
                    )
                    target.commit()
                    metrics["insert"] += perf_counter() - mark

                stream = observables(source, scan["id"])
                if indexing_needed:
                    if on_phase:
                        on_phase("indexing sibling names", 0)
                    # Single pass: observations are consumed once for indexing
                    # and score in the same stream; the leading batch stays
                    # alive in memory so it is not parsed a second time.
                    staged: List[Tuple[Dict[str, Any], str]] = []
                    indexing_started = perf_counter()
                    for indexed, (metadata, raw) in enumerate(stream, 1):
                        if cancelled and cancelled():
                            raise KeyboardInterrupt
                        sibling_index.observe(metadata)
                        inventory_signals.observe(metadata)
                        if len(staged) < BATCH_SIZE:
                            staged.append((metadata, raw))
                        if indexed % BATCH_SIZE == 0:
                            sibling_index.flush()
                            inventory_signals.flush()
                            target.commit()
                        if on_phase and indexed % 10000 == 0:
                            on_phase("indexing sibling names", indexed)
                    sibling_index.flush()
                    inventory_signals.flush()
                    target.commit()
                    timings["indexing_seconds"] = perf_counter() - indexing_started
                    scoring_started = perf_counter()
                    for metadata, raw in staged:
                        score(metadata, raw)
                    # Second cursor; the staged prefix is skipped unparsed.
                    score_stream(observables(source, scan["id"], skip=BATCH_SIZE))
                else:
                    timings["indexing_seconds"] = 0.0
                    scoring_started = perf_counter()
                    score_stream(stream)
                finalize_started = perf_counter()
                # Flush the trailing partial batch into staging, then move all
                # rows into the ranked tables in public_id order. The ranked
                # keys are random opaque IDs, so sorted insertion turns
                # scattered B-tree writes into sequential ones.
                target.executemany(
                    "INSERT INTO triage_stage_files VALUES (?,?,?,?)", file_rows
                )
                target.executemany(
                    "INSERT INTO triage_stage_categories VALUES (?,?,?)", category_rows
                )
                file_rows.clear()
                category_rows.clear()
                materialize_started = perf_counter()
                target.execute(
                    "CREATE INDEX IF NOT EXISTS triage_stage_files_idx "
                    "ON triage_stage_files(file_id)"
                )
                target.execute(
                    "CREATE INDEX IF NOT EXISTS triage_stage_categories_idx "
                    "ON triage_stage_categories(file_id)"
                )
                target.execute(
                    "INSERT INTO triage_files"
                    "(run_id,file_id,priority,metadata_json,result_json) "
                    "SELECT ?,file_id,priority,metadata_json,result_json "
                    "FROM triage_stage_files ORDER BY file_id",
                    (run_id,),
                )
                target.execute(
                    "INSERT INTO triage_categories(run_id,file_id,category,score) "
                    "SELECT ?,file_id,category,score "
                    "FROM triage_stage_categories ORDER BY file_id",
                    (run_id,),
                )
                timings["materialize_seconds"] = perf_counter() - materialize_started
                target.execute("DROP TABLE IF EXISTS triage_stage_files")
                target.execute("DROP TABLE IF EXISTS triage_stage_categories")
                target.execute(
                    "INSERT INTO triage_summaries VALUES (?,?)",
                    (run_id, json.dumps(summary)),
                )
                target.execute(
                    "UPDATE triage_runs SET status='completed', finished_at=?, file_count=?, inventory_hash=? WHERE id=?",
                    (utc_now(), count, digest.hexdigest(), run_id),
                )
                target.commit()
                timings["finalize_seconds"] = perf_counter() - finalize_started
                timings["scoring_and_saving_seconds"] = (
                    perf_counter() - scoring_started
                )
                timings["read_and_parse_seconds"] = metrics["read"]
                timings["evaluate_seconds"] = metrics["evaluate"]
                timings["signals_seconds"] = metrics["signals"]
                timings["serialize_seconds"] = metrics["serialize"]
                timings["row_build_seconds"] = metrics["row_build"]
                timings["insert_seconds"] = metrics["insert"]
            except BaseException as exc:
                target.rollback()
                # Leave the derived database clean even when a run fails.
                target.execute("DROP TABLE IF EXISTS triage_stage_files")
                target.execute("DROP TABLE IF EXISTS triage_stage_categories")
                persisted = target.execute(
                    "SELECT COUNT(*) FROM triage_files WHERE run_id=?", (run_id,)
                ).fetchone()[0]
                target.execute(
                    "UPDATE triage_runs SET status=?, finished_at=?, file_count=?, error=? WHERE id=?",
                    (
                        "interrupted"
                        if isinstance(exc, KeyboardInterrupt)
                        else "failed",
                        utc_now(),
                        persisted,
                        str(exc),
                        run_id,
                    ),
                )
                target.commit()
                raise
    return {
        "run_id": run_id,
        "scan_id": scan_data["id"],
        "scan_status": scan_data["status"],
        "files_scored": count,
        "rules_hash": rules.digest,
        "inventory_hash": digest.hexdigest(),
        "results_database": str(destination),
        "summary": summary,
        "timings": timings,
    }


def select_run(
    connection: sqlite3.Connection, database: Path, run_id: Optional[str]
) -> sqlite3.Row:
    with closing(connect_readonly(database)) as source:
        scan_ids = {str(row[0]) for row in source.execute("SELECT id FROM scans")}
    if not scan_ids:
        raise ValueError("no completed ranking run found for this inventory")
    clause = " AND id=?" if run_id else ""
    placeholders = ",".join("?" for _ in scan_ids)
    values: Tuple[Any, ...] = (*scan_ids, run_id) if run_id else tuple(scan_ids)
    row = connection.execute(
        f"SELECT * FROM triage_runs WHERE scan_id IN ({placeholders}) AND status='completed'"
        + clause
        + " ORDER BY started_at DESC, rowid DESC LIMIT 1",
        values,
    ).fetchone()
    if row is None:
        raise ValueError("no completed ranking run found for this inventory")
    return row


def list_results(
    database: Path,
    run_id: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = 100,
    min_score: int = 0,
    output: Optional[Path] = None,
    after: Optional[Tuple[int, str]] = None,
) -> Dict[str, Any]:
    if not 1 <= limit <= 10000 or min_score < 0:
        raise ValueError("limit must be 1..10000 and minimum score must be nonnegative")
    with closing(connect_readonly(output or result_path(database))) as connection:
        run = select_run(connection, database, run_id)
        connection.execute("ATTACH DATABASE ? AS inventory", (str(database.resolve()),))
        score = "c.score" if category else "f.priority"
        identifier = "c.file_id" if category else "f.file_id"
        query = (
            (
                "SELECT f.*, COALESCE(NULLIF(f.metadata_json,''),json_set(sf.payload_json,'$.host',i.host,'$.share',i.share,'$.file_id',i.public_id)) AS resolved_metadata_json, c.score AS review_score FROM triage_categories c "
                "JOIN triage_files f ON f.run_id=c.run_id AND f.file_id=c.file_id "
                "LEFT JOIN inventory.files i ON i.public_id=f.file_id "
                "LEFT JOIN inventory.scan_files sf ON sf.scan_id=? AND sf.file_id=i.id "
                "WHERE c.run_id=? AND c.category=? AND c.score>=?"
            )
            if category
            else (
                "SELECT f.*, COALESCE(NULLIF(f.metadata_json,''),json_set(sf.payload_json,'$.host',i.host,'$.share',i.share,'$.file_id',i.public_id)) AS resolved_metadata_json, f.priority AS review_score FROM triage_files f "
                "LEFT JOIN inventory.files i ON i.public_id=f.file_id "
                "LEFT JOIN inventory.scan_files sf ON sf.scan_id=? AND sf.file_id=i.id WHERE f.run_id=? AND f.priority>=?"
            )
        )
        values: List[Any] = (
            [run["scan_id"], run["id"], category, min_score]
            if category
            else [run["scan_id"], run["id"], min_score]
        )
        if category == "extension-fallback":
            # Category membership is supplied by the zero-point extension rule.
            # Keep this pool disjoint from recommendations and analyst decisions.
            query += (
                " AND f.priority=0 AND json_extract(f.result_json, '$.review') IS NULL"
            )
        if after is not None:
            if type(after[0]) is not int or after[0] < 0:
                raise ValueError("invalid ranking cursor")
            query += f" AND ({score} < ? OR ({score} = ? AND {identifier} > ?))"
            values.extend((after[0], after[0], after[1]))
        query += f" ORDER BY {score} DESC, {identifier} LIMIT ?"
        rows = list(connection.execute(query, (*values, limit + 1)))
        items = [
            {
                **json.loads(row["resolved_metadata_json"]),
                **json.loads(row["result_json"]),
                "review_score": row["review_score"],
            }
            for row in rows[:limit]
        ]
        summary: Dict[str, Any] = {}
        if connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name='triage_summaries'"
        ).fetchone():
            found = connection.execute(
                "SELECT summary_json FROM triage_summaries WHERE run_id=?", (run["id"],)
            ).fetchone()
            if found:
                summary = json.loads(found[0])
        return {
            "run_id": run["id"],
            "scan_id": run["scan_id"],
            "files_scored": run["file_count"],
            "summary": summary,
            "items": items,
            "next_cursor": [items[-1]["review_score"], items[-1]["file_id"]]
            if len(rows) > limit
            else None,
        }


def catalog(database: Path) -> Dict[str, Any]:
    with closing(connect_readonly(database)) as source:
        scans = [
            dict(row)
            for row in source.execute(
                "SELECT id, short_id, mode, status, started_at_utc, domain, username, "
                "(SELECT COUNT(*) FROM scan_files sf WHERE sf.scan_id=scans.id) AS file_count "
                "FROM scans WHERE mode IN ('spider','snaffle') "
                "ORDER BY started_at_utc DESC, rowid DESC LIMIT 200"
            )
        ]
    scan_ids = {str(scan["id"]) for scan in scans}
    runs: List[Dict[str, Any]] = []
    if result_path(database).exists() and scan_ids:
        with closing(connect_readonly(result_path(database))) as connection:
            placeholders = ",".join("?" for _ in scan_ids)
            for row in connection.execute(
                "SELECT id,scan_id,status,started_at,file_count,rules_hash,rules_json,scan_json FROM triage_runs "
                f"WHERE scan_id IN ({placeholders}) ORDER BY started_at DESC,rowid DESC LIMIT 200",
                tuple(scan_ids),
            ):
                entry = dict(row)
                rules = json.loads(entry.pop("rules_json"))
                entry["categories"] = sorted(
                    {rule["category"] for rule in rules.get("rules", [])}
                )
                entry["source_scan_status"] = json.loads(entry.pop("scan_json"))[
                    "status"
                ]
                runs.append(entry)
    return {"scans": scans, "runs": runs}


def explain(
    database: Path, file_id: str, run_id: Optional[str] = None
) -> Dict[str, Any]:
    from .rules import validate

    with closing(connect_readonly(result_path(database))) as connection:
        run = select_run(connection, database, run_id)
        connection.execute("ATTACH DATABASE ? AS inventory", (str(database.resolve()),))
        row = connection.execute(
            "SELECT f.*,COALESCE(NULLIF(f.metadata_json,''),json_set(sf.payload_json,'$.host',i.host,'$.share',i.share,'$.file_id',i.public_id)) AS resolved_metadata_json "
            "FROM triage_files f LEFT JOIN inventory.files i ON i.public_id=f.file_id "
            "LEFT JOIN inventory.scan_files sf ON sf.scan_id=? AND sf.file_id=i.id "
            "WHERE f.run_id=? AND f.file_id=?",
            (run["scan_id"], run["id"], file_id),
        ).fetchone()
        if row is None:
            raise ValueError("file ID was not present in the selected ranking run")
        metadata = json.loads(row["resolved_metadata_json"])
        result = json.loads(row["result_json"])
        # Stored results remain authoritative if an engine upgrade changes behavior.
        if run["engine_version"] == ENGINE_VERSION:
            result["rule_diagnostics"] = Engine(
                validate(json.loads(run["rules_json"]))
            ).evaluate(metadata, True, result.get("contexts", []))["rule_diagnostics"]
        return {
            "run_id": run["id"],
            "scan_id": run["scan_id"],
            "rules_hash": run["rules_hash"],
            "inventory_hash": run["inventory_hash"],
            "engine_version": run["engine_version"],
            **metadata,
            **result,
        }
