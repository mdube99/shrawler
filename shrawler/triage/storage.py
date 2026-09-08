"""Snapshot-based ranking persisted separately from the read-only inventory."""

import hashlib
import json
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

from .engine import ENGINE_VERSION, Engine
from .rules import RuleSet
from .siblings import SiblingIndex

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


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def result_path(database: Path) -> Path:
    return database.with_name(database.stem + ".triage.db")


def connect_readonly(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def select_scan(
    connection: sqlite3.Connection, requested: Optional[str]
) -> sqlite3.Row:
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
                "ORDER BY started_at_utc DESC, rowid DESC LIMIT 1"
            )
        )
    if len(rows) != 1:
        raise ValueError(
            "no matching scan; specify --scan with a full or short scan ID (default: latest completed inventory scan)"
        )
    if rows[0]["mode"] not in {"spider", "snaffle"}:
        raise ValueError("triage requires a spider or snaffle inventory scan")
    return rows[0]


def observations(source: sqlite3.Connection, scan_id: str) -> Iterator[Dict[str, Any]]:
    rows = source.execute(
        "SELECT f.public_id, h.host, s.name AS share, sf.payload_json "
        "FROM scan_files sf JOIN files f ON f.id=sf.file_id "
        "JOIN shares s ON s.id=sf.share_id JOIN hosts h ON h.id=s.host_id "
        "WHERE sf.scan_id=? ORDER BY sf.file_id",
        (scan_id,),
    )
    for row in rows:
        payload = json.loads(row["payload_json"])
        metadata = {
            **payload,
            "host": row["host"],
            "share": row["share"],
            "file_id": row["public_id"],
        }
        for field in ("file_name", "remote_path", "unc_path"):
            if not isinstance(metadata.get(field), str):
                raise ValueError(f"invalid scan observation: missing {field}")
        if type(metadata.get("size_bytes")) is not int or metadata["size_bytes"] < 0:
            raise ValueError(
                "invalid scan observation: size_bytes must be a nonnegative integer"
            )
        yield metadata


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
            version = target.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1, 2):
                raise ValueError(f"unsupported triage database version: {version}")
            target.executescript(SCHEMA)
            target.execute("PRAGMA user_version=2")
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
                if sibling_index.contexts or inventory_signals.builtins:
                    if on_phase:
                        on_phase("indexing sibling names", 0)
                    for indexed, metadata in enumerate(
                        observations(source, scan["id"]), 1
                    ):
                        if cancelled and cancelled():
                            raise KeyboardInterrupt
                        sibling_index.observe(metadata)
                        inventory_signals.observe(metadata)
                        if indexed % 1000 == 0:
                            target.commit()
                        if on_phase and indexed % 10000 == 0:
                            on_phase("indexing sibling names", indexed)
                engine = Engine(rules, sibling_index.lookup)
                if on_phase:
                    on_phase("scoring", 0)
                file_rows = []
                category_rows = []
                for metadata in observations(source, scan["id"]):
                    if cancelled and cancelled():
                        raise KeyboardInterrupt
                    serialized = json.dumps(
                        metadata, sort_keys=True, separators=(",", ":")
                    )
                    digest.update(serialized.encode() + b"\n")
                    evaluated = engine.evaluate(metadata)
                    inventory_signals.apply(metadata, evaluated)
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
                    file_rows.append(
                        (run_id, metadata["file_id"], evaluated["priority"], serialized,
                         json.dumps(evaluated, sort_keys=True, separators=(",", ":")))
                    )
                    category_rows.extend(
                        (
                            (run_id, metadata["file_id"], category, score)
                            for category, score in evaluated["category_scores"].items()
                        )
                    )
                    count += 1
                    if count % 1000 == 0:
                        target.executemany(
                            "INSERT INTO triage_files VALUES (?,?,?,?,?)", file_rows
                        )
                        target.executemany(
                            "INSERT INTO triage_categories VALUES (?,?,?,?)",
                            category_rows,
                        )
                        file_rows.clear()
                        category_rows.clear()
                        target.execute(
                            "UPDATE triage_runs SET file_count=? WHERE id=?",
                            (count, run_id),
                        )
                        target.commit()
                    if progress and count % 10000 == 0:
                        progress(count)
                    if on_phase and count % 10000 == 0:
                        on_phase("scoring", count)
                target.executemany(
                    "INSERT INTO triage_files VALUES (?,?,?,?,?)", file_rows
                )
                target.executemany(
                    "INSERT INTO triage_categories VALUES (?,?,?,?)", category_rows
                )
                target.execute(
                    "INSERT INTO triage_summaries VALUES (?,?)",
                    (run_id, json.dumps(summary)),
                )
                target.execute(
                    "UPDATE triage_runs SET status='completed', finished_at=?, file_count=?, inventory_hash=? WHERE id=?",
                    (utc_now(), count, digest.hexdigest(), run_id),
                )
                target.commit()
            except BaseException as exc:
                target.rollback()
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
    }


def select_run(
    connection: sqlite3.Connection, database: Path, run_id: Optional[str]
) -> sqlite3.Row:
    clause = " AND id=?" if run_id else ""
    values = (str(database.resolve()), run_id) if run_id else (str(database.resolve()),)
    row = connection.execute(
        "SELECT * FROM triage_runs WHERE source_path=? AND status='completed'"
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
        score = "c.score" if category else "f.priority"
        identifier = "c.file_id" if category else "f.file_id"
        query = (
            (
                "SELECT f.*, c.score AS review_score FROM triage_categories c "
                "JOIN triage_files f ON f.run_id=c.run_id AND f.file_id=c.file_id "
                "WHERE c.run_id=? AND c.category=? AND c.score>=?"
            )
            if category
            else (
                "SELECT f.*, f.priority AS review_score FROM triage_files f WHERE f.run_id=? AND f.priority>=?"
            )
        )
        values: List[Any] = (
            [run["id"], category, min_score] if category else [run["id"], min_score]
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
                **json.loads(row["metadata_json"]),
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
                "SELECT id, short_id, mode, status, started_at_utc, domain, username FROM scans "
                "WHERE mode IN ('spider','snaffle') ORDER BY started_at_utc DESC, rowid DESC LIMIT 200"
            )
        ]
    runs: List[Dict[str, Any]] = []
    if result_path(database).exists():
        with closing(connect_readonly(result_path(database))) as connection:
            for row in connection.execute(
                "SELECT id,scan_id,status,started_at,file_count,rules_hash,rules_json,scan_json FROM triage_runs "
                "WHERE source_path=? ORDER BY started_at DESC,rowid DESC LIMIT 200",
                (str(database.resolve()),),
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
        row = connection.execute(
            "SELECT * FROM triage_files WHERE run_id=? AND file_id=?",
            (run["id"], file_id),
        ).fetchone()
        if row is None:
            raise ValueError("file ID was not present in the selected ranking run")
        metadata = json.loads(row["metadata_json"])
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
