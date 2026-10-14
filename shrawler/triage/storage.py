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

# The WebUI orders equal scores by ascending file id, which the primary
# triage_priority/triage_category_score indexes already cover. The older
# direction-specific copies were pure duplication.
WEB_SORT_INDEXES: Tuple[Tuple[str, str], ...] = ()

BATCH_SIZE = 10_000
SCHEMA_VERSION = 5

# Zero-point review pools: category membership is supplied by a zero-point rule
# and the listing keeps the pool disjoint from recommendations and analyst
# decisions.
FALLBACK_CATEGORIES = frozenset({"extension-fallback", "executable-fallback"})

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
 run_id TEXT NOT NULL REFERENCES triage_runs(id), file_id INTEGER NOT NULL,
 priority INTEGER NOT NULL, metadata_json TEXT NOT NULL, result_json TEXT NOT NULL,
 PRIMARY KEY(run_id, file_id)
);
CREATE TABLE IF NOT EXISTS triage_categories (
 run_id TEXT NOT NULL, file_id INTEGER NOT NULL, category TEXT NOT NULL,
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
 file_id INTEGER NOT NULL, priority INTEGER NOT NULL,
 metadata_json TEXT NOT NULL, result_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS triage_stage_categories (
 file_id INTEGER NOT NULL, category TEXT NOT NULL, score INTEGER NOT NULL
);
"""

# Explicit DDL used by the key migration, which cannot call executescript
# inside its transaction (executescript commits first).
_RESULT_TABLES_V5 = (
    "CREATE TABLE triage_files_new ("
    " run_id TEXT NOT NULL REFERENCES triage_runs(id), file_id INTEGER NOT NULL,"
    " priority INTEGER NOT NULL, metadata_json TEXT NOT NULL, result_json TEXT NOT NULL,"
    " PRIMARY KEY(run_id, file_id))",
    "CREATE TABLE triage_categories_new ("
    " run_id TEXT NOT NULL, file_id INTEGER NOT NULL, category TEXT NOT NULL,"
    " score INTEGER NOT NULL, PRIMARY KEY(run_id, file_id, category),"
    " FOREIGN KEY(run_id, file_id) REFERENCES triage_files_new(run_id, file_id))",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _metadata_json_expr(files_alias: str = "i", scan_alias: str = "sf") -> str:
    """Rebuild a file observation as JSON from inventory columns.

    The inventory no longer repeats the payload per scan, but per-scan size and
    timestamps are kept in ``scan_files`` so a historical ranking still reads
    the observation it saw at scan time. Key order matches the historical
    stored payload plus the ``share`` and ``file_id`` keys the old ``json_set``
    added.
    """
    size = f"COALESCE({scan_alias}.size_bytes,{files_alias}.size_bytes)"
    readable = f"COALESCE({scan_alias}.readable_size,{files_alias}.readable_size)"
    mtime = f"COALESCE({scan_alias}.mtime_utc,{files_alias}.mtime_utc)"
    stamp = (
        f"COALESCE({scan_alias}.scan_timestamp_utc,{files_alias}.scan_timestamp_utc)"
    )
    return (
        f"json_object('host',{files_alias}.host,'share_name',{files_alias}.share,"
        f"'remote_path',{files_alias}.remote_path,'unc_path',{files_alias}.unc_path,"
        f"'file_name',{files_alias}.file_name,'size_bytes',{size},"
        f"'readable_size',{readable},'mtime_utc',{mtime},"
        f"'is_directory',json('false'),'scan_timestamp_utc',{stamp},"
        f"'share',{files_alias}.share,'file_id',{files_alias}.public_id)"
    )


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
    _ensure_inventory_schema(path)
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    # Large streamed joins (observations, review build) benefit directly.
    connection.execute("PRAGMA cache_size=-262144")  # 256 MiB page cache
    connection.execute("PRAGMA mmap_size=1073741824")
    connection.execute("PRAGMA temp_store=MEMORY")
    return connection


def _migrate_results(connection: sqlite3.Connection, database: Path) -> None:
    """Rewrite pre-v5 result keys from public tokens to catalog integers.

    ``triage_files.file_id`` and ``triage_categories.file_id`` are rebuilt in
    one transaction, resolving ``public_id`` through the attached inventory.
    Derived runs whose file is gone from the inventory lose that row; a run is
    only reviewable against the inventory it was scored from.
    """
    version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if version == 0 or version >= SCHEMA_VERSION:
        return
    previous = connection.isolation_level
    connection.isolation_level = None
    connection.execute("PRAGMA foreign_keys=OFF")
    attached = False
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DROP TABLE IF EXISTS triage_stage_files")
        connection.execute("DROP TABLE IF EXISTS triage_stage_categories")
        for statement in _RESULT_TABLES_V5:
            connection.execute(statement)
        connection.execute(
            "ATTACH DATABASE ? AS inventory", (str(Path(database).resolve()),)
        )
        attached = True
        connection.execute(
            "INSERT INTO triage_files_new"
            "(run_id,file_id,priority,metadata_json,result_json) "
            "SELECT t.run_id,i.id,t.priority,t.metadata_json,t.result_json "
            "FROM triage_files t JOIN inventory.files i ON i.public_id=t.file_id"
        )
        connection.execute(
            "INSERT INTO triage_categories_new"
            "(run_id,file_id,category,score) "
            "SELECT c.run_id,i.id,c.category,c.score "
            "FROM triage_categories c JOIN inventory.files i ON i.public_id=c.file_id"
        )
        connection.execute("DROP TABLE triage_files")
        connection.execute("DROP TABLE triage_categories")
        connection.execute("ALTER TABLE triage_files_new RENAME TO triage_files")
        connection.execute(
            "ALTER TABLE triage_categories_new RENAME TO triage_categories"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS triage_priority"
            " ON triage_files(run_id, priority DESC, file_id)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS triage_category_score"
            " ON triage_categories(run_id, category, score DESC, file_id)"
        )
        connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        connection.execute("COMMIT")
    except BaseException:
        connection.execute("ROLLBACK")
        raise
    finally:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.isolation_level = previous
        if attached:
            try:
                connection.execute("DETACH DATABASE inventory")
            except sqlite3.Error:
                pass


def _ensure_result_schema(path: Path, database: Path) -> None:
    """Migrate a pre-v5 result database before a read-only open."""
    target = Path(path)
    if not target.is_file():
        return
    try:
        connection = sqlite3.connect(target, timeout=5)
    except sqlite3.Error:
        return
    try:
        _migrate_results(connection, database)
    finally:
        connection.close()


def _ensure_inventory_schema(path: Path) -> None:
    """Migrate a pre-normalization inventory before a read-only open.

    Only the inventory is touched: a triage result database has a different
    schema version and no ``files`` table.
    """
    try:
        connection = sqlite3.connect(
            path.resolve().as_uri() + "?mode=ro", uri=True
        )
    except sqlite3.Error:
        return
    try:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version != 1:
            return
        if (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='files'"
            ).fetchone()
            is None
        ):
            return
    except sqlite3.Error:
        return
    finally:
        connection.close()
    # Import lazily: shrawler.store imports coverage, which imports this module.
    from ..store import migrate_inventory

    migrate_inventory(path)


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
        "SELECT f.id AS row_id, f.public_id, h.host, s.name AS share, f.remote_path, "
        "f.unc_path, f.file_name, "
        "COALESCE(sf.size_bytes, f.size_bytes) AS size_bytes, "
        "COALESCE(sf.readable_size, f.readable_size) AS readable_size, "
        "COALESCE(sf.mtime_utc, f.mtime_utc) AS mtime_utc, "
        "COALESCE(sf.scan_timestamp_utc, f.scan_timestamp_utc) AS scan_timestamp_utc "
        "FROM scan_files sf JOIN files f ON f.id=sf.file_id "
        "JOIN shares s ON s.id=sf.share_id JOIN hosts h ON h.id=s.host_id "
        "WHERE sf.scan_id=? ORDER BY sf.file_id",
        (scan_id,),
    )
    for row in rows:
        if skip:
            skip -= 1
            continue
        base = {
            "host": row["host"],
            "share_name": row["share"],
            "remote_path": row["remote_path"],
            "unc_path": row["unc_path"],
            "file_name": row["file_name"],
            "size_bytes": int(row["size_bytes"]),
            "readable_size": row["readable_size"],
            "mtime_utc": row["mtime_utc"],
            "is_directory": False,
            "scan_timestamp_utc": row["scan_timestamp_utc"],
        }
        # ``file_id`` stays the public token because analyst decisions are keyed
        # by it; ``file_key`` is the catalog integer used as the storage key in
        # every derived database, where it is 3-4 bytes instead of 22.
        metadata = {
            **base,
            "share": row["share"],
            "file_id": row["public_id"],
            "file_key": int(row["row_id"]),
        }
        payload = json.dumps(base, ensure_ascii=False, separators=(",", ":"))
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
    on_total: Optional[Callable[[int], None]] = None,
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
        if on_total:
            # Counted inside the same read snapshot the stream uses, so the
            # denominator a caller shows is the number this run will score.
            on_total(
                source.execute(
                    "SELECT COUNT(*) FROM scan_files WHERE scan_id=?", (scan["id"],)
                ).fetchone()[0]
            )
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
            if version not in (0, 1, 2, 3, 4, SCHEMA_VERSION):
                raise ValueError(f"unsupported triage database version: {version}")
            if 0 < version < SCHEMA_VERSION:
                _migrate_results(target, database)
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
                engine = Engine(rules, sibling_index.lookup)
                inventory_signals = InventorySignals(
                    target,
                    database,
                    rules.document.get("rarity", []),
                    engine,
                )
                indexing_needed = bool(
                    sibling_index.contexts or inventory_signals.rarity
                )
                if indexing_needed and on_phase:
                    on_phase("indexing sibling names", 0)

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
                            metadata["file_key"],
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
                            (metadata["file_key"], category, score_value)
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

                def score_stream(
                    iterator: Iterator[Tuple[Dict[str, Any], str]],
                ) -> None:
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
                # Materializing the ranked tables is a long, count-free tail on
                # a large inventory; name it so callers do not read a finished
                # meter as a hung run.
                if on_phase:
                    on_phase("saving", count)
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
                timings["scoring_and_saving_seconds"] = perf_counter() - scoring_started
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
    file_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    if not 1 <= limit <= 10000 or min_score < 0:
        raise ValueError("limit must be 1..10000 and minimum score must be nonnegative")
    if file_ids is not None and (
        type(file_ids) is not list or not all(type(i) is str for i in file_ids)
    ):
        raise ValueError("file_ids must be a list of candidate IDs")
    _ensure_result_schema(output or result_path(database), database)
    with closing(connect_readonly(output or result_path(database))) as connection:
        run = select_run(connection, database, run_id)
        connection.execute("ATTACH DATABASE ? AS inventory", (str(database.resolve()),))
        score = "c.score" if category else "f.priority"
        identifier = "c.file_id" if category else "f.file_id"
        query = (
            (
                "SELECT f.*, COALESCE(NULLIF(f.metadata_json,''),"
                + _metadata_json_expr("i")
                + ") AS resolved_metadata_json, c.score AS review_score FROM triage_categories c "
                "JOIN triage_files f ON f.run_id=c.run_id AND f.file_id=c.file_id "
                "LEFT JOIN inventory.files i ON i.id=f.file_id "
                "LEFT JOIN inventory.scan_files sf ON sf.scan_id=? AND sf.file_id=i.id "
                "WHERE c.run_id=? AND c.category=? AND c.score>=?"
            )
            if category
            else (
                "SELECT f.*, COALESCE(NULLIF(f.metadata_json,''),"
                + _metadata_json_expr("i")
                + ") AS resolved_metadata_json, f.priority AS review_score FROM triage_files f "
                "LEFT JOIN inventory.files i ON i.id=f.file_id "
                "LEFT JOIN inventory.scan_files sf ON sf.scan_id=? AND sf.file_id=i.id "
                "WHERE f.run_id=? AND f.priority>=?"
            )
        )
        values: List[Any] = (
            [run["scan_id"], run["id"], category, min_score]
            if category
            else [run["scan_id"], run["id"], min_score]
        )
        if category in FALLBACK_CATEGORIES:
            # Category membership is supplied by a zero-point rule.
            # Keep this pool disjoint from recommendations and analyst decisions.
            query += (
                " AND f.priority=0 AND json_extract(f.result_json, '$.review') IS NULL"
            )
        if file_ids is not None:
            # A named selection is a membership question, not a page of a
            # ranking: the caller passes public IDs, so match them through the
            # attached inventory. `identifier` would be the integer key.
            selected = sorted(set(file_ids))
            query += (
                f" AND i.public_id IN ({','.join('?' for _ in selected)})"
                if selected
                else " AND 0"
            )
            values.extend(selected)
        if after is not None:
            if type(after[0]) is not int or after[0] < 0:
                raise ValueError("invalid ranking cursor")
            query += f" AND ({score} < ? OR ({score} = ? AND {identifier} > ?))"
            values.extend((after[0], after[0], after[1]))
        page = max(limit, len(set(file_ids))) if file_ids else limit
        query += f" ORDER BY {score} DESC, {identifier} LIMIT ?"
        rows = list(connection.execute(query, (*values, page + 1)))
        items = [
            {
                **json.loads(row["resolved_metadata_json"]),
                **json.loads(row["result_json"]),
                "review_score": row["review_score"],
            }
            for row in rows[:page]
        ]
        cursor_keys = [int(row["file_id"]) for row in rows[:page]]
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
            "next_cursor": [items[-1]["review_score"], cursor_keys[-1]]
            if len(rows) > page
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
    database: Path,
    file_id: str,
    run_id: Optional[str] = None,
    output: Optional[Path] = None,
) -> Dict[str, Any]:
    from .rules import validate

    _ensure_result_schema(output or result_path(database), database)
    with closing(connect_readonly(output or result_path(database))) as connection:
        run = select_run(connection, database, run_id)
        connection.execute("ATTACH DATABASE ? AS inventory", (str(database.resolve()),))
        row = connection.execute(
            "SELECT f.*,COALESCE(NULLIF(f.metadata_json,''),"
            + _metadata_json_expr("i")
            + ") AS resolved_metadata_json "
            "FROM triage_files f LEFT JOIN inventory.files i ON i.id=f.file_id "
            "LEFT JOIN inventory.scan_files sf ON sf.scan_id=? AND sf.file_id=i.id "
            "WHERE f.run_id=? AND i.public_id=?",
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


RUN_COLUMNS = (
    "id,source_path,scan_id,started_at,finished_at,status,engine_version,"
    "rules_hash,rules_json,scan_json,inventory_hash,file_count,error"
)


def _readonly_uri(path: Path) -> str:
    return path.resolve().as_uri() + "?mode=ro"


def promote_run(
    preview_db: Path,
    results_db: Path,
    run_id: str,
    on_phase: Optional[Callable[[str, int], None]] = None,
    cancelled: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    """Copy one completed run from a preview database into the saved results.

    The preview has the results schema, so saving is a row copy rather than a
    re-score: the saved priorities are the previewed ones by construction.
    Metadata is stored empty, exactly like a direct save, and resolves from
    the inventory snapshot on read. Everything lands in one transaction.
    """
    if preview_db.resolve() == results_db.resolve():
        raise ValueError("preview and results databases must differ")
    with closing(connect_readonly(preview_db)) as source:
        run = source.execute(
            "SELECT * FROM triage_runs WHERE id=? AND status='completed'", (run_id,)
        ).fetchone()
        if run is None:
            raise ValueError("preview run is missing or incomplete")
        files = run["file_count"]
    with closing(sqlite3.connect(results_db, isolation_level=None)) as target:
        target.execute("PRAGMA foreign_keys=ON")
        target.execute("PRAGMA journal_mode=WAL")
        target.execute("PRAGMA synchronous=NORMAL")
        target.execute("PRAGMA busy_timeout=5000")
        target.execute(
            f"PRAGMA cache_size=-{_cache_kib('SHRAWLER_TRIAGE_CACHE_MB', 128)}"
        )
        version = target.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1, 2, 3, 4, SCHEMA_VERSION):
            raise ValueError(f"unsupported triage database version: {version}")
        if 0 < version < SCHEMA_VERSION:
            # The preview run records the inventory it was scored from.
            _migrate_results(target, Path(str(run["source_path"])))
        target.executescript(SCHEMA)
        for _, statement in WEB_SORT_INDEXES:
            target.execute(statement)
        target.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        target.execute("ATTACH DATABASE ? AS preview", (str(preview_db.resolve()),))
        try:
            target.execute("BEGIN IMMEDIATE")
            if target.execute(
                "SELECT 1 FROM triage_runs WHERE id=?", (run_id,)
            ).fetchone():
                raise ValueError("this preview has already been saved")
            target.execute(
                f"INSERT INTO triage_runs({RUN_COLUMNS}) "
                f"SELECT {RUN_COLUMNS} FROM preview.triage_runs WHERE id=?",
                (run_id,),
            )
            if on_phase:
                on_phase("saving preview", 0)
            # Copy in file_id ranges so a long save reports progress and can be
            # cancelled; ranges keep inserts in key order like a direct save.
            copied = 0
            lower: Any = -1
            while True:
                if cancelled and cancelled():
                    raise KeyboardInterrupt
                found = target.execute(
                    "SELECT file_id FROM preview.triage_files WHERE run_id=? AND file_id>? "
                    "ORDER BY file_id LIMIT 1 OFFSET ?",
                    (run_id, lower, BATCH_SIZE - 1),
                ).fetchone()
                upper = found[0] if found else None
                bound = "" if upper is None else " AND file_id<=?"
                values: Tuple[Any, ...] = (
                    (run_id, lower) if upper is None else (run_id, lower, upper)
                )
                copied += target.execute(
                    "INSERT INTO triage_files(run_id,file_id,priority,metadata_json,result_json) "
                    "SELECT run_id,file_id,priority,'',result_json FROM preview.triage_files "
                    f"WHERE run_id=? AND file_id>?{bound} ORDER BY file_id",
                    values,
                ).rowcount
                target.execute(
                    "INSERT INTO triage_categories(run_id,file_id,category,score) "
                    "SELECT run_id,file_id,category,score FROM preview.triage_categories "
                    f"WHERE run_id=? AND file_id>?{bound} ORDER BY file_id",
                    values,
                )
                if on_phase:
                    on_phase("saving preview", copied)
                if upper is None:
                    break
                lower = upper
            if copied != files:
                raise ValueError("preview run is incomplete")
            target.execute(
                "INSERT INTO triage_summaries(run_id,summary_json) "
                "SELECT run_id,summary_json FROM preview.triage_summaries WHERE run_id=?",
                (run_id,),
            )
            target.execute("COMMIT")
        except BaseException:
            if target.in_transaction:
                target.execute("ROLLBACK")
            raise
        finally:
            target.execute("DETACH DATABASE preview")
    return {
        "run_id": run_id,
        "scan_id": run["scan_id"],
        "files_scored": files,
        "rules_hash": run["rules_hash"],
        "inventory_hash": run["inventory_hash"],
        "results_database": str(results_db),
    }


COMPARE_ORDERS = ("delta", "preview")

# Every file in either run, keyed by file_id. Base-only rows appear when the
# runs scored different scans; a missing side has a NULL priority and counts
# as zero in the delta.
_COMPARE_PAIRS = """
WITH pairs AS (
 SELECT p.file_id, p.priority AS preview_priority, b.priority AS base_priority,
  p.metadata_json, p.result_json, :preview_scan AS scan_id
 FROM triage_files p
 LEFT JOIN base.triage_files b ON b.run_id=:base AND b.file_id=p.file_id
 WHERE p.run_id=:preview
 UNION ALL
 SELECT b.file_id, NULL, b.priority, b.metadata_json, b.result_json, :base_scan
 FROM base.triage_files b
 WHERE b.run_id=:base AND NOT EXISTS (
  SELECT 1 FROM triage_files p WHERE p.run_id=:preview AND p.file_id=b.file_id)
), scored AS (
 SELECT *, COALESCE(preview_priority,0)-COALESCE(base_priority,0) AS delta FROM pairs
)
"""


def _run_summary(connection: sqlite3.Connection, schema: str, run_id: str) -> Dict[str, Any]:
    found = connection.execute(
        f"SELECT summary_json FROM {schema}.triage_summaries WHERE run_id=?", (run_id,)
    ).fetchone()
    return json.loads(found[0]) if found else {}


def compare_runs(
    database: Path,
    preview_db: Path,
    preview_run: str,
    base_run: Optional[str] = None,
    order: str = "delta",
    limit: int = 100,
    after: Optional[Tuple[int, str]] = None,
    changed_only: bool = True,
    summary: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Read-only per-file comparison of a preview run against a saved run.

    `order=delta` pages by absolute change, `order=preview` by preview
    priority; both break ties by file_id. Pass a previously returned
    `summary` to skip the full-run aggregate when paging.
    """
    if order not in COMPARE_ORDERS:
        raise ValueError("order must be delta or preview")
    if not 1 <= limit <= 10000:
        raise ValueError("limit must be 1..10000")
    if after is not None and (
        type(after[0]) is not int or (order == "delta" and after[0] < 0)
    ):
        raise ValueError("invalid comparison cursor")
    results = result_path(database)
    if not results.exists():
        raise ValueError("no saved ranking run to compare against")
    _ensure_result_schema(results, database)
    with closing(connect_readonly(results)) as saved:
        base = dict(select_run(saved, database, base_run))
    with closing(connect_readonly(preview_db)) as connection:
        preview = connection.execute(
            "SELECT * FROM triage_runs WHERE id=? AND status='completed'",
            (preview_run,),
        ).fetchone()
        if preview is None:
            raise ValueError("preview run is missing or incomplete")
        connection.execute("ATTACH DATABASE ? AS base", (_readonly_uri(results),))
        connection.execute("ATTACH DATABASE ? AS inventory", (str(database.resolve()),))
        names = {
            "preview": preview["id"],
            "base": base["id"],
            "preview_scan": preview["scan_id"],
            "base_scan": base["scan_id"],
        }
        if summary is None:
            row = connection.execute(
                _COMPARE_PAIRS
                + "SELECT COALESCE(SUM(delta<>0),0), COALESCE(SUM(delta>0),0), "
                "COALESCE(SUM(delta<0),0), "
                "COALESCE(SUM(COALESCE(preview_priority,0)>0 AND COALESCE(base_priority,0)<=0),0), "
                "COALESCE(SUM(COALESCE(base_priority,0)>0 AND COALESCE(preview_priority,0)<=0),0), "
                "COALESCE(SUM(base_priority IS NULL),0), COALESCE(SUM(preview_priority IS NULL),0) "
                "FROM scored",
                names,
            ).fetchone()
            base_matches = _run_summary(connection, "base", base["id"]).get(
                "rule_matches", {}
            )
            preview_matches = _run_summary(connection, "main", preview["id"]).get(
                "rule_matches", {}
            )
            summary = {
                "changed": row[0],
                "raised": row[1],
                "lowered": row[2],
                "newly_positive": row[3],
                "no_longer_positive": row[4],
                "only_in_preview": row[5],
                "only_in_base": row[6],
                "rule_matches": {
                    rule: [base_matches.get(rule, 0), preview_matches.get(rule, 0)]
                    for rule in sorted(set(base_matches) | set(preview_matches))
                },
                "same_scan": base["scan_id"] == preview["scan_id"],
            }
        key = "ABS(delta)" if order == "delta" else "COALESCE(preview_priority,0)"
        query = (
            _COMPARE_PAIRS
            + f"SELECT scored.*, {key} AS sort_key, "
            + "COALESCE(NULLIF(scored.metadata_json,''),"
            + _metadata_json_expr("i")
            + ") AS resolved_metadata_json "
            "FROM scored LEFT JOIN inventory.files i ON i.id=scored.file_id "
            "LEFT JOIN inventory.scan_files sf ON sf.scan_id=scored.scan_id AND sf.file_id=i.id "
            "WHERE 1"
        )
        values: Dict[str, Any] = dict(names)
        if changed_only:
            query += " AND delta<>0"
        if after is not None:
            query += (
                f" AND ({key} < :after_score OR ({key} = :after_score "
                "AND scored.file_id > :after_id))"
            )
            values.update(after_score=after[0], after_id=after[1])
        query += f" ORDER BY {key} DESC, scored.file_id LIMIT :page"
        values["page"] = limit + 1
        rows = list(connection.execute(query, values))
        items: List[Dict[str, Any]] = []
        for row in rows[:limit]:
            metadata = (
                json.loads(row["resolved_metadata_json"])
                if row["resolved_metadata_json"]
                else {"file_id": row["file_id"]}
            )
            items.append(
                {
                    **metadata,
                    **json.loads(row["result_json"]),
                    "priority": row["preview_priority"],
                    "base_priority": row["base_priority"],
                    "preview_priority": row["preview_priority"],
                    "delta": row["delta"],
                }
            )
        return {
            "preview_run_id": preview["id"],
            "base_run_id": base["id"],
            "summary": summary,
            "items": items,
            "next_cursor": [rows[limit - 1]["sort_key"], rows[limit - 1]["file_id"]]
            if len(rows) > limit
            else None,
        }
