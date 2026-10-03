"""Pin a scan, stage its complete ledger, and build durable directory context.

Context preparation streams the pinned scan exactly once, grouping counts with
disk-backed tables. Directories are keyed by (host, share, parent) and assigned
small integer directory IDs so the ledger stays compact.
"""

import hashlib
from contextlib import closing
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..engine import segments
from ..rules import RuleSet
from ..storage import connect_readonly, observables, select_scan
from .config import (
    CONTEXT_VERSION,
    canonical,
    fingerprint,
)
from .storage import JevStore, utc_now

# Bounded in-memory buffering while staging; nothing scales with directory size.
FLUSH_ROWS = 5000
# Directory aggregate rows mirrored per run into a disk-backed table.
CONTEXT_MARKER_EXAMPLES = 12


def _extension(name: str) -> str:
    if "." not in name:
        return ""
    value = name.rsplit(".", 1)[1]
    return ("." + value).casefold() if value else ""


def _directory_key(metadata: Dict[str, Any]) -> Tuple[str, str, str]:
    path = segments(str(metadata["remote_path"]))
    parent = "/" + "/".join(path[:-1])
    return (
        str(metadata["host"]).casefold(),
        str(metadata["share"]).casefold(),
        parent.casefold(),
    )


def _directory_display(metadata: Dict[str, Any]) -> Tuple[str, str, str]:
    """Case-preserving identity for display; grouping still uses the folded key."""
    path = segments(str(metadata["remote_path"]))
    parent = "/" + "/".join(path[:-1])
    return str(metadata["host"]), str(metadata["share"]), parent


def _ancestors(parent: str) -> List[str]:
    parts = [part for part in parent.split("/") if part]
    return [parts[index] for index in range(len(parts))]


def source_fingerprint(scan: Dict[str, Any]) -> str:
    """Ordered identity of the pinned source, independent of the ledger rows."""
    return fingerprint(
        {
            "scan_id": scan["id"],
            "mode": scan.get("mode"),
            "status": scan.get("status"),
            "started_at_utc": scan.get("started_at_utc"),
        }
    )


def _enumeration(scan_status: str) -> str:
    if scan_status == "completed":
        return "observed listing complete"
    if scan_status == "partial":
        return "observed listing partial; unmapped areas possible"
    return f"observed listing {scan_status}; completeness unknown"


class PreparationResult(Dict[str, Any]):
    """Typed dict so callers can JSON-serialize the whole result."""


def stage(
    database: Path,
    store: JevStore,
    run_id: str,
    rules: Optional[RuleSet] = None,
    scan_id: Optional[str] = None,
    progress: Optional[Callable[[str, int], None]] = None,
    cancelled: Optional[Callable[[], bool]] = None,
) -> PreparationResult:
    """Stream the pinned scan once into contexts and the file ledger.

    Rules, when supplied, are used only to reuse the deterministic sibling
    marker vocabulary and compute a presentation relative priority. They never
    remove files from the ledger.
    """
    from ..engine import Engine

    if cancelled and cancelled():
        raise KeyboardInterrupt
    with closing(connect_readonly(database)) as source:
        source.execute("BEGIN")
        scan = dict(select_scan(source, scan_id))

        counters: Dict[str, int] = {"observed": 0}
        directory_keys: Dict[int, Tuple[str, str, str]] = {}
        directory_ids: Dict[Tuple[str, str, str], int] = {}
        directory_display: Dict[int, Tuple[str, str, str]] = {}
        # Disk-backed extension counts and bounded marker witnesses.
        store.connection.executescript(
            """
            CREATE TEMP TABLE IF NOT EXISTS jev_ext (
                directory_id INTEGER, extension TEXT, n INTEGER,
                PRIMARY KEY(directory_id, extension));
            DELETE FROM jev_ext;
            CREATE TEMP TABLE IF NOT EXISTS jev_markers (
                directory_id INTEGER, file_name TEXT, file_id TEXT,
                PRIMARY KEY(directory_id, file_name, file_id));
            DELETE FROM jev_markers;
            """
        )
        # Reuse the rule engine's precedence for presentation ordering only; the
        # durable marker index is built from all observed filenames.
        engine = Engine(rules) if rules is not None else None

        file_rows: List[Tuple[Any, ...]] = []
        ext_rows: List[Tuple[int, str, int]] = []
        pending_ext: Dict[Tuple[int, str], int] = {}
        last_flush = 0

        def flush() -> None:
            nonlocal last_flush
            if ext_rows:
                store.connection.executemany(
                    "INSERT INTO jev_ext VALUES (?,?,?) "
                    "ON CONFLICT(directory_id,extension) DO UPDATE SET n=n+excluded.n",
                    ext_rows,
                )
                ext_rows.clear()
            if file_rows:
                store.insert_files(file_rows)
                file_rows.clear()
            store.commit()
            last_flush = counters["observed"]

        def directory_id(key: Tuple[str, str, str]) -> int:
            found = directory_ids.get(key)
            if found is None:
                found = len(directory_ids) + 1
                directory_ids[key] = found
                directory_keys[found] = key
            return found

        def directory_index(metadata: Dict[str, Any]) -> int:
            key = _directory_key(metadata)
            found = directory_id(key)
            directory_display.setdefault(found, _directory_display(metadata))
            return found

        for metadata, _raw in observables(source, scan["id"]):
            if cancelled and cancelled():
                raise KeyboardInterrupt
            counters["observed"] += 1
            directory_value = directory_index(metadata)
            name = str(metadata["file_name"])
            extension = _extension(name)
            pending_ext[(directory_value, extension)] = (
                pending_ext.get((directory_value, extension), 0) + 1
            )
            if len(pending_ext) >= FLUSH_ROWS:
                ext_rows.extend(
                    (value, ext, n)
                    for (value, ext), n in pending_ext.items()
                )
                pending_ext.clear()
            # Exact sibling-marker evidence is preserved for every directory,
            # independent of which rules are active.
            store.connection.execute(
                "INSERT OR IGNORE INTO jev_markers VALUES (?,?,?)",
                (directory_value, name.casefold(), str(metadata["file_id"])),
            )
            feature_json = canonical(metadata)
            file_rows.append(
                (
                    run_id,
                    str(metadata["file_id"]),
                    directory_value,
                    name,
                    str(metadata["remote_path"]),
                    str(metadata["unc_path"]),
                    int(metadata["size_bytes"]),
                    metadata.get("mtime_utc"),
                    extension,
                    feature_json,
                    hashlib.sha256(feature_json.encode()).hexdigest(),
                    0,
                    "pending",
                    utc_now(),
                )
            )
            if len(file_rows) >= FLUSH_ROWS:
                if pending_ext:
                    ext_rows.extend(
                        (directory_value, ext, n)
                        for (directory_value, ext), n in pending_ext.items()
                    )
                    pending_ext.clear()
                flush()
            if progress and counters["observed"] % 50000 == 0:
                progress("staging ledger", counters["observed"])

        if pending_ext:
            ext_rows.extend(
                (directory_value, ext, n)
                for (directory_value, ext), n in pending_ext.items()
            )
            pending_ext.clear()
        flush()

        # Relative priority for presentation only; never used to drop files.
        if rules is not None and engine is not None:
            _apply_priority(store, run_id, engine, progress, cancelled)

        contexts = _build_contexts(
            store,
            run_id,
            scan,
            directory_keys,
            directory_display,
            progress,
        )
        store.update_run(
            run_id,
            total_observed=counters["observed"],
            ledger_complete=1,
            file_count=counters["observed"],
            context_count=contexts,
        )
        return PreparationResult(
            run_id=run_id,
            scan_id=scan["id"],
            scan_status=scan["status"],
            observed_files=counters["observed"],
            directories=contexts,
        )


def _distinctive_markers(
    buckets: Dict[str, List[str]], extensions: List[Tuple[str, int]]
) -> List[str]:
    """Bounded marker examples that favor unusual names over repetitive ones.

    Extension ranking is deterministic: rarer extensions and rarer basenames
    sort first, so a lone readme.txt survives beside 100k exports.csv rows.
    """
    names = [name for bucket in buckets.values() for name in bucket]
    if not names:
        return []
    counts: Dict[str, int] = {}
    for name in names:
        counts[name] = counts.get(name, 0) + 1
    extension_counts = dict(extensions)
    ordered = sorted(
        set(names),
        key=lambda name: (
            extension_counts.get(_extension(name), 0),
            counts[name],
            name,
        ),
    )
    return ordered[:CONTEXT_MARKER_EXAMPLES]


def _apply_priority(
    store: JevStore,
    run_id: str,
    engine: Any,
    progress: Optional[Callable[[str, int], None]],
    cancelled: Optional[Callable[[], bool]],
) -> None:
    """Deterministic rule score kept only as a presentation ordering hint."""
    rows = store.connection.execute(
        "SELECT file_id, feature_json FROM assessment_files WHERE run_id=? "
        "ORDER BY directory_id, file_id",
        (run_id,),
    )
    count = 0
    batch: List[Tuple[int, str, str]] = []
    for row in rows:
        if cancelled and cancelled():
            raise KeyboardInterrupt
        import json

        metadata = json.loads(row["feature_json"])
        evaluated = engine.evaluate(metadata)
        result = (evaluated["priority"], run_id, row["file_id"])
        batch.append((result[0], run_id, row["file_id"]))
        count += 1
        if len(batch) >= FLUSH_ROWS:
            store.connection.executemany(
                "UPDATE assessment_files SET priority=? WHERE run_id=? AND file_id=?",
                batch,
            )
            batch.clear()
            if progress:
                progress("scoring presentation priority", count)
    if batch:
        store.connection.executemany(
            "UPDATE assessment_files SET priority=? WHERE run_id=? AND file_id=?",
            batch,
        )
    store.commit()


def _build_contexts(
    store: JevStore,
    run_id: str,
    scan: Dict[str, Any],
    directory_keys: Dict[int, Tuple[str, str, str]],
    directory_display: Dict[int, Tuple[str, str, str]],
    progress: Optional[Callable[[str, int], None]],
) -> int:
    """Assemble one bounded, canonical context row per observed directory."""
    # directory_ids is in-memory but bounded by directory count, not file count.
    # For each directory, read back its extension counts from the temp table.
    extension_cache: Dict[int, List[Tuple[str, int]]] = {}
    for directory_value, extension, n in store.connection.execute(
        "SELECT directory_id, extension, n FROM jev_ext ORDER BY directory_id, n DESC, extension"
    ):
        extension_cache.setdefault(directory_value, []).append((extension, n))
    # Bounded witness collection: keep a generous per-directory pool so
    # distinctive names can be ranked, but never scale with directory size.
    # Markers are bucketed by extension so a minority extension is not evicted
    # by a flood of repetitive siblings.
    marker_cache: Dict[int, Dict[str, List[str]]] = {}
    per_extension = max(CONTEXT_MARKER_EXAMPLES, 32)
    for directory_value, name, extension in store.connection.execute(
        "SELECT directory_id, file_name,"
        " CASE WHEN instr(file_name,'.')>0 THEN substr(file_name,instr(file_name,'.'))"
        " ELSE '' END AS extension"
        " FROM jev_markers ORDER BY directory_id, file_id"
    ):
        buckets = marker_cache.setdefault(directory_value, {})
        bucket = buckets.setdefault(str(extension), [])
        if len(bucket) < per_extension:
            bucket.append(name)

    rows: List[Tuple[Any, ...]] = []
    enumeration = _enumeration(str(scan["status"]))
    for directory_value, key in directory_keys.items():
        host, share, parent = directory_display.get(directory_value, key)
        extensions = extension_cache.get(directory_value, [])
        observed = sum(n for _, n in extensions)
        annotated = [
            {"extension": extension or "(none)", "count": n}
            for extension, n in extensions
        ]
        markers = _distinctive_markers(
            marker_cache.get(directory_value, {}), extensions
        )
        ancestors = _ancestors(parent)
        context: Dict[str, Any] = {
            "context_version": CONTEXT_VERSION,
            "host": host,
            "share": share,
            "directory": parent or "/",
            "ancestors": ancestors[-8:],
            "observed_files": observed,
            "extensions": annotated,
            "sibling_markers": markers,
            "enumeration": enumeration,
            "complete": scan["status"] == "completed",
        }
        context_hash = fingerprint(context)
        rows.append(
            (
                run_id,
                directory_value,
                host,
                share,
                parent,
                canonical(context),
                context_hash,
                observed,
                len(canonical(context)),
                int(len(markers) >= CONTEXT_MARKER_EXAMPLES),
                canonical(
                    {
                        "extension_kinds_omitted": max(0, len(extensions) - 24),
                        "marker_examples_omitted": int(
                            len(markers) >= CONTEXT_MARKER_EXAMPLES
                        ),
                    }
                ),
                enumeration,
            )
        )
        if progress and len(rows) % 2000 == 0:
            progress("building directory context", len(rows))
    store.insert_contexts(run_id, rows)
    return len(rows)
