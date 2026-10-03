"""Read-only analyst views over persisted assessment results.

Views are append-only evidence: they report exactly what was stored, mark
pending/failed areas, and never re-rank. Ordering is by the model's numeric
inspection priority (0-4), applied in SQL before paging so a page is never a
locally sorted slice. Rule results stay in their own immutable view.
"""

import json
from typing import Any, Dict, List, Optional

from .config import (
    PRIORITY_INSPECT_MIN,
    PRIORITY_LEVELS,
    PRIORITY_NAMES,
    priority_score,
)
from .storage import JevStore

# Highest priority first; ties fall back to stable directory/file order.
_PRIORITY_ORDER = "CAST(r.choice AS INTEGER) DESC, f.directory_id, f.file_id"


def _summary(row: Any) -> Dict[str, Any]:
    choice = str(row["choice"])
    score = priority_score(choice)
    return {
        "file_id": row["file_id"],
        "file_name": row["file_name"],
        "unc_path": row["unc_path"],
        "extension": row["extension"],
        "size_bytes": row["size_bytes"],
        "mtime_utc": row["mtime_utc"],
        "choice": choice,
        "priority": score,
        "priority_name": PRIORITY_NAMES.get(choice, ""),
        "distribution": json.loads(row["distribution_json"])
        if row["distribution_json"]
        else None,
        "deployment_revision": row["deployment_revision"],
        "model": row["model"],
    }


def list_assessed(
    store: JevStore,
    run_id: str,
    label: Optional[str] = None,
    directory_id: Optional[int] = None,
    limit: int = 100,
    offset: int = 0,
) -> Dict[str, Any]:
    if label is not None and label not in PRIORITY_LEVELS:
        raise ValueError(f"label must be one of {PRIORITY_LEVELS}")
    if not 1 <= limit <= 10000 or offset < 0:
        raise ValueError("limit must be 1..10000 and offset nonnegative")
    run = store.select_run(run_id)
    clause = ""
    values: List[Any] = [run_id]
    if label is not None:
        clause += " AND r.choice=?"
        values.append(label)
    if directory_id is not None:
        clause += " AND f.directory_id=?"
        values.append(directory_id)
    rows = list(
        store.connection.execute(
            "SELECT r.choice, r.distribution_json, r.deployment_revision, r.model, "
            "f.file_id, f.file_name, f.unc_path, f.extension, f.size_bytes, f.mtime_utc "
            "FROM assessment_files f JOIN decision_results r ON r.id=f.result_id "
            "WHERE f.run_id=? AND f.status='assessed'" + clause + " "
            "ORDER BY " + _PRIORITY_ORDER + " LIMIT ? OFFSET ?",
            (*values, limit, offset),
        )
    )
    return {
        "run_id": run_id,
        "scan_id": run["scan_id"],
        "objective": run["objective"],
        "items": [_summary(row) for row in rows],
        "provisional": True,
        "note": "Model priority is metadata-based review value, not confirmed content.",
    }


def highlight_missed(
    store: JevStore, run_id: str, limit: int = 100, offset: int = 0
) -> Dict[str, Any]:
    """Model priority at/above the rule-expansion threshold among files the
    deterministic rules left at 0."""
    if not 1 <= limit <= 10000 or offset < 0:
        raise ValueError("limit must be 1..10000 and offset nonnegative")
    rows = list(
        store.connection.execute(
            "SELECT r.choice, r.distribution_json, r.deployment_revision, r.model, "
            "f.file_id, f.file_name, f.unc_path, f.extension, f.size_bytes, f.mtime_utc "
            "FROM assessment_files f JOIN decision_results r ON r.id=f.result_id "
            "WHERE f.run_id=? AND f.status='assessed' AND f.priority=0 "
            "AND CAST(r.choice AS INTEGER) >= ? "
            "ORDER BY " + _PRIORITY_ORDER + " LIMIT ? OFFSET ?",
            (run_id, PRIORITY_INSPECT_MIN, limit, offset),
        )
    )
    return {"run_id": run_id, "items": [_summary(row) for row in rows]}


def coverage_by_directory(store: JevStore, run_id: str) -> List[Dict[str, Any]]:
    grouped: Dict[int, Dict[str, Any]] = {}
    for row in store.directory_counts(run_id):
        entry = grouped.setdefault(
            int(row["directory_id"]),
            {"directory_id": int(row["directory_id"]), "counts": {}},
        )
        entry["counts"][str(row["status"])] = int(row["n"])
    for entry in grouped.values():
        context = store.context_for(run_id, entry["directory_id"])
        if context is not None:
            entry["host"] = context["host"]
            entry["share"] = context["share"]
            entry["directory"] = context["parent"]
            entry["enumeration"] = context["enumeration"]
        counts = entry["counts"]
        entry["total"] = sum(counts.values())
    return sorted(grouped.values(), key=lambda item: item["directory_id"])
