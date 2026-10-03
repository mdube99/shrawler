"""Read-only analyst views over persisted assessment results.

Views are append-only evidence: they report exactly what was stored, mark
pending/failed areas, and never re-rank. Presentation ordering uses the model
label only; rule results stay in their own immutable view.
"""

import json
from typing import Any, Dict, List, Optional

from .config import HIGH_LABEL, REVIEW_LABELS
from .storage import JevStore

LABEL_RANK = {label: index for index, label in enumerate(REVIEW_LABELS)}


def _summary(row: Any) -> Dict[str, Any]:
    return {
        "file_id": row["file_id"],
        "file_name": row["file_name"],
        "unc_path": row["unc_path"],
        "extension": row["extension"],
        "size_bytes": row["size_bytes"],
        "mtime_utc": row["mtime_utc"],
        "choice": row["choice"],
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
    if label is not None and label not in REVIEW_LABELS:
        raise ValueError(f"label must be one of {REVIEW_LABELS}")
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
            "ORDER BY f.directory_id, f.file_id LIMIT ? OFFSET ?",
            (*values, limit, offset),
        )
    )
    items = [_summary(row) for row in rows]
    # Sort by review value for presentation; the joined result IDs are stable.
    items.sort(key=lambda item: LABEL_RANK.get(item["choice"], len(REVIEW_LABELS)))
    return {
        "run_id": run_id,
        "scan_id": run["scan_id"],
        "objective": run["objective"],
        "items": items,
        "provisional": True,
        "note": "Model label is metadata-based review value, not confirmed content.",
    }


def highlight_missed(
    store: JevStore, run_id: str, limit: int = 100
) -> Dict[str, Any]:
    """High/moderate model value among files the deterministic rules left at 0."""
    rows = list(
        store.connection.execute(
            "SELECT r.choice, r.distribution_json, r.deployment_revision, r.model, "
            "f.file_id, f.file_name, f.unc_path, f.extension, f.size_bytes, f.mtime_utc "
            "FROM assessment_files f JOIN decision_results r ON r.id=f.result_id "
            "WHERE f.run_id=? AND f.status='assessed' AND f.priority=0 "
            "AND r.choice IN (?, 'moderate') "
            "ORDER BY r.choice, f.directory_id, f.file_id LIMIT ?",
            (run_id, HIGH_LABEL, limit),
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
