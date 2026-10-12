"""One cancellable local ranking job shared by the WebUI and CLI engine."""

import copy
import shutil
import sqlite3
import threading
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .rules import RuleSet, load_text
from .storage import (
    compare_runs,
    connect_readonly,
    list_results,
    promote_run,
    rank,
    result_path,
)

TERMINAL_STATUSES = {"completed", "failed", "cancelled"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class TriageBusyError(ValueError):
    pass


class PreviewGoneError(ValueError):
    """The requested preview was discarded, saved, or replaced."""


class TriageService:
    def __init__(self, database: Path, runtime: Path) -> None:
        self.database = database
        self.runtime = runtime
        # Previews live only for this service: anything left by an earlier
        # process belongs to a job that no longer exists.
        self.previews = runtime / "triage-previews"
        shutil.rmtree(self.previews, ignore_errors=True)
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._job: Optional[Dict[str, Any]] = None
        # The latest successful preview; replaced only when a newer one
        # completes so the old results stay readable while re-previewing.
        self._preview: Optional[Dict[str, Any]] = None
        self._compare_summaries: Dict[Tuple[str, str], Dict[str, Any]] = {}

    def status(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._job)

    def start(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if set(payload) - {"rules_toml", "builtins", "scan_id", "preview"}:
            raise ValueError("unknown ranking job field")
        text = payload.get("rules_toml", "version = 1\n")
        builtin = payload.get("builtins", True)
        preview = payload.get("preview", True)
        scan = payload.get("scan_id")
        if scan == "":
            scan = None
        if not isinstance(text, str) or len(text.encode()) > 65536:
            raise ValueError("rules_toml must be text up to 64 KiB")
        if type(builtin) is not bool or type(preview) is not bool:
            raise ValueError("builtins and preview must be booleans")
        if scan is not None and (not isinstance(scan, str) or len(scan) > 100):
            raise ValueError("invalid scan ID")
        rules = load_text(text, builtin)
        with self._lock:
            if self._thread and self._thread.is_alive():
                raise TriageBusyError("a ranking job is already running")
            self._cancel.clear()
            started = _now()
            identifier = uuid.uuid4().hex
            self._job = {
                "id": identifier,
                "status": "running",
                "phase": "starting",
                "processed": 0,
                "preview": preview,
                "preview_id": identifier if preview else None,
                "run_id": None,
                "rules_toml": text,
                "builtins": builtin,
                "scan_id": scan,
                "summary": None,
                "rules_hash": rules.digest,
                "started_at": started,
                "updated_at": started,
                "finished_at": None,
            }
            self._thread = threading.Thread(
                target=self._work,
                args=(identifier, rules, scan, preview, text, builtin, started),
                daemon=True,
            )
            self._thread.start()
            return copy.deepcopy(self._job)

    def _update(self, **values: Any) -> None:
        with self._lock:
            if self._job is not None:
                self._job.update(values)
                # A reader can detect a stalled job by comparing updated_at
                # against the wall clock; finished_at is the stable end marker.
                self._job["updated_at"] = _now()
                if (
                    self._job.get("status") in TERMINAL_STATUSES
                    and not self._job.get("finished_at")
                ):
                    self._job["finished_at"] = self._job["updated_at"]

    def _review_mark(self) -> Tuple[int, int]:
        """Latest review event and undo count; either moves when reviews change."""
        review = self.database.with_name(self.database.stem + ".review.db")
        if not review.exists():
            return (0, 0)
        try:
            with closing(connect_readonly(review)) as source:
                row = source.execute(
                    "SELECT COALESCE(MAX(id),0), COALESCE(SUM(undone),0) FROM review_events"
                ).fetchone()
                return (int(row[0]), int(row[1]))
        except sqlite3.Error:
            return (0, 0)

    def _scan_row(self, scan_id: str) -> Dict[str, Any]:
        with closing(connect_readonly(self.database)) as source:
            row = source.execute(
                "SELECT short_id, started_at_utc FROM scans WHERE id=?", (scan_id,)
            ).fetchone()
        return dict(row) if row else {"short_id": None, "started_at_utc": None}

    @staticmethod
    def _remove(path: Path) -> None:
        for suffix in ("", "-wal", "-shm", "-journal"):
            Path(str(path) + suffix).unlink(missing_ok=True)

    def _work(
        self,
        identifier: str,
        rules: RuleSet,
        scan: Optional[str],
        preview: bool,
        text: str,
        builtin: bool,
        started: str,
    ) -> None:
        destination: Optional[Path] = None
        try:
            review_mark = self._review_mark() if preview else (0, 0)
            if preview:
                self.previews.mkdir(mode=0o700, parents=True, exist_ok=True)
                destination = self.previews / f"{identifier}.db"
            result = rank(
                self.database,
                rules,
                scan,
                destination,
                on_phase=lambda phase, count: self._update(
                    phase=phase, processed=count
                ),
                cancelled=self._cancel.is_set,
                on_total=lambda total: self._update(total=total),
            )
            candidates = list_results(
                self.database, result["run_id"], limit=100, output=destination
            )
            if destination is not None:
                scan_row = self._scan_row(result["scan_id"])
                record = {
                    "id": identifier,
                    "run_id": result["run_id"],
                    "path": destination,
                    "created_at": started,
                    "finished_at": _now(),
                    "scan_id": result["scan_id"],
                    "scan_status": result["scan_status"],
                    "scan_short_id": scan_row["short_id"],
                    "scan_started_at": scan_row["started_at_utc"],
                    "rules_toml": text,
                    "builtins": builtin,
                    "rules_hash": result["rules_hash"],
                    "files_scored": result["files_scored"],
                    "summary": result["summary"],
                    "review_mark": review_mark,
                }
                with self._lock:
                    previous, self._preview = self._preview, record
                    self._compare_summaries.clear()
                if previous is not None:
                    self._remove(previous["path"])
            self._update(
                status="completed",
                phase="completed",
                processed=result["files_scored"],
                run_id=result["run_id"],
                scan_id=result["scan_id"],
                summary=result["summary"],
                result=result,
                candidates=candidates,
            )
        except KeyboardInterrupt:
            if destination is not None:
                self._remove(destination)
            self._update(status="cancelled", phase="cancelled")
        except Exception as exc:
            if destination is not None:
                self._remove(destination)
            self._update(status="failed", phase="failed", error=str(exc))

    def _current_preview(self, identifier: Any) -> Dict[str, Any]:
        """Caller holds the lock."""
        record = self._preview
        if (
            not isinstance(identifier, str)
            or record is None
            or record["id"] != identifier
            or not record["path"].exists()
        ):
            raise PreviewGoneError("this preview is no longer available")
        return record

    def preview(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            record = copy.deepcopy(self._preview)
        if record is None:
            return None
        newer_scan = False
        if record["scan_started_at"]:
            with closing(connect_readonly(self.database)) as source:
                newer_scan = (
                    source.execute(
                        "SELECT 1 FROM scans WHERE status='completed' "
                        "AND mode IN ('spider','snaffle') AND started_at_utc>? AND id<>? "
                        "AND EXISTS (SELECT 1 FROM scan_files sf WHERE sf.scan_id=scans.id) "
                        "LIMIT 1",
                        (record["scan_started_at"], record["scan_id"]),
                    ).fetchone()
                    is not None
                )
        reviews_changed = self._review_mark() != tuple(record["review_mark"])
        for private in ("path", "scan_started_at", "scan_status", "review_mark"):
            record.pop(private)
        record["stale"] = {"newer_scan": newer_scan, "reviews_changed": reviews_changed}
        return record

    def preview_source(self, identifier: Any) -> Tuple[Path, str]:
        """Database path and run ID of a retained preview for read endpoints."""
        with self._lock:
            record = self._current_preview(identifier)
            return record["path"], record["run_id"]

    def compare(self, identifier: Any, base: Optional[str], **options: Any) -> Dict[str, Any]:
        path, run_id = self.preview_source(identifier)
        key = (identifier, base or "")
        with self._lock:
            cached = self._compare_summaries.get(key)
        result = compare_runs(
            self.database, path, run_id, base, summary=cached, **options
        )
        if cached is None:
            with self._lock:
                if self._preview is not None and self._preview["id"] == identifier:
                    # Keyed by the requested base; an omitted base resolves to
                    # the latest saved run, which a later save can change.
                    if base:
                        self._compare_summaries[key] = result["summary"]
        return result

    def save_preview(self, identifier: Any) -> Dict[str, Any]:
        with self._lock:
            if self._thread and self._thread.is_alive():
                raise TriageBusyError("a ranking job is already running")
            record = self._current_preview(identifier)
            self._cancel.clear()
            started = _now()
            self._job = {
                "id": uuid.uuid4().hex,
                "status": "running",
                "phase": "saving preview",
                "processed": 0,
                "total": record["files_scored"],
                "preview": False,
                "preview_id": None,
                "saving_preview_id": record["id"],
                "run_id": record["run_id"],
                "rules_toml": record["rules_toml"],
                "builtins": record["builtins"],
                "scan_id": record["scan_id"],
                "summary": copy.deepcopy(record["summary"]),
                "rules_hash": record["rules_hash"],
                "started_at": started,
                "updated_at": started,
                "finished_at": None,
            }
            self._thread = threading.Thread(
                target=self._save, args=(copy.deepcopy(record),), daemon=True
            )
            self._thread.start()
            return copy.deepcopy(self._job)

    def _save(self, record: Dict[str, Any]) -> None:
        try:
            result = promote_run(
                record["path"],
                result_path(self.database),
                record["run_id"],
                on_phase=lambda phase, count: self._update(
                    phase=phase, processed=count
                ),
                cancelled=self._cancel.is_set,
            )
            result.update(
                summary=record["summary"],
                scan_status=record["scan_status"],
                saved_from_preview=record["id"],
            )
            with self._lock:
                if self._preview is not None and self._preview["id"] == record["id"]:
                    self._preview = None
                    self._compare_summaries.clear()
            self._remove(record["path"])
            self._update(
                status="completed",
                phase="completed",
                processed=result["files_scored"],
                result=result,
            )
        except KeyboardInterrupt:
            self._update(status="cancelled", phase="cancelled")
        except Exception as exc:
            self._update(status="failed", phase="failed", error=str(exc))

    def discard_preview(self, identifier: Any) -> Dict[str, Any]:
        with self._lock:
            record = self._preview
            if not isinstance(identifier, str) or record is None or record["id"] != identifier:
                return {"discarded": False}
            job = self._job or {}
            if (
                self._thread
                and self._thread.is_alive()
                and job.get("saving_preview_id") == identifier
            ):
                raise TriageBusyError("this preview is being saved")
            self._preview = None
            self._compare_summaries.clear()
        self._remove(record["path"])
        return {"discarded": True}

    def cancel(self) -> None:
        self._cancel.set()

    def close(self) -> None:
        self.cancel()
        if self._thread:
            self._thread.join(timeout=30)
        with self._lock:
            self._preview = None
        shutil.rmtree(self.previews, ignore_errors=True)
