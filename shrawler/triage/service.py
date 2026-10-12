"""One cancellable local ranking job shared by the WebUI and CLI engine."""

import copy
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from .rules import RuleSet, load_text
from .storage import list_results, rank

TERMINAL_STATUSES = {"completed", "failed", "cancelled"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class TriageBusyError(ValueError):
    pass


class TriageService:
    def __init__(self, database: Path, runtime: Path) -> None:
        self.database = database
        self.runtime = runtime
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._job: Optional[Dict[str, Any]] = None

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
            self._job = {
                "id": uuid.uuid4().hex,
                "status": "running",
                "phase": "starting",
                "processed": 0,
                "preview": preview,
                "rules_hash": rules.digest,
                "started_at": started,
                "updated_at": started,
                "finished_at": None,
            }
            self._thread = threading.Thread(
                target=self._work, args=(rules, scan, preview), daemon=True
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

    def _work(self, rules: RuleSet, scan: Optional[str], preview: bool) -> None:
        try:
            with tempfile.TemporaryDirectory(
                prefix="triage-preview-", dir=self.runtime
            ) as temporary:
                destination = Path(temporary) / "preview.db" if preview else None
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
                self._update(
                    status="completed",
                    phase="completed",
                    processed=result["files_scored"],
                    result=result,
                    candidates=candidates,
                )
        except KeyboardInterrupt:
            self._update(status="cancelled", phase="cancelled")
        except Exception as exc:
            self._update(status="failed", phase="failed", error=str(exc))

    def cancel(self) -> None:
        self._cancel.set()

    def close(self) -> None:
        self.cancel()
        if self._thread:
            self._thread.join(timeout=30)
