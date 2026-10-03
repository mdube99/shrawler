"""One cancellable model-assisted assessment job shared by the WebUI and CLI.

The durable work lives in the assessment database and its cross-process lease;
this service only owns the background thread that drives a run inside the
running WebUI server, exactly like the offline ranking service.
"""

import copy
import os
import platform
import sqlite3
import threading
import uuid
from contextlib import closing
from pathlib import Path
from typing import Any, Dict, Optional

from ..rules import load
from ..storage import connect_readonly, select_scan
from .client import JevClient
from .config import JevConfig
from .runner import JevRunner
from .storage import JevStore, RunBusyError, assessment_path
from .views import coverage_by_directory, highlight_missed, list_assessed


class JevBusyError(ValueError):
    pass


class JevService:
    """Background owner of one assessment run for one inventory."""

    def __init__(self, database: Path, runtime: Path, config: JevConfig) -> None:
        self.database = database
        self.runtime = runtime
        self.config = config
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._job: Optional[Dict[str, Any]] = None

    # -- availability -----------------------------------------------------

    def available(self) -> bool:
        return assessment_path(self.database).exists()

    def status(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(self._job)

    def _owner(self) -> str:
        return f"webui:{platform.node() or 'localhost'}:{os.getpid()}"

    # -- job control ------------------------------------------------------

    def start(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare (optionally) and dispatch a run in the background."""
        if set(payload) - {"scan_id", "prepare", "budget_seconds", "max_questions"}:
            raise ValueError("unknown assessment job field")
        scan = payload.get("scan_id")
        if scan == "":
            scan = None
        if scan is not None and (not isinstance(scan, str) or len(scan) > 100):
            raise ValueError("invalid scan ID")
        prepare = payload.get("prepare", False)
        if type(prepare) is not bool:
            raise ValueError("prepare must be a boolean")
        budget = payload.get("budget_seconds")
        if budget is not None and (type(budget) is not int or budget < 0):
            raise ValueError("budget_seconds must be a nonnegative integer")
        max_questions = payload.get("max_questions")
        if max_questions is not None and (
            type(max_questions) is not int or not 1 <= max_questions <= 10000
        ):
            raise ValueError("max_questions must be between 1 and 10000")

        with self._lock:
            if self._thread and self._thread.is_alive():
                raise JevBusyError("an assessment job is already running")
            self._cancel.clear()
            self._job = {
                "id": uuid.uuid4().hex,
                "status": "running",
                "phase": "starting",
                "processed": 0,
                "total": 0,
                "assessment_run_id": None,
                "prepare": prepare,
            }
            self._thread = threading.Thread(
                target=self._work,
                args=(scan, prepare, budget, max_questions),
                daemon=True,
            )
            self._thread.start()
            return copy.deepcopy(self._job)

    def _update(self, **values: Any) -> None:
        with self._lock:
            if self._job is not None:
                self._job.update(values)

    def _work(
        self,
        scan: Optional[str],
        prepare: bool,
        budget: Optional[int],
        max_questions: Optional[int],
    ) -> None:
        try:
            config = self.config
            if max_questions is not None and max_questions != config.max_questions_per_request:
                config = JevConfig.from_mapping(
                    {
                        **config.to_table(),
                        "max_questions_per_request": max_questions,
                    }
                )

            if prepare:
                with JevStore(self.database) as store:
                    with closing(connect_readonly(self.database)) as source:
                        source.execute("BEGIN")
                        select_scan(source, scan)
                    runner = JevRunner(self.database, config, store)
                    self._update(phase="staging ledger")
                    result = runner.prepare(scan, load(None, True))
                    run_id = result["run_id"]
                    self._update(assessment_run_id=run_id, phase="planning batches")
                    planned = runner.plan(run_id, cancelled=self._cancel.is_set)
                    self._update(
                        total=result["observed_files"],
                        planned_batches=planned,
                        phase="dispatching",
                    )
                    outcome = self._dispatch(runner, run_id, budget)
            else:
                with JevStore(self.database) as store:
                    run = store.select_run(None)
                    run_id = str(run["id"])
                    runner = JevRunner(self.database, config, store)
                    self._update(
                        assessment_run_id=run_id,
                        phase="planning batches",
                        total=int(run["total_observed"] or 0),
                    )
                    planned = runner.plan(run_id, cancelled=self._cancel.is_set)
                    self._update(planned_batches=planned, phase="dispatching")
                    outcome = self._dispatch(runner, run_id, budget)
            status = "cancelled" if self._cancel.is_set() else outcome["status"]
            self._update(
                status=status,
                phase=status,
                processed=outcome["counts"].get("assessed", 0),
                counts=outcome["counts"],
                outcome=outcome,
            )
        except KeyboardInterrupt:
            self._update(status="cancelled", phase="cancelled")
        except RunBusyError as exc:
            self._update(status="failed", phase="failed", error=str(exc))
        except (OSError, ValueError, sqlite3.Error) as exc:
            self._update(status="failed", phase="failed", error=str(exc))

    def _dispatch(self, runner: JevRunner, run_id: str, budget: Optional[int]) -> Dict[str, Any]:
        return runner.run(
            run_id,
            self._owner(),
            cancelled=self._cancel.is_set,
            progress=lambda status: self._update(
                processed=status["assessed"],
                total=status["total_observed"],
                pending=status["pending"],
                failed=status["failed"],
            ),
            budget_seconds=budget,
        )

    def cancel(self) -> None:
        self._cancel.set()

    def close(self) -> None:
        self.cancel()
        if self._thread:
            self._thread.join(timeout=30)

    # -- read-only views --------------------------------------------------

    def catalog(self) -> Dict[str, Any]:
        """Scans and runs available for the assessment page."""
        with closing(connect_readonly(self.database)) as source:
            scans = [
                dict(row)
                for row in source.execute(
                    "SELECT id, short_id, mode, status, started_at_utc, "
                    "(SELECT COUNT(*) FROM scan_files sf WHERE sf.scan_id=scans.id) "
                    "AS file_count FROM scans WHERE mode IN ('spider','snaffle') "
                    "ORDER BY started_at_utc DESC, rowid DESC LIMIT 200"
                )
            ]
        runs: list = []
        if assessment_path(self.database).exists():
            with JevStore(self.database) as store:
                runs = [
                    {
                        "id": row["id"],
                        "scan_id": row["scan_id"],
                        "status": row["status"],
                        "created_at": row["created_at"],
                        "total_observed": row["total_observed"],
                        "config_fingerprint": row["config_fingerprint"],
                    }
                    for row in store.connection.execute(
                        "SELECT id,scan_id,status,created_at,total_observed,"
                        "config_fingerprint FROM assessment_runs "
                        "ORDER BY created_at DESC, rowid DESC LIMIT 200"
                    )
                ]
        with self._lock:
            job = copy.deepcopy(self._job)
        return {
            "scans": scans,
            "runs": runs,
            "job": job,
            "endpoint": self.config.endpoint,
            "model": self.config.model,
        }

    def run_status(self, run_id: Optional[str]) -> Dict[str, Any]:
        with JevStore(self.database) as store:
            selected = store.select_run(run_id)
            runner = JevRunner(self.database, self.config, store)
            return runner.status(str(selected["id"]))

    def coverage(self, run_id: Optional[str]) -> Dict[str, Any]:
        with JevStore(self.database) as store:
            selected = store.select_run(run_id)
            return {
                "run_id": str(selected["id"]),
                "directories": coverage_by_directory(store, str(selected["id"])),
            }

    def files(
        self,
        run_id: Optional[str],
        label: Optional[str],
        directory_id: Optional[int],
        limit: int,
        offset: int,
        missed: bool,
    ) -> Dict[str, Any]:
        with JevStore(self.database) as store:
            selected = store.select_run(run_id)
            identifier = str(selected["id"])
            if missed:
                return highlight_missed(store, identifier, limit)
            return list_assessed(
                store, identifier, label, directory_id, limit, offset
            )

    def client(self) -> JevClient:
        return JevClient(self.config)

    def check(self) -> Dict[str, Any]:
        client = JevClient(self.config)
        report = client.probe()
        report["configured"] = self.config.provenance()
        return report
