"""Durable, resumable dispatch of planned batches.

A run is owned through a cross-process lease. Dispatch stops on a time budget,
cancellation, or gateway failure, but never loses valid progress: successful
answers are persisted per batch and partial answers are kept.
"""

import os
import threading
import time
from contextlib import closing
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests

from ..storage import connect_readonly, select_scan
from .client import InputError, JevClient, ProtocolError, load_payload
from .config import JevConfig
from .planner import TokenCounter, plan_directory
from .snapshot import source_fingerprint, stage
from .storage import JevStore, utc_now

PAUSE_CHECK_SECONDS = 60.0
WORK_STATUSES = ("pending", "failed", "input-error")


class RunnerError(ValueError):
    pass


class JevRunner:
    """Owns prepare/dispatch/status for one assessment database."""

    def __init__(
        self,
        database: Path,
        config: JevConfig,
        store: JevStore,
        client: Optional[Any] = None,
    ) -> None:
        self.database = database
        self.config = config
        self.store = store
        self.client = client or JevClient(config)

    # -- preparation ------------------------------------------------------

    def prepare(self, scan_id: Optional[str] = None, rules: Any = None) -> Dict[str, Any]:
        with closing(connect_readonly(self.database)) as source:
            scan = dict(select_scan(source, scan_id))
        run_id = self.store.create_run(
            scan,
            source_fingerprint(scan),
            {
                **self.config.provenance(),
                "config_fingerprint": self.config.fingerprint(),
                "budget_seconds": self.config.time_budget_seconds,
            },
        )
        return stage(self.database, self.store, run_id, rules, scan["id"])

    def plan(self, run_id: str, cancelled: Optional[Callable[[], bool]] = None) -> int:
        counter = TokenCounter(self.client, self.config)
        total = 0
        for row in self.store.context_rows(run_id):
            total += len(
                plan_directory(
                    self.store, run_id, row, self.config, counter, self.config.objective,
                    cancelled=cancelled,
                )
            )
        return total

    # -- dispatch ---------------------------------------------------------

    def run(
        self,
        run_id: str,
        owner: str,
        cancelled: Optional[Callable[[], bool]] = None,
        progress: Optional[Callable[[Dict[str, Any]], None]] = None,
        budget_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        self.store.acquire_lease(run_id, owner, os.getpid())
        self.store.update_run(run_id, started_at=utc_now(), heartbeat_at=utc_now())
        budget = self.config.time_budget_seconds if budget_seconds is None else budget_seconds
        deadline = time.monotonic() + budget if budget else None
        next: Dict[str, Any] = {"status": "completed", "error": None}
        last_heartbeat = time.monotonic()
        try:
            self._requeue_expired(run_id)
            while True:
                if cancelled and cancelled():
                    next = {"status": "cancelled", "error": None}
                    break
                if deadline and time.monotonic() >= deadline:
                    next = {"status": "paused", "error": None}
                    break
                batch = self.store.connection.execute(
                    "SELECT * FROM request_batches WHERE run_id=? AND status IN "
                    "('planned','in-flight') ORDER BY ordinal LIMIT 1",
                    (run_id,),
                ).fetchone()
                if batch is None:
                    remaining = self.store.overall_counts(run_id).get("pending", 0)
                    if remaining:
                        # Pending files whose batch already terminated (partial
                        # or exhausted) are replanned with fresh batches rather
                        # than re-selecting a terminal batch forever.
                        replanned = self._replan_pending(run_id)
                        if not replanned:
                            next = {"status": "partial", "error": None}
                            break
                        continue
                    next = {"status": "completed", "error": None}
                    break
                self._dispatch(batch)
                if progress:
                    progress(self.status(run_id))
                if time.monotonic() - last_heartbeat >= 30:
                    if not self.store.heartbeat(run_id, owner):
                        next = {"status": "lost-lease", "error": "lease lost"}
                        break
                    last_heartbeat = time.monotonic()
        except KeyboardInterrupt:
            next = {"status": "cancelled", "error": "interrupted"}
        except requests.RequestException as exc:
            next = {"status": "failed", "error": f"gateway request failed: {exc}"}
        finally:
            counts = self.store.overall_counts(run_id)
            unresolved = sum(counts.get(state, 0) for state in WORK_STATUSES)
            status = next["status"]
            if status == "completed":
                if unresolved and not counts.get("assessed"):
                    # Nothing survived: report failure rather than pretend the
                    # run merely paused.
                    status = "failed"
                elif unresolved:
                    status = "partial"
            self.store.release_lease(run_id, owner, status, next["error"])
        return {"run_id": run_id, "status": status, "counts": counts}

    def _dispatch(self, batch: Any) -> None:
        batch_id = str(batch["id"])
        members = self.store.batch_members(batch_id)
        self.store.mark_batch_dispatched(batch_id)
        for file_id in members:
            self.store.set_file_status(
                str(batch["run_id"]), [file_id], "in-flight", increment_attempt=True
            )
        self.store.commit()
        payload = load_payload(batch)
        started = time.perf_counter()
        try:
            response = self.client.decide(payload)
        except InputError as exc:
            # Reshaping a single oversized request is a planner concern; record
            # the whole batch as an input error rather than retrying unchanged.
            self.store.finish_batch(batch_id, "input-error", error=str(exc))
            self.store.set_file_status(
                str(batch["run_id"]), members, "input-error", error=str(exc)
            )
            self.store.commit()
            return
        except ProtocolError as exc:
            self._handle_failure(batch, members, str(exc), retryable=True)
            return
        except requests.RequestException as exc:
            self._handle_failure(batch, members, f"request failed: {exc}", retryable=True)
            return
        self._persist(batch, members, response, int((time.perf_counter() - started) * 1000))

    def _persist(self, batch: Any, members: List[str], response: Any, duration_ms: int) -> None:
        run_id = str(batch["run_id"])
        batch_id = str(batch["id"])
        context_row = self.store.context_for(run_id, int(batch["directory_id"]))
        context_hash = context_row["context_hash"] if context_row else ""
        answered: List[str] = []
        for file_id in members:
            answer = response.answers.get(file_id)
            if answer is None:
                continue
            result_id = self.store.record_result(
                run_id,
                batch_id,
                str(batch["request_id"]),
                file_id,
                answer.choice,
                answer.distribution,
                self.config.deployment_revision or self.config.model,
                response.model,
                self.client.adapter_version,
                self.config.provenance()["rubric_version"],
                context_hash,
            )
            self.store.set_file_status(
                run_id, [file_id], "assessed", result_id=result_id, error=None
            )
            answered.append(file_id)
        missing = [file_id for file_id in members if file_id not in answered]
        if missing:
            # Partial answers are kept; unresolved candidates return to the
            # queue and can be replanned with full context, until their own
            # attempt count is exhausted.
            exhausted, retrying = self._split_by_attempts(run_id, missing)
            if retrying:
                self.store.set_file_status(run_id, retrying, "pending", error=None)
            if exhausted:
                self.store.set_file_status(
                    run_id, exhausted, "failed", error="missing answer after retries"
                )
            batch_status = "partial" if answered else ("failed" if exhausted and not retrying else "planned")
        else:
            batch_status = "completed"
        self.store.finish_batch(
            batch_id,
            batch_status,
            usage=response.usage,
            http_status=response.http_status,
            remote_model=response.model,
            duration_ms=duration_ms,
        )
        if answered:
            self.store.put_cache(run_id, str(batch["cache_key"]), batch_id)
        self.store.commit()

    def _split_by_attempts(
        self, run_id: str, file_ids: List[str]
    ) -> Tuple[List[str], List[str]]:
        """Partition unresolved files into exhausted and retryable groups."""
        exhausted: List[str] = []
        retrying: List[str] = []
        for file_id in file_ids:
            row = self.store.file_row(run_id, file_id)
            attempts = int(row["attempts"]) if row is not None else 0
            (retrying if attempts <= self.config.retries else exhausted).append(file_id)
        return exhausted, retrying

    def _handle_failure(
        self, batch: Any, members: List[str], error: str, retryable: bool
    ) -> None:
        run_id = str(batch["run_id"])
        if retryable:
            exhausted, retrying = self._split_by_attempts(run_id, members)
        else:
            exhausted, retrying = members, []
        self.store.finish_batch(
            str(batch["id"]), "failed" if exhausted and not retrying else "planned", error=error
        )
        if retrying:
            self.store.set_file_status(run_id, retrying, "pending", error=None)
        if exhausted:
            self.store.set_file_status(run_id, exhausted, "failed", error=error)
        self.store.commit()

    def _replan_pending(self, run_id: str) -> int:
        """Create fresh batches for pending files whose prior batch terminated.

        Uses the planner so cache keys and budget enforcement stay identical to
        first-round planning. Returns the number of new batches.
        """
        counter = TokenCounter(self.client, self.config)
        directory_ids = [
            int(row["directory_id"])
            for row in self.store.connection.execute(
                "SELECT DISTINCT directory_id FROM assessment_files "
                "WHERE run_id=? AND status='pending'",
                (run_id,),
            )
        ]
        created = 0
        for directory_id in sorted(directory_ids):
            context = self.store.context_for(run_id, directory_id)
            if context is None:
                continue
            created += len(
                plan_directory(
                    self.store,
                    run_id,
                    context,
                    self.config,
                    counter,
                    self.config.objective,
                )
            )
        return created

    def _requeue_expired(self, run_id: str) -> None:
        # In-flight rows are only safe to requeue after a crash; a live lease
        # means this process owns them.
        rows = self.store.connection.execute(
            "SELECT id FROM request_batches WHERE run_id=? AND status='in-flight'",
            (run_id,),
        ).fetchall()
        ids = [str(row["id"]) for row in rows]
        if not ids:
            return
        placeholders = ",".join("?" for _ in ids)
        with self.store.connection:
            self.store.connection.execute(
                f"UPDATE request_batches SET status='planned' WHERE id IN ({placeholders})",
                ids,
            )
            self.store.connection.execute(
                f"UPDATE assessment_files SET status='pending' WHERE run_id=? "
                f"AND batch_id IN ({placeholders}) AND status='in-flight'",
                (run_id, *ids),
            )

    # -- views ------------------------------------------------------------

    def status(self, run_id: str) -> Dict[str, Any]:
        run = self.store.select_run(run_id)
        counts = self.store.overall_counts(run_id)
        total = int(run["total_observed"] or 0)
        assessed = counts.get("assessed", 0)
        in_flight = counts.get("in-flight", 0)
        pending = counts.get("pending", 0) + counts.get("planned", 0)
        failed = counts.get("failed", 0) + counts.get("input-error", 0)
        batches = self.store.batch_rows(run_id)
        return {
            "run_id": run_id,
            "scan_id": run["scan_id"],
            "status": run["status"],
            "deployment_revision": run["deployment_revision"],
            "total_observed": total,
            "assessed": assessed,
            "in_flight": in_flight,
            "pending": pending,
            "failed": failed,
            "accounted": assessed + in_flight + pending + failed,
            "reconciled": total == assessed + in_flight + pending + failed,
            "directories": int(run["context_count"] or 0),
            "batches": {
                "total": len(batches),
                "completed": sum(1 for row in batches if row["status"] == "completed"),
                "failed": sum(1 for row in batches if row["status"] == "failed"),
            },
        }


class LeaseThread(threading.Thread):
    """Background heartbeat so a long dispatch keeps a live lease."""

    def __init__(self, store: JevStore, run_id: str, owner: str) -> None:
        super().__init__(daemon=True)
        self.store = store
        self.run_id = run_id
        self.owner = owner
        self._stop = threading.Event()

    def run(self) -> None:
        while not self._stop.wait(60):
            if not self.store.heartbeat(self.run_id, self.owner):
                return

    def stop(self) -> None:
        self._stop.set()
