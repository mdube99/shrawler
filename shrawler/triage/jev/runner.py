"""Durable, resumable concurrent dispatch of planned batches.

A run is owned through a cross-process lease. One coordinator thread owns every
SQLite transition and admits bounded work to a fixed pool of HTTP workers.
Dispatch stops on a time budget, cancellation, authentication failure, or lost
lease, but never loses valid progress: successful answers are persisted per
batch and partial answers are kept.
"""

import concurrent.futures
import json
import os
import random
import sqlite3
import threading
import time
from collections import deque
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import requests

from ..storage import connect_readonly, select_scan
from .client import (
    AuthError,
    DecisionResponse,
    InputError,
    JevClient,
    load_payload,
)
from .config import JevConfig
from .planner import TokenCounter, plan_run, split_input_error_batch
from .snapshot import source_fingerprint, stage
from .storage import JevStore, utc_now

# A long gateway request must not outlive the lease; renew it independently of
# how long a single dispatch blocks.
LEASE_HEARTBEAT_SECONDS = 60.0
WORK_STATUSES = ("pending", "failed", "input-error")
# Progress is emitted at most this often; the final status is always emitted.
PROGRESS_INTERVAL_SECONDS = 0.25
# Bounded exponential backoff (with jitter) between retry waves.
RETRY_BACKOFF_BASE_SECONDS = 0.05
RETRY_BACKOFF_MAX_SECONDS = 0.5
# Maximum time the coordinator blocks waiting for a completion before it
# re-checks cancellation, deadline, rate limit, and lease heartbeat.
MAX_WAIT_SECONDS = 0.5


@dataclass(frozen=True)
class WorkItem:
    """Immutable request work item; never carries a SQLite row or connection."""

    batch_id: str
    run_id: str
    request_id: str
    payload: Dict[str, Any]
    members: Tuple[str, ...]


@dataclass
class WorkResult:
    work: WorkItem
    response: Optional[DecisionResponse] = None
    error: Optional[BaseException] = None
    duration_ms: int = 0


class RateLimiter:
    """Monotonic sliding-window admission limiter.

    ``rate_limit_per_minute=0`` is unlimited. Otherwise at most ``rate``
    admissions occur in any trailing 60-second window (no burst beyond the
    configured rate).
    """

    WINDOW_SECONDS = 60.0

    def __init__(self, per_minute: int) -> None:
        self.per_minute = per_minute
        self._timestamps: deque = deque()

    def _prune(self, now: float) -> None:
        cutoff = now - self.WINDOW_SECONDS
        while self._timestamps and self._timestamps[0] <= cutoff:
            self._timestamps.popleft()

    def blocked(self, now: float) -> bool:
        if self.per_minute <= 0:
            return False
        self._prune(now)
        return len(self._timestamps) >= self.per_minute

    def record(self, now: float) -> None:
        if self.per_minute > 0:
            self._timestamps.append(now)

    def next_slot(self, now: float) -> float:
        if self.per_minute <= 0:
            return 0.0
        self._prune(now)
        if len(self._timestamps) < self.per_minute:
            return 0.0
        return max(0.0, self._timestamps[0] + self.WINDOW_SECONDS - now)


class JevRunner:
    """Owns prepare/plan/dispatch/status for one assessment database."""

    def __init__(
        self,
        database: Path,
        config: JevConfig,
        store: JevStore,
        client: Optional[Any] = None,
        client_factory: Optional[Callable[[], Any]] = None,
    ) -> None:
        self.database = database
        self.config = config
        self.store = store
        self._injected_client = client
        if client_factory is not None:
            self._client_factory = client_factory
        elif client is not None:
            self._client_factory = lambda: client
        else:
            default_config = config
            self._client_factory = lambda: JevClient(default_config)
        self.client = client if client is not None else self._client_factory()
        self._local = threading.local()
        self._created: List[Any] = []
        self._created_lock = threading.Lock()
        self._retry_pending = False
        self.metrics: Dict[str, Any] = {}

    # -- clients ----------------------------------------------------------

    def _worker_client(self) -> Any:
        existing = getattr(self._local, "client", None)
        if existing is not None:
            return existing
        created = self._client_factory()
        self._local.client = created
        if created is not self.client and created is not self._injected_client:
            with self._created_lock:
                self._created.append(created)
        return created

    def _close_worker_clients(self) -> None:
        with self._created_lock:
            created, self._created = self._created, []
        for client in created:
            try:
                client.close()
            except Exception:
                pass
        self._local = threading.local()

    def close(self) -> None:
        self._close_worker_clients()
        if self.client is not None and self._injected_client is None:
            try:
                self.client.close()
            except Exception:
                pass

    # -- preparation ------------------------------------------------------

    def prepare(self, scan_id: Optional[str] = None, rules: Any = None) -> Dict[str, Any]:
        started = time.perf_counter()
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
        result = stage(self.database, self.store, run_id, rules, scan["id"])
        self.metrics = {"staging_ms": int((time.perf_counter() - started) * 1000)}
        self.store.set_run_metrics(run_id, self.metrics)
        return result

    def plan(self, run_id: str, cancelled: Optional[Callable[[], bool]] = None) -> int:
        started = time.perf_counter()
        counter = TokenCounter(self.client, self.config)
        result = plan_run(
            self.store,
            run_id,
            self.config,
            counter,
            self.config.objective,
            cancelled=cancelled,
            persist=True,
        )
        self.metrics["planning_ms"] = int((time.perf_counter() - started) * 1000)
        self.store.set_run_metrics(run_id, self.metrics)
        return len(result.batch_ids)

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
        workers = max(1, self.config.workers)
        limiter = RateLimiter(self.config.rate_limit_per_minute)
        counter = TokenCounter(self.client, self.config)
        self._retry_pending = False

        outcome = {"status": "completed", "error": None}
        stop_reason: Optional[str] = None
        active: Dict[concurrent.futures.Future, WorkItem] = {}
        wall_started = time.monotonic()
        remote_ms_sum = 0
        persistence_ms = 0.0
        completed_requests = 0
        retried_requests = 0
        reused_requests = 0
        peak_in_flight = 0
        next_heartbeat = time.monotonic() + 30
        last_progress = 0.0

        def emit_progress(force: bool = False) -> None:
            nonlocal last_progress
            if not progress:
                return
            now = time.monotonic()
            if force or now - last_progress >= PROGRESS_INTERVAL_SECONDS:
                progress(self.status(run_id))
                last_progress = now

        def claim_next() -> Optional[WorkItem]:
            nonlocal reused_requests
            row = self.store.next_planned_batch(run_id)
            if row is None:
                return None
            batch_id = str(row["id"])
            members = tuple(self.store.batch_members(batch_id))
            if not members:
                self.store.finish_batch(batch_id, "failed", error="empty batch")
                return None
            cached = self.store.cached_completed_batch(
                run_id, str(row["cache_key"]), batch_id
            )
            if cached is not None and self._reuse_cache(row, cached):
                reused_requests += 1
                return None
            self.store.claim_batch(run_id, batch_id, members)
            return WorkItem(
                batch_id=batch_id,
                run_id=run_id,
                request_id=str(row["request_id"]),
                payload=load_payload(row),
                members=members,
            )

        def handle_success(result: WorkResult) -> None:
            nonlocal persistence_ms
            started = time.perf_counter()
            try:
                self._persist_success(result.work, result.response)  # type: ignore[arg-type]
            finally:
                persistence_ms += (time.perf_counter() - started) * 1000

        def handle_input(result: WorkResult) -> None:
            nonlocal persistence_ms
            started = time.perf_counter()
            try:
                row = self.store.connection.execute(
                    "SELECT * FROM request_batches WHERE id=?", (result.work.batch_id,)
                ).fetchone()
                if row is None:
                    return
                split_input_error_batch(
                    self.store,
                    run_id,
                    row,
                    self.config,
                    counter,
                    self.config.objective,
                    f"input budget exceeded: {result.error}",
                )
            finally:
                persistence_ms += (time.perf_counter() - started) * 1000

        def handle_retry(result: WorkResult) -> None:
            nonlocal persistence_ms, retried_requests
            retried_requests += 1
            self._retry_pending = True
            started = time.perf_counter()
            try:
                self._handle_retryable(result.work, str(result.error))
            finally:
                persistence_ms += (time.perf_counter() - started) * 1000

        def handle_auth(result: WorkResult) -> None:
            self._abort_auth(result.work)
            outcome["status"] = "failed"
            outcome["error"] = str(result.error)
            nonlocal stop_reason
            stop_reason = "auth"

        def process(result: WorkResult) -> None:
            nonlocal remote_ms_sum, completed_requests, peak_in_flight
            remote_ms_sum += result.duration_ms
            peak_in_flight = max(peak_in_flight, len(active))
            if result.error is None and result.response is not None:
                completed_requests += 1
                handle_success(result)
            elif isinstance(result.error, AuthError):
                handle_auth(result)
            elif isinstance(result.error, InputError):
                handle_input(result)
            else:
                handle_retry(result)

        lease_thread = LeaseThread(self.store, run_id, owner)
        lease_thread.start()
        try:
            self._requeue_expired(run_id)
            # Fast-fail canary: one planned batch before the pool opens.
            if not self.store.has_successful_batch(run_id):
                canary = claim_next()
                if canary is not None:
                    process(self._execute(canary))
                    emit_progress(force=True)
                    if stop_reason == "auth":
                        raise AuthError(outcome["error"] or "authentication failed")
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=workers, thread_name_prefix="jev-http"
            ) as pool:
                while True:
                    if stop_reason is None:
                        if cancelled and cancelled():
                            stop_reason = "cancelled"
                        elif deadline and time.monotonic() >= deadline:
                            stop_reason = "paused"
                    while stop_reason is None and len(active) < workers:
                        now = time.monotonic()
                        if limiter.blocked(now):
                            break
                        work = claim_next()
                        if work is None:
                            break
                        limiter.record(now)
                        active[pool.submit(self._execute, work)] = work
                    if not active:
                        if stop_reason is not None:
                            break
                        if self.store.status_counts(run_id).get("pending", 0) > 0:
                            if self._replan(run_id):
                                self._retry_pending = False
                                continue
                            outcome["status"] = "partial"
                            break
                        break
                    peak_in_flight = max(peak_in_flight, len(active))
                    timeout = self._wait_timeout(limiter, deadline, next_heartbeat)
                    done, _ = concurrent.futures.wait(
                        active, timeout=timeout,
                        return_when=concurrent.futures.FIRST_COMPLETED,
                    )
                    now = time.monotonic()
                    for future in done:
                        work = active.pop(future)
                        try:
                            result = future.result()
                        except BaseException as exc:  # pragma: no cover - defensive
                            result = WorkResult(work=work, error=exc)
                        process(result)
                    emit_progress()
                    if now >= next_heartbeat:
                        if not self.store.heartbeat(run_id, owner):
                            outcome["status"] = "failed"
                            outcome["error"] = "lease lost"
                            stop_reason = "lease"
                            break
                        next_heartbeat = now + 30
                self._cancel_unstarted(active)
        except KeyboardInterrupt:
            outcome = {"status": "cancelled", "error": "interrupted"}
        except AuthError as exc:
            outcome = {"status": "failed", "error": str(exc)}
        except requests.RequestException as exc:
            outcome = {"status": "failed", "error": f"gateway request failed: {exc}"}
        finally:
            lease_thread.stop()
            self._close_worker_clients()
            counts = self.store.status_counts(run_id)
            unresolved = sum(counts.get(state, 0) for state in WORK_STATUSES)
            status = outcome["status"]
            if status == "completed":
                if unresolved and not counts.get("assessed"):
                    status = "failed"
                elif unresolved:
                    status = "partial"
            if stop_reason == "paused":
                status = "paused"
            elif stop_reason == "cancelled" and status == "completed":
                status = "cancelled"
            wall_ms = int((time.monotonic() - wall_started) * 1000)
            self.metrics.update(
                {
                    "dispatch_wall_ms": wall_ms,
                    "remote_request_ms_sum": remote_ms_sum,
                    "persistence_ms": int(persistence_ms),
                    "completed_requests": completed_requests,
                    "retried_requests": retried_requests,
                    "reused_requests": reused_requests,
                    "peak_in_flight": peak_in_flight,
                    "workers": workers,
                    "packing_scope": self.config.packing_scope,
                }
            )
            self.store.set_run_metrics(run_id, self.metrics)
            self.store.release_lease(run_id, owner, status, outcome["error"])
        return {"run_id": run_id, "status": status, "counts": counts}

    # -- worker -----------------------------------------------------------

    def _execute(self, work: WorkItem) -> WorkResult:
        client = self._worker_client()
        started = time.perf_counter()
        try:
            response = client.decide(work.payload)
        except BaseException as exc:
            return WorkResult(
                work=work,
                error=exc,
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        return WorkResult(
            work=work,
            response=response,
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    def _wait_timeout(
        self,
        limiter: RateLimiter,
        deadline: Optional[float],
        next_heartbeat: float,
    ) -> float:
        now = time.monotonic()
        timeout = MAX_WAIT_SECONDS
        if deadline is not None:
            timeout = min(timeout, max(0.0, deadline - now))
        timeout = min(timeout, max(0.0, next_heartbeat - now))
        if limiter.per_minute > 0:
            timeout = min(timeout, limiter.next_slot(now) or MAX_WAIT_SECONDS)
        return max(0.0, timeout)

    def _cancel_unstarted(
        self, active: Dict[concurrent.futures.Future, WorkItem]
    ) -> None:
        for future, work in list(active.items()):
            if future.cancel():
                self.store.release_batch_to_planned(
                    work.run_id, work.batch_id, work.members
                )
                active.pop(future, None)

    # -- persistence ------------------------------------------------------

    def _persist_success(self, work: WorkItem, response: DecisionResponse) -> None:
        hashes = self.store.batch_directory_hashes(work.batch_id)
        members_with_directory = self.store.batch_members_with_directory(work.batch_id)
        answers: List[Dict[str, Any]] = []
        answered: set = set()
        provenance = self.config.provenance()
        for row in members_with_directory:
            file_id = str(row["file_id"])
            answer = response.answers.get(file_id)
            if answer is None:
                continue
            answers.append(
                {
                    "file_id": file_id,
                    "choice": answer.choice,
                    "distribution": answer.distribution,
                    "deployment_revision": self.config.deployment_revision
                    or self.config.model,
                    "model": response.model,
                    "adapter_version": self.client.adapter_version,
                    "rubric_version": provenance["rubric_version"],
                    "context_hash": hashes.get(int(row["directory_id"]), ""),
                }
            )
            answered.add(file_id)
        missing = [file_id for file_id in work.members if file_id not in answered]
        exhausted, retrying = self._split_by_attempts(work.run_id, missing)
        if not missing:
            batch_status = "completed"
        elif answers:
            batch_status = "partial"
        else:
            batch_status = "failed"
        self.store.complete_batch(
            work.run_id,
            work.batch_id,
            work.request_id,
            answers,
            retrying,
            exhausted,
            batch_status,
            hashes,
            usage=response.usage,
            http_status=response.http_status,
            remote_model=response.model,
            duration_ms=response.latency_ms,
        )

    def _handle_retryable(self, work: WorkItem, error: str) -> None:
        exhausted, retrying = self._split_by_attempts(work.run_id, list(work.members))
        self.store.fail_batch(
            work.run_id, work.batch_id, retrying, exhausted, "failed", error
        )

    def _abort_auth(self, work: WorkItem) -> None:
        self.store.release_batch_to_planned(
            work.run_id, work.batch_id, list(work.members)
        )

    def _split_by_attempts(
        self, run_id: str, file_ids: Sequence[str]
    ) -> Tuple[List[str], List[str]]:
        """Partition unresolved files into exhausted and retryable groups."""
        exhausted: List[str] = []
        retrying: List[str] = []
        attempts = self.store.attempts_for(run_id, list(file_ids))
        for file_id in file_ids:
            count = attempts.get(file_id, 0)
            (retrying if count <= self.config.retries else exhausted).append(file_id)
        return exhausted, retrying

    def _reuse_cache(self, row: Any, cached: Any) -> bool:
        run_id = str(row["run_id"])
        batch_id = str(row["id"])
        cached_run = str(cached["run_id"])
        cached_batch = str(cached["id"])
        cached_results = {
            str(result["file_id"]): result
            for result in self.store.results_for_batch(cached_run, cached_batch)
        }
        members = self.store.batch_members(batch_id)
        answers = [file_id for file_id in members if file_id in cached_results]
        if not answers:
            return False
        hashes = self.store.batch_directory_hashes(batch_id)
        directories = {
            str(result["file_id"]): int(result["directory_id"])
            for result in self.store.batch_members_with_directory(batch_id)
        }
        payload_answers: List[Dict[str, Any]] = []
        for file_id in answers:
            result = cached_results[file_id]
            payload_answers.append(
                {
                    "file_id": file_id,
                    "choice": str(result["choice"]),
                    "distribution": json.loads(result["distribution_json"])
                    if result["distribution_json"]
                    else None,
                    "deployment_revision": str(result["deployment_revision"]),
                    "model": str(result["model"]),
                    "adapter_version": str(result["adapter_version"]),
                    "rubric_version": str(result["rubric_version"]),
                    "context_hash": hashes.get(directories.get(file_id, -1), ""),
                }
            )
        missing = [file_id for file_id in members if file_id not in cached_results]
        exhausted, retrying = self._split_by_attempts(run_id, missing)
        batch_status = "completed" if not missing else "partial"
        self.store.complete_batch(
            run_id,
            batch_id,
            str(row["request_id"]),
            payload_answers,
            retrying,
            exhausted,
            batch_status,
            hashes,
            error=None,
            source="cache",
        )
        return True

    # -- retry planning and recovery --------------------------------------

    def _replan(self, run_id: str) -> int:
        """Create fresh batches for pending files using the global planner."""
        if self._retry_pending:
            # Bounded exponential backoff with jitter between retry waves.
            delay = min(
                RETRY_BACKOFF_MAX_SECONDS,
                RETRY_BACKOFF_BASE_SECONDS * (2 ** random.randint(0, 3)),
            )
            time.sleep(delay)
        counter = TokenCounter(self.client, self.config)
        result = plan_run(
            self.store,
            run_id,
            self.config,
            counter,
            self.config.objective,
            persist=True,
        )
        return len(result.batch_ids)

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
        counts = self.store.status_counts(run_id)
        batch_counts = self.store.batch_status_counts(run_id)
        total = int(run["total_observed"] or 0)
        assessed = counts.get("assessed", 0)
        in_flight = counts.get("in-flight", 0)
        pending = counts.get("pending", 0) + counts.get("planned", 0)
        failed = counts.get("failed", 0) + counts.get("input-error", 0)
        metrics = {}
        if run["metrics_json"]:
            try:
                metrics = json.loads(run["metrics_json"])
            except ValueError:
                metrics = {}
        durations = sorted(self.store.recent_durations(run_id))
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
            "workers": int(self.config.workers),
            "packing_scope": self.config.packing_scope,
            "metrics": metrics,
            "latency_ms": _percentiles(durations),
            "batches": {
                "total": sum(batch_counts.values()),
                "completed": batch_counts.get("completed", 0) + batch_counts.get("partial", 0),
                "active": batch_counts.get("in-flight", 0),
                "pending": batch_counts.get("planned", 0),
                "failed": batch_counts.get("failed", 0)
                + batch_counts.get("input-error", 0),
            },
        }


def _percentiles(values: List[int]) -> Dict[str, Optional[int]]:
    if not values:
        return {"p50": None, "p95": None, "count": 0}

    def pick(percent: float) -> int:
        index = min(len(values) - 1, round(percent * (len(values) - 1)))
        return values[index]

    return {"p50": pick(0.50), "p95": pick(0.95), "count": len(values)}


class LeaseThread(threading.Thread):
    """Background heartbeat so a long dispatch keeps a live lease.

    The store connection is not shared across threads, so this opens its own
    connection to the assessment database and renews the lease independently of
    how long a single gateway request blocks.
    """

    def __init__(self, store: JevStore, run_id: str, owner: str) -> None:
        super().__init__(daemon=True, name="jev-lease")
        self.path = store.path
        self.run_id = run_id
        self.owner = owner
        # Named _stop_event, not _stop: threading.Thread uses _stop internally.
        self._stop_event = threading.Event()

    def run(self) -> None:
        connection = sqlite3.connect(self.path, timeout=30)
        try:
            while not self._stop_event.wait(LEASE_HEARTBEAT_SECONDS):
                cursor = connection.execute(
                    "UPDATE assessment_runs SET heartbeat_at=? "
                    "WHERE id=? AND lease_owner=?",
                    (utc_now(), self.run_id, self.owner),
                )
                connection.commit()
                if cursor.rowcount != 1:
                    return
        finally:
            connection.close()

    def stop(self) -> None:
        self._stop_event.set()
        self.join(timeout=5)
