#!/usr/bin/env python3
"""Deterministic Jev assessment benchmark harness (plan workstream A).

It builds a synthetic pinned inventory, stages it, plans it, and dispatches it
against an in-process fake System One gateway with configurable latency and
concurrency. It never needs credentials and never incurs hosted inference cost.

Fixtures (``--fixture``):

* ``captured``   the measured 774-file / 203-directory topology
* ``wide``       one directory holding many files
* ``many-tiny``  many small directories
* ``mixed``      wide + medium + single-file directories
* ``retry``      deterministic missing answers and transient failures

Recorded: staging/planning/dispatch wall time, peak RSS, request count and file
distribution, payload bytes and tokens, achieved concurrency, latency
percentiles, persistence/progress time, optional SQL statement counts, and
final reconciliation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import resource
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shrawler.store import ScanStore  # noqa: E402
from shrawler.triage.jev.client import (  # noqa: E402
    Answer,
    DecisionResponse,
    ProtocolError,
)
from shrawler.triage.jev.config import JevConfig  # noqa: E402
from shrawler.triage.jev.runner import JevRunner  # noqa: E402
from shrawler.triage.jev.storage import JevStore, assessment_path  # noqa: E402


def _metadata(host: str, share: str, path: str, size: int, index: int) -> Dict[str, Any]:
    name = path.replace("\\", "/").rsplit("/", 1)[-1]
    return {
        "host": host,
        "share": share,
        "file_name": name,
        "remote_path": path,
        "unc_path": f"\\\\{host}\\{share}\\" + path.lstrip("/").replace("/", "\\"),
        "size_bytes": size,
        "readable_size": f"{size}B",
        "mtime_utc": "2026-01-01T00:00:00+00:00",
        "scan_timestamp_utc": "2026-09-05T00:00:00+00:00",
    }


def captured_directories() -> List[int]:
    """The measured 203-directory / 774-file 1-11 files-per-directory shape."""
    counts = [1] * 29 + [2] * 32 + [3] * 36 + [4] * 36
    counts += [6] * (203 - len(counts))
    # Deterministically add the remaining files so the total is exactly 774.
    total = sum(counts)
    cursor = 0
    while total < 774:
        counts[cursor % len(counts)] += 1
        total += 1
        cursor += 1
    while total > 774:
        for index in range(len(counts)):
            if counts[index] > 1 and total > 774:
                counts[index] -= 1
                total -= 1
    return counts


def wide_counts(files: int) -> List[int]:
    return [files]


def many_tiny_counts(files: int) -> List[int]:
    directories = max(1, min(files, 25000))
    counts = [1] * directories
    remaining = files - directories
    index = 0
    while remaining > 0:
        counts[index] += 1
        remaining -= 1
        index = (index + 1) % len(counts)
    return counts


def mixed_counts(files: int) -> List[int]:
    counts = [files // 2, files // 4]
    counts += [3] * 20
    counts += [1] * 40
    remaining = files - sum(counts)
    if remaining > 0:
        counts[0] += remaining
    return [count for count in counts if count > 0]


def density_counts(files: int, per_directory: int) -> List[int]:
    """Uniform ``files / per_directory`` shape with a deterministic remainder."""
    per_directory = max(1, per_directory)
    directories = max(1, files // per_directory)
    counts = [per_directory] * directories
    remainder = files - per_directory * directories
    index = 0
    while remainder > 0:
        counts[index] += 1
        remainder -= 1
        index = (index + 1) % len(counts)
    return counts


FIXTURES = {
    "captured": lambda files, _args: captured_directories(),
    "wide": lambda files, _args: wide_counts(files),
    "many-tiny": lambda files, _args: many_tiny_counts(files),
    "mixed": lambda files, _args: mixed_counts(files),
    "retry": lambda files, _args: captured_directories(),
    # The confirmed scale target: ~1M files at ~20 files/directory (50k dirs).
    "density": lambda files, args: density_counts(files, args.files_per_directory),
}


@dataclass
class FakeGateway:
    """Thread-safe fake System One endpoint with measured concurrency."""

    latency_seconds: float = 0.15
    max_concurrency: int = 0
    drop_fraction: float = 0.0
    fail_fraction: float = 0.0
    seed: int = 7

    calls: int = 0
    failures: int = 0
    active: int = 0
    peak_active: int = 0
    total_latency: float = 0.0
    _semaphore: Optional[threading.Semaphore] = None
    _first_seen: set = field(default_factory=set)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    adapter_version = "benchmark-1"

    def __post_init__(self) -> None:
        if self.max_concurrency > 0:
            self._semaphore = threading.Semaphore(self.max_concurrency)

    def close(self) -> None:
        return None

    def count_tokens(self, _text: str) -> Optional[int]:
        return None

    def decide(self, payload: Dict[str, Any]) -> DecisionResponse:
        acquired = False
        if self._semaphore is not None:
            self._semaphore.acquire()
            acquired = True
        started = time.perf_counter()
        try:
            with self._lock:
                self.calls += 1
                self.active += 1
                self.peak_active = max(self.peak_active, self.active)
            time.sleep(self.latency_seconds)
            state_key = hashlib.sha256(str(payload.get("state", "")).encode()).hexdigest()
            with self._lock:
                first = state_key not in self._first_seen
                self._first_seen.add(state_key)
            rng = random.Random(f"{self.seed}:{state_key}:{self.calls}")
            if self.fail_fraction and rng.random() < self.fail_fraction and first:
                with self._lock:
                    self.failures += 1
                raise ProtocolError("benchmark transient failure")
            questions = payload.get("questions", {})
            answers = {}
            for file_id in questions:
                if self.drop_fraction and first and rng.random() < self.drop_fraction:
                    continue
                answers[file_id] = {
                    "choice": "3",
                    "probabilities": {"3": 0.8, "2": 0.2},
                }
            if not answers and questions:
                raise ProtocolError("benchmark dropped every answer")
            return DecisionResponse(
                answers={
                    file_id: Answer(
                        file_id=file_id,
                        choice=body["choice"],
                        distribution={"3": 0.8},
                    )
                    for file_id, body in answers.items()
                },
                usage={"input_tokens": len(payload.get("state", "")) // 4},
                model="jev-benchmark",
                http_status=200,
                latency_ms=int(self.latency_seconds * 1000),
            )
        finally:
            with self._lock:
                self.active -= 1
            self.total_latency += time.perf_counter() - started
            if acquired and self._semaphore is not None:
                self._semaphore.release()


def build_inventory(root: Path, counts: List[int], host: str = "server", share: str = "DATA") -> str:
    store = ScanStore(root, "spider", "DOMAIN", "benchmark")
    store.upsert_host(host, host, "complete")
    store.upsert_share(host, share, "complete", {})
    extensions = (".csv", ".txt", ".xlsx", ".conf", ".key", ".json", ".log", ".bak")
    for directory_index, count in enumerate(counts):
        depth = directory_index % 5
        parts = [f"area{directory_index % 17:02d}"]
        for level in range(depth):
            parts.append(f"sub{level}")
        parts.append(f"dir{directory_index:05d}")
        for file_index in range(count):
            extension = extensions[(directory_index + file_index) % len(extensions)]
            path = "/" + "/".join(parts) + f"/file_{file_index:04d}{extension}"
            payload = _metadata(
                host, share, path, 128 + (file_index * 37) % 8192, file_index
            )
            store.add_file(host, share, payload)
    store.finish("completed", {})
    identifier = store.scan_id
    store.close()
    return identifier


def percentiles(values: List[int]) -> Dict[str, Optional[int]]:
    if not values:
        return {"p50": None, "p95": None, "p99": None}
    ordered = sorted(values)

    def pick(fraction: float) -> int:
        index = min(len(ordered) - 1, round(fraction * (len(ordered) - 1)))
        return ordered[index]

    return {"p50": pick(0.50), "p95": pick(0.95), "p99": pick(0.99)}


def run_benchmark(args: argparse.Namespace) -> Dict[str, Any]:
    root = Path(tempfile.mkdtemp(prefix="jev-bench-"))
    database = root / "shrawler.db"
    counts = FIXTURES[args.fixture](args.files, args)
    start_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    scan_started = time.perf_counter()
    scan_id = build_inventory(root, counts)
    fixture_ms = int((time.perf_counter() - scan_started) * 1000)

    config = JevConfig.from_mapping(
        {
            "endpoint": "https://benchmark.invalid/v1/systemone",
            "model": "jev-benchmark",
            "workers": args.workers,
            "rate_limit_per_minute": args.rate_limit,
            "packing_scope": args.packing_scope,
            "max_questions_per_request": args.max_questions,
            "max_request_bytes": args.max_request_bytes,
        }
    )
    gateway = FakeGateway(
        latency_seconds=args.latency_ms / 1000.0,
        max_concurrency=args.max_concurrency,
        drop_fraction=0.15 if args.fixture == "retry" else 0.0,
        fail_fraction=0.10 if args.fixture == "retry" else 0.0,
    )
    statements: Dict[str, int] = {"staging": 0, "planning": 0, "dispatch": 0}
    phase = {"name": "staging"}

    with JevStore(database) as store:
        if args.sql_count:
            store.connection.set_trace_callback(
                lambda _s: statements.__setitem__(phase["name"], statements[phase["name"]] + 1)
            )
        runner = JevRunner(database, config, store, client=gateway)

        phase["name"] = "staging"
        prepared = runner.prepare(scan_id)
        run_id = prepared["run_id"]

        phase["name"] = "planning"
        batches = runner.plan(run_id)

        stage_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        phase["name"] = "dispatch"
        outcome = runner.run(run_id, "benchmark-owner")
        status = runner.status(run_id)
        phase["name"] = "idle"

        batch_rows = store.batch_rows(run_id)
        members_per_batch = [len(store.batch_members(str(row["id"]))) for row in batch_rows]
        directories_per_batch = [
            len(store.batch_directory_hashes(str(row["id"]))) for row in batch_rows
        ]
        durations = [int(row["duration_ms"] or 0) for row in batch_rows if row["duration_ms"]]

    end_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    metrics = status["metrics"]
    report = {
        "fixture": args.fixture,
        "config": {
            "workers": args.workers,
            "packing_scope": args.packing_scope,
            "max_questions_per_request": args.max_questions,
            "max_request_bytes": args.max_request_bytes,
            "latency_ms": args.latency_ms,
            "max_concurrency": args.max_concurrency,
        },
        "inventory": {
            "files": prepared["observed_files"],
            "directories": prepared["directories"],
            "fixture_build_ms": fixture_ms,
        },
        "plan": {
            "batches": batches,
            "min_files_per_batch": min(members_per_batch) if members_per_batch else 0,
            "max_files_per_batch": max(members_per_batch) if members_per_batch else 0,
            "average_files_per_batch": round(
                sum(members_per_batch) / len(members_per_batch), 2
            )
            if members_per_batch
            else 0,
            "min_directories_per_batch": min(directories_per_batch)
            if directories_per_batch
            else 0,
            "max_directories_per_batch": max(directories_per_batch)
            if directories_per_batch
            else 0,
            "average_directories_per_batch": round(
                sum(directories_per_batch) / len(directories_per_batch), 2
            )
            if directories_per_batch
            else 0,
            "estimated_input_tokens": sum(int(row["input_tokens"]) for row in batch_rows),
        },
        "timing_ms": {
            "staging_ms": metrics.get("staging_ms", 0),
            "planning_ms": metrics.get("planning_ms", 0),
            "dispatch_wall_ms": metrics.get("dispatch_wall_ms", 0),
            "remote_request_ms_sum": metrics.get("remote_request_ms_sum", 0),
            "persistence_ms": metrics.get("persistence_ms", 0),
        },
        "throughput": {
            "completed_requests": metrics.get("completed_requests", 0),
            "retried_requests": metrics.get("retried_requests", 0),
            "reused_requests": metrics.get("reused_requests", 0),
            "gateway_calls": gateway.calls,
            "gateway_failures": gateway.failures,
            "achieved_peak_concurrency": max(gateway.peak_active, metrics.get("peak_in_flight", 0)),
            "request_latency_ms": percentiles(durations),
        },
        "status": outcome["status"],
        "coverage": {
            "total_observed": status["total_observed"],
            "assessed": status["assessed"],
            "pending": status["pending"],
            "failed": status["failed"],
            "reconciled": status["reconciled"],
        },
        "memory_kb": {"start": start_rss, "after_staging": stage_rss, "end": end_rss},
        "sql_statements": statements if args.sql_count else None,
    }
    return report


def print_report(report: Dict[str, Any]) -> None:
    print(f"fixture: {report['fixture']}  status: {report['status']}")
    inv = report["inventory"]
    print(
        f"inventory: {inv['files']} files / {inv['directories']} directories "
        f"(fixture {inv['fixture_build_ms']} ms)"
    )
    plan = report["plan"]
    print(
        f"plan: {plan['batches']} requests | files/request min {plan['min_files_per_batch']} "
        f"avg {plan['average_files_per_batch']} max {plan['max_files_per_batch']} | "
        f"directories/request avg {plan['average_directories_per_batch']}"
    )
    print(
        f"tokens: {plan['estimated_input_tokens']} estimated input tokens | "
        f"workers {report['config']['workers']} | scope {report['config']['packing_scope']}"
    )
    timing = report["timing_ms"]
    print(
        f"timing: staging {timing['staging_ms']} ms | planning {timing['planning_ms']} ms | "
        f"dispatch {timing['dispatch_wall_ms']} ms | persistence {timing['persistence_ms']} ms"
    )
    throughput = report["throughput"]
    latency = throughput["request_latency_ms"]
    print(
        f"throughput: {throughput['completed_requests']} requests, "
        f"peak concurrency {throughput['achieved_peak_concurrency']}, "
        f"retried {throughput['retried_requests']}, reused {throughput['reused_requests']}"
    )
    print(
        f"latency ms: p50 {latency['p50']} p95 {latency['p95']} p99 {latency['p99']}"
    )
    coverage = report["coverage"]
    print(
        f"coverage: assessed {coverage['assessed']}/{coverage['total_observed']} | "
        f"pending {coverage['pending']} | failed {coverage['failed']} | "
        f"reconciled {coverage['reconciled']}"
    )
    memory = report["memory_kb"]
    print(
        f"peak RSS: start {memory['start']} kB | after staging {memory['after_staging']} kB | "
        f"end {memory['end']} kB"
    )
    if report.get("sql_statements"):
        print(f"SQL statements: {report['sql_statements']}")


def _csv_ints(value: str) -> List[int]:
    return [int(part) for part in value.split(",") if part.strip()]


def _sweep_axis(value: str, default: int) -> List[int]:
    return _csv_ints(value) if value else [default]


def run_sweep(args: argparse.Namespace) -> List[Dict[str, Any]]:
    """Measure dispatch speed across worker counts, question caps, and scopes.

    Larger requests reduce request count but can raise per-request latency, so
    the fastest point is an empirical question. This reuses one inventory and
    runs the matrix against the in-process fake gateway; no live model is called.
    """
    root = Path(tempfile.mkdtemp(prefix="jev-sweep-"))
    database = root / "shrawler.db"
    counts = FIXTURES[args.fixture](args.files, args)
    scan_id = build_inventory(root, counts)
    workers_axis = _sweep_axis(args.sweep_workers, args.workers)
    questions_axis = _sweep_axis(args.sweep_questions, args.max_questions)
    scopes_axis = args.sweep_scopes.split(",") if args.sweep_scopes else [args.packing_scope]
    rows: List[Dict[str, Any]] = []
    for scope in scopes_axis:
        for workers in workers_axis:
            for max_questions in questions_axis:
                config = JevConfig.from_mapping(
                    {
                        "endpoint": "https://benchmark.invalid/v1/systemone",
                        "model": "jev-benchmark",
                        "workers": workers,
                        "rate_limit_per_minute": args.rate_limit,
                        "packing_scope": scope,
                        "max_questions_per_request": max_questions,
                        "max_request_bytes": args.max_request_bytes,
                    }
                )
                gateway = FakeGateway(
                    latency_seconds=args.latency_ms / 1000.0,
                    max_concurrency=args.max_concurrency,
                )
                # A fresh assessment database per combination: otherwise the
                # exact-request cache short-circuits later runs (the cache key
                # ignores worker count) and the sweep measures cache reuse, not
                # dispatch.
                jev_path = assessment_path(database)
                for suffix in ("", "-wal", "-shm"):
                    Path(str(jev_path) + suffix).unlink(missing_ok=True)
                with JevStore(database) as store:
                    runner = JevRunner(database, config, store, client=gateway)
                    prepared = runner.prepare(scan_id)
                    run_id = prepared["run_id"]
                    batches = runner.plan(run_id)
                    started = time.perf_counter()
                    outcome = runner.run(run_id, "sweep")
                    wall_ms = int((time.perf_counter() - started) * 1000)
                    status = runner.status(run_id)
                metrics = status["metrics"]
                files = int(prepared["observed_files"] or 0)
                rows.append(
                    {
                        "scope": scope,
                        "workers": workers,
                        "max_questions": max_questions,
                        "batches": batches,
                        "status": outcome["status"],
                        "dispatch_wall_ms": metrics.get("dispatch_wall_ms", wall_ms),
                        "requests": metrics.get("completed_requests", 0),
                        "reused": metrics.get("reused_requests", 0),
                        "peak_in_flight": metrics.get(
                            "peak_in_flight", gateway.peak_active
                        ),
                        "p95_ms": (status.get("latency_ms") or {}).get("p95"),
                        "files_per_second": round(
                            files / max(0.001, metrics.get("dispatch_wall_ms", wall_ms) / 1000.0),
                            2,
                        ),
                    }
                )
    return rows


def print_sweep(rows: List[Dict[str, Any]]) -> None:
    print(
        f"{'scope':>15} {'workers':>7} {'maxq':>5} {'reqs':>6} {'wall_ms':>8} "
        f"{'p95_ms':>7} {'conc':>5} {'files/s':>9} status"
    )
    for row in rows:
        print(
            f"{row['scope']:>15} {row['workers']:>7} {row['max_questions']:>5} "
            f"{row['batches']:>6} {row['dispatch_wall_ms']:>8} "
            f"{row['p95_ms']!s:>7} {row['peak_in_flight']:>5} "
            f"{row['files_per_second']:>9} {row['status']}"
        )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", choices=sorted(FIXTURES), default="captured")
    parser.add_argument("--files", type=int, default=0, help="override fixture size")
    parser.add_argument(
        "--files-per-directory",
        type=int,
        default=20,
        dest="files_per_directory",
        help="density fixture: files per directory (default 20)",
    )
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--rate-limit", type=int, default=0, dest="rate_limit")
    parser.add_argument("--latency-ms", type=int, default=150, dest="latency_ms")
    parser.add_argument("--max-concurrency", type=int, default=0, dest="max_concurrency")
    parser.add_argument(
        "--packing-scope", default="multi-directory", dest="packing_scope"
    )
    parser.add_argument("--max-questions", type=int, default=500, dest="max_questions")
    parser.add_argument("--max-request-bytes", type=int, default=0, dest="max_request_bytes")
    parser.add_argument(
        "--sweep-workers",
        default="",
        dest="sweep_workers",
        help="comma-separated worker counts to sweep, e.g. 1,2,4,8",
    )
    parser.add_argument(
        "--sweep-questions",
        default="",
        dest="sweep_questions",
        help="comma-separated max_questions_per_request values to sweep",
    )
    parser.add_argument(
        "--sweep-scopes",
        default="",
        dest="sweep_scopes",
        help="comma-separated packing scopes to sweep, e.g. directory,multi-directory",
    )
    parser.add_argument("--sql-count", action="store_true", dest="sql_count")
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)
    if args.files <= 0:
        args.files = {
            "wide": 100000,
            "many-tiny": 100000,
            "density": 1000000,
        }.get(args.fixture, 774)
    sweep = bool(args.sweep_workers or args.sweep_questions or args.sweep_scopes)
    if sweep:
        rows = run_sweep(args)
        if args.as_json:
            print(json.dumps(rows, indent=2, default=str))
        else:
            print_sweep(rows)
        return 0
    started = time.perf_counter()
    report = run_benchmark(args)
    report["wall_ms"] = int((time.perf_counter() - started) * 1000)
    if args.as_json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
