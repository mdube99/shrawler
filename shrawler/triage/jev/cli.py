"""CLI for the model-assisted Jev assessment path.

Commands stage a durable ledger and context (``prepare``), show the exact
planned work (``preview``), dispatch resumable inference (``run``), and report
or browse results (``status``, ``list``, ``check``).
"""

import argparse
import json
import socket
import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from ...output import escape_terminal
from ..rules import load
from .client import JevClient
from .config import PRIORITY_LEVELS, JevConfig
from .planner import TokenCounter, plan_run
from .runner import JevRunner
from .storage import JevStore, RunBusyError
from .views import coverage_by_directory, highlight_missed, list_assessed


def _config_from_file() -> JevConfig:
    from ...config import load_config

    section = load_config().get("jev", {})
    if section and not isinstance(section, dict):
        raise ValueError("configuration field [jev] must be a table")
    return JevConfig.from_mapping(section)


def _owner() -> str:
    return f"{socket.gethostname()}:{__import__('os').getpid()}"


def _print_status(payload: Dict[str, Any]) -> None:
    print(
        f"Run {payload['run_id']} | scan {payload['scan_id']} | {payload['status']}"
    )
    print(
        f"observed {payload['total_observed']} | assessed {payload['assessed']} | "
        f"in-flight {payload['in_flight']} | pending {payload['pending']} | "
        f"failed {payload['failed']}"
    )
    reconciled = "yes" if payload["reconciled"] else "NO"
    print(f"coverage reconciled: {reconciled}")
    batches = payload["batches"]
    print(
        f"directories: {payload['directories']} | batches "
        f"{batches['completed']}/{batches['total']} completed | "
        f"active {batches.get('active', 0)} | pending {batches.get('pending', 0)} | "
        f"failed {batches.get('failed', 0)}"
    )
    print(
        f"packing: {payload.get('packing_scope', 'multi-directory')} | "
        f"workers: {payload.get('workers', '?')}"
    )
    metrics = payload.get("metrics") or {}
    if metrics:
        print(
            "timing: "
            f"staging {metrics.get('staging_ms', 0)}ms | "
            f"planning {metrics.get('planning_ms', 0)}ms | "
            f"dispatch {metrics.get('dispatch_wall_ms', 0)}ms | "
            f"requests {metrics.get('completed_requests', 0)}"
        )
        if metrics.get("remote_request_ms_sum"):
            print(
                f"remote request time: {metrics['remote_request_ms_sum']}ms | "
                f"peak in-flight: {metrics.get('peak_in_flight', 0)} | "
                f"retried {metrics.get('retried_requests', 0)} | "
                f"cache-reused {metrics.get('reused_requests', 0)}"
            )
    latency = payload.get("latency_ms") or {}
    if latency.get("p50") is not None:
        print(
            f"request latency: p50 {latency['p50']}ms | p95 {latency.get('p95')}ms "
            f"(n={latency.get('count', 0)})"
        )
    usage = payload.get("usage") or {}
    if usage.get("billed_input_tokens"):
        price = usage.get("input_price_per_million_tokens", 0.042)
        print(
            f"billed input tokens: {usage['billed_input_tokens']} "
            f"({usage.get('tokens_per_file', 0)}/file, "
            f"{usage.get('files_per_request', 0)} files/request) | "
            f"est cost ${usage.get('estimated_cost_usd', 0)} @ ${price}/M"
        )


def _print_list(payload: Dict[str, Any]) -> None:
    print(f"Run {payload['run_id']} | scan {payload['scan_id']}")
    print("PRIORITY    FILE ID                   UNC PATH")
    for item in payload["items"]:
        label = f"{item['priority']} {item['priority_name']}".strip()
        print(
            f"{label:<10}  {item['file_id']}  "
            f"{escape_terminal(item['unc_path'])}"
        )
    print(payload["note"])


def _load(database: Path) -> JevStore:
    return JevStore(database)


def _runner(database: Path, store: JevStore, config: JevConfig) -> JevRunner:
    return JevRunner(database, config, store)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="shrawler triage jev",
        description="Model-assisted full-coverage file assessment over a saved inventory.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    check = commands.add_parser("check", help="probe gateway capabilities and routing")
    check.add_argument("database", type=Path)

    prepare = commands.add_parser("prepare", help="stage the ledger and directory context")
    prepare.add_argument("database", type=Path)
    prepare.add_argument("--scan")
    prepare.add_argument("--rules", type=Path, action="append")
    prepare.add_argument("--no-builtins", action="store_true")

    preview = commands.add_parser("preview", help="show planned work without dispatching")
    preview.add_argument("database", type=Path)
    preview.add_argument("--run", dest="run_id")
    preview.add_argument("--limit", type=int, default=3, help="payload examples to show")

    run = commands.add_parser("run", help="dispatch planned batches (resumable)")
    run.add_argument("database", type=Path)
    run.add_argument("--run", dest="run_id")
    run.add_argument("--budget", type=int, default=None, help="seconds; 0 uses config")

    status = commands.add_parser("status", help="coverage, errors, and batch progress")
    status.add_argument("database", type=Path)
    status.add_argument("--run", dest="run_id")
    status.add_argument("--by-directory", action="store_true")

    listing = commands.add_parser("list", help="model-assisted analyst view")
    listing.add_argument("database", type=Path)
    listing.add_argument("--run", dest="run_id")
    listing.add_argument("--label", choices=PRIORITY_LEVELS)
    listing.add_argument("--directory", type=int)
    listing.add_argument("--limit", type=int, default=100)
    listing.add_argument("--offset", type=int, default=0)
    listing.add_argument(
        "--missed",
        action="store_true",
        help="priority at/above the rule-expansion threshold missed by rules",
    )

    for command in (check, prepare, preview, run, status, listing):
        command.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    try:
        config = _config_from_file()
        if args.command == "check":
            client = JevClient(config)
            report = client.probe()
            report["configured"] = config.provenance()
            _emit(report, args.json, _print_check)
            return 0
        if args.command == "prepare" and not args.scan:
            pass
        if args.command == "prepare":
            with _load(args.database) as store:
                runner = _runner(args.database, store, config)
                rules = load(args.rules, not args.no_builtins)
                result = runner.prepare(args.scan, rules)
                _emit(result, args.json, lambda payload: _print_prepare(payload, store, result["run_id"], config))
            return 0
        with _load(args.database) as store:
            run_id = str(store.select_run(args.run_id)["id"])
            if args.command == "preview":
                _preview(store, run_id, config, args.limit, args.json)
                return 0
            if args.command == "run":
                budget = args.budget
                if budget == 0:
                    budget = config.time_budget_seconds
                runner = _runner(args.database, store, config)
                planned = runner.plan(run_id)
                result = runner.run(run_id, _owner(), budget_seconds=budget)
                result["planned_batches"] = planned
                _emit(result, args.json, lambda payload: _print_run(payload))
                return 0
            if args.command == "status":
                runner = _runner(args.database, store, config)
                payload = runner.status(run_id)
                if args.by_directory:
                    payload = {**payload, "directories": coverage_by_directory(store, run_id)}
                _emit(payload, args.json, _print_status)
                return 0
            if args.missed:
                payload = highlight_missed(store, run_id, args.limit)
            else:
                payload = list_assessed(
                    store, run_id, args.label, args.directory, args.limit, args.offset
                )
            _emit(payload, args.json, _print_list)
            return 0
    except KeyboardInterrupt:
        print("Jev assessment interrupted.", file=sys.stderr)
        return 130
    except RunBusyError as exc:
        print(f"Jev busy: {escape_terminal(str(exc))}", file=sys.stderr)
        return 1
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(f"Jev error: {escape_terminal(str(exc))}", file=sys.stderr)
        return 1


def _emit(payload: Any, as_json: bool, printer: Any) -> None:
    if as_json:
        print(json.dumps(payload, ensure_ascii=True, default=str))
    else:
        printer(payload)


def _print_check(payload: Dict[str, Any]) -> None:
    print(f"Endpoint: {payload.get('endpoint')}")
    if not payload.get("reachable"):
        print(f"Unreachable: {payload.get('error')}")
        return
    print(f"HTTP {payload.get('http_status')} in {payload.get('latency_ms')} ms")
    print(f"Resolved model: {payload.get('resolved_model')}")
    print(
        f"answers: {payload.get('returns_answers')} | usage: {payload.get('returns_usage')}"
    )


def _print_prepare(
    payload: Dict[str, Any], store: JevStore, run_id: str, config: JevConfig
) -> None:
    print(
        f"Staged {payload['observed_files']} files across {payload['directories']} directories"
    )
    print(f"Run: {run_id}")
    print(f"Scan: {payload['scan_id']} ({payload['scan_status']})")
    print(f"Assessment database: {escape_terminal(str(store.path))}")


def _print_run(payload: Dict[str, Any]) -> None:
    print(
        f"Run {payload['run_id']} | {payload['status']} | "
        f"planned batches: {payload.get('planned_batches')}"
    )
    counts = payload.get("counts", {})
    print(" | ".join(f"{key}={value}" for key, value in sorted(counts.items())))


def _preview(
    store: JevStore, run_id: str, config: JevConfig, limit: int, as_json: bool
) -> None:
    counter = TokenCounter(JevClient(config), config)
    pending = store.status_counts(run_id).get("pending", 0)
    if pending:
        # Dry-run the exact global planner without persisting or dispatching.
        result = plan_run(
            store,
            run_id,
            config,
            counter,
            config.objective,
            persist=False,
            preview_limit=limit,
        )
        summary = result.summary(limit=limit)
    else:
        planned = store.planned_batch_stats(run_id)
        summary = {
            "planned_batches": planned["batches"],
            "pending_candidates": planned["candidates"],
            "estimated_input_tokens": planned["input_tokens"],
            "min_candidates_per_request": planned["min_candidates"],
            "max_candidates_per_request": planned["max_candidates"],
            "average_candidates_per_request": planned["average_candidates"],
            "min_directories_per_request": planned["min_directories"],
            "max_directories_per_request": planned["max_directories"],
            "average_directories_per_request": planned["average_directories"],
            "examples": [],
        }
    workers = max(1, config.workers)
    planned_batches = int(summary.get("planned_batches", 0))
    payload = {
        "run_id": run_id,
        "packing_scope": config.packing_scope,
        "workers": workers,
        "estimated_request_waves": -(-planned_batches // workers),
        **summary,
        "note": "Preview examples are illustrative; inference scope is every observed file.",
    }
    if as_json:
        print(json.dumps(payload, ensure_ascii=True, default=str))
    else:
        _print_preview(payload)


def _print_preview(payload: Dict[str, Any]) -> None:
    print(
        f"Pending candidates: {payload.get('pending_candidates', 0)} "
        f"across {payload.get('planned_batches', 0)} planned requests "
        f"(packing {payload.get('packing_scope')}, {payload.get('workers')} workers)"
    )
    print(
        f"requests: min {payload.get('min_candidates_per_request', 0)} / "
        f"avg {payload.get('average_candidates_per_request', 0)} / "
        f"max {payload.get('max_candidates_per_request', 0)} candidates; "
        f"directories min {payload.get('min_directories_per_request', 0)} / "
        f"avg {payload.get('average_directories_per_request', 0)} / "
        f"max {payload.get('max_directories_per_request', 0)}"
    )
    print(
        f"estimated input tokens: {payload.get('estimated_input_tokens', 0)} | "
        f"estimated bytes: {payload.get('estimated_request_bytes', 0)} | "
        f"request waves: {payload.get('estimated_request_waves', 0)}"
    )
    for example in payload.get("examples", []):
        print(
            f"\n--- example request "
            f"(~{example.get('estimated_input_tokens', 0)} input tokens)"
        )
        print(example["state"])
