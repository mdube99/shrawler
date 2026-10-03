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
from .config import REVIEW_LABELS, JevConfig
from .planner import TokenCounter
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
    print(
        f"directories: {payload['directories']} | batches {payload['batches']['completed']}"
        f"/{payload['batches']['total']} completed"
    )


def _print_list(payload: Dict[str, Any]) -> None:
    print(f"Run {payload['run_id']} | scan {payload['scan_id']}")
    print("LABEL       FILE ID                   UNC PATH")
    for item in payload["items"]:
        print(
            f"{item['choice']:<10}  {item['file_id']}  "
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
    listing.add_argument("--label", choices=REVIEW_LABELS)
    listing.add_argument("--directory", type=int)
    listing.add_argument("--limit", type=int, default=100)
    listing.add_argument("--offset", type=int, default=0)
    listing.add_argument("--missed", action="store_true", help="high value missed by rules")

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
    examples: List[Dict[str, Any]] = []
    total = 0
    for row in store.context_rows(run_id):
        context = json.loads(row["context_json"])
        candidates = [
            dict(item)
            for item in store.connection.execute(
                "SELECT file_id,file_name,size_bytes,mtime_utc FROM assessment_files "
                "WHERE run_id=? AND directory_id=? AND status='pending' ORDER BY file_id LIMIT 3",
                (run_id, row["directory_id"]),
            )
        ]
        if not candidates:
            continue
        from .planner import question_for, state_text

        state = state_text({**context, "objective": config.objective}, candidates)
        total += len(
            store.connection.execute(
                "SELECT 1 FROM assessment_files WHERE run_id=? AND directory_id=? "
                "AND status='pending'",
                (run_id, row["directory_id"]),
            ).fetchall()
        )
        if len(examples) < limit:
            questions = {
                item["file_id"]: question_for(item["file_id"], config) for item in candidates
            }
            examples.append(
                {
                    "directory": context["directory"],
                    "state": state,
                    "questions": questions,
                    "estimated_input_tokens": counter.count(state)
                    + sum(counter.count(json.dumps(q, sort_keys=True)) for q in questions.values()),
                }
            )
    payload = {
        "run_id": run_id,
        "pending_candidates": total,
        "examples": examples,
        "note": "Preview examples are illustrative; inference scope is every observed file.",
    }
    if as_json:
        print(json.dumps(payload, ensure_ascii=True, default=str))
    else:
        print(f"Pending candidates: {total} (all will be assessed)")
        for example in examples:
            print(
                f"\n--- {example['directory']} (~{example['estimated_input_tokens']} input tokens)"
            )
            print(example["state"])
