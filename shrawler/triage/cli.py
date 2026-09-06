"""Offline CLI for scoring, reviewing and explaining saved inventory metadata."""

import argparse
import json
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..output import escape_terminal
from .rules import load
from .storage import explain, list_results, rank


def _rule_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--rules",
        type=Path,
        action="append",
        help="additional TOML file/directory; repeat to combine",
    )
    parser.add_argument(
        "--no-builtins", action="store_true", help="use only supplied rules"
    )
    parser.add_argument(
        "--scan", help="full or short scan ID; default: latest completed inventory scan"
    )


def _print_list(result: Dict[str, Any]) -> None:
    print(
        f"Run {result['run_id']} | Scan {result['scan_id']} | {result['files_scored']} files scored"
    )
    summary = result.get("summary", {})
    if "positive_files" in summary:
        print(f"Files with positive priority: {summary['positive_files']}")
    print("SCORE  FILE ID                   UNC PATH")
    for item in result["items"]:
        print(
            f"{item['review_score']:5}  {item['file_id']}  {escape_terminal(item['unc_path'])}"
        )
    print(
        "Priority is metadata-based review order, not a probability or confirmed finding."
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="shrawler triage",
        description="Rank saved file metadata offline; no SMB credentials or remote access.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="persist a new ranking run")
    run.add_argument("database", type=Path)
    _rule_options(run)
    listing = commands.add_parser("list", help="show ranked candidates")
    listing.add_argument("database", type=Path)
    listing.add_argument(
        "--run", dest="run_id", help="ranking run ID; default: latest completed"
    )
    listing.add_argument("--category")
    listing.add_argument("--limit", type=int, default=100)
    listing.add_argument("--min-score", type=int, default=0)
    explanation = commands.add_parser(
        "explain", help="show evidence and failed rule conditions"
    )
    explanation.add_argument("database", type=Path)
    explanation.add_argument(
        "file_id",
        help="opaque file ID; put -- before it to handle IDs starting with a hyphen",
    )
    explanation.add_argument("--run", dest="run_id")
    rules = commands.add_parser(
        "rules", help="preview rules without saving ranking results"
    )
    actions = rules.add_subparsers(dest="action", required=True)
    test = actions.add_parser(
        "test", help="evaluate a candidate ruleset in temporary local storage"
    )
    test.add_argument("database", type=Path)
    test.add_argument("candidate", type=Path)
    _rule_options(test)
    test.add_argument("--limit", type=int, default=20)
    for command in (run, listing, explanation, test):
        command.add_argument(
            "--json", action="store_true", help="machine-readable output"
        )
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            result = rank(
                args.database,
                load(args.rules, not args.no_builtins),
                args.scan,
                on_phase=lambda phase, count: print(
                    f"{phase}: {count} files", file=sys.stderr
                ),
            )
            if args.json:
                print(json.dumps(result, ensure_ascii=True))
            else:
                print(f"Scored {result['files_scored']} files. Run: {result['run_id']}")
                print(f"Scan: {result['scan_id']} ({result['scan_status']})")
                print(f"Saved: {escape_terminal(result['results_database'])}")
        elif args.command == "list":
            result = list_results(
                args.database, args.run_id, args.category, args.limit, args.min_score
            )
            if args.json:
                print(json.dumps(result, ensure_ascii=True))
            else:
                _print_list(result)
        elif args.command == "explain":
            # JSON escapes untrusted filenames and makes nested evidence readable.
            print(
                json.dumps(
                    explain(args.database, args.file_id, args.run_id),
                    indent=None if args.json else 2,
                    ensure_ascii=True,
                )
            )
        else:
            if not 1 <= args.limit <= 10000:
                raise ValueError("limit must be 1..10000")
            ruleset = load([*(args.rules or []), args.candidate], not args.no_builtins)
            with tempfile.TemporaryDirectory(prefix="shrawler-triage-") as tmp:
                destination = Path(tmp) / "preview.db"
                summary = rank(args.database, ruleset, args.scan, destination)
                result = list_results(
                    args.database,
                    summary["run_id"],
                    limit=args.limit,
                    output=destination,
                )
                if args.json:
                    print(json.dumps(result, ensure_ascii=True))
                else:
                    _print_list(result)
                    print("Preview only; no ranking results were retained.")
        return 0
    except KeyboardInterrupt:
        print("Triage interrupted.", file=sys.stderr)
        return 130
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(f"Triage error: {escape_terminal(str(exc))}", file=sys.stderr)
        return 1
