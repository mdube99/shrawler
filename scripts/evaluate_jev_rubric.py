#!/usr/bin/env python3
"""Evaluate the built-in Jev inspection-priority rubric against labeled cases.

This is a reusable live-endpoint evaluation, not a unit test. It loads a
labeled fixture of filename + directory-context cases, stages them as a
synthetic pinned inventory, and dispatches them through the real Jev pipeline
(``snapshot.stage`` -> ``planner.plan_run`` -> ``runner.run``) using the
endpoint and credentials configured in ``~/.config/shrawler/config.toml`` (or
``$XDG_CONFIG_HOME/shrawler/config.toml``). No file contents are supplied: the
cases exist to prove that unambiguous credential indicators reach level 4 from
filename and directory context alone.

The runner asserts that every ``credential`` case reaches level 4 and that no
``benign`` case reaches level 4. ``pii``, ``phi``, and ``financial`` cases are
secondary high-priority cases: their achieved labels and the endpoint's
per-file distributions are reported honestly but not asserted.

Examples::

    python scripts/evaluate_jev_rubric.py
    python scripts/evaluate_jev_rubric.py --json --save /tmp/jev_rubric_report.json
    # Iterate a candidate objective without editing the source of truth:
    python scripts/evaluate_jev_rubric.py --objective-file /tmp/candidate.txt
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, cast

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from shrawler.config import config_path, load_config  # noqa: E402
from shrawler.store import ScanStore  # noqa: E402
from shrawler.triage.jev.config import JevConfig, priority_score  # noqa: E402
from shrawler.triage.jev.runner import JevRunner  # noqa: E402
from shrawler.triage.jev.storage import JevStore  # noqa: E402

DEFAULT_CASES = Path(__file__).with_name("jev_rubric_cases.json")
CREDENTIAL = "credential"
BENIGN = "benign"
SECONDARY_CLASSES = ("pii", "phi", "financial")


def _metadata(host: str, share: str, remote_path: str, size: int) -> Dict[str, Any]:
    name = remote_path.replace("\\", "/").rsplit("/", 1)[-1]
    return {
        "host": host,
        "share": share,
        "file_name": name,
        "remote_path": remote_path,
        "unc_path": f"\\\\{host}\\{share}\\"
        + remote_path.lstrip("/").replace("/", "\\"),
        "size_bytes": size,
        "readable_size": f"{size}B",
        "mtime_utc": "2026-01-01T00:00:00+00:00",
        "scan_timestamp_utc": "2026-09-05T00:00:00+00:00",
    }


def load_cases(path: Path) -> Tuple[str, str, List[Dict[str, Any]]]:
    payload = cast(Dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    raw_cases = payload.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError(f"{path} does not contain a non-empty 'cases' list")
    entries = cast(List[Any], raw_cases)
    host = str(payload.get("host") or "server")
    share = str(payload.get("share") or "DATA")
    seen: set[str] = set()
    cases: List[Dict[str, Any]] = []
    for raw_entry in entries:
        if not isinstance(raw_entry, dict):
            raise ValueError(f"case is not an object: {raw_entry!r}")
        entry = cast(Dict[str, Any], raw_entry)
        case: Dict[str, Any] = {str(key): value for key, value in entry.items()}
        for field in ("id", "class", "file_name", "remote_path"):
            if not case.get(field):
                raise ValueError(f"case is missing {field!r}: {case!r}")
        case_id = str(case["id"])
        if case_id in seen:
            raise ValueError(f"duplicate case id: {case_id}")
        seen.add(case_id)
        cases.append(case)
    return host, share, cases


def build_scan(root: Path, host: str, share: str, cases: List[Dict[str, Any]]) -> str:
    store = ScanStore(root, "spider", "DOMAIN", "jev-rubric-eval")
    store.upsert_host(host, host, "complete")
    store.upsert_share(host, share, "complete", {})
    for index, case in enumerate(cases):
        payload = _metadata(
            host, share, str(case["remote_path"]), 256 + (index * 97) % 4096
        )
        store.add_file(host, share, payload)
    store.finish("completed", {})
    identifier = store.scan_id
    store.close()
    return identifier


def resolve_config(objective_file: Optional[Path], workers: Optional[int]) -> JevConfig:
    raw_section = load_config().get("jev", {})
    if raw_section and not isinstance(raw_section, dict):
        raise ValueError("configuration field [jev] must be a table")
    section: Dict[str, Any] = (
        cast(Dict[str, Any], raw_section) if isinstance(raw_section, dict) else {}
    )
    values: Dict[str, Any] = dict(section)
    if objective_file is not None:
        values["objective"] = objective_file.read_text(encoding="utf-8")
    if workers is not None:
        values["workers"] = workers
    config = JevConfig.from_mapping(values)
    if not config.resolved_api_key():
        raise SystemExit(
            f"No Jev API key found. Set {config.api_key_env} or [jev] api_key in "
            f"{config_path()}."
        )
    return config


def collect_results(
    store: JevStore, run_id: str, cases: List[Dict[str, Any]]
) -> Dict[str, Dict[str, Any]]:
    rows = store.connection.execute(
        "SELECT f.remote_path, f.file_name, f.status, "
        "r.choice, r.distribution_json, r.model "
        "FROM assessment_files f LEFT JOIN decision_results r ON r.id=f.result_id "
        "WHERE f.run_id=?",
        (run_id,),
    ).fetchall()
    by_path = {str(row["remote_path"]): dict(row) for row in rows}
    results: Dict[str, Dict[str, Any]] = {}
    for case in cases:
        row = by_path.get(str(case["remote_path"]), {})
        distribution = None
        if row.get("distribution_json"):
            try:
                distribution = json.loads(row["distribution_json"])
            except (TypeError, ValueError):
                distribution = row["distribution_json"]
        results[str(case["id"])] = {
            "file_name": case["file_name"],
            "remote_path": case["remote_path"],
            "class": case["class"],
            "note": case.get("note", ""),
            "file_status": row.get("status"),
            "choice": row.get("choice"),
            "priority": priority_score(row.get("choice")),
            "distribution": distribution,
            "model": row.get("model"),
        }
    return results


def evaluate(
    results: Dict[str, Dict[str, Any]], cases: List[Dict[str, Any]]
) -> Dict[str, Any]:
    credential = [case for case in cases if case["class"] == CREDENTIAL]
    benign = [case for case in cases if case["class"] == BENIGN]
    secondary = [case for case in cases if case["class"] in SECONDARY_CLASSES]
    credential_failures = [
        case["id"] for case in credential if results[case["id"]]["priority"] != 4
    ]
    benign_failures = [
        case["id"] for case in benign if results[case["id"]]["priority"] >= 4
    ]
    class_distributions: Dict[str, Dict[str, int]] = {}
    for case in cases:
        bucket = class_distributions.setdefault(case["class"], {})
        label = results[case["id"]]["choice"]
        bucket[str(label)] = bucket.get(str(label), 0) + 1
    return {
        "credential_total": len(credential),
        "credential_at_4": len(credential) - len(credential_failures),
        "credential_failures": credential_failures,
        "benign_total": len(benign),
        "benign_failures": benign_failures,
        "secondary_total": len(secondary),
        "class_distributions": class_distributions,
        "passed": not credential_failures and not benign_failures,
    }


def _format_distribution(distribution: Any) -> str:
    if not isinstance(distribution, dict):
        return "-"
    dist = cast(Dict[str, Any], distribution)
    return " ".join(f"{key}={dist[key]}" for key in sorted(dist))


def print_report(report: Dict[str, Any]) -> None:
    print(f"Cases:       {report['cases_path']}")
    print(f"Endpoint:    {report['endpoint']}")
    print(f"Model:       {report['model']} (revision {report['deployment_revision']})")
    print(f"Objective:   {report['objective_source']}")
    print(
        f"Coverage:    assessed {report['coverage']['assessed']}/"
        f"{report['coverage']['total_observed']} | pending "
        f"{report['coverage']['pending']} | failed {report['coverage']['failed']} | "
        f"reconciled {report['coverage']['reconciled']}"
    )
    print("")
    print("CREDENTIAL INDICATORS (must be 4):")
    for item in report["results"]:
        if item["class"] != CREDENTIAL:
            continue
        mark = "ok" if item["priority"] == 4 else "FAIL"
        print(
            f"  [{mark:>4}] {item['priority']} {item['file_name']}  "
            f"({item['remote_path']})  dist: {_format_distribution(item['distribution'])}"
        )
    print("")
    print("BENIGN CONTROLS (must be < 4):")
    for item in report["results"]:
        if item["class"] != BENIGN:
            continue
        mark = "ok" if item["priority"] < 4 else "FAIL"
        print(
            f"  [{mark:>4}] {item['priority']} {item['file_name']}  "
            f"({item['remote_path']})  dist: {_format_distribution(item['distribution'])}"
        )
    print("")
    print("SECONDARY HIGH-PRIORITY (reported, not asserted):")
    for item in report["results"]:
        if item["class"] not in SECONDARY_CLASSES:
            continue
        print(
            f"  [{item['class']:>9}] {item['priority']} {item['file_name']}  "
            f"({item['remote_path']})  dist: {_format_distribution(item['distribution'])}"
        )
    print("")
    print("Observed label distribution by class:")
    for name in sorted(report["class_distributions"]):
        print(f"  {name:>9}: {report['class_distributions'][name]}")
    print("")
    verdict = "PASS" if report["passed"] else "FAIL"
    print(
        f"{verdict}: credential at 4 "
        f"{report['credential_at_4']}/{report['credential_total']} | "
        f"benign at 4 {len(report['benign_failures'])}"
    )
    if report["credential_failures"]:
        print(f"  credential cases below 4: {sorted(report['credential_failures'])}")
    if report["benign_failures"]:
        print(f"  benign cases at 4: {sorted(report['benign_failures'])}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cases",
        type=Path,
        default=DEFAULT_CASES,
        help="labeled fixture JSON (default: scripts/jev_rubric_cases.json)",
    )
    parser.add_argument(
        "--objective-file",
        type=Path,
        default=None,
        help="override the configured objective with this file (candidate iteration)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="override the configured worker count",
    )
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    parser.add_argument(
        "--save",
        type=Path,
        default=None,
        help="also write the full JSON report to this path",
    )
    args = parser.parse_args(argv)

    host, share, cases = load_cases(args.cases)
    config = resolve_config(args.objective_file, args.workers)
    root = Path(tempfile.mkdtemp(prefix="jev-rubric-eval-"))
    database = root / "shrawler.db"
    scan_id = build_scan(root, host, share, cases)

    with JevStore(database) as store:
        runner = JevRunner(database, config, store)
        prepared = runner.prepare(scan_id)
        run_id = prepared["run_id"]
        batches = runner.plan(run_id)
        outcome = runner.run(run_id, "jev-rubric-eval")
        status = runner.status(run_id)
        results = collect_results(store, run_id, cases)

    verdict = evaluate(results, cases)
    configured_model = config.model
    observed_models = {item["model"] for item in results.values() if item["model"]}
    report = {
        "cases_path": str(args.cases),
        "database": str(database),
        "run_id": run_id,
        "status": outcome["status"],
        "batches": batches,
        "endpoint": config.endpoint,
        "model": ", ".join(sorted(observed_models))
        if observed_models
        else configured_model,
        "deployment_revision": config.deployment_revision or config.model,
        "objective_source": (
            str(args.objective_file)
            if args.objective_file is not None
            else "built-in DEFAULT_OBJECTIVE"
        ),
        "coverage": {
            "total_observed": status["total_observed"],
            "assessed": status["assessed"],
            "pending": status["pending"],
            "failed": status["failed"],
            "reconciled": status["reconciled"],
        },
        "results": [results[case["id"]] for case in cases],
        **verdict,
    }
    if args.save is not None:
        args.save.write_text(
            json.dumps(report, indent=2, default=str), encoding="utf-8"
        )
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print_report(report)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
