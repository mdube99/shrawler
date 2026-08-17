"""Saved-result reporting and Nemesis recovery workflows."""

import argparse
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests
import urllib3

from .core import convert_unc_to_nemesis_path


def _iter_downloads(results: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    for host, host_result in results.items():
        if host.startswith("_") or not isinstance(host_result, dict):
            continue
        for share in host_result.get("shares", {}).values():
            yield from share.get("downloaded_files", [])


def _resolve_local_path(results_path: Path, entry: Dict[str, Any]) -> Path:
    recorded = Path(str(entry.get("local_path", "")))
    if recorded.is_file():
        return recorded
    fallback = results_path.parent / "downloads" / str(entry["local_filename"])
    return fallback


def _upload_file(
    entry: Dict[str, Any],
    local_path: Path,
    url: str,
    auth: str,
    project: str,
) -> Dict[str, Any]:
    username, password = auth.split(":", 1)
    current_time = datetime.now(timezone.utc)
    metadata = {
        "agent_id": "shrawler",
        "source": f"host://{entry['host']}",
        "project": project,
        "timestamp": current_time.isoformat(),
        "expiration": (current_time + timedelta(days=365)).isoformat(),
        "path": convert_unc_to_nemesis_path(str(entry["unc_path"])),
        "modification_time": datetime.fromtimestamp(
            float(entry.get("mtime_epoch", 0)), timezone.utc
        ).isoformat(),
    }
    try:
        with local_path.open("rb") as file_data:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            response = requests.post(
                f"{url.rstrip('/')}/files",
                files={
                    "file": (
                        local_path.name,
                        file_data,
                        "application/octet-stream",
                    ),
                    "metadata": (None, json.dumps(metadata), "application/json"),
                },
                auth=(username, password),
                verify=False,
                timeout=30,
            )
        if response.status_code not in {200, 201}:
            return {"success": False, "response_id": None, "error": f"HTTP {response.status_code}"}
        try:
            response_id = response.json().get("id")
        except (json.JSONDecodeError, AttributeError):
            response_id = None
        return {"success": True, "response_id": response_id, "error": None}
    except (OSError, requests.RequestException) as exc:
        return {"success": False, "response_id": None, "error": str(exc)}


def _retry_entry(
    entry: Dict[str, Any],
    results_path: Path,
    url: str,
    auth: str,
    project: str,
    retries: int,
) -> Tuple[bool, str]:
    state = entry.setdefault("nemesis", {})
    local_path = _resolve_local_path(results_path, entry)
    if not local_path.is_file():
        state.update(
            {
                "status": "failed",
                "last_error": f"Local file not found: {local_path}",
            }
        )
        return False, str(entry.get("unc_path", local_path))

    for attempt in range(1, retries + 2):
        state.update({"status": "uploading", "attempts": attempt})
        result = _upload_file(entry, local_path, url, auth, project)
        if result["success"]:
            state.update(
                {
                    "status": "uploaded",
                    "response_id": result["response_id"],
                    "last_error": None,
                }
            )
            return True, str(entry.get("unc_path", local_path))
        state.update({"last_error": result["error"]})
        if attempt <= retries:
            time.sleep(2 ** (attempt - 1))

    state["status"] = "failed"
    return False, str(entry.get("unc_path", local_path))


def _write_results(path: Path, results: Dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("w") as output_file:
        json.dump(results, output_file, indent=4)
        output_file.flush()
        os.fsync(output_file.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _print_summary(results: Dict[str, Any]) -> None:
    summary = results.get("_summary", {})
    downloads = list(_iter_downloads(results))
    statuses: Dict[str, int] = {}
    for entry in downloads:
        status = str(entry.get("nemesis", {}).get("status", "unknown"))
        statuses[status] = statuses.get(status, 0) + 1

    print(f"Hosts attempted: {summary.get('hosts_attempted', 'unknown')}")
    print(f"Shares enumerated: {summary.get('shares_enumerated', 'unknown')}")
    print(f"Files seen: {summary.get('files_seen', 'unknown')}")
    print(f"Files downloaded: {len(downloads)}")
    if statuses:
        formatted = ", ".join(f"{key}={value}" for key, value in sorted(statuses.items()))
        print(f"Nemesis: {formatted}")


def main(argv: Optional[List[str]] = None) -> int:
    """Run the saved-result report workflow."""
    parser = argparse.ArgumentParser(prog="shrawler report")
    parser.add_argument("results", type=Path, help="Path to shrawler_results.json")
    parser.add_argument(
        "--retry-failed",
        action="store_true",
        help="Retry failed or interrupted Nemesis uploads",
    )
    parser.add_argument("--nemesis-url", default=os.getenv("NEMESIS_URL"))
    parser.add_argument("--nemesis-auth", default=os.getenv("NEMESIS_AUTH"))
    parser.add_argument("--nemesis-project", default=os.getenv("NEMESIS_PROJECT"))
    parser.add_argument("--nemesis-upload-workers", type=int, default=2)
    parser.add_argument("--nemesis-retries", type=int, default=2)
    args = parser.parse_args(argv)

    if not args.results.is_file():
        parser.error(f"Results file not found: {args.results}")
    if args.nemesis_upload_workers < 1 or args.nemesis_retries < 0:
        parser.error("Upload workers must be positive and retries cannot be negative")

    with args.results.open() as source:
        results = json.load(source)
    if not isinstance(results, dict):
        parser.error("Results file must contain a JSON object")

    retry_failures = 0
    if args.retry_failed:
        missing = [
            name
            for name, value in (
                ("--nemesis-url", args.nemesis_url),
                ("--nemesis-auth", args.nemesis_auth),
                ("--nemesis-project", args.nemesis_project),
            )
            if not value
        ]
        if missing:
            parser.error("Retry requires " + ", ".join(missing))
        if ":" not in args.nemesis_auth:
            parser.error("--nemesis-auth must use username:password format")

        retryable = [
            entry
            for entry in _iter_downloads(results)
            if entry.get("nemesis", {}).get("status")
            in {"failed", "queued", "uploading"}
        ]
        with ThreadPoolExecutor(max_workers=args.nemesis_upload_workers) as executor:
            futures = [
                executor.submit(
                    _retry_entry,
                    entry,
                    args.results,
                    args.nemesis_url,
                    args.nemesis_auth,
                    args.nemesis_project,
                    args.nemesis_retries,
                )
                for entry in retryable
            ]
            completed = [future.result() for future in as_completed(futures)]
        nemesis_summary = results.setdefault("_summary", {}).setdefault(
            "nemesis", {}
        )
        all_downloads = list(_iter_downloads(results))
        nemesis_summary.update(
            {
                "uploaded": sum(
                    item.get("nemesis", {}).get("status") == "uploaded"
                    for item in all_downloads
                ),
                "failed": sum(
                    item.get("nemesis", {}).get("status") == "failed"
                    for item in all_downloads
                ),
            }
        )
        _write_results(args.results, results)
        successes = sum(success for success, _ in completed)
        retry_failures = len(completed) - successes
        print(f"Nemesis retry: {successes} uploaded, {retry_failures} failed")

    _print_summary(results)
    return 1 if retry_failures else 0


__all__ = ["main"]
