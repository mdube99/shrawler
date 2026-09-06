"""Create a local Shrawler fixture for exercising triage and coverage.

Usage:
    .venv/bin/python scripts/create_test_workspace.py

The generated workspace is intentionally synthetic and never contacts SMB.
Run with ``--output PATH`` to choose another directory. Existing output is
refused so a real workspace cannot be overwritten accidentally.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from shrawler.collection import CollectionQueue
from shrawler.coverage import SavedEntry
from shrawler.store import ScanStore
from shrawler.triage.review import ReviewStore
from shrawler.triage.rules import load
from shrawler.triage.storage import rank


def metadata(host: str, share: str, path: str, size: int = 128) -> dict[str, Any]:
    name = path.rsplit("/", 1)[-1]
    now = datetime.now(timezone.utc).isoformat()
    windows_path = path.lstrip("/").replace("/", "\\")
    return {
        "file_name": name,
        "remote_path": path,
        "unc_path": f"\\\\{host}\\{share}\\{windows_path}",
        "size_bytes": size,
        "readable_size": f"{size}B",
        "mtime_utc": now,
        "scan_timestamp_utc": now,
    }


def add_inventory(store: ScanStore, host: str, share: str) -> None:
    store.upsert_host(host, host, "complete")
    store.upsert_share(host, share, "complete", {"unc_path": f"\\\\{host}\\{share}"})
    files = [
        ("/Deployments/Orion/appsettings.production.json", 640),
        ("/Deployments/Orion/web.config", 480),
        ("/Deployments/Orion/deploy.ps1", 256),
        ("/Finance/payroll-2025.xlsx", 2048),
        ("/Finance/invoices-2025.csv", 1024),
        ("/Customers/customer-export.csv", 4096),
        ("/Reports/report-2024-01.csv", 512),
        ("/Reports/report-2024-02.csv", 512),
        ("/Reports/report-2024-03.csv", 512),
        ("/Reports/passwords.kdbx", 8192),
        ("/Public/readme.txt", 32),
    ]
    for path, size in files:
        store.add_file(host, share, metadata(host, share, path, size))


def add_coverage(store: ScanStore, host: str, share: str) -> None:
    store.upsert_host(host, host, "scanning")
    store.upsert_share(host, share, "scanning", {})
    store.coverage.scope(
        {
            "identity": "LAB\\analyst",
            "scope": "selected shares",
            "shares": [share],
            "max_depth": 2,
            "directory_budget": 2,
        }
    )
    store.coverage.listed(
        host,
        share,
        "/",
        0,
        [
            SavedEntry("Deployments", True, 0, 1),
            SavedEntry("Finance", True, 0, 1),
            SavedEntry("root.txt", False, 32, 1),
        ],
    )
    store.coverage.mark(host, share, "/", 0, "complete")
    store.coverage.mark(host, share, "/Deployments", 1, "failed", "synthetic access denied")
    store.coverage.mark(host, share, "/Finance", 1, "depth_limit", "synthetic depth limit")
    store.upsert_host(host, host, "partial")
    store.upsert_share(host, share, "partial", {})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("test-workspace"),
        help="new directory to create (default: ./test-workspace)",
    )
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    if output.exists():
        parser.error(f"refusing to overwrite existing path: {output}")
    output.mkdir(parents=True, mode=0o700)

    completed = ScanStore(output, "spider", domain="LAB", username="analyst")
    add_inventory(completed, "fileserver", "DATA")
    completed.coverage.scope({"identity": "LAB\\analyst", "scope": "DATA"})
    completed.coverage.listed(
        "fileserver",
        "DATA",
        "/",
        0,
        [SavedEntry("Deployments", True, 0, 1), SavedEntry("Finance", True, 0, 1)],
    )
    completed.coverage.mark("fileserver", "DATA", "/", 0, "complete")
    completed.coverage.mark("fileserver", "DATA", "/Deployments", 1, "excluded", "synthetic exclusion")
    completed.coverage.mark("fileserver", "DATA", "/Finance", 1, "complete")
    completed.finish("completed", {"fixture": "completed ranking inventory"})
    completed_scan = completed.scan_id
    completed.close()

    partial = ScanStore(output, "spider", domain="LAB", username="analyst")
    add_coverage(partial, "fileserver", "DATA")
    partial.finish("partial", {"fixture": "coverage inventory"})
    partial_scan = partial.scan_id
    partial.close()

    database = output / "shrawler.db"
    ranking = rank(database, load(), completed_scan)
    review = ReviewStore(database)
    families = review.build(completed_scan)
    family_rows = review.families(completed_scan)["items"]
    if family_rows:
        review.decide("family", family_rows[0]["family_id"], "defer", "Synthetic review decision")
    candidates = ranking["run_id"]
    manifest = CollectionQueue(database).create(
        run_id=candidates,
        name="Fixture shortlist",
        limit=6,
        min_score=1,
        max_file_size=16 * 1024,
        max_total_bytes=64 * 1024,
    )

    def retrieve(item: Any, sink: Any) -> None:
        if item.file_name == "passwords.kdbx":
            sink(b"synthetic partial evidence")
            raise OSError("synthetic SMB disconnect")
        sink((f"synthetic evidence for {item.unc_path}\n").encode())

    collected = CollectionQueue(database).run(manifest["id"], retrieve)
    summary = {
        "workspace": str(output),
        "database": str(database),
        "completed_scan": completed_scan,
        "partial_scan": partial_scan,
        "ranking_run": ranking["run_id"],
        "families": families,
        "collection_manifest": collected["id"],
        "collection_statuses": {
            item["status"]: sum(1 for current in collected["items"] if current["status"] == item["status"])
            for item in collected["items"]
        },
    }
    (output / "FIXTURE.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
