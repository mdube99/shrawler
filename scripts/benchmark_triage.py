"""Reproducible local ranking/family benchmark; no SMB access.

Run: .venv/bin/python scripts/benchmark_triage.py --files 2000000
Temporary fixtures are removed after measurements; JSON results go to stdout.
"""

import argparse
import json
import resource
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shrawler.store import ScanStore
from shrawler.triage.review import ReviewStore
from shrawler.triage.rules import load
from shrawler.triage.storage import list_results, rank
from shrawler.web import DatabaseIndex


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--files", type=int, default=2000000)
    args = parser.parse_args()
    if args.files < 100:
        parser.error("--files must be at least 100")
    measurements = {"files": args.files}
    with tempfile.TemporaryDirectory(prefix="shrawler-benchmark-") as directory:
        root = Path(directory)
        store = ScanStore(root, "spider")
        store.upsert_host("server", "server", "complete")
        store.upsert_share("server", "DATA", "complete", {})
        scan = store.scan_id
        host_id = store.connection.execute("SELECT id FROM hosts").fetchone()[0]
        share_id = store.connection.execute(
            "SELECT id FROM shares WHERE host_id=?", (host_id,)
        ).fetchone()[0]
        started = time.perf_counter()
        # Batch fixture writes directly; only fixture generation bypasses the
        # scanner. Ranking and grouping use the production services unchanged.
        with store._lock:
            for offset in range(0, args.files, 1000):
                files, observations = [], []
                for index in range(offset, min(offset + 1000, args.files)):
                    parent = "/reports/project" + str(index // 100)
                    name = (
                        "passwords.config"
                        if index % 100 == 0
                        else "report-" + str(index) + ".csv"
                    )
                    remote = parent + "/" + name
                    unc = "\\\\server\\DATA" + remote.replace("/", "\\")
                    metadata = {
                        "file_name": name,
                        "remote_path": remote,
                        "unc_path": unc,
                        "size_bytes": 100,
                        "mtime_utc": "2026-01-01T00:00:00+00:00",
                        "scan_timestamp_utc": "2026-09-05T00:00:00+00:00",
                        "readable_size": "100B",
                    }
                    files.append(
                        (
                            index + 1,
                            str(index),
                            "server",
                            "DATA",
                            remote,
                            parent,
                            unc,
                            name,
                            Path(name).suffix,
                            100,
                            "100B",
                            metadata["mtime_utc"],
                            metadata["scan_timestamp_utc"],
                            remote.casefold(),
                        )
                    )
                    observations.append(
                        (scan, share_id, index + 1, json.dumps(metadata))
                    )
                store.connection.executemany(
                    "INSERT INTO files VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", files
                )
                store.connection.executemany(
                    "INSERT INTO scan_files VALUES (?,?,?,?)", observations
                )
                store.connection.commit()
        store.finish("completed", {})
        store.close()
        measurements["fixture_seconds"] = time.perf_counter() - started
        print("Fixture ready", file=sys.stderr, flush=True)
        database = root / "shrawler.db"
        started = time.perf_counter()
        ranked = rank(
            database,
            load(),
            on_phase=lambda phase, count: (
                print(f"{phase}: {count}", file=sys.stderr, flush=True)
                if count % 200000 == 0
                else None
            ),
        )
        measurements["rank_seconds"] = time.perf_counter() - started
        started = time.perf_counter()
        result = list_results(database, ranked["run_id"])
        measurements["top100_seconds"] = time.perf_counter() - started
        assert result["files_scored"] == args.files
        assert any(
            signal["rule_id"] == "builtin.rare-extension"
            for signal in result["items"][0]["signals"]
        )
        started = time.perf_counter()
        review = ReviewStore(database)
        groups = review.build()
        measurements["families_build_seconds"] = time.perf_counter() - started
        started = time.perf_counter()
        families = review.families(scan)
        measurements["families_first_page_seconds"] = time.perf_counter() - started
        assert groups["files"] == args.files and families["items"]
        measurements["families"] = groups["families"]
        index = DatabaseIndex(database)
        for label, query, page in (
            ("inventory_first_page", "", 1),
            ("inventory_substring", "passwords", 1),
            ("inventory_deep_page", "", max(1, args.files // 100 - 1)),
        ):
            started = time.perf_counter()
            page_result = index.search(query, "", "", "", page, 100)
            measurements[label + "_seconds"] = time.perf_counter() - started
            assert page_result["items"]

        measurements["peak_rss_mib"] = (
            resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        )
        measurements["database_mib"] = {
            p.name: p.stat().st_size / 1024**2 for p in root.glob("*.db")
        }
    print(json.dumps(measurements, indent=2))


if __name__ == "__main__":
    main()
