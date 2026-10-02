"""Disk-backed benchmark for the complete ranking and persistence pipeline.

Run from the repository root with a new workspace:
    uv run python -m scripts.benchmark_ranking /tmp/opencode/ranking-benchmark --files 1000000
"""

import argparse
import json
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from shrawler.store import ScanStore
from shrawler.triage.rules import load
from shrawler.triage.storage import rank, result_path


def build(workspace: Path, count: int) -> Path:
    workspace.mkdir(parents=True, exist_ok=False)
    store = ScanStore(workspace, "spider")
    store.upsert_host("server", "server", "complete")
    store.upsert_share("server", "docs", "complete", {})
    share_id = store._share_id("server", "docs")
    database = store.path
    scan_id = store.scan_id
    started = time.perf_counter()
    with store.connection:
        for start in range(0, count, 10_000):
            files = []
            observations = []
            for number in range(start, min(start + 10_000, count)):
                folder = number % 50_000
                if number % 10_000 == 0:
                    name = f"password-backup-{number}.kdbx"
                elif number % 1_000 == 0:
                    # Repeated runtime binaries exercise environment-frequency
                    # suppression; the count stays well above the threshold.
                    name = "kernel32.dll"
                    folder = number  # a distinct directory keeps paths unique
                elif number % 7_000 == 3:
                    name = f"InternalTool{number}.exe"
                else:
                    name = f"report-{number}.txt"
                remote = f"/department-{folder % 100}/project-{folder}/{name}"
                public_id = f"file{number:016}"
                payload = {
                    "file_name": name,
                    "remote_path": remote,
                    "unc_path": "\\\\server\\docs" + remote.replace("/", "\\"),
                    "size_bytes": number,
                    "readable_size": f"{number}B",
                    "mtime_utc": "2026-01-01T00:00:00+00:00",
                    "scan_timestamp_utc": "2026-01-01T00:00:00+00:00",
                }
                files.append(
                    (
                        public_id,
                        "server",
                        "docs",
                        remote,
                        remote.rsplit("/", 1)[0],
                        payload["unc_path"],
                        name,
                        "." + name.rsplit(".", 1)[1],
                        number,
                        payload["readable_size"],
                        payload["mtime_utc"],
                        payload["scan_timestamp_utc"],
                        "server docs " + remote + " " + name,
                    )
                )
                observations.append((scan_id, share_id, public_id, json.dumps(payload)))
            store.connection.executemany(
                "INSERT INTO files(public_id,host,share,remote_path,parent_path,unc_path,file_name,extension,size_bytes,readable_size,mtime_utc,scan_timestamp_utc,search_text) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                files,
            )
            store.connection.executemany(
                "INSERT INTO scan_files SELECT ?,?,id,? FROM files WHERE public_id=?",
                ((row[0], row[1], row[3], row[2]) for row in observations),
            )
    store.finish("completed", {})
    store.close()
    print(f"Built {count:,} files in {time.perf_counter() - started:.1f}s", flush=True)
    return database


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", type=Path)
    parser.add_argument("--files", type=int, default=1_000_000)
    args = parser.parse_args()
    if args.workspace.exists():
        parser.error("workspace must not already exist")
    database = build(args.workspace.resolve(), args.files)
    phases = []
    started = time.perf_counter()
    result = rank(
        database,
        load(),
        on_phase=lambda phase, count: phases.append(
            {"seconds": time.perf_counter() - started, "phase": phase, "files": count}
        ),
    )
    elapsed = time.perf_counter() - started
    with closing(sqlite3.connect(result_path(database))) as connection:
        rows = connection.execute(
            "SELECT COUNT(*) FROM triage_files WHERE run_id=?", (result["run_id"],)
        ).fetchone()[0]
    report = {
        "files": args.files,
        "seconds": elapsed,
        "files_per_second": args.files / elapsed,
        "saved_rows": rows,
        "database_bytes": result_path(database).stat().st_size,
        "timings": result["timings"],
        "phases": phases,
    }
    (args.workspace / "ranking-benchmark.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
