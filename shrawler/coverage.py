"""Durable directory listings and offline coverage inspection."""

import argparse
import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .output import escape_terminal
from .triage.storage import connect_readonly, utc_now

SCHEMA = """
CREATE TABLE IF NOT EXISTS directory_work (
 scan_id TEXT NOT NULL, host TEXT NOT NULL, share TEXT NOT NULL, path TEXT NOT NULL,
 depth INTEGER NOT NULL, status TEXT NOT NULL, entries_json TEXT, error TEXT,
 updated_at TEXT NOT NULL, PRIMARY KEY(scan_id,host,share,path)
);
CREATE INDEX IF NOT EXISTS directory_work_status ON directory_work(scan_id,status,host,share);
CREATE TABLE IF NOT EXISTS scan_scope (scan_id TEXT PRIMARY KEY, payload_json TEXT NOT NULL);
"""


@dataclass
class SavedEntry:
    name: str
    directory: bool
    size: int
    mtime: float
    ctime: float = 0
    atime: float = 0

    def get_longname(self) -> str:
        return self.name

    def is_directory(self) -> bool:
        return self.directory

    def get_filesize(self) -> int:
        return self.size

    def get_mtime_epoch(self) -> float:
        return self.mtime

    def get_ctime_epoch(self) -> float:
        return self.ctime

    def get_atime_epoch(self) -> float:
        return self.atime


def canonical(path: str) -> str:
    return "/" + "/".join(p for p in path.replace("\\", "/").split("/") if p)


class DirectoryCoverage:
    def __init__(self, store: Any):
        self.store = store
        with store._lock:
            store.connection.executescript(SCHEMA)
            store.connection.commit()

    def scope(self, values: Dict[str, Any]) -> None:
        with self.store._lock:
            self.store.connection.execute(
                "INSERT OR IGNORE INTO scan_scope VALUES (?,?)",
                (self.store.scan_id, json.dumps(values)),
            )
            self.store._touch(force=True)

    def mark(
        self,
        host: str,
        share: str,
        path: str,
        depth: int,
        status: str,
        error: Optional[str] = None,
    ) -> None:
        with self.store._lock:
            self.store.connection.execute(
                """INSERT INTO directory_work
                VALUES (?,?,?,?,?,?,NULL,?,?) ON CONFLICT(scan_id,host,share,path)
                DO UPDATE SET status=excluded.status,error=excluded.error,updated_at=excluded.updated_at""",
                (
                    self.store.scan_id,
                    host,
                    share,
                    canonical(path),
                    depth,
                    status,
                    error,
                    utc_now(),
                ),
            )
            self.store._touch(force=True)

    def cached(self, host: str, share: str, path: str) -> Optional[List[SavedEntry]]:
        with self.store._lock:
            row = self.store.connection.execute(
                """SELECT entries_json FROM directory_work
                WHERE scan_id=? AND host=? AND share=? AND path=?""",
                (self.store.scan_id, host, share, canonical(path)),
            ).fetchone()
        return (
            [SavedEntry(**entry) for entry in json.loads(row[0])]
            if row and row[0] is not None
            else None
        )

    def listed(
        self, host: str, share: str, path: str, depth: int, entries: List[Any]
    ) -> None:
        path = canonical(path)
        payload: List[Dict[str, Any]] = [
            {
                "name": e.get_longname(),
                "directory": bool(e.is_directory()),
                "size": int(e.get_filesize()),
                "mtime": float(e.get_mtime_epoch()),
                "ctime": float(e.get_ctime_epoch()),
                "atime": float(e.get_atime_epoch()),
            }
            for e in entries
            if e.get_longname() not in (".", "..")
        ]
        # Listing and discovered child work commit together before file processing.
        with self.store._lock:
            self.store.connection.execute(
                """INSERT INTO directory_work VALUES (?,?,?,?,?,'listed',?,NULL,?)
                ON CONFLICT(scan_id,host,share,path) DO UPDATE SET status='listed',
                entries_json=excluded.entries_json,error=NULL,updated_at=excluded.updated_at""",
                (
                    self.store.scan_id,
                    host,
                    share,
                    path,
                    depth,
                    json.dumps(payload),
                    utc_now(),
                ),
            )
            for entry in payload:
                if entry["directory"]:
                    self.store.connection.execute(
                        """INSERT OR IGNORE INTO directory_work
                        VALUES (?,?,?,?,?,'pending',NULL,NULL,?)""",
                        (
                            self.store.scan_id,
                            host,
                            share,
                            canonical(path + "/" + entry["name"]),
                            depth + 1,
                            utc_now(),
                        ),
                    )
            self.store._touch(force=True)

    def outstanding(
        self, host: Optional[str] = None, share: Optional[str] = None
    ) -> bool:
        query = "SELECT 1 FROM directory_work WHERE scan_id=? AND status NOT IN ('complete','excluded')"
        values = [self.store.scan_id]
        for key, value in (("host", host), ("share", share)):
            if value is not None:
                query += " AND " + key + "=?"
                values.append(value)
        with self.store._lock:
            return (
                self.store.connection.execute(query + " LIMIT 1", values).fetchone()
                is not None
            )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="shrawler coverage",
        description="Inspect saved directory coverage without SMB access.",
    )
    parser.add_argument("database", type=Path)
    parser.add_argument("--scan")
    parser.add_argument(
        "--view", choices=("all", "remaining", "failed", "covered"), default="all"
    )
    parser.add_argument("--host")
    parser.add_argument("--share")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--offset", type=int, default=0)
    args = parser.parse_args(argv)
    try:
        if not 1 <= args.limit <= 10000 or args.offset < 0:
            raise ValueError("limit must be 1..10000 and offset nonnegative")
        with closing(connect_readonly(args.database)) as db:
            scan = db.execute(
                "SELECT * FROM scans WHERE id=? OR short_id=?"
                if args.scan
                else "SELECT * FROM scans ORDER BY started_at_utc DESC LIMIT 1",
                (args.scan, args.scan) if args.scan else (),
            ).fetchone()
            if scan is None:
                raise ValueError("No matching scan")
            if (
                db.execute(
                    "SELECT 1 FROM sqlite_master WHERE name='directory_work'"
                ).fetchone()
                is None
            ):
                raise ValueError(
                    "This inventory predates directory coverage; start a new scan to record it"
                )
            query = " FROM directory_work WHERE scan_id=?"
            values: List[Any] = [scan["id"]]
            for key in ("host", "share"):
                if getattr(args, key):
                    query += " AND " + key + "=?"
                    values.append(getattr(args, key))
            statuses = {
                "remaining": "status NOT IN ('complete','excluded')",
                "failed": "status='failed'",
                "covered": "entries_json IS NOT NULL",
            }
            if args.view in statuses:
                query += " AND " + statuses[args.view]
            scope = db.execute(
                "SELECT payload_json FROM scan_scope WHERE scan_id=?", (scan["id"],)
            ).fetchone()
            rows = db.execute(
                "SELECT host,share,path,depth,status,error,updated_at,"
                "json_array_length(entries_json) AS observed_entries"
                + query
                + " ORDER BY host,share,path LIMIT ? OFFSET ?",
                (*values, args.limit, args.offset),
            )
            result = {
                "scan": dict(scan),
                "scope": json.loads(scope[0]) if scope else {},
                "total": db.execute("SELECT COUNT(*)" + query, values).fetchone()[0],
                "items": [dict(row) for row in rows],
                "shares": [
                    dict(row)
                    for row in db.execute(
                        "SELECT h.host,s.name,s.status,s.payload_json FROM shares s JOIN hosts h ON h.id=s.host_id WHERE h.scan_id=? ORDER BY h.host,s.name LIMIT ? OFFSET ?",
                        (scan["id"], args.limit, args.offset),
                    )
                ],
                "note": "Listing coverage only. Collection and analyst review are tracked separately. Unlisted descendants are unknown.",
            }
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return 0
    except (ValueError, OSError, sqlite3.Error) as exc:
        parser.exit(1, "Coverage error: " + escape_terminal(str(exc)) + "\n")
