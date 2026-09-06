"""Offline file-family grouping and reversible analyst decisions."""

import argparse
import hashlib
import json
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..output import escape_terminal
from .storage import connect_readonly, observations, select_scan, utc_now

SCHEMA = """
CREATE TABLE IF NOT EXISTS family_members (
 scan_id TEXT NOT NULL, family_id TEXT NOT NULL, file_id TEXT NOT NULL,
 metadata_json TEXT NOT NULL, PRIMARY KEY(scan_id,file_id)
);
CREATE INDEX IF NOT EXISTS family_members_group ON family_members(scan_id,family_id,file_id);
CREATE TABLE IF NOT EXISTS review_events (
 id INTEGER PRIMARY KEY, scope TEXT NOT NULL, target TEXT NOT NULL,
 disposition TEXT NOT NULL, note TEXT NOT NULL, created_at TEXT NOT NULL,
 undone INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS review_lookup ON review_events(scope,target,id DESC);
CREATE TABLE IF NOT EXISTS evidence_hashes (
 local_path TEXT PRIMARY KEY, file_id TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL
);
"""
DISPOSITIONS = ("reviewed", "relevant", "defer", "exclude")


def family_key(metadata: Dict[str, Any]) -> str:
    # Numeric runs represent possible dates/versions. This is deliberately only
    # a review grouping; host/share and every nonnumeric path segment remain.
    path = metadata["remote_path"].replace("\\", "/").casefold()
    normalized = re.sub(r"\d+", "#", path)
    value = [metadata["host"].casefold(), metadata["share"].casefold(), normalized]
    return hashlib.sha256(json.dumps(value).encode()).hexdigest()[:24]


class ReviewStore:
    def __init__(self, database: Path):
        self.database = database.resolve()
        self.path = self.database.with_name(self.database.stem + ".review.db")
        with closing(self.connect()) as db, db:
            db.executescript(SCHEMA)
        self.path.chmod(0o600)

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        return db

    def build(self, scan_id: Optional[str] = None) -> Dict[str, Any]:
        with closing(connect_readonly(self.database)) as source, closing(
            self.connect()
        ) as db, db:
            source.execute("BEGIN")
            scan = select_scan(source, scan_id)
            db.execute("DELETE FROM family_members WHERE scan_id=?", (scan["id"],))
            count = 0
            for item in observations(source, scan["id"]):
                db.execute(
                    "INSERT INTO family_members VALUES (?,?,?,?)",
                    (scan["id"], family_key(item), item["file_id"], json.dumps(item)),
                )
                count += 1
            return {
                "scan_id": scan["id"],
                "files": count,
                "families": db.execute(
                    "SELECT COUNT(DISTINCT family_id) FROM family_members WHERE scan_id=?",
                    (scan["id"],),
                ).fetchone()[0],
            }

    def families(
        self,
        scan_id: str,
        limit: int = 100,
        offset: int = 0,
        family_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not 1 <= limit <= 1000 or offset < 0:
            raise ValueError("limit must be 1..1000 and offset nonnegative")
        with closing(self.connect()) as db:
            if family_id:
                rows = db.execute(
                    "SELECT metadata_json FROM family_members WHERE scan_id=? AND family_id=? ORDER BY file_id LIMIT ? OFFSET ?",
                    (scan_id, family_id, limit, offset),
                )
                return {"items": [json.loads(row[0]) for row in rows]}
            rows = db.execute(
                """SELECT family_id,COUNT(*) AS file_count,
                MIN(json_extract(metadata_json,'$.mtime_utc')) AS first_mtime,
                MAX(json_extract(metadata_json,'$.mtime_utc')) AS last_mtime,
                MIN(json_extract(metadata_json,'$.unc_path')) AS representative,
                SUM(json_extract(metadata_json,'$.size_bytes')) AS expected_bytes
                FROM family_members WHERE scan_id=? GROUP BY family_id
                ORDER BY file_count DESC,family_id LIMIT ? OFFSET ?""",
                (scan_id, limit, offset),
            )
            items = [dict(row) for row in rows]
            for item in items:
                event = db.execute(
                    "SELECT * FROM review_events WHERE scope='family' AND target=? AND undone=0 ORDER BY id DESC LIMIT 1",
                    (item["family_id"],),
                ).fetchone()
                item["review"] = dict(event) if event else None
            return {"scan_id": scan_id, "items": items, "provisional": True}

    def decide(
        self, scope: str, target: str, disposition: str, note: str = ""
    ) -> Dict[str, Any]:
        if scope not in ("file", "family") or disposition not in DISPOSITIONS:
            raise ValueError("Invalid review scope or disposition")
        if type(note) is not str or len(note) > 4000:
            raise ValueError("Review note must be at most 4000 characters")
        column = "file_id" if scope == "file" else "family_id"
        with closing(self.connect()) as db, db:
            if (
                db.execute(
                    "SELECT 1 FROM family_members WHERE " + column + "=? LIMIT 1",
                    (target,),
                ).fetchone()
                is None
            ):
                raise ValueError("Unknown review target; build families first")
            cursor = db.execute(
                "INSERT INTO review_events(scope,target,disposition,note,created_at) VALUES (?,?,?,?,?)",
                (scope, target, disposition, note, utc_now()),
            )
            return {
                "event_id": cursor.lastrowid,
                "scope": scope,
                "target": target,
                "disposition": disposition,
                "note": note,
            }

    def undo(self, event_id: int) -> Dict[str, Any]:
        with closing(self.connect()) as db, db:
            cursor = db.execute(
                "UPDATE review_events SET undone=1 WHERE id=? AND undone=0", (event_id,)
            )
            if not cursor.rowcount:
                raise ValueError("Unknown or already undone review event")
        return {"undone": event_id}

    def hashes(self) -> Dict[str, Any]:
        from ..collection import CollectionQueue

        count = 0
        with closing(self.connect()) as db, db:
            # Rebuild from local evidence so deleted/changed files cannot retain
            # stale confirmed-duplicate status. This never performs SMB reads.
            db.execute("DELETE FROM evidence_hashes")
            for manifest in CollectionQueue(self.database).list():
                for item in manifest["items"]:
                    if item["status"] != "collected" or not item["local_path"]:
                        continue
                    path = Path(item["local_path"])
                    if not path.is_file():
                        continue
                    digest = hashlib.sha256()
                    size = 0
                    with path.open("rb") as handle:
                        for chunk in iter(lambda: handle.read(1024**2), b""):
                            digest.update(chunk)
                            size += len(chunk)
                    db.execute(
                        "INSERT OR REPLACE INTO evidence_hashes VALUES (?,?,?,?)",
                        (str(path), item["file_id"], digest.hexdigest(), size),
                    )
                    count += 1
            groups = db.execute(
                "SELECT sha256,size,COUNT(*) AS copies,json_group_array(local_path) AS paths FROM evidence_hashes GROUP BY sha256,size HAVING COUNT(*)>1"
            )
            return {"hashed_files": count, "duplicates": [dict(row) for row in groups]}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="shrawler review")
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("database", type=Path)
    build.add_argument("--scan")
    listing = commands.add_parser("list")
    listing.add_argument("database", type=Path)
    listing.add_argument("--scan", required=True)
    listing.add_argument("--family", dest="family_id")
    listing.add_argument("--limit", type=int, default=100)
    listing.add_argument("--offset", type=int, default=0)
    decide = commands.add_parser("decide")
    decide.add_argument("database", type=Path)
    decide.add_argument("scope", choices=("file", "family"))
    decide.add_argument("target")
    decide.add_argument("disposition", choices=DISPOSITIONS)
    decide.add_argument("--note", default="")
    undo = commands.add_parser("undo")
    undo.add_argument("database", type=Path)
    undo.add_argument("event_id", type=int)
    hashes = commands.add_parser("hashes")
    hashes.add_argument("database", type=Path)
    args = parser.parse_args(argv)
    try:
        store = ReviewStore(args.database)
        if args.command == "build":
            result = store.build(args.scan)
        elif args.command == "list":
            result = store.families(args.scan, args.limit, args.offset, args.family_id)
        elif args.command == "decide":
            result = store.decide(args.scope, args.target, args.disposition, args.note)
        elif args.command == "undo":
            result = store.undo(args.event_id)
        else:
            result = store.hashes()
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return 0
    except (ValueError, OSError, sqlite3.Error) as exc:
        parser.exit(1, "Review error: " + escape_terminal(str(exc)) + "\n")
