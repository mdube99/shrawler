"""Persistent, reviewable collection manifests independent of traversal."""

import fcntl
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, Generator, List, Optional

from .smb import SMBAuth
from .triage.storage import connect_readonly, list_results, utc_now


class CollectionBusyError(ValueError):
    pass


class CollectionQueue:
    def __init__(self, database: Path) -> None:
        self.database = Path(database).resolve()
        self.path = self.database.with_name(self.database.stem + ".collection.db")
        self.evidence = self.database.with_name(self.database.stem + ".collection")
        with self.connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS manifests (id TEXT PRIMARY KEY, payload TEXT NOT NULL)"
            )
        os.chmod(self.path, 0o600)

    @contextmanager
    def connect(self) -> Generator[sqlite3.Connection, None, None]:
        db = sqlite3.connect(self.path, timeout=30)
        try:
            with db:
                yield db
        finally:
            db.close()

    def _save(self, manifest: Dict[str, Any]) -> None:
        with self.connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO manifests VALUES (?,?)",
                (manifest["id"], json.dumps(manifest)),
            )

    def get(self, identifier: str) -> Dict[str, Any]:
        with self.connect() as db:
            row = db.execute(
                "SELECT payload FROM manifests WHERE id=?", (identifier,)
            ).fetchone()
        if row is None:
            raise ValueError("Unknown collection manifest")
        return json.loads(row[0])

    def list(self) -> List[Dict[str, Any]]:
        with self.connect() as db:
            return [
                json.loads(row[0])
                for row in db.execute(
                    "SELECT payload FROM manifests ORDER BY rowid DESC"
                )
            ]

    def create(
        self,
        *,
        run_id: Optional[str] = None,
        category: Optional[str] = None,
        limit: int = 100,
        min_score: int = 0,
        max_file_size: int = 50 * 1024**2,
        max_total_bytes: int = 500 * 1024**2,
        file_ids: Optional[List[str]] = None,
        name: str = "Collection",
    ) -> Dict[str, Any]:
        for value in (limit, max_file_size, max_total_bytes):
            if type(value) is not int or value < 1:
                raise ValueError("Counts and byte limits must be positive integers")
        if type(min_score) is not int or min_score < 0:
            raise ValueError("Minimum score must be a nonnegative integer")
        if type(name) is not str or not 1 <= len(name) <= 200:
            raise ValueError("Name must contain 1..200 characters")
        candidates = list_results(self.database, run_id, category, limit, min_score)
        if file_ids is not None:
            if type(file_ids) is not list or not all(type(i) is str for i in file_ids):
                raise ValueError("file_ids must be a list of candidate IDs")
            available = {item["file_id"] for item in candidates["items"]}
            if not set(file_ids) <= available:
                raise ValueError("Selection contains files outside the saved query")
        previously = {
            item["file_id"]
            for manifest in self.list()
            for item in manifest["items"]
            if item["status"] == "collected"
        }
        source = connect_readonly(self.database)
        try:
            # Historical collection is evidence of a prior retrieval, not freshness.
            rows = source.execute("""SELECT h.host, s.name, json_extract(d.payload_json, '$.remote_path')
                FROM downloads d JOIN shares s ON s.id=d.share_id JOIN hosts h ON h.id=s.host_id""")
            prior_paths = {
                (h.casefold(), s.casefold(), self._path(p)) for h, s, p in rows if p
            }
        finally:
            source.close()
        items: List[Dict[str, Any]] = []
        expected = 0
        for candidate in candidates["items"]:
            if file_ids is not None and candidate["file_id"] not in file_ids:
                continue
            prior = (
                candidate["file_id"] in previously
                or (
                    candidate["host"].casefold(),
                    candidate["share"].casefold(),
                    self._path(candidate["remote_path"]),
                )
                in prior_paths
            )
            size = candidate["size_bytes"]
            status = "previously_collected" if prior else "pending"
            if (candidate.get("review") or {}).get("disposition") == "exclude":
                status = "excluded_review"
            if status == "pending":
                if size > max_file_size or expected + size > max_total_bytes:
                    status = "excluded_limit"
                else:
                    expected += size
            items.append(
                {
                    **candidate,
                    "reasons": [
                        s["description"]
                        for s in candidate["signals"]
                        if s["credited_points"] > 0
                    ]
                    or [
                        s["description"]
                        for s in candidate["signals"]
                        if s["category"] == "extension-fallback"
                    ]
                    or [
                        f"Selected by saved ranking query (score {candidate['review_score']})"
                    ],
                    "previously_collected": prior,
                    "status": status,
                    "attempts": [],
                    "local_path": None,
                }
            )
        manifest: Dict[str, Any] = {
            "version": 1,
            "id": uuid.uuid4().hex,
            "name": name,
            "created_at": utc_now(),
            "source_database": str(self.database),
            "query": {
                "run_id": candidates["run_id"],
                "category": category,
                "limit": limit,
                "min_score": min_score,
                "file_ids": file_ids,
            },
            "scan_id": candidates["scan_id"],
            "max_file_size": max_file_size,
            "max_total_bytes": max_total_bytes,
            "consumed_bytes": 0,
            "expected_files": sum(i["status"] == "pending" for i in items),
            "expected_bytes": expected,
            "items": items,
        }
        self._save(manifest)
        return manifest

    @staticmethod
    def _path(value: str) -> str:
        return "/" + "/".join(
            p for p in value.replace("\\", "/").casefold().split("/") if p
        )

    def run(
        self, identifier: str, retrieve: Callable[[Any, Callable[[bytes], None]], None]
    ) -> Dict[str, Any]:
        """One attempt per unfinished item. Sink accounting includes failed reads."""
        with self.path.open("rb") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise CollectionBusyError(
                    "A collection is already running for this inventory"
                )
            manifest = self.get(identifier)
            destination = self.evidence / manifest["id"]
            destination.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(self.evidence, 0o700)
            for item in manifest["items"]:
                if item["status"] not in {"pending", "failed", "collecting"}:
                    continue
                if item["status"] == "collecting" and item["attempts"]:
                    item["attempts"][-1].update(
                        status="interrupted", finished_at=utc_now()
                    )
                remaining = manifest["max_total_bytes"] - manifest["consumed_bytes"]
                if remaining <= 0 or remaining < item["size_bytes"]:
                    item["status"] = "failed"
                    item["error"] = (
                        "Remaining total budget is smaller than expected file size"
                    )
                    self._save(manifest)
                    continue
                attempt = {"started_at": utc_now(), "bytes": 0, "status": "collecting"}
                item["attempts"].append(attempt)
                item["status"] = "collecting"
                item.pop("error", None)
                self._save(manifest)
                path = destination / (uuid.uuid4().hex + ".bin")
                try:
                    with path.open("xb") as handle:
                        os.chmod(path, 0o600)

                        def sink(
                            data: bytes, attempt: Dict[str, Any] = attempt
                        ) -> None:
                            # Reserve budget durably before writing evidence. A failed
                            # attempt never refunds bytes and retries share this budget.
                            attempt["bytes"] += len(data)
                            manifest["consumed_bytes"] += len(data)
                            self._save(manifest)
                            if (
                                attempt["bytes"] > manifest["max_file_size"]
                                or manifest["consumed_bytes"]
                                > manifest["max_total_bytes"]
                            ):
                                raise ValueError(
                                    "Actual content exceeds collection byte limit"
                                )
                            handle.write(data)

                        retrieve(SimpleNamespace(**item), sink)
                        handle.flush()
                        os.fsync(handle.fileno())
                    item.update(status="collected", local_path=str(path))
                    attempt["status"] = "collected"
                except BaseException as exc:
                    path.unlink(missing_ok=True)
                    item.update(status="failed", error=str(exc))
                    attempt.update(status="failed", error=str(exc))
                    if not isinstance(exc, Exception):
                        attempt["finished_at"] = utc_now()
                        self._save(manifest)
                        raise
                attempt["finished_at"] = utc_now()
                self._save(manifest)
            return manifest


def smb_retriever(auth: SMBAuth) -> Callable[[Any, Callable[[bytes], None]], None]:
    from .smb import close_smb, connect_smb

    def retrieve(item: Any, sink: Callable[[bytes], None]) -> None:
        client = connect_smb(item.host, auth)
        try:
            client.getFile(item.share, item.remote_path, sink)
        finally:
            close_smb(client)

    return retrieve


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    from .arguments import parse_size
    from .cli import add_smb_auth_arguments
    from .output import escape_terminal
    from .smb import create_smb_auth

    parser = argparse.ArgumentParser(
        prog="shrawler collect",
        description="Review and retrieve saved collection manifests without scanning.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("database", type=Path)
    create.add_argument("--name", default="Collection")
    create.add_argument("--run", dest="run_id")
    create.add_argument("--category")
    create.add_argument("--limit", type=int, default=100)
    create.add_argument("--min-score", type=int, default=0)
    create.add_argument("--file-id", dest="file_ids", action="append")
    create.add_argument("--max-file-size", type=parse_size, default=50 * 1024**2)
    create.add_argument("--max-total-bytes", type=parse_size, default=500 * 1024**2)
    listing = commands.add_parser("list")
    listing.add_argument("database", type=Path)
    show = commands.add_parser("show")
    show.add_argument("database", type=Path)
    show.add_argument("id")
    run = commands.add_parser(
        "run", help="retrieve pending or failed items; repeat to resume"
    )
    run.add_argument("database", type=Path)
    run.add_argument("id")
    run.add_argument("auth")
    add_smb_auth_arguments(run)
    args = parser.parse_args(argv)
    try:
        result: Any
        queue = CollectionQueue(args.database)
        if args.command == "create":
            options = vars(args).copy()
            for key in ("database", "command"):
                options.pop(key)
            result = queue.create(**options)
        elif args.command == "list":
            result = queue.list()
        elif args.command == "show":
            result = queue.get(args.id)
        else:
            result = queue.run(
                args.id,
                smb_retriever(
                    create_smb_auth(
                        args.auth,
                        args.hashes,
                        bool(args.no_pass),
                        bool(args.k),
                        args.aesKey,
                    )
                ),
            )
        print(json.dumps(result, indent=2, ensure_ascii=True))
        if args.command == "run" and any(
            i["status"] == "failed" for i in result["items"]
        ):
            return 1
        return 0
    except (ValueError, OSError, sqlite3.Error) as exc:
        parser.exit(1, "Collection error: " + escape_terminal(str(exc)) + "\n")
    except KeyboardInterrupt:
        return 130
