"""Persistent, reviewable collection manifests independent of traversal."""

import fcntl
import json
import os
import sqlite3
import uuid
from contextlib import closing, contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, Generator, List, Optional

from .smb import SMBAuth
from .triage.storage import (
    FALLBACK_CATEGORIES,
    connect_readonly,
    list_results,
    utc_now,
)


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
        if limit > 10000:
            raise ValueError("Selection is limited to the first 10000 candidates")
        if type(min_score) is not int or min_score < 0:
            raise ValueError("Minimum score must be a nonnegative integer")
        if type(name) is not str or not 1 <= len(name) <= 200:
            raise ValueError("Name must contain 1..200 characters")
        if file_ids is not None and (
            type(file_ids) is not list
            or not file_ids
            or not all(type(i) is str for i in file_ids)
        ):
            raise ValueError("file_ids must be a non-empty list of candidate IDs")
        candidates = self._candidates(run_id, category, limit, min_score, file_ids)
        ranked = candidates["items"] if candidates else []
        if file_ids is None:
            selection = ranked
        else:
            # A hand-picked file the selected run never rated -- most often one
            # captured after the ranking ran -- still has an exact path. Resolve
            # it from the inventory so the manifest stays a frozen list of real
            # files instead of a page of a ranking.
            unrated = sorted(set(file_ids) - {item["file_id"] for item in ranked})
            selection = ranked + self._inventory_items(unrated)
        # Record the run only when it contributed something. A selection the run
        # never rated has no source ranking, and naming one would imply reasons
        # that are not in the manifest.
        recorded = candidates if (file_ids is None or ranked) else None
        previously = {
            item["file_id"]
            for manifest in self.list()
            for item in manifest["items"]
            if item["status"] == "collected"
        }
        source = connect_readonly(self.database)
        try:
            # Historical collection is evidence of a prior retrieval, not freshness.
            # Scope to the candidate hosts/shares so growing web-download evidence
            # never turns manifest creation into a full-table materialization.
            targets = sorted(
                {
                    (candidate["host"], candidate["share"])
                    for candidate in selection
                }
            )
            prior_paths: set = set()
            for start in range(0, len(targets), 200):
                chunk = targets[start : start + 200]
                conditions = " OR ".join("(h.host=? AND s.name=?)" for _ in chunk)
                rows = source.execute(
                    "SELECT h.host, s.name, json_extract(d.payload_json, '$.remote_path') "
                    "FROM downloads d JOIN shares s ON s.id=d.share_id "
                    "JOIN hosts h ON h.id=s.host_id "
                    f"WHERE {conditions}",
                    [value for pair in chunk for value in pair],
                )
                prior_paths.update(
                    (h.casefold(), s.casefold(), self._path(p)) for h, s, p in rows if p
                )
        finally:
            source.close()
        items: List[Dict[str, Any]] = []
        expected = 0
        for candidate in selection:
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
                        for s in candidate.get("signals") or []
                        if s["credited_points"] > 0
                    ]
                    or [
                        s["description"]
                        for s in candidate.get("signals") or []
                        if s["category"] in FALLBACK_CATEGORIES
                    ]
                    or (
                        [
                            f"Selected by saved ranking query "
                            f"(score {candidate['review_score']})"
                        ]
                        if candidate.get("review_score") is not None
                        else ["Selected by hand; not included in a rule ranking"]
                    ),
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
                "run_id": recorded["run_id"] if recorded else None,
                "category": category,
                "limit": limit,
                "min_score": min_score,
                "file_ids": file_ids,
            },
            "scan_id": recorded["scan_id"] if recorded else None,
            "max_file_size": max_file_size,
            "max_total_bytes": max_total_bytes,
            "consumed_bytes": 0,
            "expected_files": sum(i["status"] == "pending" for i in items),
            "expected_bytes": expected,
            "items": items,
        }
        self._save(manifest)
        return manifest

    def _candidates(
        self,
        run_id: Optional[str],
        category: Optional[str],
        limit: int,
        min_score: int,
        file_ids: Optional[List[str]],
    ) -> Optional[Dict[str, Any]]:
        """Ranked candidates for the selection, or None when there is no run.

        A named run that fails to resolve is still an error. An unnamed run is
        only a preference: a hand-picked selection survives an inventory that
        has never been ranked, which is what makes an ad-hoc manifest possible.
        """
        requested = sorted(set(file_ids)) if file_ids is not None else None
        try:
            return list_results(
                self.database,
                run_id,
                category,
                limit,
                min_score,
                file_ids=requested,
            )
        except ValueError:
            if run_id or file_ids is None:
                raise
            return None

    def _inventory_items(self, file_ids: List[str]) -> List[Dict[str, Any]]:
        """Resolve files straight from the inventory, with no rule rating.

        The shape matches a ranked candidate so the rest of manifest creation
        (paths, prior collection, byte limits) treats both identically. Reaching
        here means the selected run does not cover the file, not that the file
        is missing from the inventory.
        """
        if not file_ids:
            return []
        with closing(connect_readonly(self.database)) as source:
            placeholders = ",".join("?" for _ in file_ids)
            rows = source.execute(
                "SELECT public_id, host, share, remote_path, unc_path, file_name, "
                "extension, size_bytes, readable_size, mtime_utc, "
                "scan_timestamp_utc FROM files "
                f"WHERE public_id IN ({placeholders})",
                file_ids,
            ).fetchall()
        found = {
            str(row["public_id"]): {
                "file_id": str(row["public_id"]),
                "host": str(row["host"]),
                "share": str(row["share"]),
                "remote_path": str(row["remote_path"]),
                "unc_path": str(row["unc_path"]),
                "file_name": str(row["file_name"]),
                "extension": str(row["extension"]),
                "size_bytes": int(row["size_bytes"]),
                "readable_size": str(row["readable_size"]),
                "mtime_utc": str(row["mtime_utc"]),
                "scan_timestamp_utc": str(row["scan_timestamp_utc"]),
                "signals": [],
                "review_score": None,
            }
            for row in rows
        }
        missing = [file_id for file_id in file_ids if file_id not in found]
        if missing:
            raise ValueError("Unknown file ID: " + ", ".join(sorted(missing)[:5]))
        return [found[file_id] for file_id in file_ids]

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
