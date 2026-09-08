"""SQLite-backed scan persistence and export."""

import csv
import fcntl
import json
import os
import secrets
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, cast

from .coverage import DirectoryCoverage
from .output import safe_csv_row

SCHEMA_VERSION = 1


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _path_key(value: Any) -> str:
    return "/" + "/".join(
        part
        for part in str(value or "").replace("\\", "/").casefold().split("/")
        if part
    )


class WorkspaceBusyError(RuntimeError):
    """Raised when another scanner owns the workspace."""


class ScanStore:
    """Single-writer SQLite store for one active scan in a shared workspace."""

    def __init__(
        self,
        workspace: Path,
        mode: str,
        domain: str = "",
        username: str = "",
        resume: Optional[str] = None,
    ) -> None:
        self.workspace = workspace.expanduser().resolve()
        self.workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.workspace, 0o700)
        self.path = self.workspace / "shrawler.db"
        self._lock_file = (self.workspace / ".shrawler.lock").open("a+")
        os.chmod(self.workspace / ".shrawler.lock", 0o600)
        try:
            fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            self._lock_file.close()
            raise WorkspaceBusyError(
                f"workspace already has an active scanner: {self.workspace}"
            ) from exc
        self._lock = threading.RLock()
        self._pending = 0
        self._last_commit = time.monotonic()
        self.connection = sqlite3.connect(self.path, timeout=5, check_same_thread=False)
        os.chmod(self.path, 0o600)
        self.connection.row_factory = sqlite3.Row
        self._configure()
        self._create_schema()
        # Owning the workspace lock proves no previous scanner is still live.
        self.connection.execute(
            "UPDATE scans SET status='interrupted', updated_at_utc=? "
            "WHERE status='running'",
            (utc_now(),),
        )
        self.connection.commit()
        if resume is not None:
            self.scan_id, self.short_id, run_path = self._select_resume(resume, mode)
            saved_identity = self.connection.execute(
                "SELECT domain,username FROM scans WHERE id=?", (self.scan_id,)
            ).fetchone()
            if tuple(saved_identity) != (domain, username):
                self.connection.close()
                self._lock_file.close()
                raise ValueError(
                    "Resume must use the original domain and username; start a new scan for another identity"
                )
            self.run_dir = Path(run_path)
            self.connection.execute(
                "UPDATE scans SET status='running', updated_at_utc=? WHERE id=?",
                (utc_now(), self.scan_id),
            )
            self.connection.commit()
        else:
            self.scan_id = uuid.uuid4().hex
            self.short_id = self.scan_id[:6]
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            self.run_dir = self.workspace / "runs" / f"{stamp}-{mode}-{self.short_id}"
            self.run_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
            self.connection.execute(
                """INSERT INTO scans
                   (id, short_id, mode, status, started_at_utc, updated_at_utc,
                    run_dir, domain, username)
                   VALUES (?, ?, ?, 'running', ?, ?, ?, ?, ?)""",
                (
                    self.scan_id,
                    self.short_id,
                    mode,
                    utc_now(),
                    utc_now(),
                    str(self.run_dir),
                    domain,
                    username,
                ),
            )
            self.connection.commit()
        self.coverage = DirectoryCoverage(self)
        self._stop_commit = threading.Event()
        self._commit_thread = threading.Thread(
            target=self._commit_periodically,
            name="shrawler-db-commit",
            daemon=True,
        )
        self._commit_thread.start()

    def _configure(self) -> None:
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA synchronous=NORMAL")
        self.connection.execute("PRAGMA busy_timeout=5000")

    def _create_schema(self) -> None:
        version = int(self.connection.execute("PRAGMA user_version").fetchone()[0])
        if version > SCHEMA_VERSION:
            raise ValueError(
                f"database schema {version} is newer than supported schema {SCHEMA_VERSION}"
            )
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO metadata(key, value) VALUES ('revision', 0);
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                short_id TEXT NOT NULL UNIQUE,
                mode TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL,
                finished_at_utc TEXT,
                run_dir TEXT NOT NULL,
                domain TEXT NOT NULL DEFAULT '',
                username TEXT NOT NULL DEFAULT '',
                summary_json TEXT,
                snaffler_summary_json TEXT
            );
            CREATE TABLE IF NOT EXISTS hosts (
                id INTEGER PRIMARY KEY,
                scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                host TEXT NOT NULL,
                display_name TEXT,
                status TEXT NOT NULL,
                error TEXT,
                scan_timestamp_utc TEXT NOT NULL,
                UNIQUE(scan_id, host)
            );
            CREATE TABLE IF NOT EXISTS shares (
                id INTEGER PRIMARY KEY,
                host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                UNIQUE(host_id, name)
            );
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY,
                public_id TEXT NOT NULL UNIQUE,
                host TEXT NOT NULL,
                share TEXT NOT NULL,
                remote_path TEXT NOT NULL,
                parent_path TEXT NOT NULL,
                unc_path TEXT NOT NULL,
                file_name TEXT NOT NULL,
                extension TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                readable_size TEXT NOT NULL,
                mtime_utc TEXT NOT NULL,
                scan_timestamp_utc TEXT NOT NULL,
                search_text TEXT NOT NULL,
                UNIQUE(host, share, remote_path)
            );
            CREATE TABLE IF NOT EXISTS scan_files (
                scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                share_id INTEGER NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
                file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                payload_json TEXT NOT NULL,
                PRIMARY KEY(scan_id, file_id)
            );
            CREATE TABLE IF NOT EXISTS downloads (
                id INTEGER PRIMARY KEY,
                scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                share_id INTEGER NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
                remote_path_key TEXT,
                payload_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS snaffler_matches (
                id INTEGER PRIMARY KEY,
                scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                share_id INTEGER REFERENCES shares(id) ON DELETE CASCADE,
                remote_path_key TEXT,
                payload_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS files_host_idx ON files(host COLLATE NOCASE);
            CREATE INDEX IF NOT EXISTS files_share_idx ON files(share COLLATE NOCASE);
            CREATE INDEX IF NOT EXISTS files_ext_idx ON files(extension, id);
            CREATE INDEX IF NOT EXISTS files_parent_idx
                ON files(host, share, parent_path, id);
            CREATE INDEX IF NOT EXISTS files_path_sort_idx
                ON files(host COLLATE NOCASE, share COLLATE NOCASE,
                         remote_path COLLATE NOCASE, file_name COLLATE NOCASE,
                         public_id);
            CREATE INDEX IF NOT EXISTS files_name_sort_idx
                ON files(file_name COLLATE NOCASE, remote_path COLLATE NOCASE, public_id);
            CREATE INDEX IF NOT EXISTS files_type_sort_idx
                ON files(extension COLLATE NOCASE, file_name COLLATE NOCASE, public_id);
            CREATE INDEX IF NOT EXISTS files_size_sort_idx
                ON files(size_bytes, file_name COLLATE NOCASE, public_id);
            CREATE INDEX IF NOT EXISTS files_modified_sort_idx
                ON files(mtime_utc, file_name COLLATE NOCASE, public_id);
            CREATE INDEX IF NOT EXISTS scan_files_scan_idx ON scan_files(scan_id, share_id);
            CREATE INDEX IF NOT EXISTS scan_files_file_idx ON scan_files(file_id);
            CREATE INDEX IF NOT EXISTS matches_scan_share_idx ON snaffler_matches(scan_id, share_id);
            CREATE INDEX IF NOT EXISTS downloads_scan_share_idx ON downloads(scan_id, share_id);
            CREATE INDEX IF NOT EXISTS matches_lookup_idx ON snaffler_matches(scan_id, share_id, remote_path_key);
            CREATE INDEX IF NOT EXISTS downloads_lookup_idx ON downloads(scan_id, share_id, remote_path_key);
            """
        )
        self.connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        self.connection.commit()

    def _select_resume(self, value: str, mode: str) -> Tuple[str, str, str]:
        if value:
            row = self.connection.execute(
                """SELECT id, short_id, run_dir, mode FROM scans
                   WHERE (id=? OR short_id=?) AND status!='completed'""",
                (value, value),
            ).fetchone()
        else:
            row = self.connection.execute(
                """SELECT id, short_id, run_dir, mode FROM scans
                   WHERE status!='completed' ORDER BY started_at_utc DESC LIMIT 1"""
            ).fetchone()
        if row is None:
            raise ValueError("no matching incomplete scan found to resume")
        if row["mode"] != mode:
            raise ValueError(
                f"scan {row['short_id']} uses mode {row['mode']}, not {mode}"
            )
        return str(row["id"]), str(row["short_id"]), str(row["run_dir"])

    def _touch(self, count: int = 1, force: bool = False) -> None:
        self._pending += count
        if not self._pending:
            return
        if force or self._pending >= 500 or time.monotonic() - self._last_commit >= 1:
            self.connection.execute(
                "UPDATE metadata SET value=value+1 WHERE key='revision'"
            )
            self.connection.execute(
                "UPDATE scans SET updated_at_utc=? WHERE id=?",
                (utc_now(), self.scan_id),
            )
            self.connection.commit()
            self._pending = 0
            self._last_commit = time.monotonic()

    def _commit_periodically(self) -> None:
        while not self._stop_commit.wait(1):
            with self._lock:
                self._touch(0, force=True)

    def flush(self) -> None:
        with self._lock:
            self._touch(0, force=True)

    def host_status(self, host: str) -> Optional[str]:
        with self._lock:
            if self.coverage.outstanding(host):
                return "partial"
            row = self.connection.execute(
                "SELECT status FROM hosts WHERE scan_id=? AND host=?",
                (self.scan_id, host),
            ).fetchone()
            return str(row[0]) if row else None

    def upsert_host(
        self, host: str, display_name: str, status: str, error: Optional[str] = None
    ) -> None:
        with self._lock:
            self.connection.execute(
                """INSERT INTO hosts
                   (scan_id, host, display_name, status, error, scan_timestamp_utc)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(scan_id, host) DO UPDATE SET
                     display_name=excluded.display_name,
                     status=excluded.status, error=excluded.error""",
                (self.scan_id, host, display_name, status, error, utc_now()),
            )
            self._touch(force=status != "scanning")

    def _host_id(self, host: str) -> int:
        row = self.connection.execute(
            "SELECT id FROM hosts WHERE scan_id=? AND host=?", (self.scan_id, host)
        ).fetchone()
        if row is None:
            raise ValueError(f"host has not been recorded: {host}")
        return int(row[0])

    def share_status(self, host: str, share: str) -> Optional[str]:
        with self._lock:
            if self.coverage.outstanding(host, share):
                return "partial"
            row = self.connection.execute(
                """SELECT s.status FROM shares s JOIN hosts h ON h.id=s.host_id
                   WHERE h.scan_id=? AND h.host=? AND s.name=?""",
                (self.scan_id, host, share),
            ).fetchone()
            return str(row[0]) if row else None

    def upsert_share(
        self, host: str, share: str, status: str, payload: Dict[str, Any]
    ) -> None:
        with self._lock:
            host_id = self._host_id(host)
            self.connection.execute(
                """INSERT INTO shares(host_id, name, status, payload_json)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(host_id, name) DO UPDATE SET
                     status=excluded.status, payload_json=excluded.payload_json""",
                (host_id, share, status, _json(payload)),
            )
            self._touch(force=status == "complete")

    def _share_id(self, host: str, share: str) -> int:
        row = self.connection.execute(
            """SELECT s.id FROM shares s JOIN hosts h ON h.id=s.host_id
               WHERE h.scan_id=? AND h.host=? AND s.name=?""",
            (self.scan_id, host, share),
        ).fetchone()
        if row is None:
            raise ValueError(f"share has not been recorded: {host}\\{share}")
        return int(row[0])

    def add_file(self, host: str, share: str, payload: Dict[str, Any]) -> bool:
        remote = str(payload["remote_path"])
        name = str(payload["file_name"])
        extension = Path(name).suffix.lower()
        normalized = "/" + remote.replace("\\", "/").lstrip("/")
        parent = normalized.rsplit("/", 1)[0] or "/"
        search = " ".join(
            (host, share, remote, str(payload["unc_path"]), name, extension)
        ).casefold()
        with self._lock:
            share_id = self._share_id(host, share)
            self.connection.execute(
                """INSERT INTO files
                   (public_id, host, share, remote_path, parent_path, unc_path,
                    file_name, extension, size_bytes, readable_size, mtime_utc,
                    scan_timestamp_utc, search_text)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(host, share, remote_path) DO UPDATE SET
                    unc_path=excluded.unc_path, file_name=excluded.file_name,
                    extension=excluded.extension, size_bytes=excluded.size_bytes,
                    readable_size=excluded.readable_size, mtime_utc=excluded.mtime_utc,
                    scan_timestamp_utc=excluded.scan_timestamp_utc,
                    search_text=excluded.search_text""",
                (
                    secrets.token_urlsafe(16),
                    host,
                    share,
                    remote,
                    parent,
                    payload["unc_path"],
                    name,
                    extension,
                    int(payload.get("size_bytes") or 0),
                    str(payload.get("readable_size") or ""),
                    str(payload.get("mtime_utc") or ""),
                    str(payload.get("scan_timestamp_utc") or ""),
                    search,
                ),
            )
            file_id = int(
                self.connection.execute(
                    "SELECT id FROM files WHERE host=? AND share=? AND remote_path=?",
                    (host, share, remote),
                ).fetchone()[0]
            )
            cursor = self.connection.execute(
                """INSERT OR IGNORE INTO scan_files
                   (scan_id, share_id, file_id, payload_json) VALUES (?, ?, ?, ?)""",
                (self.scan_id, share_id, file_id, _json(payload)),
            )
            self._touch()
            return cursor.rowcount > 0

    def existing_paths(self, host: str, share: str) -> Set[str]:
        with self._lock:
            return {
                str(row[0])
                for row in self.connection.execute(
                    """SELECT f.unc_path FROM scan_files sf
                       JOIN files f ON f.id=sf.file_id
                       JOIN shares s ON s.id=sf.share_id
                       JOIN hosts h ON h.id=s.host_id
                       WHERE sf.scan_id=? AND h.host=? AND s.name=?""",
                    (self.scan_id, host, share),
                )
            }

    def add_download(self, host: str, share: str, payload: Dict[str, Any]) -> int:
        stored = {key: value for key, value in payload.items() if key != "_store_id"}
        with self._lock:
            cursor = self.connection.execute(
                "INSERT INTO downloads(scan_id, share_id, remote_path_key, payload_json) VALUES (?, ?, ?, ?)",
                (self.scan_id, self._share_id(host, share), _path_key(stored.get("remote_path")), _json(stored)),
            )
            self._touch()
            if cursor.lastrowid is None:
                raise RuntimeError("download record did not receive an ID")
            return cursor.lastrowid

    def update_download(self, download_id: int, payload: Dict[str, Any]) -> None:
        stored = {key: value for key, value in payload.items() if key != "_store_id"}
        with self._lock:
            self.connection.execute(
                "UPDATE downloads SET remote_path_key=?, payload_json=? WHERE id=? AND scan_id=?",
                (_path_key(stored.get("remote_path")), _json(stored), download_id, self.scan_id),
            )
            self._touch()

    def add_match(self, payload: Dict[str, Any]) -> None:
        host, share = str(payload.get("host", "")), str(payload.get("share_name", ""))
        with self._lock:
            share_id = None
            if host and share:
                try:
                    share_id = self._share_id(host, share)
                except ValueError:
                    pass
            self.connection.execute(
                """INSERT INTO snaffler_matches(scan_id, share_id, remote_path_key, payload_json)
                   VALUES (?, ?, ?, ?)""",
                (self.scan_id, share_id, _path_key(payload.get("remote_path")), _json(payload)),
            )
            self._touch()

    def summary_counts(self) -> Dict[str, Any]:
        with self._lock:
            statuses = {
                str(row[0]): int(row[1])
                for row in self.connection.execute(
                    "SELECT status, COUNT(*) FROM hosts WHERE scan_id=? GROUP BY status",
                    (self.scan_id,),
                )
            }
            counts = self.connection.execute(
                """SELECT
                   (SELECT COUNT(*) FROM hosts WHERE scan_id=?),
                   (SELECT COUNT(*) FROM shares s JOIN hosts h ON h.id=s.host_id
                      WHERE h.scan_id=?),
                   (SELECT COUNT(*) FROM scan_files WHERE scan_id=?),
                   (SELECT COUNT(*) FROM downloads WHERE scan_id=?),
                   (SELECT COUNT(*) FROM snaffler_matches WHERE scan_id=?)""",
                (self.scan_id,) * 5,
            ).fetchone()
            download_rows = [
                json.loads(row[0])
                for row in self.connection.execute(
                    "SELECT payload_json FROM downloads WHERE scan_id=?",
                    (self.scan_id,),
                )
            ]
            return {
                "hosts_attempted": int(counts[0]),
                "host_statuses": statuses,
                "shares_enumerated": int(counts[1]),
                "files_seen": int(counts[2]),
                "files_downloaded": int(counts[3]),
                "downloaded_bytes": sum(
                    int(row.get("actual_size_bytes") or 0) for row in download_rows
                ),
                "snaffler_matches": int(counts[4]),
                "downloads": download_rows,
            }

    def progress_counts(self) -> Tuple[int, int]:
        """Return lightweight host/share counts for terminal progress."""
        with self._lock:
            row = self.connection.execute(
                """SELECT
                   (SELECT COUNT(*) FROM hosts WHERE scan_id=?),
                   (SELECT COUNT(*) FROM shares s JOIN hosts h ON h.id=s.host_id
                    WHERE h.scan_id=?)""",
                (self.scan_id, self.scan_id),
            ).fetchone()
            return int(row[0]), int(row[1])

    def finish(
        self,
        status: str,
        summary: Dict[str, Any],
        snaffler_summary: Optional[Dict[str, Any]] = None,
    ) -> None:
        with self._lock:
            if status == "completed" and self.coverage.outstanding():
                status = "partial"
            self.connection.execute(
                """UPDATE scans SET status=?, updated_at_utc=?, finished_at_utc=?,
                   summary_json=?, snaffler_summary_json=? WHERE id=?""",
                (
                    status,
                    utc_now(),
                    utc_now(),
                    _json(summary),
                    _json(snaffler_summary) if snaffler_summary else None,
                    self.scan_id,
                ),
            )
            self._touch(force=True)

    def host_statuses(self) -> Dict[str, int]:
        return dict(self.summary_counts()["host_statuses"])

    def _hosts(self) -> List[sqlite3.Row]:
        return list(
            self.connection.execute(
                "SELECT * FROM hosts WHERE scan_id=? ORDER BY host COLLATE NOCASE",
                (self.scan_id,),
            )
        )

    def build_results(self, summary: Dict[str, Any]) -> Dict[str, Any]:
        """Build one scan result. Primarily retained for tests and small reports."""
        result: Dict[str, Any] = {
            "_schema": {"name": "shrawler-results", "version": 3},
            "_summary": summary,
        }
        scan = self.connection.execute(
            "SELECT snaffler_summary_json FROM scans WHERE id=?", (self.scan_id,)
        ).fetchone()
        if scan and scan[0]:
            result["_snaffler_summary"] = json.loads(scan[0])
        for host in self._hosts():
            host_data: Dict[str, Any] = {
                "scan_timestamp_utc": host["scan_timestamp_utc"],
                "status": host["status"],
                "error": host["error"],
                "shares": {},
            }
            shares = self.connection.execute(
                "SELECT * FROM shares WHERE host_id=? ORDER BY name COLLATE NOCASE",
                (host["id"],),
            )
            for share in shares:
                payload = json.loads(share["payload_json"])
                payload["status"] = share["status"]
                payload["discovered_files"] = [
                    json.loads(row[0])
                    for row in self.connection.execute(
                        """SELECT sf.payload_json FROM scan_files sf
                           WHERE sf.scan_id=? AND sf.share_id=? ORDER BY sf.rowid""",
                        (self.scan_id, share["id"]),
                    )
                ]
                payload["downloaded_files"] = [
                    json.loads(row[0])
                    for row in self.connection.execute(
                        """SELECT payload_json FROM downloads
                           WHERE scan_id=? AND share_id=? ORDER BY id""",
                        (self.scan_id, share["id"]),
                    )
                ]
                matches = [
                    json.loads(row[0])
                    for row in self.connection.execute(
                        """SELECT payload_json FROM snaffler_matches
                           WHERE scan_id=? AND share_id=? ORDER BY id""",
                        (self.scan_id, share["id"]),
                    )
                ]
                if matches:
                    payload["snaffler_matches"] = matches
                host_data["shares"][share["name"]] = payload
            result[str(host["host"])] = host_data
        return result

    def export_json(self, summary: Dict[str, Any]) -> Path:
        """Atomically export the current scan using schema-v3 structure."""
        path = self.run_dir / "shrawler_results.json"
        temporary = self.run_dir / ".shrawler_results.json.tmp"
        with temporary.open("w", encoding="utf-8") as handle:
            os.chmod(temporary, 0o600)
            handle.write("{")

            def property_value(name: str, value: Any, comma: bool = True) -> None:
                if comma:
                    handle.write(",")
                handle.write(_json(name) + ":" + _json(value))

            property_value("_schema", {"name": "shrawler-results", "version": 3}, False)
            property_value("_summary", summary)
            scan = self.connection.execute(
                "SELECT snaffler_summary_json FROM scans WHERE id=?", (self.scan_id,)
            ).fetchone()
            if scan and scan[0]:
                property_value("_snaffler_summary", json.loads(scan[0]))

            for host in self._hosts():
                handle.write("," + _json(str(host["host"])) + ":{")
                property_value("scan_timestamp_utc", host["scan_timestamp_utc"], False)
                property_value("status", host["status"])
                property_value("error", host["error"])
                handle.write("," + _json("shares") + ":{")
                first_share = True
                shares = self.connection.execute(
                    "SELECT * FROM shares WHERE host_id=? ORDER BY name COLLATE NOCASE",
                    (host["id"],),
                )
                for share in shares:
                    if not first_share:
                        handle.write(",")
                    first_share = False
                    handle.write(_json(str(share["name"])) + ":{")
                    payload = json.loads(share["payload_json"])
                    first_property = True
                    for name, value in payload.items():
                        if name in {
                            "status",
                            "discovered_files",
                            "downloaded_files",
                            "snaffler_matches",
                        }:
                            continue
                        property_value(name, value, not first_property)
                        first_property = False
                    property_value("status", share["status"], not first_property)
                    handle.write("," + _json("discovered_files") + ":[")
                    rows = self.connection.execute(
                        """SELECT payload_json FROM scan_files
                           WHERE scan_id=? AND share_id=? ORDER BY rowid""",
                        (self.scan_id, share["id"]),
                    )
                    for index, row in enumerate(rows):
                        if index:
                            handle.write(",")
                        handle.write(row[0])
                    handle.write("]," + _json("downloaded_files") + ":[")
                    rows = self.connection.execute(
                        """SELECT payload_json FROM downloads
                           WHERE scan_id=? AND share_id=? ORDER BY id""",
                        (self.scan_id, share["id"]),
                    )
                    for index, row in enumerate(rows):
                        if index:
                            handle.write(",")
                        handle.write(row[0])
                    handle.write("]")
                    matches = self.connection.execute(
                        """SELECT payload_json FROM snaffler_matches
                           WHERE scan_id=? AND share_id=? ORDER BY id""",
                        (self.scan_id, share["id"]),
                    )
                    first_match = True
                    for row in matches:
                        if first_match:
                            handle.write("," + _json("snaffler_matches") + ":[")
                            first_match = False
                        else:
                            handle.write(",")
                        handle.write(row[0])
                    if not first_match:
                        handle.write("]")
                    handle.write("}")
                handle.write("}}")
            handle.write("}")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        return path

    def _payloads(self, table: str) -> Iterable[Dict[str, Any]]:
        query = f"SELECT payload_json FROM {table} WHERE scan_id=? ORDER BY id"
        for row in self.connection.execute(query, (self.scan_id,)):
            yield json.loads(row[0])

    def export_csv(self) -> List[str]:
        """Write current CSV views from persisted rows."""
        written: List[str] = []

        def write(name: str, fields: List[str], rows: Iterable[Dict[str, Any]]) -> None:
            materialized = iter(rows)
            try:
                first = next(materialized)
            except StopIteration:
                return
            path = self.run_dir / name
            with path.open("w", newline="", encoding="utf-8") as handle:
                os.chmod(path, 0o600)
                writer = csv.DictWriter(
                    handle, fieldnames=fields, extrasaction="ignore"
                )
                writer.writeheader()
                writer.writerow(safe_csv_row(first))
                writer.writerows(safe_csv_row(row) for row in materialized)
            written.append(str(path))

        share_fields = [
            "host",
            "share_name",
            "status",
            "skip_reason",
            "comment",
            "read_permission",
            "write_permission",
            "write_status",
            "write_check",
            "can_add_file",
            "can_add_subdirectory",
            "can_write_dac",
            "can_write_owner",
            "write_verified",
            "cleanup_succeeded",
            "unc_path",
            "scan_timestamp_utc",
        ]

        def share_rows() -> Iterable[Dict[str, Any]]:
            for row in self.connection.execute(
                """SELECT h.host, h.scan_timestamp_utc, s.name, s.payload_json, s.status
                   FROM shares s JOIN hosts h ON h.id=s.host_id
                   WHERE h.scan_id=? ORDER BY h.host, s.name""",
                (self.scan_id,),
            ):
                payload, permissions = json.loads(row[3]), {}
                permissions = payload.get("permissions", {})
                rights = permissions.get("write_rights", {})
                raw_probe = permissions.get("write_probe")
                probe: Dict[str, Any] = (
                    cast(Dict[str, Any], raw_probe)
                    if isinstance(raw_probe, dict)
                    else {}
                )
                cleanup: List[Optional[bool]] = []
                for created, deleted in (
                    ("file_created", "file_deleted"),
                    ("directory_created", "directory_deleted"),
                ):
                    value = probe.get(deleted) if probe.get(created) else None
                    cleanup.append(value if isinstance(value, bool) else None)
                attempted: List[bool] = [
                    value for value in cleanup if value is not None
                ]
                yield {
                    "host": row[0],
                    "share_name": row[2],
                    "status": row[4],
                    "skip_reason": payload.get("skip_reason", ""),
                    "comment": payload.get("comment", ""),
                    "read_permission": permissions.get("read"),
                    "write_permission": permissions.get("write"),
                    "write_status": permissions.get("write_status"),
                    "write_check": permissions.get("write_check"),
                    "can_add_file": rights.get("add_file"),
                    "can_add_subdirectory": rights.get("add_subdirectory"),
                    "can_write_dac": rights.get("write_dac"),
                    "can_write_owner": rights.get("write_owner"),
                    "write_verified": permissions.get("write_status") == "verified",
                    "cleanup_succeeded": all(attempted) if attempted else None,
                    "unc_path": payload.get("unc_path"),
                    "scan_timestamp_utc": row[1],
                }

        write("shrawler_shares.csv", share_fields, share_rows())
        file_fields = [
            "host",
            "share_name",
            "remote_path",
            "unc_path",
            "file_name",
            "size_bytes",
            "readable_size",
            "mtime_utc",
            "is_directory",
            "can_read",
            "can_write",
            "scan_timestamp_utc",
        ]
        write(
            "shrawler_files.csv",
            file_fields,
            (
                {**json.loads(row[0]), "can_read": None, "can_write": None}
                for row in self.connection.execute(
                    "SELECT payload_json FROM scan_files WHERE scan_id=? ORDER BY rowid",
                    (self.scan_id,),
                )
            ),
        )
        download_fields = [
            "host",
            "share_name",
            "remote_path",
            "unc_path",
            "local_filename",
            "local_path",
            "size_bytes",
            "actual_size_bytes",
            "sha256",
            "mtime_utc",
            "timestamp_utc",
            "nemesis_status",
            "nemesis_attempts",
            "nemesis_response_id",
            "nemesis_last_error",
        ]

        def download_rows() -> Iterable[Dict[str, Any]]:
            for payload in self._payloads("downloads"):
                nemesis = payload.get("nemesis", {})
                yield {
                    **payload,
                    "share_name": payload.get("share"),
                    "nemesis_status": nemesis.get("status"),
                    "nemesis_attempts": nemesis.get("attempts"),
                    "nemesis_response_id": nemesis.get("response_id"),
                    "nemesis_last_error": nemesis.get("last_error"),
                }

        write("shrawler_downloads.csv", download_fields, download_rows())
        match_fields = [
            "host",
            "share_name",
            "remote_path",
            "unc_path",
            "rule_name",
            "triage",
            "scope",
            "match_location",
            "matched_string",
            "timestamp_utc",
        ]
        write(
            "shrawler_snaffler_matches.csv",
            match_fields,
            self._payloads("snaffler_matches"),
        )
        return written

    def close(self) -> None:
        self._stop_commit.set()
        self._commit_thread.join(timeout=2)
        with self._lock:
            try:
                if self.connection.in_transaction:
                    self._touch(0, force=True)
                self.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                self.connection.close()
            finally:
                fcntl.flock(self._lock_file.fileno(), fcntl.LOCK_UN)
                self._lock_file.close()


__all__ = ["SCHEMA_VERSION", "ScanStore", "WorkspaceBusyError"]
