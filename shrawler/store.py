"""SQLite-backed scan persistence and export."""

import base64
import binascii
import calendar
import csv
import fcntl
import functools
import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, cast

from .coverage import DirectoryCoverage
from .output import safe_csv_row
from .search_index import (
    ensure as ensure_search_index,
    optimize as optimize_search_index,
    supported as search_supported,
)

SCHEMA_VERSION = 5

# Web-initiated retrievals share the downloads table but are not scan-time
# downloads, so scan summaries and JSON/CSV exports exclude them.
_SCAN_DOWNLOAD_FILTER = (
    "COALESCE(json_extract(payload_json, '$.source'), 'scan') != 'web'"
)


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


# --- Value encodings -------------------------------------------------------
#
# Timestamps are written by the scanner as ``datetime.isoformat()`` in UTC:
# ``YYYY-MM-DDTHH:MM:SS[.ffffff]+00:00``. Such a value is stored as integer
# epoch seconds plus an optional microsecond column, which is exact and keeps
# chronological (= lexicographic) order. Anything else is stored verbatim as
# text, and the empty string as NULL so it still sorts first. ``_ts_sql``
# renders the original text back.

_CANONICAL_TS = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{6}))?\+00:00"
)


@functools.lru_cache(maxsize=65536)
def encode_timestamp(text: str) -> Tuple[Any, Optional[int]]:
    """Return ``(seconds_or_text_or_None, microseconds_or_None)``."""
    if text == "":
        return None, None
    match = _CANONICAL_TS.fullmatch(text)
    if match is None:
        return text, None
    year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
    try:
        moment = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        return text, None
    seconds = calendar.timegm(moment.utctimetuple())
    fraction = match.group(7)
    return seconds, (int(fraction) if fraction is not None else None)


def decode_timestamp(value: Any, micro: Optional[int]) -> str:
    """Python mirror of ``_ts_sql``."""
    if value is None:
        return ""
    if isinstance(value, int):
        moment = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=value)
        text = (
            f"{moment.year:04d}-{moment.month:02d}-{moment.day:02d}T"
            f"{moment.hour:02d}:{moment.minute:02d}:{moment.second:02d}"
        )
        return text + ("" if micro is None else f".{micro:06d}") + "+00:00"
    return str(value)


def _ts_sql(value: str, micro: str) -> str:
    return (
        f"CASE typeof({value}) WHEN 'integer' THEN "
        f"strftime('%Y-%m-%dT%H:%M:%S', {value}, 'unixepoch') || "
        f"CASE WHEN {micro} IS NULL THEN '' ELSE printf('.%06d', {micro}) END || '+00:00' "
        f"WHEN 'null' THEN '' ELSE {value} END"
    )


def _readable_sql(size: str) -> str:
    """The printable size: a pure function of the byte count."""
    return f"""CASE
        WHEN {size} < 1024 THEN
            rtrim(rtrim(printf('%.2f', {size}), '0'), '.') || 'B'
        WHEN {size} < 1048576 THEN
            rtrim(rtrim(printf('%.2f', {size} / 1024.0), '0'), '.') || 'KB'
        WHEN {size} < 1073741824 THEN
            rtrim(rtrim(printf('%.2f', {size} / 1048576.0), '0'), '.') || 'MB'
        ELSE
            rtrim(rtrim(printf('%.2f', {size} / 1073741824.0), '0'), '.') || 'GB'
    END"""


# Public file tokens. A token is a keyed 64-bit Feistel permutation of the
# integer id, so it is unique, stable for the life of the database (ids are
# AUTOINCREMENT and never reused) and opaque without the per-database key in
# ``metadata``.

_PUBLIC_ID_KEY = "public_id_key"


def public_id_key(
    connection: sqlite3.Connection, schema: Optional[str] = None
) -> bytes:
    table = "metadata" if schema is None else f'"{schema}".metadata'
    row = connection.execute(
        f"SELECT value FROM {table} WHERE key=?", (_PUBLIC_ID_KEY,)
    ).fetchone()
    if row is None:
        raise ValueError("catalog has no public id key")
    return int(row[0]).to_bytes(8, "big", signed=True)


@functools.lru_cache(maxsize=16)
def _round_states(key: bytes) -> Tuple[Any, ...]:
    # Keyed BLAKE2b state per Feistel round; copying it skips the key setup.
    return tuple(
        hashlib.blake2b(digest_size=4, key=key, person=bytes([number]) * 16)
        for number in range(4)
    )


def _round(key: bytes, number: int, half: int) -> int:
    state = _round_states(key)[number].copy()
    state.update(half.to_bytes(4, "big"))
    return int.from_bytes(state.digest(), "big")


def derive_public_id(key: bytes, file_id: int) -> str:
    left, right = file_id >> 32, file_id & 0xFFFFFFFF
    for number in range(4):
        left, right = right, left ^ _round(key, number, right)
    block = ((left << 32) | right).to_bytes(8, "big")
    return base64.urlsafe_b64encode(block).decode("ascii").rstrip("=")


def _underive_public_id(key: bytes, token: str) -> Optional[int]:
    if len(token) != 11:
        return None
    try:
        block = base64.urlsafe_b64decode(token + "=")
    except (binascii.Error, ValueError):
        return None
    if len(block) != 8 or base64.urlsafe_b64encode(block).decode("ascii")[:11] != token:
        return None
    value = int.from_bytes(block, "big")
    left, right = value >> 32, value & 0xFFFFFFFF
    for number in reversed(range(4)):
        left, right = right ^ _round(key, number, left), left
    return (left << 32) | right


def public_id(key: bytes, file_id: int) -> str:
    """The opaque token callers see for a catalog row."""
    return derive_public_id(key, int(file_id))


def resolve_public_id(
    connection: sqlite3.Connection, token: str, schema: Optional[str] = None
) -> Optional[int]:
    """Map a token back to its catalog row id, or None when it is unknown."""
    file_id = _underive_public_id(public_id_key(connection, schema), token)
    if file_id is None or file_id >= 1 << 63:
        return None
    table = "catalog_files" if schema is None else f'"{schema}".catalog_files'
    row = connection.execute(
        f"SELECT id FROM {table} WHERE id=?", (file_id,)
    ).fetchone()
    return int(row[0]) if row else None


def register_public_id_function(
    connection: sqlite3.Connection, key: bytes, name: str = "public_id_token"
) -> None:
    """Register a SQL function that maps a catalog row id to its token."""

    def render(value: Any) -> str:
        return public_id(key, int(value))

    connection.create_function(name, 1, render, deterministic=True)


# --- Catalog schema (version 5) -------------------------------------------
#
# One row per directory (host, share and the remote path up to and including
# its last ``/``) and one narrow row per file: directory id, name, extension
# id, size and integer timestamps. ``files`` and ``scan_files`` are views with
# the exact column set and values of the version 4 tables, so readers and
# exports keep working; the views store nothing.

_UNC_DIR_SQL = "'\\\\' || {d}.host || '\\' || {d}.share || '\\' || ltrim({d}.path, '/')"

_CATALOG_TABLES = """
CREATE TABLE IF NOT EXISTS catalog_dirs (
    id INTEGER PRIMARY KEY,
    host TEXT NOT NULL,
    share TEXT NOT NULL,
    path TEXT NOT NULL,
    file_count INTEGER NOT NULL DEFAULT 0,
    size_bytes INTEGER NOT NULL DEFAULT 0,
    search_text TEXT GENERATED ALWAYS AS (
        lower(host) || ' ' || lower(share) || ' ' || lower(path) || ' ' ||
        lower('\\\\' || host || '\\' || share || '\\' || ltrim(path, '/'))
    ) VIRTUAL
);
CREATE INDEX IF NOT EXISTS catalog_dirs_sort_idx ON catalog_dirs(
    host COLLATE NOCASE, share COLLATE NOCASE, path COLLATE NOCASE);
CREATE TABLE IF NOT EXISTS catalog_extensions (
    id INTEGER PRIMARY KEY,
    extension TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS catalog_extensions_sort_idx
    ON catalog_extensions(extension COLLATE NOCASE);
CREATE TABLE IF NOT EXISTS catalog_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dir_id INTEGER NOT NULL REFERENCES catalog_dirs(id),
    name TEXT NOT NULL,
    ext_id INTEGER NOT NULL REFERENCES catalog_extensions(id),
    size_bytes INTEGER NOT NULL,
    mtime,
    mtime_us INTEGER,
    scan_ts,
    scan_ts_us INTEGER
);
-- Per-scan observations: which share of which scan saw the file, in
-- discovery order (seq). readable_size is NULL when it equals the formula for
-- the observed size. The observed size and timestamps are the file row's
-- current values unless scan_observation_history holds the row: those values
-- are written there just before the file row changes (see
-- catalog_files_observation_history), so every scan keeps what it saw.
CREATE TABLE IF NOT EXISTS scan_observations (
    file_id INTEGER NOT NULL REFERENCES catalog_files(id) ON DELETE CASCADE,
    share_id INTEGER NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    readable_size TEXT,
    PRIMARY KEY(file_id, share_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS scan_observation_history (
    file_id INTEGER NOT NULL,
    share_id INTEGER NOT NULL,
    size_bytes INTEGER NOT NULL,
    mtime,
    mtime_us INTEGER,
    scan_ts,
    scan_ts_us INTEGER,
    PRIMARY KEY(file_id, share_id),
    FOREIGN KEY(file_id, share_id) REFERENCES scan_observations(file_id, share_id)
        ON DELETE CASCADE
) WITHOUT ROWID;
-- Version 4 observation rows whose share does not resolve to their scan are
-- kept verbatim here (normally empty).
CREATE TABLE IF NOT EXISTS scan_files_unmapped (
    scan_id TEXT NOT NULL,
    share_id INTEGER NOT NULL,
    file_id INTEGER NOT NULL,
    size_bytes INTEGER,
    readable_size TEXT,
    mtime_utc TEXT,
    scan_timestamp_utc TEXT,
    seq INTEGER NOT NULL
);
"""

# Indexes the writer needs while a scan is running: the (directory, name)
# lookup behind every upsert and the per-share observation index used by
# exports and share deletes.
_CATALOG_WRITE_INDEXES = (
    "CREATE INDEX IF NOT EXISTS catalog_files_dir_idx "
    "ON catalog_files(dir_id, name COLLATE NOCASE)",
    "CREATE INDEX IF NOT EXISTS scan_observations_share_idx ON scan_observations(share_id, seq)",
)

_CATALOG_TRIGGERS = """
-- catalog_dirs_sort_idx is NOCASE; enforce (host, share, path) uniqueness
-- under the binary comparison with one probe of it instead of a second index.
CREATE TRIGGER IF NOT EXISTS catalog_dirs_unique_insert BEFORE INSERT ON catalog_dirs
WHEN EXISTS (SELECT 1 FROM catalog_dirs WHERE host = NEW.host COLLATE NOCASE
             AND share = NEW.share COLLATE NOCASE AND path = NEW.path COLLATE NOCASE
             AND host = NEW.host AND share = NEW.share AND path = NEW.path)
BEGIN
    SELECT RAISE(ABORT, 'UNIQUE constraint failed: catalog_dirs.host, catalog_dirs.share, catalog_dirs.path');
END;
CREATE TRIGGER IF NOT EXISTS catalog_dirs_unique_update BEFORE UPDATE OF host, share, path
ON catalog_dirs
WHEN EXISTS (SELECT 1 FROM catalog_dirs WHERE host = NEW.host COLLATE NOCASE
             AND share = NEW.share COLLATE NOCASE AND path = NEW.path COLLATE NOCASE
             AND host = NEW.host AND share = NEW.share AND path = NEW.path AND id != OLD.id)
BEGIN
    SELECT RAISE(ABORT, 'UNIQUE constraint failed: catalog_dirs.host, catalog_dirs.share, catalog_dirs.path');
END;
-- The sort index is NOCASE, so (directory, name) uniqueness under the
-- original binary comparison is enforced here with one probe of that index.
CREATE TRIGGER IF NOT EXISTS catalog_files_unique_insert BEFORE INSERT ON catalog_files
WHEN EXISTS (SELECT 1 FROM catalog_files WHERE dir_id = NEW.dir_id
             AND name = NEW.name COLLATE NOCASE AND name = NEW.name)
BEGIN
    SELECT RAISE(ABORT, 'UNIQUE constraint failed: files.host, files.share, files.remote_path');
END;
CREATE TRIGGER IF NOT EXISTS catalog_files_unique_update BEFORE UPDATE OF dir_id, name
ON catalog_files
WHEN EXISTS (SELECT 1 FROM catalog_files WHERE dir_id = NEW.dir_id
             AND name = NEW.name COLLATE NOCASE AND name = NEW.name AND id != OLD.id)
BEGIN
    SELECT RAISE(ABORT, 'UNIQUE constraint failed: files.host, files.share, files.remote_path');
END;
-- Per-directory totals make tree browsing independent of the file count.
CREATE TRIGGER IF NOT EXISTS catalog_files_count_insert AFTER INSERT ON catalog_files BEGIN
    UPDATE catalog_dirs SET file_count = file_count + 1, size_bytes = size_bytes + NEW.size_bytes
    WHERE id = NEW.dir_id;
END;
CREATE TRIGGER IF NOT EXISTS catalog_files_count_delete AFTER DELETE ON catalog_files BEGIN
    UPDATE catalog_dirs SET file_count = file_count - 1, size_bytes = size_bytes - OLD.size_bytes
    WHERE id = OLD.dir_id;
END;
CREATE TRIGGER IF NOT EXISTS catalog_files_count_update AFTER UPDATE OF dir_id, size_bytes
ON catalog_files BEGIN
    UPDATE catalog_dirs SET file_count = file_count - 1, size_bytes = size_bytes - OLD.size_bytes
    WHERE id = OLD.dir_id;
    UPDATE catalog_dirs SET file_count = file_count + 1, size_bytes = size_bytes + NEW.size_bytes
    WHERE id = NEW.dir_id;
END;
-- When a file's size or timestamps change, every observation that was
-- sharing them (no history row yet) receives the outgoing values, so each
-- scan keeps exactly what it saw.
CREATE TRIGGER IF NOT EXISTS catalog_files_observation_history
AFTER UPDATE OF size_bytes, mtime, mtime_us, scan_ts, scan_ts_us ON catalog_files
WHEN NEW.size_bytes IS NOT OLD.size_bytes OR NEW.mtime IS NOT OLD.mtime
  OR NEW.mtime_us IS NOT OLD.mtime_us OR NEW.scan_ts IS NOT OLD.scan_ts
  OR NEW.scan_ts_us IS NOT OLD.scan_ts_us
BEGIN
    INSERT OR IGNORE INTO scan_observation_history(file_id, share_id, size_bytes, mtime,
        mtime_us, scan_ts, scan_ts_us)
    SELECT file_id, share_id, OLD.size_bytes, OLD.mtime, OLD.mtime_us, OLD.scan_ts,
        OLD.scan_ts_us
    FROM scan_observations WHERE file_id = OLD.id;
END;
"""

# The exported columns of one observation row: catalog_files f, catalog_dirs d,
# scan_observations o and its optional scan_observation_history p.
_OBSERVED_COLUMNS = f"""
       d.host AS host,
       d.share AS share,
       d.path || f.name AS remote_path,
       {_UNC_DIR_SQL.format(d="d")} || f.name AS unc_path,
       f.name AS file_name,
       coalesce(p.size_bytes, f.size_bytes) AS size_bytes,
       coalesce(o.readable_size, {_readable_sql("coalesce(p.size_bytes, f.size_bytes)")})
           AS readable_size,
       CASE WHEN p.file_id IS NULL THEN {_ts_sql("f.mtime", "f.mtime_us")}
            ELSE {_ts_sql("p.mtime", "p.mtime_us")} END AS mtime_utc,
       CASE WHEN p.file_id IS NULL THEN {_ts_sql("f.scan_ts", "f.scan_ts_us")}
            ELSE {_ts_sql("p.scan_ts", "p.scan_ts_us")} END AS scan_timestamp_utc,
       o.seq AS seq"""
_OBSERVED_FROM = """
FROM scan_observations o
JOIN catalog_files f ON f.id = o.file_id
JOIN catalog_dirs d ON d.id = f.dir_id
LEFT JOIN scan_observation_history p ON p.file_id = o.file_id AND p.share_id = o.share_id"""
# The same columns for a verbatim version 4 row in scan_files_unmapped u
# (NULL meant "the file's value", as it did in version 4).
_UNMAPPED_COLUMNS = f"""
       d.host, d.share, d.path || f.name, {_UNC_DIR_SQL.format(d="d")} || f.name, f.name,
       coalesce(u.size_bytes, f.size_bytes),
       coalesce(u.readable_size, {_readable_sql("f.size_bytes")}),
       coalesce(u.mtime_utc, {_ts_sql("f.mtime", "f.mtime_us")}),
       coalesce(u.scan_timestamp_utc, {_ts_sql("f.scan_ts", "f.scan_ts_us")}),
       u.seq"""
_UNMAPPED_FROM = """
FROM scan_files_unmapped u
JOIN catalog_files f ON f.id = u.file_id
JOIN catalog_dirs d ON d.id = f.dir_id"""

_CATALOG_VIEWS = f"""
CREATE VIEW IF NOT EXISTS files AS
SELECT f.id AS id,
       d.host AS host,
       d.share AS share,
       d.path || f.name AS remote_path,
       f.name AS file_name,
       e.extension AS extension,
       f.size_bytes AS size_bytes,
       {_readable_sql("f.size_bytes")} AS readable_size,
       CASE WHEN rtrim(d.path, '/') = '' THEN '/' ELSE rtrim(d.path, '/') END AS parent_path,
       {_UNC_DIR_SQL.format(d="d")} || f.name AS unc_path,
       {_ts_sql("f.mtime", "f.mtime_us")} AS mtime_utc,
       {_ts_sql("f.scan_ts", "f.scan_ts_us")} AS scan_timestamp_utc,
       lower(d.host) || ' ' || lower(d.share) || ' ' || lower(d.path || f.name) || ' ' ||
       lower({_UNC_DIR_SQL.format(d="d")} || f.name) || ' ' || lower(f.name) || ' ' ||
       lower(e.extension) AS search_text
FROM catalog_files f
JOIN catalog_dirs d ON d.id = f.dir_id
JOIN catalog_extensions e ON e.id = f.ext_id;
CREATE VIEW IF NOT EXISTS scan_files AS
SELECT h.scan_id AS scan_id,
       o.share_id AS share_id,
       o.file_id AS file_id,
       coalesce(p.size_bytes, f.size_bytes) AS size_bytes,
       coalesce(o.readable_size, {_readable_sql("coalesce(p.size_bytes, f.size_bytes)")})
           AS readable_size,
       CASE WHEN p.file_id IS NULL THEN {_ts_sql("f.mtime", "f.mtime_us")}
            ELSE {_ts_sql("p.mtime", "p.mtime_us")} END AS mtime_utc,
       CASE WHEN p.file_id IS NULL THEN {_ts_sql("f.scan_ts", "f.scan_ts_us")}
            ELSE {_ts_sql("p.scan_ts", "p.scan_ts_us")} END AS scan_timestamp_utc,
       o.seq AS seq
FROM scan_observations o
JOIN shares s ON s.id = o.share_id
JOIN hosts h ON h.id = s.host_id
LEFT JOIN catalog_files f ON f.id = o.file_id
LEFT JOIN scan_observation_history p ON p.file_id = o.file_id AND p.share_id = o.share_id
UNION ALL
SELECT u.scan_id, u.share_id, u.file_id,
       coalesce(u.size_bytes, f.size_bytes),
       coalesce(u.readable_size, {_readable_sql("f.size_bytes")}),
       coalesce(u.mtime_utc, {_ts_sql("f.mtime", "f.mtime_us")}),
       coalesce(u.scan_timestamp_utc, {_ts_sql("f.scan_ts", "f.scan_ts_us")}),
       u.seq
FROM scan_files_unmapped u LEFT JOIN catalog_files f ON f.id = u.file_id;
"""

# Sort indexes that are only needed by readers. A fresh inventory creates them
# after the bulk load (build_file_indexes) so their leaves are packed. Every
# entry is the key plus the implicit rowid, which is also the tie-break.
_CATALOG_INDEXES = (
    "CREATE INDEX IF NOT EXISTS catalog_files_name_idx ON catalog_files(name COLLATE NOCASE)",
    "CREATE INDEX IF NOT EXISTS catalog_files_ext_idx ON catalog_files(ext_id)",
    "CREATE INDEX IF NOT EXISTS catalog_files_size_idx ON catalog_files(size_bytes)",
    "CREATE INDEX IF NOT EXISTS catalog_files_mtime_idx ON catalog_files(mtime, mtime_us)",
)

# Tables other than the catalog that every inventory has.
_COMMON_DDL = """
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
CREATE INDEX IF NOT EXISTS matches_scan_share_idx ON snaffler_matches(scan_id, share_id);
CREATE INDEX IF NOT EXISTS downloads_scan_share_idx ON downloads(scan_id, share_id);
CREATE INDEX IF NOT EXISTS matches_lookup_idx ON snaffler_matches(scan_id, share_id, remote_path_key);
CREATE INDEX IF NOT EXISTS downloads_lookup_idx ON downloads(scan_id, share_id, remote_path_key);
"""


def _execute_script(connection: sqlite3.Connection, script: str) -> None:
    """Run a multi-statement script without ``executescript``'s implicit COMMIT."""
    statement = ""
    for line in script.splitlines(keepends=True):
        statement += line
        if sqlite3.complete_statement(statement):
            connection.execute(statement)
            statement = ""
    if statement.strip():
        connection.execute(statement)


def _compact(connection: sqlite3.Connection) -> None:
    """VACUUM into packed pages, then return the WAL's copy to the disk.

    The temporary copy is kept in memory for databases up to 1 GiB so the
    transient disk cost is the WAL alone. A failure (for example a full disk)
    leaves the database valid, merely unpacked.
    """
    pages, page_size = (
        int(connection.execute(f"PRAGMA {name}").fetchone()[0])
        for name in ("page_count", "page_size")
    )
    in_memory = pages * page_size <= 1 << 30
    if in_memory:
        connection.execute("PRAGMA temp_store=MEMORY")
    # Takes effect with this VACUUM; see ScanStore._configure.
    connection.execute("PRAGMA auto_vacuum=INCREMENTAL")
    try:
        connection.execute("VACUUM")
    except sqlite3.Error:
        pass
    finally:
        if in_memory:
            connection.execute("PRAGMA temp_store=DEFAULT")
    connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")


def _create_catalog(connection: sqlite3.Connection) -> None:
    _execute_script(connection, _COMMON_DDL)
    _execute_script(connection, _CATALOG_TABLES)
    for statement in _CATALOG_WRITE_INDEXES:
        connection.execute(statement)
    _execute_script(connection, _CATALOG_TRIGGERS)
    _execute_script(connection, _CATALOG_VIEWS)
    connection.execute(
        "INSERT OR IGNORE INTO metadata(key, value) VALUES (?, ?)",
        (_PUBLIC_ID_KEY, secrets.randbits(63)),
    )


def _file_payload(row: sqlite3.Row) -> Dict[str, Any]:
    """Canonical discovered-file payload, rebuilt from stored columns."""
    return {
        "host": str(row["host"]),
        "share_name": str(row["share"]),
        "remote_path": str(row["remote_path"]),
        "unc_path": str(row["unc_path"]),
        "file_name": str(row["file_name"]),
        "size_bytes": int(row["size_bytes"]),
        "readable_size": str(row["readable_size"]),
        "mtime_utc": str(row["mtime_utc"]),
        "is_directory": False,
        "scan_timestamp_utc": str(row["scan_timestamp_utc"]),
    }


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
        # Cheap progress counters (seeded once from SQL, then delta-tracked).
        self._host_count = int(
            self.connection.execute(
                "SELECT COUNT(*) FROM hosts WHERE scan_id=?", (self.scan_id,)
            ).fetchone()[0]
        )
        self._share_count = int(
            self.connection.execute(
                """SELECT COUNT(*) FROM shares s JOIN hosts h ON h.id=s.host_id
                   WHERE h.scan_id=?""",
                (self.scan_id,),
            ).fetchone()[0]
        )
        self._seen_hosts: Set[str] = {
            str(row[0])
            for row in self.connection.execute(
                "SELECT host FROM hosts WHERE scan_id=?", (self.scan_id,)
            )
        }
        self._seen_shares: Set[Tuple[str, str]] = {
            (str(row[0]), str(row[1]))  # host, share name
            for row in self.connection.execute(
                """SELECT h.host, s.name FROM shares s JOIN hosts h ON h.id=s.host_id
                   WHERE h.scan_id=?""",
                (self.scan_id,),
            )
        }
        # share_id per (host, share): only _share_id resolves it; add_file hits
        # this cache instead of a hosts/shares JOIN per file.
        self._share_ids: Dict[Tuple[str, str], int] = {}
        # Catalog directory and extension ids; bounded, refilled from SQL.
        self._dir_ids: Dict[Tuple[str, str, str], int] = {}
        self._ext_ids: Dict[str, int] = {}
        # Discovery order of this scan's observations (resumes continue it).
        self._seq = int(
            self.connection.execute(
                """SELECT coalesce(max((SELECT max(seq) FROM scan_observations o
                                        WHERE o.share_id = s.id)), 0)
                   FROM shares s JOIN hosts h ON h.id = s.host_id WHERE h.scan_id = ?""",
                (self.scan_id,),
            ).fetchone()[0]
        )

    def _configure(self) -> None:
        # Incremental auto-vacuum lets later deletes (resumed scans, pruned runs)
        # return pages instead of leaving the file at its high-water mark. It
        # must precede journal_mode=WAL, which writes the header of a new file
        # and would freeze auto_vacuum at NONE; existing files adopt it at
        # their next VACUUM.
        self.connection.execute("PRAGMA auto_vacuum=INCREMENTAL")
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
        if 0 < version < SCHEMA_VERSION:
            raise ValueError(
                f"database schema {version} is not supported; "
                f"recreate the workspace to upgrade to schema {SCHEMA_VERSION}"
            )
        _create_catalog(self.connection)
        self.connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        self.connection.commit()
        # A fresh inventory has no rows yet: build_file_indexes() creates the
        # query indexes after the bulk load so their leaves are packed. A
        # reopened inventory already holds rows, so pack any missing index now.
        if self.connection.execute("SELECT 1 FROM catalog_files LIMIT 1").fetchone():
            self.build_file_indexes()
        # New inventories stay substring-indexed as they grow.
        if (
            not self.connection.execute(
                "SELECT 1 FROM catalog_files LIMIT 1"
            ).fetchone()
            and search_supported()
        ):
            ensure_search_index(self.connection)
            self.connection.commit()

    def build_file_indexes(self) -> None:
        """Create the catalog sort indexes once the bulk load has finished.

        Creating them on an empty table and then inserting rows in discovery
        order leaves the B-tree leaves roughly 30% empty. Building them after
        the rows exist lets SQLite sort and write packed leaves. When anything
        was built, the substring index is merged into one segment and the
        planner statistics are refreshed. A no-op when everything exists.
        """
        with self._lock:
            existing = {
                str(row[0])
                for row in self.connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='index'"
                )
            }
            missing = [
                statement
                for statement in _CATALOG_INDEXES
                if statement.split(" IF NOT EXISTS ")[1].split()[0] not in existing
            ]
            if not missing:
                return
            for statement in missing:
                self.connection.execute(statement)
            optimize_search_index(self.connection)
            self.connection.execute("PRAGMA analysis_limit=1000")
            self.connection.execute("ANALYZE")
            self.connection.commit()
            # First build after a bulk load: the writer's lookup index and the
            # WITHOUT ROWID observation b-trees were filled in discovery
            # order (~88% full) and the FTS merge freed its old segments.
            # One rewrite packs them; later scans only append.
            _compact(self.connection)

    def _select_resume(self, value: str, mode: str) -> Tuple[str, str, str]:
        if value:
            # An explicit ID may reopen a completed scan to expand depth or
            # scope; the default only resumes genuinely incomplete work.
            row = self.connection.execute(
                """SELECT id, short_id, run_dir, mode FROM scans
                   WHERE id=? OR short_id=?""",
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
            if host not in self._seen_hosts:
                self._seen_hosts.add(host)
                self._host_count += 1
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
            if (host, share) not in self._seen_shares:
                self._seen_shares.add((host, share))
                self._share_count += 1
            self._touch(force=status == "complete")

    def _share_id(self, host: str, share: str) -> int:
        key = (host, share)
        cached = self._share_ids.get(key)
        if cached is not None:
            return cached
        row = self.connection.execute(
            """SELECT s.id FROM shares s JOIN hosts h ON h.id=s.host_id
               WHERE h.scan_id=? AND h.host=? AND s.name=?""",
            (self.scan_id, host, share),
        ).fetchone()
        if row is None:
            raise ValueError(f"share has not been recorded: {host}\\{share}")
        value = int(row[0])
        self._share_ids[key] = value
        return value

    def _dir_id(self, host: str, share: str, folder: str) -> int:
        key = (host, share, folder)
        cached = self._dir_ids.get(key)
        if cached is not None:
            return cached
        row = self.connection.execute(
            "SELECT id FROM catalog_dirs WHERE host=?1 COLLATE NOCASE "
            "AND share=?2 COLLATE NOCASE AND path=?3 COLLATE NOCASE "
            "AND host=?1 AND share=?2 AND path=?3",
            key,
        ).fetchone()
        if row is None:
            value = int(
                self.connection.execute(
                    "INSERT INTO catalog_dirs(host, share, path) VALUES (?, ?, ?) RETURNING id",
                    key,
                ).fetchone()[0]
            )
        else:
            value = int(row[0])
        if len(self._dir_ids) >= 100_000:
            self._dir_ids.clear()
        self._dir_ids[key] = value
        return value

    def _ext_id(self, extension: str) -> int:
        cached = self._ext_ids.get(extension)
        if cached is not None:
            return cached
        row = self.connection.execute(
            "SELECT id FROM catalog_extensions WHERE extension=?", (extension,)
        ).fetchone()
        if row is None:
            value = int(
                self.connection.execute(
                    "INSERT INTO catalog_extensions(extension) VALUES (?) RETURNING id",
                    (extension,),
                ).fetchone()[0]
            )
        else:
            value = int(row[0])
        self._ext_ids[extension] = value
        return value

    def add_file(self, host: str, share: str, payload: Dict[str, Any]) -> bool:
        remote = str(payload["remote_path"])
        # The directory part keeps its trailing "/" so remote_path is exactly
        # path || name. The extension is still taken from the payload's file
        # name: Path.suffix semantics (dotfiles, .tar.gz) are not a function of
        # the stored name alone.
        cut = remote.rfind("/") + 1
        folder, name = remote[:cut], remote[cut:]
        extension = Path(str(payload["file_name"])).suffix.lower()
        size = int(payload.get("size_bytes") or 0)
        mtime = encode_timestamp(str(payload.get("mtime_utc") or ""))
        stamp = encode_timestamp(str(payload.get("scan_timestamp_utc") or ""))
        with self._lock:
            dir_id = self._dir_id(host, share, folder)
            values = (self._ext_id(extension), size, *mtime, *stamp)
            row = self.connection.execute(
                "SELECT id, ext_id, size_bytes, mtime, mtime_us, scan_ts, scan_ts_us "
                "FROM catalog_files WHERE dir_id=? AND name=? COLLATE NOCASE AND name=?",
                (dir_id, name, name),
            ).fetchone()
            if row is None:
                file_id = int(
                    self.connection.execute(
                        "INSERT INTO catalog_files(dir_id, name, ext_id, size_bytes, mtime, "
                        "mtime_us, scan_ts, scan_ts_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                        "RETURNING id",
                        (dir_id, name, *values),
                    ).fetchone()[0]
                )
            else:
                file_id = int(row[0])
                if tuple(row[1:]) != values:
                    self.connection.execute(
                        "UPDATE catalog_files SET ext_id=?, size_bytes=?, mtime=?, mtime_us=?, "
                        "scan_ts=?, scan_ts_us=? WHERE id=?",
                        (*values, file_id),
                    )
            share_id = self._share_id(host, share)
            # The observation equals the file row just written, so it is
            # stored as shared (NULL) values; see scan_observations.
            cursor = self.connection.execute(
                "INSERT OR IGNORE INTO scan_observations(file_id, share_id, seq, readable_size) "
                "VALUES (:file, :share, :seq, CASE WHEN :readable IS "
                + _readable_sql(":size")
                + " THEN NULL ELSE :readable END)",
                {
                    "file": file_id,
                    "share": share_id,
                    "seq": self._seq + 1,
                    "readable": str(payload.get("readable_size") or ""),
                    "size": size,
                },
            )
            if cursor.rowcount > 0:
                self._seq += 1
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
                (
                    self.scan_id,
                    self._share_id(host, share),
                    _path_key(stored.get("remote_path")),
                    _json(stored),
                ),
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
                (
                    _path_key(stored.get("remote_path")),
                    _json(stored),
                    download_id,
                    self.scan_id,
                ),
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
                (
                    self.scan_id,
                    share_id,
                    _path_key(payload.get("remote_path")),
                    _json(payload),
                ),
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
                f"""SELECT
                   (SELECT COUNT(*) FROM hosts WHERE scan_id=?),
                   (SELECT COUNT(*) FROM shares s JOIN hosts h ON h.id=s.host_id
                      WHERE h.scan_id=?),
                   ((SELECT COUNT(*) FROM scan_observations o JOIN shares s ON s.id=o.share_id
                       JOIN hosts h ON h.id=s.host_id WHERE h.scan_id=?)
                    + (SELECT COUNT(*) FROM scan_files_unmapped WHERE scan_id=?)),
                   (SELECT COUNT(*) FROM downloads WHERE scan_id=?
                      AND {_SCAN_DOWNLOAD_FILTER}),
                   (SELECT COUNT(*) FROM snaffler_matches WHERE scan_id=?)""",
                (self.scan_id,) * 6,
            ).fetchone()
            download_rows = [
                json.loads(row[0])
                for row in self.connection.execute(
                    f"SELECT payload_json FROM downloads WHERE scan_id=? "
                    f"AND {_SCAN_DOWNLOAD_FILTER}",
                    (self.scan_id,),
                )
            ]
            downloaded_bytes = int(
                self.connection.execute(
                    f"""SELECT COALESCE(SUM(json_extract(payload_json,'$.actual_size_bytes')),0)
                     FROM downloads WHERE scan_id=? AND {_SCAN_DOWNLOAD_FILTER}""",
                    (self.scan_id,),
                ).fetchone()[0]
            )
            return {
                "hosts_attempted": int(counts[0]),
                "host_statuses": statuses,
                "shares_enumerated": int(counts[1]),
                "files_seen": int(counts[2]),
                "files_downloaded": int(counts[3]),
                "downloaded_bytes": downloaded_bytes,
                "snaffler_matches": int(counts[4]),
                "downloads": download_rows,
            }

    def progress_counts(self) -> Tuple[int, int]:
        """Return lightweight host/share counts for terminal progress."""
        # Delta-tracked in memory at upsert time; no COUNT queries per tick.
        with self._lock:
            return self._host_count, self._share_count

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
        # The bulk load is done; pack the catalog query indexes now.
        self.build_file_indexes()

    def _hosts(self) -> List[sqlite3.Row]:
        return list(
            self.connection.execute(
                "SELECT * FROM hosts WHERE scan_id=? ORDER BY host COLLATE NOCASE",
                (self.scan_id,),
            )
        )

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
                        # Every row of this scan's share is a mapped observation.
                        f"SELECT {_OBSERVED_COLUMNS} {_OBSERVED_FROM} "
                        "WHERE o.share_id=? ORDER BY o.seq",
                        (share["id"],),
                    )
                    for index, row in enumerate(rows):
                        if index:
                            handle.write(",")
                        handle.write(_json(_file_payload(row)))
                    handle.write("]," + _json("downloaded_files") + ":[")
                    rows = self.connection.execute(
                        f"""SELECT payload_json FROM downloads
                           WHERE scan_id=? AND share_id=?
                             AND {_SCAN_DOWNLOAD_FILTER} ORDER BY id""",
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

    def _payloads(
        self, table: str, scan_downloads_only: bool = False
    ) -> Iterable[Dict[str, Any]]:
        query = f"SELECT payload_json FROM {table} WHERE scan_id=?"
        if scan_downloads_only:
            query += f" AND {_SCAN_DOWNLOAD_FILTER}"
        query += " ORDER BY id"
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
                {**_file_payload(row), "can_read": None, "can_write": None}
                for row in self.connection.execute(
                    f"""SELECT {_OBSERVED_COLUMNS} {_OBSERVED_FROM}
                       WHERE o.share_id IN (SELECT s.id FROM shares s
                                            JOIN hosts h ON h.id=s.host_id WHERE h.scan_id=?1)
                       UNION ALL
                       SELECT {_UNMAPPED_COLUMNS} {_UNMAPPED_FROM} WHERE u.scan_id=?1
                       ORDER BY seq""",
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
            for payload in self._payloads("downloads", scan_downloads_only=True):
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


__all__ = [
    "SCHEMA_VERSION",
    "ScanStore",
    "WorkspaceBusyError",
    "public_id",
    "public_id_key",
    "register_public_id_function",
    "resolve_public_id",
]
