"""Local-only, dependency-free WebUI for saved Shrawler inventories."""

import json
import logging
import os
import re
import secrets
import shutil
import sqlite3
import tempfile
import threading
import urllib.parse
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, cast

from .collection import CollectionBusyError, CollectionQueue, smb_retriever
from .output import escape_terminal
from .smb import SMBAuth, close_smb, connect_smb
from .store import SCHEMA_VERSION
from .triage.review import ReviewStore
from .triage.service import TriageBusyError, TriageService
from .triage.storage import (
    catalog as triage_catalog,
    explain as triage_explain,
    list_results as triage_list,
)

TEXT_EXTENSIONS = frozenset(
    ".txt .log .csv .json .xml .ini .conf .config .cnf .properties .prop .yaml .yml .md .rst .py .js .ts .jsx .tsx .java .cs .go .rs .rb .php .ps1 .bat .cmd .vbs .sh .sql .pem .key".split()
)
BINARY_EXTENSIONS = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".pdf": "application/pdf",
}
MAGIC = {
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".gif": (b"GIF87a", b"GIF89a"),
    ".webp": (b"RIFF",),
    ".pdf": (b"%PDF-",),
}
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; frame-src blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
}


@dataclass
class FileRecord:
    id: str
    host: str
    share: str
    remote_path: str
    unc_path: str
    file_name: str
    extension: str
    size_bytes: int
    readable_size: str
    mtime_utc: str
    scan_timestamp_utc: str
    search_text: str
    rule_matches: Tuple[Dict[str, Any], ...] = ()
    permissions: Dict[str, Any] = field(default_factory=dict)
    collection_status: str = "unknown"
    collection_detail: Optional[Dict[str, Any]] = None
    metadata_scan_timestamp_utc: str = ""

    def public(self) -> Dict[str, Any]:
        value = asdict(self)
        value.pop("search_text")
        value["rule_matches"] = list(self.rule_matches)
        value["permissions"] = self.permissions or {}
        return value


class FileIndex:
    def __init__(
        self, path: Path, records: List[FileRecord], page_size: int, skipped: int = 0
    ) -> None:
        self.path = path
        self.records = records
        self.by_id = {row.id: row for row in records}
        self.page_size = min(max(page_size, 1), 500)
        self.skipped = skipped

    @classmethod
    def load(cls, path: Path, page_size: int = 100) -> "FileIndex":
        with path.expanduser().resolve().open(encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, dict) or data.get("_schema") != {
            "name": "shrawler-results",
            "version": 3,
        }:
            raise ValueError("RESULTS must be a schema-v3 shrawler-results JSON object")
        rows: List[FileRecord] = []
        skipped = 0
        seen: Dict[Tuple[str, str, str], FileRecord] = {}
        for host, host_data in data.items():
            if host.startswith("_"):
                continue
            if not isinstance(host_data, dict) or not isinstance(
                host_data.get("shares"), dict
            ):
                skipped += 1
                continue
            for share, share_data in host_data["shares"].items():
                if not isinstance(share_data, dict) or not isinstance(
                    share_data.get("discovered_files"), list
                ):
                    continue
                for item in share_data["discovered_files"]:
                    if not isinstance(item, dict):
                        skipped += 1
                        continue
                    remote = item.get("remote_path")
                    name = item.get("file_name")
                    if (
                        not all(
                            isinstance(x, str) and x
                            for x in (host, share, remote, name)
                        )
                        or "\0" in remote
                        or remote.endswith(("/", "\\"))
                    ):
                        skipped += 1
                        continue
                    key = (host, share, remote)
                    if key in seen:
                        continue

                    def clean(value: Any) -> str:
                        return str(value or "").replace("\0", "")

                    extension = Path(name).suffix.lower()
                    unc = clean(item.get("unc_path")) or "\\\\{}\\{}\\{}".format(
                        host, share, remote.lstrip("/\\").replace("/", "\\")
                    )
                    search = " ".join(
                        (host, share, remote.replace("\\", "/"), unc, name, extension)
                    ).casefold()
                    try:
                        size_bytes = max(int(item.get("size_bytes") or 0), 0)
                    except (TypeError, ValueError):
                        skipped += 1
                        continue
                    metadata = cls._payload_metadata(item, share_data)
                    record = FileRecord(
                        secrets.token_urlsafe(16),
                        host,
                        share,
                        remote,
                        unc,
                        clean(name),
                        extension,
                        size_bytes,
                        clean(item.get("readable_size")),
                        clean(item.get("mtime_utc")),
                        clean(item.get("scan_timestamp_utc")),
                        search,
                        **metadata,
                    )
                    seen[key] = record
                    rows.append(record)
        rows.sort(
            key=lambda row: (
                row.host.casefold(),
                row.share.casefold(),
                row.remote_path.casefold(),
                row.file_name.casefold(),
            )
        )
        if not rows:
            raise ValueError("RESULTS contains no valid retrievable discovered_files")
        return cls(path, rows, page_size, skipped)

    @staticmethod
    def _norm_path(value: Any) -> str:
        return str(value or "").replace("\\", "/").rstrip("/").casefold()

    @classmethod
    def _payload_metadata(
        cls, item: Dict[str, Any], share_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Extract evidence attached to a file, keeping share permissions visible."""
        remote = cls._norm_path(item.get("remote_path"))
        unc = cls._norm_path(item.get("unc_path"))

        def matches_path(payload: Any) -> bool:
            if not isinstance(payload, dict):
                return False
            return bool(
                (remote and cls._norm_path(payload.get("remote_path")) == remote)
                or (unc and cls._norm_path(payload.get("unc_path")) == unc)
            )

        matches = tuple(
            value
            for value in share_data.get("snaffler_matches", [])
            if matches_path(value)
        )
        downloads = [
            value
            for value in share_data.get("downloaded_files", [])
            if matches_path(value)
        ]
        detail = downloads[-1] if downloads else None
        if detail:
            status = str(
                detail.get("status") or detail.get("collection_status") or "collected"
            )
            if status in {"success", "downloaded", "complete"}:
                status = "collected"
        elif item.get("collection_status"):
            status = str(item["collection_status"])
        else:
            status = "not_collected"
        return {
            "rule_matches": matches,
            "permissions": dict(share_data.get("permissions") or {}),
            "collection_status": status,
            "collection_detail": detail,
            "metadata_scan_timestamp_utc": str(
                item.get("scan_timestamp_utc")
                or share_data.get("scan_timestamp_utc")
                or ""
            ),
        }

    def facets(self) -> Dict[str, List[str]]:
        return {
            "hosts": sorted({r.host for r in self.records}, key=str.casefold),
            "shares": sorted({r.share for r in self.records}, key=str.casefold),
            "extensions": sorted({r.extension for r in self.records}),
            "rules": sorted(
                {
                    str(m.get("rule_name"))
                    for r in self.records
                    for m in r.rule_matches
                    if m.get("rule_name")
                },
                key=str.casefold,
            ),
            "triages": sorted(
                {
                    str(m.get("triage"))
                    for r in self.records
                    for m in r.rule_matches
                    if m.get("triage")
                },
                key=str.casefold,
            ),
            "collections": sorted({r.collection_status for r in self.records}),
            "permissions": [
                "read",
                "write",
                "add_file",
                "add_subdirectory",
                "write_dac",
                "write_owner",
            ],
        }

    def get(self, public_id: str) -> Optional[FileRecord]:
        return self.by_id.get(public_id)

    def status(self) -> Dict[str, Any]:
        return {
            "results_name": self.path.name,
            "schema_version": 3,
            "file_count": len(self.records),
            "host_count": len(self.facets()["hosts"]),
            "revision": 0,
            "scan_active": False,
        }

    def _matching(
        self,
        q: str,
        host: str,
        share: str,
        extension: str,
        rule: str = "",
        triage: str = "",
        permission: str = "",
        collection: str = "",
    ) -> List[FileRecord]:
        terms = q.casefold().split()
        return [
            record
            for record in self.records
            if (not host or record.host == host)
            and (not share or record.share == share)
            and (not extension or record.extension == extension)
            and all(term in record.search_text for term in terms)
            and (
                not (rule or triage)
                or any(
                    (not rule or match.get("rule_name") == rule)
                    and (not triage or match.get("triage") == triage)
                    for match in record.rule_matches
                )
            )
            and (
                not permission
                or (
                    record.permissions
                    if permission in {"read", "write"}
                    else record.permissions.get("write_rights", {})
                ).get(permission)
                is True
            )
            and (not collection or record.collection_status == collection)
        ]

    def search(
        self,
        q: str,
        host: str,
        share: str,
        extension: str,
        page: int,
        per_page: int,
        rule: str = "",
        triage: str = "",
        permission: str = "",
        collection: str = "",
    ) -> Dict[str, Any]:
        matches = self._matching(
            q, host, share, extension, rule, triage, permission, collection
        )
        per_page = min(max(per_page, 1), self.page_size, 500)
        page = max(page, 1)
        start = (page - 1) * per_page
        return {
            "items": [r.public() for r in matches[start : start + per_page]],
            "page": page,
            "per_page": per_page,
            "total": len(matches),
            "has_next": start + per_page < len(matches),
        }

    def tree(
        self,
        q: str,
        host: str,
        share: str,
        extension: str,
        rule: str = "",
        triage: str = "",
        permission: str = "",
        collection: str = "",
    ) -> Dict[str, Any]:
        """Build a complete host/share/folder hierarchy for matching records."""
        matches = self._matching(
            q, host, share, extension, rule, triage, permission, collection
        )
        hosts: Dict[str, Dict[str, Any]] = {}

        def branch(name: str) -> Dict[str, Any]:
            return {
                "name": name,
                "file_count": 0,
                "size_bytes": 0,
                "folders": {},
                "files": [],
            }

        for record in matches:
            host_node = hosts.setdefault(
                record.host,
                {
                    "name": record.host,
                    "file_count": 0,
                    "size_bytes": 0,
                    "shares": {},
                },
            )
            share_node = host_node["shares"].setdefault(
                record.share, branch(record.share)
            )
            host_node["file_count"] += 1
            host_node["size_bytes"] += record.size_bytes
            share_node["file_count"] += 1
            share_node["size_bytes"] += record.size_bytes

            parts = [
                part
                for part in record.remote_path.replace("\\", "/").split("/")
                if part
            ]
            if parts and parts[-1].casefold() == record.file_name.casefold():
                parts.pop()
            parent = share_node
            for part in parts:
                parent = parent["folders"].setdefault(part, branch(part))
                parent["file_count"] += 1
                parent["size_bytes"] += record.size_bytes
            parent["files"].append(record.public())

        def serialize_branch(node: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "name": node["name"],
                "file_count": node["file_count"],
                "size_bytes": node["size_bytes"],
                "folders": [
                    serialize_branch(folder)
                    for folder in sorted(
                        node["folders"].values(),
                        key=lambda value: value["name"].casefold(),
                    )
                ],
                "files": sorted(
                    node["files"], key=lambda value: value["file_name"].casefold()
                ),
            }

        public_hosts = []
        for host_node in sorted(
            hosts.values(), key=lambda value: value["name"].casefold()
        ):
            public_hosts.append(
                {
                    "name": host_node["name"],
                    "file_count": host_node["file_count"],
                    "size_bytes": host_node["size_bytes"],
                    "shares": [
                        serialize_branch(share_node)
                        for share_node in sorted(
                            host_node["shares"].values(),
                            key=lambda value: value["name"].casefold(),
                        )
                    ],
                }
            )
        return {"total": len(matches), "hosts": public_hosts}


class DatabaseIndex:
    """Query a cumulative Shrawler SQLite inventory."""

    def __init__(self, path: Path, page_size: int = 100) -> None:
        self.path = path.expanduser().resolve()
        if not self.path.is_file():
            raise ValueError(f"DATABASE does not exist: {self.path}")
        self.page_size = min(max(page_size, 1), 500)
        self.skipped = 0
        with self._connect() as connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version != SCHEMA_VERSION:
                raise ValueError(f"unsupported Shrawler database schema {version}")
            connection.execute("SELECT 1 FROM files LIMIT 1").fetchone()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.create_function(
            "path_key",
            1,
            self._path_key,
            deterministic=True,
        )
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    @staticmethod
    def _path_key(value: Any) -> str:
        return "/" + "/".join(
            part
            for part in str(value or "").replace("\\", "/").casefold().split("/")
            if part
        )

    @staticmethod
    def _record(row: sqlite3.Row) -> FileRecord:
        return FileRecord(
            str(row["public_id"]),
            str(row["host"]),
            str(row["share"]),
            str(row["remote_path"]),
            str(row["unc_path"]),
            str(row["file_name"]),
            str(row["extension"]),
            int(row["size_bytes"]),
            str(row["readable_size"]),
            str(row["mtime_utc"]),
            str(row["scan_timestamp_utc"]),
            str(row["search_text"]),
        )

    @staticmethod
    def _latest_observation() -> str:
        return """(SELECT observation.rowid FROM scan_files observation
                   JOIN scans observation_scan ON observation_scan.id=observation.scan_id
                   WHERE observation.file_id=files.id
                   ORDER BY observation_scan.started_at_utc DESC, observation.rowid DESC
                   LIMIT 1)"""

    @classmethod
    def _evidence_join(cls, table: str) -> str:
        # table is an internal constant, never a request parameter.
        return f"""JOIN scan_files sf ON sf.file_id=files.id
                       AND sf.rowid={cls._latest_observation()}
                   JOIN {table} evidence ON evidence.scan_id=sf.scan_id
                       AND evidence.share_id=sf.share_id
                       AND path_key(json_extract(evidence.payload_json, '$.remote_path'))
                           =path_key(files.remote_path)"""

    def _enrich(self, records: List[FileRecord]) -> List[FileRecord]:
        """Load only the selected files' latest evidence in bounded SQL batches."""
        with self._connect() as connection:
            for offset in range(0, len(records), 400):
                batch = {record.id: record for record in records[offset : offset + 400]}
                placeholders = ",".join("?" for _ in batch)
                selected = f" WHERE files.public_id IN ({placeholders})"
                parameters = list(batch)
                observations = connection.execute(
                    f"""SELECT files.public_id, share.payload_json,
                               scan.started_at_utc
                        FROM files JOIN scan_files sf ON sf.file_id=files.id
                            AND sf.rowid={self._latest_observation()}
                        JOIN shares share ON share.id=sf.share_id
                        JOIN scans scan ON scan.id=sf.scan_id"""
                    + selected,
                    parameters,
                )
                for row in observations:
                    record = batch[str(row[0])]
                    payload: Dict[str, Any] = json.loads(row[1])
                    record.permissions = payload.get("permissions") or {}
                    record.collection_status = "not_collected"
                    record.metadata_scan_timestamp_utc = str(row[2])
                for table in ("snaffler_matches", "downloads"):
                    evidence_rows = connection.execute(
                        "SELECT files.public_id, evidence.payload_json FROM files "
                        + self._evidence_join(table)
                        + selected
                        + " ORDER BY evidence.id",
                        parameters,
                    )
                    for row in evidence_rows:
                        record = batch[str(row[0])]
                        detail: Dict[str, Any] = json.loads(row[1])
                        if table == "snaffler_matches":
                            record.rule_matches += (detail,)
                        else:
                            record.collection_status = "collected"
                            record.collection_detail = detail
        return records

    @classmethod
    def _where(
        cls,
        q: str,
        host: str,
        share: str,
        extension: str,
        rule: str = "",
        triage: str = "",
        permission: str = "",
        collection: str = "",
    ) -> Tuple[str, List[Any]]:
        clauses: List[str] = []
        values: List[Any] = []
        for column, value in (
            ("host", host),
            ("share", share),
            ("extension", extension),
        ):
            if value:
                clauses.append(f"files.{column}=?")
                values.append(value)
        for term in q.casefold().split():
            clauses.append("files.search_text LIKE ? ESCAPE '\\'")
            escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            values.append(f"%{escaped}%")
        if rule or triage:
            match_conditions: List[str] = []
            for key, value in (("rule_name", rule), ("triage", triage)):
                if value:
                    match_conditions.append(
                        f"json_extract(evidence.payload_json, '$.{key}')=?"
                    )
                    values.append(value)
            clauses.append(
                "EXISTS (SELECT 1 FROM files AS matched_file "
                + cls._evidence_join("snaffler_matches")
                + " WHERE matched_file.id=files.id AND "
                + " AND ".join(match_conditions)
                + ")"
            )
        if permission:
            permission_paths = {
                "read": "$.permissions.read",
                "write": "$.permissions.write",
                "add_file": "$.permissions.write_rights.add_file",
                "add_subdirectory": "$.permissions.write_rights.add_subdirectory",
                "write_dac": "$.permissions.write_rights.write_dac",
                "write_owner": "$.permissions.write_rights.write_owner",
            }
            if permission not in permission_paths:
                raise ValueError("Invalid permission filter")
            clauses.append(
                f"""EXISTS (SELECT 1 FROM scan_files sf
                    JOIN shares sh ON sh.id=sf.share_id
                    WHERE sf.file_id=files.id AND sf.rowid={cls._latest_observation()}
                    AND json_extract(sh.payload_json, ?)=1)"""
            )
            values.append(permission_paths[permission])
        if collection:
            if collection not in {"collected", "not_collected"}:
                raise ValueError("Invalid collection filter")
            prefix = "NOT " if collection == "not_collected" else ""
            clauses.append(
                prefix
                + "EXISTS (SELECT 1 FROM files AS matched_file "
                + cls._evidence_join("downloads")
                + " WHERE matched_file.id=files.id)"
            )
        return (" WHERE " + " AND ".join(clauses) if clauses else "", values)

    def facets(self) -> Dict[str, List[str]]:
        with self._connect() as connection:
            return {
                "hosts": [
                    str(row[0])
                    for row in connection.execute(
                        "SELECT DISTINCT host FROM files ORDER BY host COLLATE NOCASE"
                    )
                ],
                "shares": [
                    str(row[0])
                    for row in connection.execute(
                        "SELECT DISTINCT share FROM files ORDER BY share COLLATE NOCASE"
                    )
                ],
                "extensions": [
                    str(row[0])
                    for row in connection.execute(
                        "SELECT DISTINCT extension FROM files ORDER BY extension"
                    )
                ],
                "rules": [
                    str(row[0])
                    for row in connection.execute(
                        "SELECT DISTINCT json_extract(payload_json, '$.rule_name') FROM snaffler_matches WHERE json_extract(payload_json, '$.rule_name') IS NOT NULL ORDER BY 1 COLLATE NOCASE"
                    )
                ],
                "triages": [
                    str(row[0])
                    for row in connection.execute(
                        "SELECT DISTINCT json_extract(payload_json, '$.triage') FROM snaffler_matches WHERE json_extract(payload_json, '$.triage') IS NOT NULL ORDER BY 1 COLLATE NOCASE"
                    )
                ],
                "collections": ["collected", "not_collected"],
                "permissions": [
                    "read",
                    "write",
                    "add_file",
                    "add_subdirectory",
                    "write_dac",
                    "write_owner",
                ],
            }

    def status(self) -> Dict[str, Any]:
        with self._connect() as connection:
            revision = connection.execute(
                "SELECT value FROM metadata WHERE key='revision'"
            ).fetchone()
            counts = connection.execute(
                "SELECT COUNT(*), COUNT(DISTINCT host) FROM files"
            ).fetchone()
            active = connection.execute(
                "SELECT EXISTS(SELECT 1 FROM scans WHERE status='running')"
            ).fetchone()
        return {
            "results_name": self.path.name,
            "schema_version": 3,
            "file_count": int(counts[0]),
            "host_count": int(counts[1]),
            "revision": int(revision[0]) if revision else 0,
            "scan_active": bool(active[0]),
        }

    def get(self, public_id: str) -> Optional[FileRecord]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM files WHERE public_id=?", (public_id,)
            ).fetchone()
        return self._enrich([self._record(row)])[0] if row else None

    def search(
        self,
        q: str,
        host: str,
        share: str,
        extension: str,
        page: int,
        per_page: int,
        rule: str = "",
        triage: str = "",
        permission: str = "",
        collection: str = "",
    ) -> Dict[str, Any]:
        where, values = self._where(
            q, host, share, extension, rule, triage, permission, collection
        )
        per_page = min(max(per_page, 1), self.page_size, 500)
        page = max(page, 1)
        start = (page - 1) * per_page
        with self._connect() as connection:
            total = int(
                connection.execute(
                    "SELECT COUNT(*) FROM files" + where, values
                ).fetchone()[0]
            )
            rows = connection.execute(
                "SELECT * FROM files"
                + where
                + " ORDER BY host COLLATE NOCASE, share COLLATE NOCASE, "
                "remote_path COLLATE NOCASE, file_name COLLATE NOCASE LIMIT ? OFFSET ?",
                (*values, per_page, start),
            )
            items = [
                record.public()
                for record in self._enrich([self._record(row) for row in rows])
            ]
        return {
            "items": items,
            "page": page,
            "per_page": per_page,
            "total": total,
            "has_next": start + per_page < total,
        }

    def tree(
        self,
        q: str,
        host: str,
        share: str,
        extension: str,
        rule: str = "",
        triage: str = "",
        permission: str = "",
        collection: str = "",
    ) -> Dict[str, Any]:
        """Return root host nodes; descendants are loaded on expansion."""
        where, values = self._where(
            q, host, share, extension, rule, triage, permission, collection
        )
        with self._connect() as connection:
            rows = list(
                connection.execute(
                    "SELECT host AS name, COUNT(*) AS file_count, "
                    "COALESCE(SUM(size_bytes), 0) AS size_bytes FROM files"
                    + where
                    + " GROUP BY host ORDER BY host COLLATE NOCASE",
                    values,
                )
            )
        hosts: List[Dict[str, Any]] = [
            {
                "name": str(row["name"]),
                "file_count": int(row["file_count"]),
                "size_bytes": int(row["size_bytes"]),
                "shares": [],
                "loaded": False,
            }
            for row in rows
        ]
        return {"total": sum(row["file_count"] for row in hosts), "hosts": hosts}

    def tree_branch(
        self,
        q: str,
        host: str,
        share: str,
        extension: str,
        parent: str,
        rule: str = "",
        triage: str = "",
        permission: str = "",
        collection: str = "",
    ) -> Dict[str, Any]:
        """Return immediate children for one host, share, or folder."""
        if not host:
            raise ValueError("tree branch requires a host")
        where, values = self._where(
            q, host, share, extension, rule, triage, permission, collection
        )
        if not share:
            with self._connect() as connection:
                rows = list(
                    connection.execute(
                        "SELECT share AS name, COUNT(*) AS file_count, "
                        "COALESCE(SUM(size_bytes), 0) AS size_bytes FROM files"
                        + where
                        + " GROUP BY share ORDER BY share COLLATE NOCASE",
                        values,
                    )
                )
            return {
                "shares": [
                    {
                        "name": str(row["name"]),
                        "host": host,
                        "file_count": int(row["file_count"]),
                        "size_bytes": int(row["size_bytes"]),
                        "folders": [],
                        "files": [],
                        "loaded": False,
                    }
                    for row in rows
                ]
            }

        normalized_parent = parent.replace("\\", "/").rstrip("/") or "/"
        prefix = "/" if normalized_parent == "/" else normalized_parent + "/"
        folders: Dict[str, Dict[str, Any]] = {}
        files: List[FileRecord] = []
        with self._connect() as connection:
            for row in connection.execute(
                "SELECT * FROM files" + where + " ORDER BY remote_path COLLATE NOCASE",
                values,
            ):
                record = self._record(row)
                path = "/" + record.remote_path.replace("\\", "/").lstrip("/")
                if not path.startswith(prefix):
                    continue
                relative = path[len(prefix) :]
                if "/" not in relative:
                    files.append(record)
                    continue
                name = relative.split("/", 1)[0]
                folder = folders.setdefault(
                    name,
                    {
                        "name": name,
                        "host": host,
                        "share": share,
                        "path": prefix.rstrip("/") + "/" + name,
                        "file_count": 0,
                        "size_bytes": 0,
                        "folders": [],
                        "files": [],
                        "loaded": False,
                    },
                )
                folder["file_count"] += 1
                folder["size_bytes"] += record.size_bytes
        return {
            "folders": sorted(
                folders.values(), key=lambda value: value["name"].casefold()
            ),
            "files": [r.public() for r in self._enrich(files)],
        }


class DownloadTooLarge(Exception):
    pass


class LimitedSink:
    def __init__(self, writer: Callable[[bytes], Any], limit: int) -> None:
        self.writer = writer
        self.limit = limit
        self.size = 0

    def __call__(self, chunk: bytes) -> None:
        if self.size + len(chunk) > self.limit:
            raise DownloadTooLarge()
        self.writer(chunk)
        self.size += len(chunk)


def classify_preview(name: str, data: bytes) -> Tuple[str, str, Optional[str]]:
    extension = Path(name).suffix.lower()
    if extension in BINARY_EXTENSIONS:
        valid = any(data.startswith(prefix) for prefix in MAGIC[extension])
        if extension == ".webp":
            valid = (
                data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WEBP"
            )
        if not valid:
            raise ValueError("file content does not match its preview type")
        return "binary", BINARY_EXTENSIONS[extension], None
    if extension not in TEXT_EXTENSIONS:
        raise ValueError("unsupported preview type")
    sample = data[:8192]
    if b"\0" in sample:
        raise ValueError("binary content cannot be previewed as text")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("text preview is not valid UTF-8") from exc
    if (
        sample
        and sum(chr(byte).isprintable() or byte in b"\r\n\t" for byte in sample)
        / len(sample)
        < 0.85
    ):
        raise ValueError("content is not sufficiently text-like")
    return "text", "application/json", text


def content_disposition(name: str) -> str:
    clean = re.sub(r"[\r\n/\\\x00-\x1f\x7f]+", "_", name).strip(" .") or "download"
    ascii_name = clean.encode("ascii", "replace").decode("ascii").replace('"', "_")
    return "attachment; filename=\"{}\"; filename*=UTF-8''{}".format(
        ascii_name, urllib.parse.quote(clean, safe="")
    )


class SessionPool:
    def __init__(self, auth: SMBAuth) -> None:
        self.auth = auth
        self._sessions: Dict[str, Tuple[Any, threading.Lock]] = {}
        self._lock = threading.Lock()

    def retrieve(self, record: FileRecord, sink: Callable[[bytes], Any]) -> None:
        last_error = None
        for attempt in range(2):
            with self._lock:
                current = self._sessions.get(record.host)
                if current is None:
                    current = (connect_smb(record.host, self.auth), threading.Lock())
                    self._sessions[record.host] = current
            client, lock = current
            try:
                with lock:
                    client.getFile(record.share, record.remote_path, sink)
                return
            except DownloadTooLarge:
                raise
            except Exception as exc:
                last_error = exc
                with self._lock:
                    self._sessions.pop(record.host, None)
                close_smb(client)
                if attempt:
                    break
        raise RuntimeError("SMB retrieval failed") from last_error

    def close(self) -> None:
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for client, _ in sessions:
            close_smb(client)


@dataclass
class WebState:
    index: Any
    pool: Optional[SessionPool]
    token: str
    preview_max: int
    download_max: int
    runtime_dir: Path
    retrievals: threading.BoundedSemaphore
    triage: Optional[TriageService] = None


@dataclass(frozen=True)
class WebConfig:
    database_path: Path
    port: int
    token_auth: bool
    preview_max_bytes: int
    download_max_bytes: int
    page_size: int


class WebServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: Tuple[str, int], state: WebState) -> None:
        self.state = state
        super().__init__(address, WebHandler)


class WebHandler(BaseHTTPRequestHandler):
    server: WebServer
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        logging.debug("%s", escape_terminal(fmt % args))

    def _headers(self, status: int, content_type: str, length: int) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        self.end_headers()

    def _send(
        self,
        body: bytes,
        status: int = 200,
        content_type: str = "application/json; charset=utf-8",
    ) -> None:
        self._headers(status, content_type, len(body))
        self.wfile.write(body)

    def _json(self, value: Any, status: int = 200) -> None:
        self._send(json.dumps(value, ensure_ascii=False).encode("utf-8"), status)

    def _error(self, status: int, message: str, code: str) -> None:
        self._json({"error": message, "code": code}, status)

    def _valid_host(self) -> bool:
        expected = str(self.server.server_port)
        raw = self.headers.get("Host", "")
        return raw in {
            "127.0.0.1:" + expected,
            "localhost:" + expected,
            "[::1]:" + expected,
        }

    def _authorized(self) -> bool:
        if not self.server.state.token:
            return True
        return secrets.compare_digest(
            self.headers.get("Authorization", ""), "Bearer " + self.server.state.token
        )

    def _guard(self) -> bool:
        if self.server.server_address[0] != "127.0.0.1" or not self._valid_host():
            self._error(400, "Invalid Host header", "invalid_host")
            return False
        if not self._authorized():
            self._error(401, "Authentication required", "unauthorized")
            return False
        return True

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        assets = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/assets/app.css": ("app.css", "text/css; charset=utf-8"),
            "/assets/app.js": ("app.js", "text/javascript; charset=utf-8"),
            "/triage": ("triage.html", "text/html; charset=utf-8"),
            "/assets/triage.js": ("triage.js", "text/javascript; charset=utf-8"),
            "/assets/triage.css": ("triage.css", "text/css; charset=utf-8"),
        }
        if parsed.path in assets:
            name, content_type = assets[parsed.path]
            body = (Path(__file__).parent / "web_assets" / name).read_bytes()
            self._send(body, content_type=content_type)
            return
        if parsed.path == "/favicon.ico":
            self._send(b"", status=204, content_type="image/x-icon")
            return
        if not parsed.path.startswith("/api/"):
            self._error(404, "Not found", "not_found")
            return
        if not self._guard():
            return
        state = self.server.state
        if parsed.path == "/api/review/families":
            try:
                query = urllib.parse.parse_qs(parsed.query)
                self._json(
                    ReviewStore(state.index.path).families(
                        query["scan"][0],
                        int(query.get("limit", ["100"])[0]),
                        int(query.get("offset", ["0"])[0]),
                        query.get("family", [None])[0],
                    )
                )
            except (ValueError, KeyError, OSError, sqlite3.Error) as exc:
                self._error(400, str(exc), "invalid_request")
            return
        if parsed.path == "/api/collection":
            try:
                queue = CollectionQueue(state.index.path)
                query = urllib.parse.parse_qs(parsed.query)
                self._json(
                    queue.get(query["id"][0])
                    if "id" in query
                    else {"items": queue.list()}
                )
            except (ValueError, OSError, sqlite3.Error) as exc:
                self._error(400, str(exc), "invalid_request")
            return
        if parsed.path.startswith("/api/triage/"):
            self._triage_get(parsed)
            return
        if parsed.path == "/api/status":
            status = state.index.status()
            status.update(
                {
                    "preview_max_bytes": state.preview_max,
                    "download_max_bytes": state.download_max,
                    "retrieval_enabled": state.pool is not None,
                    "triage_enabled": state.triage is not None,
                }
            )
            self._json(status)
            return
        if parsed.path == "/api/facets":
            self._json(state.index.facets())
            return
        if parsed.path in {"/api/files", "/api/tree", "/api/tree/branch"}:
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if any(len(value[0]) > 512 for value in query.values() if value):
                self._error(400, "Query value is too long", "invalid_query")
                return
            filters = tuple(
                query.get(key, [""])[0]
                for key in (
                    "q",
                    "host",
                    "share",
                    "extension",
                    "rule",
                    "triage",
                    "permission",
                    "collection",
                )
            )
            if filters[6] not in {
                "",
                "read",
                "write",
                "add_file",
                "add_subdirectory",
                "write_dac",
                "write_owner",
            } or filters[7] not in {"", "collected", "not_collected"}:
                self._error(400, "Invalid evidence filter", "invalid_query")
                return
            if parsed.path == "/api/tree/branch":
                try:
                    self._json(
                        state.index.tree_branch(
                            *filters[:4], query.get("parent", [""])[0], *filters[4:]
                        )
                    )
                except (AttributeError, ValueError) as exc:
                    self._error(400, str(exc), "invalid_query")
                return
            if parsed.path == "/api/tree":
                self._json(state.index.tree(*filters))
                return
            try:
                self._json(
                    state.index.search(
                        *filters[:4],
                        int(query.get("page", ["1"])[0]),
                        int(query.get("per_page", [str(state.index.page_size)])[0]),
                        *filters[4:],
                    )
                )
            except (ValueError, OverflowError):
                self._error(400, "Invalid pagination", "invalid_query")
            return
        match = re.fullmatch(
            r"/api/files/([A-Za-z0-9_-]{16,32})(?:/(preview|download))?", parsed.path
        )
        if not match:
            self._error(400, "Invalid file ID", "invalid_id")
            return
        record = state.index.get(match.group(1))
        if record is None:
            self._error(404, "Unknown file", "not_found")
            return
        action = match.group(2)
        if action is not None and state.pool is None:
            self._error(
                403, "Remote retrieval is disabled in offline mode", "offline_mode"
            )
            return
        if action is None:
            self._json(record.public())
        elif action == "preview":
            self._preview(record)
        else:
            self._download(record)

    def _retrieve(self, record: FileRecord, path: Path, limit: int) -> int:
        pool = self.server.state.pool
        if pool is None:
            raise ValueError("Remote retrieval is disabled in offline mode")
        with self.server.state.retrievals:
            with path.open("xb") as handle:
                os.chmod(path, 0o600)
                sink = LimitedSink(handle.write, limit)
                pool.retrieve(record, sink)
                return sink.size

    def _preview(self, record: FileRecord) -> None:
        state = self.server.state
        if record.extension not in TEXT_EXTENSIONS | set(BINARY_EXTENSIONS):
            self._error(415, "Unsupported preview type", "unsupported_preview")
            return
        if record.size_bytes > state.preview_max:
            self._error(413, "File exceeds preview limit", "preview_too_large")
            return
        path = state.runtime_dir / (secrets.token_hex(16) + ".preview")
        try:
            size = self._retrieve(record, path, state.preview_max)
            data = path.read_bytes()
            kind, content_type, text = classify_preview(record.file_name, data)
            if kind == "text":
                self._json(
                    {
                        "kind": "text",
                        "encoding": "utf-8",
                        "content": text,
                        "truncated": False,
                        "bytes_read": size,
                    }
                )
            else:
                self._send(data, content_type=content_type)
        except DownloadTooLarge:
            self._error(413, "File exceeds preview limit", "preview_too_large")
        except ValueError as exc:
            self._error(415, str(exc), "unsupported_preview")
        except Exception as exc:
            logging.error(
                "Preview retrieval failed for %s: %s",
                escape_terminal(record.unc_path),
                escape_terminal(exc),
            )
            self._error(502, "SMB retrieval failed", "smb_failure")
        finally:
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    def _download(self, record: FileRecord) -> None:
        state = self.server.state
        if record.size_bytes > state.download_max:
            self._error(413, "File exceeds download limit", "download_too_large")
            return
        path = state.runtime_dir / (secrets.token_hex(16) + ".download")
        try:
            size = self._retrieve(record, path, state.download_max)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header(
                "Content-Disposition", content_disposition(record.file_name)
            )
            self.send_header("Content-Length", str(size))
            for name, value in SECURITY_HEADERS.items():
                self.send_header(name, value)
            self.end_headers()
            with path.open("rb") as handle:
                shutil.copyfileobj(handle, self.wfile, 64 * 1024)
        except DownloadTooLarge:
            self._error(413, "File exceeds download limit", "download_too_large")
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            logging.error(
                "Download retrieval failed for %s: %s",
                escape_terminal(record.unc_path),
                escape_terminal(exc),
            )
            self._error(502, "SMB retrieval failed", "smb_failure")
        finally:
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    def do_HEAD(self) -> None:
        self._error(405, "Method not allowed", "method_not_allowed")

    do_PUT = do_DELETE = do_PATCH = do_HEAD

    def _triage_get(self, parsed: urllib.parse.SplitResult) -> None:
        service = self.server.state.triage
        if service is None:
            self._error(404, "Ranking is unavailable for this inventory", "not_found")
            return
        query = urllib.parse.parse_qs(parsed.query)
        if any(len(values) != 1 or len(values[0]) > 512 for values in query.values()):
            self._error(400, "Invalid ranking query", "invalid_query")
            return
        try:
            run_id = query.get("run", [None])[0]
            if parsed.path == "/api/triage/catalog":
                self._json(triage_catalog(service.database))
            elif parsed.path == "/api/triage/job":
                self._json({"job": service.status()})
            elif parsed.path == "/api/triage/files":
                after = None
                if "after_score" in query or "after_id" in query:
                    after = (int(query["after_score"][0]), query["after_id"][0])
                self._json(
                    triage_list(
                        service.database,
                        run_id,
                        query.get("category", [None])[0],
                        min(100, int(query.get("limit", ["100"])[0])),
                        int(query.get("min_score", ["0"])[0]),
                        after=after,
                    )
                )
            elif parsed.path == "/api/triage/explain":
                self._json(
                    triage_explain(service.database, query["file_id"][0], run_id)
                )
            else:
                self._error(404, "Unknown ranking endpoint", "not_found")
        except (ValueError, KeyError, OSError, sqlite3.Error) as exc:
            self._error(400, str(exc), "invalid_query")

    def do_POST(self) -> None:
        if not self._guard():
            self.close_connection = True
            return
        # JSON plus a custom header excludes cross-origin form submissions.
        origin = self.headers.get("Origin")
        if (
            self.headers.get("X-Shrawler-Request") != "1"
            or (
                origin is not None
                and origin != "http://" + self.headers.get("Host", "")
            )
            or self.headers.get("Content-Type", "").split(";")[0] != "application/json"
            or self.headers.get("Transfer-Encoding")
        ):
            self.close_connection = True
            self._error(403, "Invalid local request", "invalid_origin")
            return
        service = self.server.state.triage
        if service is None:
            self.close_connection = True
            self._error(404, "Ranking unavailable", "not_found")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= 131072:
                raise ValueError("request body must be 1..131072 bytes")
            self.connection.settimeout(10)
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError("expected a JSON object")
            payload = cast(Dict[str, Any], payload)
            path = urllib.parse.urlsplit(self.path).path
            if path == "/api/review/build":
                self._json(ReviewStore(service.database).build(payload.get("scan_id")))
            elif path == "/api/review/decide":
                self._json(ReviewStore(service.database).decide(**payload))
            elif path == "/api/review/undo":
                self._json(ReviewStore(service.database).undo(payload["event_id"]))
            elif path == "/api/review/hashes":
                self._json(ReviewStore(service.database).hashes())
            elif path == "/api/collection/create":
                self._json(CollectionQueue(service.database).create(**payload), 201)
            elif path == "/api/collection/run":
                pool = self.server.state.pool
                if pool is None:
                    raise ValueError("Remote retrieval is disabled in offline mode")
                with self.server.state.retrievals:
                    self._json(
                        CollectionQueue(service.database).run(
                            payload["id"], smb_retriever(pool.auth)
                        )
                    )
            elif path == "/api/triage/jobs":
                self._json(service.start(payload), 202)
            elif path == "/api/triage/cancel":
                service.cancel()
                self._json({"cancel_requested": True})
            else:
                self._error(404, "Unknown ranking endpoint", "not_found")
        except (TriageBusyError, CollectionBusyError) as exc:
            self._error(409, str(exc), "job_running")
        except (ValueError, OSError, sqlite3.Error, TypeError, KeyError) as exc:
            self.close_connection = True
            self._error(400, str(exc), "invalid_request")


def run(config: WebConfig, auth: Optional[SMBAuth]) -> int:
    """Run the local WebUI with validated configuration and authentication."""
    index = DatabaseIndex(config.database_path, config.page_size)
    runtime = Path(tempfile.mkdtemp(prefix="shrawler-web-"))
    os.chmod(runtime, 0o700)
    token = secrets.token_hex(32) if config.token_auth else ""
    state = WebState(
        index,
        SessionPool(auth) if auth else None,
        token,
        config.preview_max_bytes,
        config.download_max_bytes,
        runtime,
        threading.BoundedSemaphore(2),
        TriageService(config.database_path, runtime),
    )
    server = WebServer(("127.0.0.1", config.port), state)
    url = f"http://127.0.0.1:{server.server_port}/"
    if token:
        url += f"#token={token}"
    print(
        f"Loaded {index.status()['file_count']} files from {escape_terminal(index.path)}"
    )
    print("Local WebUI: " + url)
    if not token:
        print("WebUI token authentication is disabled; use --token-auth to enable it.")
    print(
        "Files are fetched live from SMB and may differ from crawl metadata."
        if auth
        else "Offline mode: saved metadata only; remote retrieval is disabled."
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if state.triage:
            state.triage.close()
        if state.pool:
            state.pool.close()
        shutil.rmtree(runtime, ignore_errors=True)
    return 0


__all__ = [
    "DatabaseIndex",
    "DownloadTooLarge",
    "FileIndex",
    "FileRecord",
    "LimitedSink",
    "WebConfig",
    "classify_preview",
    "content_disposition",
    "run",
]
