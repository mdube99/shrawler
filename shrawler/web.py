"""Local-only, dependency-free WebUI for saved Shrawler inventories."""

import gzip
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import urllib.parse
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
    cast,
)

from .catalog_total import total as catalog_total
from .collection import CollectionBusyError, CollectionQueue, smb_retriever
from .nemesis import DeliveryStore, NemesisConfig
from .output import escape_terminal
from .search_index import (
    available as search_index_available,
    bounded_ids as search_bounded_ids,
    candidates as search_candidates,
    ensure as ensure_search_index,
    plan_term as search_plan_term,
    predicate as search_predicate,
    supported as search_index_supported,
)
from .smb import SMBAuth, close_smb, connect_smb
from .store import (
    SCHEMA_VERSION,
    public_id,
    public_id_key,
    resolve_public_id,
)
from .triage.jev.config import PRIORITY_NAMES, JevConfig, priority_score
from .triage.jev.service import JevBusyError, JevService
from .triage.jev.storage import JevStore, assessment_path
from .triage.review import ReviewStore
from .triage.scoring import (
    DEFAULT_SCORING,
    RATING_FULL,
    ScoringConfig,
    combine_priority,
    combined_sql,
)
from .triage.service import PreviewGoneError, TriageBusyError, TriageService
from .triage.storage import (
    WEB_SORT_INDEXES,
    _ensure_result_schema,
    catalog as triage_catalog,
    explain as triage_explain,
    list_results as triage_list,
    result_path as triage_result_path,
    utc_now,
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
    # ``font-src`` is the only addition over the previous policy: the UI loads
    # its two typefaces from a CDN so an air-gapped install never has to ship
    # font binaries. Every other directive is unchanged, so style-src and
    # script-src stay locked to 'self'.
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; font-src 'self' https://cdn.jsdelivr.net; frame-src blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
}

# Cache directives replaced per-response when a caller supplies its own.
_OVERRIDABLE_HEADERS = frozenset({"Cache-Control", "Pragma"})

ASSET_ROOT = Path(__file__).parent / "web_assets"

# Screens are served from an explicit table: only these two documents exist and
# their paths are part of the product, not a resource lookup.
HTML_ROUTES = {
    "/": "explore.html",
    "/score": "score.html",
}

# Legacy pages redirect once so old bookmarks keep working.
REDIRECTS = {"/triage": "/score", "/assessment": "/score"}

ASSET_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".woff2": "font/woff2",
    ".ico": "image/x-icon",
}

# Below this size the gzip header costs more than it saves.
GZIP_FLOOR = 512

# Facets that accept repeated include values (``host=a&host=b``) and repeated
# exclusions under a ``not_`` prefix (``not_host=c``). Values within a facet
# are ORed; facets, and includes against excludes, are ANDed.
FILTER_FACETS = (
    "host",
    "share",
    "extension",
    "rule",
    "triage",
    "permission",
    "collection",
    "activity",
)
EXCLUDE_PREFIX = "not_"
# Bounds one request's IN-lists well under SQLite's oldest 999-variable limit.
MAX_FACET_VALUES = 50
PERMISSION_PATHS = {
    "read": "$.permissions.read",
    "write": "$.permissions.write",
    "add_file": "$.permissions.write_rights.add_file",
    "add_subdirectory": "$.permissions.write_rights.add_subdirectory",
    "write_dac": "$.permissions.write_rights.write_dac",
    "write_owner": "$.permissions.write_rights.write_owner",
}
COLLECTION_VALUES = ("collected", "not_collected")
ACTIVITY_VALUES = (
    "downloaded",
    "not_downloaded",
    "nemesis_sent",
    "not_nemesis_sent",
    "nemesis_failed",
)
_FIXED_VOCABULARIES: Dict[str, Tuple[str, ...]] = {
    "permission": tuple(PERMISSION_PATHS),
    "collection": COLLECTION_VALUES,
    "activity": ACTIVITY_VALUES,
}

# A facet argument is a single value (the original scalar API) or a list.
FacetValue = Union[str, Sequence[str]]


def _facet_values(value: Optional[FacetValue]) -> Tuple[str, ...]:
    """Normalize a scalar or list facet argument to unique non-empty values."""
    if not value:
        return ()
    items = (value,) if isinstance(value, str) else tuple(value)
    return tuple(dict.fromkeys(item for item in items if item))


@dataclass(frozen=True)
class FacetFilters:
    """Include and exclude values per facet, validated once for both indexes."""

    include: Dict[str, Tuple[str, ...]]
    exclude: Dict[str, Tuple[str, ...]]

    @classmethod
    def build(
        cls,
        host: Optional[FacetValue] = None,
        share: Optional[FacetValue] = None,
        extension: Optional[FacetValue] = None,
        rule: Optional[FacetValue] = None,
        triage: Optional[FacetValue] = None,
        permission: Optional[FacetValue] = None,
        collection: Optional[FacetValue] = None,
        activity: Optional[FacetValue] = None,
        exclude: Optional[Mapping[str, FacetValue]] = None,
    ) -> "FacetFilters":
        include = {
            "host": _facet_values(host),
            "share": _facet_values(share),
            "extension": _facet_values(extension),
            "rule": _facet_values(rule),
            "triage": _facet_values(triage),
            "permission": _facet_values(permission),
            "collection": _facet_values(collection),
            "activity": _facet_values(activity),
        }
        unknown = set(exclude or {}) - set(FILTER_FACETS)
        if unknown:
            raise ValueError("Unknown exclude filter: " + ", ".join(sorted(unknown)))
        excluded = {
            key: _facet_values((exclude or {}).get(key)) for key in FILTER_FACETS
        }
        for key, allowed in _FIXED_VOCABULARIES.items():
            if any(value not in allowed for value in include[key] + excluded[key]):
                raise ValueError(f"Invalid {key} filter")
        return cls(include, excluded)

    def key(self) -> Tuple[Tuple[str, Tuple[str, ...], Tuple[str, ...]], ...]:
        """Hashable identity for result caches."""
        return tuple(
            (key, self.include[key], self.exclude[key]) for key in FILTER_FACETS
        )


def jev_catalog(database: Path) -> List[Dict[str, Any]]:
    """Assessment runs recorded beside an inventory, newest first."""
    path = assessment_path(database)
    if not path.is_file():
        return []
    try:
        connection = sqlite3.connect(str(path), timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only=ON")
            rows = connection.execute(
                "SELECT id, scan_id, status, created_at, total_observed "
                "FROM assessment_runs ORDER BY created_at DESC, rowid DESC LIMIT 200"
            ).fetchall()
        finally:
            connection.close()
    except sqlite3.Error:
        return []
    return [
        {
            "id": str(row["id"]),
            "scan_id": str(row["scan_id"]),
            "status": str(row["status"]),
            "created_at": str(row["created_at"]),
            "total_observed": int(row["total_observed"] or 0),
        }
        for row in rows
    ]


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
    downloaded_at_utc: str = ""
    download_count: int = 0
    nemesis_status: str = ""
    nemesis_deliveries: int = 0
    nemesis_updated_at_utc: str = ""
    nemesis_response_id: str = ""
    nemesis_error: str = ""
    metadata_scan_timestamp_utc: str = ""
    ranking_run_id: str = ""
    ranking_priority: Optional[int] = None
    ranking_score: Optional[int] = None
    ranking_category: str = ""
    jev_run_id: str = ""
    jev_choice: str = ""
    jev_score: Optional[int] = None
    jev_priority_name: str = ""
    combined_score: Optional[int] = None
    combined_coverage: str = "none"
    catalog_id: int = field(default=0, repr=False, compare=False)

    def public(self) -> Dict[str, Any]:
        value = asdict(self)
        value.pop("search_text")
        value.pop("catalog_id", None)
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
        count = detail.get("download_count") if detail else None
        download_count = int(count) if count is not None else (1 if detail else 0)
        if detail and download_count > 0:
            status = str(
                detail.get("status") or detail.get("collection_status") or "collected"
            )
            if status in {"success", "downloaded", "complete"}:
                status = "collected"
        elif item.get("collection_status"):
            status = str(item["collection_status"])
        else:
            status = "not_collected"
        nemesis = (detail or {}).get("nemesis") or {}
        return {
            "rule_matches": matches,
            "permissions": dict(share_data.get("permissions") or {}),
            "collection_status": status,
            "collection_detail": detail,
            "downloaded_at_utc": str(
                (detail or {}).get("downloaded_at_utc")
                or (detail or {}).get("timestamp_utc")
                or ""
            ),
            "download_count": download_count,
            "nemesis_status": str(nemesis.get("status") or ""),
            "nemesis_deliveries": int(nemesis.get("deliveries") or 0),
            "nemesis_updated_at_utc": str(nemesis.get("updated_at") or ""),
            "nemesis_response_id": str(nemesis.get("response_id") or ""),
            "nemesis_error": str(nemesis.get("last_error") or ""),
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
            "activities": [
                "downloaded",
                "not_downloaded",
                "nemesis_sent",
                "not_nemesis_sent",
                "nemesis_failed",
            ],
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

    def record_download(
        self, record: FileRecord, actual_size: int, sha256: str
    ) -> None:
        """JSON result files are read-only; transfers are not persisted."""

    def record_nemesis(self, record: FileRecord, state: Dict[str, Any]) -> None:
        """JSON result files are read-only; transfers are not persisted."""

    def status(self) -> Dict[str, Any]:
        return {
            "results_name": self.path.name,
            "schema_version": 3,
            "file_count": len(self.records),
            "host_count": len(self.facets()["hosts"]),
            "revision": 0,
            "scan_active": False,
            "rating_full": RATING_FULL,
        }

    def _matching(
        self,
        q: str,
        host: FacetValue,
        share: FacetValue,
        extension: FacetValue,
        rule: FacetValue = "",
        triage: FacetValue = "",
        permission: FacetValue = "",
        collection: FacetValue = "",
        ranking_run: str = "",
        ranking_category: str = "",
        ranking_min: int = 0,
        activity: FacetValue = "",
        exclude: Optional[Mapping[str, FacetValue]] = None,
    ) -> List[FileRecord]:
        filters = FacetFilters.build(
            host,
            share,
            extension,
            rule,
            triage,
            permission,
            collection,
            activity,
            exclude,
        )
        terms = q.casefold().split()
        return [
            record
            for record in self.records
            if all(term in record.search_text for term in terms)
            and self._facets_match(record, filters)
        ]

    @classmethod
    def _facets_match(cls, record: FileRecord, filters: FacetFilters) -> bool:
        include, exclude = filters.include, filters.exclude

        def keep(values: Tuple[str, ...], blocked: Tuple[str, ...], value: str) -> bool:
            return (not values or value in values) and value not in blocked

        if not (
            keep(include["host"], exclude["host"], record.host)
            and keep(include["share"], exclude["share"], record.share)
            and keep(include["extension"], exclude["extension"], record.extension)
        ):
            return False
        rules, triages = include["rule"], include["triage"]
        # Rule and triage includes must hold on the same match, as before.
        if (rules or triages) and not any(
            (not rules or match.get("rule_name") in rules)
            and (not triages or match.get("triage") in triages)
            for match in record.rule_matches
        ):
            return False
        if any(
            match.get("rule_name") in exclude["rule"]
            or match.get("triage") in exclude["triage"]
            for match in record.rule_matches
        ):
            return False

        def permitted(name: str) -> bool:
            rights = (
                record.permissions
                if name in {"read", "write"}
                else record.permissions.get("write_rights", {})
            )
            return rights.get(name) is True

        checks: Tuple[Tuple[str, Callable[[str], bool]], ...] = (
            ("permission", permitted),
            ("collection", lambda value: record.collection_status == value),
            ("activity", lambda value: cls._activity_match(record, value)),
        )
        for key, test in checks:
            if include[key] and not any(test(value) for value in include[key]):
                return False
            if any(test(value) for value in exclude[key]):
                return False
        return True

    @staticmethod
    def _activity_match(record: FileRecord, activity: str) -> bool:
        if not activity:
            return True
        if activity == "downloaded":
            return record.collection_status == "collected"
        if activity == "not_downloaded":
            return record.collection_status != "collected"
        if activity == "nemesis_sent":
            return record.nemesis_status == "uploaded"
        if activity == "not_nemesis_sent":
            return record.nemesis_status != "uploaded"
        if activity == "nemesis_failed":
            return record.nemesis_status in {
                "upload_failed",
                "retrieval_failed",
                "failed",
                "unknown",
            }
        raise ValueError("Invalid activity filter")

    def search(
        self,
        q: str,
        host: FacetValue,
        share: FacetValue,
        extension: FacetValue,
        page: int,
        per_page: int,
        rule: FacetValue = "",
        triage: FacetValue = "",
        permission: FacetValue = "",
        collection: FacetValue = "",
        ranking_run: str = "",
        ranking_category: str = "",
        ranking_min: int = 0,
        sort: str = "path",
        direction: str = "asc",
        include_total: bool = True,
        activity: FacetValue = "",
        jev_run: str = "",
        exclude: Optional[Mapping[str, FacetValue]] = None,
    ) -> Dict[str, Any]:
        matches = self._matching(
            q,
            host,
            share,
            extension,
            rule,
            triage,
            permission,
            collection,
            activity=activity,
            exclude=exclude,
        )
        sort_keys: Dict[str, Callable[[FileRecord], Any]] = {
            "path": lambda row: (
                row.host.casefold(),
                row.share.casefold(),
                row.remote_path.casefold(),
            ),
            "type": lambda row: (row.extension, row.file_name.casefold()),
            "file": lambda row: row.file_name.casefold(),
            "location": lambda row: (
                row.host.casefold(),
                row.share.casefold(),
                row.remote_path.casefold(),
            ),
            "priority": lambda row: row.ranking_score or 0,
            "size": lambda row: row.size_bytes,
            "modified": lambda row: row.mtime_utc,
        }
        # JSON result sets carry no assessment database, so Jev and combined
        # sorting fall back to path order rather than failing.
        if sort in {"jev", "combined"}:
            sort = "path"
        if sort not in sort_keys or direction not in {"asc", "desc"}:
            raise ValueError("Invalid inventory sort")
        matches.sort(key=sort_keys[sort], reverse=direction == "desc")
        per_page = min(max(per_page, 1), self.page_size, 500)
        page = max(page, 1)
        start = (page - 1) * per_page
        return {
            "items": [r.public() for r in matches[start : start + per_page]],
            "page": page,
            "per_page": per_page,
            "total": len(matches),
            "has_next": start + per_page < len(matches),
            # JSON indexes are loaded once and never live-append, so there is
            # no evolution to report and the revision stays fixed.
            "revision": 0,
        }

    def tree(
        self,
        q: str,
        host: FacetValue,
        share: FacetValue,
        extension: FacetValue,
        rule: FacetValue = "",
        triage: FacetValue = "",
        permission: FacetValue = "",
        collection: FacetValue = "",
        ranking_run: str = "",
        ranking_category: str = "",
        ranking_min: int = 0,
        sort: str = "path",
        direction: str = "asc",
        activity: FacetValue = "",
        jev_run: str = "",
        exclude: Optional[Mapping[str, FacetValue]] = None,
    ) -> Dict[str, Any]:
        """Build a complete host/share/folder hierarchy for matching records.

        ``jev_run`` is accepted for parity with the other inventory readers. A
        JSON result set carries no assessment database, so there is nothing to
        resolve it against.
        """
        matches = self._matching(
            q,
            host,
            share,
            extension,
            rule,
            triage,
            permission,
            collection,
            activity=activity,
            exclude=exclude,
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
        return {"total": len(matches), "hosts": public_hosts, "revision": 0}


class DatabaseIndex:
    """Query a cumulative Shrawler SQLite inventory."""

    def __init__(
        self,
        path: Path,
        page_size: int = 100,
        scoring: Optional[ScoringConfig] = None,
    ) -> None:
        self.path = path.expanduser().resolve()
        if not self.path.is_file():
            raise ValueError(f"DATABASE does not exist: {self.path}")
        self._public_id_key: Optional[bytes] = None
        # The ranking and assessment files are keyed by catalog integer ids;
        # ensure any legacy result schema is rejected clearly before queries.
        _ensure_result_schema(triage_result_path(self.path), self.path)
        jev_path = assessment_path(self.path)
        if jev_path.is_file():
            JevStore(self.path).close()
        self.page_size = min(max(page_size, 1), 500)
        self.scoring = scoring or ScoringConfig()
        self.skipped = 0
        self._facets_cache: Tuple[float, Dict[str, List[str]]] | None = None
        self._status_cache: Tuple[float, int, int] | None = None
        self._total_cache: Dict[Tuple[Any, ...], int] = {}
        with self._connect() as connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version != SCHEMA_VERSION:
                raise ValueError(
                    f"database schema {version} is not supported; "
                    f"recreate the workspace to upgrade to schema {SCHEMA_VERSION}"
                )
            self._public_id_key = public_id_key(connection)
            connection.execute("SELECT 1 FROM files LIMIT 1").fetchone()

    SORT_INDEXES = (
        (
            "path",
            "catalog_dirs_sort_idx",
            "CREATE INDEX IF NOT EXISTS catalog_dirs_sort_idx ON catalog_dirs(host COLLATE NOCASE, share COLLATE NOCASE, path COLLATE NOCASE)",
        ),
        (
            "filename",
            "catalog_files_name_idx",
            "CREATE INDEX IF NOT EXISTS catalog_files_name_idx ON catalog_files(name COLLATE NOCASE)",
        ),
        (
            "file type",
            "catalog_files_ext_idx",
            "CREATE INDEX IF NOT EXISTS catalog_files_ext_idx ON catalog_files(ext_id)",
        ),
        (
            "size",
            "catalog_files_size_idx",
            "CREATE INDEX IF NOT EXISTS catalog_files_size_idx ON catalog_files(size_bytes)",
        ),
        (
            "modified date",
            "catalog_files_mtime_idx",
            "CREATE INDEX IF NOT EXISTS catalog_files_mtime_idx ON catalog_files(mtime, mtime_us)",
        ),
    )

    def missing_sort_indexes(self) -> List[Tuple[str, str]]:
        with self._connect() as connection:
            existing = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='index'"
                )
            }
        return [
            (label, statement)
            for label, name, statement in self.SORT_INDEXES
            if name not in existing
        ]

    def ensure_sort_indexes(
        self, progress: Optional[Callable[[str, int, int], None]] = None
    ) -> None:
        """Install optional WebUI indexes on existing inventories."""
        statements = self.missing_sort_indexes()
        connection = sqlite3.connect(self.path, timeout=60)
        try:
            connection.create_function(
                "path_key", 1, self._path_key, deterministic=True
            )
            connection.execute("PRAGMA busy_timeout=60000")
            for position, (label, statement) in enumerate(statements, 1):
                if progress:
                    progress(label, position, len(statements))
                connection.execute(statement)
                connection.commit()
        finally:
            connection.close()

    def ensure_evidence_indexes(
        self, progress: Optional[Callable[[str, int, int], None]] = None
    ) -> None:
        """Backfill indexed evidence paths for databases created before this feature."""
        connection = sqlite3.connect(self.path, timeout=60)
        try:
            connection.create_function(
                "path_key", 1, self._path_key, deterministic=True
            )
            connection.execute("PRAGMA busy_timeout=60000")
            for position, table in enumerate(("snaffler_matches", "downloads"), 1):
                columns = {
                    row[1] for row in connection.execute(f"PRAGMA table_info({table})")
                }
                if "remote_path_key" not in columns:
                    connection.execute(
                        f"ALTER TABLE {table} ADD COLUMN remote_path_key TEXT"
                    )
                    connection.commit()
                if progress:
                    progress(f"{table} evidence", position, 2)
                connection.execute(
                    f"UPDATE {table} SET remote_path_key=path_key(json_extract(payload_json, '$.remote_path')) WHERE remote_path_key IS NULL"
                )
                connection.execute(
                    f"CREATE INDEX IF NOT EXISTS {table}_lookup_idx ON {table}(scan_id, share_id, remote_path_key)"
                )
                connection.commit()
        finally:
            connection.close()

    def ensure_search_index(self) -> None:
        connection = sqlite3.connect(self.path, timeout=60)
        try:
            connection.execute("BEGIN IMMEDIATE")
            ensure_search_index(connection)
            connection.commit()
        finally:
            connection.close()

    def missing_ranking_indexes(self) -> List[Tuple[str, str]]:
        with self._connect() as connection:
            if not triage_result_path(self.path).is_file():
                return []
            existing = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM triage.sqlite_master WHERE type='index'"
                )
            }
        return [(name, sql) for name, sql in WEB_SORT_INDEXES if name not in existing]

    def ensure_ranking_indexes(self) -> None:
        missing = self.missing_ranking_indexes()
        if not missing:
            return
        connection = sqlite3.connect(triage_result_path(self.path), timeout=60)
        try:
            for _, statement in missing:
                connection.execute(statement)
            connection.commit()
        finally:
            connection.close()

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
        ranking_path = triage_result_path(self.path)
        if ranking_path.is_file():
            connection.execute(
                "ATTACH DATABASE ? AS triage",
                (str(ranking_path.resolve()),),
            )
        jev_path = assessment_path(self.path)
        if jev_path.is_file():
            connection.execute(
                "ATTACH DATABASE ? AS jev",
                (str(jev_path.resolve()),),
            )
        return connection

    @staticmethod
    def _path_key(value: Any) -> str:
        return "/" + "/".join(
            part
            for part in str(value or "").replace("\\", "/").casefold().split("/")
            if part
        )

    def _record(self, row: sqlite3.Row) -> FileRecord:
        assert self._public_id_key is not None
        file_id = int(row["id"])
        record = FileRecord(
            public_id(self._public_id_key, file_id),
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
        record.catalog_id = file_id
        return record

    @staticmethod
    def _latest_observation() -> str:
        # Query the normalized observation table directly: the scan_files view
        # adds joins that defeat the (file_id, share_id) primary key and force a
        # full scan in this correlated subquery.
        return """(SELECT observation.share_id FROM scan_observations observation
                   JOIN shares observation_share ON observation_share.id=observation.share_id
                   JOIN hosts observation_host ON observation_host.id=observation_share.host_id
                   JOIN scans observation_scan ON observation_scan.id=observation_host.scan_id
                   WHERE observation.file_id=files.id
                   ORDER BY observation_scan.started_at_utc DESC, observation.seq DESC
                   LIMIT 1)"""

    @classmethod
    def _evidence_join(cls, table: str) -> str:
        # table is an internal constant, never a request parameter.
        return f"""JOIN scan_observations sf ON sf.file_id=files.id
                       AND sf.share_id={cls._latest_observation()}
                   JOIN shares sf_share ON sf_share.id=sf.share_id
                   JOIN hosts sf_host ON sf_host.id=sf_share.host_id
                   JOIN {table} evidence ON evidence.scan_id=sf_host.scan_id
                       AND evidence.share_id=sf.share_id
                        AND evidence.remote_path_key=path_key(files.remote_path)"""

    def _write_connect(self) -> sqlite3.Connection:
        """Short-lived writer for web-initiated download/Nemesis evidence."""
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    @staticmethod
    def _observation_target(
        connection: sqlite3.Connection, public_id: str
    ) -> Optional[sqlite3.Row]:
        file_id = resolve_public_id(connection, public_id)
        if file_id is None:
            return None
        return connection.execute(
            """SELECT sf_host.scan_id AS scan_id, sf.share_id AS share_id,
                      files.remote_path AS remote_path
               FROM files
               JOIN scan_observations sf ON sf.file_id=files.id
                 AND sf.share_id=(SELECT observation.share_id FROM scan_observations observation
                     JOIN shares observation_share
                       ON observation_share.id=observation.share_id
                     JOIN hosts observation_host
                       ON observation_host.id=observation_share.host_id
                     JOIN scans observation_scan
                       ON observation_scan.id=observation_host.scan_id
                     WHERE observation.file_id=files.id
                     ORDER BY observation_scan.started_at_utc DESC,
                              observation.seq DESC LIMIT 1)
               JOIN shares sf_share ON sf_share.id=sf.share_id
               JOIN hosts sf_host ON sf_host.id=sf_share.host_id
               WHERE files.id=?""",
            (file_id,),
        ).fetchone()

    @staticmethod
    def _web_download_row(
        connection: sqlite3.Connection,
        scan_id: str,
        share_id: int,
        remote_path_key: str,
    ) -> Optional[sqlite3.Row]:
        return connection.execute(
            """SELECT id, payload_json FROM downloads
               WHERE scan_id=? AND share_id=? AND remote_path_key=?
                 AND json_extract(payload_json, '$.source')='web'
               ORDER BY id DESC LIMIT 1""",
            (scan_id, share_id, remote_path_key),
        ).fetchone()

    def _web_base_payload(self, record: FileRecord, now: str) -> Dict[str, Any]:
        return {
            "host": record.host,
            "share_name": record.share,
            "remote_path": record.remote_path,
            "unc_path": record.unc_path,
            "local_filename": record.file_name,
            "size_bytes": record.size_bytes,
            "actual_size_bytes": 0,
            "sha256": "",
            "mtime_utc": record.mtime_utc,
            "timestamp_utc": now,
            "source": "web",
            "download_count": 0,
            "downloaded_at_utc": "",
            "nemesis": {},
        }

    def _record_web_transfer(
        self,
        public_id: str,
        base: Callable[[], Dict[str, Any]],
        update: Callable[[Dict[str, Any]], None],
    ) -> None:
        """Upsert one web row per file, keyed by its latest observation path."""
        connection = self._write_connect()
        try:
            target = self._observation_target(connection, public_id)
            if target is None:
                return
            key = self._path_key(target["remote_path"])
            row = self._web_download_row(
                connection, target["scan_id"], target["share_id"], key
            )
            payload = json.loads(row["payload_json"]) if row else base()
            update(payload)
            payload["updated_at_utc"] = utc_now()
            encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            if row:
                connection.execute(
                    "UPDATE downloads SET payload_json=? WHERE id=?",
                    (encoded, row["id"]),
                )
            else:
                connection.execute(
                    "INSERT INTO downloads"
                    "(scan_id, share_id, remote_path_key, payload_json) "
                    "VALUES (?, ?, ?, ?)",
                    (target["scan_id"], target["share_id"], key, encoded),
                )
            connection.commit()
        finally:
            connection.close()
            # Web writes do not bump the scan revision, so cached totals would
            # otherwise hide the new evidence from activity filters.
            self._total_cache.clear()

    def record_download(
        self, record: FileRecord, actual_size: int, sha256: str
    ) -> None:
        now = utc_now()

        def update(payload: Dict[str, Any]) -> None:
            payload["download_count"] = int(payload.get("download_count") or 0) + 1
            payload["downloaded_at_utc"] = now
            payload["actual_size_bytes"] = int(actual_size)
            payload["sha256"] = sha256

        self._record_web_transfer(
            record.id, lambda: self._web_base_payload(record, now), update
        )

    def record_nemesis(self, record: FileRecord, state: Dict[str, Any]) -> None:
        now = utc_now()

        def update(payload: Dict[str, Any]) -> None:
            response_id = str(state.get("response_id") or "")
            prior = state.get("response_ids") or []
            payload["nemesis"] = {
                "status": state.get("status"),
                "attempts": state.get("attempts"),
                "response_id": response_id,
                "response_ids": list(prior),
                "deliveries": (1 if response_id else 0) + len(prior),
                "last_error": state.get("error") or state.get("last_error"),
                "updated_at": state.get("updated_at") or now,
            }

        self._record_web_transfer(
            record.id, lambda: self._web_base_payload(record, now), update
        )

    def _enrich(self, records: List[FileRecord]) -> List[FileRecord]:
        """Load only the selected files' latest evidence in bounded SQL batches."""
        with self._connect() as connection:
            for offset in range(0, len(records), 400):
                batch = {
                    record.catalog_id: record
                    for record in records[offset : offset + 400]
                }
                placeholders = ",".join("?" for _ in batch)
                selected = f" WHERE files.id IN ({placeholders})"
                parameters = list(batch)
                observations = connection.execute(
                    f"""SELECT files.id, share.payload_json,
                               scan.started_at_utc
                        FROM files JOIN scan_observations sf ON sf.file_id=files.id
                            AND sf.share_id={self._latest_observation()}
                        JOIN shares share ON share.id=sf.share_id
                        JOIN hosts sf_host ON sf_host.id=share.host_id
                        JOIN scans scan ON scan.id=sf_host.scan_id"""
                    + selected,
                    parameters,
                )
                for row in observations:
                    record = batch[int(row[0])]
                    payload: Dict[str, Any] = json.loads(row[1])
                    record.permissions = payload.get("permissions") or {}
                    record.collection_status = "not_collected"
                    record.metadata_scan_timestamp_utc = str(row[2])
                for table in ("snaffler_matches", "downloads"):
                    evidence_rows = connection.execute(
                        "SELECT files.id, evidence.payload_json FROM files "
                        + self._evidence_join(table)
                        + selected
                        + " ORDER BY evidence.id",
                        parameters,
                    )
                    for row in evidence_rows:
                        record = batch[int(row[0])]
                        detail: Dict[str, Any] = json.loads(row[1])
                        if table == "snaffler_matches":
                            record.rule_matches += (detail,)
                            continue
                        count = detail.get("download_count")
                        row_count = int(count) if count is not None else 1
                        if row_count > 0:
                            record.download_count = max(
                                record.download_count, row_count
                            )
                            record.collection_status = "collected"
                            record.collection_detail = detail
                            record.downloaded_at_utc = str(
                                detail.get("downloaded_at_utc")
                                or detail.get("timestamp_utc")
                                or ""
                            )
                        nemesis = detail.get("nemesis") or {}
                        if nemesis:
                            record.nemesis_status = str(nemesis.get("status") or "")
                            record.nemesis_deliveries = int(
                                nemesis.get("deliveries") or 0
                            )
                            record.nemesis_updated_at_utc = str(
                                nemesis.get("updated_at") or ""
                            )
                            record.nemesis_response_id = str(
                                nemesis.get("response_id") or ""
                            )
                            record.nemesis_error = str(nemesis.get("last_error") or "")
        return records

    @classmethod
    def _where(
        cls,
        q: str,
        host: FacetValue,
        share: FacetValue,
        extension: FacetValue,
        rule: FacetValue = "",
        triage: FacetValue = "",
        permission: FacetValue = "",
        collection: FacetValue = "",
        ranking_run: str = "",
        ranking_category: str = "",
        ranking_min: int = 0,
        activity: FacetValue = "",
        exclude: Optional[Mapping[str, FacetValue]] = None,
    ) -> Tuple[str, List[Any]]:
        filters = FacetFilters.build(
            host,
            share,
            extension,
            rule,
            triage,
            permission,
            collection,
            activity,
            exclude,
        )
        include, excluded = filters.include, filters.exclude
        clauses: List[str] = []
        values: List[Any] = []

        def placeholders(items: Tuple[str, ...]) -> str:
            return ",".join("?" for _ in items)

        for column in ("host", "share", "extension"):
            if include[column]:
                clauses.append(f"files.{column} IN ({placeholders(include[column])})")
                values.extend(include[column])
            if excluded[column]:
                clauses.append(
                    f"files.{column} NOT IN ({placeholders(excluded[column])})"
                )
                values.extend(excluded[column])
        for term in q.casefold().split():
            clauses.append("files.search_text LIKE ? ESCAPE '\\'")
            escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            values.append(f"%{escaped}%")
        matches = (
            "SELECT 1 FROM files AS matched_file "
            + cls._evidence_join("snaffler_matches")
            + " WHERE matched_file.id=files.id AND "
        )
        evidence_keys = (("rule", "rule_name"), ("triage", "triage"))
        # Rule and triage includes must hold on the same Snaffler match.
        match_conditions: List[str] = []
        for facet, key in evidence_keys:
            if include[facet]:
                match_conditions.append(
                    f"json_extract(evidence.payload_json, '$.{key}') "
                    f"IN ({placeholders(include[facet])})"
                )
                values.extend(include[facet])
        if match_conditions:
            clauses.append("EXISTS (" + matches + " AND ".join(match_conditions) + ")")
        # An exclusion drops a file if any of its matches carries the value;
        # files without matches have nothing to exclude and are kept.
        for facet, key in evidence_keys:
            if excluded[facet]:
                clauses.append(
                    "NOT EXISTS ("
                    + matches
                    + f"json_extract(evidence.payload_json, '$.{key}') "
                    + f"IN ({placeholders(excluded[facet])}))"
                )
                values.extend(excluded[facet])
        for names, prefix in (
            (include["permission"], ""),
            (excluded["permission"], "NOT "),
        ):
            if names:
                clauses.append(
                    f"""{prefix}EXISTS (SELECT 1 FROM scan_observations sf
                    JOIN shares sh ON sh.id=sf.share_id
                    WHERE sf.file_id=files.id AND sf.share_id={cls._latest_observation()}
                    AND ("""
                    + " OR ".join("json_extract(sh.payload_json, ?)=1" for _ in names)
                    + "))"
                )
                values.extend(PERMISSION_PATHS[name] for name in names)
        downloads = (
            "EXISTS (SELECT 1 FROM files AS matched_file "
            + cls._evidence_join("downloads")
            + " WHERE matched_file.id=files.id AND "
        )
        is_download = (
            "COALESCE(json_extract(evidence.payload_json, '$.download_count'), 1) > 0)"
        )
        is_uploaded = (
            "json_extract(evidence.payload_json, '$.nemesis.status')='uploaded')"
        )
        # Every predicate below is an internal constant keyed by a validated
        # vocabulary value; none of them interpolates request input.
        predicates: Dict[str, Dict[str, str]] = {
            "collection": {
                "collected": downloads + is_download,
                "not_collected": "NOT " + downloads + is_download,
            },
            "activity": {
                "downloaded": downloads + is_download,
                "not_downloaded": "NOT " + downloads + is_download,
                "nemesis_sent": downloads + is_uploaded,
                "not_nemesis_sent": "NOT " + downloads + is_uploaded,
                "nemesis_failed": downloads
                + "json_extract(evidence.payload_json, '$.nemesis.status') IN "
                "('upload_failed','retrieval_failed','failed','unknown'))",
            },
        }
        for facet, table in predicates.items():
            if include[facet]:
                clauses.append(
                    "(" + " OR ".join(table[value] for value in include[facet]) + ")"
                )
            if excluded[facet]:
                clauses.append(
                    "NOT ("
                    + " OR ".join(table[value] for value in excluded[facet])
                    + ")"
                )
        if ranking_run and ranking_min > 0:
            clauses.append("ranking_score >= ?")
            values.append(ranking_min)
        if ranking_run and ranking_category:
            clauses.append("ranking_category.file_id IS NOT NULL")
        return (" WHERE " + " AND ".join(clauses) if clauses else "", values)

    def facets(self) -> Dict[str, List[str]]:
        now = time.monotonic()
        if self._facets_cache and now - self._facets_cache[0] < 10:
            return self._facets_cache[1]
        with self._connect() as connection:
            facets = {
                "hosts": [
                    str(row[0])
                    for row in connection.execute(
                        "SELECT host FROM catalog_dirs GROUP BY host "
                        "HAVING sum(file_count) > 0 ORDER BY host COLLATE NOCASE, host"
                    )
                ],
                "shares": [
                    str(row[0])
                    for row in connection.execute(
                        "SELECT share FROM catalog_dirs GROUP BY share "
                        "HAVING sum(file_count) > 0 ORDER BY share COLLATE NOCASE, share"
                    )
                ],
                "extensions": [
                    str(row[0])
                    for row in connection.execute(
                        "SELECT extension FROM catalog_extensions e WHERE EXISTS "
                        "(SELECT 1 FROM catalog_files WHERE ext_id = e.id) "
                        "ORDER BY extension"
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
                "activities": [
                    "downloaded",
                    "not_downloaded",
                    "nemesis_sent",
                    "not_nemesis_sent",
                    "nemesis_failed",
                ],
                "permissions": [
                    "read",
                    "write",
                    "add_file",
                    "add_subdirectory",
                    "write_dac",
                    "write_owner",
                ],
            }
        self._facets_cache = (now, facets)
        return facets

    def status(self) -> Dict[str, Any]:
        with self._connect() as connection:
            revision = connection.execute(
                "SELECT value FROM metadata WHERE key='revision'"
            ).fetchone()
            active = connection.execute(
                "SELECT EXISTS(SELECT 1 FROM scans WHERE status='running')"
            ).fetchone()
            revision_value = int(revision[0]) if revision else 0
            now = time.monotonic()
            if self._status_cache and now - self._status_cache[0] < 10:
                file_count, host_count = self._status_cache[1:]
            else:
                counts = connection.execute(
                    "SELECT coalesce(sum(file_count), 0), count(DISTINCT host) "
                    "FROM catalog_dirs WHERE file_count > 0"
                ).fetchone()
                file_count, host_count = int(counts[0]), int(counts[1])
                self._status_cache = (now, file_count, host_count)
        return {
            "results_name": self.path.name,
            "schema_version": 3,
            "file_count": file_count,
            "host_count": host_count,
            "revision": revision_value,
            "scan_active": bool(active[0]),
            "rating_full": self.scoring.rating_full,
            "ranking_runs": self.ranking_catalog().get("runs", []),
            "jev_runs": jev_catalog(self.path),
        }

    def ranking_catalog(self) -> Dict[str, Any]:
        try:
            return triage_catalog(self.path)
        except (OSError, sqlite3.Error, ValueError):
            return {"scans": [], "runs": []}

    def _resolve_jev_run(self, requested: str) -> str:
        """Pick the assessment run to surface, preferring a finished one.

        A run that exists is honoured as-is, matching the ranking dropdown.
        This keeps a run selectable the moment it exists: an in-progress run may
        have completed no batch yet, so it never appears among finished runs even
        though the client enables it as soon as its status is ``running`` or
        ``paused``. When nothing is requested, fall back to the newest finished
        run, then to the newest run of any status.

        An id that no longer exists resolves to no run at all. Callers join the
        assessment tables only when this returns something, so a stale id in a
        shared URL degrades to an inventory without AI scores instead of
        failing the request with a missing-table error.
        """
        runs = jev_catalog(self.path)
        if requested:
            return requested if any(run["id"] == requested for run in runs) else ""
        if not runs:
            return ""
        for run in runs:
            if run["status"] in {"completed", "partial"}:
                return run["id"]
        return runs[0]["id"]

    @staticmethod
    def _ranking_join(run_id: str, category: str) -> Tuple[str, List[Any], str]:
        if not run_id:
            return "", [], "0"
        joins = (
            " LEFT JOIN triage.triage_files ranking"
            " ON ranking.file_id=files.id AND ranking.run_id=?"
        )
        values: List[Any] = [run_id]
        score = "COALESCE(ranking.priority, 0)"
        if category:
            joins += (
                " LEFT JOIN triage.triage_categories ranking_category"
                " ON ranking_category.file_id=files.id"
                " AND ranking_category.run_id=ranking.run_id"
                " AND ranking_category.category=?"
            )
            values.append(category)
            score = "COALESCE(ranking_category.score, 0)"
        return joins, values, score

    @staticmethod
    def _apply_ranking(
        records: List[FileRecord], rows: List[sqlite3.Row], category: str
    ) -> None:
        for record, row in zip(records, rows):
            record.ranking_run_id = str(row["ranking_run_id"] or "")
            record.ranking_priority = (
                int(row["ranking_priority"])
                if row["ranking_priority"] is not None
                else None
            )
            record.ranking_score = (
                int(row["ranking_score"]) if row["ranking_score"] is not None else None
            )
            record.ranking_category = category

    @staticmethod
    def _apply_jev(records: List[FileRecord], rows: List[sqlite3.Row]) -> None:
        for record, row in zip(records, rows):
            choice = row["jev_choice"]
            record.jev_run_id = str(row["jev_run_id"] or "")
            record.jev_choice = str(choice) if choice is not None else ""
            record.jev_score = priority_score(choice) if choice is not None else None
            record.jev_priority_name = PRIORITY_NAMES.get(record.jev_choice, "")

    def _apply_combined(
        self,
        records: List[FileRecord],
        *,
        rating_available: bool,
        jev_available: bool,
    ) -> None:
        for record in records:
            rating = record.ranking_score if record.ranking_run_id else None
            jev = record.jev_score if record.jev_run_id else None
            record.combined_score, record.combined_coverage = combine_priority(
                rating,
                jev,
                rating_available=rating_available,
                jev_available=jev_available,
                config=self.scoring,
            )

    def get(self, public_id: str) -> Optional[FileRecord]:
        with self._connect() as connection:
            file_id = resolve_public_id(connection, public_id)
            if file_id is None:
                return None
            row = connection.execute(
                "SELECT * FROM files WHERE id=?", (file_id,)
            ).fetchone()
        return self._enrich([self._record(row)])[0] if row else None

    def _search_catalog(
        self,
        q: str,
        host: FacetValue,
        share: FacetValue,
        extension: FacetValue,
        page: int,
        per_page: int,
        sort: str,
        direction: str,
        include_total: bool,
    ) -> Dict[str, Any]:
        """Index-backed catalog search: resolve ids from the normalized tables.

        Only used when no ranking/assessment run and no evidence facet is in
        play; the presentation columns are still rendered through the ``files``
        view. Sorting walks the directory/name/size indexes, so a deep page
        never materializes a temporary sort.
        """
        if direction not in {"asc", "desc"}:
            raise ValueError("Invalid inventory sort direction")
        order_keys = {
            "path": [
                "d.host COLLATE NOCASE",
                "d.share COLLATE NOCASE",
                "d.path COLLATE NOCASE",
                "d.id",
                "f.name COLLATE NOCASE",
                "f.id",
            ],
            "location": [
                "d.host COLLATE NOCASE",
                "d.share COLLATE NOCASE",
                "d.path COLLATE NOCASE",
                "d.id",
                "f.name COLLATE NOCASE",
                "f.id",
            ],
            "file": ["f.name COLLATE NOCASE", "f.id"],
            "type": ["e.extension COLLATE NOCASE", "e.id", "f.id"],
            "size": ["f.size_bytes", "f.id"],
            "modified": ["f.mtime", "f.mtime_us", "f.id"],
        }
        if sort not in order_keys:
            raise ValueError("Invalid inventory sort")
        hosts = _facet_values(host)
        shares = _facet_values(share)
        extensions = _facet_values(extension)
        terms = list(dict.fromkeys(term for term in q.casefold().split() if term))
        where: List[str] = []
        values: List[Any] = []
        # Only join the dictionary tables a query actually needs. Both joins
        # cost a primary-key lookup per row, so an unconditional join turns a
        # deep page over an otherwise flat index into hundreds of ms: every
        # skipped row still pays for the join it does not use.
        needs_dirs = sort in ("path", "location") or bool(hosts) or bool(shares)
        needs_extension = sort == "type" or bool(extensions)
        source = "catalog_files f"
        if needs_dirs:
            source += " JOIN catalog_dirs d ON d.id=f.dir_id"
        if needs_extension:
            source += " JOIN catalog_extensions e ON e.id=f.ext_id"
        with self._connect() as connection:
            connection.execute("BEGIN")
            if hosts:
                where.append(f"d.host IN ({','.join('?' for _ in hosts)})")
                values.extend(hosts)
            if shares:
                where.append(f"d.share IN ({','.join('?' for _ in shares)})")
                values.extend(shares)
            if extensions:
                where.append(f"e.extension IN ({','.join('?' for _ in extensions)})")
                values.extend(extensions)
            plans: List[Any] = []
            if terms:
                plans = [search_plan_term(connection, term) for term in terms]
                for plan in plans:
                    sql, params = search_predicate(plan, "f")
                    where.append(sql)
                    values.extend(params)
                # A term (or the whole query) with bounded candidates is driven
                # by its id list; a term whose name match is unbounded makes the
                # intersection unbounded and is answered by walking the sort
                # index with the predicate.
                bounded = search_bounded_ids(connection, plans)
                if bounded is not None:
                    where.append("f.id IN (SELECT value FROM json_each(?))")
                    values.append(json.dumps(sorted(bounded)))
            clause = (" WHERE " + " AND ".join(where)) if where else ""
            revision_row = connection.execute(
                "SELECT value FROM metadata WHERE key='revision'"
            ).fetchone()
            revision = int(revision_row[0]) if revision_row else 0
            total = None
            if include_total:
                # Totals are cached against the catalog revision, which every
                # writer bumps in the same commit as its change. The UI asks for
                # a total on every request, including paging, so recounting each
                # time is what regressed against the pre-normalization path.
                total_key = (
                    revision,
                    "catalog",
                    tuple(terms),
                    tuple(hosts),
                    tuple(shares),
                    tuple(extensions),
                )
                total = self._total_cache.get(total_key)
                if total is None:
                    total = catalog_total(
                        connection, terms, plans, hosts, shares, extensions
                    )
                    if len(self._total_cache) >= 64:
                        self._total_cache.clear()
                    self._total_cache[total_key] = total
            order = ", ".join(f"{key} {direction.upper()}" for key in order_keys[sort])
            per_page = min(max(per_page, 1), self.page_size, 500)
            page = max(page, 1)
            start = (page - 1) * per_page
            fetch = per_page if include_total else per_page + 1
            ids = [
                int(row[0])
                for row in connection.execute(
                    f"SELECT f.id FROM {source}{clause} ORDER BY {order} "
                    "LIMIT ? OFFSET ?",
                    (*values, fetch, start),
                )
            ]
            has_next = (
                len(ids) > per_page if total is None else start + per_page < total
            )
            ids = ids[:per_page]
            rows = (
                {
                    int(row["id"]): row
                    for row in connection.execute(
                        "SELECT * FROM files WHERE id IN "
                        "(SELECT value FROM json_each(?))",
                        (json.dumps(ids),),
                    )
                }
                if ids
                else {}
            )
            records = [self._record(rows[file_id]) for file_id in ids]
            items = [record.public() for record in self._enrich(records)]
        return {
            "items": items,
            "page": page,
            "per_page": per_page,
            "total": total,
            "has_next": has_next,
            "revision": revision,
        }

    def search(
        self,
        q: str,
        host: FacetValue,
        share: FacetValue,
        extension: FacetValue,
        page: int,
        per_page: int,
        rule: FacetValue = "",
        triage: FacetValue = "",
        permission: FacetValue = "",
        collection: FacetValue = "",
        ranking_run: str = "",
        ranking_category: str = "",
        ranking_min: int = 0,
        sort: str = "path",
        direction: str = "asc",
        include_total: bool = True,
        activity: FacetValue = "",
        jev_run: str = "",
        exclude: Optional[Mapping[str, FacetValue]] = None,
    ) -> Dict[str, Any]:
        if (
            sort in {"", "path", "location", "file", "type", "size", "modified"}
            and not rule
            and not triage
            and not permission
            and not collection
            and not activity
            and not exclude
            and not ranking_run
            and not ranking_category
            and ranking_min == 0
            and not jev_run
        ):
            return self._search_catalog(
                q,
                host,
                share,
                extension,
                page,
                per_page,
                sort or "path",
                direction,
                include_total,
            )
        where, where_values = self._where(
            q,
            host,
            share,
            extension,
            rule,
            triage,
            permission,
            collection,
            ranking_run,
            ranking_category,
            ranking_min,
            activity,
            exclude,
        )
        joins, join_values, ranking_score = self._ranking_join(
            ranking_run, ranking_category
        )
        jev_run_id = self._resolve_jev_run(jev_run)
        jev_join = ""
        jev_join_values: List[Any] = []
        jev_projection = "NULL AS jev_choice, '' AS jev_run_id"
        jev_order: Optional[str] = None
        if jev_run_id:
            # Scope the assessment-file join to the chosen run (inner join). A
            # bare join keyed only on file_id would multiply rows across every
            # assessment run that has touched the file, which mis-counts totals
            # and pagination unless the run is constrained here.
            jev_join = (
                " LEFT JOIN jev.assessment_files jev_file"
                " ON jev_file.file_id=files.id AND jev_file.run_id=?"
                " LEFT JOIN jev.decision_results jev_result"
                " ON jev_result.id=jev_file.result_id"
                " AND jev_result.run_id=jev_file.run_id"
            )
            jev_join_values = [jev_run_id]
            jev_projection = (
                "jev_result.choice AS jev_choice, jev_file.run_id AS jev_run_id"
            )
            jev_order = "CAST(jev_result.choice AS INTEGER)"
        combined_expr = combined_sql(
            ranking_score,
            "jev_result.choice",
            rating_available=bool(ranking_run),
            jev_available=bool(jev_run_id),
            config=self.scoring,
        )
        combined_projection = (
            f"{combined_expr} AS combined_score"
            if combined_expr
            else "NULL AS combined_score"
        )
        ranking_projection = (
            (
                "ranking.run_id AS ranking_run_id, ranking.priority AS ranking_priority, "
                f"{ranking_score} AS ranking_score"
                if ranking_run
                else "'' AS ranking_run_id, NULL AS ranking_priority, NULL AS ranking_score"
            )
            + ", "
            + jev_projection
            + ", "
            + combined_projection
        )
        values = join_values + jev_join_values + where_values
        if ranking_run and ranking_min > 0:
            where = where.replace("ranking_score >= ?", f"{ranking_score} >= ?")
        ranking_source = "files" + joins + jev_join
        ranking_order_id = "files.id"
        if sort == "priority" and ranking_run and direction == "desc" and not jev_join:
            # These are inner joins: the indexed score is never NULL. Using
            # COALESCE or the inventory's ID in ORDER BY forces a temporary sort.
            indexed_score = (
                "ranking_category.score" if ranking_category else "ranking.priority"
            )
            where = where.replace(ranking_score, indexed_score)
            ranking_order_id = (
                "ranking_category.file_id" if ranking_category else "ranking.file_id"
            )
            ranking_score = indexed_score
            if ranking_category:
                ranking_source = (
                    "triage.triage_categories ranking_category "
                    "JOIN triage.triage_files ranking"
                    " ON ranking.run_id=ranking_category.run_id"
                    " AND ranking.file_id=ranking_category.file_id "
                    "JOIN files ON files.id=ranking.file_id"
                )
                values = [ranking_run, ranking_category, *where_values]
            else:
                ranking_source = (
                    "triage.triage_files ranking JOIN files ON files.id=ranking.file_id"
                )
                values = [ranking_run, *where_values]
            where = (
                " WHERE ranking.run_id=?"
                + (" AND ranking_category.category=?" if ranking_category else "")
                + (" AND " + where[7:] if where else "")
            )
        sort_columns = {
            "path": [
                "files.host COLLATE NOCASE",
                "files.share COLLATE NOCASE",
                "files.remote_path COLLATE NOCASE",
            ],
            "type": [
                "files.extension COLLATE NOCASE",
            ],
            "file": [
                "files.file_name COLLATE NOCASE",
            ],
            "location": [
                "files.host COLLATE NOCASE",
                "files.share COLLATE NOCASE",
                "files.remote_path COLLATE NOCASE",
            ],
            "priority": [ranking_score],
            "size": ["files.size_bytes"],
            "modified": ["files.mtime_utc"],
        }
        if jev_order:
            sort_columns["jev"] = [jev_order]
        if combined_expr:
            sort_columns["combined"] = [combined_expr]
        if direction not in {"asc", "desc"}:
            raise ValueError("Invalid inventory sort direction")
        # A score the caller cannot supply falls back to path order rather than
        # failing: the UI offers these sorts by default and disables the
        # unavailable ones, so a stale link must still render an inventory.
        # This has to happen before the membership check below, otherwise the
        # fallbacks are unreachable for exactly the keys they guard.
        if sort == "priority" and not ranking_run:
            sort = "path"
        if sort == "jev" and not jev_order:
            sort = "path"
        if sort == "combined" and not combined_expr:
            sort = "path"
        if sort not in sort_columns:
            raise ValueError("Invalid inventory sort")
        if sort == "jev":
            # Assessed files first, highest priority first; unassessed rows last
            # regardless of direction.
            order = (
                " ORDER BY (jev_result.choice IS NULL) ASC, "
                f"{jev_order} {direction.upper()}, files.id {direction.upper()}"
            )
        else:
            # Equal scores always break by ascending file id. That matches the
            # primary triage_priority/triage_category_score indexes and lets the
            # direction-specific duplicates stay deleted.
            tie_direction = (
                "ASC" if ranking_order_id != "files.id" else direction.upper()
            )
            order = (
                " ORDER BY "
                + ", ".join(
                    f"{column} {direction.upper()}" for column in sort_columns[sort]
                )
                + f", {ranking_order_id} {tie_direction}"
            )
        per_page = min(max(per_page, 1), self.page_size, 500)
        page = max(page, 1)
        start = (page - 1) * per_page
        revision = 0
        with self._connect() as connection:
            # The candidate probe and result query must observe the same scan
            # revision, including while the scanner commits new files.
            connection.execute("BEGIN")
            candidate_ids = search_candidates(connection, q)
            if candidate_ids is not None:
                if ranking_order_id != "files.id":
                    # SQLite otherwise favors walking the entire score index,
                    # even for a handful of candidate IDs. CROSS JOIN pins the
                    # bounded inventory lookups as the outer loop.
                    ranking_source = (
                        "files CROSS JOIN triage.triage_files ranking"
                        " ON ranking.file_id=files.id"
                    )
                    if ranking_category:
                        ranking_source += (
                            " CROSS JOIN triage.triage_categories ranking_category"
                            " ON ranking_category.run_id=ranking.run_id"
                            " AND ranking_category.file_id=ranking.file_id"
                        )
                where += (" AND " if where else " WHERE ") + (
                    "files.id IN (SELECT value FROM json_each(?))"
                )
                values.append(json.dumps(candidate_ids))
            revision_row = connection.execute(
                "SELECT value FROM metadata WHERE key='revision'"
            ).fetchone()
            revision = int(revision_row[0]) if revision_row else 0
            total_key = (
                revision,
                q,
                FacetFilters.build(
                    host,
                    share,
                    extension,
                    rule,
                    triage,
                    permission,
                    collection,
                    activity,
                    exclude,
                ).key(),
                ranking_run,
                ranking_category,
                ranking_min,
                jev_run_id,
            )
            total = self._total_cache.get(total_key) if include_total else None
            if include_total and total is None:
                total = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM " + ranking_source + where, values
                    ).fetchone()[0]
                )
                if len(self._total_cache) >= 64:
                    self._total_cache.clear()
                self._total_cache[total_key] = total
            fetch_limit = per_page if include_total else per_page + 1
            rows = connection.execute(
                "SELECT files.*, "
                + ranking_projection
                + " FROM "
                + ranking_source
                + where
                + order
                + " LIMIT ? OFFSET ?",
                (*values, fetch_limit, start),
            )
            rows = list(rows)
            has_next = (
                len(rows) > per_page if total is None else start + per_page < total
            )
            rows = rows[:per_page]
            records = [self._record(row) for row in rows]
            self._apply_ranking(records, rows, ranking_category)
            self._apply_jev(records, rows)
            self._apply_combined(
                records,
                rating_available=bool(ranking_run),
                jev_available=bool(jev_run_id),
            )
            items = [record.public() for record in self._enrich(records)]
        return {
            "items": items,
            "page": page,
            "per_page": per_page,
            "total": total,
            "has_next": has_next,
            # The metadata revision this page was read at, so the client can
            # tell a genuinely newer inventory from a narrower search result.
            "revision": revision,
        }

    def tree(
        self,
        q: str,
        host: FacetValue,
        share: FacetValue,
        extension: FacetValue,
        rule: FacetValue = "",
        triage: FacetValue = "",
        permission: FacetValue = "",
        collection: FacetValue = "",
        ranking_run: str = "",
        ranking_category: str = "",
        ranking_min: int = 0,
        sort: str = "path",
        direction: str = "asc",
        activity: FacetValue = "",
        jev_run: str = "",
        exclude: Optional[Mapping[str, FacetValue]] = None,
    ) -> Dict[str, Any]:
        """Return root host nodes; descendants are loaded on expansion.

        ``jev_run`` is accepted for parity with ``search`` and ``tree_branch``.
        The root query groups by host and never projects a per-file score, so
        the run is resolved and then unused: resolving it here keeps the three
        inventory readers on one selection contract instead of two.
        """
        self._resolve_jev_run(jev_run)
        fast = (
            not q
            and not host
            and not share
            and not extension
            and not rule
            and not triage
            and not permission
            and not collection
            and not activity
            and not exclude
            and not ranking_run
            and not ranking_category
            and not ranking_min
            and not jev_run
        )
        if fast:
            with self._connect() as connection:
                revision_row = connection.execute(
                    "SELECT value FROM metadata WHERE key='revision'"
                ).fetchone()
                rows = list(
                    connection.execute(
                        "SELECT host AS name, sum(file_count) AS file_count, "
                        "coalesce(sum(size_bytes), 0) AS size_bytes FROM catalog_dirs "
                        "GROUP BY host HAVING sum(file_count) > 0 "
                        "ORDER BY host COLLATE NOCASE, host"
                    )
                )
            hosts = [
                {
                    "name": str(row["name"]),
                    "file_count": int(row["file_count"]),
                    "size_bytes": int(row["size_bytes"]),
                    "shares": [],
                    "loaded": False,
                }
                for row in rows
            ]
            return {
                "total": sum(row["file_count"] for row in hosts),
                "hosts": hosts,
                "revision": int(revision_row[0]) if revision_row else 0,
            }
        where, where_values = self._where(
            q,
            host,
            share,
            extension,
            rule,
            triage,
            permission,
            collection,
            ranking_run,
            ranking_category,
            ranking_min,
            activity,
            exclude,
        )
        joins, join_values, ranking_score = self._ranking_join(
            ranking_run, ranking_category
        )
        omit_ranking_join = ranking_run and ranking_min == 0 and not ranking_category
        if omit_ranking_join:
            joins, join_values = "", []
        values = join_values + where_values
        if ranking_run and ranking_min > 0:
            where = where.replace("ranking_score >= ?", f"{ranking_score} >= ?")
        with self._connect() as connection:
            revision_row = connection.execute(
                "SELECT value FROM metadata WHERE key='revision'"
            ).fetchone()
            rows = list(
                connection.execute(
                    "SELECT files.host AS name, COUNT(*) AS file_count, "
                    "COALESCE(SUM(size_bytes), 0) AS size_bytes FROM files"
                    + joins
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
        # Same revision contract as the table response: the tree view tracks
        # inventory changes with it rather than with a filtered total.
        return {
            "total": sum(row["file_count"] for row in hosts),
            "hosts": hosts,
            "revision": int(revision_row[0]) if revision_row else 0,
        }

    def tree_branch(
        self,
        q: str,
        host: FacetValue,
        share: FacetValue,
        extension: FacetValue,
        parent: str,
        rule: FacetValue = "",
        triage: FacetValue = "",
        permission: FacetValue = "",
        collection: FacetValue = "",
        ranking_run: str = "",
        ranking_category: str = "",
        ranking_min: int = 0,
        sort: str = "path",
        direction: str = "asc",
        activity: FacetValue = "",
        jev_run: str = "",
        exclude: Optional[Mapping[str, FacetValue]] = None,
        level: str = "",
    ) -> Dict[str, Any]:
        """Return immediate children for one host, share, or folder.

        ``host`` names the branch and must be a single value. ``share`` names
        the share to walk; with ``level="shares"`` it is only a filter, so a
        host can be expanded while the share facet stays applied.
        """
        hosts = _facet_values(host)
        if len(hosts) != 1:
            raise ValueError("tree branch requires a host")
        if level not in {"", "shares"}:
            raise ValueError("Invalid tree branch level")
        shares = _facet_values(share)
        list_shares = level == "shares" or not shares
        if not list_shares and len(shares) != 1:
            raise ValueError("tree branch requires a single share")
        host = hosts[0]
        fast = (
            not q
            and not extension
            and not rule
            and not triage
            and not permission
            and not collection
            and not activity
            and not exclude
            and not ranking_run
            and not ranking_category
            and not ranking_min
            and not jev_run
            and (not list_shares or not shares)
        )
        if fast:
            with self._connect() as connection:
                if list_shares:
                    rows = list(
                        connection.execute(
                            "SELECT share AS name, sum(file_count) AS file_count, "
                            "coalesce(sum(size_bytes), 0) AS size_bytes FROM catalog_dirs "
                            "WHERE host=?1 COLLATE NOCASE AND host=?1 "
                            "GROUP BY share HAVING sum(file_count) > 0 "
                            "ORDER BY share COLLATE NOCASE, share",
                            (host,),
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

                base = "/" + parent.replace("\\", "/").strip("/")
                if base != "/":
                    base += "/"
                dir_rows = list(
                    connection.execute(
                        "SELECT path, file_count, size_bytes FROM catalog_dirs "
                        "WHERE host=?1 COLLATE NOCASE AND share=?2 COLLATE NOCASE "
                        "AND host=?1 AND share=?2 AND path>=?3 AND path<?4 "
                        "AND file_count > 0",
                        (host, shares[0], base, base[:-1] + "0"),
                    )
                )
                folders: Dict[str, Dict[str, Any]] = {}
                for row in dir_rows:
                    remainder = str(row["path"])[len(base) :]
                    if not remainder:
                        continue
                    segment = remainder.split("/", 1)[0]
                    entry = folders.setdefault(
                        segment,
                        {
                            "name": segment,
                            "host": host,
                            "share": shares[0],
                            "path": base.rstrip("/") + "/" + segment,
                            "file_count": 0,
                            "size_bytes": 0,
                            "folders": [],
                            "files": [],
                            "loaded": False,
                        },
                    )
                    entry["file_count"] += int(row["file_count"])
                    entry["size_bytes"] += int(row["size_bytes"] or 0)
                file_rows = list(
                    connection.execute(
                        "SELECT f.id FROM catalog_files f "
                        "JOIN catalog_dirs d ON d.id=f.dir_id "
                        "WHERE d.host=?1 COLLATE NOCASE AND d.share=?2 COLLATE NOCASE "
                        "AND d.host=?1 AND d.share=?2 "
                        "AND d.path=?3 COLLATE NOCASE AND d.path=?3 "
                        "ORDER BY f.name COLLATE NOCASE, f.id",
                        (host, shares[0], base),
                    )
                )
                ids = [int(row[0]) for row in file_rows]
                records: List[FileRecord] = []
                if ids:
                    rows = {
                        int(row["id"]): row
                        for row in connection.execute(
                            "SELECT * FROM files WHERE id IN "
                            "(SELECT value FROM json_each(?))",
                            (json.dumps(ids),),
                        )
                    }
                    records = [self._record(rows[file_id]) for file_id in ids]
            return {
                "folders": sorted(
                    folders.values(), key=lambda value: value["name"].casefold()
                ),
                "files": [r.public() for r in self._enrich(records)],
            }
        where, where_values = self._where(
            q,
            host,
            share,
            extension,
            rule,
            triage,
            permission,
            collection,
            ranking_run,
            ranking_category,
            ranking_min,
            activity,
            exclude,
        )
        joins, join_values, ranking_score = self._ranking_join(
            ranking_run, ranking_category
        )
        jev_run_id = self._resolve_jev_run(jev_run)
        jev_join = ""
        jev_join_values: List[Any] = []
        jev_projection = "NULL AS jev_choice, '' AS jev_run_id"
        if jev_run_id:
            # Constrain the assessment join to the chosen run so files are not
            # multiplied across every run that has touched them.
            jev_join = (
                " LEFT JOIN jev.assessment_files jev_file"
                " ON jev_file.file_id=files.id AND jev_file.run_id=?"
                " LEFT JOIN jev.decision_results jev_result"
                " ON jev_result.id=jev_file.result_id"
                " AND jev_result.run_id=jev_file.run_id"
            )
            jev_join_values = [jev_run_id]
            jev_projection = (
                "jev_result.choice AS jev_choice, jev_file.run_id AS jev_run_id"
            )
        combined_expr = combined_sql(
            ranking_score,
            "jev_result.choice",
            rating_available=bool(ranking_run),
            jev_available=bool(jev_run_id),
            config=self.scoring,
        )
        combined_projection = (
            f"{combined_expr} AS combined_score"
            if combined_expr
            else "NULL AS combined_score"
        )
        ranking_projection = (
            (
                "ranking.run_id AS ranking_run_id, ranking.priority AS ranking_priority, "
                f"{ranking_score} AS ranking_score"
                if ranking_run
                else "'' AS ranking_run_id, NULL AS ranking_priority, NULL AS ranking_score"
            )
            + ", "
            + jev_projection
            + ", "
            + combined_projection
        )
        base_values = join_values + where_values
        if ranking_run and ranking_min > 0:
            where = where.replace("ranking_score >= ?", f"{ranking_score} >= ?")
        if list_shares:
            aggregate_joins = joins
            aggregate_values = base_values
            if ranking_run and ranking_min == 0 and not ranking_category:
                aggregate_joins = ""
                aggregate_values = where_values
            with self._connect() as connection:
                rows = list(
                    connection.execute(
                        "SELECT files.share AS name, COUNT(*) AS file_count, "
                        "COALESCE(SUM(size_bytes), 0) AS size_bytes FROM files"
                        + aggregate_joins
                        + where
                        + " GROUP BY share ORDER BY share COLLATE NOCASE",
                        aggregate_values,
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
        subtree_clause = "(files.parent_path=? OR files.parent_path LIKE ? ESCAPE '\\')"
        escaped_parent = (
            normalized_parent.replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )
        where += (" AND " if where else " WHERE ") + subtree_clause
        values = join_values + jev_join_values + where_values
        values.extend((normalized_parent, escaped_parent.rstrip("/") + "/%"))
        order = " ORDER BY files.remote_path COLLATE NOCASE"
        if sort == "priority" and ranking_run and direction in {"asc", "desc"}:
            order = (
                " ORDER BY "
                + ranking_score
                + " "
                + direction.upper()
                + ", files.remote_path COLLATE NOCASE"
            )
        elif sort == "combined" and combined_expr and direction in {"asc", "desc"}:
            order = (
                " ORDER BY "
                + combined_expr
                + " "
                + direction.upper()
                + ", files.remote_path COLLATE NOCASE"
            )
        folders: Dict[str, Dict[str, Any]] = {}
        files: List[FileRecord] = []
        with self._connect() as connection:
            for row in connection.execute(
                "SELECT files.*, "
                + ranking_projection
                + " FROM files"
                + joins
                + jev_join
                + where
                + order,
                values,
            ):
                record = self._record(row)
                record_rows = [row]
                self._apply_ranking([record], record_rows, ranking_category)
                self._apply_jev([record], record_rows)
                self._apply_combined(
                    [record],
                    rating_available=bool(ranking_run),
                    jev_available=bool(jev_run_id),
                )
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
                        "share": shares[0],
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
    jev: Optional[JevService] = None
    nemesis: Optional[NemesisConfig] = None
    nemesis_max: int = 50 * 1024**2
    index_status: Dict[str, Any] = field(
        default_factory=lambda: {"status": "idle", "completed": 0, "total": 0}
    )


# Only the fields a status pill needs. The full job payload (rule preview
# candidates, run results) stays on /api/triage/job and /api/assessment/job.
JOB_SUMMARY_KEYS = (
    "id",
    "status",
    "phase",
    "processed",
    "total",
    "started_at",
    "updated_at",
    "finished_at",
    "preview",
    "assessment_run_id",
)


def _job_summary(service: Any) -> Optional[Dict[str, Any]]:
    if service is None:
        return None
    job = service.status()
    if not job:
        return None
    summary = {key: job.get(key) for key in JOB_SUMMARY_KEYS if key in job}
    summary["active"] = job.get("status") == "running"
    return summary


@dataclass(frozen=True)
class WebConfig:
    database_path: Path
    port: int
    token_auth: bool
    preview_max_bytes: int
    download_max_bytes: int
    page_size: int
    bind: str = "127.0.0.1"
    nemesis: Optional[NemesisConfig] = None
    nemesis_max_bytes: int = 50 * 1024**2
    jev: Optional[JevConfig] = None
    scoring: ScoringConfig = DEFAULT_SCORING


class WebServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request: Any, client_address: Tuple[str, int]) -> None:
        _type, error, _traceback = sys.exc_info()
        if isinstance(error, (BrokenPipeError, ConnectionResetError)):
            logging.debug(
                "Client disconnected while sending response to %s:%s", *client_address
            )
            return
        super().handle_error(request, client_address)

    def __init__(
        self,
        address: Tuple[str, int],
        state: WebState,
        allowed_hosts: Optional[set[str]] = None,
    ) -> None:
        self.state = state
        self.allowed_hosts = allowed_hosts
        super().__init__(address, WebHandler)


class WebHandler(BaseHTTPRequestHandler):
    server: WebServer
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        logging.debug("%s", escape_terminal(fmt % args))

    def _headers(
        self,
        status: int,
        content_type: str,
        length: int,
        extra: Optional[Dict[str, str]] = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        overrides = {name.casefold() for name in (extra or ())}
        for name, value in SECURITY_HEADERS.items():
            if name.casefold() in overrides:
                continue
            self.send_header(name, value)
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()

    def _send(
        self,
        body: bytes,
        status: int = 200,
        content_type: str = "application/json; charset=utf-8",
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        self._headers(status, content_type, len(body), extra_headers)
        self.wfile.write(body)

    def _empty(
        self, status: int, extra_headers: Optional[Dict[str, str]] = None
    ) -> None:
        """Answer a validator hit. A 304 carries no body and no Content-Length."""
        self.send_response(status)
        for name, value in SECURITY_HEADERS.items():
            if name.casefold() in {"cache-control", "pragma"}:
                continue
            self.send_header(name, value)
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _accepts_gzip(self) -> bool:
        return "gzip" in self.headers.get("Accept-Encoding", "").lower()

    def _not_modified(self, etag: str, modified: float) -> bool:
        """True when the client's validators already cover this representation."""
        stamp = self.date_time_string(int(modified))
        if_none_match = self.headers.get("If-None-Match", "")
        if if_none_match:
            candidates = {value.strip() for value in if_none_match.split(",")}
            return "*" in candidates or etag in candidates
        since = self.headers.get("If-Modified-Since")
        return bool(since) and since.strip() == stamp

    def _asset(self, relative: str) -> None:
        """Resolve and serve one file from web_assets.

        The extension table is the allow-list: an unknown suffix is refused
        rather than guessed at, and the resolved path must still sit inside
        ASSET_ROOT so no crafted traversal reaches the wider package.
        """
        if ".." in relative.split("/") or relative.startswith("/"):
            self._error(404, "Not found", "not_found")
            return
        suffix = Path(relative).suffix.lower()
        content_type = ASSET_TYPES.get(suffix)
        if content_type is None:
            self._error(404, "Not found", "not_found")
            return
        try:
            path = (ASSET_ROOT / relative).resolve()
            path.relative_to(ASSET_ROOT.resolve())
        except (OSError, ValueError):
            self._error(404, "Not found", "not_found")
            return
        try:
            body = path.read_bytes()
            modified = path.stat().st_mtime
        except OSError:
            self._error(404, "Not found", "not_found")
            return
        # Validators come from the file identity, not the bytes: assets change
        # only when they are rewritten, so mtime plus size is enough and the
        # response never has to be hashed on the request path.
        etag = f'W/"{int(modified * 1000):x}-{len(body):x}"'
        headers = {
            "ETag": etag,
            "Last-Modified": self.date_time_string(int(modified)),
            # Stylesheets, scripts, and fonts are immutable per deployment, so
            # they get a long shared lifetime. The two HTML documents are not:
            # they name their own assets, so caching one would strand the tab
            # on an older module graph.
            "Cache-Control": (
                "no-store" if suffix == ".html" else "public, max-age=3600"
            ),
        }
        if suffix == ".html":
            headers["Pragma"] = "no-cache"
        if self._not_modified(etag, modified):
            self._empty(304, headers)
            return
        self._send(body, content_type=content_type, extra_headers=headers)

    def _json(self, value: Any, status: int = 200) -> None:
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        headers: Dict[str, str] = {}
        # Inventory and job responses are polled constantly and must never be
        # served from a cache, so they opt out of every revalidation path.
        if len(body) >= GZIP_FLOOR and self._accepts_gzip():
            body = gzip.compress(body, 6, mtime=0)
            headers["Content-Encoding"] = "gzip"
            headers["Vary"] = "Accept-Encoding"
        self._send(body, status, extra_headers=headers)

    def _error(self, status: int, message: str, code: str) -> None:
        self._json({"error": message, "code": code}, status)

    def _valid_host(self) -> bool:
        """Reject foreign Host headers while accepting any local spelling.

        The port must always match the listening port, which blocks simple
        DNS-rebinding probes from another origin. When bound to a wildcard
        address any hostname on that port is accepted, because the operator
        asked to serve every interface. When bound to a specific address the
        hostname must be that address, a loopback name, the local machine name,
        or one of the machine's own addresses: a browser reaches a LAN bind by
        IP, by hostname, or by a DNS alias, and pinning to the raw ``--bind``
        value alone rejected every other spelling and returned HTTP 400 for the
        whole UI.
        """
        raw = self.headers.get("Host", "")
        parsed = urllib.parse.urlsplit("//" + raw)
        hostname = parsed.hostname
        port = parsed.port
        if port is None:
            # A portless Host is compared against the loopback/wildcard case
            # below using the bare registered port.
            port = self.server.server_port
        if port != self.server.server_port:
            return False
        if self.server.allowed_hosts is None:
            if self.server.server_address[0] in {"0.0.0.0", "::"}:
                return True
            return hostname in {"127.0.0.1", "localhost", "::1"}
        return hostname in self.server.allowed_hosts

    @staticmethod
    def _local_hostnames(bind: str) -> set[str]:
        """Host spellings that resolve to this machine for a given bind address."""
        names = {"127.0.0.1", "localhost", "::1", bind}
        try:
            names.add(socket.gethostname())
            names.add(socket.getfqdn())
        except OSError:  # pragma: no cover - hostname lookup is best effort
            pass
        try:
            names.update(socket.gethostbyname_ex(socket.gethostname())[2])
        except OSError:  # pragma: no cover
            pass
        return {name for name in names if name}

    def _authorized(self) -> bool:
        if not self.server.state.token:
            return True
        return secrets.compare_digest(
            self.headers.get("Authorization", ""), "Bearer " + self.server.state.token
        )

    def _guard(self) -> bool:
        if not self._valid_host():
            self._error(400, "Invalid Host header", "invalid_host")
            return False
        if not self._authorized():
            self._error(401, "Authentication required", "unauthorized")
            return False
        return True

    def _redirect(self, location: str) -> None:
        self._empty(301, {"Location": location, "Cache-Control": "no-store"})

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path in REDIRECTS:
            self._redirect(REDIRECTS[parsed.path])
            return
        if parsed.path.startswith("/assets/"):
            self._asset(urllib.parse.unquote(parsed.path[len("/assets/") :]))
            return
        if parsed.path in HTML_ROUTES:
            self._asset(HTML_ROUTES[parsed.path])
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
        if parsed.path.startswith("/api/assessment/"):
            self._assessment_get(parsed)
            return
        if parsed.path == "/api/status":
            status = state.index.status()
            status.update(
                {
                    "preview_max_bytes": state.preview_max,
                    "download_max_bytes": state.download_max,
                    "retrieval_enabled": state.pool is not None,
                    "triage_enabled": state.triage is not None,
                    "assessment_enabled": state.jev is not None,
                    "nemesis_enabled": state.nemesis is not None,
                    "nemesis_max_bytes": state.nemesis_max,
                    "index_optimization": dict(state.index_status),
                    "jobs": {
                        "rule": _job_summary(state.triage),
                        "ai": _job_summary(state.jev),
                    },
                }
            )
            self._json(status)
            return
        if parsed.path == "/api/facets":
            self._json(state.index.facets())
            return
        if parsed.path in {"/api/files", "/api/tree", "/api/tree/branch"}:
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if any(len(item) > 512 for value in query.values() for item in value):
                self._error(400, "Query value is too long", "invalid_query")
                return
            # Facets repeat (``host=a&host=b``) and negate under ``not_``;
            # every other parameter keeps its single-value contract.
            facet_args = {
                key: _facet_values(query.get(key, [])) for key in FILTER_FACETS
            }
            exclude = {
                key: _facet_values(query.get(EXCLUDE_PREFIX + key, []))
                for key in FILTER_FACETS
            }
            if any(
                len(values) > MAX_FACET_VALUES
                for values in (*facet_args.values(), *exclude.values())
            ):
                self._error(400, "Too many filter values", "invalid_query")
                return
            try:
                FacetFilters.build(**facet_args, exclude=exclude)
            except ValueError as exc:
                code = "activity" if "activity" in str(exc) else "evidence"
                self._error(400, f"Invalid {code} filter", "invalid_query")
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
                    "ranking_run",
                    "ranking_category",
                    "ranking_min",
                    "sort",
                    "direction",
                    "activity",
                )
            )
            facet_filters = (
                filters[0],
                facet_args["host"],
                facet_args["share"],
                facet_args["extension"],
                facet_args["rule"],
                facet_args["triage"],
                facet_args["permission"],
                facet_args["collection"],
            )
            if filters[11] not in {
                "",
                "path",
                "type",
                "file",
                "location",
                "priority",
                "size",
                "modified",
                "jev",
                "combined",
            }:
                self._error(400, "Invalid inventory sort", "invalid_query")
                return
            if filters[12] not in {"", "asc", "desc"}:
                self._error(400, "Invalid inventory sort direction", "invalid_query")
                return
            if filters[9] and not filters[8]:
                self._error(
                    400, "Ranking category requires a ranking run", "invalid_query"
                )
                return
            if filters[8] and not triage_result_path(state.index.path).is_file():
                self._error(
                    400,
                    "No saved ranking database exists for this inventory",
                    "invalid_query",
                )
                return
            try:
                ranking_min = int(filters[10] or "0")
            except ValueError:
                self._error(400, "Invalid ranking minimum", "invalid_query")
                return
            if ranking_min < 0 or ranking_min > 100000:
                self._error(400, "Invalid ranking minimum", "invalid_query")
                return
            ranking_args = (
                filters[8],
                filters[9],
                ranking_min,
                filters[11] or "path",
                filters[12]
                or (
                    "desc" if filters[11] in {"priority", "combined", "jev"} else "asc"
                ),
            )
            if parsed.path == "/api/tree/branch":
                try:
                    self._json(
                        state.index.tree_branch(
                            *facet_filters[:4],
                            query.get("parent", [""])[0],
                            *facet_filters[4:8],
                            *ranking_args,
                            activity=facet_args["activity"],
                            jev_run=query.get("jev_run", [""])[0],
                            exclude=exclude,
                            level=query.get("level", [""])[0],
                        )
                    )
                except (AttributeError, ValueError) as exc:
                    self._error(400, str(exc), "invalid_query")
                return
            if parsed.path == "/api/tree":
                self._json(
                    state.index.tree(
                        *facet_filters,
                        *ranking_args,
                        activity=facet_args["activity"],
                        jev_run=query.get("jev_run", [""])[0],
                        exclude=exclude,
                    )
                )
                return
            try:
                self._json(
                    state.index.search(
                        *facet_filters[:4],
                        int(query.get("page", ["1"])[0]),
                        int(query.get("per_page", [str(state.index.page_size)])[0]),
                        *facet_filters[4:8],
                        *ranking_args,
                        activity=facet_args["activity"],
                        include_total=query.get("include_total", ["0"])[0] == "1",
                        jev_run=query.get("jev_run", [""])[0],
                        exclude=exclude,
                    )
                )
            except (ValueError, OverflowError):
                self._error(400, "Invalid pagination", "invalid_query")
            return
        match = re.fullmatch(
            r"/api/files/([A-Za-z0-9_-]{8,32})(?:/(preview|download))?", parsed.path
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
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                while True:
                    chunk = handle.read(64 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    self.wfile.write(chunk)
            try:
                state.index.record_download(record, size, digest.hexdigest())
            except Exception as exc:
                logging.warning(
                    "Failed to record download for %s: %s",
                    escape_terminal(record.unc_path),
                    escape_terminal(str(exc)),
                )
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
            # A retained rule preview is read through the same listing and
            # explanation code as a saved run, just from its own database.
            output: Optional[Path] = None
            if "preview" in query and parsed.path in (
                "/api/triage/files",
                "/api/triage/explain",
            ):
                if run_id is not None:
                    raise ValueError("use either run or preview, not both")
                output, run_id = service.preview_source(query["preview"][0])
            after = None
            if "after_score" in query or "after_id" in query:
                after = (int(query["after_score"][0]), query["after_id"][0])
            if parsed.path == "/api/triage/catalog":
                self._json(triage_catalog(service.database))
            elif parsed.path == "/api/triage/job":
                self._json({"job": service.status()})
            elif parsed.path == "/api/triage/preview":
                self._json({"preview": service.preview()})
            elif parsed.path == "/api/triage/files":
                self._json(
                    triage_list(
                        service.database,
                        run_id,
                        query.get("category", [None])[0],
                        min(100, int(query.get("limit", ["100"])[0])),
                        int(query.get("min_score", ["0"])[0]),
                        output=output,
                        after=after,
                    )
                )
            elif parsed.path == "/api/triage/explain":
                self._json(
                    triage_explain(
                        service.database, query["file_id"][0], run_id, output
                    )
                )
            elif parsed.path == "/api/triage/compare":
                changed = query.get("changed", ["1"])[0]
                if changed not in ("0", "1"):
                    raise ValueError("changed must be 0 or 1")
                self._json(
                    service.compare(
                        query["preview"][0],
                        query.get("base", [None])[0],
                        order=query.get("order", ["delta"])[0],
                        limit=min(100, int(query.get("limit", ["100"])[0])),
                        after=after,
                        changed_only=changed == "1",
                    )
                )
            else:
                self._error(404, "Unknown ranking endpoint", "not_found")
        except PreviewGoneError as exc:
            self._error(410, str(exc), "preview_gone")
        except (ValueError, KeyError, OSError, sqlite3.Error) as exc:
            self._error(400, str(exc), "invalid_query")

    def _assessment_get(self, parsed: urllib.parse.SplitResult) -> None:
        service = self.server.state.jev
        if service is None:
            self._error(404, "Assessment is unavailable", "not_found")
            return
        query = urllib.parse.parse_qs(parsed.query)
        if any(len(values) != 1 or len(values[0]) > 512 for values in query.values()):
            self._error(400, "Invalid assessment query", "invalid_query")
            return
        try:
            run_id = query.get("run", [None])[0]
            path = parsed.path
            if path == "/api/assessment/check":
                self._json(service.check())
            elif path == "/api/assessment/job":
                self._json({"job": service.status()})
            elif path == "/api/assessment/catalog":
                self._json(service.catalog())
            elif path == "/api/assessment/status":
                self._json(service.run_status(run_id))
            elif path == "/api/assessment/coverage":
                self._json(service.coverage(run_id))
            elif path == "/api/assessment/files":
                directory = query.get("directory", [None])[0]
                self._json(
                    service.files(
                        run_id,
                        query.get("label", [None])[0],
                        int(directory) if directory is not None else None,
                        min(500, int(query.get("limit", ["100"])[0])),
                        int(query.get("offset", ["0"])[0]),
                        query.get("missed", ["0"])[0] == "1",
                    )
                )
            else:
                self._error(404, "Unknown assessment endpoint", "not_found")
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
            if path.startswith("/api/assessment/"):
                assessment = self.server.state.jev
                if assessment is None:
                    self.close_connection = True
                    self._error(404, "Assessment is unavailable", "not_found")
                    return
                if path == "/api/assessment/jobs":
                    self._json(assessment.start(payload), 202)
                elif path == "/api/assessment/cancel":
                    assessment.cancel()
                    self._json({"cancel_requested": True})
                else:
                    self._error(404, "Unknown assessment endpoint", "not_found")
                return
            service = self.server.state.triage
            if service is None:
                self.close_connection = True
                self._error(404, "Ranking unavailable", "not_found")
                return
            if path == "/api/nemesis/send":
                state = self.server.state
                if state.nemesis is None:
                    raise ValueError(
                        "Configure Nemesis URL, authentication, and project first"
                    )
                if set(payload) - {"file_id", "resend"} or not isinstance(
                    payload.get("file_id"), str
                ):
                    raise ValueError("Provide a file_id and optional resend")
                resend = payload.get("resend", False)
                if not isinstance(resend, bool):
                    raise ValueError("resend must be a boolean")
                record = state.index.get(payload["file_id"])
                if record is None:
                    raise ValueError("Unknown file ID")
                with state.retrievals:
                    result = DeliveryStore(service.database).send(
                        record,
                        state.nemesis,
                        state.pool.retrieve if state.pool else None,
                        state.nemesis_max,
                        resend=resend,
                    )
                try:
                    state.index.record_nemesis(record, result)
                except Exception as exc:
                    logging.warning(
                        "Failed to record Nemesis status for %s: %s",
                        escape_terminal(record.unc_path),
                        escape_terminal(str(exc)),
                    )
                self._json(result)
            elif path == "/api/review/build":
                self._json(ReviewStore(service.database).build(payload.get("scan_id")))
            elif path == "/api/review/decide":
                self._json(ReviewStore(service.database).decide(**payload))
            elif path == "/api/review/undo":
                self._json(ReviewStore(service.database).undo(payload["event_id"]))
            elif path == "/api/review/hashes":
                self._json(ReviewStore(service.database).hashes())
            elif path == "/api/collection/create":
                if self.server.state.pool is None:
                    raise ValueError("Remote retrieval is disabled in offline mode")
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
            elif path in ("/api/triage/preview/save", "/api/triage/preview/discard"):
                if set(payload) != {"id"} or not isinstance(payload["id"], str):
                    raise ValueError("Provide the preview id")
                if path.endswith("/save"):
                    self._json(service.save_preview(payload["id"]), 202)
                else:
                    self._json(service.discard_preview(payload["id"]))
            else:
                self._error(404, "Unknown ranking endpoint", "not_found")
        except PreviewGoneError as exc:
            logging.warning(
                "POST %s rejected: %s",
                escape_terminal(self.path),
                escape_terminal(str(exc)),
            )
            self._error(410, str(exc), "preview_gone")
        except (TriageBusyError, CollectionBusyError, JevBusyError) as exc:
            logging.warning(
                "POST %s rejected: %s",
                escape_terminal(self.path),
                escape_terminal(str(exc)),
            )
            self._error(409, str(exc), "job_running")
        except (ValueError, OSError, sqlite3.Error, TypeError, KeyError) as exc:
            self.close_connection = True
            logging.warning(
                "POST %s rejected: %s",
                escape_terminal(self.path),
                escape_terminal(str(exc)),
            )
            self._error(400, str(exc), "invalid_request")


def run(config: WebConfig, auth: Optional[SMBAuth]) -> int:
    """Run the local WebUI with validated configuration and authentication."""
    index = DatabaseIndex(
        config.database_path, config.page_size, scoring=config.scoring
    )
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
        # [jev] enabled is an explicit opt-in: without it the WebUI exposes no
        # assessment page or API and reports assessment as disabled.
        JevService(
            config.database_path,
            runtime,
            config.jev or JevConfig.from_mapping({}),
        )
        if config.jev is not None and config.jev.enabled
        else None,
        config.nemesis,
        config.nemesis_max_bytes,
    )
    allowed_hosts = None
    if config.bind not in {"127.0.0.1", "localhost", "::1", "0.0.0.0", "::"}:
        # Serve a specific LAN address by any of its local spellings (address,
        # hostname, FQDN, aliases) rather than only the literal --bind value.
        allowed_hosts = WebHandler._local_hostnames(config.bind)
    server = WebServer((config.bind, config.port), state, allowed_hosts)
    display_host = "127.0.0.1" if config.bind in {"0.0.0.0", "::"} else config.bind
    url = f"http://{display_host}:{server.server_port}/"
    if token:
        url += f"#token={token}"
    print(
        f"Loaded {index.status()['file_count']} files from {escape_terminal(index.path)}"
    )
    missing = index.missing_sort_indexes()
    ranking_missing = index.missing_ranking_indexes()
    evidence_missing = False
    with index._connect() as connection:
        search_missing = not search_index_available(connection)
        evidence_missing = any(
            "remote_path_key"
            not in {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
            or connection.execute(
                f"SELECT 1 FROM {table} WHERE remote_path_key IS NULL LIMIT 1"
            ).fetchone()
            for table in ("snaffler_matches", "downloads")
        )
    if search_missing and not search_index_supported():
        search_missing = False
        print(
            "Substring search indexing unavailable: SQLite needs FTS5 with the trigram tokenizer. Using scan-based search."
        )
    if missing or evidence_missing or search_missing or ranking_missing:
        total_work = (
            len(missing)
            + (2 if evidence_missing else 0)
            + int(search_missing)
            + len(ranking_missing)
        )
        state.index_status.update(status="pending", completed=0, total=total_work)

        def optimize() -> None:
            started = time.monotonic()

            def progress(label: str, position: int, total: int) -> None:
                state.index_status.update(
                    status="running", current=label, completed=position - 1, total=total
                )
                print(
                    f"Optimizing inventory [{position}/{total}]: building {label} index…",
                    flush=True,
                )

            try:
                if evidence_missing:
                    index.ensure_evidence_indexes(progress)
                index.ensure_sort_indexes(progress)
                if ranking_missing:
                    progress(
                        "ranking order", total_work - int(search_missing), total_work
                    )
                    index.ensure_ranking_indexes()
                if search_missing:
                    progress(
                        "substring search (one-time backfill)", total_work, total_work
                    )
                    index.ensure_search_index()
                state.index_status.update(
                    status="completed",
                    current="",
                    completed=total_work,
                    total=total_work,
                    elapsed_seconds=round(time.monotonic() - started, 1),
                )
                print(
                    f"Inventory optimization complete in {time.monotonic() - started:.1f}s.",
                    flush=True,
                )
            except (OSError, sqlite3.Error) as exc:
                state.index_status.update(status="failed", error=str(exc))
                print(
                    f"Inventory optimization failed: {escape_terminal(exc)}", flush=True
                )

        threading.Thread(target=optimize, name="shrawler-indexer", daemon=True).start()
        print(
            f"Optimizing inventory in background: {total_work} maintenance steps pending.",
            flush=True,
        )
    print(f"WebUI listening on {escape_terminal(config.bind)}:{server.server_port}")
    print("Open WebUI: " + url)
    if config.bind in {"0.0.0.0", "::"}:
        print(
            "Remote clients should replace 127.0.0.1 with this server's IP address or hostname."
        )
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
        if state.jev:
            state.jev.close()
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
