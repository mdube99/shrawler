"""Local-only, dependency-free WebUI for saved Shrawler inventories."""

import json
import logging
import os
import re
import secrets
import shutil
import tempfile
import threading
import urllib.parse
import webbrowser
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .smb import SMBAuth, close_smb, connect_smb

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


@dataclass(frozen=True)
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

    def public(self) -> Dict[str, Any]:
        value = asdict(self)
        value.pop("search_text")
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

    def facets(self) -> Dict[str, List[str]]:
        return {
            "hosts": sorted({r.host for r in self.records}, key=str.casefold),
            "shares": sorted({r.share for r in self.records}, key=str.casefold),
            "extensions": sorted({r.extension for r in self.records}),
        }

    def search(
        self, q: str, host: str, share: str, extension: str, page: int, per_page: int
    ) -> Dict[str, Any]:
        terms = q.casefold().split()
        matches = [
            r
            for r in self.records
            if (not host or r.host == host)
            and (not share or r.share == share)
            and (not extension or r.extension == extension)
            and all(term in r.search_text for term in terms)
        ]
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
    index: FileIndex
    pool: SessionPool
    token: str
    preview_max: int
    download_max: int
    runtime_dir: Path
    retrievals: threading.BoundedSemaphore


@dataclass(frozen=True)
class WebConfig:
    results_path: Path
    port: int
    open_browser: bool
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
        logging.debug(fmt, *args)

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
        if parsed.path == "/api/status":
            self._json(
                {
                    "results_name": state.index.path.name,
                    "schema_version": 3,
                    "file_count": len(state.index.records),
                    "host_count": len(state.index.facets()["hosts"]),
                    "preview_max_bytes": state.preview_max,
                    "download_max_bytes": state.download_max,
                }
            )
            return
        if parsed.path == "/api/facets":
            self._json(state.index.facets())
            return
        if parsed.path == "/api/files":
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if any(len(value[0]) > 512 for value in query.values() if value):
                self._error(400, "Query value is too long", "invalid_query")
                return
            try:
                self._json(
                    state.index.search(
                        *(
                            query.get(k, [""])[0]
                            for k in ("q", "host", "share", "extension")
                        ),
                        int(query.get("page", ["1"])[0]),
                        int(query.get("per_page", [str(state.index.page_size)])[0]),
                    )
                )
            except ValueError:
                self._error(400, "Invalid pagination", "invalid_query")
            return
        match = re.fullmatch(
            r"/api/files/([A-Za-z0-9_-]{16,32})(?:/(preview|download))?", parsed.path
        )
        if not match:
            self._error(400, "Invalid file ID", "invalid_id")
            return
        record = state.index.by_id.get(match.group(1))
        if record is None:
            self._error(404, "Unknown file", "not_found")
            return
        action = match.group(2)
        if action is None:
            self._json(record.public())
        elif action == "preview":
            self._preview(record)
        else:
            self._download(record)

    def _retrieve(self, record: FileRecord, path: Path, limit: int) -> int:
        with self.server.state.retrievals:
            with path.open("xb") as handle:
                os.chmod(path, 0o600)
                sink = LimitedSink(handle.write, limit)
                self.server.state.pool.retrieve(record, sink)
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
            logging.error("Preview retrieval failed for %s: %s", record.unc_path, exc)
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
            logging.error("Download retrieval failed for %s: %s", record.unc_path, exc)
            self._error(502, "SMB retrieval failed", "smb_failure")
        finally:
            try:
                path.unlink()
            except FileNotFoundError:
                pass

    def do_POST(self) -> None:
        if self.path != "/api/shutdown":
            self._error(404, "Not found", "not_found")
            return
        if not self._guard():
            return
        expected = f"http://127.0.0.1:{self.server.server_port}"
        origin = self.headers.get("Origin")
        if origin not in {expected, f"http://localhost:{self.server.server_port}"}:
            self._error(403, "Invalid Origin", "invalid_origin")
            return
        self._json({"status": "shutting_down"})
        threading.Thread(target=self.server.shutdown, daemon=True).start()

    def do_HEAD(self) -> None:
        self._error(405, "Method not allowed", "method_not_allowed")

    do_PUT = do_DELETE = do_PATCH = do_HEAD


def run(config: WebConfig, auth: SMBAuth) -> int:
    """Run the local WebUI with validated configuration and authentication."""
    index = FileIndex.load(config.results_path, config.page_size)
    runtime = Path(tempfile.mkdtemp(prefix="shrawler-web-"))
    os.chmod(runtime, 0o700)
    token = secrets.token_hex(32)
    state = WebState(
        index,
        SessionPool(auth),
        token,
        config.preview_max_bytes,
        config.download_max_bytes,
        runtime,
        threading.BoundedSemaphore(2),
    )
    server = WebServer(("127.0.0.1", config.port), state)
    url = f"http://127.0.0.1:{server.server_port}/#token={token}"
    print(
        f"Loaded {len(index.records)} files ({index.skipped} skipped) from {index.path}"
    )
    print("Local WebUI: " + url)
    print("Files are fetched live from SMB and may differ from crawl metadata.")
    if config.open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        state.pool.close()
        shutil.rmtree(runtime, ignore_errors=True)
    return 0


__all__ = [
    "DownloadTooLarge",
    "FileIndex",
    "FileRecord",
    "LimitedSink",
    "WebConfig",
    "classify_preview",
    "content_disposition",
    "run",
]
