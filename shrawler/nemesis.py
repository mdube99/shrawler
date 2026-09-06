"""Explicit Nemesis delivery, independent of browser downloads and scanning."""

import fcntl
import hashlib
import json
import os
import sqlite3
from contextlib import closing
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, cast
from urllib.parse import urlsplit

import requests


@dataclass(frozen=True)
class NemesisConfig:
    url: str
    auth: str = field(repr=False)
    project: str

    def validate(self) -> None:
        parsed = urlsplit(self.url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "Nemesis requires an HTTP(S) API URL without credentials or query"
            )
        if ":" not in self.auth or not self.project:
            raise ValueError(
                "Nemesis requires USER:PASSWORD authentication and a project"
            )


def add_arguments(parser: Any) -> None:
    for name in ("url", "auth", "project"):
        parser.add_argument("--nemesis-" + name)


def configuration(options: Any) -> Optional[NemesisConfig]:
    from .config import load_config

    section = load_config().get("nemesis", {})
    if not isinstance(section, dict):
        raise ValueError("configuration field [nemesis] must be a table")
    section = cast(Dict[str, Any], section)
    values: Dict[str, str] = {}
    for key in ("url", "auth", "project"):
        value = (
            getattr(options, "nemesis_" + key, None)
            or section.get(key)
            or os.getenv("NEMESIS_" + key.upper(), "")
        )
        if not isinstance(value, str):
            raise ValueError("Nemesis " + key + " must be a string")
        values[key] = value
    if not any(values.values()):
        return None
    config = NemesisConfig(**values)
    config.validate()
    return config


def upload(config: NemesisConfig, path: Path, record: Dict[str, Any]) -> Dict[str, Any]:
    # Keep the same multipart API contract as scan-time delivery.
    from .core import convert_unc_to_nemesis_path

    config.validate()
    username, password = config.auth.split(":", 1)
    now = datetime.now(timezone.utc)
    metadata = {
        "agent_id": "shrawler",
        "source": "host://" + record["host"],
        "project": config.project,
        "timestamp": now.isoformat(),
        "expiration": (now + timedelta(days=365)).isoformat(),
        "path": convert_unc_to_nemesis_path(record["unc_path"]),
    }
    if record.get("mtime_utc"):
        metadata["modification_time"] = record["mtime_utc"]
    with path.open("rb") as handle:
        response = requests.post(
            config.url.rstrip("/") + "/files",
            files={
                "file": (record["file_name"], handle, "application/octet-stream"),
                "metadata": (None, json.dumps(metadata), "application/json"),
            },
            auth=(username, password),
            verify=False,
            timeout=30,
            allow_redirects=False,
        )
    try:
        if response.status_code not in (200, 201):
            raise ValueError("Nemesis returned HTTP " + str(response.status_code))
        try:
            body = response.json()
        except ValueError:
            body = {}
        return {
            "response_id": cast(Dict[str, Any], body).get("id")
            if isinstance(body, dict)
            else None
        }
    finally:
        response.close()


class DeliveryStore:
    """Durable delivery receipt and retry spool; credentials are never persisted."""

    def __init__(self, database: Path):
        self.root = database.resolve().with_suffix(".nemesis")

    def list(self) -> List[Dict[str, Any]]:
        path = self.root / "deliveries.db"
        if not path.exists():
            return []
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
            return [
                json.loads(row[0])
                for row in db.execute(
                    "SELECT payload FROM deliveries ORDER BY json_extract(payload, '$.updated_at') DESC LIMIT 1000"
                )
            ]

    def send(
        self,
        record: Any,
        config: NemesisConfig,
        retrieve: Optional[Callable[[Any, Callable[[bytes], None]], None]],
        limit: int,
        retry_unknown: bool = False,
    ) -> Dict[str, Any]:
        config.validate()
        if limit < 1:
            raise ValueError("Upload size limit must be positive")
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        with (self.root / "lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError(
                    "Another Nemesis transfer is running; retry when it finishes"
                )
            with closing(sqlite3.connect(self.root / "deliveries.db")) as db:
                db.execute(
                    "CREATE TABLE IF NOT EXISTS deliveries (id TEXT PRIMARY KEY, payload TEXT NOT NULL)"
                )
                metadata = asdict(record)
                identity = [
                    record.id,
                    record.size_bytes,
                    record.mtime_utc,
                    record.metadata_scan_timestamp_utc or record.scan_timestamp_utc,
                    config.url.rstrip("/"),
                    config.project,
                ]
                key = hashlib.sha256(json.dumps(identity).encode()).hexdigest()
                row = db.execute(
                    "SELECT payload FROM deliveries WHERE id=?", (key,)
                ).fetchone()
                state: Dict[str, Any] = (
                    json.loads(row[0])
                    if row
                    else {
                        "id": key,
                        "file": metadata,
                        "destination": config.url,
                        "project": config.project,
                        "status": "pending",
                        "attempts": 0,
                    }
                )
                path = self.root / (key + ".bin")

                def save() -> None:
                    state["updated_at"] = datetime.now(timezone.utc).isoformat()
                    db.execute(
                        "INSERT OR REPLACE INTO deliveries VALUES (?, ?)",
                        (key, json.dumps(state)),
                    )
                    db.commit()

                if state["status"] == "uploaded":
                    path.unlink(missing_ok=True)
                    return state
                if state["status"] in {"uploading", "unknown"} and not retry_unknown:
                    # A lost acknowledgment is ambiguous; do not silently duplicate delivery.
                    raise ValueError(
                        "Previous upload has an unknown outcome; check Nemesis, then use CLI --retry-unknown if another submission is needed"
                    )
                if not state.get("sha256"):
                    if retrieve is None:
                        raise ValueError(
                            "This file requires SMB retrieval; start with credentials"
                        )
                    if record.size_bytes > limit:
                        raise ValueError("File exceeds Nemesis upload size limit")
                    path.unlink(missing_ok=True)
                    state.update(status="retrieving", bytes_read=0)
                    save()
                    digest = hashlib.sha256()
                    try:
                        with path.open("xb") as handle:
                            os.chmod(path, 0o600)

                            def sink(chunk: bytes) -> None:
                                state["bytes_read"] += len(chunk)
                                if state["bytes_read"] > limit:
                                    raise ValueError(
                                        "File exceeds Nemesis upload size limit"
                                    )
                                handle.write(chunk)
                                digest.update(chunk)

                            retrieve(record, sink)
                            handle.flush()
                            os.fsync(handle.fileno())
                        if state["bytes_read"] != record.size_bytes:
                            raise ValueError(
                                "Remote file size changed; refresh the inventory before sending"
                            )
                        state.update(status="staged", sha256=digest.hexdigest())
                        save()
                    except BaseException as exc:
                        path.unlink(missing_ok=True)
                        state.update(status="retrieval_failed")
                        save()
                        if isinstance(exc, Exception) and not isinstance(
                            exc, ValueError
                        ):
                            raise ValueError(
                                "SMB retrieval failed; no file was uploaded"
                            ) from exc
                        raise
                if not path.is_file():
                    raise ValueError(
                        "Staged evidence is missing; refusing to silently reread SMB"
                    )
                if path.stat().st_size > limit:
                    raise ValueError(
                        "Staged evidence exceeds Nemesis upload size limit"
                    )
                digest = hashlib.sha256()
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
                if digest.hexdigest() != state["sha256"]:
                    raise ValueError("Staged evidence hash changed; refusing upload")
                state.update(
                    status="uploading", attempts=state["attempts"] + 1, error=None
                )
                save()
                try:
                    state.update(upload(config, path, state["file"]))
                except requests.RequestException:
                    state.update(
                        status="unknown",
                        error="Upload connection failed; acknowledgment unknown",
                    )
                except Exception as exc:
                    state.update(status="upload_failed", error=str(exc))
                else:
                    state.update(status="uploaded")
                save()
                if state["status"] == "uploaded":
                    path.unlink(missing_ok=True)
                return state


def main(argv: Any = None) -> int:
    import argparse

    from .arguments import parse_size
    from .cli import add_smb_auth_arguments
    from .collection import smb_retriever
    from .output import escape_terminal
    from .smb import create_smb_auth
    from .web import DatabaseIndex

    parser = argparse.ArgumentParser(prog="shrawler nemesis")
    commands = parser.add_subparsers(dest="action", required=True)
    listing = commands.add_parser(
        "list", help="show up to 1000 recent delivery receipts"
    )
    listing.add_argument("database", type=Path)
    send = commands.add_parser(
        "send",
        help="retrieve an indexed file and submit it, or retry locally staged bytes",
    )
    send.add_argument("database", type=Path)
    send.add_argument("file_id")
    send.add_argument("auth", nargs="?")
    send.add_argument("--max-file-size", type=parse_size, default=50 * 1024**2)
    send.add_argument(
        "--retry-unknown",
        action="store_true",
        help="resubmit after checking an ambiguous upload outcome; may duplicate delivery",
    )
    add_smb_auth_arguments(send)
    add_arguments(send)
    args = parser.parse_args(argv)
    try:
        if args.action == "list":
            print(
                json.dumps(
                    DeliveryStore(args.database).list(), indent=2, ensure_ascii=True
                )
            )
            return 0
        config = configuration(args)
        if config is None:
            raise ValueError("Configure Nemesis URL, authentication, and project first")
        record = DatabaseIndex(args.database).get(args.file_id)
        if record is None:
            raise ValueError("Unknown file ID")
        retrieve = None
        if args.auth:
            retrieve = smb_retriever(
                create_smb_auth(
                    args.auth,
                    args.hashes,
                    bool(args.no_pass),
                    bool(args.k),
                    args.aesKey,
                )
            )
        result = DeliveryStore(args.database).send(
            record, config, retrieve, args.max_file_size, args.retry_unknown
        )
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return 0 if result["status"] == "uploaded" else 1
    except (ValueError, OSError, sqlite3.Error) as exc:
        parser.exit(1, "Nemesis error: " + escape_terminal(str(exc)) + "\n")
    except KeyboardInterrupt:
        return 130
