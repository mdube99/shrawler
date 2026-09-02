#!/usr/bin/env python3

import copy
import hashlib
import json
import logging
import os
import socket
import threading
import time
import uuid
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import requests
import urllib3
from colorama import Fore, Style, init
from dotenv import load_dotenv
from impacket.examples.utils import parse_target
from impacket.smbconnection import (
    SMB2_DIALECT_002,
    SMB2_DIALECT_21,
    SMB_DIALECT,
    SessionError,
    SMBConnection,
)

from .progress import ProgressReporter
from .snaffler import SnafflerEngineMixin, SnafflerRule
from .state import ScanStateStore

# Load .env file if it exists
load_dotenv()

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for Linux filesystem compatibility.

    Args:
        filename: The filename to sanitize

    Returns:
        Sanitized filename with illegal characters replaced
    """
    # Characters that are problematic in Linux filenames
    illegal_chars = ["\\", ":", "*", "?", '"', "<", ">", "|", "\0"]

    sanitized = filename
    for char in illegal_chars:
        sanitized = sanitized.replace(char, "_")

    # Replace multiple consecutive underscores with single underscore
    while "__" in sanitized:
        sanitized = sanitized.replace("__", "_")

    # Remove leading/trailing underscores
    sanitized = sanitized.strip("_")

    # Ensure we don't have an empty filename
    if not sanitized:
        sanitized = "unnamed_file"

    return sanitized


def convert_unc_to_nemesis_path(unc_path: str) -> str:
    """
    Convert UNC path to Nemesis-compatible format.

    Nemesis expects paths in the format: /D:/Office/here/file.txt
    UNC paths come in as: \\\\host\\C$\\path\\to\\file.txt

    This function:
    1. Removes the host prefix (already captured in 'source' field)
    2. Converts admin shares (C$, D$) to drive notation (C:, D:)
    3. Uses forward slashes throughout
    4. Preserves named shares as-is

    Examples:
        \\\\192.168.1.100\\C$\\Users\\file.txt -> /C:/Users/file.txt
        \\\\host\\D$\\Documents\\report.pdf -> /D:/Documents/report.pdf
        \\\\host\\share\\path\\file.txt -> /share/path/file.txt

    Args:
        unc_path: Windows UNC path with backslashes

    Returns:
        Nemesis-compatible path with forward slashes and proper drive notation
    """
    import re

    # Remove leading backslashes and split into components
    parts = unc_path.lstrip("\\").split("\\")

    if len(parts) < 2:
        # Not a valid UNC path, just convert slashes
        return unc_path.replace("\\", "/")

    share = parts[1]  # e.g., "C$" or "share_name"
    path_parts = parts[2:]  # e.g., ["Users", "Admin", "Documents", "file.txt"]

    # Convert admin share notation (C$, D$, etc.) to drive letter (C:, D:, etc.)
    if re.match(r"^[A-Za-z]\$$", share):
        # This is an admin share like C$ or D$
        drive_letter = share[0].upper() + ":"
        share = drive_letter

    # Build Nemesis path: /drive:/path/to/file or /share/path/to/file
    if path_parts:
        nemesis_path = "/" + share + "/" + "/".join(path_parts)
    else:
        # Root of share/drive
        nemesis_path = "/" + share + "/"

    return nemesis_path


# custom log colors
class Formatter(logging.Formatter):
    """Custom Formatter."""

    def format(self, record: logging.LogRecord) -> str:
        init()
        if record.levelno == logging.INFO:
            self._style._fmt = f"{Fore.GREEN}[+]{Style.RESET_ALL} %(message)s"
        elif record.levelno == logging.DEBUG:
            self._style._fmt = f"{Fore.YELLOW}[+]{Style.RESET_ALL} %(message)s"
        else:
            self._style._fmt = f"{Fore.RED}[-]{Style.RESET_ALL} %(message)s"
        return super().format(record)


def error(msg: str) -> str:
    """Custom error message."""
    max_length: int = 70
    padding: int = max(0, (max_length - len(msg)) // 2)
    this: str = "-" * padding + msg + "-" * (max_length - len(msg) - padding)
    return Fore.RED + this + Style.RESET_ALL + "\n"


def success(msg: str) -> str:
    """Custom success message."""
    max_length: int = 70
    padding: int = max(0, (max_length - len(msg)) // 2)
    this: str = "-" * padding + msg + "-" * (max_length - len(msg) - padding)
    return Fore.GREEN + this + Style.RESET_ALL + "\n"


def print_share_info(
    share_name: str,
    share_comment: str,
    share_perms: Dict[str, Union[str, bool]],
    largest_share_name: int,
    snaffler_marker: str = "",
) -> None:
    """Custom print message."""
    if share_perms["read"] and share_perms["write"]:
        prefix = Fore.GREEN + "[+]" + Style.RESET_ALL
    elif share_perms["read"] and not share_perms["write"]:
        prefix = Fore.YELLOW + "[+]" + Style.RESET_ALL
    else:
        prefix = Fore.RED + "[-]" + Style.RESET_ALL

    if share_perms["read"]:
        read = "Yes"
    else:
        read = "No"

    if share_perms["write"] == "N/A":
        write = "N/A"
    elif share_perms["write"]:
        write = "Yes"
    else:
        write = "No"

    # fmt: off
    print(f"     {prefix} {share_name.ljust(largest_share_name + 20)} | Read: {read.ljust(3)} | Write: {write.ljust(3)} | Comment: {share_comment if share_comment else 'N/A'}{snaffler_marker}")


def find_unique_files_by_mtime(
    file_list: List[Tuple[str, float]],
) -> List[Tuple[float, str]]:
    """
    Find files with unique modification times.

    Args:
        file_list: List of (file_path, mtime) tuples

    Returns:
        List of (mtime, file_path) tuples for files with unique modification times
    """
    mtime_groups: defaultdict[float, List[str]] = defaultdict(list)

    for file_path, mtime in file_list:
        mtime_groups[mtime].append(file_path)

    unique_files_data: List[Tuple[float, str]] = []
    for mtime, paths in mtime_groups.items():
        if len(paths) == 1:
            unique_files_data.append((mtime, paths[0]))

    return unique_files_data


def find_unique_files_in_directory(
    files_with_mtime: List[Tuple[Any, float]],
) -> Set[int]:
    """
    Find files with unique modification times within a directory.

    Args:
        files_with_mtime: List of (file_result_object, mtime_epoch) tuples

    Returns:
        Set of indices of files that are unique within the directory
    """
    if len(files_with_mtime) <= 1:
        return set()  # No files are unique if there's only 0 or 1 file

    mtime_counts: defaultdict[int, int] = defaultdict(int)

    # Round epoch timestamps to minutes before comparing (to match display precision)
    for _, mtime in files_with_mtime:
        rounded_mtime = (
            int(mtime // 60) * 60
        )  # Round to minute precision to match display
        mtime_counts[rounded_mtime] += 1

    # Find indices of files with unique rounded mtimes
    unique_indices: Set[int] = set()
    for i, (_, mtime) in enumerate(files_with_mtime):
        rounded_mtime = int(mtime // 60) * 60
        if mtime_counts[rounded_mtime] == 1:
            unique_indices.add(i)

    return unique_indices


def display_unique_files(unique_files_data: List[Tuple[float, str]]) -> None:
    """
    Display files with unique modification times in spider-like format.

    Args:
        unique_files_data: List of (mtime, file_path) tuples
    """
    print(f"\n{Fore.GREEN}[+] Files with Unique Modification Times{Style.RESET_ALL}\n")

    if not unique_files_data:
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} No unique files found.")
        return

    for mtime, file_path in unique_files_data:
        readable_time = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {readable_time} | {file_path}")


class Shrawler(SnafflerEngineMixin):
    """SMB Share Crawling Tool."""

    def __init__(self, options: Any) -> None:
        init()  # for Colorama
        self.args = options
        self.download_count = 0
        self.downloaded_bytes = 0
        self._reserved_download_bytes = 0
        self.files_seen_count = 0
        self.host_outcomes: Dict[str, Dict[str, Any]] = {}

        # Initialize file counting data structures
        self.file_counts: Dict[str, int] = {}
        self.count_extensions_list: List[str] = []
        self.count_strings_list: List[str] = []

        # Initialize unique file timestamp data collection
        self.unique_files_data: List[Tuple[str, float]] = []

        # Initialize scan results for consolidated JSON output
        self.scan_results: Dict[str, Any] = {}

        self._thread_context = threading.local()
        self._state_lock = threading.RLock()
        self.operation_counts: Counter[str] = Counter()
        self.operation_seconds: defaultdict[str, float] = defaultdict(float)
        self.operation_bytes: Counter[str] = Counter()
        self.content_reads = 0
        self.content_read_bytes = 0
        self._prefetched_content: Dict[str, bytes] = {}
        self._nemesis_executor: Optional[ThreadPoolExecutor] = None
        self._nemesis_futures: List[Any] = []
        self._nemesis_slots = threading.BoundedSemaphore(self.args.nemesis_queue_size)

        # CSV output data structures
        self.share_rows: List[Dict[str, Any]] = []
        self.file_rows: List[Dict[str, Any]] = []
        self.download_rows: List[Dict[str, Any]] = []
        self.csv_enabled = False
        self.json_enabled = False

        # Snaffler runtime state
        self.snaffler_enabled = False
        self.snaffler_rules: List[SnafflerRule] = []
        self.snaffler_rules_by_scope: Dict[str, List[SnafflerRule]] = defaultdict(list)
        self.snaffler_rule_lookup: Dict[str, SnafflerRule] = {}
        self.snaffler_matches: List[Dict[str, Any]] = []
        self.snaffler_match_counter: Counter[str] = Counter()
        self.snaffler_matched_file_keys: Set[str] = set()

        self.verbose = self.args.verbose

        self.normal_shares = [
            "ADMIN$",
            "C$",
            "IPC$",
            "NETLOGON",
            "PRINT$",
            "print$",
            "SYSVOL",
        ]

        # extensions that it will look for
        self.extensions = [
            ".txt",
            ".csv",
            ".xlsx",
            ".pdf",
            ".kbdx",
            ".kbd",
            ".docx",
            ".doc",
            ".xls",
            ".ps1",
            ".bat",
            ".vbs",
            ".tar",
            ".zip",
            ".sh",
            ".json",
            ".ini",
            ".conf",
            ".cnf",
            ".config",
            ".properties",
            ".prop",
            ".yaml",
            ".yml",
            ".pem",
            ".key",
            ".sql",
            ".db",
        ]

        # Set CSV output flag
        self.csv_enabled = self.args.csv_output
        self.json_enabled = self.args.json_output

        # Track downloads by UNC path to avoid duplicate downloads
        self.downloaded_unc_paths: Set[str] = set()

        self.output_dir = Path(self.args.output_dir).expanduser()
        resume_path = getattr(self.args, "resume", None)
        state_root = Path(resume_path).expanduser() if resume_path else self.output_dir
        persist_state = self.args.operating_mode != "legacy" or bool(resume_path)
        self.state_store = ScanStateStore(state_root, enabled=persist_state)
        self._resume_paths: Set[str] = set()
        if resume_path:
            saved = self.state_store.load()
            saved_results = saved.get("results", {})
            if isinstance(saved_results, dict):
                self.scan_results = saved_results
                self._resume_paths = {
                    str(item.get("unc_path"))
                    for key, host in saved_results.items()
                    if not key.startswith("_") and isinstance(host, dict)
                    for share in host.get("shares", {}).values()
                    for item in share.get("discovered_files", [])
                    if item.get("unc_path")
                }
            saved_summary = saved.get("summary", {})
            if isinstance(saved_summary, dict):
                self.files_seen_count = int(saved_summary.get("files_seen", 0))
                self.download_count = int(saved_summary.get("files_downloaded", 0))
                self.downloaded_bytes = int(saved_summary.get("downloaded_bytes", 0))

        # Process counting arguments (requires self.extensions)
        self._process_count_arguments()

        # Optional Snaffler rule loading
        self._initialize_snaffler_rules()

    @property
    def current_host(self) -> Optional[str]:
        """Return the host associated with the current worker thread."""
        return getattr(self._thread_context, "current_host", None)

    @current_host.setter
    def current_host(self, value: Optional[str]) -> None:
        self._thread_context.current_host = value

    def _record_operation(
        self, name: str, elapsed: float, byte_count: int = 0
    ) -> None:
        """Record an operation without exposing mutable counters to workers."""
        with self._state_lock:
            self.operation_counts[name] += 1
            self.operation_seconds[name] += elapsed
            if byte_count:
                self.operation_bytes[name] += byte_count

    def _display_operation_metrics(self) -> None:
        """Display operation counts, elapsed time, and transferred bytes."""
        if not self.operation_counts:
            return
        logging.info("Operation metrics:")
        for name in sorted(self.operation_counts):
            count = self.operation_counts[name]
            elapsed = self.operation_seconds[name]
            byte_count = self.operation_bytes[name]
            suffix = f", {byte_count} bytes" if byte_count else ""
            logging.info(f"  {name}: {count} calls, {elapsed:.2f}s{suffix}")

    def _process_count_arguments(self) -> None:
        """Process --count-ext and --count-string arguments."""
        # Process --count-ext argument
        if self.args.count_ext is not None:
            if self.args.count_ext == "default":
                # Use default extensions for counting
                self.count_extensions_list = [ext.lower() for ext in self.extensions]
            else:
                # Process user-provided extensions
                extensions = [ext.strip() for ext in self.args.count_ext.split(",")]
                for ext in extensions:
                    ext = ext.strip().lower()
                    if not ext.startswith("."):
                        ext = "." + ext
                    self.count_extensions_list.append(ext)

        # Process --count-string argument
        if self.args.count_string is not None:
            string = [string.strip() for string in self.args.count_string.split(",")]
            self.count_strings_list = [string.strip().lower() for string in string]

    def _should_download_by_cli(self, filename_lower: str) -> bool:
        """Evaluate existing extension/name download flags."""
        download_by_extension = False
        download_by_name = False

        if self.args.download_ext is not None:
            if self.args.download_ext.strip() == "":
                download_by_extension = True
            elif self.args.download_ext == "default":
                for ext in self.extensions:
                    ext_lower = ext.lower()
                    if not ext_lower.startswith("."):
                        ext_lower = "." + ext_lower
                    if filename_lower.endswith(ext_lower):
                        download_by_extension = True
                        break
            else:
                extensions = [ext.strip() for ext in self.args.download_ext.split(",")]
                for ext in extensions:
                    ext = ext.strip().lower()
                    if not ext.startswith("."):
                        ext = "." + ext
                    if filename_lower.endswith(ext):
                        download_by_extension = True
                        break

        if self.args.download_name is not None:
            search_terms = [
                term.strip().lower() for term in self.args.download_name.split(",")
            ]
            for term in search_terms:
                if term in filename_lower:
                    download_by_name = True
                    break

        return download_by_extension or download_by_name

    def _should_upload_to_nemesis(self, snaffler_match: bool) -> bool:
        """Apply the configured Nemesis delivery policy to a local download."""
        return self.args.nemesis_mode == "downloads" or (
            self.args.nemesis_mode == "matches" and snaffler_match
        )

    def _download_file_with_dedupe(
        self,
        smbclient: Any,
        share: str,
        remote_file_path: str,
        file_size: int,
        mtime_epoch: float,
        nemesis_upload: bool = False,
    ) -> str:
        """Download a file once per UNC path and return display marker."""
        host_for_ops = self.current_host or "unknown-host"
        unc_key = f"\\\\{host_for_ops}\\{share}\\{remote_file_path.lstrip('/')}"
        with self._state_lock:
            if unc_key in self.downloaded_unc_paths:
                self._prefetched_content.pop(unc_key, None)
                return f" {Fore.YELLOW}[DOWNLOAD SKIPPED DUPLICATE]{Style.RESET_ALL}"
            if (
                self.args.max_file_size is not None
                and file_size > self.args.max_file_size
            ):
                self._prefetched_content.pop(unc_key, None)
                return f" {Fore.YELLOW}[DOWNLOAD SKIPPED: FILE SIZE LIMIT]{Style.RESET_ALL}"
            if (
                self.args.max_total_download is not None
                and self.downloaded_bytes
                + self._reserved_download_bytes
                + file_size
                > self.args.max_total_download
            ):
                self._prefetched_content.pop(unc_key, None)
                return f" {Fore.YELLOW}[DOWNLOAD SKIPPED: TOTAL SIZE LIMIT]{Style.RESET_ALL}"
            self._reserved_download_bytes += file_size

        sanitized_path = sanitize_filename(
            remote_file_path.replace("/", "_").lstrip("_")
        )
        path_digest = hashlib.sha256(unc_key.encode("utf-8")).hexdigest()[:10]
        local_filename = f"{host_for_ops}__{share}__{sanitized_path}__{path_digest}"

        download_success, nemesis_queued = self.download_file(
            smbclient,
            share,
            remote_file_path,
            local_filename,
            host_for_ops,
            file_size,
            mtime_epoch,
            nemesis_upload,
        )

        with self._state_lock:
            self._reserved_download_bytes -= file_size

        if download_success:
            with self._state_lock:
                self.downloaded_unc_paths.add(unc_key)
            download_status = f" {Fore.CYAN}[DOWNLOADED]{Style.RESET_ALL}"
            if nemesis_queued:
                download_status += f" {Fore.MAGENTA}[NEMESIS QUEUED]{Style.RESET_ALL}"
            return download_status

        return f" {Fore.RED}[DOWNLOAD FAILED]{Style.RESET_ALL}"

    def _count_file(self, filename: str) -> None:
        """Count a file based on extension and string criteria."""
        filename_lower = filename.lower()

        with self._state_lock:
            for ext in self.count_extensions_list:
                if filename_lower.endswith(ext):
                    self.file_counts[ext] = self.file_counts.get(ext, 0) + 1

            for string in self.count_strings_list:
                if string in filename_lower:
                    self.file_counts[string] = self.file_counts.get(string, 0) + 1

    def _display_file_count_summary(self) -> None:
        """Display the final file count summary."""
        if not self.file_counts:
            return

        init()  # Initialize colorama
        print(f"\n{Fore.GREEN}[+] File Count Summary{Style.RESET_ALL}\n")

        # Sort by count (descending) for better readability
        sorted_counts = sorted(
            self.file_counts.items(), key=lambda x: x[1], reverse=True
        )

        # Calculate total count
        total_count = sum(count for _, count in sorted_counts)

        # Calculate column widths
        max_type_width = max(
            len("File Type"),
            max(len(str(item)) for item, _ in sorted_counts),
            len("TOTAL"),
        )
        count_width = max(len("Count"), len(str(total_count)))

        border_line = (
            "+" + "=" * (max_type_width + 2) + "+" + "=" * (count_width + 2) + "+"
        )

        # Print table
        print(border_line)
        print(f"| {'File Type'.ljust(max_type_width)} | {'Count'.rjust(count_width)} |")
        print(border_line)

        for item, count in sorted_counts:
            print(
                f"| {str(item).ljust(max_type_width)} | {str(count).rjust(count_width)} |"
            )

        print(border_line)
        print(
            f"| {'TOTAL'.ljust(max_type_width)} | {str(total_count).rjust(count_width)} |\n"
        )

    def banner(self) -> str:
        ascii = r"""
  _____ _                      _            
 / ____| |                    | |           
| (___ | |__  _ __ __ ___   __| | ___ _ __  
 \___ \| '_ \| '__/ _` \ \ /\ / / |/ _ \ '__|
 ____) | | | | | | (_| |\ V  V /| |  __/ |   
|_____/|_| |_|_|  \__,_| \_/\_/ |_|\___|_|   
        """
        return Fore.GREEN + ascii + Style.RESET_ALL + "\n"

    def check_port(self, machine: str, port: int) -> bool:
        """Check if port is open."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)

            try:
                return s.connect_ex((machine, port)) == 0
            except (socket.timeout, OSError) as e:
                logging.debug(f"Port check failed for {machine}:{port} - {e}")
                return False

    def download_file(
        self,
        smbclient: Any,
        share: str,
        remote_path: str,
        local_filename: str,
        host: str,
        file_size: int = 0,
        mtime_epoch: float = 0,
        nemesis_upload: bool = False,
    ) -> Tuple[bool, bool]:
        """
        Downloads a file from the SMB share and saves it locally.

        Args:
            smbclient: The SMB client instance
            share: SMB share name
            remote_path: Full path to the remote file
            local_filename: Local filename to save as
            host: Target host IP
            file_size: File size in bytes
            mtime_epoch: File modification time as epoch

        Returns:
            tuple[bool, bool]: (download_success, nemesis_upload_queued)
        """
        try:
            loot_dir = self.output_dir / "downloads"
            loot_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(loot_dir, 0o700)
            local_path = loot_dir / local_filename
            partial_path = loot_dir / f".{local_filename}.{uuid.uuid4().hex}.part"
            unc_path_key = f"\\\\{host}\\{share}\\{remote_path.lstrip('/')}"
            with self._state_lock:
                prefetched_content = self._prefetched_content.pop(unc_path_key, None)

            try:
                with partial_path.open("xb") as local_file:
                    os.chmod(partial_path, 0o600)
                    started = time.perf_counter()
                    if prefetched_content is not None:
                        local_file.write(prefetched_content)
                        operation_name = "download_reused_content"
                    else:
                        smbclient.getFile(share, remote_path, local_file.write)
                        operation_name = "download"
                    local_file.flush()
                    os.fsync(local_file.fileno())
                    self._record_operation(
                        operation_name,
                        time.perf_counter() - started,
                        local_file.tell() if operation_name == "download" else 0,
                    )
                actual_size = partial_path.stat().st_size
                if file_size and actual_size != file_size:
                    raise OSError(
                        f"download size mismatch: expected {file_size}, got {actual_size}"
                    )
                # Publish without overwriting evidence from an earlier run.
                while True:
                    try:
                        os.link(partial_path, local_path)
                        partial_path.unlink()
                        break
                    except FileExistsError:
                        local_path = loot_dir / (
                            f"{Path(local_filename).stem}__{uuid.uuid4().hex[:8]}"
                            f"{Path(local_filename).suffix}"
                        )
            finally:
                try:
                    partial_path.unlink()
                except FileNotFoundError:
                    pass

            sha256 = hashlib.sha256()
            with local_path.open("rb") as downloaded_file:
                for chunk in iter(lambda: downloaded_file.read(1024 * 1024), b""):
                    sha256.update(chunk)

            # Populate manifest data on successful download
            file_entry: Dict[str, Any] = {
                "timestamp": datetime.now().isoformat(),
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "host": host,
                "share": share,
                "remote_path": remote_path,
                "unc_path": f"\\\\{host}\\{share}\\{remote_path.lstrip('/')}",
                "local_filename": local_path.name,
                "local_path": str(local_path),
                "size_bytes": file_size,
                "actual_size_bytes": actual_size,
                "sha256": sha256.hexdigest(),
                "mtime_epoch": mtime_epoch,
                "mtime_utc": datetime.fromtimestamp(
                    mtime_epoch, timezone.utc
                ).isoformat(),
                "origin_tool": "shrawler",
                "nemesis": {
                    "status": "queued" if nemesis_upload else "not_requested",
                    "attempts": 0,
                    "response_id": None,
                    "last_error": None,
                },
            }

            # Collect data for CSV output
            csv_entry: Optional[Dict[str, Any]] = None
            if self.args.csv_output:
                clean_remote_path = remote_path.lstrip("/").replace("/", "\\")
                unc_path = f"\\\\{host}\\{share}\\{clean_remote_path}"

                csv_entry = {
                    "host": host,
                    "share_name": share,
                    "remote_path": remote_path,
                    "unc_path": unc_path,
                    "local_filename": local_path.name,
                    "local_path": str(local_path),
                    "size_bytes": file_size,
                    "actual_size_bytes": actual_size,
                    "sha256": file_entry["sha256"],
                    "mtime_utc": file_entry["mtime_utc"],
                    "timestamp_utc": file_entry["timestamp_utc"],
                    "nemesis_status": file_entry["nemesis"]["status"],
                    "nemesis_attempts": 0,
                    "nemesis_response_id": None,
                    "nemesis_last_error": None,
                }
                self.download_rows.append(csv_entry)

            # Add to scan results (within the appropriate share's downloaded_files list)
            with self._state_lock:
                self.scan_results[host]["shares"][share]["downloaded_files"].append(
                    file_entry
                )
                self.download_count += 1
                self.downloaded_bytes += actual_size

            if nemesis_upload:
                self._queue_nemesis_upload(file_entry, csv_entry)

            return (True, nemesis_upload)

        except Exception as e:
            logging.warning(f"Failed to download {remote_path}: {e!s}")
            return (False, False)

    def _queue_nemesis_upload(
        self,
        file_entry: Dict[str, Any],
        csv_entry: Optional[Dict[str, Any]],
    ) -> None:
        """Queue a local evidence file for background Nemesis delivery."""
        self._nemesis_slots.acquire()
        with self._state_lock:
            if self._nemesis_executor is None:
                self._nemesis_executor = ThreadPoolExecutor(
                    max_workers=self.args.nemesis_upload_workers,
                    thread_name_prefix="shrawler-nemesis",
                )
            future = self._nemesis_executor.submit(
                self._upload_to_nemesis_with_retries,
                file_entry,
                csv_entry,
            )
            future.add_done_callback(lambda _future: self._nemesis_slots.release())
            self._nemesis_futures.append(future)

    def _upload_to_nemesis_with_retries(
        self,
        file_entry: Dict[str, Any],
        csv_entry: Optional[Dict[str, Any]],
    ) -> None:
        """Upload one file with bounded exponential-backoff retries."""
        state = file_entry["nemesis"]
        clean_remote_path = str(file_entry["remote_path"]).lstrip("/").replace(
            "/", "\\"
        )
        unc_path = (
            f"\\\\{file_entry['host']}\\{file_entry['share']}\\{clean_remote_path}"
        )
        max_attempts = self.args.nemesis_retries + 1

        for attempt in range(1, max_attempts + 1):
            with self._state_lock:
                state["status"] = "uploading"
                state["attempts"] = attempt
                if csv_entry is not None:
                    csv_entry["nemesis_status"] = "uploading"
                    csv_entry["nemesis_attempts"] = attempt

            result = self.submit_to_nemesis(
                str(file_entry["local_path"]),
                unc_path,
                float(file_entry["mtime_epoch"]),
                str(file_entry["host"]),
            )
            if result["success"]:
                with self._state_lock:
                    state["status"] = "uploaded"
                    state["response_id"] = result["response_id"]
                    state["last_error"] = None
                    if csv_entry is not None:
                        csv_entry["nemesis_status"] = "uploaded"
                        csv_entry["nemesis_response_id"] = result["response_id"]
                        csv_entry["nemesis_last_error"] = None
                return

            last_error = result.get("last_error") or "Nemesis upload failed"
            with self._state_lock:
                state["last_error"] = last_error
                if csv_entry is not None:
                    csv_entry["nemesis_last_error"] = last_error
            if attempt < max_attempts:
                time.sleep(2 ** (attempt - 1))

        with self._state_lock:
            state["status"] = "failed"
            if csv_entry is not None:
                csv_entry["nemesis_status"] = "failed"
        logging.warning(
            f"Nemesis upload failed after {max_attempts} attempts: "
            f"{file_entry['unc_path']}"
        )

    def _finish_nemesis_uploads(self) -> None:
        """Wait for queued uploads so final reports contain terminal statuses."""
        with self._state_lock:
            futures = list(self._nemesis_futures)
            executor = self._nemesis_executor
        for future in as_completed(futures):
            future.result()
        if executor is not None:
            executor.shutdown(wait=True)
        uploaded = sum(
            entry.get("nemesis", {}).get("status") == "uploaded"
            for host, result in self.scan_results.items()
            if not host.startswith("_") and isinstance(result, dict)
            for share in result.get("shares", {}).values()
            for entry in share.get("downloaded_files", [])
        )
        failed = sum(
            entry.get("nemesis", {}).get("status") == "failed"
            for host, result in self.scan_results.items()
            if not host.startswith("_") and isinstance(result, dict)
            for share in result.get("shares", {}).values()
            for entry in share.get("downloaded_files", [])
        )
        if futures:
            logging.info(f"Nemesis uploads: {uploaded} uploaded, {failed} failed")

    def submit_to_nemesis(
        self, local_file_path: str, unc_path: str, file_mtime_epoch: float, host: str
    ) -> Dict[str, Any]:
        """Submit downloaded file to Nemesis API using multipart form data.

        Args:
            local_file_path: Path to the local file to upload
            unc_path: UNC path of the original file
            file_mtime_epoch: File modification time as epoch timestamp
            host: Target host IP or hostname

        Returns:
            dict: Upload status with 'success' (bool), 'timestamp' (str), and optional 'response_id' (str)
        """
        upload_result = {
            "success": False,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "response_id": None,
            "last_error": None,
        }

        if (
            not self.args.nemesis_url
            or not self.args.nemesis_auth
            or not self.args.nemesis_project
        ):
            upload_result["last_error"] = (
                "Nemesis URL, auth, and project are required"
            )
            return upload_result

        if not os.path.exists(local_file_path):
            upload_result["last_error"] = f"Local file not found: {local_file_path}"
            return upload_result

        # Convert UNC path to Nemesis format (removes host, converts C$ to C:, uses forward slashes)
        nemesis_path = convert_unc_to_nemesis_path(unc_path)

        try:
            # Parse authentication
            if ":" not in self.args.nemesis_auth:
                upload_result["last_error"] = (
                    "Nemesis auth must be in username:password format"
                )
                return upload_result

            username, password = self.args.nemesis_auth.split(":", 1)

            # Prepare endpoint
            endpoint = f"{self.args.nemesis_url.rstrip('/')}/files"

            # Prepare metadata
            current_time = datetime.now(timezone.utc)
            expiration_time = current_time + timedelta(days=365)  # 1 year from now
            file_mtime = datetime.fromtimestamp(file_mtime_epoch, timezone.utc)

            metadata = {
                "agent_id": "shrawler",
                "source": f"host://{host}",
                "project": self.args.nemesis_project,
                "timestamp": current_time.isoformat(),
                "expiration": expiration_time.isoformat(),
                "path": nemesis_path,
                "modification_time": file_mtime.isoformat(),
            }

            # Prepare multipart form data
            with open(local_file_path, "rb") as file_data:
                # Both file and metadata must be in files dict to match curl -F behavior
                files = {
                    "file": (
                        os.path.basename(local_file_path),
                        file_data,
                        "application/octet-stream",
                    ),
                    "metadata": (None, json.dumps(metadata), "application/json"),
                }

                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                response = requests.post(
                    endpoint,
                    files=files,
                    auth=(username, password),
                    verify=False,
                    timeout=30,
                )

                if response.status_code not in [200, 201]:
                    upload_result["last_error"] = f"HTTP {response.status_code}"
                else:
                    logging.debug(
                        f"Successfully submitted file to Nemesis: {nemesis_path}"
                    )
                    upload_result["success"] = True

                    # Try to extract response ID if present
                    try:
                        response_data = response.json()
                        if "id" in response_data:
                            upload_result["response_id"] = response_data["id"]
                    except (json.JSONDecodeError, KeyError) as e:
                        logging.debug(
                            f"Failed to parse Nemesis response for {nemesis_path}: {e}"
                        )

        except (
            requests.exceptions.RequestException,
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            FileNotFoundError,
        ) as e:
            upload_result["last_error"] = str(e)
            logging.debug(f"Nemesis submission error for {nemesis_path}: {e!s}")
        except Exception as e:
            upload_result["last_error"] = str(e)
            logging.debug(
                f"Unexpected error in Nemesis submission for {nemesis_path}: {e!s}"
            )

        return upload_result

    def write_csv_outputs(self) -> List[str]:
        """Write CSV output files conditionally based on data presence.

        Returns:
            List of CSV filenames that were actually written
        """
        import csv

        csv_files_written = []
        self.output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        # Write shares CSV (only if share data exists)
        if self.share_rows:
            shares_fieldnames = [
                "host",
                "share_name",
                "comment",
                "read_permission",
                "write_permission",
                "unc_path",
                "scan_timestamp_utc",
            ]
            output_path = self.output_dir / "shrawler_shares.csv"
            with output_path.open("w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=shares_fieldnames)
                writer.writeheader()
                writer.writerows(self.share_rows)
            os.chmod(output_path, 0o600)
            csv_files_written.append(str(output_path))

        # Write files CSV (only if file data exists - requires --spider)
        if self.file_rows:
            files_fieldnames = [
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
            output_path = self.output_dir / "shrawler_files.csv"
            with output_path.open("w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=files_fieldnames)
                writer.writeheader()
                writer.writerows(self.file_rows)
            os.chmod(output_path, 0o600)
            csv_files_written.append(str(output_path))

        # Write downloads CSV (only if download data exists - requires download criteria)
        if self.download_rows:
            downloads_fieldnames = [
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
            output_path = self.output_dir / "shrawler_downloads.csv"
            with output_path.open("w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=downloads_fieldnames)
                writer.writeheader()
                writer.writerows(self.download_rows)
            os.chmod(output_path, 0o600)
            csv_files_written.append(str(output_path))

        if self.snaffler_matches:
            snaffler_fieldnames = [
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
            output_path = self.output_dir / "shrawler_snaffler_matches.csv"
            with output_path.open("w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=snaffler_fieldnames)
                writer.writeheader()
                writer.writerows(self.snaffler_matches)
            os.chmod(output_path, 0o600)
            csv_files_written.append(str(output_path))

        return csv_files_written

    def write_json_output(self) -> Path:
        """Write consolidated JSON results with private permissions."""
        self.scan_results["_schema"] = {
            "name": "shrawler-results",
            "version": 2,
        }
        self.scan_results["_summary"] = self._build_scan_summary()
        self.output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        output_path = self.output_dir / "shrawler_results.json"
        with output_path.open("w") as output_file:
            json.dump(self.scan_results, output_file, indent=4)
        os.chmod(output_path, 0o600)
        return output_path

    def _build_scan_summary(self) -> Dict[str, Any]:
        """Build a machine-readable summary of the current scan state."""
        host_results = [
            result
            for key, result in self.scan_results.items()
            if not key.startswith("_") and isinstance(result, dict)
        ]
        status_counts = Counter(
            str(result.get("status", "unknown")) for result in host_results
        )
        shares = [
            share
            for result in host_results
            for share in result.get("shares", {}).values()
        ]
        downloads = [
            download
            for share in shares
            for download in share.get("downloaded_files", [])
        ]
        return {
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "hosts_attempted": len(host_results),
            "host_statuses": dict(status_counts),
            "shares_enumerated": len(shares),
            "readable_shares": sum(
                bool(share.get("permissions", {}).get("read")) for share in shares
            ),
            "writable_shares": sum(
                share.get("permissions", {}).get("write") is True for share in shares
            ),
            "files_seen": self.files_seen_count,
            "files_downloaded": self.download_count,
            "downloaded_bytes": self.downloaded_bytes,
            "snaffler_matches": len(self.snaffler_matches),
            "nemesis": {
                "mode": self.args.nemesis_mode,
                "uploaded": sum(
                    item.get("nemesis", {}).get("status") == "uploaded"
                    for item in downloads
                ),
                "failed": sum(
                    item.get("nemesis", {}).get("status") == "failed"
                    for item in downloads
                ),
            },
            "operations": {
                name: {
                    "count": self.operation_counts[name],
                    "seconds": round(self.operation_seconds[name], 6),
                    "bytes": self.operation_bytes[name],
                }
                for name in sorted(self.operation_counts)
            },
        }

    def finalize(self, interrupted: bool = False) -> None:
        """Display summaries and persist requested output exactly once."""
        self._finish_nemesis_uploads()
        if interrupted:
            print("\n\n" + error("User interrupted scan."))
            print(success("Summary of work done:"))
        else:
            print(success("Shrawler Scan Complete"))

        if self.args.spider:
            logging.info(f"Total files seen: {self.files_seen_count}")
        if self.download_count > 0 or self.args.download_ext is not None:
            logging.info(f"Total files downloaded: {self.download_count}")
            logging.info(f"Total bytes downloaded: {self.downloaded_bytes}")

        if self.snaffler_enabled:
            self._display_snaffler_summary()
            self.scan_results["_snaffler_summary"] = {
                "total_matches": len(self.snaffler_matches),
                "unique_matched_files": len(self.snaffler_matched_file_keys),
                "top_rules": [
                    {"rule_name": name, "count": count}
                    for name, count in self.snaffler_match_counter.most_common(10)
                ],
            }

        if self.args.metrics:
            self._display_operation_metrics()

        if self.count_extensions_list or self.count_strings_list:
            self._display_file_count_summary()
        if self.args.unique and self.unique_files_data and not self.args.spider:
            display_unique_files(find_unique_files_by_mtime(self.unique_files_data))

        if self.csv_enabled:
            files_written = self.write_csv_outputs()
            if files_written:
                logging.info(f"CSV files written: {', '.join(files_written)}")
            else:
                logging.info("No data to write to CSV files")
        if self.json_enabled and self.scan_results:
            try:
                output_path = self.write_json_output()
                logging.info(f"Scan results written to {output_path}")
            except Exception as exc:
                logging.warning(f"Failed to write scan results file: {exc}")
        self._checkpoint_state()

    def get_shares(
        self,
        target: str,
        mach_name: str,
        smbclient: Any,
        default_shares: List[str],
        spider: bool = False,
        desired_share: str = "",
    ) -> None:
        started = time.perf_counter()
        shares = smbclient.listShares()
        self._record_operation("list_shares", time.perf_counter() - started)

        share_names = [share["shi1_netname"][:-1] for share in shares]
        largest_share_name = max([len(name) for name in share_names], default=0)

        excluded_shares = set(default_shares)
        if desired_share:
            requested = {
                name.strip() for name in desired_share.split(",") if name.strip()
            }
            missing_requested = sorted(requested.difference(set(share_names)))
            if missing_requested:
                logging.warning(
                    f"Requested shares not found: {', '.join(missing_requested)}"
                )
            excluded_shares = set(share_names).difference(requested)

        for share in shares:
            share_name = share["shi1_netname"][:-1]
            share_comment = share["shi1_remark"][:-1]
            if share_name in excluded_shares:
                continue
            existing_share = self.scan_results.get(target, {}).get("shares", {}).get(
                share_name, {}
            )
            if existing_share.get("status") == "complete":
                logging.info(f"Skipping completed share from resume state: {share_name}")
                continue

            try:
                share_snaffle_rules: List[SnafflerRule] = []
                if self.snaffler_enabled:
                    discard_share, share_snaffle_rules = self._evaluate_snaffler_share(
                        target,
                        share_name,
                    )
                    if discard_share:
                        logging.debug(
                            f"Skipping share {target}\\{share_name} due to Snaffler discard"
                        )
                        continue

                share_perms, root_results = self.check_share_perm(
                    share_name, smbclient, require_listing=spider
                )

                if target not in self.scan_results:
                    self.scan_results[target] = {
                        "scan_timestamp_utc": datetime.now(timezone.utc).isoformat(),
                        "shares": {},
                    }

                self.scan_results[target]["shares"][share_name] = {
                    "comment": share_comment,
                    "permissions": share_perms,
                    "unc_path": f"\\\\{target}\\{share_name}",
                    "status": "scanning",
                    "discovered_files": existing_share.get("discovered_files", []),
                    "downloaded_files": existing_share.get("downloaded_files", []),
                }

                if share_snaffle_rules:
                    self.scan_results[target]["shares"][share_name][
                        "snaffler_share_rules"
                    ] = [
                        {
                            "rule_name": rule.rule_name,
                            "triage": rule.triage,
                            "description": rule.description,
                        }
                        for rule in share_snaffle_rules
                    ]

                    share_context = {
                        "host": target,
                        "share_name": share_name,
                        "remote_path": "",
                        "unc_path": f"\\\\{target}\\{share_name}",
                    }
                    for rule in share_snaffle_rules:
                        self._record_snaffler_match(share_context, rule, share_name)

                snaffler_share_marker = ""
                if share_snaffle_rules:
                    first_rule = share_snaffle_rules[0]
                    snaffler_share_marker = (
                        f" {Fore.YELLOW}[SNAFFLER: {first_rule.rule_name}/{first_rule.triage}]"
                        f"{Style.RESET_ALL}"
                    )

                if self.csv_enabled:
                    self.share_rows.append(
                        {
                            "host": target,
                            "share_name": share_name,
                            "comment": share_comment,
                            "read_permission": share_perms["read"],
                            "write_permission": share_perms["write"],
                            "unc_path": f"\\\\{target}\\{share_name}",
                            "scan_timestamp_utc": datetime.now(
                                timezone.utc
                            ).isoformat(),
                        }
                    )

                if spider and share_perms["read"]:
                    if self.args.output_mode == "tree":
                        print()
                        logging.info(
                            f"{mach_name}\\{share_name}{snaffler_share_marker}"
                        )
                        self.print_table_header()
                    self.spider_shares(
                        target,
                        share_name,
                        "/",
                        smbclient,
                        initial_results=root_results,
                    )
                else:
                    if self.args.output_mode == "tree" or share_snaffle_rules:
                        print_share_info(
                            share_name,
                            share_comment,
                            share_perms,
                            largest_share_name,
                            snaffler_share_marker,
                        )
                self.scan_results[target]["shares"][share_name]["status"] = "complete"
                self.state_store.append(
                    "share_finished", host=target, share=share_name, status="complete"
                )
                self._checkpoint_state()

            except KeyboardInterrupt:
                raise

    def check_share_perm(
        self, share: str, smbclient: Any, require_listing: bool = False
    ) -> Tuple[Dict[str, Union[str, bool]], Optional[List[Any]]]:
        read_write = {"read": False, "write": "N/A"}
        root_results: Optional[List[Any]] = None

        if self.args.permission_check != "none" or require_listing:
            started = time.perf_counter()
            try:
                root_results = list(smbclient.listPath(share, "*", password=None))
                read_write["read"] = True
            except SessionError:
                read_write["read"] = False
            finally:
                self._record_operation("list_path", time.perf_counter() - started)

        # check for write rights
        if self.args.permission_check == "read-write":
            try:
                # pretty much all tools that crawl shares have to attempt to write to disk.
                # If it does not allow, you've got your write perms
                # Downside, its possible to allow write but not delete perms.
                # In this case, I like to specify the folder name incase this happens - you can let clients know
                directory = f"shrawler_write_test_{uuid.uuid4().hex}"
                created = False
                try:
                    started = time.perf_counter()
                    smbclient.createDirectory(share, directory)
                    self._record_operation(
                        "write_probe_create", time.perf_counter() - started
                    )
                    created = True
                    read_write["write"] = True
                finally:
                    if created:
                        try:
                            started = time.perf_counter()
                            smbclient.deleteDirectory(share, directory)
                            self._record_operation(
                                "write_probe_delete", time.perf_counter() - started
                            )
                        except SessionError as cleanup_error:
                            logging.warning(
                                f"Created but could not remove {share}\\{directory}: "
                                f"{cleanup_error}"
                            )
            except SessionError as e:
                logging.debug(f"Full error: {e}")
                read_write["write"] = False
        return read_write, root_results

    def build_tree_structure(
        self,
        base_dir: str,
        directory_result: Any,
        smbclient: Any,
        share: str,
        indent: str = "",
        last: bool = False,
        depth: int = 0,
    ) -> None:
        """
        Recursively prints the tree structure for a given directory, appending paths using string concatenation.
        """
        directory = directory_result.get_longname()
        target_host = self.current_host or ""
        directory_remote_path = base_dir + directory

        if self.snaffler_enabled:
            discard_directory, _ = self._evaluate_snaffler_directory(
                target_host,
                share,
                directory_remote_path,
            )
            if discard_directory:
                logging.debug(
                    f"Skipping directory {share}:{directory_remote_path} due to Snaffler discard"
                )
                return

        # Format directory in table format
        size = "-"
        mtime = self.readable_time_short(directory_result.get_mtime_epoch())

        # Build the proper tree structure for directories
        connector = "└── " if last else "├── "
        name = indent + connector + f"{Fore.BLUE}{directory}/{Style.RESET_ALL}"

        if self.args.output_mode == "tree":
            print(self.format_table_row(size, mtime, name))

        # Update the indent for the next depth level
        next_indent = indent + ("    " if last else "│   ")

        try:
            started = time.perf_counter()
            results = smbclient.listPath(
                share, base_dir + directory + "/*", password=None
            )
            self._record_operation("list_path", time.perf_counter() - started)

            # Filter out '.' and '..' and separate directories from files
            directories: List[Any] = []
            files: List[Any] = []
            for result in results:
                if result.get_longname() not in [".", ".."]:
                    if result.is_directory():
                        directories.append(result)
                    else:
                        files.append(result)

            directories_to_visit = directories if self.args.max_depth > 0 else []
            total_items = len(directories_to_visit) + len(files)
            count = 0

            # Always inspect files in this directory. Only recursion is depth-limited.
            if files or (directories and depth < self.args.max_depth - 1):
                # Process directories first
                directories_to_visit = (
                    directories if depth < self.args.max_depth - 1 else []
                )
                total_items = len(directories_to_visit) + len(files)
                for result in directories_to_visit:
                    # throttling
                    if self.args.delay > 0:
                        time.sleep(self.args.delay)

                    count += 1
                    is_last = count == total_items

                    self.build_tree_structure(
                        base_dir + directory + "/",
                        result,
                        smbclient,
                        share,
                        next_indent,
                        last=is_last,
                        depth=depth + 1,
                    )

                # Process files - conditional logic based on --unique-mtime
                if self.args.unique:
                    # Collect files with mtime for uniqueness analysis
                    files_with_mtime: List[Tuple[Any, float]] = []
                    for file_result in files:
                        file_mtime_epoch = file_result.get_mtime_epoch()
                        files_with_mtime.append((file_result, file_mtime_epoch))

                    # Determine which files are unique in this directory
                    unique_indices = find_unique_files_in_directory(files_with_mtime)

                    # Display files with uniqueness information
                    for i, (file_result, _file_mtime_epoch) in enumerate(
                        files_with_mtime
                    ):
                        # throttling
                        if self.args.delay > 0:
                            time.sleep(self.args.delay)

                        count += 1
                        is_last = count == total_items
                        is_unique = i in unique_indices

                        self._process_and_display_file(
                            file_result,
                            base_dir,
                            directory,
                            smbclient,
                            share,
                            next_indent,
                            is_last,
                            is_unique,
                        )
                else:
                    # Original behavior - process files immediately without uniqueness analysis
                    for file_result in files:
                        # throttling
                        if self.args.delay > 0:
                            time.sleep(self.args.delay)

                        count += 1
                        is_last = count == total_items

                        self._process_and_display_file(
                            file_result,
                            base_dir,
                            directory,
                            smbclient,
                            share,
                            next_indent,
                            is_last,
                            is_unique=False,
                        )

        except Exception as e:
            logging.warning(f"Error accessing directory: {e}")

    def _record_discovered_file(
        self,
        host: str,
        share: str,
        remote_path: str,
        unc_path: str,
        filename: str,
        size_bytes: int,
        mtime_epoch: float,
    ) -> Dict[str, Any]:
        """Record a discovered file in JSON state and optional CSV state."""
        file_entry: Dict[str, Any] = {
            "host": host,
            "share_name": share,
            "remote_path": remote_path,
            "unc_path": unc_path,
            "file_name": filename,
            "size_bytes": size_bytes,
            "readable_size": self.readable_file_size(size_bytes),
            "mtime_utc": datetime.fromtimestamp(mtime_epoch, timezone.utc).isoformat(),
            "is_directory": False,
            "scan_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
        with self._state_lock:
            host_result = self.scan_results.setdefault(
                host,
                {
                    "scan_timestamp_utc": datetime.now(timezone.utc).isoformat(),
                    "status": "scanning",
                    "error": None,
                    "shares": {},
                },
            )
            share_result = host_result["shares"].setdefault(
                share,
                {"downloaded_files": [], "discovered_files": []},
            )
            share_result.setdefault("discovered_files", []).append(file_entry)

            if self.csv_enabled:
                csv_entry = dict(file_entry)
                csv_entry.update({"can_read": None, "can_write": None})
                self.file_rows.append(csv_entry)
        self.state_store.append("file_discovered", host=host, share=share, file=file_entry)
        return file_entry

    def _checkpoint_state(self) -> None:
        """Publish an atomic snapshot suitable for a later --resume."""
        with self._state_lock:
            results = copy.deepcopy(self.scan_results)
            summary = self._build_scan_summary()
            self.state_store.checkpoint(results, summary)

    def _process_and_display_file(
        self,
        file_result: Any,
        base_dir: str,
        directory: str,
        smbclient: Any,
        share: str,
        indent: str,
        is_last: bool,
        is_unique: bool,
    ) -> None:
        """Process and display a single file with download and unique logic."""
        next_filedir = file_result.get_longname()
        remote_file_path = base_dir + directory + "/" + next_filedir
        host_for_ops = self.current_host or ""
        file_size = file_result.get_filesize()
        file_mtime_epoch = file_result.get_mtime_epoch()
        file_extension = os.path.splitext(next_filedir)[1].lower()
        unc_path = f"\\\\{host_for_ops}\\{share}\\{remote_file_path.lstrip('/')}"
        if unc_path in self._resume_paths:
            return
        with self._state_lock:
            self.files_seen_count += 1

        file_context = {
            "host": host_for_ops,
            "share_name": share,
            "remote_path": remote_file_path,
            "unc_path": unc_path,
            "file_name": next_filedir,
            "file_extension": file_extension,
            "size_bytes": file_size,
        }

        self._record_discovered_file(
            host_for_ops,
            share,
            remote_file_path,
            unc_path,
            next_filedir,
            file_size,
            file_mtime_epoch,
        )

        snaffler_eval = self._evaluate_snaffler_file(smbclient, share, file_context)
        if snaffler_eval.get("discarded"):
            with self._state_lock:
                self._prefetched_content.pop(unc_path, None)
            return

        candidate_matches = list(snaffler_eval.get("candidate_matches", []))
        for rule, matched_string in candidate_matches:
            self._record_snaffler_match(file_context, rule, matched_string)

        if self.count_extensions_list or self.count_strings_list:
            self._count_file(next_filedir)

        if self.args.unique:
            self.unique_files_data.append((remote_file_path, file_mtime_epoch))

        download_status = ""
        unique_status = f" {Fore.MAGENTA}[UNIQUE]{Style.RESET_ALL}" if is_unique else ""
        filename_lower = next_filedir.lower()
        should_download = self._should_download_by_cli(filename_lower)
        if candidate_matches and not self.args.snaffler_no_auto_download:
            should_download = True

        if should_download:
            nemesis_upload = self._should_upload_to_nemesis(bool(candidate_matches))
            download_status = self._download_file_with_dedupe(
                smbclient,
                share,
                remote_file_path,
                file_size,
                file_mtime_epoch,
                nemesis_upload,
            )
        else:
            with self._state_lock:
                self._prefetched_content.pop(unc_path, None)

        snaffler_status = self._snaffler_console_marker(candidate_matches)
        file_metadata = self.parse_file(file_result)
        size = file_metadata["size"]
        mtime = self.readable_time_short(file_mtime_epoch)

        file_connector = "└── " if is_last else "├── "
        name = indent + file_connector + f"{Fore.GREEN}{next_filedir}{Style.RESET_ALL}"
        if unique_status:
            name += unique_status
        if download_status:
            name += download_status
        if snaffler_status:
            name += snaffler_status

        if self.args.output_mode == "tree":
            print(self.format_table_row(size, mtime, name))
        elif self.args.output_mode == "matches" and (
            candidate_matches or download_status or is_unique
        ):
            print(f"{unc_path}{unique_status}{download_status}{snaffler_status}")

    def spider_shares(
        self,
        target: str,
        share: str,
        base_dir: str,
        smbclient: Any,
        initial_results: Optional[List[Any]] = None,
    ) -> None:
        directories: List[Any] = []
        files: List[Any] = []
        try:
            # List all items in the base directory
            if initial_results is None:
                started = time.perf_counter()
                results = list(
                    smbclient.listPath(share, base_dir + "*", password=None)
                )
                self._record_operation("list_path", time.perf_counter() - started)
            else:
                results = initial_results

            # Separate directories and files
            for result in results:
                if result.get_longname() not in [".", ".."]:
                    if result.is_directory():
                        directories.append(result)
                    else:
                        files.append(result)

            # A max depth of zero means inspect only files at the share root.
            directories_to_visit = directories if self.args.max_depth > 0 else []
            total_items = len(directories_to_visit) + len(files)
            current_item = 0

            # Process directories first
            for directory in directories_to_visit:
                current_item += 1
                is_last = current_item == total_items

                self.build_tree_structure(
                    base_dir, directory, smbclient, share, last=is_last
                )

            # Process files at root level - conditional logic based on --unique-mtime
            if self.args.unique:
                # Collect files with mtime for uniqueness analysis
                files_with_mtime: List[Tuple[Any, float]] = []
                for file_result in files:
                    file_mtime_epoch = file_result.get_mtime_epoch()
                    files_with_mtime.append((file_result, file_mtime_epoch))

                # Determine which files are unique in this directory
                unique_indices = find_unique_files_in_directory(files_with_mtime)

                # Display files with uniqueness information
                for i, (file_result, _file_mtime_epoch) in enumerate(files_with_mtime):
                    current_item += 1
                    is_last = current_item == total_items
                    is_unique = i in unique_indices

                    self._process_and_display_file_root(
                        file_result,
                        base_dir,
                        smbclient,
                        share,
                        is_last,
                        is_unique,
                    )
            else:
                # Original behavior - process files immediately without uniqueness analysis
                for file_result in files:
                    current_item += 1
                    is_last = current_item == total_items

                    self._process_and_display_file_root(
                        file_result,
                        base_dir,
                        smbclient,
                        share,
                        is_last,
                        is_unique=False,
                    )

        except Exception as e:
            logging.warning(f"Error accessing directory: {e}")

    def _process_and_display_file_root(
        self,
        file_result: Any,
        base_dir: str,
        smbclient: Any,
        share: str,
        is_last: bool,
        is_unique: bool,
    ) -> None:
        """Process and display a file at root level with download and unique logic."""
        with self._state_lock:
            self.files_seen_count += 1

        filename = file_result.get_longname()
        remote_file_path = base_dir + filename
        host_for_ops = self.current_host or ""
        file_size = file_result.get_filesize()
        file_mtime_epoch = file_result.get_mtime_epoch()
        file_extension = os.path.splitext(filename)[1].lower()
        unc_path = f"\\\\{host_for_ops}\\{share}\\{remote_file_path.lstrip('/')}"

        file_context = {
            "host": host_for_ops,
            "share_name": share,
            "remote_path": remote_file_path,
            "unc_path": unc_path,
            "file_name": filename,
            "file_extension": file_extension,
            "size_bytes": file_size,
        }

        self._record_discovered_file(
            host_for_ops,
            share,
            remote_file_path,
            unc_path,
            filename,
            file_size,
            file_mtime_epoch,
        )

        snaffler_eval = self._evaluate_snaffler_file(smbclient, share, file_context)
        if snaffler_eval.get("discarded"):
            with self._state_lock:
                self._prefetched_content.pop(unc_path, None)
            return

        candidate_matches = list(snaffler_eval.get("candidate_matches", []))
        for rule, matched_string in candidate_matches:
            self._record_snaffler_match(file_context, rule, matched_string)

        if self.count_extensions_list or self.count_strings_list:
            self._count_file(filename)

        if self.args.unique:
            self.unique_files_data.append((remote_file_path, file_mtime_epoch))

        download_status = ""
        unique_status = (
            f" {Fore.MAGENTA}[POTENTIAL UNIQUE FILE]{Style.RESET_ALL}"
            if is_unique
            else ""
        )

        filename_lower = filename.lower()
        should_download = self._should_download_by_cli(filename_lower)
        if candidate_matches and not self.args.snaffler_no_auto_download:
            should_download = True

        if should_download:
            nemesis_upload = self._should_upload_to_nemesis(bool(candidate_matches))
            download_status = self._download_file_with_dedupe(
                smbclient,
                share,
                remote_file_path,
                file_size,
                file_mtime_epoch,
                nemesis_upload,
            )
        else:
            with self._state_lock:
                self._prefetched_content.pop(unc_path, None)

        snaffler_status = self._snaffler_console_marker(candidate_matches)
        file_metadata = self.parse_file(file_result)
        size = file_metadata["size"]
        mtime = self.readable_time_short(file_mtime_epoch)

        connector = "└── " if is_last else "├── "
        name = connector + f"{Fore.GREEN}{filename}{Style.RESET_ALL}"
        if unique_status:
            name += unique_status
        if download_status:
            name += download_status
        if snaffler_status:
            name += snaffler_status

        if self.args.output_mode == "tree":
            print(self.format_table_row(size, mtime, name))
        elif self.args.output_mode == "matches" and (
            candidate_matches or download_status or is_unique
        ):
            print(f"{unc_path}{unique_status}{download_status}{snaffler_status}")

    def readable_file_size(self, nbytes: float) -> str:
        "Convert into readable file sizes"
        suffixes = ["B", "KB", "MB", "GB"]

        i = 0
        for i in range(len(suffixes)):
            if nbytes < 1024 or i == len(suffixes) - 1:
                break
            nbytes /= 1024

        size_str = f"{nbytes:.2f}".rstrip("0").rstrip(".")

        return f"{size_str}{suffixes[i]}"

    def readable_time(self, timestamp: float) -> str:
        "convert into readable time"
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))

    def readable_time_short(self, timestamp: float) -> str:
        "convert into readable time without seconds"
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(timestamp))

    def format_table_row(self, size: str, mtime: str, name: str) -> str:
        "format a table row with fixed-width columns"
        return f"{size:>9} {mtime:<21} {name}"

    def print_table_header(self) -> None:
        "print the table header and separator"
        print()
        header = self.format_table_row("SIZE", "LAST MODIFIED", "NAME")
        separator = self.format_table_row("-" * 9, "-" * 21, "-" * 40)
        print(header)
        print(separator)

    def parse_file(self, file_info: Any) -> Dict[str, str]:
        "Parse file and output metadata"
        file_size = file_info.get_filesize()
        file_creation_date = file_info.get_ctime_epoch()
        file_modified_date = file_info.get_mtime_epoch()

        results = {
            "size": self.readable_file_size(file_size),
            "ctime": self.readable_time(file_creation_date),
            "mtime": self.readable_time(file_modified_date),
        }
        return results

    def init_smb_session(
        self,
        domain: str,
        username: str,
        password: str,
        address: str,
        lmhash: str,
        nthash: str,
    ):
        """
        Initiate SMB Session with host using impacket libraries.
        """
        started = time.perf_counter()
        try:
            smbClient = SMBConnection(address, address, sess_port=445)
            smbClient.enableDFSSupport = True

            dialect = smbClient.getDialect()

            if dialect == SMB_DIALECT:
                logging.debug("SMBv1 dialect used")

            elif dialect == SMB2_DIALECT_002:
                logging.debug("SMBv2.0 dialect used")

            elif dialect == SMB2_DIALECT_21:
                logging.debug("SMBv2.1 dialect used")

            else:
                logging.debug("SMBv3.0 dialect used")

            if self.args.k is True:
                smbClient.kerberosLogin(
                    username,
                    password,
                    domain,
                    lmhash,
                    nthash,
                    self.args.aesKey,
                    domain,
                )

            else:
                smbClient.login(username, password, domain, lmhash, nthash)
            if smbClient.isGuestSession() > 0:
                logging.debug("GUEST Session Granted")
            else:
                logging.debug("USER Session Granted")
        except SessionError as e:
            self._record_operation("smb_connect", time.perf_counter() - started)
            logging.warning(f"Invalid login attempt on '{address}'\n")
            logging.debug(f"Full error: {e}")
            print(error(""))
            return None
        except Exception:
            self._record_operation("smb_connect", time.perf_counter() - started)
            raise

        self._record_operation("smb_connect", time.perf_counter() - started)
        logging.info(f"Connected to {address}")
        return smbClient

    def get_ip_addrs(self, file: str) -> List[str]:
        with open(file) as f:
            lines = []
            for raw_line in f:
                line = raw_line.split("#", 1)[0].strip()
                if line:
                    lines.append(line)

        return lines

    def _scan_host(
        self,
        domain: str,
        lmhash: str,
        nthash: str,
        mach_ip: str,
        mach_name: str,
    ) -> None:
        """Scan one host using worker-local SMB state."""
        self.current_host = mach_ip
        existing = self.scan_results.get(mach_ip, {})
        if existing.get("status") == "complete":
            logging.info(f"Skipping completed host from resume state: {mach_ip}")
            return
        with self._state_lock:
            host_state = self.scan_results.setdefault(mach_ip, {"shares": {}})
            host_state.update(
                {
                    "scan_timestamp_utc": datetime.now(timezone.utc).isoformat(),
                    "status": "scanning",
                    "error": None,
                }
            )
            host_state.setdefault("shares", {})

        smbclient: Any = None
        try:
            smbclient = self.init_smb_session(
                domain,
                self.username,
                self.password,
                mach_ip,
                lmhash,
                nthash,
            )
            if smbclient is None:
                self.scan_results[mach_ip]["status"] = "authentication_failed"
                self.scan_results[mach_ip]["error"] = "SMB authentication failed"
                return

            self.get_shares(
                mach_ip,
                mach_name,
                smbclient,
                self.normal_shares,
                self.args.spider,
                self.args.shares,
            )
            self.scan_results[mach_ip]["status"] = "complete"
            if self.args.output_mode == "tree":
                print()
                print(success(""))
        except OSError as exc:
            self.scan_results[mach_ip]["status"] = "connection_failed"
            self.scan_results[mach_ip]["error"] = str(exc)
            logging.warning(f"Could not connect to SMB on '{mach_ip}': {exc}")
        except Exception as exc:
            self.scan_results[mach_ip]["status"] = "scan_failed"
            self.scan_results[mach_ip]["error"] = str(exc)
            logging.warning(f"Scan failed for '{mach_ip}': {exc}")
        finally:
            if smbclient is not None:
                try:
                    smbclient.logoff()
                except Exception:
                    logging.debug(f"Failed to close SMB session for {mach_ip}")
            self.state_store.append(
                "host_finished",
                host=mach_ip,
                status=self.scan_results.get(mach_ip, {}).get("status", "unknown"),
            )
            self._checkpoint_state()

    def main(self) -> int:
        # Logging
        logger = logging.getLogger()
        handler = logging.StreamHandler()
        handler.setFormatter(Formatter())

        logger.addHandler(handler)

        if self.verbose:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)

        if self.args.output_mode != "progress":
            print(self.banner())
        # parses the argument 'target' to get the values needed
        domain, self.username, self.password, self.domain_controller = parse_target(
            self.args.target
        )
        if (
            len(self.password) == 0
            and len(self.username) != 0
            and self.args.hashes is None
            and self.args.no_pass is False
            and self.args.aesKey is None
        ):
            from getpass import getpass

            self.password = getpass("Password:")

        if self.args.aesKey is not None:
            self.args.k = True

        if self.args.hashes is not None:
            try:
                lmhash, nthash = self.args.hashes.split(":", 1)
            except ValueError as exc:
                raise ValueError("--hashes must use LMHASH:NTHASH format") from exc
        else:
            lmhash, nthash = "", ""

        if self.args.skip_share:
            shares = self.args.skip_share.split(",")
            for share in shares:
                self.normal_shares.append(share)

        if self.args.add_share:
            shares = self.args.add_share.split(",")
            for share in shares:
                share = share.strip()
                if share in self.normal_shares:
                    self.normal_shares.remove(share)

        if self.args.hosts_file:
            machine_ip = self.get_ip_addrs(self.args.hosts_file)
            machine_names = machine_ip

        elif self.args.host:
            machine_ip = [self.args.host]
            machine_names = machine_ip

        else:
            if not self.domain_controller:
                raise ValueError("No target host was provided")
            machine_ip = [self.domain_controller]
            machine_names = machine_ip

        hosts = list(zip(machine_ip, machine_names))
        worker_count = min(self.args.workers, max(1, len(hosts)))
        progress = ProgressReporter(self) if self.args.output_mode == "progress" else None
        if progress:
            progress.start()
        try:
            if worker_count == 1:
                for mach_ip, mach_name in hosts:
                    self._scan_host(domain, lmhash, nthash, mach_ip, mach_name)
            else:
                with ThreadPoolExecutor(
                    max_workers=worker_count, thread_name_prefix="shrawler-host"
                ) as executor:
                    futures = [
                        executor.submit(
                            self._scan_host,
                            domain,
                            lmhash,
                            nthash,
                            mach_ip,
                            mach_name,
                        )
                        for mach_ip, mach_name in hosts
                    ]
                    for future in as_completed(futures):
                        future.result()
        finally:
            if progress:
                progress.stop()

        self._checkpoint_state()
        self.finalize()
        statuses = self._build_scan_summary()["host_statuses"]
        return 0 if statuses and set(statuses) == {"complete"} else 1


def main(options: Any) -> None:
    """Calling shrawler."""
    s = Shrawler(options)
    try:
        raise SystemExit(s.main())
    except KeyboardInterrupt:
        s.finalize(interrupted=True)
        raise SystemExit(130)


if __name__ == "__main__":
    main()
