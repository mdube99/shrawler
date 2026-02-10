#!/usr/bin/env python3

from impacket.smbconnection import (
    SMBConnection,
    SMB2_DIALECT_002,
    SMB2_DIALECT_21,
    SMB_DIALECT,
    SessionError,
)
from impacket.examples.utils import parse_target
import socket
import argparse
import logging
import json
import time
import os
import re
import io
import requests
import urllib3
import ipaddress
from typing import Any, Union, List, Dict, Tuple, Set
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from colorama import init, Fore, Style
from dotenv import load_dotenv

# Load .env file if it exists
load_dotenv()

# Disable SSL warnings for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
    print(f"     {prefix} {share_name.ljust(largest_share_name + 20)} | Read: {read.ljust(3)} | Write: {write.ljust(3)} | Comment: {share_comment if share_comment else 'N/A'}")


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


class Shrawler:
    """SMB Share Crawling Tool."""

    def __init__(self) -> None:
        init()  # for Colorama
        parser = argparse.ArgumentParser(
            """python3 shrawler.py homelab.local/user:password@dc-ip"""
        )
        parser.add_argument(
            "target",
            action="store",
            help="[[domain/]username[:password]@]<dc-ip>",
        )
        parser.add_argument("-v", "--verbose", action="store_true", help="Verbose")
        parser.add_argument(
            "--read-only",
            dest="read_only",
            action="store_true",
            help="Skip checking for write permission",
        )
        parser.add_argument(
            "--skip-share",
            dest="skip_share",
            help="Additional shares to skip, separated by comma. Case Sensitive",
        )
        parser.add_argument(
            "--add-share",
            dest="add_share",
            help="Add additional shares to search for, separated by comma. Case sensitive",
        )
        parser.add_argument(
            "--shares",
            dest="shares",
            help="Only scan shares specified with this argument",
        )

        parser.add_argument(
            "--hosts-file",
            action="store",
            dest="hosts_file",
            help="File containing IP addresses or CIDR ranges of target machines (supports comments with #)",
        )
        parser.add_argument(
            "--host",
            action="store",
            help="Specific machine or CIDR range to target (e.g., 10.0.0.0/24)",
        )

        nemesis = parser.add_argument_group("nemesis integration")
        nemesis.add_argument(
            "--nemesis-url",
            action="store",
            dest="nemesis_url",
            default=os.getenv("NEMESIS_URL"),
            help="Nemesis API URL (e.g., https://nemesis:7443/api)",
        )
        nemesis.add_argument(
            "--nemesis-auth",
            action="store",
            dest="nemesis_auth",
            default=os.getenv("NEMESIS_AUTH"),
            help="Nemesis authentication in username:password format (e.g., n:n)",
        )
        nemesis.add_argument(
            "--nemesis-project",
            action="store",
            dest="nemesis_project",
            default=os.getenv("NEMESIS_PROJECT"),
            help="Project name for Nemesis file submissions",
        )
        nemesis.add_argument(
            "--nemesis-ingest",
            action="store_true",
            dest="nemesis_ingest",
            help="Enable file submission to Nemesis for downloaded files",
        )

        group = parser.add_argument_group("authentication")
        group.add_argument(
            "-H",
            "--hashes",
            action="store",
            metavar="LMHASH:NTHASH",
            help="NTLM hashes, format is NTHASH:LMHASH",
        )
        group.add_argument(
            "-no-pass",
            action="store_true",
            help="Don't ask for password (useful for -k)",
        )
        group.add_argument(
            "-k",
            action="store_true",
            help="Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line",
        )
        group.add_argument(
            "-aesKey",
            action="store",
            metavar="hex key",
            help="AES key to use for Kerberos Authentication (128 or 256 bits)",
        )

        spider = parser.add_argument_group("spider")
        spider.add_argument(
            "--spider", action="store_true", help="Spider all shares found"
        )
        # Download files
        # If you specify nothing, it will download everything
        spider.add_argument(
            "--download-ext",
            action="store",
            dest="download_ext",
            nargs="?",
            const=" ",
            help="Download files. Specify nothing, it will download everything."
            "You can specify specific extensions limited by a ','."
            "You can also specify '--download default' for shrawler to choose the extensions for you.",
        )
        spider.add_argument(
            "--download-name",
            action="store",
            dest="download_name",
            help="Download files if their name contains any of these comma-separated substrings",
        )
        spider.add_argument(
            "--max-depth",
            action="store",
            dest="max_depth",
            type=int,
            default=5,
            help="Max depth of spidering. Default: 5",
        )
        spider.add_argument(
            "--delay",
            action="store",
            dest="delay",
            type=float,
            default=0,
            help="Seconds to wait between file/directory request. Default: 0",
        )
        spider.add_argument(
            "--count-ext",
            action="store",
            dest="count_ext",
            nargs="?",
            const="default",
            help="Count files by extension. Specify nothing for default extensions, "
            "or provide comma-separated extensions (e.g., '.txt,.log,.sh')",
        )
        spider.add_argument(
            "--count-string",
            action="store",
            dest="count_string",
            help="Count files containing specific strings in their names. Provide comma-separated strings "
            "(e.g., 'backup,config,password')",
        )
        spider.add_argument(
            "--unique",
            action="store_true",
            dest="unique",
            help="Identify and display files with unique modification times",
        )
        spider.add_argument(
            "--content-search",
            action="store",
            dest="content_search",
            nargs="?",
            const="default",
            help="Search file contents for sensitive patterns. Use 'default' for built-in patterns, "
            "or provide comma-separated regex patterns (e.g., 'password,api_key,secret')",
        )
        spider.add_argument(
            "--content-search-file",
            action="store",
            dest="content_search_file",
            help="File containing regex patterns for content search, one per line (supports # comments)",
        )
        spider.add_argument(
            "--content-search-max-size",
            action="store",
            dest="content_search_max_size",
            type=int,
            default=5242880,
            help="Maximum file size in bytes to scan for content (default: 5242880 / 5MB)",
        )
        spider.add_argument(
            "--csv-output",
            action="store_true",
            dest="csv_output",
            help="Output results in CSV format (generates shrawler_shares.csv, shrawler_files.csv, shrawler_downloads.csv)",
        )
        spider.add_argument(
            "--json-output",
            action="store_true",
            dest="json_output",
            help="Output results in JSON format (generates shrawler_results.json)",
        )

        self.args = parser.parse_args()

        self.download_count = 0
        self.files_seen_count = 0

        # Initialize file counting data structures
        self.file_counts: Dict[str, int] = {}
        self.count_extensions_list: List[str] = []
        self.count_strings_list: List[str] = []

        # Initialize unique file timestamp data collection
        self.unique_files_data: List[Tuple[str, float]] = []

        # Initialize scan results for consolidated JSON output
        self.scan_results: Dict[str, Any] = {}

        # Track the currently processed host for download operations
        self.current_host = None

        # CSV output data structures
        self.share_rows: List[Dict[str, Any]] = []
        self.file_rows: List[Dict[str, Any]] = []
        self.download_rows: List[Dict[str, Any]] = []
        self.csv_enabled = False
        self.json_enabled = False

        # Content search data structures
        self.content_search_patterns: List[Tuple[str, re.Pattern]] = []
        self.content_matches: List[Dict[str, Any]] = []
        self.content_match_rows: List[Dict[str, Any]] = []

        # Default sensitive content patterns for pentesting
        self.default_content_patterns = [
            ("Password in config", r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+"),
            ("API Key", r"(?i)(api[_-]?key|apikey)\s*[=:]\s*\S+"),
            ("Secret/Token", r"(?i)(secret|token|auth[_-]?token)\s*[=:]\s*\S+"),
            (
                "Connection String",
                r"(?i)(connection[_-]?string|connstr|data\s*source|server=.*database=)",
            ),
            ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
            (
                "Private Key Header",
                r"-----BEGIN\s+(RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
            ),
            ("Credentials in URL", r"(?i)https?://[^:]+:[^@]+@"),
            (
                "Database Credentials",
                r"(?i)(db[_-]?(user|pass|host|name|password))\s*[=:]\s*\S+",
            ),
            ("NTLM Hash", r"[a-fA-F0-9]{32}:[a-fA-F0-9]{32}"),
            ("Net-NTLMv2 Hash", r"(?i)\w+::\w+:[a-fA-F0-9]+:[a-fA-F0-9]+:[a-fA-F0-9]+"),
        ]

        # Process counting arguments
        self._process_count_arguments()
        self._process_content_search_arguments()

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

    def _process_content_search_arguments(self) -> None:
        """Process --content-search and --content-search-file arguments."""
        patterns_to_compile: List[Tuple[str, str]] = []

        # Process --content-search argument
        if self.args.content_search is not None:
            if self.args.content_search == "default":
                patterns_to_compile.extend(self.default_content_patterns)
            else:
                # User-provided comma-separated patterns
                user_patterns = [p.strip() for p in self.args.content_search.split(",")]
                for pattern in user_patterns:
                    if pattern:
                        patterns_to_compile.append((pattern, pattern))

        # Process --content-search-file argument
        if self.args.content_search_file is not None:
            try:
                with open(self.args.content_search_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            patterns_to_compile.append((line, line))
            except FileNotFoundError:
                logging.error(
                    f"Content search pattern file not found: {self.args.content_search_file}"
                )
            except Exception as e:
                logging.error(f"Error reading content search pattern file: {e}")

        # Compile all patterns
        for label, pattern_str in patterns_to_compile:
            try:
                compiled = re.compile(pattern_str)
                self.content_search_patterns.append((label, compiled))
            except re.error as e:
                logging.error(f"Invalid regex pattern '{pattern_str}': {e}")

    def _count_file(self, filename: str) -> None:
        """Count a file based on extension and string criteria."""
        filename_lower = filename.lower()

        # Check extensions
        for ext in self.count_extensions_list:
            if filename_lower.endswith(ext):
                self.file_counts[ext] = self.file_counts.get(ext, 0) + 1

        # Check strings contained in a file name
        for string in self.count_strings_list:
            if string in filename_lower:
                self.file_counts[string] = self.file_counts.get(string, 0) + 1

    @staticmethod
    def _is_binary_file(data: bytes) -> bool:
        """Check if data appears to be binary by looking for null bytes.

        Args:
            data: Raw file bytes (checks first 8192 bytes)

        Returns:
            True if file appears to be binary, False if text-like
        """
        check_bytes = data[:8192]
        return b"\x00" in check_bytes

    def _scan_file_content(
        self,
        smbclient: Any,
        share: str,
        remote_path: str,
        file_size: int,
        host: str,
    ) -> List[Dict[str, Any]]:
        """Scan file contents in memory for sensitive patterns.

        Args:
            smbclient: The SMB client instance
            share: SMB share name
            remote_path: Full path to the remote file
            file_size: File size in bytes
            host: Target host IP

        Returns:
            List of match dictionaries with pattern info and matched lines
        """
        matches: List[Dict[str, Any]] = []

        # Skip files exceeding size limit
        if file_size > self.args.content_search_max_size:
            logging.debug(
                f"Skipping content scan (size {file_size} > {self.args.content_search_max_size}): {remote_path}"
            )
            return matches

        # Skip empty files
        if file_size == 0:
            return matches

        try:
            # Read file into memory
            buffer = io.BytesIO()
            smbclient.getFile(share, remote_path, buffer.write)
            data = buffer.getvalue()
            buffer.close()

            # Skip binary files
            if self._is_binary_file(data):
                logging.debug(f"Skipping binary file: {remote_path}")
                return matches

            # Decode content (UTF-8 with latin-1 fallback)
            try:
                content = data.decode("utf-8")
            except UnicodeDecodeError:
                content = data.decode("latin-1")

            # Search line by line
            for line_num, line in enumerate(content.splitlines(), 1):
                for label, pattern in self.content_search_patterns:
                    if pattern.search(line):
                        clean_remote_path = remote_path.lstrip("/").replace("/", "\\")
                        matches.append(
                            {
                                "host": host,
                                "share": share,
                                "remote_path": remote_path,
                                "unc_path": f"\\\\{host}\\{share}\\{clean_remote_path}",
                                "pattern_name": label,
                                "matched_line": line.strip()[:200],
                                "line_number": line_num,
                            }
                        )

        except SessionError as e:
            logging.debug(f"SMB error scanning {remote_path}: {e}")
        except Exception as e:
            logging.debug(f"Error scanning file content {remote_path}: {e}")

        return matches

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

        # Create table format
        table_width = max_type_width + count_width + 3  # 3 for separators
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

    def _display_content_search_summary(self) -> None:
        """Display summary of all content search matches."""
        if not self.content_matches:
            if self.content_search_patterns:
                print(f"\n{Fore.GREEN}[+] Content Search Summary{Style.RESET_ALL}\n")
                print(f"{Fore.GREEN}[+]{Style.RESET_ALL} No content matches found.")
            return

        print(
            f"\n{Fore.RED}[+] Content Search Matches ({len(self.content_matches)} match(es)){Style.RESET_ALL}\n"
        )

        # Calculate column widths
        max_host = max(len("Host"), max(len(m["host"]) for m in self.content_matches))
        max_share = max(
            len("Share"), max(len(m["share"]) for m in self.content_matches)
        )
        max_pattern = max(
            len("Pattern"),
            max(len(m["pattern_name"][:30]) for m in self.content_matches),
        )
        max_path = max(
            len("File Path"),
            max(len(m["remote_path"][:60]) for m in self.content_matches),
        )

        border = (
            "+"
            + "=" * (max_host + 2)
            + "+"
            + "=" * (max_share + 2)
            + "+"
            + "=" * (max_pattern + 2)
            + "+"
            + "=" * (max_path + 2)
            + "+"
        )
        separator = (
            "+"
            + "-" * (max_host + 2)
            + "+"
            + "-" * (max_share + 2)
            + "+"
            + "-" * (max_pattern + 2)
            + "+"
            + "-" * (max_path + 2)
            + "+"
        )

        # Header
        print(border)
        print(
            f"| {'Host'.ljust(max_host)} "
            f"| {'Share'.ljust(max_share)} "
            f"| {'Pattern'.ljust(max_pattern)} "
            f"| {'File Path'.ljust(max_path)} |"
        )
        print(border)

        # Rows
        for match in self.content_matches:
            print(
                f"| {match['host'].ljust(max_host)} "
                f"| {match['share'].ljust(max_share)} "
                f"| {match['pattern_name'][:30].ljust(max_pattern)} "
                f"| {match['remote_path'][:60].ljust(max_path)} |"
            )
            # Show matched line preview
            matched_preview = match["matched_line"][:120]
            print(
                f"| {''.ljust(max_host)} "
                f"| {''.ljust(max_share)} "
                f"| {''.ljust(max_pattern)} "
                f"| {Fore.YELLOW}→ {matched_preview}{Style.RESET_ALL}{''.ljust(max(0, max_path - len(matched_preview) - 2))} |"
            )
            print(separator)

        # Count unique files
        unique_files = set(
            (m["host"], m["share"], m["remote_path"]) for m in self.content_matches
        )
        print(
            f"\n{Fore.RED}[+]{Style.RESET_ALL} "
            f"Total: {len(self.content_matches)} match(es) across {len(unique_files)} file(s)"
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
            except (socket.timeout, socket.error, OSError) as e:
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
            tuple[bool, bool]: (download_success, nemesis_upload_success)
        """
        try:
            # Create loot directory if it doesn't exist
            loot_dir = "downloads"
            if not os.path.exists(loot_dir):
                os.makedirs(loot_dir)

            local_path = os.path.join(loot_dir, local_filename)

            # Download the file using impacket's getFile method
            with open(local_path, "wb") as local_file:
                smbclient.getFile(share, remote_path, local_file.write)

            # Populate manifest data on successful download
            file_entry: Dict[str, Any] = {
                "timestamp": datetime.now().isoformat(),
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "host": host,
                "share": share,
                "remote_path": remote_path,
                "unc_path": f"\\\\{host}\\{share}\\{remote_path.lstrip('/')}",
                "local_filename": local_filename,
                "size_bytes": file_size,
                "mtime_epoch": mtime_epoch,
                "mtime_utc": datetime.fromtimestamp(
                    mtime_epoch, timezone.utc
                ).isoformat(),
                "origin_tool": "shrawler",
            }

            # Submit to Nemesis if enabled (only for successfully downloaded files)
            nemesis_success = False
            if self.args.nemesis_ingest:
                clean_remote_path = remote_path.lstrip("/").replace("/", "\\")
                unc_path = f"\\\\{host}\\{share}\\{clean_remote_path}"
                nemesis_result = self.submit_to_nemesis(
                    local_path, unc_path, mtime_epoch
                )
                nemesis_success = nemesis_result["success"]

            # Collect data for CSV output
            if self.args.csv_output:
                clean_remote_path = remote_path.lstrip("/").replace("/", "\\")
                unc_path = f"\\\\{host}\\{share}\\{clean_remote_path}"

                self.download_rows.append(
                    {
                        "host": host,
                        "share_name": share,
                        "remote_path": remote_path,
                        "unc_path": unc_path,
                        "local_filename": local_filename,
                        "size_bytes": file_size,
                        "mtime_utc": file_entry["mtime_utc"],
                        "timestamp_utc": file_entry["timestamp_utc"],
                    }
                )

            # Add to scan results (within the appropriate share's downloaded_files list)
            self.scan_results[host]["shares"][share]["downloaded_files"].append(
                file_entry
            )

            # Increment counter on success
            self.download_count += 1

            return (True, nemesis_success)

        except Exception as e:
            logging.warning(f"Failed to download {remote_path}: {str(e)}")
            return (False, False)

    def submit_to_nemesis(
        self, local_file_path: str, unc_path: str, file_mtime_epoch: float
    ) -> Dict[str, Any]:
        """Submit downloaded file to Nemesis API using multipart form data.

        Returns:
            dict: Upload status with 'success' (bool), 'timestamp' (str), and optional 'response_id' (str)
        """
        upload_result = {
            "success": False,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "response_id": None,
        }

        if not self.args.nemesis_ingest:
            return upload_result

        if (
            not self.args.nemesis_url
            or not self.args.nemesis_auth
            or not self.args.nemesis_project
        ):
            logging.warning("Nemesis URL, auth, and project required for ingestion")
            return upload_result

        if not os.path.exists(local_file_path):
            logging.warning(
                f"Local file not found for Nemesis submission: {local_file_path}"
            )
            return upload_result

        try:
            # Parse authentication
            if ":" not in self.args.nemesis_auth:
                logging.warning("Nemesis auth must be in username:password format")
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
                "project": self.args.nemesis_project,
                "timestamp": current_time.isoformat(),
                "expiration": expiration_time.isoformat(),
                "path": unc_path,
            }

            # Prepare multipart form data
            with open(local_file_path, "rb") as file_data:
                files = {
                    "file": (
                        os.path.basename(local_file_path),
                        file_data,
                        "application/octet-stream",
                    )
                }
                data = {"metadata": json.dumps(metadata)}

                # Submit with basic auth and SSL verification disabled (like curl -k)
                response = requests.post(
                    endpoint,
                    files=files,
                    data=data,
                    auth=(username, password),
                    verify=False,
                    timeout=30,
                )

                if response.status_code not in [200, 201]:
                    logging.warning(
                        f"Failed to submit file to Nemesis: {unc_path} (HTTP {response.status_code})"
                    )
                else:
                    logging.debug(f"Successfully submitted file to Nemesis: {unc_path}")
                    upload_result["success"] = True

                    # Try to extract response ID if present
                    try:
                        response_data = response.json()
                        if "id" in response_data:
                            upload_result["response_id"] = response_data["id"]
                    except (json.JSONDecodeError, KeyError) as e:
                        logging.debug(
                            f"Failed to parse Nemesis response for {unc_path}: {e}"
                        )

        except (
            requests.exceptions.RequestException,
            requests.exceptions.Timeout,
            requests.exceptions.ConnectionError,
            FileNotFoundError,
        ) as e:
            logging.debug(f"Nemesis submission error for {unc_path}: {str(e)}")
        except Exception as e:
            logging.debug(
                f"Unexpected error in Nemesis submission for {unc_path}: {str(e)}"
            )

        return upload_result

    def write_csv_outputs(self) -> List[str]:
        """Write CSV output files conditionally based on data presence.

        Returns:
            List of CSV filenames that were actually written
        """
        import csv

        csv_files_written = []

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
            with open("shrawler_shares.csv", "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=shares_fieldnames)
                writer.writeheader()
                writer.writerows(self.share_rows)
            csv_files_written.append("shrawler_shares.csv")

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
            with open("shrawler_files.csv", "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=files_fieldnames)
                writer.writeheader()
                writer.writerows(self.file_rows)
            csv_files_written.append("shrawler_files.csv")

        # Write downloads CSV (only if download data exists - requires download criteria)
        if self.download_rows:
            downloads_fieldnames = [
                "host",
                "share_name",
                "remote_path",
                "unc_path",
                "local_filename",
                "size_bytes",
                "mtime_utc",
                "timestamp_utc",
            ]
            with open("shrawler_downloads.csv", "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=downloads_fieldnames)
                writer.writeheader()
                writer.writerows(self.download_rows)
            csv_files_written.append("shrawler_downloads.csv")

        # Write content matches CSV (only if content match data exists)
        if self.content_match_rows:
            content_fieldnames = [
                "host",
                "share_name",
                "remote_path",
                "unc_path",
                "pattern_name",
                "matched_line",
                "line_number",
                "timestamp_utc",
            ]
            with open("shrawler_content_matches.csv", "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=content_fieldnames)
                writer.writeheader()
                writer.writerows(self.content_match_rows)
            csv_files_written.append("shrawler_content_matches.csv")

        return csv_files_written

    def get_shares(
        self,
        target: str,
        mach_name: str,
        smbclient: Any,
        default_shares: List[str],
        spider: bool = False,
        desired_share: str = "",
    ) -> None:
        shares = smbclient.listShares()

        largest_share_name = len(max(shares, key=len))

        # Assuming shares is a list of share dictionaries
        share_names = [share["shi1_netname"][:-1] for share in shares]

        # only print desired share
        if desired_share:
            desired_share_list = desired_share.split(",")
            default_shares = share_names
            for share in desired_share_list:
                default_shares.remove(share)

        if default_shares not in share_names:
            for share in shares:
                # last char can be a hex value
                # This grabs the sharename without the last character
                # impacket naming scheme
                share_name = share["shi1_netname"][:-1]
                share_comment = share["shi1_remark"][:-1]
                if share_name not in default_shares:
                    try:
                        share_perms = self.check_share_perm(share_name, smbclient)

                        # Initialize host entry in scan_results if it doesn't exist
                        if target not in self.scan_results:
                            self.scan_results[target] = {
                                "scan_timestamp_utc": datetime.now(
                                    timezone.utc
                                ).isoformat(),
                                "shares": {},
                            }

                        # Add share information to scan_results
                        self.scan_results[target]["shares"][share_name] = {
                            "comment": share_comment,
                            "permissions": share_perms,
                            "unc_path": f"\\\\{target}\\{share_name}",
                            "downloaded_files": [],
                        }

                        # Collect data for CSV output
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

                        # If you're spidering you don't need to print out share perms
                        # Assumes you're doing this in separate steps - will still print out what it finds though
                        if spider and share_perms["read"]:
                            print("")
                            logging.info(f"{mach_name}\\{share_name}")
                            self.print_table_header()
                            self.spider_shares(target, share_name, "/", smbclient)

                        # If you're not spidering, will print out
                        else:
                            print_share_info(
                                share_name,
                                share_comment,
                                share_perms,
                                largest_share_name,
                            )

                    except KeyboardInterrupt:
                        input("\nPress enter to continue")
                        continue
        else:
            logging.warning("No desired shares found")

    def check_share_perm(
        self, share: str, smbclient: Any
    ) -> Dict[str, Union[str, bool]]:
        read_write = {"read": False, "write": "N/A"}

        # check for read rights
        try:
            smbclient.listPath(share, "*", password=None)
            read_write["read"] = True
        except SessionError:
            read_write["read"] = False

        # check for write rights
        if not self.args.read_only:
            try:
                # pretty much all tools that crawl shares have to attempt to write to disk.
                # If it does not allow, you've got your write perms
                # Downside, its possible to allow write but not delete perms.
                # In this case, I like to specify the folder name incase this happens - you can let clients know
                directory = "pentest_temp_dir"
                smbclient.createDirectory(share, directory)
                smbclient.deleteDirectory(share, directory)
                read_write["write"] = True
            except SessionError as e:
                logging.debug(f"Full error: {e}")
                read_write["write"] = False
        return read_write

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

        # Format directory in table format
        size = "-"
        mtime = self.readable_time_short(directory_result.get_mtime_epoch())

        # Build the proper tree structure for directories
        connector = "└── " if last else "├── "
        name = indent + connector + f"{Fore.BLUE}{directory}/{Style.RESET_ALL}"

        print(self.format_table_row(size, mtime, name))

        # Update the indent for the next depth level
        next_indent = indent + ("    " if last else "│   ")

        try:
            results = smbclient.listPath(
                share, base_dir + directory + "/*", password=None
            )

            # Filter out '.' and '..' and separate directories from files
            directories: List[Any] = []
            files: List[Any] = []
            for result in results:
                if result.get_longname() not in [".", ".."]:
                    if result.is_directory():
                        directories.append(result)
                    else:
                        files.append(result)

            total_items = len(directories) + len(files)
            count = 0

            # depth has an index of 0, max_depth assumes human readable
            if depth < self.args.max_depth - 1:
                # Process directories first
                for result in directories:
                    # throttling
                    if self.args.delay > 0:
                        time.sleep(self.args.delay)

                    next_filedir = result.get_longname()
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
                    for i, (file_result, file_mtime_epoch) in enumerate(
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
        self.files_seen_count += 1
        next_filedir = file_result.get_longname()

        # Compute remote_file_path once (needed for downloads and content scanning)
        remote_file_path = base_dir + directory + "/" + next_filedir

        # Count the file based on counting criteria
        if self.count_extensions_list or self.count_strings_list:
            self._count_file(next_filedir)

        # Collect data for global unique timestamp analysis if enabled
        if self.args.unique:
            file_mtime_epoch = file_result.get_mtime_epoch()
            self.unique_files_data.append((remote_file_path, file_mtime_epoch))

        # Collect data for CSV output
        if self.csv_enabled:
            file_mtime_utc = datetime.fromtimestamp(
                file_result.get_mtime_epoch(), timezone.utc
            ).isoformat()

            self.file_rows.append(
                {
                    "host": self.current_host,
                    "share_name": share,
                    "remote_path": remote_file_path,
                    "unc_path": f"\\\\{self.current_host}\\{share}\\{remote_file_path.lstrip('/')}",
                    "file_name": next_filedir,
                    "size_bytes": file_result.get_filesize(),
                    "readable_size": self.readable_file_size(
                        file_result.get_filesize()
                    ),
                    "mtime_utc": file_mtime_utc,
                    "is_directory": False,
                    "can_read": None,
                    "can_write": None,
                    "scan_timestamp_utc": datetime.now(timezone.utc).isoformat(),
                }
            )

        # Print file with the correct connector and indentation
        file_connector = "└── " if is_last else "├── "
        download_status = ""
        unique_status = f" {Fore.MAGENTA}[UNIQUE]{Style.RESET_ALL}" if is_unique else ""

        # Initialize download flags
        download_by_extension = False
        download_by_name = False

        # Cache filename once
        filename_lower = next_filedir.lower()

        # Check extension-based download criteria
        if self.args.download_ext is not None:  # --download was used
            if (
                self.args.download_ext.strip() == ""
            ):  # --download with no args (const=" ")
                download_by_extension = True
            elif self.args.download_ext == "default":  # --download default
                # Use self.extensions for default behavior
                for ext in self.extensions:
                    ext_lower = ext.lower()
                    if not ext_lower.startswith("."):
                        ext_lower = "." + ext_lower
                    if filename_lower.endswith(ext_lower):
                        download_by_extension = True
                        break
            else:  # --download with specific extensions
                extensions = [ext.strip() for ext in self.args.download_ext.split(",")]

                for ext in extensions:
                    ext = ext.strip().lower()
                    if not ext.startswith("."):
                        ext = "." + ext
                    if filename_lower.endswith(ext):
                        download_by_extension = True
                        break

        # Check name-based download criteria
        if self.args.download_name is not None:
            search_terms = [
                term.strip().lower() for term in self.args.download_name.split(",")
            ]
            for term in search_terms:
                if term in filename_lower:
                    download_by_name = True
                    break

        # Final download decision
        should_download = download_by_extension or download_by_name

        # Download the file if criteria met
        if should_download:
            # Create local filename with double underscore delimiters and sanitization
            sanitized_path = sanitize_filename(
                remote_file_path.replace("/", "_").lstrip("_")
            )
            local_filename = f"{self.current_host}__{share}__{sanitized_path}"

            download_success, nemesis_success = self.download_file(
                smbclient,
                share,
                remote_file_path,
                local_filename,
                self.current_host,
                file_result.get_filesize(),
                file_result.get_mtime_epoch(),
            )

            # Build download status with both download and Nemesis upload results
            if download_success:
                download_status = f" {Fore.CYAN}[DOWNLOADED]{Style.RESET_ALL}"
                if self.args.nemesis_ingest and nemesis_success:
                    download_status += (
                        f" {Fore.MAGENTA}[UPLOADED TO NEMESIS]{Style.RESET_ALL}"
                    )
                elif self.args.nemesis_ingest and not nemesis_success:
                    download_status += f" {Fore.RED}[NEMESIS FAILED]{Style.RESET_ALL}"
            else:
                download_status = f" {Fore.RED}[DOWNLOAD FAILED]{Style.RESET_ALL}"

        # Content scanning (independent of download criteria)
        content_match_status = ""
        if self.content_search_patterns:
            content_matches = self._scan_file_content(
                smbclient,
                share,
                remote_file_path,
                file_result.get_filesize(),
                self.current_host,
            )
            if content_matches:
                self.content_matches.extend(content_matches)

                # Build inline status
                pattern_names = list(
                    dict.fromkeys(m["pattern_name"] for m in content_matches)
                )
                match_label = ", ".join(pattern_names[:2])
                if len(pattern_names) > 2:
                    match_label += f" +{len(pattern_names) - 2} more"
                content_match_status = (
                    f" {Fore.RED}[MATCH: {match_label}]{Style.RESET_ALL}"
                )

                # Add to JSON scan results
                if self.json_enabled and self.current_host in self.scan_results:
                    if "content_matches" not in self.scan_results[self.current_host][
                        "shares"
                    ].get(share, {}):
                        self.scan_results[self.current_host]["shares"][share][
                            "content_matches"
                        ] = []
                    self.scan_results[self.current_host]["shares"][share][
                        "content_matches"
                    ].extend(content_matches)

                # Collect for CSV output
                if self.csv_enabled:
                    for match in content_matches:
                        self.content_match_rows.append(
                            {
                                "host": match["host"],
                                "share_name": match["share"],
                                "remote_path": match["remote_path"],
                                "unc_path": match["unc_path"],
                                "pattern_name": match["pattern_name"],
                                "matched_line": match["matched_line"],
                                "line_number": match["line_number"],
                                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                            }
                        )

                # Auto-download if not already downloaded
                if not should_download:
                    sanitized_path = sanitize_filename(
                        remote_file_path.replace("/", "_").lstrip("_")
                    )
                    local_filename = f"{self.current_host}__{share}__{sanitized_path}"

                    download_success, nemesis_success = self.download_file(
                        smbclient,
                        share,
                        remote_file_path,
                        local_filename,
                        self.current_host,
                        file_result.get_filesize(),
                        file_result.get_mtime_epoch(),
                    )
                    if download_success:
                        download_status = f" {Fore.CYAN}[DOWNLOADED]{Style.RESET_ALL}"
                        if self.args.nemesis_ingest and nemesis_success:
                            download_status += (
                                f" {Fore.MAGENTA}[UPLOADED TO NEMESIS]{Style.RESET_ALL}"
                            )
                        elif self.args.nemesis_ingest and not nemesis_success:
                            download_status += (
                                f" {Fore.RED}[NEMESIS FAILED]{Style.RESET_ALL}"
                            )
                    else:
                        download_status = (
                            f" {Fore.RED}[DOWNLOAD FAILED]{Style.RESET_ALL}"
                        )

        # Always print the file in table format
        file_metadata = self.parse_file(file_result)
        size = file_metadata["size"]
        mtime = self.readable_time_short(file_result.get_mtime_epoch())

        # Build name with tree structure and download/unique status
        file_connector = "└── " if is_last else "├── "
        name = indent + file_connector + f"{Fore.GREEN}{next_filedir}{Style.RESET_ALL}"
        if unique_status:
            name += unique_status
        if download_status:
            name += download_status
        if content_match_status:
            name += content_match_status

        print(self.format_table_row(size, mtime, name))

    def spider_shares(
        self, target: str, share: str, base_dir: str, smbclient: Any
    ) -> None:
        directories: List[Any] = []
        files: List[Any] = []
        try:
            # List all items in the base directory
            results = list(smbclient.listPath(share, base_dir + "*", password=None))

            # Separate directories and files
            for result in results:
                if result.get_longname() not in [".", ".."]:
                    if result.is_directory():
                        directories.append(result)
                    else:
                        files.append(result)

            # Calculate total items for proper tree formatting
            total_items = len(directories) + len(files)
            current_item = 0

            # Process directories first
            for directory in directories:
                current_item += 1
                is_last = current_item == total_items

                next_filedir = directory.get_longname()

                # Format directory in table format with tree characters
                size = "-"
                mtime = self.readable_time_short(directory.get_mtime_epoch())
                connector = "└── " if is_last else "├── "
                name = connector + f"{Fore.BLUE}{next_filedir}/{Style.RESET_ALL}"

                # print(self.format_table_row(size, mtime, name))

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
                for i, (file_result, file_mtime_epoch) in enumerate(files_with_mtime):
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
        self.files_seen_count += 1

        # Compute remote_file_path once (needed for downloads and content scanning)
        remote_file_path = base_dir + file_result.get_longname()

        # Count the file based on counting criteria
        if self.count_extensions_list or self.count_strings_list:
            self._count_file(file_result.get_longname())

        # Collect data for global unique timestamp analysis if enabled
        if self.args.unique:
            file_mtime_epoch = file_result.get_mtime_epoch()
            self.unique_files_data.append((remote_file_path, file_mtime_epoch))

        # Collect data for CSV output
        if self.csv_enabled:
            file_mtime_utc = datetime.fromtimestamp(
                file_result.get_mtime_epoch(), timezone.utc
            ).isoformat()

            self.file_rows.append(
                {
                    "host": self.current_host,
                    "share_name": share,
                    "remote_path": remote_file_path,
                    "unc_path": f"\\\\{self.current_host}\\{share}\\{remote_file_path.lstrip('/')}",
                    "file_name": file_result.get_longname(),
                    "size_bytes": file_result.get_filesize(),
                    "readable_size": self.readable_file_size(
                        file_result.get_filesize()
                    ),
                    "mtime_utc": file_mtime_utc,
                    "is_directory": False,
                    "can_read": None,
                    "can_write": None,
                    "scan_timestamp_utc": datetime.now(timezone.utc).isoformat(),
                }
            )

        connector = "└── " if is_last else "├── "
        download_status = ""
        unique_status = (
            f" {Fore.MAGENTA}[POTENTIAL UNIQUE FILE]{Style.RESET_ALL}"
            if is_unique
            else ""
        )

        # Initialize download flags
        download_by_extension = False
        download_by_name = False

        # Cache filename once
        filename_lower = file_result.get_longname().lower()

        # Check extension-based download criteria
        if self.args.download_ext is not None:  # --download was used
            if self.args.download_ext.strip() == "":  # --download with no args
                download_by_extension = True
            elif self.args.download_ext == "default":  # --download default
                # Use self.extensions for default behavior
                for ext in self.extensions:
                    ext_lower = ext.lower()
                    if not ext_lower.startswith("."):
                        ext_lower = "." + ext_lower
                    if filename_lower.endswith(ext_lower):
                        download_by_extension = True
                        break
            else:  # --download with specific extensions
                extensions = [ext.strip() for ext in self.args.download_ext.split(",")]

                for ext in extensions:
                    ext = ext.strip().lower()
                    if not ext.startswith("."):
                        ext = "." + ext
                    if filename_lower.endswith(ext):
                        download_by_extension = True
                        break

        # Check name-based download criteria
        if self.args.download_name is not None:
            search_terms = [
                term.strip().lower() for term in self.args.download_name.split(",")
            ]
            for term in search_terms:
                if term in filename_lower:
                    download_by_name = True
                    break

        # Final download decision
        should_download = download_by_extension or download_by_name

        # Download the file if criteria met
        if should_download:
            # Create local filename with double underscore delimiters and sanitization
            sanitized_path = sanitize_filename(
                remote_file_path.replace("/", "_").lstrip("_")
            )
            local_filename = f"{self.current_host}__{share}__{sanitized_path}"

            download_success, nemesis_success = self.download_file(
                smbclient,
                share,
                remote_file_path,
                local_filename,
                self.current_host,
                file_result.get_filesize(),
                file_result.get_mtime_epoch(),
            )

            # Build download status with both download and Nemesis upload results
            if download_success:
                download_status = f" {Fore.CYAN}[DOWNLOADED]{Style.RESET_ALL}"
                if self.args.nemesis_ingest and nemesis_success:
                    download_status += (
                        f" {Fore.MAGENTA}[UPLOADED TO NEMESIS]{Style.RESET_ALL}"
                    )
                elif self.args.nemesis_ingest and not nemesis_success:
                    download_status += f" {Fore.RED}[NEMESIS FAILED]{Style.RESET_ALL}"
            else:
                download_status = f" {Fore.RED}[DOWNLOAD FAILED]{Style.RESET_ALL}"

        # Content scanning (independent of download criteria)
        content_match_status = ""
        if self.content_search_patterns:
            content_matches = self._scan_file_content(
                smbclient,
                share,
                remote_file_path,
                file_result.get_filesize(),
                self.current_host,
            )
            if content_matches:
                self.content_matches.extend(content_matches)

                # Build inline status
                pattern_names = list(
                    dict.fromkeys(m["pattern_name"] for m in content_matches)
                )
                match_label = ", ".join(pattern_names[:2])
                if len(pattern_names) > 2:
                    match_label += f" +{len(pattern_names) - 2} more"
                content_match_status = (
                    f" {Fore.RED}[MATCH: {match_label}]{Style.RESET_ALL}"
                )

                # Add to JSON scan results
                if self.json_enabled and self.current_host in self.scan_results:
                    if "content_matches" not in self.scan_results[self.current_host][
                        "shares"
                    ].get(share, {}):
                        self.scan_results[self.current_host]["shares"][share][
                            "content_matches"
                        ] = []
                    self.scan_results[self.current_host]["shares"][share][
                        "content_matches"
                    ].extend(content_matches)

                # Collect for CSV output
                if self.csv_enabled:
                    for match in content_matches:
                        self.content_match_rows.append(
                            {
                                "host": match["host"],
                                "share_name": match["share"],
                                "remote_path": match["remote_path"],
                                "unc_path": match["unc_path"],
                                "pattern_name": match["pattern_name"],
                                "matched_line": match["matched_line"],
                                "line_number": match["line_number"],
                                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                            }
                        )

                # Auto-download if not already downloaded
                if not should_download:
                    sanitized_path = sanitize_filename(
                        remote_file_path.replace("/", "_").lstrip("_")
                    )
                    local_filename = f"{self.current_host}__{share}__{sanitized_path}"

                    download_success, nemesis_success = self.download_file(
                        smbclient,
                        share,
                        remote_file_path,
                        local_filename,
                        self.current_host,
                        file_result.get_filesize(),
                        file_result.get_mtime_epoch(),
                    )
                    if download_success:
                        download_status = f" {Fore.CYAN}[DOWNLOADED]{Style.RESET_ALL}"
                        if self.args.nemesis_ingest and nemesis_success:
                            download_status += (
                                f" {Fore.MAGENTA}[UPLOADED TO NEMESIS]{Style.RESET_ALL}"
                            )
                        elif self.args.nemesis_ingest and not nemesis_success:
                            download_status += (
                                f" {Fore.RED}[NEMESIS FAILED]{Style.RESET_ALL}"
                            )
                    else:
                        download_status = (
                            f" {Fore.RED}[DOWNLOAD FAILED]{Style.RESET_ALL}"
                        )

        # Format file in table format
        file_metadata = self.parse_file(file_result)
        size = file_metadata["size"]
        mtime = self.readable_time_short(file_result.get_mtime_epoch())

        # Build name with tree structure and status
        connector = "└── " if is_last else "├── "
        name = connector + f"{Fore.GREEN}{file_result.get_longname()}{Style.RESET_ALL}"
        if unique_status:
            name += unique_status
        if download_status:
            name += download_status
        if content_match_status:
            name += content_match_status

        print(self.format_table_row(size, mtime, name))

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
        try:
            smbClient = SMBConnection(address, address, sess_port=int(445))
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
            logging.warning(f"Invalid login attempt on '{address}'\n")
            logging.debug(f"Full error: {e}")
            print(error(""))
            return None

        logging.info(f"Connected to {address}")
        return smbClient

    def expand_hosts(self, raw_hosts: List[str]) -> List[str]:
        """
        Expand host entries including CIDR notation into individual IP addresses.

        Args:
            raw_hosts: List of raw host strings (IPs, CIDR ranges, or hostnames)

        Returns:
            List of unique individual host addresses

        Features:
            - Expands CIDR notation (e.g., 192.168.1.0/24) into individual hosts
            - Excludes network and broadcast addresses for CIDR ranges
            - Strips whitespace and skips empty lines
            - Supports comments (lines starting with #)
            - Deduplicates hosts while preserving order
            - Gracefully handles invalid CIDR notation with warnings
        """
        expanded = []
        seen = set()
        cidr_count = 0
        total_expanded = 0

        for entry in raw_hosts:
            # Strip whitespace
            entry = entry.strip()

            # Skip empty lines and comments
            if not entry or entry.startswith("#"):
                continue

            # Check if this is CIDR notation
            if "/" in entry:
                cidr_count += 1
                try:
                    # Parse as IP network (strict=False allows host bits to be set)
                    network = ipaddress.ip_network(entry, strict=False)

                    # Expand to individual hosts (excludes network and broadcast)
                    # For /31 and /32, .hosts() returns appropriate hosts
                    for host in network.hosts():
                        host_str = str(host)
                        total_expanded += 1
                        if host_str not in seen:
                            seen.add(host_str)
                            expanded.append(host_str)

                    # Special case: /32 (single host) - .hosts() returns empty
                    # Use the network address itself
                    if network.num_addresses == 1:
                        host_str = str(network.network_address)
                        total_expanded += 1
                        if host_str not in seen:
                            seen.add(host_str)
                            expanded.append(host_str)

                except (
                    ValueError,
                    ipaddress.AddressValueError,
                    ipaddress.NetmaskValueError,
                ) as e:
                    logging.warning(f"Invalid CIDR notation '{entry}': {e}")
                    continue
            else:
                # Single IP or hostname - pass through as-is
                if entry not in seen:
                    seen.add(entry)
                    expanded.append(entry)

        # Log expansion summary
        if cidr_count > 0:
            logging.info(
                f"Expanded {cidr_count} CIDR range(s) into {total_expanded} host(s), "
                f"{len(expanded)} unique total"
            )

        return expanded

    def get_ip_addrs(self, file: str) -> List[str]:
        with open(file, "r") as f:
            lines = f.read().splitlines()

        return self.expand_hosts(lines)

    def main(self) -> None:
        # Logging
        logger = logging.getLogger()
        handler = logging.StreamHandler()
        handler.setFormatter(Formatter())

        logger.addHandler(handler)

        if self.verbose:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)

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
            lmhash, nthash = self.args.hashes.split(":")
        else:
            lmhash, nthash = "", ""

        if self.args.skip_share:
            shares = self.args.skip_share.split(",")
            for share in shares:
                self.normal_shares.append(share)

        if self.args.add_share:
            shares = self.args.add_share.split(",")
            for share in shares:
                self.normal_shares.remove(share)

        if self.args.hosts_file:
            machine_ip = self.get_ip_addrs(self.args.hosts_file)
            machine_names = machine_ip

        elif self.args.host:
            machine_ip = self.expand_hosts([self.args.host])
            machine_names = machine_ip

        else:
            logging.warning(
                "Please specify hosts file (--host) or specific host (--hosts) to check"
            )
            quit()

        # iterate through machine IPs and machines at the same time
        for mach_ip, mach_name in zip(machine_ip, machine_names):
            # Set the current host being processed for download operations
            self.current_host = mach_ip
            try:
                if self.check_port(mach_ip, 445):
                    # Start SMB session against the host in question
                    try:
                        smbclient = self.init_smb_session(
                            domain,
                            self.username,
                            self.password,
                            mach_ip,
                            lmhash,
                            nthash,
                        )

                        # get shares on host
                        self.get_shares(
                            mach_ip,
                            mach_name,
                            smbclient,
                            self.normal_shares,
                            self.args.spider,
                            self.args.shares,
                        )

                        # just for a new line
                        print("")

                        # This is used to separate hosts. Will print a colored line after each host.
                        print(success(""))
                    except Exception as e:
                        logging.debug(e)
                        continue
                else:
                    logging.warning(f"Port 445 not open on '{mach_ip}'")
                    print(error(""))
            except AttributeError as e:
                logging.debug(f"Full error: {e}")
                continue

            except KeyboardInterrupt:
                input("Press enter to continue...")
                continue

        print(success("Shrawler Scan Complete"))
        if self.args.spider:
            logging.info(f"Total files seen: {self.files_seen_count}")
        if self.args.download_ext is not None:
            logging.info(f"Total files downloaded: {self.download_count}")

        # Write CSV or JSON output if any data was collected
        if self.csv_enabled:
            files_written = self.write_csv_outputs()
            if files_written:
                logging.info(f"CSV files written: {', '.join(files_written)}")
            else:
                logging.info("No data to write to CSV files")
        elif self.json_enabled and self.scan_results:
            try:
                with open("shrawler_results.json", "w") as f:
                    json.dump(self.scan_results, f, indent=4)
                logging.info("Scan results written to shrawler_results.json")
            except Exception as e:
                logging.warning(f"Failed to write scan results file: {str(e)}")

        # Display file count summary if counting was enabled
        if self.count_extensions_list or self.count_strings_list:
            self._display_file_count_summary()

        # Display content search summary if content search was enabled
        if self.content_search_patterns:
            self._display_content_search_summary()

        # Display unique files summary if unique timestamp analysis was enabled
        # Only show this summary if NOT in spider mode
        if self.args.unique and self.unique_files_data and not self.args.spider:
            unique_results = find_unique_files_by_mtime(self.unique_files_data)
            display_unique_files(unique_results)


def main() -> None:
    """Calling shrawler."""
    s = Shrawler()
    try:
        s.main()
    except KeyboardInterrupt:
        print("\n\n" + error("User interrupted scan."))
        print(success("Summary of work done:"))
        if s.args.spider:
            logging.info(f"Total files seen: {s.files_seen_count}")
        if s.args.download_ext is not None:
            logging.info(f"Total files downloaded: {s.download_count}")

        # Display file count summary if counting was enabled
        if s.count_extensions_list or s.count_strings_list:
            s._display_file_count_summary()

        # Display content search summary if content search was enabled
        if s.content_search_patterns:
            s._display_content_search_summary()

        # Display unique files summary if unique timestamp analysis was enabled
        # Only show this summary if NOT in spider mode
        if s.args.unique and s.unique_files_data and not s.args.spider:
            unique_results = find_unique_files_by_mtime(s.unique_files_data)
            display_unique_files(unique_results)

        # Write CSV output before exiting
        if s.csv_enabled:
            files_written = s.write_csv_outputs()
            if files_written:
                logging.info(f"CSV files written: {', '.join(files_written)}")
            else:
                logging.info("No data to write to CSV files")

        quit()


if __name__ == "__main__":
    main()
