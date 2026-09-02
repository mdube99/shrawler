"""Canonical command-line parsing and operating-mode dispatch."""

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from impacket.examples.utils import parse_target

from .config import CONFIG_OPTIONS, DEFAULT_CONFIG, config_path, load_config
from .core import main as scan_main
from .report import main as report_main

SCAN_MODES = {"shares", "spider", "snaffle"}
PROFILES = ("quiet", "balanced", "fast")
POLICIES = ("audit", "collect", "aggressive")
FORMATS = ("console", "json", "csv", "all")
_SIZE_UNITS = {
    "": 1,
    "b": 1,
    "kb": 1000,
    "mb": 1000**2,
    "gb": 1000**3,
    "kib": 1024,
    "mib": 1024**2,
    "gib": 1024**3,
}
_LIMITS: Dict[str, Tuple[int, int]] = {
    "conservative": (10 * 1024**2, 250 * 1024**2),
    "standard": (50 * 1024**2, 2 * 1024**3),
    "unlimited": (0, 0),
}


def _parse_size(value: str) -> int:
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([kmgt]?i?b)?\s*", value.lower())
    if not match or match.group(2) not in _SIZE_UNITS:
        raise argparse.ArgumentTypeError(
            "use bytes or a size such as 20MB, 2GB, or 512MiB"
        )
    return int(float(match.group(1)) * _SIZE_UNITS[match.group(2)])


def _scan_parser(mode: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=f"shrawler {mode}")
    parser.add_argument("target", help="[[domain/]username[:password]@]<host>")
    targets = parser.add_argument_group("target selection")
    target_source = targets.add_mutually_exclusive_group()
    target_source.add_argument("--host", help="scan one explicit host")
    target_source.add_argument(
        "--hosts-file",
        help="file containing hosts, blank lines and # comments allowed",
    )
    auth = parser.add_argument_group("authentication")
    auth.add_argument("-H", "--hashes", metavar="LMHASH:NTHASH")
    auth.add_argument("-no-pass", action="store_true", default=None)
    auth.add_argument("-k", action="store_true", default=None)
    auth.add_argument("-aesKey", metavar="HEX_KEY")
    scan = parser.add_argument_group("scan behavior")
    scan.add_argument("--profile", "--scan-profile", dest="profile", choices=PROFILES)
    scan.add_argument("--policy", choices=POLICIES)
    scan.add_argument("-v", "--verbose", action="store_true", default=None)
    scan.add_argument(
        "--workers",
        type=int,
        help=(
            "concurrent hosts (shares within each host remain sequential; "
            "recursive tree views use one effective worker)"
        ),
    )
    scan.add_argument(
        "--permission-check",
        choices=("none", "read", "read-write"),
        help="permission assessment; read-write uses non-invasive server access checks",
    )
    scan.add_argument(
        "--file-write-check",
        action="store_true",
        default=None,
        help="create/delete verification; modifies the target and may leave artifacts",
    )
    scan.add_argument("--metrics", action="store_true", default=None)
    scan.add_argument("--read-only", action="store_true", default=None)
    shares = parser.add_argument_group("share selection")
    shares.add_argument("--share", action="append", metavar="NAME")
    shares.add_argument("--shares", help="comma-separated compatibility form")
    shares.add_argument(
        "--exclude-share",
        "--skip-share",
        dest="exclude_share",
        action="append",
        metavar="NAME",
    )
    shares.add_argument("--add-share", help="comma-separated shares normally skipped")
    output = parser.add_argument_group("output")
    output.add_argument("-o", "--output", "--output-dir", dest="output")
    output.add_argument("--format", choices=FORMATS)
    views = (
        ("summary", "progress", "tree")
        if mode == "shares"
        else ("summary", "progress", "matches", "tree")
    )
    output.add_argument(
        "--view",
        "--output-mode",
        dest="view",
        choices=views,
        help=(
            "terminal rendering; shares tree blocks are grouped by host in "
            "completion order, while recursive tree output is serialized"
        ),
    )
    output.add_argument("--resume", nargs="?", const=".")
    output.add_argument("--csv-output", action="store_true", default=None)
    output.add_argument("--json-output", action="store_true", default=None)
    if mode in {"spider", "snaffle"}:
        spider = parser.add_argument_group("downloads and content analysis")
        spider.add_argument(
            "--download", "--download-ext", dest="download", nargs="?", const=" "
        )
        spider.add_argument("--limits", choices=tuple(_LIMITS))
        spider.add_argument("--max-file-size", type=_parse_size)
        spider.add_argument(
            "--download-budget",
            "--max-total-download",
            dest="download_budget",
            type=_parse_size,
        )
        spider.add_argument("--download-name")
        spider.add_argument("--max-depth", type=int)
        spider.add_argument("--delay", type=float)
        spider.add_argument("--count-ext", nargs="?", const="default")
        spider.add_argument("--count-string")
        spider.add_argument("--unique", action="store_true", default=None)
        spider.add_argument("--max-content-reads", type=int)
        spider.add_argument("--content-read-budget", type=_parse_size)
        nemesis = parser.add_argument_group("Nemesis")
        nemesis.add_argument("--nemesis", "--nemesis-url", dest="nemesis_url")
        nemesis.add_argument("--nemesis-auth")
        nemesis.add_argument("--nemesis-project")
        nemesis.add_argument("--nemesis-mode", choices=("off", "matches", "downloads"))
        nemesis.add_argument("--nemesis-upload-workers", type=int)
        nemesis.add_argument("--nemesis-retries", type=int)
        nemesis.add_argument("--nemesis-queue-size", type=int)
    if mode == "snaffle":
        snaffle = parser.add_argument_group("Snaffler")
        snaffle.add_argument("--rules", "--snaffler-rules-dir", dest="rules")
        snaffle.add_argument(
            "--interest",
            "--snaffler-interest-level",
            dest="interest",
            type=int,
            choices=range(4),
        )
        snaffle.add_argument("--snaffler-max-size-to-grep", type=_parse_size)
        snaffle.add_argument("--snaffler-strict", action="store_true", default=None)
        snaffle.add_argument(
            "--snaffler-no-auto-download", action="store_true", default=None
        )
        snaffle.add_argument("--snaffler-content-mode", choices=("relayed", "all"))
    return parser


def _config_value(
    data: Dict[str, Any], name: str, section: Optional[str] = None
) -> Any:
    source = data.get(section, {}) if section else data
    if section and not isinstance(source, dict):
        raise ValueError(f"configuration field [{section}] must be a table")
    return source.get(name) if isinstance(source, dict) else None


def _normalize(
    mode: str, parsed: argparse.Namespace, config: Dict[str, Any]
) -> argparse.Namespace:
    def pick(
        name: str,
        default: Any = None,
        config_name: Optional[str] = None,
        section: Optional[str] = None,
        env: Optional[str] = None,
    ) -> Any:
        cli = getattr(parsed, name, None)
        configured = _config_value(config, config_name or name, section)
        return (
            cli
            if cli is not None
            else configured
            if configured is not None
            else os.getenv(env)
            if env and os.getenv(env) is not None
            else default
        )

    profile = pick("profile", "balanced")
    if profile not in PROFILES:
        raise ValueError(
            f"configuration field profile must be one of {', '.join(PROFILES)}"
        )
    policy = pick("policy", "audit" if mode == "shares" else "collect")
    if policy not in POLICIES:
        raise ValueError(
            f"configuration field policy must be one of {', '.join(POLICIES)}"
        )
    defaults = {
        "quiet": (1, "matches"),
        "balanced": (4, "matches"),
        "fast": (8, "summary"),
    }[profile]
    parsed.operating_mode = mode
    parsed.scan_profile = profile
    parsed.policy = policy
    parsed.spider = mode != "shares"
    parsed.workers = pick("workers", defaults[0])
    explicit_permission_check = parsed.permission_check is not None
    parsed.permission_check = pick("permission_check", "read-write")
    parsed.file_write_check = bool(parsed.file_write_check)
    parsed.output_mode = pick("view", "tree" if mode == "shares" else defaults[1])
    parsed.output_dir = pick("output", ".")
    if parsed.resume and parsed.output is None:
        parsed.output_dir = parsed.resume
    fmt = pick("format", "console")
    parsed.csv_output = bool(parsed.csv_output) or fmt in {"csv", "all"}
    parsed.json_output = bool(parsed.json_output) or fmt in {"json", "all"}
    included = list(parsed.share or [])
    configured_shares = _config_value(config, "shares") or []
    if not parsed.share and not parsed.shares:
        included.extend(configured_shares)
    if parsed.shares:
        included.extend(x.strip() for x in parsed.shares.split(",") if x.strip())
    parsed.shares = ",".join(included) if included else None
    excluded = list(
        parsed.exclude_share or (_config_value(config, "exclude_shares") or [])
    )
    parsed.skip_share = ",".join(excluded) if excluded else None
    parsed.no_pass = bool(parsed.no_pass)
    parsed.k = bool(parsed.k)
    parsed.verbose = bool(parsed.verbose)
    parsed.metrics = bool(parsed.metrics)
    parsed.read_only = bool(parsed.read_only)
    if parsed.file_write_check and parsed.read_only:
        raise ValueError("--read-only cannot be combined with --file-write-check")
    if parsed.file_write_check and parsed.permission_check in {"none", "read"}:
        if explicit_permission_check or parsed.read_only:
            raise ValueError(
                "--file-write-check requires --permission-check read-write"
            )
        parsed.permission_check = "read-write"
    if parsed.read_only:
        parsed.permission_check = "read"
    parsed.max_depth = pick("max_depth", 5)
    parsed.delay = pick("delay", 0)
    parsed.download_ext = getattr(parsed, "download", None)
    parsed.max_total_download = getattr(parsed, "download_budget", None)
    parsed.count_ext = getattr(parsed, "count_ext", None)
    parsed.count_string = getattr(parsed, "count_string", None)
    parsed.unique = bool(getattr(parsed, "unique", False))
    parsed.download_name = getattr(parsed, "download_name", None)
    parsed.max_content_reads = getattr(parsed, "max_content_reads", None)
    parsed.content_read_budget = getattr(parsed, "content_read_budget", None)
    parsed.snaffler_rules_dir = (
        pick("rules", None, section="snaffle") if mode == "snaffle" else None
    )
    parsed.snaffler_interest_level = (
        pick("interest", 0, section="snaffle") if mode == "snaffle" else None
    )
    parsed.snaffler_max_size_to_grep = pick("snaffler_max_size_to_grep", 1024**2)
    parsed.snaffler_strict = bool(getattr(parsed, "snaffler_strict", False))
    parsed.snaffler_no_auto_download = bool(
        getattr(parsed, "snaffler_no_auto_download", False)
    )
    parsed.snaffler_content_mode = pick("snaffler_content_mode", "relayed")
    parsed.nemesis_url = pick("nemesis_url", None, "url", "nemesis", "NEMESIS_URL")
    parsed.nemesis_auth = pick("nemesis_auth", None, "auth", "nemesis", "NEMESIS_AUTH")
    parsed.nemesis_project = pick(
        "nemesis_project", None, "project", "nemesis", "NEMESIS_PROJECT"
    )
    parsed.nemesis_mode = pick("nemesis_mode", "off", "mode", "nemesis")
    parsed.nemesis_upload_workers = pick(
        "nemesis_upload_workers", 2, "upload_workers", "nemesis"
    )
    parsed.nemesis_retries = pick("nemesis_retries", 2, "retries", "nemesis")
    parsed.nemesis_queue_size = pick("nemesis_queue_size", 100, "queue_size", "nemesis")
    limits = pick("limits", "standard")
    if mode != "shares":
        file_limit, total_limit = _LIMITS[limits]
        parsed.max_file_size = (
            parsed.max_file_size
            if parsed.max_file_size is not None
            else (file_limit or None)
        )
        parsed.max_total_download = (
            parsed.max_total_download
            if parsed.max_total_download is not None
            else (total_limit or None)
        )
    else:
        parsed.max_file_size = parsed.max_total_download = None
    _, _, _, embedded_host = parse_target(parsed.target)
    if parsed.hosts_file:
        path = Path(parsed.hosts_file)
        try:
            hosts = [
                line.split("#", 1)[0].strip() for line in path.read_text().splitlines()
            ]
        except OSError as exc:
            raise ValueError(f"cannot read --hosts-file {path}: {exc}") from exc
        if not any(hosts):
            raise ValueError(f"--hosts-file {path} contains no hosts")
    elif not parsed.host and not embedded_host:
        raise ValueError(
            "no target host provided; embed one in TARGET or use --host/--hosts-file"
        )
    for name, minimum in (
        ("workers", 1),
        ("max_depth", 0),
        ("delay", 0),
        ("nemesis_upload_workers", 1),
        ("nemesis_retries", 0),
        ("nemesis_queue_size", 1),
    ):
        if getattr(parsed, name) < minimum:
            raise ValueError(f"--{name.replace('_', '-')} must be {minimum} or greater")
    for name in (
        "max_file_size",
        "max_total_download",
        "max_content_reads",
        "content_read_budget",
    ):
        value = getattr(parsed, name)
        if value is not None and value < 0:
            raise ValueError(f"--{name.replace('_', '-')} must be zero or greater")
    if parsed.nemesis_mode != "off":
        missing = [
            option
            for option, value in (
                ("--nemesis", parsed.nemesis_url),
                ("--nemesis-auth", parsed.nemesis_auth),
                ("--nemesis-project", parsed.nemesis_project),
            )
            if not value
        ]
        if missing:
            raise ValueError("Nemesis mode requires " + ", ".join(missing))
        if ":" not in parsed.nemesis_auth:
            raise ValueError("--nemesis-auth must use username:password format")
    if mode == "spider" and parsed.nemesis_mode == "matches":
        raise ValueError("spider mode supports Nemesis modes 'off' and 'downloads'")
    if mode == "snaffle" and not parsed.snaffler_rules_dir:
        raise ValueError("snaffle mode requires --rules")
    return parsed


def parse_scan_options(
    mode: str, arguments: List[str], config: Optional[Dict[str, Any]] = None
) -> argparse.Namespace:
    parser = _scan_parser(mode)
    parsed = parser.parse_args(arguments)
    try:
        return _normalize(mode, parsed, load_config() if config is None else config)
    except ValueError as exc:
        parser.error(str(exc))


def _print_top_level_help() -> None:
    print(
        """usage: shrawler <command> [options]\n\ncommands:\n  shares\n  spider\n  snaffle\n  report\n  config\n\nRun 'shrawler <command> --help' for all command options."""
    )


def main(argv: Optional[List[str]] = None) -> None:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] in {"-h", "--help"}:
        _print_top_level_help()
        return
    command = arguments[0]
    if command == "config":
        action = arguments[1] if len(arguments) > 1 else "show"
        path = config_path()
        if action == "path":
            print(path)
            return
        if action == "init":
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                raise SystemExit(f"Configuration already exists: {path}")
            path.write_text(DEFAULT_CONFIG, encoding="utf-8")
            path.chmod(0o600)
            print(f"Created {path}")
            return
        if action == "show":
            print(path.read_text() if path.exists() else DEFAULT_CONFIG)
            return
        if action == "options":
            print(CONFIG_OPTIONS)
            return
        raise SystemExit("usage: shrawler config {init|show|path|options}")
    if command == "report":
        raise SystemExit(report_main(arguments[1:]))
    if command in SCAN_MODES:
        if any(item in {"-h", "--help"} for item in arguments[1:]):
            _scan_parser(command).print_help()
            return
        options = parse_scan_options(command, arguments[1:])
    else:
        mode = "spider" if "--spider" in arguments else "shares"
        arguments = [item for item in arguments if item != "--spider"]
        options = parse_scan_options(mode, arguments)
    scan_main(options)


__all__ = ["main", "parse_scan_options"]
