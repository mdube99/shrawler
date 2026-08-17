"""Command-line entry point and operating-mode dispatch."""

import argparse
import re
import sys
from typing import Dict, List, Optional, Tuple

from .config import (
    CONFIG_OPTIONS,
    DEFAULT_CONFIG,
    compact_config_arguments,
    config_path,
    load_config,
)
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


def _scan_parser(mode: str) -> argparse.ArgumentParser:
    descriptions = {
        "shares": "Enumerate SMB shares and permissions.",
        "spider": "Recursively inventory readable SMB shares.",
        "snaffle": "Find interesting files using Snaffler rules.",
    }
    parser = argparse.ArgumentParser(
        prog=f"shrawler {mode}",
        description=descriptions[mode],
        epilog=(
            f"Run 'shrawler {mode} --help-advanced' for every tuning option. "
            "Existing option names remain supported."
        ),
    )
    parser.add_argument("target", help="[[domain/]username[:password]@]<host>")
    parser.add_argument(
        "--profile", choices=PROFILES, default="balanced",
        help="noise and concurrency preset (default: balanced)",
    )
    parser.add_argument(
        "--policy", choices=POLICIES, default="collect" if mode != "shares" else "audit",
        help="audit safely, collect selected files, or scan aggressively",
    )
    parser.add_argument(
        "--share", action="append", metavar="NAME",
        help="scan only this share; repeat for more than one",
    )
    parser.add_argument(
        "--exclude-share", action="append", metavar="NAME",
        help="skip this share; repeat for more than one",
    )
    parser.add_argument("-o", "--output", metavar="PATH", help="results directory")
    parser.add_argument(
        "--format", choices=FORMATS, default="console",
        help="saved result format (default: console)",
    )
    view_choices = ("summary", "progress", "tree") if mode == "shares" else (
        "summary", "progress", "matches", "tree"
    )
    parser.add_argument(
        "--view", "--output-mode", dest="view", choices=view_choices,
        default="progress" if sys.stderr.isatty() else None,
        help="terminal detail: totals, matches, or the complete tree",
    )
    parser.add_argument(
        "--resume", nargs="?", const=".", metavar="PATH",
        help="resume from a previous output directory",
    )
    # Authentication switches remain accepted here so they can be combined with
    # compact options, but live in advanced help to keep the common path small.
    parser.add_argument("-H", "--hashes", metavar="LMHASH:NTHASH", help=argparse.SUPPRESS)
    parser.add_argument("-no-pass", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("-k", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("-aesKey", metavar="HEX_KEY", help=argparse.SUPPRESS)
    parser.add_argument("--nemesis-auth", help=argparse.SUPPRESS)
    parser.add_argument("--nemesis-project", help=argparse.SUPPRESS)
    parser.add_argument(
        "--nemesis-mode", choices=("off", "matches", "downloads"),
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--nemesis-upload-workers", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--nemesis-retries", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--nemesis-queue-size", type=int, help=argparse.SUPPRESS)

    if mode in {"spider", "snaffle"}:
        parser.add_argument(
            "--download", nargs="?", const="default", metavar="EXTENSIONS",
            help="download default or comma-separated file extensions",
        )
        parser.add_argument(
            "--limits", choices=tuple(_LIMITS), default="standard",
            help="download size preset (default: standard)",
        )
        parser.add_argument(
            "--max-file-size", type=_parse_size, metavar="SIZE",
            help="override per-file limit, for example 20MB",
        )
        parser.add_argument(
            "--download-budget", type=_parse_size, metavar="SIZE",
            help="override total download limit, for example 2GB",
        )
        parser.add_argument(
            "--nemesis", metavar="URL",
            help="send downloaded files to Nemesis (credentials come from the environment)",
        )

    if mode == "snaffle":
        parser.add_argument("--rules", required=True, metavar="PATH")
        parser.add_argument("--interest", choices=range(4), type=int, default=0)

    return parser


def _parse_size(value: str) -> int:
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([kmgt]?i?b)?\s*", value.lower())
    if not match or match.group(2) not in _SIZE_UNITS:
        raise argparse.ArgumentTypeError(
            "use bytes or a size such as 20MB, 2GB, or 512MiB"
        )
    return int(float(match.group(1)) * _SIZE_UNITS[match.group(2)])


def _policy_arguments(mode: str, policy: str) -> List[str]:
    if policy == "audit":
        return ["--permission-check", "read", "--read-only"]
    if policy == "aggressive":
        arguments = ["--permission-check", "read-write"]
        if mode != "shares":
            arguments.extend(["--download-ext", " "])
        return arguments
    return ["--permission-check", "read"]


def _compact_arguments(mode: str, arguments: List[str]) -> Optional[List[str]]:
    """Parse the compact interface, returning None when legacy options are present."""
    compact_options = {
        "--profile", "--policy", "--share", "--exclude-share", "-o", "--output",
        "--format", "--view", "--output-mode", "--download", "--limits",
        "--download-budget", "--nemesis", "--resume",
        "--max-file-size", "--rules", "--interest",
        "-H", "--hashes", "-no-pass", "-k", "-aesKey",
        "--nemesis-auth", "--nemesis-project", "--nemesis-mode",
        "--nemesis-upload-workers", "--nemesis-retries", "--nemesis-queue-size",
    }
    if any(
        argument.startswith("-")
        and argument.split("=", 1)[0] not in compact_options
        and argument not in {"-h", "--help"}
        for argument in arguments
    ):
        return None

    parser = _scan_parser(mode)
    parsed = parser.parse_args(arguments)
    translated = [parsed.target, "--scan-profile", parsed.profile]
    translated.extend(_policy_arguments(mode, parsed.policy))
    if parsed.share:
        translated.extend(["--shares", ",".join(parsed.share)])
    if parsed.exclude_share:
        translated.extend(["--skip-share", ",".join(parsed.exclude_share)])
    if parsed.output:
        translated.extend(["--output-dir", parsed.output])
    if parsed.resume:
        translated.extend(["--resume", parsed.resume])
        if not parsed.output:
            translated.extend(["--output-dir", parsed.resume])
    if parsed.format in {"csv", "all"}:
        translated.append("--csv-output")
    if parsed.format in {"json", "all"}:
        translated.append("--json-output")
    if parsed.view:
        translated.extend(["--output-mode", parsed.view])
    if parsed.hashes:
        translated.extend(["-H", parsed.hashes])
    if parsed.no_pass:
        translated.append("-no-pass")
    if parsed.k:
        translated.append("-k")
    if parsed.aesKey:
        translated.extend(["-aesKey", parsed.aesKey])
    if parsed.nemesis_project:
        translated.extend(["--nemesis-project", parsed.nemesis_project])
    if parsed.nemesis_auth:
        translated.extend(["--nemesis-auth", parsed.nemesis_auth])
    if parsed.nemesis_mode:
        translated.extend(["--nemesis-mode", parsed.nemesis_mode])
    if parsed.nemesis_upload_workers is not None:
        translated.extend(
            ["--nemesis-upload-workers", str(parsed.nemesis_upload_workers)]
        )
    if parsed.nemesis_retries is not None:
        translated.extend(["--nemesis-retries", str(parsed.nemesis_retries)])
    if parsed.nemesis_queue_size is not None:
        translated.extend(["--nemesis-queue-size", str(parsed.nemesis_queue_size)])

    if mode in {"spider", "snaffle"}:
        file_limit, total_limit = _LIMITS[parsed.limits]
        if parsed.limits != "unlimited":
            translated.extend(["--max-file-size", str(parsed.max_file_size or file_limit)])
            translated.extend(
                ["--max-total-download", str(parsed.download_budget or total_limit)]
            )
        elif parsed.max_file_size:
            translated.extend(["--max-file-size", str(parsed.max_file_size)])
        if parsed.limits == "unlimited" and parsed.download_budget:
            translated.extend(["--max-total-download", str(parsed.download_budget)])
        if parsed.download is not None:
            translated.extend(["--download-ext", parsed.download])
        if parsed.nemesis:
            translated.extend(
                ["--nemesis-url", parsed.nemesis]
            )
            if not parsed.nemesis_mode:
                translated.extend(["--nemesis-mode", "downloads"])

    if mode == "snaffle":
        translated.extend(["--snaffler-rules-dir", parsed.rules])
        translated.extend(["--snaffler-interest-level", str(parsed.interest)])
    return translated


def _print_advanced_help(mode: str) -> None:
    # The scanner owns the compatibility interface, so its help cannot drift.
    sys.argv = [sys.argv[0], "--help", "--operating-mode", mode]
    scan_main()


def _print_top_level_help() -> None:
    print(
        """usage: shrawler <command> [options]

commands:
  shares    Enumerate SMB shares and permissions
  spider    Recursively inventory readable shares
  snaffle   Spider and classify interesting files with Snaffler rules
  report    Summarize saved results or retry failed Nemesis uploads
  config    Initialize or inspect persistent defaults

Run 'shrawler <command> --help' for the common options.
Run 'shrawler <command> --help-advanced' for every tuning option.
"""
    )


def main(argv: Optional[List[str]] = None) -> None:
    """Dispatch an operating mode while retaining the original CLI syntax."""
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
            print(path.read_text(encoding="utf-8") if path.exists() else DEFAULT_CONFIG)
            return
        if action == "options":
            print(CONFIG_OPTIONS)
            return
        raise SystemExit("usage: shrawler config {init|show|path|options}")
    if command == "report":
        raise SystemExit(report_main(arguments[1:]))

    if command in SCAN_MODES:
        scan_arguments = arguments[1:]
        if "--help-advanced" in scan_arguments:
            _print_advanced_help(command)
            return
        if any(argument in {"-h", "--help"} for argument in scan_arguments):
            _scan_parser(command).print_help()
            return
        configured = compact_config_arguments(command, load_config())
        translated = _compact_arguments(command, [*configured, *scan_arguments])
        sys.argv = [
            sys.argv[0], *(translated if translated is not None else scan_arguments),
            "--operating-mode", command,
        ]
    elif argv is not None:
        sys.argv = [sys.argv[0], *arguments]

    scan_main()


__all__ = ["main"]
