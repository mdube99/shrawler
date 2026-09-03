"""Shared command-line argument definitions."""

import argparse
import re

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


def parse_size(value: str) -> int:
    """Parse a byte count or a human-readable size."""
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([kmgt]?i?b)?\s*", value.lower())
    if not match or match.group(2) not in _SIZE_UNITS:
        raise argparse.ArgumentTypeError(
            "use bytes or a size such as 20MB, 2GB, or 512MiB"
        )
    return int(float(match.group(1)) * _SIZE_UNITS[match.group(2)])


def add_smb_auth_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the authentication options shared by SMB-backed commands."""
    auth = parser.add_argument_group("authentication")
    auth.add_argument(
        "-H",
        "--hashes",
        metavar="LMHASH:NTHASH",
        help="authenticate with NTLM hashes; use :NTHASH when no LM hash is available",
    )
    auth.add_argument(
        "-no-pass",
        action="store_true",
        default=None,
        help="do not prompt for a password (for null sessions or other auth material)",
    )
    auth.add_argument(
        "-k",
        action="store_true",
        default=None,
        help="use Kerberos authentication from the credential cache",
    )
    auth.add_argument(
        "-aesKey", metavar="HEX_KEY", help="Kerberos AES key (implies -k)"
    )


__all__ = ["add_smb_auth_arguments", "parse_size"]
