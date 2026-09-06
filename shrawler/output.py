"""Helpers for rendering attacker controlled values in output formats.

The values collected from SMB servers are untrusted.  Keep the original
values in JSON and use these helpers only at presentation boundaries.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Mapping
from typing import Any

# Unicode bidirectional formatting and isolate controls can make a filename or
# finding appear in a different order from the stored value.
_BIDI_CONTROLS = {
    *(range(0x202A, 0x202F)),
    *(range(0x2066, 0x206A)),
    0x061C,  # ARABIC LETTER MARK
}


def escape_terminal(value: Any) -> str:
    """Return *value* with terminal controls represented visibly.

    C0/C1 controls, DEL, bidi controls, and other Unicode format characters
    are escaped as code points.  Printable text, including non-ASCII names,
    is preserved.  This is intended for untrusted fields embedded in terminal
    messages; application-owned ANSI styling should be written separately.
    """

    text = "" if value is None else str(value)
    escaped: list[str] = []
    for character in text:
        codepoint = ord(character)
        if codepoint <= 0x1F or 0x7F <= codepoint <= 0x9F:
            escaped.append(f"\\x{codepoint:02x}")
        elif codepoint in _BIDI_CONTROLS or unicodedata.category(character) == "Cf":
            escaped.append(f"\\u{codepoint:04x}")
        else:
            escaped.append(character)
    return "".join(escaped)


def neutralize_csv_formula(value: Any) -> str:
    """Make a value safe for spreadsheet import while retaining its text.

    Spreadsheet applications may evaluate cells beginning with ``=``, ``+``,
    ``-``, or ``@`` as formulas.  Check past leading whitespace and controls,
    then prefix the complete cell with an apostrophe when needed.  The raw
    value remains available in JSON output.
    """

    text = "" if value is None else str(value)
    for character in text:
        if character.isspace() or unicodedata.category(character).startswith("C"):
            continue
        if character in "=+-@":
            return "'" + text
        break
    return text


def safe_csv_row(row: Mapping[str, Any]) -> dict[str, str]:
    """Return a CSV presentation copy with formula-like cells neutralized."""

    return {key: neutralize_csv_formula(value) for key, value in row.items()}


__all__ = ["escape_terminal", "neutralize_csv_formula", "safe_csv_row"]
