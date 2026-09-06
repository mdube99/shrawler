"""Verify presentation escaping at real output boundaries."""

import csv
import io
import json
import logging
from pathlib import Path

from shrawler.core import Formatter, HostRenderResult, Shrawler, format_share_info
from shrawler.store import ScanStore


def test_store_csv_escapes_formulas_without_changing_json(tmp_path: Path):
    store = ScanStore(tmp_path, "spider")
    try:
        store.upsert_host("server", "server", "complete")
        comment = "\t=1+1"
        store.upsert_share(
            "server", "DATA", "complete", {"comment": comment, "permissions": {}}
        )
        payload = {
            "remote_path": "/=1+1.txt",
            "unc_path": r"\\server\DATA\=1+1.txt",
            "file_name": "=1+1.txt",
            "size_bytes": 10,
        }
        store.add_file("server", "DATA", payload)
        store.upsert_share(
            "server", "SYSVOL", "skipped", {"skip_reason": "default_exclusion"}
        )
        store.export_csv()
        with (store.run_dir / "shrawler_files.csv").open(newline="") as handle:
            row = next(csv.DictReader(handle))
        assert row["file_name"] == "'=1+1.txt"
        assert row["size_bytes"] == "10"
        with (store.run_dir / "shrawler_shares.csv").open(newline="") as handle:
            shares = {row["share_name"]: row for row in csv.DictReader(handle)}
        assert shares["DATA"]["comment"] == "'" + comment
        assert shares["SYSVOL"]["status"] == "skipped"
        assert shares["SYSVOL"]["skip_reason"] == "default_exclusion"
        result = json.loads(store.export_json({}).read_text())
        assert result["server"]["shares"]["DATA"]["comment"] == comment
        assert result["server"]["shares"]["DATA"]["discovered_files"] == [payload]
    finally:
        store.close()


def test_terminal_rows_escape_remote_control_sequences():
    row = format_share_info(
        "DATA\x1b[2J", "comment\nforged\x9b2J", {"read": True, "write": False}, 4
    )
    assert "\x1b[2J" not in row
    assert "\x9b" not in row
    assert "\n" not in row
    block = Shrawler.render_host_block(
        HostRenderResult("server", "server\rforged", "scan_failed", "bad\x1b[2J")
    )
    assert "\r" not in block
    assert "\x1b[2J" not in block


def test_log_formatter_escapes_message_without_mutating_record():
    record = logging.LogRecord(
        "test",
        logging.WARNING,
        __file__,
        1,
        "Failed: %s",
        ("bad\x1b[2J\nforged",),
        None,
    )
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(Formatter())
    handler.handle(record)
    rendered = stream.getvalue()
    assert "\x1b[2J" not in rendered
    assert rendered.count("\n") == 1
    assert record.getMessage() == "Failed: bad\x1b[2J\nforged"
