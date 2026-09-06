import json
import tempfile
import unittest
from pathlib import Path

from shrawler.store import ScanStore, WorkspaceBusyError
from shrawler.web import DatabaseIndex


class ScanStoreTests(unittest.TestCase):
    def test_multiple_scans_share_files_and_export_per_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = ScanStore(root, "spider", "DOMAIN", "alice")
            first.upsert_host("server", "server", "scanning")
            first.upsert_share(
                "server",
                "DATA",
                "scanning",
                {
                    "comment": "Data",
                    "permissions": {"read": True, "write": False},
                    "share_type": 0,
                    "unc_path": r"\\server\DATA",
                },
            )
            file_data = {
                "remote_path": "/reports/secret.txt",
                "unc_path": r"\\server\DATA\reports\secret.txt",
                "file_name": "secret.txt",
                "size_bytes": 10,
                "readable_size": "10B",
                "mtime_utc": "2026-01-01T00:00:00+00:00",
                "is_directory": False,
                "scan_timestamp_utc": "2026-09-04T00:00:00+00:00",
            }
            self.assertTrue(first.add_file("server", "DATA", file_data))
            self.assertFalse(first.add_file("server", "DATA", file_data))
            first.upsert_share(
                "server",
                "DATA",
                "complete",
                {
                    "comment": "Data",
                    "permissions": {"read": True, "write": False},
                    "share_type": 0,
                    "unc_path": r"\\server\DATA",
                },
            )
            first.upsert_host("server", "server", "complete")
            summary = {"files_seen": 1, "host_statuses": {"complete": 1}}
            first.finish("completed", summary)
            exported = first.export_json(summary)
            first.close()

            payload = json.loads(exported.read_text())
            self.assertEqual(
                payload["server"]["shares"]["DATA"]["discovered_files"],
                [file_data],
            )

            second = ScanStore(root, "spider", "DOMAIN", "bob")
            second.upsert_host("server", "server", "scanning")
            second.upsert_share(
                "server",
                "DATA",
                "scanning",
                {
                    "comment": "Data",
                    "permissions": {"read": True, "write": False},
                    "share_type": 0,
                    "unc_path": r"\\server\DATA",
                },
            )
            newer = {**file_data, "size_bytes": 20, "readable_size": "20B"}
            self.assertTrue(second.add_file("server", "DATA", newer))
            second.flush()
            index = DatabaseIndex(root / "shrawler.db")
            found = index.search("secret", "", "", "", 1, 100)
            self.assertEqual(found["total"], 1)
            self.assertEqual(found["items"][0]["size_bytes"], 20)
            tree = index.tree("", "", "", "")
            self.assertEqual(tree["hosts"][0]["shares"], [])
            shares = index.tree_branch("", "server", "", "", "")
            self.assertEqual(shares["shares"][0]["name"], "DATA")
            branch = index.tree_branch("", "server", "DATA", "", "/")
            self.assertEqual(branch["folders"][0]["name"], "reports")
            second.close()

    def test_workspace_allows_one_scanner(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = ScanStore(Path(tmp), "spider")
            with self.assertRaises(WorkspaceBusyError):
                ScanStore(Path(tmp), "spider")
            first.close()

    def test_resume_selects_most_recent_incomplete_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = ScanStore(root, "spider")
            scan_id = first.scan_id
            first.finish("interrupted", {"files_seen": 0})
            first.close()

            resumed = ScanStore(root, "spider", resume="")
            self.assertEqual(resumed.scan_id, scan_id)
            resumed.close()


if __name__ == "__main__":
    unittest.main()
