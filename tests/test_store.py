import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from shrawler.store import SCHEMA_VERSION, ScanStore, WorkspaceBusyError
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
                "host": "server",
                "share_name": "DATA",
                "remote_path": "/reports/secret.txt",
                "unc_path": "\\\\server\\DATA\\reports/secret.txt",
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

    def test_v1_inventory_migrates_in_place(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "shrawler.db"
            connection = sqlite3.connect(path)
            connection.executescript(
                """
                CREATE TABLE files (
                    id INTEGER PRIMARY KEY,
                    public_id TEXT NOT NULL UNIQUE,
                    host TEXT NOT NULL,
                    share TEXT NOT NULL,
                    remote_path TEXT NOT NULL,
                    parent_path TEXT NOT NULL,
                    unc_path TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    extension TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    readable_size TEXT NOT NULL,
                    mtime_utc TEXT NOT NULL,
                    scan_timestamp_utc TEXT NOT NULL,
                    search_text TEXT NOT NULL,
                    UNIQUE(host, share, remote_path)
                );
                CREATE TABLE scan_files (
                    scan_id TEXT NOT NULL,
                    share_id INTEGER NOT NULL,
                    file_id INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY(scan_id, file_id)
                );
                PRAGMA user_version=1;
                """
            )
            payload = {
                "host": "server",
                "share_name": "DATA",
                "remote_path": "/reports/secret.txt",
                "unc_path": r"\\server\DATA\reports\secret.txt",
                "file_name": "secret.txt",
                "size_bytes": 10,
                "readable_size": "10B",
                "mtime_utc": "2026-01-01T00:00:00+00:00",
                "is_directory": False,
                "scan_timestamp_utc": "2026-09-04T00:00:00+00:00",
            }
            connection.execute(
                "INSERT INTO files(public_id,host,share,remote_path,parent_path,"
                "unc_path,file_name,extension,size_bytes,readable_size,mtime_utc,"
                "scan_timestamp_utc,search_text) "
                "VALUES ('abc','server','DATA','/reports/secret.txt','/reports',"
                "?, 'secret.txt','.txt',10,'10B','2026-01-01T00:00:00+00:00',"
                "'2026-09-04T00:00:00+00:00','stale')",
                (payload["unc_path"],),
            )
            connection.execute(
                "INSERT INTO scan_files VALUES ('scan1',1,1,?)",
                (json.dumps(payload),),
            )
            connection.commit()
            connection.close()

            store = ScanStore(root, "spider", "DOMAIN", "bob")
            try:
                columns = {
                    row[1]
                    for row in store.connection.execute("PRAGMA table_info(scan_files)")
                }
                self.assertNotIn("payload_json", columns)
                self.assertEqual(
                    store.connection.execute("PRAGMA user_version").fetchone()[0],
                    SCHEMA_VERSION,
                )
                per_scan = store.connection.execute(
                    "SELECT size_bytes,max(readable_size) FROM scan_files"
                ).fetchone()
                self.assertEqual(tuple(per_scan), (10, "10B"))
                self.assertEqual(
                    store.connection.execute(
                        "SELECT readable_size FROM files"
                    ).fetchone()[0],
                    "10B",
                )
                self.assertIn(
                    "secret",
                    store.connection.execute(
                        "SELECT search_text FROM files"
                    ).fetchone()[0],
                )
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
