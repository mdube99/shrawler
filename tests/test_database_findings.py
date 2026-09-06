import tempfile
import unittest
from pathlib import Path

from shrawler.store import ScanStore
from shrawler.web import DatabaseIndex


def _file(remote_path: str, host: str, share: str) -> dict:
    name = remote_path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    unc_remote = remote_path.lstrip("/\\").replace("/", "\\")
    return {
        "remote_path": remote_path,
        "unc_path": rf"\\{host}\{share}\{unc_remote}",
        "file_name": name,
        "size_bytes": 10,
        "readable_size": "10B",
        "mtime_utc": "2026-09-04T00:00:00+00:00",
        "is_directory": False,
        "scan_timestamp_utc": "2026-09-04T00:00:00+00:00",
    }


class DatabaseIndexEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.stores = []

    def tearDown(self):
        for store in self.stores:
            store.close()
        self.tmp.cleanup()

    def _store(self, username: str = "alice") -> ScanStore:
        store = ScanStore(self.root, "spider", "DOMAIN", username)
        self.stores.append(store)
        return store

    @staticmethod
    def _share(store: ScanStore, host: str, share: str, permissions=None):
        store.upsert_host(host, host, "scanning")
        store.upsert_share(
            host,
            share,
            "scanning",
            {
                "permissions": permissions or {"read": True, "write": False},
                "unc_path": rf"\\{host}\{share}",
            },
        )

    def test_latest_scan_observation_is_used_for_evidence_and_filters(self):
        old = self._store("alice")
        self._share(old, "server", "DATA")
        old.add_file("server", "DATA", _file("/secret.txt", "server", "DATA"))
        old.add_match(
            {
                **_file("/secret.txt", "server", "DATA"),
                "host": "server",
                "share_name": "DATA",
                "rule_name": "OldRule",
                "triage": "High",
            }
        )
        old.add_download(
            "server",
            "DATA",
            {**_file("/secret.txt", "server", "DATA"), "status": "success"},
        )
        old.flush()
        old.connection.execute(
            "UPDATE scans SET started_at_utc=? WHERE id=?",
            ("2026-09-01T00:00:00+00:00", old.scan_id),
        )
        old.connection.commit()
        old.close()
        self.stores.remove(old)

        latest = self._store("bob")
        self._share(latest, "server", "DATA")
        latest.add_file("server", "DATA", _file("/secret.txt", "server", "DATA"))
        latest.flush()
        latest.connection.execute(
            "UPDATE scans SET started_at_utc=? WHERE id=?",
            ("2026-09-02T00:00:00+00:00", latest.scan_id),
        )
        latest.connection.commit()
        latest.close()
        self.stores.remove(latest)

        index = DatabaseIndex(self.root / "shrawler.db", page_size=500)
        item = index.search("", "server", "DATA", "", 1, 10)["items"][0]
        self.assertEqual(item["rule_matches"], [])
        self.assertEqual(item["collection_status"], "not_collected")
        self.assertEqual(
            index.search("", "", "", "", 1, 10, rule="OldRule")["total"], 0
        )
        self.assertEqual(
            index.search("", "", "", "", 1, 10, collection="collected")["total"], 0
        )
        self.assertEqual(
            index.search("", "", "", "", 1, 10, collection="not_collected")["total"], 1
        )

    def test_same_path_on_hosts_and_shares_keeps_evidence_separate(self):
        store = self._store()
        for host, share, rule in (
            ("server1", "DATA", "HostOne"),
            ("server1", "BACKUP", "ShareTwo"),
            ("server2", "DATA", "HostTwo"),
        ):
            self._share(store, host, share)
            payload = _file("/same.txt", host, share)
            store.add_file(host, share, payload)
            store.add_match(
                {
                    **payload,
                    "host": host,
                    "share_name": share,
                    "rule_name": rule,
                    "triage": "Medium",
                }
            )
        store.close()
        self.stores.remove(store)

        index = DatabaseIndex(self.root / "shrawler.db")
        for host, share, rule in (
            ("server1", "DATA", "HostOne"),
            ("server1", "BACKUP", "ShareTwo"),
            ("server2", "DATA", "HostTwo"),
        ):
            item = index.search("", host, share, "", 1, 10)["items"][0]
            self.assertEqual([m["rule_name"] for m in item["rule_matches"]], [rule])

    def test_slash_normalization_and_same_rule_rule_and_triage_filters(self):
        store = self._store()
        self._share(store, "server", "DATA")
        payload = _file(r"\\nested\\report.txt", "server", "DATA")
        store.add_file("server", "DATA", payload)
        store.add_match(
            {
                **payload,
                "remote_path": "/nested/report.txt",
                "host": "server",
                "share_name": "DATA",
                "rule_name": "CredentialRule",
                "triage": "Critical",
            }
        )
        store.close()
        self.stores.remove(store)

        index = DatabaseIndex(self.root / "shrawler.db")
        result = index.search(
            "", "server", "DATA", "", 1, 10, "CredentialRule", "Critical"
        )
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["items"][0]["rule_matches"][0]["triage"], "Critical")

    def test_permission_filters_use_latest_share_acl_and_tree_matches_table(self):
        store = self._store()
        self._share(store, "server", "DATA", {"read": True, "write": False})
        self._share(store, "server", "PUBLIC", {"read": True, "write": True})
        for share in ("DATA", "PUBLIC"):
            payload = _file("/root.txt", "server", share)
            store.add_file("server", share, payload)
            store.add_match(
                {
                    **payload,
                    "host": "server",
                    "share_name": share,
                    "rule_name": "Keep",
                    "triage": "High",
                }
            )
        store.close()
        self.stores.remove(store)

        index = DatabaseIndex(self.root / "shrawler.db")
        table = index.search("", "", "", "", 1, 10, rule="Keep", permission="write")
        tree = index.tree("", "", "", "", rule="Keep", permission="write")
        self.assertEqual(table["total"], 1)
        self.assertEqual(tree["total"], table["total"])
        branch = index.tree_branch("", "server", "", "", "", "Keep", "", "write", "")
        self.assertEqual({share["name"] for share in branch["shares"]}, {"PUBLIC"})

    def test_enrichment_batches_more_than_four_hundred_records(self):
        store = self._store()
        self._share(store, "server", "DATA")
        for number in range(405):
            payload = _file(f"/files/file-{number}.txt", "server", "DATA")
            store.add_file("server", "DATA", payload)
        store.close()
        self.stores.remove(store)

        index = DatabaseIndex(self.root / "shrawler.db", page_size=500)
        result = index.search("", "server", "DATA", "", 1, 500)
        self.assertEqual(result["total"], 405)
        self.assertEqual(len(result["items"]), 405)
        self.assertTrue(
            all(item["metadata_scan_timestamp_utc"] for item in result["items"])
        )


if __name__ == "__main__":
    unittest.main()
