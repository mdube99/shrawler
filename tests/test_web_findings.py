import json
import tempfile
import unittest
from pathlib import Path

from shrawler.web import FileIndex


def inventory(path: Path) -> Path:
    files = [
        {
            "remote_path": r"\Reports\same.txt",
            "unc_path": r"\\alpha\DATA\Reports\same.txt",
            "file_name": "same.txt",
            "size_bytes": 4,
            "scan_timestamp_utc": "2026-09-01T00:00:00+00:00",
        },
        {
            "remote_path": "/Reports/same.txt",
            "unc_path": r"\\bravo\DATA\Reports\same.txt",
            "file_name": "same.txt",
            "size_bytes": 4,
            "scan_timestamp_utc": "2026-09-01T00:00:00+00:00",
        },
    ]
    data = {
        "_schema": {"name": "shrawler-results", "version": 3},
        "alpha": {
            "shares": {
                "DATA": {
                    "permissions": {"read": True, "write": False},
                    "discovered_files": files[:1],
                    "snaffler_matches": [
                        {
                            "host": "alpha",
                            "share_name": "DATA",
                            "remote_path": "/Reports/same.txt",
                            "rule_name": "KeepSecret",
                            "triage": "high",
                        }
                    ],
                    "downloaded_files": [],
                }
            }
        },
        "bravo": {
            "shares": {
                "DATA": {
                    "permissions": {"read": False, "write": True},
                    "discovered_files": files[1:],
                    "snaffler_matches": [
                        {
                            "host": "bravo",
                            "share_name": "DATA",
                            "remote_path": "/other.txt",
                            "rule_name": "Other",
                            "triage": "low",
                        }
                    ],
                    "downloaded_files": [
                        {
                            "host": "bravo",
                            "share_name": "DATA",
                            "remote_path": r"\Reports\same.txt",
                            "status": "downloaded",
                        }
                    ],
                }
            }
        },
    }
    result = path / "results.json"
    result.write_text(json.dumps(data), encoding="utf-8")
    return result


class WebFindingTests(unittest.TestCase):
    def test_metadata_is_path_and_host_specific_and_visible_in_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            index = FileIndex.load(inventory(Path(temporary)))
            alpha = next(item for item in index.records if item.host == "alpha")
            bravo = next(item for item in index.records if item.host == "bravo")

            self.assertEqual(alpha.rule_matches[0]["rule_name"], "KeepSecret")
            self.assertEqual(alpha.collection_status, "not_collected")
            self.assertTrue(alpha.permissions["read"])
            self.assertEqual(bravo.rule_matches, ())
            self.assertEqual(bravo.collection_status, "collected")
            self.assertTrue(bravo.permissions["write"])

            tree = index.tree("", "", "", "")
            tree_files = [
                file
                for host in tree["hosts"]
                for share in host["shares"]
                for folder in share["folders"]
                for file in folder["files"]
            ]
            self.assertEqual(
                {file["collection_status"] for file in tree_files},
                {"collected", "not_collected"},
            )

    def test_combined_finding_permission_and_collection_filters(self):
        with tempfile.TemporaryDirectory() as temporary:
            index = FileIndex.load(inventory(Path(temporary)))
            result = index.search(
                "same",
                "alpha",
                "DATA",
                ".txt",
                1,
                100,
                "KeepSecret",
                "high",
                "read",
                "not_collected",
            )
            self.assertEqual(result["total"], 1)
            self.assertEqual(result["items"][0]["host"], "alpha")

            self.assertEqual(
                index.search("", "", "", "", 1, 100, "KeepSecret", "", "", "collected")[
                    "total"
                ],
                0,
            )
            self.assertEqual(index.facets()["rules"], ["KeepSecret"])
            self.assertEqual(index.facets()["triages"], ["high"])


if __name__ == "__main__":
    unittest.main()
