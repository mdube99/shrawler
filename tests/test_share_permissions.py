import csv
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from impacket.dcerpc.v5.srvs import STYPE_DISKTREE, STYPE_IPC, STYPE_TEMPORARY
from impacket.nt_errors import STATUS_ACCESS_DENIED
from impacket.smb3structs import (
    FILE_ADD_FILE,
    FILE_ADD_SUBDIRECTORY,
    FILE_OPEN,
    GENERIC_WRITE,
    WRITE_DAC,
    WRITE_OWNER,
)
from impacket.smbconnection import SessionError

from shrawler.core import print_share_info

try:
    from .test_snaffler_rules import _build_shrawler
except ImportError:
    from test_snaffler_rules import _build_shrawler


class _MaskClient:
    def __init__(self, granted=(), unexpected=()):
        self.granted = set(granted)
        self.unexpected = set(unexpected)
        self.calls = []

    def connectTree(self, share):
        self.calls.append(("connectTree", share))
        return 7

    def openFile(self, tree_id, path, **kwargs):
        access = kwargs["desiredAccess"]
        self.calls.append(("openFile", tree_id, path, kwargs))
        if access in self.unexpected:
            raise OSError("transport failed")
        if access not in self.granted:
            raise SessionError(STATUS_ACCESS_DENIED)
        return bytes([access & 255])

    def closeFile(self, tree_id, file_id):
        self.calls.append(("closeFile", tree_id, file_id))

    def disconnectTree(self, tree_id):
        self.calls.append(("disconnectTree", tree_id))


class _EmpiricalClient:
    def __init__(self, fail_directory=False, fail_delete_file=False):
        self.fail_directory = fail_directory
        self.fail_delete_file = fail_delete_file
        self.calls = []

    def createDirectory(self, share, path):
        self.calls.append(("createDirectory", share, path))
        if self.fail_directory:
            raise SessionError(STATUS_ACCESS_DENIED)

    def deleteDirectory(self, share, path):
        self.calls.append(("deleteDirectory", share, path))

    def connectTree(self, share):
        self.calls.append(("connectTree", share))
        return 8

    def createFile(self, tree_id, path, **kwargs):
        self.calls.append(("createFile", tree_id, path, kwargs))
        return b"file-id"

    def closeFile(self, tree_id, file_id):
        self.calls.append(("closeFile", tree_id, file_id))

    def disconnectTree(self, tree_id):
        self.calls.append(("disconnectTree", tree_id))

    def deleteFile(self, share, path):
        self.calls.append(("deleteFile", share, path))
        if self.fail_delete_file:
            raise SessionError(STATUS_ACCESS_DENIED)


class SharePermissionTests(unittest.TestCase):
    def test_default_check_lists_once_and_only_opens_existing_root(self):
        crawler = _build_shrawler(permission_check="read-write")
        client = _MaskClient(granted=(FILE_ADD_FILE,))
        client.listPath = mock.Mock(return_value=[])

        permissions, root_results = crawler.check_share_perm("DATA", client)

        self.assertTrue(permissions["read"])
        self.assertTrue(permissions["write"])
        self.assertEqual(root_results, [])
        client.listPath.assert_called_once_with("DATA", "*", password=None)
        for call in (call for call in client.calls if call[0] == "openFile"):
            self.assertEqual(call[2], "\\")
            self.assertEqual(call[3]["creationDisposition"], FILE_OPEN)
        self.assertFalse(
            any(call[0].startswith(("create", "delete")) for call in client.calls)
        )

    def test_access_masks_are_independent_and_non_mutating(self):
        crawler = _build_shrawler(permission_check="read-write")
        client = _MaskClient(granted=(FILE_ADD_FILE, WRITE_DAC))

        result = crawler._check_share_write_access_masks("DATA", client)

        self.assertEqual(result["write_status"], "allowed")
        self.assertTrue(result["write"])
        self.assertEqual(
            result["write_rights"],
            {
                "generic_write": False,
                "add_file": True,
                "add_subdirectory": False,
                "write_dac": True,
                "write_owner": False,
            },
        )
        self.assertEqual(
            [
                call[3]["desiredAccess"]
                for call in client.calls
                if call[0] == "openFile"
            ],
            [
                GENERIC_WRITE,
                FILE_ADD_FILE,
                FILE_ADD_SUBDIRECTORY,
                WRITE_DAC,
                WRITE_OWNER,
            ],
        )
        self.assertFalse(
            any(call[0].startswith(("create", "delete")) for call in client.calls)
        )
        self.assertEqual(sum(call[0] == "disconnectTree" for call in client.calls), 5)

    def test_all_mask_denials_are_conclusive(self):
        crawler = _build_shrawler(permission_check="read-write")
        result = crawler._check_share_write_access_masks("DATA", _MaskClient())
        self.assertFalse(result["write"])
        self.assertEqual(result["write_status"], "denied")

    def test_unexpected_mask_error_is_unknown_not_denied(self):
        crawler = _build_shrawler(permission_check="read-write")
        result = crawler._check_share_write_access_masks(
            "DATA", _MaskClient(unexpected=(GENERIC_WRITE,))
        )
        self.assertEqual(result["write"], "N/A")
        self.assertEqual(result["write_status"], "unknown")

    def test_non_disk_share_skips_write_probe(self):
        crawler = _build_shrawler(permission_check="read-write")
        client = mock.Mock()
        client.listPath.return_value = []
        permissions, _ = crawler.check_share_perm("IPC$", client, share_type=STYPE_IPC)
        self.assertEqual(permissions["write_status"], "not_applicable")
        client.connectTree.assert_not_called()

    def test_special_flagged_disk_share_is_probed(self):
        crawler = _build_shrawler(permission_check="read-write")
        client = _MaskClient()
        client.listPath = mock.Mock(return_value=[])
        permissions, _ = crawler.check_share_perm(
            "DATA", client, share_type=STYPE_DISKTREE | STYPE_TEMPORARY
        )
        self.assertEqual(permissions["write_status"], "denied")
        self.assertTrue(any(call[0] == "openFile" for call in client.calls))

    def test_empirical_file_and_directory_checks_are_independent(self):
        crawler = _build_shrawler(file_write_check=True)
        client = _EmpiricalClient(fail_directory=True)
        result = crawler._check_share_write_empirically("DATA", client)
        self.assertTrue(result["file_created"])
        self.assertTrue(result["file_deleted"])
        self.assertFalse(result["directory_created"])
        self.assertIsNone(result["directory_deleted"])
        names = [
            call[2]
            for call in client.calls
            if call[0] in {"createFile", "createDirectory"}
        ]
        self.assertTrue(all(name.startswith("shrawler_write_test_") for name in names))

    def test_empirical_cleanup_failure_records_residual_path(self):
        crawler = _build_shrawler(file_write_check=True)
        crawler.current_host = "host"
        with self.assertLogs(level="WARNING"):
            result = crawler._check_share_write_empirically(
                "DATA", _EmpiricalClient(fail_directory=True, fail_delete_file=True)
            )
        self.assertEqual(len(result["residual_artifacts"]), 1)
        self.assertTrue(
            result["residual_artifacts"][0].startswith(
                r"\\host\DATA\shrawler_write_test_"
            )
        )

    def test_tree_output_distinguishes_granular_rights(self):
        output = io.StringIO()
        with redirect_stdout(output):
            print_share_info(
                "DATA",
                "files",
                {
                    "read": True,
                    "write": True,
                    "write_status": "allowed",
                    "write_rights": {
                        "generic_write": False,
                        "add_file": True,
                        "add_subdirectory": True,
                        "write_dac": True,
                        "write_owner": False,
                    },
                },
                4,
            )
        self.assertIn("Write: Files, Subdirs, ACL", output.getvalue())

    def test_csv_preserves_aggregate_and_adds_granular_columns(self):
        with tempfile.TemporaryDirectory() as output_dir:
            crawler = _build_shrawler(output_dir=output_dir, csv_output=True)
            crawler.share_rows = [
                {
                    "host": "host",
                    "share_name": "DATA",
                    "comment": "",
                    "read_permission": True,
                    "write_permission": True,
                    "write_status": "allowed",
                    "write_check": "access-mask",
                    "can_add_file": True,
                    "can_add_subdirectory": False,
                    "can_write_dac": False,
                    "can_write_owner": False,
                    "write_verified": False,
                    "cleanup_succeeded": None,
                    "unc_path": r"\\host\DATA",
                    "scan_timestamp_utc": "now",
                }
            ]
            crawler.write_csv_outputs()
            with Path(output_dir, "shrawler_shares.csv").open(newline="") as source:
                row = next(csv.DictReader(source))
            self.assertEqual(row["read_permission"], "True")
            self.assertEqual(row["write_permission"], "True")
            self.assertEqual(row["can_add_file"], "True")
            self.assertEqual(row["write_status"], "allowed")


if __name__ == "__main__":
    unittest.main()
