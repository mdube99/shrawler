import json
import stat
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

try:
    from .test_snaffler_rules import _build_shrawler
except ImportError:
    from test_snaffler_rules import _build_shrawler


class _FileInfo:
    def __init__(self, name, directory=False, content=b"payload"):
        self.name = name
        self.directory = directory
        self.content = content

    def get_longname(self):
        return self.name

    def is_directory(self):
        return self.directory

    def get_filesize(self):
        return len(self.content)

    def get_mtime_epoch(self):
        return 1_700_000_000

    def get_ctime_epoch(self):
        return 1_700_000_000


class _TraversalClient:
    def listPath(self, share, path, password=None):
        del share, password
        if path == "/parent/*":
            return [_FileInfo("at-limit.txt")]
        return []


class _RootTraversalClient:
    def listPath(self, share, path, password=None):
        del share, password
        if path == "/*":
            return [
                _FileInfo("nested", directory=True),
                _FileInfo("root.txt"),
            ]
        return []


class _DownloadClient:
    def __init__(self, content=b"payload", fail=False):
        self.content = content
        self.fail = fail
        self.calls = 0

    def getFile(self, share, remote_path, callback):
        del share, remote_path
        self.calls += 1
        callback(self.content)
        if self.fail:
            raise OSError("interrupted")


class ReliabilityTests(unittest.TestCase):
    def test_share_formatter_returns_row_without_printing(self):
        from shrawler.core import format_share_info

        output = StringIO()
        with redirect_stdout(output):
            row = format_share_info(
                "DATA", "Department data", {"read": True, "write": False}, 6
            )

        self.assertEqual(output.getvalue(), "")
        self.assertIn("DATA", row)
        self.assertIn("Read: Yes", row)
        self.assertIn("Write: No", row)

    def test_concurrent_share_tree_blocks_render_in_completion_order(self):
        import threading

        from shrawler.core import HostRenderResult, ShareDisplay

        crawler = _build_shrawler(
            operating_mode="shares",
            spider=False,
            output_mode="tree",
            workers=2,
        )
        crawler.args.hosts_file = "hosts.txt"
        crawler.args.host = None
        crawler.get_ip_addrs = lambda _: ["host-a", "host-b"]
        crawler.banner = lambda: ""
        crawler.finalize = lambda *args, **kwargs: None
        crawler._checkpoint_state = lambda: None
        crawler._build_scan_summary = lambda: {
            "host_statuses": ["complete", "complete"]
        }
        release_a = threading.Event()
        b_finished = threading.Event()

        def scan_host(_domain, _lmhash, _nthash, host, _name):
            if host == "host-a":
                release_a.wait(timeout=2)
            else:
                b_finished.set()
                release_a.set()
            return HostRenderResult(
                host=host,
                display_name=host,
                status="complete",
                shares=[
                    ShareDisplay(
                        name=f"{host}-share",
                        comment="",
                        permissions={"read": True, "write": False},
                    )
                ],
            )

        crawler._scan_host = scan_host
        output = StringIO()
        with mock.patch("shrawler.core.parse_target", return_value=("", "", "", "")):
            with redirect_stdout(output):
                self.assertEqual(crawler.main(), 0)

        rendered = output.getvalue()
        self.assertTrue(b_finished.is_set())
        self.assertLess(rendered.index("host-b"), rendered.index("host-a"))
        a_block = rendered.split("host-a", 1)[1]
        self.assertIn("host-a-share", a_block)
        self.assertNotIn("host-b-share", a_block)

    def test_host_blocks_use_styled_headers_and_clean_errors(self):
        from shrawler.core import HostRenderResult, Shrawler

        success_block = Shrawler.render_host_block(
            HostRenderResult("10.0.0.1", "fileserver", "complete")
        )
        failure_block = Shrawler.render_host_block(
            HostRenderResult(
                "10.0.0.2",
                "10.0.0.2",
                "connection_failed",
                "connection timed out",
            )
        )

        self.assertIn("[+]", success_block)
        self.assertIn("fileserver (10.0.0.1)", success_block)
        self.assertNotIn("Host:", success_block)
        self.assertIn("[-]", failure_block)
        self.assertIn("10.0.0.2", failure_block)
        self.assertIn("Connection failed:", failure_block)
        self.assertIn("connection timed out", failure_block)

    def test_recursive_tree_uses_one_effective_worker(self):
        crawler = _build_shrawler(
            operating_mode="spider", spider=True, output_mode="tree", workers=4
        )
        self.assertEqual(crawler._effective_worker_count(8), 1)

    def test_non_tree_recursive_view_keeps_concurrency(self):
        crawler = _build_shrawler(
            operating_mode="spider", spider=True, output_mode="progress", workers=4
        )
        self.assertEqual(crawler._effective_worker_count(8), 4)

    def test_shares_mode_disables_spidering(self):
        crawler = _build_shrawler(
            operating_mode="shares", spider=False, output_mode="tree"
        )
        self.assertFalse(crawler.args.spider)
        self.assertEqual(crawler.args.output_mode, "tree")

    def test_spider_mode_enables_spidering(self):
        crawler = _build_shrawler(operating_mode="spider", spider=True)
        self.assertTrue(crawler.args.spider)

    def test_nemesis_delivery_policies(self):
        off = _build_shrawler(nemesis_mode="off")
        matches = _build_shrawler(
            nemesis_mode="matches",
            nemesis_url="https://nemesis/api",
            nemesis_auth="user:pass",
            nemesis_project="test",
        )
        downloads = _build_shrawler(
            nemesis_mode="downloads",
            nemesis_url="https://nemesis/api",
            nemesis_auth="user:pass",
            nemesis_project="test",
        )

        self.assertFalse(off._should_upload_to_nemesis(True))
        self.assertFalse(matches._should_upload_to_nemesis(False))
        self.assertTrue(matches._should_upload_to_nemesis(True))
        self.assertTrue(downloads._should_upload_to_nemesis(False))

    def test_nemesis_queue_retries_and_updates_manifest(self):
        with tempfile.TemporaryDirectory() as output_dir:
            crawler = _build_shrawler(
                output_dir=output_dir,
                nemesis_mode="downloads",
                nemesis_url="https://nemesis/api",
                nemesis_auth="user:pass",
                nemesis_project="test",
                nemesis_retries=1,
            )
            crawler.current_host = "host"
            crawler.scan_results = {
                "host": {"shares": {"DATA": {"downloaded_files": []}}}
            }
            attempts = []

            def submit(*args, **kwargs):
                attempts.append((args, kwargs))
                if len(attempts) == 1:
                    return {
                        "success": False,
                        "response_id": None,
                        "last_error": "temporary",
                    }
                return {
                    "success": True,
                    "response_id": "file-123",
                    "last_error": None,
                }

            crawler.submit_to_nemesis = submit
            with mock.patch("shrawler.core.time.sleep"):
                result = crawler.download_file(
                    _DownloadClient(),
                    "DATA",
                    "/file.txt",
                    "file.txt",
                    "host",
                    7,
                    0,
                    nemesis_upload=True,
                )
                crawler._finish_nemesis_uploads()

            self.assertEqual(result, (True, True))
            state = crawler.scan_results["host"]["shares"]["DATA"]["downloaded_files"][
                0
            ]["nemesis"]
            self.assertEqual(state["status"], "uploaded")
            self.assertEqual(state["attempts"], 2)
            self.assertEqual(state["response_id"], "file-123")

    def test_balanced_profile_defaults(self):
        crawler = _build_shrawler(
            workers=4,
            permission_check="read",
            output_mode="matches",
            snaffler_content_mode="relayed",
        )

        self.assertEqual(crawler.args.workers, 4)
        self.assertEqual(crawler.args.permission_check, "read")
        self.assertEqual(crawler.args.output_mode, "matches")
        self.assertEqual(crawler.args.snaffler_content_mode, "relayed")

    def test_host_workers_use_thread_local_host_context(self):
        class Client:
            def logoff(self):
                return None

        crawler = _build_shrawler(workers=2)
        crawler.username = "user"
        crawler.password = "password"
        crawler.init_smb_session = lambda *args, **kwargs: Client()
        seen = {}

        def get_shares(target, *args, **kwargs):
            seen[target] = crawler.current_host
            return []

        crawler.get_shares = get_shares
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(crawler._scan_host, "", "", "", host, host)
                for host in ("host-a", "host-b")
            ]
            for future in futures:
                future.result()

        self.assertEqual(seen, {"host-a": "host-a", "host-b": "host-b"})

    def test_files_are_processed_at_maximum_depth(self):
        crawler = _build_shrawler(max_depth=1)
        seen = []
        crawler._process_and_display_file = lambda file_info, *args, **kwargs: (
            seen.append(file_info.get_longname())
        )

        crawler.build_tree_structure(
            "/", _FileInfo("parent", directory=True), _TraversalClient(), "DATA"
        )

        self.assertEqual(seen, ["at-limit.txt"])

    def test_zero_depth_processes_root_files_without_recursing(self):
        crawler = _build_shrawler(max_depth=0)
        root_files = []
        directories = []
        crawler._process_and_display_file_root = lambda file_info, *args, **kwargs: (
            root_files.append(file_info.get_longname())
        )
        crawler.build_tree_structure = lambda *args, **kwargs: directories.append(args)

        crawler.spider_shares("host", "DATA", "/", _RootTraversalClient())

        self.assertEqual(root_files, ["root.txt"])
        self.assertEqual(directories, [])

    def test_download_is_atomic_and_records_hash(self):
        with tempfile.TemporaryDirectory() as output_dir:
            crawler = _build_shrawler(output_dir=output_dir)
            crawler.current_host = "host"
            crawler.scan_results = {
                "host": {"shares": {"DATA": {"downloaded_files": []}}}
            }

            result = crawler.download_file(
                _DownloadClient(), "DATA", "/file.txt", "file.txt", "host", 7, 0
            )

            self.assertEqual(result, (True, False))
            downloaded = Path(output_dir, "downloads", "file.txt")
            self.assertEqual(downloaded.read_bytes(), b"payload")
            entry = crawler.scan_results["host"]["shares"]["DATA"]["downloaded_files"][
                0
            ]
            self.assertEqual(len(entry["sha256"]), 64)

    def test_download_reuses_prefetched_snaffler_content(self):
        with tempfile.TemporaryDirectory() as output_dir:
            crawler = _build_shrawler(output_dir=output_dir)
            crawler.current_host = "host"
            crawler.scan_results = {
                "host": {"shares": {"DATA": {"downloaded_files": []}}}
            }
            unc_path = r"\\host\DATA\file.txt"
            crawler._prefetched_content[unc_path] = b"payload"
            client = _DownloadClient()

            result = crawler.download_file(
                client, "DATA", "/file.txt", "file.txt", "host", 7, 0
            )

            self.assertEqual(result, (True, False))
            self.assertEqual(client.calls, 0)
            self.assertEqual(crawler.operation_counts["download_reused_content"], 1)

    def test_permission_check_reuses_root_listing(self):
        class Client:
            def __init__(self):
                self.calls = 0

            def listPath(self, share, path, password=None):
                del share, path, password
                self.calls += 1
                return [_FileInfo("root.txt")]

        crawler = _build_shrawler(permission_check="read")
        client = Client()

        permissions, root_results = crawler.check_share_perm(
            "DATA", client, require_listing=True
        )

        self.assertTrue(permissions["read"])
        self.assertEqual(client.calls, 1)
        self.assertEqual(root_results[0].get_longname(), "root.txt")

    def test_interrupted_download_removes_partial_file(self):
        with tempfile.TemporaryDirectory() as output_dir:
            crawler = _build_shrawler(output_dir=output_dir)
            crawler.current_host = "host"
            crawler.scan_results = {
                "host": {"shares": {"DATA": {"downloaded_files": []}}}
            }

            result = crawler.download_file(
                _DownloadClient(fail=True),
                "DATA",
                "/file.txt",
                "file.txt",
                "host",
                7,
                0,
            )

            self.assertEqual(result, (False, False))
            self.assertEqual(list(Path(output_dir, "downloads").iterdir()), [])

    def test_discovered_files_are_in_json_state_without_csv(self):
        crawler = _build_shrawler(csv_output=False)
        crawler.scan_results = {
            "host": {"status": "complete", "error": None, "shares": {}}
        }

        crawler._record_discovered_file(
            "host", "DATA", "/file.txt", r"\\host\DATA\file.txt", "file.txt", 7, 0
        )

        files = crawler.scan_results["host"]["shares"]["DATA"]["discovered_files"]
        self.assertEqual(files[0]["file_name"], "file.txt")
        self.assertEqual(crawler.file_rows, [])

    def test_json_output_is_schema_versioned_and_private(self):
        with tempfile.TemporaryDirectory() as output_dir:
            crawler = _build_shrawler(output_dir=output_dir, json_output=True)
            crawler.scan_results = {
                "host": {
                    "status": "complete",
                    "error": None,
                    "shares": {},
                }
            }

            output_path = crawler.write_json_output()
            payload = json.loads(output_path.read_text())

            self.assertEqual(payload["_schema"]["version"], 3)
            self.assertEqual(payload["_summary"]["hosts_attempted"], 1)
            self.assertEqual(stat.S_IMODE(output_path.stat().st_mode), 0o600)

    def test_scan_summary_counts_host_outcomes_and_permissions(self):
        crawler = _build_shrawler()
        crawler.scan_results = {
            "good": {
                "status": "complete",
                "shares": {
                    "DATA": {
                        "permissions": {"read": True, "write": False},
                    }
                },
            },
            "closed": {"status": "port_closed", "shares": {}},
        }

        summary = crawler._build_scan_summary()

        self.assertEqual(summary["hosts_attempted"], 2)
        self.assertEqual(summary["host_statuses"], {"complete": 1, "port_closed": 1})
        self.assertEqual(summary["readable_shares"], 1)


if __name__ == "__main__":
    unittest.main()
