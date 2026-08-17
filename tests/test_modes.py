import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from shrawler import cli, report


class OperatingModeTests(unittest.TestCase):
    def _mode_help(self, mode):
        output = io.StringIO()
        with redirect_stdout(output):
            cli.main([mode, "--help"])
        return output.getvalue()

    def test_shares_help_only_shows_share_relevant_options(self):
        help_text = self._mode_help("shares")

        self.assertIn("--policy", help_text)
        self.assertIn("--format", help_text)
        self.assertIn("--view", help_text)
        self.assertIn("--output-mode", help_text)
        self.assertNotIn("--download", help_text)
        self.assertNotIn("--nemesis", help_text)
        self.assertNotIn("--rules", help_text)

    def test_spider_help_includes_acquisition_but_not_snaffler(self):
        help_text = self._mode_help("spider")

        self.assertIn("--download", help_text)
        self.assertIn("--limits", help_text)
        self.assertIn("--view", help_text)
        self.assertIn("--nemesis", help_text)
        self.assertNotIn("--rules", help_text)

    def test_snaffle_help_includes_rules_and_content_controls(self):
        help_text = self._mode_help("snaffle")

        self.assertIn("--rules", help_text)
        self.assertIn("--interest", help_text)
        self.assertIn("--nemesis", help_text)

    def test_spider_command_translates_to_operating_mode(self):
        with mock.patch.object(cli, "scan_main") as scan_main:
            cli.main(["spider", "user@host", "--output-mode", "summary"])

        scan_main.assert_called_once_with()
        self.assertEqual(sys.argv[1], "user@host")
        self.assertEqual(
            sys.argv[sys.argv.index("--output-mode") + 1], "summary"
        )
        self.assertEqual(
            sys.argv[sys.argv.index("--operating-mode") + 1], "spider"
        )

    def test_legacy_syntax_still_dispatches_to_scanner(self):
        with mock.patch.object(cli, "scan_main") as scan_main:
            cli.main(["user@host", "--spider"])

        scan_main.assert_called_once_with()

    def test_report_retries_failed_upload_and_updates_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            local_file = root / "downloads" / "evidence.txt"
            local_file.parent.mkdir()
            local_file.write_bytes(b"evidence")
            results_path = root / "shrawler_results.json"
            results_path.write_text(
                json.dumps(
                    {
                        "_summary": {
                            "hosts_attempted": 1,
                            "shares_enumerated": 1,
                            "files_seen": 1,
                        },
                        "host": {
                            "shares": {
                                "DATA": {
                                    "downloaded_files": [
                                        {
                                            "host": "host",
                                            "share": "DATA",
                                            "remote_path": "/evidence.txt",
                                            "unc_path": r"\\host\DATA\evidence.txt",
                                            "local_filename": "evidence.txt",
                                            "local_path": str(local_file),
                                            "mtime_epoch": 0,
                                            "nemesis": {"status": "failed"},
                                        }
                                    ]
                                }
                            }
                        },
                    }
                )
            )

            with mock.patch.object(
                report,
                "_upload_file",
                return_value={
                    "success": True,
                    "response_id": "file-123",
                    "error": None,
                },
            ):
                exit_code = report.main(
                    [
                        str(results_path),
                        "--retry-failed",
                        "--nemesis-url",
                        "https://nemesis/api",
                        "--nemesis-auth",
                        "user:pass",
                        "--nemesis-project",
                        "test",
                        "--nemesis-retries",
                        "0",
                    ]
                )

            updated = json.loads(results_path.read_text())
            state = updated["host"]["shares"]["DATA"]["downloaded_files"][0][
                "nemesis"
            ]
            self.assertEqual(exit_code, 0)
            self.assertEqual(state["status"], "uploaded")
            self.assertEqual(state["response_id"], "file-123")


if __name__ == "__main__":
    unittest.main()
