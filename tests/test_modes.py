import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from shrawler import cli, report
from shrawler.smb import SMBAuth


class OperatingModeTests(unittest.TestCase):
    def _mode_help(self, mode):
        output = io.StringIO()
        with redirect_stdout(output):
            cli.main([mode, "--help"])
        return output.getvalue()

    def test_shares_help_only_shows_share_relevant_options(self):
        help_text = self._mode_help("shares")

        self.assertIn("--format", help_text)
        self.assertIn("--view", help_text)
        self.assertIn("--output-mode", help_text)
        self.assertNotIn("--download-ext", help_text)
        self.assertNotIn("--nemesis-url", help_text)
        self.assertNotIn("--rules", help_text)

    def test_spider_help_includes_acquisition_but_not_snaffler(self):
        help_text = self._mode_help("spider")

        self.assertIn("--download-ext", help_text)
        self.assertIn("--limits", help_text)
        self.assertIn("--view", help_text)
        self.assertIn("--nemesis-url", help_text)
        self.assertNotIn("--rules", help_text)

    def test_snaffle_help_includes_rules_and_content_controls(self):
        help_text = self._mode_help("snaffle")

        self.assertIn("--rules", help_text)
        self.assertIn("--interest", help_text)
        self.assertIn("--nemesis-url", help_text)

    def test_top_level_help_describes_commands(self):
        output = io.StringIO()
        with redirect_stdout(output):
            cli.main(["--help"])
        help_text = output.getvalue()
        self.assertIn("shares    Enumerate shares", help_text)
        self.assertIn("examples:", help_text)

    def test_config_help_exits_successfully(self):
        for option in ("--help", "-h"):
            output = io.StringIO()
            with redirect_stdout(output), self.assertRaises(SystemExit) as context:
                cli.main(["config", option])
            self.assertEqual(context.exception.code, 0)
            self.assertIn("persistent TOML configuration", output.getvalue())

    def test_spider_command_translates_to_operating_mode(self):
        with mock.patch.object(cli, "scan_main") as scan_main:
            cli.main(["spider", "user@host", "-no-pass", "--output-mode", "summary"])

        scan_main.assert_called_once()
        options = scan_main.call_args.args[0]
        self.assertEqual(options.target, "user@host")
        self.assertEqual(options.output_mode, "summary")
        self.assertEqual(options.operating_mode, "spider")
        self.assertIsInstance(scan_main.call_args.args[1], SMBAuth)

    def test_legacy_syntax_still_dispatches_to_scanner(self):
        with mock.patch.object(cli, "scan_main") as scan_main:
            cli.main(["user@host", "--spider", "-no-pass"])

        scan_main.assert_called_once()

    def test_web_command_passes_normalized_config_and_auth(self):
        with mock.patch("shrawler.web.run", return_value=0) as run:
            with self.assertRaises(SystemExit) as context:
                cli.main(
                    [
                        "web",
                        "results.json",
                        "DOMAIN/user@dc",
                        "-no-pass",
                        "--preview-max-size",
                        "2MiB",
                    ]
                )

        self.assertEqual(context.exception.code, 0)
        config, auth = run.call_args.args
        self.assertEqual(config.results_path, Path("results.json"))
        self.assertEqual(config.preview_max_bytes, 2 * 1024**2)
        self.assertFalse(config.token_auth)
        self.assertEqual(auth.domain, "DOMAIN")
        self.assertEqual(auth.target_host, "dc")

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
            state = updated["host"]["shares"]["DATA"]["downloaded_files"][0]["nemesis"]
            self.assertEqual(exit_code, 0)
            self.assertEqual(state["status"], "uploaded")
            self.assertEqual(state["response_id"], "file-123")


if __name__ == "__main__":
    unittest.main()
