import tempfile
import unittest
from pathlib import Path

from shrawler.cli import _parse_size, _scan_parser, parse_scan_options


class CanonicalCliTests(unittest.TestCase):
    def test_human_readable_sizes(self):
        self.assertEqual(_parse_size("20MB"), 20_000_000)
        self.assertEqual(_parse_size("2 GiB"), 2 * 1024**3)

    def test_host_composes_with_modern_and_advanced_options(self):
        options = parse_scan_options(
            "spider",
            ["user@embedded", "--host", "explicit", "--view", "summary",
             "--profile", "quiet", "--workers", "12", "--format", "all",
             "--output", "results", "--download", ".docx", "--download-budget", "1GiB"],
            {},
        )
        self.assertEqual(options.host, "explicit")
        self.assertEqual(options.output_mode, "summary")
        self.assertEqual(options.workers, 12)
        self.assertTrue(options.csv_output)
        self.assertTrue(options.json_output)
        self.assertEqual(options.max_total_download, 1024**3)

    def test_hosts_file_composes_with_view(self):
        with tempfile.TemporaryDirectory() as tmp:
            hosts = Path(tmp) / "hosts.txt"
            hosts.write_text("# comment\nserver1\n\nserver2 # note\n")
            options = parse_scan_options("spider", ["user", "--hosts-file", str(hosts), "--view", "progress"], {})
        self.assertEqual(options.output_mode, "progress")

    def test_host_sources_are_mutually_exclusive(self):
        with self.assertRaises(SystemExit):
            _scan_parser("spider").parse_args(["user@host", "--host", "one", "--hosts-file", "hosts"])

    def test_empty_hosts_file_fails_before_scanning(self):
        with tempfile.TemporaryDirectory() as tmp:
            hosts = Path(tmp) / "hosts.txt"
            hosts.write_text("# only comments\n")
            with self.assertRaises(SystemExit):
                parse_scan_options("spider", ["user", "--hosts-file", str(hosts)], {})

    def test_config_precedence_cli_then_toml_then_environment(self):
        options = parse_scan_options("spider", ["user@host", "--profile", "fast", "--nemesis", "cli"], {"profile": "quiet", "nemesis": {"url": "toml"}})
        self.assertEqual(options.scan_profile, "fast")
        self.assertEqual(options.nemesis_url, "cli")

    def test_compatibility_aliases_normalize(self):
        options = parse_scan_options("snaffle", ["user@host", "--scan-profile", "quiet", "--output-mode", "matches", "--shares", "A,B", "--skip-share", "C", "--snaffler-rules-dir", "rules", "--snaffler-interest-level", "2"], {})
        self.assertEqual(options.scan_profile, "quiet")
        self.assertEqual(options.shares, "A,B")
        self.assertEqual(options.skip_share, "C")
        self.assertEqual(options.snaffler_rules_dir, "rules")

    def test_help_is_complete_and_has_no_advanced_help(self):
        help_text = _scan_parser("snaffle").format_help()
        self.assertIn("target selection", help_text)
        self.assertIn("downloads and content analysis", help_text)
        self.assertIn("Snaffler", help_text)
        self.assertIn("--workers", help_text)
        self.assertNotIn("help-advanced", help_text)


if __name__ == "__main__":
    unittest.main()
