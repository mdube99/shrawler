import unittest

from shrawler.cli import _compact_arguments, _parse_size, _scan_parser


class CompactCliTests(unittest.TestCase):
    def test_human_readable_sizes(self):
        self.assertEqual(_parse_size("20MB"), 20_000_000)
        self.assertEqual(_parse_size("2 GiB"), 2 * 1024**3)

    def test_shares_compact_options_translate_to_legacy_interface(self):
        arguments = _compact_arguments(
            "shares",
            [
                "user@host",
                "--profile", "quiet",
                "--share", "Finance",
                "--share", "HR",
                "--exclude-share", "Archive",
                "--format", "all",
                "--view", "tree",
                "-o", "results",
            ],
        )
        self.assertIn("--scan-profile", arguments)
        self.assertIn("Finance,HR", arguments)
        self.assertIn("Archive", arguments)
        self.assertIn("--csv-output", arguments)
        self.assertIn("--json-output", arguments)
        self.assertIn("--output-mode", arguments)
        self.assertIn("tree", arguments)
        self.assertIn("results", arguments)

    def test_spider_limits_and_nemesis_translate(self):
        arguments = _compact_arguments(
            "spider",
            [
                "user@host",
                "--download", ".docx,.xlsx",
                "--max-file-size", "20MB",
                "--download-budget", "1GiB",
                "--nemesis", "https://nemesis/api",
            ],
        )
        self.assertIn("20000000", arguments)
        self.assertIn(str(1024**3), arguments)
        self.assertIn("--nemesis-mode", arguments)
        self.assertIn("downloads", arguments)

    def test_snaffle_uses_short_rule_options(self):
        arguments = _compact_arguments(
            "snaffle", ["user@host", "--rules", "rules", "--interest", "2"]
        )
        self.assertIn("--snaffler-rules-dir", arguments)
        self.assertIn("rules", arguments)
        self.assertIn("--snaffler-interest-level", arguments)
        self.assertIn("2", arguments)

    def test_legacy_options_bypass_translation(self):
        self.assertIsNone(
            _compact_arguments("spider", ["user@host", "--workers", "12"])
        )

    def test_snaffle_requires_rules_in_compact_interface(self):
        with self.assertRaises(SystemExit):
            _scan_parser("snaffle").parse_args(["user@host"])


if __name__ == "__main__":
    unittest.main()
