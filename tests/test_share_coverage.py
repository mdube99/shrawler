import unittest

from shrawler.core import STYPE_DISKTREE

from .test_snaffler_rules import _build_shrawler


class _ShareClient:
    def __init__(self, *names):
        self.shares = [
            {"shi1_netname": name, "shi1_remark": "", "shi1_type": STYPE_DISKTREE}
            for name in names
        ]

    def listShares(self):
        return self.shares


class ShareCoverageTests(unittest.TestCase):
    def _crawler(self, **kwargs):
        crawler = _build_shrawler(**kwargs)
        crawler.check_share_perm = lambda *args, **kwargs: (
            {"read": True, "write": False},
            [],
        )
        return crawler

    def test_selected_administrative_share_overrides_default_exclusion(self):
        crawler = self._crawler(shares="SYSVOL", spider=False, output_mode="tree")
        displayed = crawler.get_shares(
            "host",
            "host",
            _ShareClient("SYSVOL", "DATA"),
            ["SYSVOL"],
            desired_share="sysvol",
        )
        self.assertEqual([share.name for share in displayed], ["SYSVOL"])
        self.assertEqual(
            crawler.skipped_shares["host"],
            [("DATA", "not selected by --share/--shares")],
        )

    def test_explicit_exclusion_wins_over_requested_share(self):
        crawler = self._crawler(skip_share="sysvol")
        displayed = crawler.get_shares(
            "host", "host", _ShareClient("SYSVOL"), ["SYSVOL"], desired_share="SYSVOL"
        )
        self.assertEqual(displayed, [])
        self.assertEqual(
            crawler.scan_results["host"]["shares"]["SYSVOL"]["skip_reason"],
            "explicitly excluded",
        )

    def test_default_exclusion_is_persisted_with_reason(self):
        crawler = self._crawler()
        crawler.get_shares(
            "host", "host", _ShareClient("C$", "DATA"), ["C$"], desired_share=""
        )
        skipped = crawler.scan_results["host"]["shares"]["C$"]
        self.assertEqual(skipped["status"], "skipped")
        self.assertEqual(
            skipped["skip_reason"], "administrative share (default exclusion)"
        )

    def test_snaffler_discard_is_persisted_with_reason(self):
        crawler = self._crawler()
        crawler.snaffler_enabled = True
        crawler._evaluate_snaffler_share = lambda *args: (True, [])
        crawler.get_shares("host", "host", _ShareClient("DATA"), [])
        skipped = crawler.scan_results["host"]["shares"]["DATA"]
        self.assertEqual(skipped["status"], "skipped")
        self.assertEqual(skipped["skip_reason"], "Snaffler share discard rule")

    def test_add_share_removes_only_builtin_exclusion(self):
        crawler = self._crawler(add_share="c$", skip_share="Print$")
        crawler._configure_share_exclusions()
        excluded = {name.casefold() for name in crawler.normal_shares}
        self.assertNotIn("c$", excluded)
        self.assertIn("print$", excluded)

    def test_include_all_keeps_explicit_exclusion(self):
        crawler = self._crawler(include_all_shares=True, skip_share="SYSVOL")
        crawler._configure_share_exclusions()
        self.assertEqual(crawler.normal_shares, ["SYSVOL"])


if __name__ == "__main__":
    unittest.main()
