import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from shrawler.collection import CollectionQueue
from shrawler.coverage import SavedEntry, main as coverage_main
from shrawler.store import ScanStore
from shrawler.triage.review import ReviewStore, family_key
from shrawler.triage.rules import load
from shrawler.triage.storage import list_results, rank

from .test_snaffler_rules import _build_shrawler
from .test_triage import metadata


class DirectoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = ScanStore(self.root, "spider")
        self.store.upsert_host("server", "server", "scanning")
        self.store.upsert_share("server", "DATA", "scanning", {})
        self.crawler = _build_shrawler(directory_budget=1, max_depth=4)
        self.crawler.store = self.store
        self.crawler.current_host = "server"
        self.crawler._thread_context.resume_paths = set()
        self.client = unittest.mock.Mock()
        self.client.listPath.return_value = [SavedEntry("child.txt", False, 4, 1)]
        self.entries = [
            SavedEntry("child", True, 0, 1),
            SavedEntry("root.txt", False, 4, 1),
        ]

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_budget_persists_pending_and_resume_reuses_root_listing(self):
        self.crawler.spider_shares("server", "DATA", "/", self.client, self.entries)
        self.client.listPath.assert_not_called()
        rows = self.store.connection.execute(
            "SELECT path,status FROM directory_work ORDER BY path"
        ).fetchall()
        self.assertEqual(
            [tuple(row) for row in rows], [("/", "complete"), ("/child", "pending")]
        )
        self.assertEqual(self.store.summary_counts()["files_seen"], 1)
        self.store.upsert_host("server", "server", "complete")
        self.store.upsert_share("server", "DATA", "complete", {})
        self.assertEqual(self.store.host_status("server"), "partial")
        self.assertEqual(self.store.share_status("server", "DATA"), "partial")
        self.store.finish("completed", {})
        self.assertEqual(
            self.store.connection.execute("SELECT status FROM scans").fetchone()[0],
            "partial",
        )
        scan_id = self.store.scan_id
        self.store.close()
        self.store = ScanStore(self.root, "spider", resume=scan_id)
        self.crawler.store = self.store
        self.crawler._directory_listings = 0
        self.crawler._thread_context.resume_paths = self.store.existing_paths(
            "server", "DATA"
        )
        self.crawler.spider_shares("server", "DATA", "/", self.client)
        self.client.listPath.assert_called_once_with("DATA", "/child/*", password=None)
        self.assertFalse(self.store.coverage.outstanding())
        self.assertEqual(self.store.summary_counts()["files_seen"], 2)
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(
                coverage_main([str(self.store.path), "--view", "covered"]), 0
            )
        self.assertEqual(json.loads(output.getvalue())["total"], 2)

    def test_depth_exclusions_and_listing_failure_are_visible(self):
        self.crawler.args.max_depth = 0
        self.crawler.spider_shares("server", "DATA", "/", self.client, self.entries)
        row = self.store.connection.execute(
            "SELECT status FROM directory_work WHERE path='/child'"
        ).fetchone()
        self.assertEqual(row[0], "depth_limit")
        self.crawler.args.max_depth = 1
        self.crawler.args.directory_budget = None
        self.client.listPath.side_effect = OSError("access denied")
        self.crawler._thread_context.resume_paths = self.store.existing_paths(
            "server", "DATA"
        )
        self.crawler.spider_shares("server", "DATA", "/", self.client)
        row = self.store.connection.execute(
            "SELECT status,error FROM directory_work WHERE path='/child'"
        ).fetchone()
        self.assertEqual(tuple(row), ("failed", "access denied"))

    def test_cached_listing_survives_file_processing_interruption(self):
        with patch.object(
            self.crawler, "_process_and_display_file", side_effect=KeyboardInterrupt
        ):
            with self.assertRaises(KeyboardInterrupt):
                self.crawler.spider_shares(
                    "server", "DATA", "/", self.client, self.entries
                )
        self.assertIsNotNone(self.store.coverage.cached("server", "DATA", "/"))
        self.assertTrue(self.store.coverage.outstanding())
        self.client.listPath.assert_not_called()

    def test_expansion_is_case_insensitive(self):
        self.crawler.args.directory_budget = None
        self.crawler.args.expand_directory = ["/CHILD"]
        self.crawler.spider_shares("server", "DATA", "/", self.client, self.entries)
        self.client.listPath.assert_called_once_with("DATA", "/child/*", password=None)
        self.assertFalse(self.store.coverage.outstanding())

    def test_resume_identity_cannot_be_changed(self):
        self.store.finish("interrupted", {})
        scan = self.store.scan_id
        self.store.close()
        with self.assertRaisesRegex(ValueError, "original domain and username"):
            ScanStore(self.root, "spider", username="different-user", resume=scan)
        self.store = ScanStore(self.root, "spider", resume=scan)


class FamilyReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.database = self.root / "shrawler.db"
        store = ScanStore(self.root, "spider")
        store.upsert_host("server", "server", "complete")
        store.upsert_share("server", "DATA", "complete", {})
        for index in range(20):
            store.add_file(
                "server",
                "DATA",
                metadata(f"/reports/report-2026-{index:02}.csv", size=4),
            )
        store.add_file("server", "DATA", metadata("/reports/passwords.config", size=4))
        store.finish("completed", {})
        self.scan = store.scan_id
        store.close()
        self.review = ReviewStore(self.database)

    def tearDown(self):
        self.tmp.cleanup()

    def test_grouping_scoped_feedback_undo_and_immutable_ranking(self):
        with patch("socket.socket", side_effect=AssertionError("network")):
            built = self.review.build()
            self.assertEqual(built["families"], 2)
            families = self.review.families(self.scan)["items"]
            self.assertEqual(families[0]["file_count"], 20)
            group = families[0]["family_id"]
            members = self.review.families(self.scan, family_id=group)["items"]
            self.assertEqual(len(members), 20)
            event = self.review.decide("family", group, "exclude")
            file_id = members[0]["file_id"]
            override = self.review.decide(
                "file", file_id, "relevant", "assessment priority"
            )
            run = rank(self.database, load())
            result = list_results(self.database, run["run_id"])
            first = result["items"][0]
            self.assertEqual(first["file_id"], file_id)
            self.assertEqual(first["priority"], 100)
            self.assertEqual(first["review"]["id"], override["event_id"])
            self.assertEqual(
                sum(
                    (i["review"] or {}).get("disposition") == "exclude"
                    for i in result["items"]
                ),
                19,
            )
            manifest = CollectionQueue(self.database).create(run_id=run["run_id"])
            self.assertEqual(
                sum(i["status"] == "excluded_review" for i in manifest["items"]), 19
            )
            self.review.undo(override["event_id"])
            self.review.undo(event["event_id"])
            fresh = rank(self.database, load())
            self.assertTrue(
                all(
                    i["review"] is None
                    for i in list_results(self.database, fresh["run_id"])["items"]
                )
            )
            self.assertEqual(
                list_results(self.database, run["run_id"])["items"][0]["priority"], 100
            )

    def test_rarity_explains_observed_population_and_local_hashes(self):
        run = rank(self.database, load())
        item = list_results(self.database, run["run_id"])["items"][0]
        rarity = next(
            s for s in item["signals"] if s["rule_id"] == "builtin.rare-extension"
        )
        self.assertEqual(rarity["evidence"]["observed_files"], 21)
        self.assertEqual(rarity["evidence"]["same_extension"], 1)
        queue = CollectionQueue(self.database)
        manifest = queue.create(limit=2)
        queue.run(manifest["id"], lambda item, sink: sink(b"same"))
        with patch("socket.socket", side_effect=AssertionError("network")):
            result = self.review.hashes()
        self.assertEqual(result["hashed_files"], 2)
        self.assertEqual(result["duplicates"][0]["copies"], 2)

    def test_families_do_not_cross_hosts_shares_or_nonnumeric_paths(self):
        first = metadata("/reports/report-2026.csv")
        self.assertEqual(
            family_key(first), family_key(metadata("/reports/report-2025.csv"))
        )
        for other in (
            metadata("/other/report-2025.csv"),
            metadata("/reports/report-2025.csv", host="other"),
            metadata("/reports/report-2025.csv", share="OTHER"),
        ):
            self.assertNotEqual(family_key(first), family_key(other))

    def test_financial_and_customer_categories(self):
        from shrawler.triage.engine import Engine

        engine = Engine(load())
        self.assertEqual(
            engine.evaluate(metadata("/payroll.xlsx"))["category_scores"][
                "financial-data"
            ],
            25,
        )
        self.assertEqual(
            engine.evaluate(metadata("/customers.csv"))["category_scores"][
                "customer-information"
            ],
            25,
        )
