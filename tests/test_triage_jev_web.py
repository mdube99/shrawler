"""WebUI integration for the model-assisted assessment path."""

import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional
from unittest.mock import patch

from shrawler.store import ScanStore
from shrawler.triage.jev.config import JevConfig
from shrawler.triage.jev.service import JevBusyError, JevService
from shrawler.web import DatabaseIndex, WebServer, WebState

from .test_triage import metadata


def fake_decide(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Minimal System One response builder used to avoid live gateway calls."""
    from shrawler.triage.jev.client import Answer, DecisionResponse

    answers = {
        file_id: Answer(file_id=file_id, choice="3", distribution={"3": 0.9})
        for file_id in payload.get("questions", {})
    }
    return DecisionResponse(
        answers=answers,
        usage={"input_tokens": 1},
        model="jev-fake",
        http_status=200,
        latency_ms=1,
    )


class AssessmentHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database = self.root / "shrawler.db"
        scan = ScanStore(self.root, "spider")
        scan.upsert_host("server", "server", "complete")
        scan.upsert_share("server", "DATA", "complete", {})
        for payload in (
            metadata("/Finance/Payroll/export.csv"),
            metadata("/Finance/Payroll/readme.txt", size=1024),
        ):
            scan.add_file("server", "DATA", payload)
        scan.finish("completed", {})
        scan.close()
        config = JevConfig.from_mapping(
            {"endpoint": "https://example.test/v1/systemone", "model": "jev-fake"}
        )
        self.service = JevService(self.database, self.root, config)
        self.state = WebState(
            DatabaseIndex(self.database),
            None,
            "token",
            1024,
            1024,
            self.root,
            threading.BoundedSemaphore(2),
            None,
            self.service,
        )
        self.server = WebServer(("127.0.0.1", 0), self.state)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.service.close()
        self.temporary.cleanup()

    def request(
        self,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        values = {"Authorization": "Bearer token"}
        if payload is not None:
            values.update(
                {
                    "Content-Type": "application/json",
                    "X-Shrawler-Request": "1",
                    "Origin": self.base,
                }
            )
        values.update(headers or {})
        request = urllib.request.Request(
            self.base + path,
            data=json.dumps(payload).encode() if payload is not None else None,
            headers=values,
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read())

    def finished_job(self) -> Dict[str, Any]:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            job = self.request("/api/assessment/job")["job"]
            if job and job["status"] != "running":
                return job
            time.sleep(0.02)
        self.fail("assessment job did not finish")

    def test_prepare_run_coverage_and_results(self) -> None:
        self.assertTrue(self.request("/api/status")["assessment_enabled"])
        catalog = self.request("/api/assessment/catalog")
        self.assertEqual(len(catalog["scans"]), 1)
        self.assertEqual(catalog["model"], "jev-fake")
        with patch("shrawler.triage.jev.client.JevClient.decide", side_effect=fake_decide), patch(
            "shrawler.triage.jev.client.JevClient.count_tokens", return_value=8
        ):
            job = self.request(
                "/api/assessment/jobs",
                {"scan_id": None, "prepare": True, "budget_seconds": 0},
            )
            self.assertEqual(job["status"], "running")
            finished = self.finished_job()
        self.assertEqual(finished["status"], "completed", finished)
        run_id = finished["assessment_run_id"]
        coverage = self.request(f"/api/assessment/status?run={run_id}")
        self.assertEqual(coverage["assessed"], 2)
        self.assertTrue(coverage["reconciled"])
        results = self.request(f"/api/assessment/files?run={run_id}")
        self.assertEqual(len(results["items"]), 2)
        self.assertEqual(results["items"][0]["choice"], "3")
        self.assertEqual(results["items"][0]["priority"], 3)
        self.assertEqual(results["items"][0]["priority_name"], "Strong")
        by_directory = self.request(f"/api/assessment/coverage?run={run_id}")
        self.assertEqual(len(by_directory["directories"]), 1)

    def test_missed_filter_returns_zero_priority_high_value(self) -> None:
        # A directory the deterministic rules leave at zero priority.
        from shrawler.store import ScanStore

        store = ScanStore(self.root, "spider")
        store.upsert_host("server", "DATA", "complete")
        store.upsert_share("server", "DATA", "complete", {})
        for payload in (
            metadata("/misc/alpha.csv"),
            metadata("/misc/beta.txt", size=512),
        ):
            store.add_file("server", "DATA", payload)
        store.finish("completed", {})
        store.close()
        with patch("shrawler.triage.jev.client.JevClient.decide", side_effect=fake_decide), patch(
            "shrawler.triage.jev.client.JevClient.count_tokens", return_value=8
        ):
            self.request("/api/assessment/jobs", {"scan_id": store.scan_id, "prepare": True})
            finished = self.finished_job()
        run_id = finished["assessment_run_id"]
        missed = self.request(f"/api/assessment/files?run={run_id}&missed=1")
        self.assertEqual(len(missed["items"]), 2)
        # Paging the missed view must advance, not repeat page one.
        first = self.request(f"/api/assessment/files?run={run_id}&missed=1&limit=1")
        second = self.request(
            f"/api/assessment/files?run={run_id}&missed=1&limit=1&offset=1"
        )
        self.assertEqual(len(first["items"]), 1)
        self.assertEqual(len(second["items"]), 1)
        self.assertNotEqual(first["items"][0]["file_id"], second["items"][0]["file_id"])

    def test_disabled_configuration_hides_assessment(self) -> None:
        # [jev] enabled defaults to false and must gate the WebUI surface.
        config = JevConfig.from_mapping({})
        self.assertFalse(config.enabled)
        state = WebState(
            DatabaseIndex(self.database),
            None,
            "token",
            1024,
            1024,
            self.root,
            threading.BoundedSemaphore(2),
            None,
            None,
        )
        server = WebServer(("127.0.0.1", 0), state)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            request = urllib.request.Request(
                base + "/api/status", headers={"Authorization": "Bearer token"}
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                self.assertFalse(json.loads(response.read())["assessment_enabled"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_busy_and_untrusted_requests(self) -> None:
        with patch.object(self.service, "start", side_effect=JevBusyError("busy")):
            with self.assertRaises(urllib.error.HTTPError) as failure:
                self.request("/api/assessment/jobs", {"prepare": True})
            self.assertEqual(failure.exception.code, 409)
        # A request missing the local-request header is rejected.
        with self.assertRaises(urllib.error.HTTPError):
            self.request(
                "/api/assessment/jobs",
                {"prepare": True},
                {"X-Shrawler-Request": ""},
            )

    def test_page_and_assets_served(self) -> None:
        for path, marker in (
            ("/assessment", b"Model-assisted assessment"),
            ("/assets/assessment.js", b"/api/assessment/jobs"),
            ("/assets/assessment.css", b"coverage-directories"),
        ):
            request = urllib.request.Request(self.base + path, headers={"Authorization": "Bearer token"})
            with urllib.request.urlopen(request, timeout=5) as response:
                self.assertEqual(response.status, 200)
                self.assertIn(marker, response.read())


class CombinedPriorityHttpTests(AssessmentHttpTests):
    """The combined metric blends a saved ranking with an assessment run."""

    def setUp(self) -> None:
        super().setUp()
        from shrawler.triage.service import TriageService

        # The inherited state only carries the Jev service; add a triage
        # service so a ranking run can be created over HTTP too.
        self.triage = TriageService(self.database, self.root)
        self.state.triage = self.triage

    def tearDown(self) -> None:
        self.triage.close()
        super().tearDown()

    def _run_ranking(self) -> str:
        self.request("/api/triage/jobs", {"preview": False})
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            job = self.request("/api/triage/job")["job"]
            if job["status"] != "running":
                self.assertEqual(job["status"], "completed", job)
                return job["result"]["run_id"]
            time.sleep(0.01)
        self.fail("ranking job did not finish")

    def _run_assessment(self) -> str:
        with patch(
            "shrawler.triage.jev.client.JevClient.decide", side_effect=fake_decide
        ), patch(
            "shrawler.triage.jev.client.JevClient.count_tokens", return_value=8
        ):
            self.request("/api/assessment/jobs", {"scan_id": None, "prepare": True})
            finished = self.finished_job()
        return finished["assessment_run_id"]

    def test_combined_score_requires_a_component(self) -> None:
        inventory = self.request("/api/files?limit=10")
        self.assertTrue(inventory["items"])
        for item in inventory["items"]:
            self.assertIsNone(item["combined_score"])
            self.assertEqual(item["combined_coverage"], "none")

    def test_combined_blends_ranking_and_jev(self) -> None:
        run_id = self._run_ranking()
        jev_run = self._run_assessment()
        inventory = self.request(
            f"/api/files?ranking_run={run_id}&jev_run={jev_run}&limit=10"
        )
        self.assertTrue(inventory["items"])
        for item in inventory["items"]:
            self.assertEqual(item["combined_coverage"], "both", item)
            self.assertIsNotNone(item["combined_score"])
            expected = round(
                100
                * (
                    0.5 * min(item["ranking_score"] / 80, 1.0)
                    + 0.5 * min(max(item["jev_score"], 0), 4) / 4.0
                )
            )
            self.assertEqual(item["combined_score"], expected, item)
            # Sorting and the shown number are produced by the same arithmetic.
            self.assertLessEqual(0, item["combined_score"])
            self.assertLessEqual(item["combined_score"], 100)

    def test_combined_sort_is_descending_by_default(self) -> None:
        run_id = self._run_ranking()
        jev_run = self._run_assessment()
        items = self.request(
            f"/api/files?ranking_run={run_id}&jev_run={jev_run}&sort=combined&limit=10"
        )["items"]
        scores = [item["combined_score"] for item in items]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_ranking_only_fills_the_full_scale(self) -> None:
        run_id = self._run_ranking()
        items = self.request(
            f"/api/files?ranking_run={run_id}&limit=10"
        )["items"]
        for item in items:
            self.assertEqual(item["combined_coverage"], "rules", item)
            self.assertEqual(
                item["combined_score"],
                round(100 * min(item["ranking_score"] / 80, 1.0)),
                item,
            )

    def test_tree_branch_carries_combined_score(self) -> None:
        run_id = self._run_ranking()
        jev_run = self._run_assessment()
        branch = self.request(
            f"/api/tree/branch?host=server&share=DATA&parent=/Finance/Payroll"
            f"&ranking_run={run_id}&jev_run={jev_run}"
        )
        self.assertTrue(branch["files"])
        for item in branch["files"]:
            self.assertEqual(item["combined_coverage"], "both", item)
            self.assertIsNotNone(item["combined_score"])


if __name__ == "__main__":
    unittest.main()
