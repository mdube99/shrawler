"""Offline ranking API integration and local mutation protection."""

import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import patch

from shrawler.cli import main as dispatch
from shrawler.nemesis import NemesisConfig
from shrawler.store import ScanStore
from shrawler.triage.service import TriageBusyError, TriageService
from shrawler.triage.storage import result_path
from shrawler.web import DatabaseIndex, WebServer, WebState

from .test_triage import metadata


class OfflineWebCliTests(unittest.TestCase):
    def test_offline_mode_never_constructs_authentication(self) -> None:
        with patch(
            "shrawler.cli._create_auth", side_effect=AssertionError("auth requested")
        ), patch("shrawler.web.run", return_value=0) as run:
            with self.assertRaises(SystemExit) as result:
                dispatch(["web", "--offline", "inventory.db"])
            self.assertEqual(result.exception.code, 0)
            self.assertIsNone(run.call_args.args[1])
            self.assertEqual(run.call_args.args[0].database_path, Path("inventory.db"))
        with self.assertRaises(SystemExit):
            dispatch(["web", "inventory.db"])
        with self.assertRaises(SystemExit):
            dispatch(["web", "user@host", "inventory.db", "--offline"])


class RankingHttpTests(unittest.TestCase):
    def test_direct_nemesis_action_and_offline_retry(self) -> None:
        from unittest.mock import Mock

        self.server.state.nemesis = NemesisConfig("https://nemesis/api", "u:p", "test")
        record = self.server.state.index.search("", "", "", "", 1, 1)["items"][0]
        pool = Mock()
        pool.retrieve.side_effect = lambda record, sink: sink(b"x" * record.size_bytes)
        self.server.state.pool = pool
        with patch("shrawler.nemesis.upload", side_effect=ValueError("HTTP 503")):
            result = self.request("/api/nemesis/send", {"file_id": record["id"]})
        self.assertEqual(result["status"], "upload_failed")
        self.server.state.pool = None
        with patch("shrawler.nemesis.upload", return_value={"response_id": "ok"}):
            result = self.request("/api/nemesis/send", {"file_id": record["id"]})
        self.assertEqual(result["status"], "uploaded")
        pool.retrieve.assert_called_once()

    def test_nemesis_resend_uploads_again(self) -> None:
        from unittest.mock import Mock

        self.server.state.nemesis = NemesisConfig("https://nemesis/api", "u:p", "test")
        record = self.server.state.index.search("", "", "", "", 1, 1)["items"][0]
        pool = Mock()
        pool.retrieve.side_effect = lambda record, sink: sink(b"x" * record.size_bytes)
        self.server.state.pool = pool
        with patch(
            "shrawler.nemesis.upload",
            side_effect=[{"response_id": "first"}, {"response_id": "second"}],
        ) as submit:
            first = self.request("/api/nemesis/send", {"file_id": record["id"]})
            second = self.request(
                "/api/nemesis/send", {"file_id": record["id"], "resend": True}
            )
        self.assertEqual(first["status"], "uploaded")
        self.assertEqual(second["status"], "uploaded")
        self.assertEqual(second["response_id"], "second")
        self.assertEqual(second["response_ids"], ["first"])
        self.assertEqual(submit.call_count, 2)
        self.assertEqual(pool.retrieve.call_count, 2)

    def test_nemesis_rejects_malformed_resend_flag(self) -> None:
        self.server.state.nemesis = NemesisConfig("https://nemesis/api", "u:p", "test")
        record = self.server.state.index.search("", "", "", "", 1, 1)["items"][0]
        with self.assertRaises(urllib.error.HTTPError):
            self.request(
                "/api/nemesis/send", {"file_id": record["id"], "resend": "yes"}
            )

    def test_nemesis_rejects_unconfigured_and_untrusted_requests(self) -> None:
        for headers in ({}, {"X-Shrawler-Request": ""}):
            with self.assertRaises(urllib.error.HTTPError):
                self.request("/api/nemesis/send", {"file_id": "a" * 24}, headers)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database = self.root / "shrawler.db"
        scan = ScanStore(self.root, "spider")
        scan.upsert_host("server", "server", "complete")
        scan.upsert_share("server", "DATA", "complete", {})
        for payload in (
            metadata("/Project42/creds.xlsx"),
            metadata("/Project42/web.config"),
            metadata("/Project42/deploy.ps1"),
            metadata("/Project42/settings.config"),
        ):
            scan.add_file("server", "DATA", payload)
        scan.finish("completed", {})
        scan.close()
        self.service = TriageService(self.database, self.root)
        state = WebState(
            DatabaseIndex(self.database),
            None,
            "token",
            1024,
            1024,
            self.root,
            threading.BoundedSemaphore(2),
            self.service,
        )
        self.server = WebServer(("127.0.0.1", 0), state)
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
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            job = self.request("/api/triage/job")["job"]
            if job["status"] != "running":
                self.assertEqual(job["status"], "completed", job)
                return job
            time.sleep(0.01)
        self.fail("ranking job did not finish")

    def test_preview_save_list_explain_and_offline_retrieval(self) -> None:
        source = self.database.read_bytes()
        self.assertFalse(self.request("/api/status")["retrieval_enabled"])
        self.assertEqual(len(self.request("/api/triage/catalog")["scans"]), 1)
        self.request("/api/triage/jobs", {"preview": True})
        preview = self.finished_job()
        self.assertEqual(preview["result"]["summary"]["positive_files"], 4)
        self.assertFalse(result_path(self.database).exists())
        self.request("/api/triage/jobs", {"preview": False})
        saved = self.finished_job()
        run_id = saved["result"]["run_id"]
        inventory = self.request(
            f"/api/files?ranking_run={run_id}&sort=priority&limit=4"
        )
        self.assertEqual(inventory["items"][0]["ranking_run_id"], run_id)
        self.assertGreaterEqual(
            inventory["items"][0]["ranking_score"],
            inventory["items"][-1]["ranking_score"],
        )
        names_ascending = self.request("/api/files?sort=file&direction=asc")["items"]
        names_descending = self.request("/api/files?sort=file&direction=desc")["items"]
        self.assertEqual(
            [item["file_name"] for item in names_ascending],
            list(reversed([item["file_name"] for item in names_descending])),
        )
        rating_ascending = self.request(
            f"/api/files?ranking_run={run_id}&sort=priority&direction=asc"
        )["items"]
        self.assertLessEqual(
            rating_ascending[0]["ranking_score"],
            rating_ascending[-1]["ranking_score"],
        )
        positive = self.request(
            f"/api/files?ranking_run={run_id}&ranking_min=1&limit=10"
        )
        self.assertTrue(positive["items"])
        self.assertTrue(all(item["ranking_score"] >= 1 for item in positive["items"]))
        tree = self.request(f"/api/tree?ranking_run={run_id}")
        self.assertEqual(tree["total"], 4)
        branch = self.request(
            f"/api/tree/branch?host=server&share=DATA&parent=/Project42&ranking_run={run_id}"
        )
        self.assertTrue(
            any(item["ranking_run_id"] == run_id for item in branch["files"])
        )
        catalog = self.request("/api/triage/catalog")
        self.assertEqual(catalog["runs"][0]["id"], run_id)
        page = self.request(
            f"/api/triage/files?run={run_id}&limit=1&category=infrastructure"
        )
        self.assertEqual(page["items"][0]["priority"], 30)
        self.assertIsNotNone(page["next_cursor"])
        file_id = page["items"][0]["file_id"]
        detail = self.request(f"/api/triage/explain?run={run_id}&file_id={file_id}")
        self.assertTrue(detail["contexts"][0]["sibling_evidence"])
        self.assertIn("rule_diagnostics", detail)
        for action in ("preview", "download"):
            with self.assertRaises(urllib.error.HTTPError) as denied:
                self.request(f"/api/files/{file_id}/{action}")
            self.assertEqual(denied.exception.code, 403)
        self.assertEqual(source, self.database.read_bytes())

    def test_ranking_job_publishes_a_real_total(self) -> None:
        # The Score meter divides processed by total; without a published total
        # the bar has no denominator and cannot move.
        accepted = self.request("/api/triage/jobs", {"preview": True})
        self.assertEqual(accepted["status"], "running")
        self.assertEqual(accepted["phase"], "starting")
        job = self.finished_job()
        self.assertEqual(job["total"], 4)
        self.assertEqual(job["processed"], job["total"])

    def test_rank_reports_total_before_scoring_and_names_the_save_tail(self) -> None:
        from shrawler.triage.rules import load
        from shrawler.triage.storage import rank

        events: List[Any] = []
        rank(
            self.database,
            load(),
            on_phase=lambda phase, count: events.append((phase, count)),
            on_total=lambda total: events.append(("total", total)),
        )
        self.assertEqual(events[0], ("total", 4))
        self.assertEqual(events[-1], ("saving", 4))

    def test_mutations_require_local_json_requests_even_without_token(self) -> None:
        self.server.state.token = ""
        for headers in (
            {"Origin": "https://example.com"},
            {"X-Shrawler-Request": ""},
            {"Content-Type": "text/plain"},
            {"Host": "attacker.example"},
        ):
            with self.subTest(headers=headers), self.assertRaises(
                urllib.error.HTTPError
            ) as denied:
                self.request("/api/triage/jobs", {}, headers)
            self.assertIn(denied.exception.code, (400, 403))
        self.assertIsNone(self.service.status())

    def test_api_rejects_unknown_fields_and_invalid_rules(self) -> None:
        payloads: List[Dict[str, Any]] = [
            {"rules_path": "/etc/passwd"},
            {"scan_id": []},
            {"builtins": "yes"},
            {"rules_toml": "broken = ["},
            {"rules_toml": "version = 1\nunknown = true"},
        ]
        for payload in payloads:
            with self.subTest(payload=payload), self.assertRaises(
                urllib.error.HTTPError
            ) as denied:
                self.request("/api/triage/jobs", payload)
            self.assertEqual(denied.exception.code, 400)
        with self.assertRaises(urllib.error.HTTPError) as denied:
            self.request(
                "/api/triage/catalog", headers={"Authorization": "Bearer wrong"}
            )
        self.assertEqual(denied.exception.code, 401)

    def test_job_guard_and_cancel(self) -> None:
        entered = threading.Event()
        released = threading.Event()

        def hold(*_args: Any, **_kwargs: Any) -> None:
            entered.set()
            released.wait(timeout=3)

        try:
            with patch.object(self.service, "_work", side_effect=hold):
                self.service.start({})
                self.assertTrue(entered.wait(timeout=1))
                with self.assertRaises(TriageBusyError):
                    self.service.start({})
                self.assertTrue(
                    self.request("/api/triage/cancel", {})["cancel_requested"]
                )
        finally:
            released.set()

    def test_family_review_api_offline_and_undo(self) -> None:
        built = self.request("/api/review/build", {})
        families = self.request("/api/review/families?scan=" + built["scan_id"])
        family = families["items"][0]["family_id"]
        members = self.request(
            "/api/review/families?scan=" + built["scan_id"] + "&family=" + family
        )
        self.assertTrue(members["items"])
        event = self.request(
            "/api/review/decide",
            {
                "scope": "family",
                "target": family,
                "disposition": "exclude",
                "note": "reviewed locally",
            },
        )
        refreshed = self.request("/api/review/families?scan=" + built["scan_id"])
        self.assertEqual(refreshed["items"][0]["review"]["disposition"], "exclude")
        self.assertEqual(
            self.request("/api/review/undo", {"event_id": event["event_id"]})["undone"],
            event["event_id"],
        )
        with self.assertRaises(urllib.error.HTTPError) as failure:
            self.request(
                "/api/review/decide",
                {"scope": "family", "target": family, "disposition": "exclude"},
                {"X-Shrawler-Request": "0"},
            )
        self.assertEqual(failure.exception.code, 403)


    PS1_RULES = (
        "version = 1\n[[rules]]\nid = \"custom.ps1\"\ndescription = \"scripts\"\n"
        "category = \"scripts\"\nsignal_group = \"scripts\"\npoints = 40\n"
        "[rules.when]\nextension_any = [\".ps1\"]\n"
    )

    def status_of(self, path: str, payload: Optional[Dict[str, Any]] = None) -> int:
        try:
            self.request(path, payload)
        except urllib.error.HTTPError as error:
            return error.code
        return 200

    def preview_job(self, **payload: Any) -> Dict[str, Any]:
        self.request("/api/triage/jobs", {"preview": True, **payload})
        return self.finished_job()

    def test_preview_is_retained_and_read_through_ranking_endpoints(self) -> None:
        job = self.preview_job(rules_toml=self.PS1_RULES)
        self.assertEqual(job["preview_id"], job["id"])
        self.assertEqual(job["rules_toml"], self.PS1_RULES)
        self.assertTrue(job["builtins"])
        self.assertEqual(job["run_id"], job["result"]["run_id"])
        self.assertEqual(job["scan_id"], job["result"]["scan_id"])
        self.assertEqual(job["summary"]["positive_files"], 4)
        self.assertTrue((self.root / "triage-previews" / f"{job['id']}.db").exists())
        self.assertFalse(result_path(self.database).exists())
        preview = self.request("/api/triage/preview")["preview"]
        self.assertEqual(preview["id"], job["id"])
        self.assertEqual(preview["run_id"], job["run_id"])
        self.assertEqual(preview["rules_toml"], self.PS1_RULES)
        self.assertEqual(preview["files_scored"], 4)
        self.assertEqual(preview["scan_short_id"], job["scan_id"][:6])
        self.assertEqual(
            preview["stale"], {"newer_scan": False, "reviews_changed": False}
        )
        pages: List[str] = []
        cursor = ""
        while True:
            page = self.request(
                f"/api/triage/files?preview={job['id']}&limit=1{cursor}"
            )
            self.assertEqual(page["run_id"], job["run_id"])
            pages.extend(item["file_id"] for item in page["items"])
            if not page["next_cursor"]:
                break
            score, after = page["next_cursor"]
            cursor = f"&after_score={score}&after_id={after}"
        self.assertEqual(len(set(pages)), 4)
        scripts = self.request(f"/api/triage/files?preview={job['id']}&category=scripts")
        self.assertEqual([item["file_name"] for item in scripts["items"]], ["deploy.ps1"])
        detail = self.request(
            f"/api/triage/explain?preview={job['id']}&file_id={pages[0]}"
        )
        self.assertEqual(detail["run_id"], job["run_id"])
        self.assertIn("rule_diagnostics", detail)
        self.assertEqual(
            self.status_of(f"/api/triage/files?preview={job['id']}&run=x"), 400
        )
        self.assertEqual(self.status_of("/api/triage/files?preview=missing"), 410)
        self.assertEqual(
            self.status_of(f"/api/triage/explain?preview=missing&file_id={pages[0]}"),
            410,
        )
        self.request("/api/review/build", {})
        families = self.request("/api/review/families?scan=" + job["scan_id"])
        self.request(
            "/api/review/decide",
            {
                "scope": "family",
                "target": families["items"][0]["family_id"],
                "disposition": "exclude",
            },
        )
        self.assertTrue(
            self.request("/api/triage/preview")["preview"]["stale"]["reviews_changed"]
        )

    def test_only_the_latest_preview_is_kept_and_replaced_on_completion(self) -> None:
        from shrawler.triage import service as module

        first = self.preview_job()
        first_path = self.root / "triage-previews" / f"{first['id']}.db"
        entered = threading.Event()
        released = threading.Event()
        real_rank = module.rank

        def slow_rank(*args: Any, **kwargs: Any) -> Any:
            entered.set()
            released.wait(timeout=3)
            return real_rank(*args, **kwargs)

        with patch.object(module, "rank", side_effect=slow_rank):
            self.request("/api/triage/jobs", {"preview": True})
            self.assertTrue(entered.wait(timeout=2))
            # The old preview stays readable while the new one runs.
            self.assertTrue(first_path.exists())
            self.assertEqual(
                self.request("/api/triage/preview")["preview"]["id"], first["id"]
            )
            released.set()
            second = self.finished_job()
        self.assertFalse(first_path.exists())
        self.assertEqual(
            sorted(path.name for path in (self.root / "triage-previews").glob("*.db")),
            [f"{second['id']}.db"],
        )
        self.assertEqual(self.status_of(f"/api/triage/files?preview={first['id']}"), 410)
        self.assertEqual(
            self.request("/api/triage/preview")["preview"]["id"], second["id"]
        )
        self.assertEqual(
            self.request("/api/triage/preview/discard", {"id": second["id"]}),
            {"discarded": True},
        )
        self.assertIsNone(self.request("/api/triage/preview")["preview"])
        self.assertFalse(any((self.root / "triage-previews").iterdir()))

    def test_saving_a_preview_promotes_identical_scores(self) -> None:
        from shrawler.triage.storage import list_results

        job = self.preview_job(rules_toml=self.PS1_RULES)
        before = self.request(f"/api/triage/files?preview={job['id']}")["items"]
        categories = self.request(
            f"/api/triage/files?preview={job['id']}&category=scripts"
        )["items"]
        accepted = self.request("/api/triage/preview/save", {"id": job["id"]})
        self.assertEqual(accepted["phase"], "saving preview")
        self.assertEqual(accepted["total"], 4)
        saved = self.finished_job()
        run_id = saved["result"]["run_id"]
        self.assertEqual(run_id, job["run_id"])
        self.assertEqual(saved["processed"], 4)
        self.assertFalse((self.root / "triage-previews" / f"{job['id']}.db").exists())
        self.assertIsNone(self.request("/api/triage/preview")["preview"])
        after = self.request(f"/api/triage/files?run={run_id}")["items"]
        self.assertEqual(
            [(item["file_id"], item["priority"], item["unc_path"]) for item in before],
            [(item["file_id"], item["priority"], item["unc_path"]) for item in after],
        )
        self.assertEqual(
            [item["file_id"] for item in categories],
            [
                item["file_id"]
                for item in self.request(
                    f"/api/triage/files?run={run_id}&category=scripts"
                )["items"]
            ],
        )
        self.assertEqual(
            list_results(self.database, run_id)["summary"], job["summary"]
        )
        self.assertEqual(self.request("/api/triage/catalog")["runs"][0]["id"], run_id)
        self.assertEqual(
            self.status_of("/api/triage/preview/save", {"id": job["id"]}), 410
        )

    def test_compare_preview_against_saved_run(self) -> None:
        self.request("/api/triage/jobs", {"preview": False})
        base = self.finished_job()["result"]["run_id"]
        job = self.preview_job(rules_toml=self.PS1_RULES)
        compared = self.request(f"/api/triage/compare?preview={job['id']}&base={base}")
        summary = compared["summary"]
        self.assertEqual(summary["changed"], 1)
        self.assertEqual(summary["raised"], 1)
        self.assertEqual(summary["lowered"], 0)
        self.assertEqual(summary["no_longer_positive"], 0)
        self.assertTrue(summary["same_scan"])
        self.assertEqual(summary["rule_matches"]["custom.ps1"], [0, 1])
        self.assertEqual(len(compared["items"]), 1)
        item = compared["items"][0]
        self.assertEqual(item["file_name"], "deploy.ps1")
        self.assertGreater(item["delta"], 0)
        self.assertEqual(
            item["preview_priority"] - item["base_priority"], item["delta"]
        )
        everything = self.request(
            f"/api/triage/compare?preview={job['id']}&base={base}&order=preview&changed=0&limit=3"
        )
        self.assertEqual(len(everything["items"]), 3)
        self.assertIsNotNone(everything["next_cursor"])
        score, after = everything["next_cursor"]
        rest = self.request(
            f"/api/triage/compare?preview={job['id']}&base={base}&order=preview"
            f"&changed=0&after_score={score}&after_id={after}"
        )
        self.assertEqual(len(rest["items"]), 1)
        self.assertEqual(rest["summary"], summary)
        self.assertEqual(
            self.status_of(f"/api/triage/compare?preview={job['id']}&order=sideways"),
            400,
        )
        self.assertEqual(self.status_of("/api/triage/compare?preview=gone"), 410)

    def test_preview_save_conflicts_and_gone(self) -> None:
        self.assertEqual(self.status_of("/api/triage/preview/save", {"id": "nope"}), 410)
        self.assertEqual(self.status_of("/api/triage/preview/save", {}), 400)
        job = self.preview_job()
        entered = threading.Event()
        released = threading.Event()

        def hold(*_args: Any, **_kwargs: Any) -> None:
            entered.set()
            released.wait(timeout=3)

        try:
            with patch.object(self.service, "_work", side_effect=hold):
                self.service.start({})
                self.assertTrue(entered.wait(timeout=1))
                self.assertEqual(
                    self.status_of("/api/triage/preview/save", {"id": job["id"]}),
                    409,
                )
        finally:
            released.set()
        self.service._thread.join(timeout=3)
        self.assertEqual(
            self.request("/api/triage/preview/discard", {"id": job["id"]}),
            {"discarded": True},
        )
        self.assertEqual(
            self.status_of("/api/triage/preview/save", {"id": job["id"]}), 410
        )

    def test_previews_are_removed_on_close_and_startup(self) -> None:
        job = self.preview_job()
        directory = self.root / "triage-previews"
        self.assertTrue((directory / f"{job['id']}.db").exists())
        TriageService(self.database, self.root)
        self.assertFalse(directory.exists())
        job = self.preview_job()
        self.assertTrue((directory / f"{job['id']}.db").exists())
        self.service.close()
        self.assertFalse(directory.exists())


if __name__ == "__main__":
    unittest.main()
