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


if __name__ == "__main__":
    unittest.main()
