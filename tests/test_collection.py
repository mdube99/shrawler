import fcntl
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from shrawler.collection import CollectionBusyError, CollectionQueue, main
from shrawler.store import ScanStore
from shrawler.triage.rules import load
from shrawler.triage.storage import rank

from .test_triage import metadata
from .test_triage_web import RankingHttpTests


class CollectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.database = self.root / "shrawler.db"
        store = ScanStore(self.root, "spider")
        store.upsert_host("server", "server", "complete")
        store.upsert_share("server", "DATA", "complete", {})
        for name in ("a", "b", "c"):
            store.add_file(
                "server", "DATA", metadata("/Deployments/" + name + ".config", size=4)
            )
        store.finish("completed", {})
        store.close()
        rank(self.database, load())
        self.queue = CollectionQueue(self.database)

    def tearDown(self):
        self.tmp.cleanup()

    def test_offline_manifest_limits_and_cli(self):
        with patch("socket.socket", side_effect=AssertionError("network")):
            manifest = self.queue.create(limit=3, max_file_size=4, max_total_bytes=8)
            self.assertEqual(manifest["expected_files"], 2)
            self.assertEqual(manifest["expected_bytes"], 8)
            self.assertEqual(
                [i["status"] for i in manifest["items"]],
                ["pending", "pending", "excluded_limit"],
            )
            self.assertTrue(manifest["items"][0]["reasons"])
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["show", str(self.database), manifest["id"]]), 0)
            self.assertEqual(json.loads(output.getvalue()), manifest)

    def test_resume_only_failed_direct_paths_and_prior_collection(self):
        manifest = self.queue.create(limit=2, max_total_bytes=20)
        paths = []

        def retrieve(item, sink):
            paths.append((item.host, item.share, item.remote_path))
            sink(b"ab")
            if len(paths) == 2:
                raise OSError("disconnected")
            sink(b"cd")

        result = self.queue.run(manifest["id"], retrieve)
        self.assertEqual(
            [i["status"] for i in result["items"]], ["collected", "failed"]
        )
        self.assertEqual(result["consumed_bytes"], 6)
        result = CollectionQueue(self.database).run(manifest["id"], retrieve)
        self.assertEqual(result["consumed_bytes"], 10)
        self.assertEqual(len(paths), 3)
        self.assertEqual(paths[1], paths[2])
        self.assertEqual(Path(result["items"][1]["local_path"]).read_bytes(), b"abcd")
        self.assertEqual(len(result["items"][1]["attempts"]), 2)
        self.assertEqual(self.queue.create(limit=2)["expected_files"], 0)
        self.queue.run(manifest["id"], lambda *_: self.fail("collected twice"))

    def test_actual_size_limit_and_failed_bytes_persist(self):
        manifest = self.queue.create(limit=2, max_file_size=4, max_total_bytes=8)
        calls = []

        def retrieve(item, sink):
            calls.append(item.remote_path)
            sink(b"abc")
            sink(b"def")

        result = self.queue.run(manifest["id"], retrieve)
        self.assertEqual(result["consumed_bytes"], 6)
        self.assertEqual(len(calls), 1)
        self.assertTrue(all(i["status"] == "failed" for i in result["items"]))
        self.assertFalse(list(self.queue.evidence.rglob("*.bin")))
        self.queue.run(manifest["id"], lambda *_: self.fail("budget bypassed"))

    def test_selection_validation_and_cross_process_lock(self):
        manifest = self.queue.create(limit=1)
        with self.assertRaises(ValueError):
            self.queue.create(file_ids=["unknown"])
        selected = self.queue.create(file_ids=[manifest["items"][0]["file_id"]])
        self.assertEqual(len(selected["items"]), 1)
        with self.queue.path.open("rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(CollectionBusyError):
                self.queue.run(manifest["id"], lambda *_: None)

    def test_smb_transport_only_retrieves_exact_source(self):
        from shrawler.collection import smb_retriever
        from shrawler.smb import SMBAuth

        auth = SMBAuth("", "user", "", "", "", False, None, "", None)
        manifest = self.queue.create(limit=1)
        with patch("shrawler.smb.connect_smb") as connect:
            client = connect.return_value
            client.getFile.side_effect = lambda share, path, sink: sink(b"data")
            result = self.queue.run(manifest["id"], smb_retriever(auth))
            connect.assert_called_once_with("server", auth)
            self.assertEqual(
                client.getFile.call_args.args[:2],
                ("DATA", manifest["items"][0]["remote_path"]),
            )
            client.listPath.assert_not_called()
            client.listShares.assert_not_called()
            client.logoff.assert_called_once()
            self.assertEqual(result["items"][0]["status"], "collected")

    def test_interrupt_persists_outcome(self):
        manifest = self.queue.create(limit=1)

        def retrieve(item, sink):
            sink(b"a")
            raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            self.queue.run(manifest["id"], retrieve)
        result = self.queue.get(manifest["id"])
        self.assertEqual(result["items"][0]["status"], "failed")
        self.assertEqual(result["consumed_bytes"], 1)


class CollectionHttpTests(RankingHttpTests):
    def test_shared_queue_and_offline_retrieval_guard(self):
        import urllib.error

        rank(self.database, load())
        manifest = self.request("/api/collection/create", {"limit": 2})
        self.assertEqual(CollectionQueue(self.database).get(manifest["id"]), manifest)
        self.assertEqual(self.request("/api/collection")["items"][0], manifest)
        with self.assertRaises(urllib.error.HTTPError) as failure:
            self.request("/api/collection/run", {"id": manifest["id"]})
        self.assertEqual(failure.exception.code, 400)
        with self.assertRaises(urllib.error.HTTPError) as failure:
            self.request(
                "/api/collection/create", {"limit": 2}, {"X-Shrawler-Request": "0"}
            )
        self.assertEqual(failure.exception.code, 403)
