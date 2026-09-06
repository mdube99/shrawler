"""Delivery must not couple upload retries to additional remote file reads."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import requests

from shrawler.nemesis import DeliveryStore, NemesisConfig, configuration, main, upload
from shrawler.web import FileRecord


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = DeliveryStore(Path(self.temp.name) / "shrawler.db")
        self.config = NemesisConfig("https://nemesis/api", "user:secret", "test")
        self.record = FileRecord(
            "a" * 24,
            "server",
            "DATA",
            "/AD Join.ps1",
            "\\\\server\\DATA\\AD Join.ps1",
            "AD Join.ps1",
            ".ps1",
            5,
            "5B",
            "2026-01-01T00:00:00Z",
            "2026-01-02T00:00:00Z",
            "",
        )
        self.retrieve = Mock(side_effect=lambda record, sink: sink(b"hello"))

    @patch("shrawler.nemesis.upload")
    def test_send_cleans_spool_and_repeat_does_not_read_or_upload(self, submit):
        submit.return_value = {"response_id": "nemesis-123"}
        result = self.store.send(self.record, self.config, self.retrieve, 10)
        self.assertEqual(result["status"], "uploaded")
        self.assertEqual(result["response_id"], "nemesis-123")
        self.assertEqual(result["file"]["unc_path"], self.record.unc_path)
        self.assertFalse(list(self.store.root.glob("*.bin")))
        self.store.send(self.record, self.config, None, 10)
        self.retrieve.assert_called_once()
        submit.assert_called_once()
        self.assertNotIn("user:secret", json.dumps(result))

    @patch("shrawler.nemesis.upload")
    def test_failed_upload_retries_local_bytes_without_smb(self, submit):
        submit.side_effect = [ValueError("HTTP 503"), {"response_id": "ok"}]
        failed = self.store.send(self.record, self.config, self.retrieve, 10)
        self.assertEqual(failed["status"], "upload_failed")
        evidence = next(self.store.root.glob("*.bin"))
        self.assertEqual(evidence.read_bytes(), b"hello")
        self.assertEqual(evidence.stat().st_mode & 0o777, 0o600)
        restarted = DeliveryStore(Path(self.temp.name) / "shrawler.db")
        result = restarted.send(self.record, self.config, None, 10)
        self.assertEqual(result["status"], "uploaded")
        self.assertEqual(result["attempts"], 2)
        self.retrieve.assert_called_once()

    @patch("shrawler.nemesis.upload")
    def test_interrupted_upload_is_ambiguous_and_preserves_evidence(self, submit):
        submit.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            self.store.send(self.record, self.config, self.retrieve, 10)
        self.assertEqual(self.store.list()[0]["status"], "uploading")
        self.assertEqual(next(self.store.root.glob("*.bin")).read_bytes(), b"hello")
        with self.assertRaisesRegex(ValueError, "unknown outcome"):
            self.store.send(self.record, self.config, None, 10)

    @patch("shrawler.nemesis.upload", return_value={"response_id": "ok"})
    def test_concurrent_send_is_rejected_before_second_remote_read(self, submit):
        def retrieve(record, sink):
            with self.assertRaisesRegex(ValueError, "Another Nemesis transfer"):
                self.store.send(record, self.config, self.retrieve, 10)
            sink(b"hello")

        self.store.send(self.record, self.config, retrieve, 10)
        self.retrieve.assert_not_called()
        submit.assert_called_once()

    @patch("shrawler.nemesis.upload")
    def test_missing_spool_is_not_silently_refetched(self, submit):
        submit.side_effect = ValueError("HTTP 503")
        self.store.send(self.record, self.config, self.retrieve, 10)
        next(self.store.root.glob("*.bin")).unlink()
        with self.assertRaisesRegex(ValueError, "missing"):
            self.store.send(self.record, self.config, self.retrieve, 10)
        self.retrieve.assert_called_once()

    def test_list_is_read_only_and_needs_no_configuration(self):
        with patch(
            "shrawler.nemesis.configuration", side_effect=AssertionError("config read")
        ), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(
                main(["list", str(Path(self.temp.name) / "shrawler.db")]), 0
            )
        self.assertEqual(json.loads(output.getvalue()), [])
        self.assertFalse(self.store.root.exists())

    @patch("shrawler.config.load_config", return_value={"nemesis": {"url": 42}})
    def test_invalid_configuration_has_a_clear_error(self, _load):
        with self.assertRaisesRegex(ValueError, "must be a string"):
            configuration(SimpleNamespace())

    @patch("shrawler.nemesis.upload")
    def test_unknown_acknowledgment_requires_explicit_retry(self, submit):
        submit.side_effect = requests.Timeout("credentials must not be stored")
        result = self.store.send(self.record, self.config, self.retrieve, 10)
        self.assertEqual(result["status"], "unknown")
        self.assertNotIn("credentials", result["error"])
        with self.assertRaisesRegex(ValueError, "unknown outcome"):
            self.store.send(self.record, self.config, self.retrieve, 10)
        submit.side_effect = None
        submit.return_value = {"response_id": "ok"}
        self.store.send(self.record, self.config, None, 10, retry_unknown=True)
        self.retrieve.assert_called_once()

    @patch("shrawler.nemesis.upload")
    def test_size_gates_and_remote_growth_never_upload_partial_files(self, submit):
        with self.assertRaisesRegex(ValueError, "limit"):
            self.store.send(self.record, self.config, self.retrieve, 4)
        self.retrieve.assert_not_called()
        self.retrieve.side_effect = lambda record, sink: sink(b"too much data")
        with self.assertRaisesRegex(ValueError, "limit"):
            self.store.send(self.record, self.config, self.retrieve, 10)
        self.assertFalse(list(self.store.root.glob("*.bin")))
        self.retrieve.side_effect = lambda record, sink: sink(b"tiny")
        with self.assertRaisesRegex(ValueError, "size changed"):
            self.store.send(self.record, self.config, self.retrieve, 10)
        submit.assert_not_called()

    @patch("shrawler.nemesis.upload")
    def test_tampered_spool_is_not_uploaded_or_refetched(self, submit):
        submit.side_effect = ValueError("HTTP 503")
        self.store.send(self.record, self.config, self.retrieve, 10)
        next(self.store.root.glob("*.bin")).write_bytes(b"other")
        with self.assertRaisesRegex(ValueError, "hash changed"):
            self.store.send(self.record, self.config, self.retrieve, 10)
        self.retrieve.assert_called_once()
        submit.assert_called_once()

    @patch("shrawler.nemesis.upload")
    def test_offline_and_invalid_config_do_not_retrieve(self, submit):
        with self.assertRaisesRegex(ValueError, "SMB"):
            self.store.send(self.record, self.config, None, 10)
        with self.assertRaises(ValueError):
            self.store.send(
                self.record,
                NemesisConfig("https://user:pass@host", "a:b", "p"),
                self.retrieve,
                10,
            )
        self.retrieve.assert_not_called()
        submit.assert_not_called()

    @patch("shrawler.nemesis.requests.post")
    def test_transport_preserves_original_filename_and_metadata(self, post):
        post.return_value.status_code = 201
        post.return_value.json.return_value = {"id": "123"}
        path = Path(self.temp.name) / "random.bin"
        path.write_bytes(b"hello")
        result = upload(self.config, path, self.record.public())
        self.assertEqual(result["response_id"], "123")
        args = post.call_args.kwargs
        self.assertEqual(args["files"]["file"][0], "AD Join.ps1")
        metadata = json.loads(args["files"]["metadata"][1])
        self.assertEqual(metadata["path"], "/DATA/AD Join.ps1")
        self.assertEqual(metadata["source"], "host://server")
        self.assertFalse(args["allow_redirects"])
        post.return_value.close.assert_called_once()
