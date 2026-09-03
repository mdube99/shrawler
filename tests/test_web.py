import io
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from shrawler.web import (
    DownloadTooLarge,
    FileIndex,
    LimitedSink,
    SessionPool,
    WebServer,
    WebState,
    classify_preview,
    content_disposition,
)


def result_file(root: Path) -> Path:
    path = root / "results.json"
    path.write_text(
        json.dumps(
            {
                "_schema": {"name": "shrawler-results", "version": 3},
                "server": {
                    "shares": {
                        "docs": {
                            "discovered_files": [
                                {
                                    "host": "wrong",
                                    "share_name": "wrong",
                                    "remote_path": "/Reports/Secret.txt",
                                    "unc_path": "\\\\server\\docs\\Reports\\Secret.txt",
                                    "file_name": "Secret.txt",
                                    "size_bytes": 5,
                                    "readable_size": "5B",
                                },
                                {
                                    "remote_path": "/Reports/café.md",
                                    "file_name": "café.md",
                                    "size_bytes": 4,
                                },
                            ]
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    return path


class IndexTests(unittest.TestCase):
    def test_load_search_facets_and_opaque_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            index = FileIndex.load(result_file(Path(tmp)), page_size=1)
        self.assertEqual(len(index.records), 2)
        self.assertEqual(index.records[0].host, "server")
        self.assertNotIn("server", index.records[0].id)
        found = index.search("SECRET reports", "server", "docs", ".txt", 1, 999)
        self.assertEqual(found["total"], 1)
        self.assertEqual(found["per_page"], 1)
        self.assertEqual(index.facets()["extensions"], [".md", ".txt"])

    def test_rejects_wrong_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text('{"_schema":{"name":"other","version":3}}')
            with self.assertRaises(ValueError):
                FileIndex.load(path)

    def test_skips_invalid_file_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = result_file(Path(tmp))
            payload = json.loads(path.read_text())
            payload["server"]["shares"]["docs"]["discovered_files"][0]["size_bytes"] = (
                "invalid"
            )
            path.write_text(json.dumps(payload))
            index = FileIndex.load(path)
        self.assertEqual(len(index.records), 1)
        self.assertEqual(index.skipped, 1)


class ContentTests(unittest.TestCase):
    def test_preview_requires_extension_and_valid_content(self):
        self.assertEqual(classify_preview("a.txt", b"hello")[0], "text")
        with self.assertRaises(ValueError):
            classify_preview("a.txt", b"\0binary")
        with self.assertRaises(ValueError):
            classify_preview("a.png", b"not png")
        self.assertEqual(
            classify_preview("a.png", b"\x89PNG\r\n\x1a\nrest")[0], "binary"
        )
        with self.assertRaises(ValueError):
            classify_preview("a.svg", b"<svg onload='alert(1)'>")

    def test_limited_sink_stops_overflow(self):
        output = io.BytesIO()
        sink = LimitedSink(output.write, 4)
        sink(b"123")
        with self.assertRaises(DownloadTooLarge):
            sink(b"45")

    def test_content_disposition_blocks_header_injection(self):
        value = content_disposition('evil\r\nX-Bad: yes/".txt')
        self.assertNotIn("\r", value)
        self.assertNotIn("\n", value)
        self.assertIn("filename*=UTF-8''", value)

    def test_size_limit_does_not_retry_smb_transfer(self):
        class Client:
            def __init__(self):
                self.calls = 0

            def getFile(self, share, remote_path, sink):
                del share, remote_path
                self.calls += 1
                sink(b"too large")

        client = Client()
        pool = SessionPool(None)
        pool._sessions["host"] = (client, threading.Lock())
        record = type(
            "Record", (), {"host": "host", "share": "DATA", "remote_path": "/file"}
        )()
        with self.assertRaises(DownloadTooLarge):
            pool.retrieve(record, LimitedSink(io.BytesIO().write, 2))
        self.assertEqual(client.calls, 1)


class FakePool:
    def retrieve(self, record, sink):
        sink(b"hello")

    def close(self):
        pass


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        index = FileIndex.load(result_file(root))
        state = WebState(
            index, FakePool(), "token", 1024, 1024, root, threading.BoundedSemaphore(2)
        )
        self.server = WebServer(("127.0.0.1", 0), state)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.tmp.cleanup()

    def request(self, path, token="token", host=None):
        headers = {"Authorization": "Bearer " + token}
        if host:
            headers["Host"] = host
        return urllib.request.urlopen(
            urllib.request.Request(self.base + path, headers=headers)
        )

    def test_api_requires_token_and_validates_host(self):
        with self.assertRaises(urllib.error.HTTPError) as denied:
            self.request("/api/status", token="wrong")
        self.assertEqual(denied.exception.code, 401)
        with self.assertRaises(urllib.error.HTTPError) as denied_host:
            self.request("/api/status", host="evil.example")
        self.assertEqual(denied_host.exception.code, 400)

    def test_preview_and_download_security_headers(self):
        record = self.server.state.index.records[0]
        with self.request(f"/api/files/{record.id}/preview") as response:
            self.assertIn(
                "default-src 'self'", response.headers["Content-Security-Policy"]
            )
            self.assertEqual(json.loads(response.read())["content"], "hello")
        with self.request(f"/api/files/{record.id}/download") as response:
            self.assertEqual(response.read(), b"hello")
            self.assertEqual(
                response.headers["Content-Type"], "application/octet-stream"
            )
        self.assertEqual(list(Path(self.tmp.name).glob("*.download")), [])


if __name__ == "__main__":
    unittest.main()
