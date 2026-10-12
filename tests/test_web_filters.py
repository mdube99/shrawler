"""Multi-value include and ``not_`` exclude filters across both inventory readers.

Every semantic case runs against the SQLite ``DatabaseIndex`` and the offline
JSON ``FileIndex`` built from the same fixture, so the two stay in parity.
"""

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

from shrawler.store import ScanStore
from shrawler.web import DatabaseIndex, FileIndex, WebServer, WebState

# (host, share, remote_path, (rule, triage) or None, download nemesis status)
# A download status of None means the file was never collected; "" means it
# was collected but never sent to Nemesis.
FIXTURE: Tuple[Tuple[str, str, str, Optional[Tuple[str, str]], Optional[str]], ...] = (
    ("alpha", "DATA", "/a/keep.txt", ("RuleA", "high"), None),
    ("alpha", "DATA", "/a/plain.log", None, None),
    ("alpha", "PUBLIC", "/b/cfg.config", ("RuleB", "low"), "uploaded"),
    ("bravo", "DATA", "/c/secret.txt", ("RuleA", "low"), "upload_failed"),
    ("bravo", "DATA", "/c/notes.txt", None, None),
    ("dc01", "SYSVOL", "/d/script.ps1", None, None),
)
PERMISSIONS: Dict[Tuple[str, str], Dict[str, Any]] = {
    ("alpha", "DATA"): {"read": True, "write": False},
    ("alpha", "PUBLIC"): {
        "read": True,
        "write": True,
        "write_rights": {"add_file": True},
    },
    ("bravo", "DATA"): {"read": True, "write": False},
    ("dc01", "SYSVOL"): {"read": True, "write": False},
}
ALL = {"keep.txt", "plain.log", "cfg.config", "secret.txt", "notes.txt", "script.ps1"}


def _file(host: str, share: str, remote: str) -> Dict[str, Any]:
    return {
        "remote_path": remote,
        "unc_path": f"\\\\{host}\\{share}\\" + remote.lstrip("/").replace("/", "\\"),
        "file_name": remote.rsplit("/", 1)[-1],
        "size_bytes": 10,
        "readable_size": "10B",
        "mtime_utc": "2026-09-04T00:00:00+00:00",
        "is_directory": False,
        "scan_timestamp_utc": "2026-09-04T00:00:00+00:00",
    }


def _download(nemesis: str) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"status": "downloaded"}
    if nemesis:
        payload["nemesis"] = {"status": nemesis}
    return payload


def build_database(root: Path) -> DatabaseIndex:
    store = ScanStore(root, "spider", "DOMAIN", "alice")
    try:
        for host, share in PERMISSIONS:
            store.upsert_host(host, host, "complete")
            store.upsert_share(
                host, share, "complete", {"permissions": PERMISSIONS[(host, share)]}
            )
        for host, share, remote, match, nemesis in FIXTURE:
            payload = _file(host, share, remote)
            store.add_file(host, share, payload)
            if match:
                store.add_match(
                    {
                        **payload,
                        "host": host,
                        "share_name": share,
                        "rule_name": match[0],
                        "triage": match[1],
                    }
                )
            if nemesis is not None:
                store.add_download(host, share, {**payload, **_download(nemesis)})
    finally:
        store.close()
    return DatabaseIndex(root / "shrawler.db", page_size=500)


def build_json(root: Path) -> FileIndex:
    data: Dict[str, Any] = {"_schema": {"name": "shrawler-results", "version": 3}}
    for (host, share), permissions in PERMISSIONS.items():
        data.setdefault(host, {"shares": {}})["shares"][share] = {
            "permissions": permissions,
            "discovered_files": [],
            "snaffler_matches": [],
            "downloaded_files": [],
        }
    for host, share, remote, match, nemesis in FIXTURE:
        payload = _file(host, share, remote)
        bucket = data[host]["shares"][share]
        bucket["discovered_files"].append(payload)
        if match:
            bucket["snaffler_matches"].append(
                {"remote_path": remote, "rule_name": match[0], "triage": match[1]}
            )
        if nemesis is not None:
            bucket["downloaded_files"].append(
                {"remote_path": remote, **_download(nemesis)}
            )
    path = root / "results.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return FileIndex.load(path, page_size=500)


Values = Union[str, Sequence[str]]

# The mixin is not collected on its own; type checkers still see TestCase.
_MixinBase = unittest.TestCase if TYPE_CHECKING else object


class FilterSemanticsMixin(_MixinBase):
    """Cases shared by both index implementations."""

    index: Any

    def names(
        self, exclude: Optional[Mapping[str, Values]] = None, **include: Values
    ) -> Set[str]:
        result = self.index.search(
            include.pop("q", ""),
            include.pop("host", ""),
            include.pop("share", ""),
            include.pop("extension", ""),
            1,
            500,
            exclude=exclude,
            **include,
        )
        self.assertEqual(result["total"], len(result["items"]))
        return {item["file_name"] for item in result["items"]}

    def test_multi_value_include_is_or_within_a_facet(self) -> None:
        self.assertEqual(
            self.names(host=["alpha", "dc01"]),
            {"keep.txt", "plain.log", "cfg.config", "script.ps1"},
        )
        self.assertEqual(
            self.names(extension=[".txt", ".log"]),
            {"keep.txt", "plain.log", "secret.txt", "notes.txt"},
        )
        self.assertEqual(
            self.names(rule=["RuleA", "RuleB"]),
            {"keep.txt", "cfg.config", "secret.txt"},
        )
        # AND across facets still holds.
        self.assertEqual(
            self.names(host=["alpha", "bravo"], extension=".txt"),
            {"keep.txt", "secret.txt", "notes.txt"},
        )

    def test_exclude_removes_matches_and_keeps_the_rest(self) -> None:
        self.assertEqual(self.names(exclude={"host": ["dc01"]}), ALL - {"script.ps1"})
        self.assertEqual(
            self.names(exclude={"host": "dc01", "share": ["PUBLIC"]}),
            ALL - {"script.ps1", "cfg.config"},
        )
        self.assertEqual(
            self.names(exclude={"extension": [".txt", ".log"]}),
            {"cfg.config", "script.ps1"},
        )
        # Empty excludes are no-ops.
        self.assertEqual(self.names(exclude={"host": [], "rule": ""}), ALL)
        self.assertEqual(self.names(exclude={}), ALL)

    def test_include_and_exclude_on_the_same_facet(self) -> None:
        self.assertEqual(
            self.names(host=["alpha", "bravo"], exclude={"host": ["bravo"]}),
            {"keep.txt", "plain.log", "cfg.config"},
        )
        self.assertEqual(
            self.names(rule="RuleA", exclude={"rule": "RuleA"}),
            set(),
        )

    def test_evidence_excludes_drop_any_matching_file_and_keep_unmatched(self) -> None:
        self.assertEqual(
            self.names(exclude={"rule": ["RuleA"]}),
            ALL - {"keep.txt", "secret.txt"},
        )
        self.assertEqual(
            self.names(exclude={"triage": ["low"]}),
            ALL - {"cfg.config", "secret.txt"},
        )
        self.assertEqual(
            self.names(rule="RuleA", exclude={"triage": ["low"]}), {"keep.txt"}
        )
        # Rule and triage includes still have to hold on the same match.
        self.assertEqual(self.names(rule="RuleA", triage="high"), {"keep.txt"})
        self.assertEqual(self.names(rule="RuleB", triage="high"), set())

    def test_permission_exclude(self) -> None:
        self.assertEqual(self.names(permission="write"), {"cfg.config"})
        self.assertEqual(
            self.names(exclude={"permission": ["write"]}), ALL - {"cfg.config"}
        )
        self.assertEqual(
            self.names(exclude={"permission": ["add_file", "write_dac"]}),
            ALL - {"cfg.config"},
        )
        self.assertEqual(self.names(exclude={"permission": ["read"]}), set())

    def test_collection_and_activity_excludes(self) -> None:
        collected = {"cfg.config", "secret.txt"}
        self.assertEqual(
            self.names(exclude={"collection": ["collected"]}), ALL - collected
        )
        self.assertEqual(self.names(collection=["collected", "not_collected"]), ALL)
        self.assertEqual(
            self.names(exclude={"activity": ["downloaded"]}), ALL - collected
        )
        self.assertEqual(
            self.names(exclude={"activity": ["nemesis_sent"]}), ALL - {"cfg.config"}
        )
        self.assertEqual(
            self.names(activity=["nemesis_sent", "nemesis_failed"]), collected
        )
        self.assertEqual(
            self.names(activity="downloaded", exclude={"activity": ["nemesis_failed"]}),
            {"cfg.config"},
        )

    def test_invalid_or_unknown_excludes_are_rejected(self) -> None:
        for exclude in (
            {"permission": ["root"]},
            {"collection": ["maybe"]},
            {"activity": ["teleported"]},
            {"bogus": ["x"]},
        ):
            with self.assertRaises(ValueError):
                self.names(exclude=exclude)
        with self.assertRaises(ValueError):
            self.names(permission=["read", "root"])

    def test_tree_respects_includes_and_excludes(self) -> None:
        tree = self.index.tree(
            "", ["alpha", "bravo", "dc01"], "", "", exclude={"host": ["dc01"]}
        )
        self.assertEqual([host["name"] for host in tree["hosts"]], ["alpha", "bravo"])
        self.assertEqual(tree["total"], 5)
        tree = self.index.tree("", "", "", "", exclude={"rule": ["RuleA", "RuleB"]})
        self.assertEqual(tree["total"], 3)


class DatabaseFilterTests(FilterSemanticsMixin, unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.index = build_database(Path(self.tmp.name))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_total_cache_distinguishes_excludes(self) -> None:
        first = self.index.search("", "", "", "", 1, 10, include_total=True)
        second = self.index.search(
            "", "", "", "", 1, 10, include_total=True, exclude={"host": ["dc01"]}
        )
        self.assertEqual((first["total"], second["total"]), (6, 5))

    def test_tree_branch_respects_excludes(self) -> None:
        shares = self.index.tree_branch(
            "", "alpha", "", "", "", exclude={"share": ["PUBLIC"]}
        )
        self.assertEqual([share["name"] for share in shares["shares"]], ["DATA"])
        branch = self.index.tree_branch(
            "", "alpha", "DATA", "", "/a", exclude={"extension": [".log"]}
        )
        self.assertEqual([item["file_name"] for item in branch["files"]], ["keep.txt"])

    def test_tree_branch_share_listing_keeps_share_filter(self) -> None:
        # Expanding a host while a share filter is active lists shares, not
        # the share's files.
        listed = self.index.tree_branch(
            "", "alpha", ["DATA", "PUBLIC"], "", "", level="shares"
        )
        self.assertEqual(
            [share["name"] for share in listed["shares"]], ["DATA", "PUBLIC"]
        )
        listed = self.index.tree_branch("", "alpha", "DATA", "", "", level="shares")
        self.assertEqual([share["name"] for share in listed["shares"]], ["DATA"])
        with self.assertRaises(ValueError):
            self.index.tree_branch("", ["alpha", "bravo"], "", "", "")
        with self.assertRaises(ValueError):
            self.index.tree_branch("", "alpha", ["DATA", "PUBLIC"], "", "/a")


class JsonFilterTests(FilterSemanticsMixin, unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.index = build_json(Path(self.tmp.name))

    def tearDown(self) -> None:
        self.tmp.cleanup()


class FilterHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.servers: List[Tuple[WebServer, threading.Thread]] = []
        self.database = self.serve(build_database(root), root)
        self.json = self.serve(build_json(root), root)

    def serve(self, index: Any, root: Path) -> str:
        state = WebState(
            index, None, "token", 1024, 1024, root, threading.BoundedSemaphore(2)
        )
        server = WebServer(("127.0.0.1", 0), state)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        self.servers.append((server, thread))
        return f"http://127.0.0.1:{server.server_port}"

    def tearDown(self) -> None:
        for server, thread in self.servers:
            server.shutdown()
            server.server_close()
            thread.join()
        self.tmp.cleanup()

    @staticmethod
    def get(base: str, path: str) -> Dict[str, Any]:
        request = urllib.request.Request(
            base + path, headers={"Authorization": "Bearer token"}
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read())

    def names(self, base: str, query: str) -> Set[str]:
        payload = self.get(base, "/api/files?include_total=1&per_page=500&" + query)
        return {item["file_name"] for item in payload["items"]}

    def test_repeated_and_not_params_reach_both_indexes(self) -> None:
        for base in (self.database, self.json):
            self.assertEqual(
                self.names(base, "host=alpha&host=bravo&not_share=PUBLIC"),
                {"keep.txt", "plain.log", "secret.txt", "notes.txt"},
            )
            self.assertEqual(
                self.names(base, "not_rule=RuleA&not_activity=nemesis_sent"),
                ALL - {"keep.txt", "secret.txt", "cfg.config"},
            )
            # A legacy single-value link keeps working, and blank params are no-ops.
            self.assertEqual(
                self.names(base, "host=dc01&not_host=&share="), {"script.ps1"}
            )
            tree = self.get(base, "/api/tree?not_host=dc01&not_host=bravo")
            self.assertEqual([host["name"] for host in tree["hosts"]], ["alpha"])

    def test_tree_branch_level_and_excludes_over_http(self) -> None:
        shares = self.get(
            self.database,
            "/api/tree/branch?host=alpha&share=DATA&level=shares&not_extension=.log",
        )
        self.assertEqual(
            [(share["name"], share["file_count"]) for share in shares["shares"]],
            [("DATA", 1)],
        )

    def test_invalid_excluded_vocabulary_is_rejected(self) -> None:
        for query, message in (
            ("not_permission=root", "Invalid evidence filter"),
            ("not_collection=maybe", "Invalid evidence filter"),
            ("not_activity=teleported", "Invalid activity filter"),
            ("permission=read&permission=root", "Invalid evidence filter"),
            (
                "&".join([f"not_host=h{n}" for n in range(51)]),
                "Too many filter values",
            ),
        ):
            for base in (self.database, self.json):
                for path in ("/api/files", "/api/tree"):
                    with self.assertRaises(urllib.error.HTTPError) as caught:
                        self.get(base, f"{path}?{query}")
                    self.assertEqual(caught.exception.code, 400)
                    body = json.loads(caught.exception.read())
                    self.assertEqual(body, {"error": message, "code": "invalid_query"})


if __name__ == "__main__":
    unittest.main()
