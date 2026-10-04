import json
import tempfile
import unittest
from pathlib import Path

import tomllib

from shrawler.config import (
    CONFIG_OPTIONS,
    DEFAULT_CONFIG,
    load_config,
)
from shrawler.state import ScanStateStore
from shrawler.triage.jev.config import JevConfig


class ConfigTests(unittest.TestCase):
    def test_initializer_contains_editable_nemesis_schema(self):
        self.assertIn('url = ""', DEFAULT_CONFIG)
        self.assertIn('auth = ""', DEFAULT_CONFIG)
        self.assertIn('project = ""', DEFAULT_CONFIG)
        self.assertIn('mode = "off"', DEFAULT_CONFIG)
        self.assertIn("upload_workers = 2", DEFAULT_CONFIG)
        self.assertIn("https://nemesis:7443/api", DEFAULT_CONFIG)
        self.assertIn("username:password", DEFAULT_CONFIG)
        self.assertIn('"off", "matches", "downloads"', DEFAULT_CONFIG)
        self.assertIn("off | matches | downloads", CONFIG_OPTIONS)

    def test_initializer_jev_values_match_the_shipped_defaults(self) -> None:
        # The template is a written-out copy of JevConfig's defaults, so the two
        # can drift. When they do, `shrawler config init` quietly pins a stale
        # value that overrides the shipped default (this bit when the candidate
        # cap per request rose from 200 to 500). The template is what new
        # operators actually run, so its values must agree with the source.
        written = tomllib.loads(DEFAULT_CONFIG)["jev"]
        defaults = JevConfig().to_table()
        for field, value in written.items():
            self.assertIn(field, defaults, f"unknown [jev] field in template: {field}")
            expected = defaults[field]
            # `objective` is deliberately blank in the template so it resolves to
            # the built-in text at load time.
            if field == "objective":
                value = expected if value == "" else value
            self.assertEqual(value, expected, f"[jev] {field} drifted in the template")
        # The template must also stay valid input to the parser it feeds.
        JevConfig.from_mapping(written)

    def test_loads_structured_toml(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text(
                'profile = "quiet"\nview = "progress"\n'
                '[nemesis]\nurl = "https://nemesis/api"\n'
                'auth = "user:password"\nproject = "demo"\n'
                'mode = "matches"\nupload_workers = 4\nretries = 5\n'
            )
            config = load_config(path)

        self.assertEqual(config["profile"], "quiet")
        self.assertEqual(config["view"], "progress")
        self.assertEqual(config["nemesis"]["url"], "https://nemesis/api")
        self.assertEqual(config["nemesis"]["upload_workers"], 4)

    def test_missing_config_is_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(load_config(Path(tmp) / "missing.toml"), {})


class ScanStateStoreTests(unittest.TestCase):
    def test_events_are_appended_and_checkpoint_is_loadable(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ScanStateStore(Path(tmp))
            store.append("file_discovered", host="host", share="DATA")
            results = {"host": {"status": "complete", "shares": {}}}
            summary = {"files_seen": 12}
            store.checkpoint(results, summary)

            event = json.loads((Path(tmp) / "scan-events.jsonl").read_text())
            self.assertEqual(event["event"], "file_discovered")
            self.assertEqual(store.load()["results"], results)
            self.assertFalse((Path(tmp) / ".scan-state.json.tmp").exists())

    def test_disabled_store_does_not_touch_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "state"
            store = ScanStateStore(root, enabled=False)
            store.append("ignored")
            store.checkpoint({}, {})
            self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
