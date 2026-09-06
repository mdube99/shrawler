import copy
import io
import json
import socket
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

from shrawler.cli import main as dispatch
from shrawler.store import ScanStore
from shrawler.triage.cli import main
from shrawler.triage.engine import Engine
from shrawler.triage.rules import load, load_text, validate
from shrawler.triage.storage import explain, list_results, rank, result_path


def metadata(
    path: str = "/Deployments/App/production.config",
    host: str = "server",
    share: str = "DATA",
    size: int = 20,
) -> Dict[str, Any]:
    name = path.replace("\\", "/").rsplit("/", 1)[-1]
    return {
        "host": host,
        "share": share,
        "file_name": name,
        "remote_path": path,
        "unc_path": f"\\\\{host}\\{share}\\" + path.lstrip("/").replace("/", "\\"),
        "size_bytes": size,
        "mtime_utc": "2026-01-01T00:00:00+00:00",
        "scan_timestamp_utc": "2026-09-05T00:00:00+00:00",
        "readable_size": f"{size}B",
    }


def rule(
    identifier: str = "config",
    points: int = 30,
    group: str = "config",
    category: str = "infrastructure",
    **when: Any,
) -> Dict[str, Any]:
    return {
        "id": identifier,
        "description": identifier,
        "category": category,
        "signal_group": group,
        "points": points,
        "when": when or {"extension_any": [".config"]},
    }


class EngineTests(unittest.TestCase):
    def test_context_depth_boundaries_and_explanation(self):
        engine = Engine(load())
        for path in (
            "/Deployments/production.config",
            "/DEPLOYMENTS/App/production.config",
            "/Deployments/a/b/production.config",
        ):
            evaluated = engine.evaluate(metadata(path))
            self.assertEqual(evaluated["priority"], 50)
        for path in (
            "/Deployments/a/b/c/production.config",
            "/NotDeployments/production.config",
            "/foo/Deployments.config",
        ):
            self.assertNotEqual(engine.evaluate(metadata(path))["priority"], 50)
        details = engine.evaluate(metadata(), True)
        evidence = details["signals"][0]["evidence"]["context_sources"][0]
        self.assertEqual(evidence["source_path"], "/Deployments")
        self.assertEqual(evidence["distance"], 1)
        self.assertTrue(
            any(item["failed_conditions"] for item in details["rule_diagnostics"])
        )

    def test_explicit_subtree_is_scoped_and_boundary_aware(self):
        rules = validate(
            {
                "version": 1,
                "contexts": [
                    {
                        "id": "orion",
                        "tag": "deployment",
                        "host": "server",
                        "share": "DATA",
                        "path": "/Orion",
                        "apply_to_descendants": 1,
                    }
                ],
                "rules": [rule(context_any=["deployment"])],
            }
        )
        engine = Engine(rules)
        self.assertEqual(
            engine.evaluate(metadata(r"\ORION\app\settings.config"))["priority"], 30
        )
        for data in (
            metadata("/Orion2/settings.config"),
            metadata("/Orion/a/b/settings.config"),
            metadata("/Orion/settings.config", host="other"),
            metadata("/Orion/settings.config", share="OTHER"),
        ):
            self.assertEqual(engine.evaluate(data)["priority"], 0)

    def test_root_label_depth_zero_and_parent_exact_match(self):
        rules = validate(
            {
                "version": 1,
                "contexts": [
                    {
                        "id": "root",
                        "tag": "root",
                        "host": "server",
                        "share": "DATA",
                        "path": "/",
                        "apply_to_descendants": 0,
                    }
                ],
                "rules": [
                    rule(context_any=["root"]),
                    rule("parent", group="parent", parent_name_any=["examples"]),
                ],
            }
        )
        engine = Engine(rules)
        self.assertEqual(engine.evaluate(metadata("/settings.config"))["priority"], 30)
        self.assertEqual(
            engine.evaluate(metadata("/other/settings.config"))["priority"], 0
        )
        self.assertEqual(
            engine.evaluate(metadata("/Examples/file.txt"))["priority"], 30
        )

    def test_group_caps_category_separation_and_token_boundaries(self):
        rules = validate(
            {
                "version": 1,
                "rules": [
                    rule(points=30),
                    rule("overlap", points=20),
                    rule(
                        "env", points=20, group="env", filename_token_any=["production"]
                    ),
                    rule("other", points=60, category="credentials"),
                ],
            }
        )
        engine = Engine(rules)
        result = engine.evaluate(metadata("/production.config"))
        self.assertEqual(
            result["category_scores"], {"infrastructure": 50, "credentials": 60}
        )
        self.assertEqual(result["priority"], 60)
        self.assertEqual(
            engine.evaluate(metadata("/reproduction.config"))["category_scores"][
                "infrastructure"
            ],
            30,
        )
        self.assertEqual(
            engine.evaluate(metadata("/appProduction.config"))["category_scores"][
                "infrastructure"
            ],
            50,
        )

    def test_globs_size_limits_and_dotfile_extension(self):
        rules = validate(
            {
                "version": 1,
                "rules": [
                    rule(
                        filename_glob_any=["appsettings.*.json"],
                        min_size_bytes=10,
                        max_size_bytes=20,
                    ),
                    rule("env", extension_any=[".env"]),
                ],
            }
        )
        engine = Engine(rules)
        self.assertEqual(
            engine.evaluate(metadata("/APPSETTINGS.Production.JSON"))["priority"], 30
        )
        self.assertEqual(
            engine.evaluate(metadata("/appsettings.production.json", size=21))[
                "priority"
            ],
            0,
        )
        self.assertEqual(engine.evaluate(metadata("/.env"))["priority"], 30)

    def test_partial_filename_matching_is_literal_and_group_capped(self):
        engine = Engine(load())
        for name in ("creds.xlsx", "vpn_pass_backup.txt", "CRED2026.csv"):
            result = engine.evaluate(metadata("/" + name))
            self.assertEqual(result["category_scores"]["credentials"], 15)
        result = engine.evaluate(metadata("/credentials.txt"))
        self.assertEqual(result["category_scores"]["credentials"], 25)
        fragment = next(
            s
            for s in result["signals"]
            if s["rule_id"] == "builtin.credential-fragment"
        )
        self.assertEqual(fragment["credited_points"], 0)
        self.assertEqual(
            fragment["evidence"]["filename_contains_any_matched_terms"], ["cred"]
        )
        self.assertEqual(
            engine.evaluate(metadata("/employeeSSNexport.xlsx"))["category_scores"][
                "personal-information"
            ],
            15,
        )
        literal = Engine(
            validate({"version": 1, "rules": [rule(filename_contains_any=["pass*"])]})
        )
        self.assertEqual(literal.evaluate(metadata("/passwords.txt"))["priority"], 0)
        self.assertEqual(literal.evaluate(metadata("/pass*notes.txt"))["priority"], 30)
        # Broad substrings intentionally retain possible false positives at low weight.
        self.assertEqual(engine.evaluate(metadata("/compass.txt"))["priority"], 15)

    def test_partial_parent_and_context_matching(self):
        rules = load_text(
            """version = 1
[[contexts]]
id = "area"
tag = "area"
directory_name_contains_any = ["deploy"]
apply_to_descendants = 0
[[rules]]
id = "file"
description = "file"
category = "infrastructure"
signal_group = "context"
points = 30
[rules.when]
context_any = ["area"]
parent_name_contains_any = ["prod"]
""",
            False,
        )
        engine = Engine(rules)
        self.assertEqual(
            engine.evaluate(metadata("/ProdDeploy2026/notes.txt"))["priority"], 30
        )
        self.assertEqual(
            engine.evaluate(metadata("/ProdDeploy2026/child/notes.txt"))["priority"], 0
        )

    def test_invalid_rules_fail_instead_of_silently_broadening(self):
        valid: Dict[str, Any] = {"version": 1, "rules": [rule()]}
        variants: List[Dict[str, Any]] = [
            {"version": True},
            {"version": 2},
            {"version": 1, "rules": ["bad"]},
            {"version": 1, "rules": [rule(), rule()]},
            {"version": 1, "rules": [rule(context_any=["missing"])]},
            {"version": 1, "rules": [rule(content_any=["secret"])]},
            {"version": 1, "rules": [rule(points=True)]},
            {"version": 1, "rules": [rule(extension_any=[])]},
            {"version": 1, "rules": [rule(min_size_bytes=30, max_size_bytes=10)]},
        ]
        malformed = copy.deepcopy(valid)
        malformed["rules"][0]["download"] = True
        variants.append(malformed)
        for variant in variants:
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                validate(variant)


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.database = self.root / "shrawler.db"

    def scan(self, files: List[Dict[str, Any]], status: str = "completed") -> str:
        store = ScanStore(self.root, "spider", "DOMAIN", "alice")
        store.upsert_host("server", "server", "complete")
        store.upsert_share("server", "DATA", "complete", {})
        for payload in files:
            store.add_file("server", "DATA", payload)
        store.finish(status, {})
        identifier = store.scan_id
        store.close()
        return identifier

    def test_scoring_uses_historical_observations_and_preserves_inventory(self):
        first = self.scan([metadata(size=10), metadata("/notes.txt")])
        self.scan([metadata(size=999)])
        original = self.database.read_bytes()
        rules = validate(
            {
                "version": 1,
                "rules": [rule(extension_any=[".config"], max_size_bytes=20)],
            }
        )
        result = rank(self.database, rules, first)
        listing = list_results(self.database)
        self.assertEqual(result["files_scored"], 2)
        self.assertEqual(listing["items"][0]["size_bytes"], 10)
        self.assertEqual(listing["items"][0]["priority"], 30)
        self.assertEqual(original, self.database.read_bytes())
        second = rank(self.database, rules, first)
        self.assertEqual(result["inventory_hash"], second["inventory_hash"])
        self.assertNotEqual(result["run_id"], second["run_id"])
        detail = explain(
            self.database, listing["items"][0]["file_id"], result["run_id"]
        )
        self.assertEqual(detail["size_bytes"], 10)
        self.assertEqual(detail["rules_hash"], rules.digest)
        self.assertTrue(detail["rule_diagnostics"][0]["matched"])

    def test_category_order_and_prior_runs_remain_available(self):
        self.scan([metadata(), metadata("/vault.kdbx"), metadata("/notes.txt")])
        first = rank(self.database, load())
        all_items = list_results(self.database)["items"]
        self.assertEqual(all_items[0]["file_name"], "vault.kdbx")
        infrastructure = list_results(self.database, category="infrastructure")["items"]
        self.assertEqual(len(infrastructure), 1)
        self.assertEqual(infrastructure[0]["review_score"], 50)
        rank(self.database, validate({"version": 1}))
        self.assertEqual(list_results(self.database)["items"][0]["priority"], 0)
        self.assertEqual(
            list_results(self.database, first["run_id"])["items"][0]["priority"], 60
        )

    def test_interrupted_inventory_requires_explicit_selection(self):
        scan_id = self.scan([metadata()], "interrupted")
        with self.assertRaises(ValueError):
            rank(self.database, load())
        result = rank(self.database, load(), scan_id)
        self.assertEqual(result["scan_status"], "interrupted")
        self.assertEqual(result["files_scored"], 1)

    def test_offline_cli_and_rule_preview(self):
        self.scan([metadata(), metadata("/\x1b[31mnotes.txt")])
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE files SET public_id=? WHERE file_name=?",
                ("-leading-hyphen-id", "production.config"),
            )
        with patch.object(
            socket.socket, "connect", side_effect=AssertionError("network used")
        ), patch("shrawler.cli._create_auth", side_effect=AssertionError("auth used")):
            with redirect_stdout(io.StringIO()) as stream, self.assertRaises(
                SystemExit
            ) as exit_info:
                dispatch(["triage", "run", str(self.database), "--json"])
            self.assertEqual(exit_info.exception.code, 0)
            summary = json.loads(stream.getvalue())
            self.assertEqual(summary["files_scored"], 2)
            with redirect_stdout(io.StringIO()) as stream:
                self.assertEqual(main(["list", str(self.database)]), 0)
            self.assertNotIn("\x1b", stream.getvalue())
            with redirect_stdout(io.StringIO()) as stream:
                self.assertEqual(main(["list", str(self.database), "--json"]), 0)
            file_id = json.loads(stream.getvalue())["items"][0]["file_id"]
            with redirect_stdout(io.StringIO()) as stream:
                self.assertEqual(
                    main(["explain", str(self.database), "--json", "--", file_id]), 0
                )
            self.assertEqual(json.loads(stream.getvalue())["priority"], 50)
            candidate = self.root / "candidate.toml"
            candidate.write_text("version = 1\n", encoding="utf-8")
            with sqlite3.connect(result_path(self.database)) as connection:
                before = connection.execute(
                    "SELECT COUNT(*) FROM triage_runs"
                ).fetchone()[0]
            with redirect_stdout(io.StringIO()) as stream:
                self.assertEqual(
                    main(
                        [
                            "rules",
                            "test",
                            str(self.database),
                            str(candidate),
                            "--no-builtins",
                            "--json",
                        ]
                    ),
                    0,
                )
            self.assertTrue(
                all(
                    item["priority"] == 0
                    for item in json.loads(stream.getvalue())["items"]
                )
            )
            with sqlite3.connect(result_path(self.database)) as connection:
                self.assertEqual(
                    before,
                    connection.execute("SELECT COUNT(*) FROM triage_runs").fetchone()[
                        0
                    ],
                )

    def test_interrupted_ranking_is_not_published(self):
        self.scan([metadata()])
        with patch.object(
            Engine, "evaluate", side_effect=KeyboardInterrupt
        ), self.assertRaises(KeyboardInterrupt):
            rank(self.database, load())
        with self.assertRaises(ValueError):
            list_results(self.database)
        with sqlite3.connect(result_path(self.database)) as connection:
            self.assertEqual(
                connection.execute("SELECT status FROM triage_runs").fetchone()[0],
                "interrupted",
            )

    def test_sibling_context_is_two_pass_and_explainable(self):
        self.scan(
            [
                metadata("/Project42/settings.config"),
                metadata("/Project42/web.config"),
                metadata("/Project42/deploy.ps1"),
                metadata("/Project42/child/other.config"),
                metadata("/Project42/child/deeper/other.config"),
                metadata("/Other/web.config"),
            ]
        )
        result = rank(self.database, load())
        items = {
            item["remote_path"]: item for item in list_results(self.database)["items"]
        }
        self.assertEqual(items["/Project42/settings.config"]["priority"], 30)
        self.assertEqual(items["/Project42/child/other.config"]["priority"], 30)
        self.assertEqual(items["/Project42/child/deeper/other.config"]["priority"], 0)
        self.assertEqual(items["/Other/web.config"]["priority"], 0)
        detail = explain(self.database, items["/Project42/settings.config"]["file_id"])
        self.assertEqual(
            {w["file_name"] for w in detail["contexts"][0]["sibling_evidence"]},
            {"web.config", "deploy.ps1"},
        )
        self.assertTrue(
            next(
                r
                for r in detail["rule_diagnostics"]
                if r["rule_id"] == "builtin.deployment-config"
            )["matched"]
        )
        # deploy.ps1 now has its own operational-purpose signal in addition to
        # serving as sibling context for the three configuration files.
        self.assertEqual(items["/Project42/deploy.ps1"]["priority"], 10)
        self.assertEqual(result["summary"]["positive_files"], 4)

    def test_sibling_patterns_require_distinct_files_and_historical_scope(self):
        custom = validate(
            {
                "version": 1,
                "contexts": [
                    {
                        "id": "siblings",
                        "tag": "siblings",
                        "sibling_name_any": ["*.config", "web.*"],
                        "minimum_distinct_patterns": 2,
                        "apply_to_descendants": 0,
                    }
                ],
                "rules": [rule(context_any=["siblings"])],
            }
        )
        first = self.scan([metadata("/Project42/web.config")], "interrupted")
        rank(self.database, custom, first)
        self.assertEqual(list_results(self.database)["items"][0]["priority"], 0)
        self.scan(
            [metadata("/Project42/web.config"), metadata("/Project42/app.config")]
        )
        rank(self.database, custom)
        self.assertTrue(
            all(item["priority"] == 30 for item in list_results(self.database)["items"])
        )
        rank(self.database, custom, first)
        self.assertEqual(list_results(self.database)["items"][0]["priority"], 0)

    def test_ranked_cursor_preserves_ties_and_categories(self):
        self.scan(
            [metadata(f"/Deployments/App/{i}.production.config") for i in range(9)]
            + [metadata("/plain.txt")]
        )
        rank(self.database, load())
        for category, expected in ((None, 10), ("infrastructure", 9)):
            ids: List[str] = []
            after = None
            while True:
                result = list_results(
                    self.database, category=category, limit=2, after=after
                )
                ids.extend(item["file_id"] for item in result["items"])
                after = tuple(result["next_cursor"]) if result["next_cursor"] else None
                if after is None:
                    break
            self.assertEqual(len(ids), expected)
            self.assertEqual(len(set(ids)), expected)

    def test_missing_database_does_not_create_inventory_or_results(self):
        with self.assertRaises(sqlite3.OperationalError):
            rank(self.database, load())
        self.assertFalse(self.database.exists())
        self.assertFalse(result_path(self.database).exists())

    def test_rule_loading_across_files_and_stable_hash(self):
        rules_dir = self.root / "rules"
        rules_dir.mkdir()
        (rules_dir / "context.toml").write_text("""version = 1
[[contexts]]
id = "manual"
tag = "orion"
host = "server"
share = "DATA"
path = "/Orion"
apply_to_descendants = 0
""")
        (rules_dir / "rule.toml").write_text("""version = 1
[[rules]]
id = "file"
description = "Orion configuration"
category = "infrastructure"
signal_group = "configuration"
points = 30
[rules.when]
extension_any = [".config"]
context_any = ["orion"]
""")
        loaded = load([rules_dir], False)
        self.assertEqual(
            Engine(loaded).evaluate(metadata("/Orion/settings.config"))["priority"], 30
        )
        self.assertEqual(loaded.digest, load([rules_dir], False).digest)
        with self.assertRaises(ValueError):
            load([rules_dir, rules_dir], False)


if __name__ == "__main__":
    unittest.main()
