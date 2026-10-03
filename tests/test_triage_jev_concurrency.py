"""Concurrency, packing, storage-migration, and cache tests for Jev.

These exercise the plan's workstreams B/C/D/E/F invariants directly rather than
only through the legacy end-to-end suite.
"""

import json
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional

from shrawler.store import ScanStore
from shrawler.triage.jev.client import Answer, DecisionResponse, JevClient
from shrawler.triage.jev.config import JevConfig
from shrawler.triage.jev.planner import (
    TokenCounter,
    plan_run,
    split_input_error_batch,
)
from shrawler.triage.jev.runner import JevRunner, RateLimiter
from shrawler.triage.jev.storage import SCHEMA_VERSION, JevStore


def metadata(path: str, size: int = 20) -> Dict[str, Any]:
    name = path.replace("\\", "/").rsplit("/", 1)[-1]
    return {
        "host": "server",
        "share": "DATA",
        "file_name": name,
        "remote_path": path,
        "unc_path": "\\\\server\\DATA\\" + path.lstrip("/").replace("/", "\\"),
        "size_bytes": size,
        "mtime_utc": "2026-01-01T00:00:00+00:00",
        "scan_timestamp_utc": "2026-09-05T00:00:00+00:00",
        "readable_size": f"{size}B",
    }


def make_scan(root: Path, files: List[Dict[str, Any]], scan_id: Optional[str] = None):
    store = ScanStore(root, "spider", "DOMAIN", "alice")
    store.upsert_host("server", "server", "complete")
    store.upsert_share("server", "DATA", "complete", {})
    for payload in files:
        store.add_file("server", "DATA", payload)
    store.finish("completed", {})
    identifier = store.scan_id
    store.close()
    return identifier


class CountingClient(JevClient):
    """Deterministic local tokenizer + immediate answers."""

    def __init__(self, config: JevConfig, answers: Optional[Dict[str, str]] = None) -> None:
        super().__init__(config)
        self.calls = 0
        self.answers = answers or {}

    def count_tokens(self, text: str) -> Optional[int]:
        return max(1, len(text.split()))

    def decide(self, payload: Dict[str, Any]) -> DecisionResponse:
        self.calls += 1
        return DecisionResponse(
            answers={
                file_id: Answer(
                    file_id=file_id,
                    choice=self.answers.get(file_id, "3"),
                    distribution={"3": 0.7},
                )
                for file_id in payload.get("questions", {})
            },
            usage={"input_tokens": 5},
            model="jev-fake",
            http_status=200,
            latency_ms=1,
        )


class ConcurrencyClient(CountingClient):
    """Tracks the peak number of simultaneously executing requests."""

    lock = threading.Lock()
    active = 0
    peak = 0

    def decide(self, payload: Dict[str, Any]) -> DecisionResponse:
        with ConcurrencyClient.lock:
            ConcurrencyClient.active += 1
            ConcurrencyClient.peak = max(
                ConcurrencyClient.peak, ConcurrencyClient.active
            )
        try:
            time.sleep(0.03)
            return super().decide(payload)
        finally:
            with ConcurrencyClient.lock:
                ConcurrencyClient.active -= 1


class AuthedClient(CountingClient):
    """Records a single call index used by the canary/auth tests."""

    def __init__(self, config: JevConfig, fail_auth_for: int = 0) -> None:
        super().__init__(config)
        self.fail_auth_for = fail_auth_for

    def decide(self, payload: Dict[str, Any]) -> DecisionResponse:
        self.calls += 1
        if self.calls <= self.fail_auth_for:
            from shrawler.triage.jev.client import AuthError

            raise AuthError("invalid key")
        return super().decide(payload)


class PlannerPackingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.root = root
        self.database = root / "shrawler.db"
        # Many single-file directories on one share.
        files = [
            metadata(f"/cluster{i:03d}/only.csv") for i in range(30)
        ]
        self.scan_id = make_scan(root, files)

    def config(self, **overrides: Any) -> JevConfig:
        base = {
            "endpoint": "https://example.test/v1/systemone",
            "model": "jev-fake",
            "packing_scope": "multi-directory",
        }
        base.update(overrides)
        return JevConfig.from_mapping(base)

    def test_packs_tiny_directories_into_one_request(self) -> None:
        config = self.config()
        with JevStore(self.database) as store:
            runner = JevRunner(
                self.database, config, store, client=CountingClient(config)
            )
            run_id = runner.prepare(self.scan_id)["run_id"]
            counter = TokenCounter(runner.client, config)
            result = plan_run(store, run_id, config, counter)
            self.assertLess(result.batches, 30)
            # Each batch records every directory it references.
            for batch_id in result.batch_ids:
                hashes = store.batch_directory_hashes(batch_id)
                members = store.batch_members(batch_id)
                directories = {
                    int(row["directory_id"])
                    for row in store.batch_members_with_directory(batch_id)
                }
                self.assertEqual(set(hashes), directories)
                self.assertEqual(len(members), len(set(members)))

    def test_directory_context_appears_once_per_block(self) -> None:
        config = self.config()
        with JevStore(self.database) as store:
            runner = JevRunner(
                self.database, config, store, client=CountingClient(config)
            )
            run_id = runner.prepare(self.scan_id)["run_id"]
            counter = TokenCounter(runner.client, config)
            plan_run(store, run_id, config, counter)
            row = store.batch_rows(run_id)[0]
            # The first example must render one labeled block per directory.
            payload = json.loads(row["payload_json"])
            self.assertIn("Directory D000001:", payload["state"])
            self.assertEqual(payload["state"].count("Directory D"), len(
                store.batch_directory_hashes(str(row["id"]))
            ))

    def test_wide_directory_repeats_context_across_requests(self) -> None:
        root = Path(self.tmp.name) / "wide"
        files = [metadata(f"/wide/export_{i:04d}.csv") for i in range(60)]
        scan_id = make_scan(root, files)
        config = self.config(max_questions_per_request=10)
        with JevStore(root / "shrawler.db") as store:
            runner = JevRunner(
                root / "shrawler.db", config, store, client=CountingClient(config)
            )
            run_id = runner.prepare(scan_id)["run_id"]
            counter = TokenCounter(runner.client, config)
            result = plan_run(store, run_id, config, counter)
            self.assertEqual(result.batches, 6)
            for batch_id in result.batch_ids:
                self.assertIn("Directory D000001:", store.connection.execute(
                    "SELECT state_json FROM request_batches WHERE id=?", (batch_id,)
                ).fetchone()[0])

    def test_run_wide_ordinals_are_globally_increasing(self) -> None:
        config = self.config()
        with JevStore(self.database) as store:
            runner = JevRunner(
                self.database, config, store, client=CountingClient(config)
            )
            run_id = runner.prepare(self.scan_id)["run_id"]
            counter = TokenCounter(runner.client, config)
            plan_run(store, run_id, config, counter)
            ordinals = [
                int(row["ordinal"]) for row in store.batch_rows(run_id)
            ]
            self.assertEqual(ordinals, sorted(ordinals))
            self.assertEqual(len(ordinals), len(set(ordinals)))

    def test_enforces_question_cap_and_byte_limit(self) -> None:
        config = self.config(max_questions_per_request=5, max_request_bytes=1)
        with JevStore(self.database) as store:
            runner = JevRunner(
                self.database, config, store, client=CountingClient(config)
            )
            run_id = runner.prepare(self.scan_id)["run_id"]
            counter = TokenCounter(runner.client, config)
            result = plan_run(store, run_id, config, counter)
            self.assertGreater(result.batches, 1)

    def test_single_oversized_candidate_is_visible_input_error(self) -> None:
        config = self.config(
            max_questions_per_request=1,
            max_input_tokens=1000,
            max_state_longest_question_tokens=1000,
            token_headroom_percent=0,
        )
        root = Path(self.tmp.name) / "huge"
        # Many whitespace-separated candidate records exceed the byte-estimate
        # budget once the directory block is included, so the single candidate
        # cannot fit an empty request and becomes a visible input error.
        oversized = metadata("/huge/" + " ".join(["token"] * 3000) + ".csv")
        scan_id = make_scan(root, [oversized])
        with JevStore(root / "shrawler.db") as store:
            runner = JevRunner(
                root / "shrawler.db", config, store, client=CountingClient(config)
            )
            run_id = runner.prepare(scan_id)["run_id"]
            counter = TokenCounter(runner.client, config)
            result = plan_run(store, run_id, config, counter)
            self.assertEqual(result.batches, 0)
            self.assertEqual(len(result.oversized_files), 1)
            counts = store.status_counts(run_id)
            self.assertEqual(counts.get("input-error"), 1)

    def test_split_input_error_batch_is_deterministic(self) -> None:
        config = self.config(max_questions_per_request=20, retries=2)
        root = Path(self.tmp.name) / "split"
        scan_id = make_scan(
            root, [metadata(f"/s/f{i}.csv") for i in range(8)]
        )
        with JevStore(root / "shrawler.db") as store:
            runner = JevRunner(
                root / "shrawler.db", config, store, client=CountingClient(config)
            )
            run_id = runner.prepare(scan_id)["run_id"]
            counter = TokenCounter(runner.client, config)
            result = plan_run(store, run_id, config, counter)
            self.assertEqual(result.batches, 1)
            original = store.batch_rows(run_id)[0]
            created = split_input_error_batch(
                store, run_id, original, config, counter, config.objective, "413"
            )
            self.assertEqual(created, 2)
            terminal = store.connection.execute(
                "SELECT status FROM request_batches WHERE id=?",
                (original["id"],),
            ).fetchone()[0]
            self.assertEqual(terminal, "input-error")
            children = store.batch_rows(run_id, "planned")
            self.assertEqual(len(children), 2)
            members = sorted(
                member
                for batch in children
                for member in store.batch_members(str(batch["id"]))
            )
            self.assertEqual(members, sorted(
                store.batch_members(str(original["id"]))
            ))

    def test_zero_remote_tokenizer_requests_by_default(self) -> None:
        config = self.config()
        with JevStore(self.database) as store:
            runner = JevRunner(
                self.database, config, store, client=CountingClient(config)
            )
            run_id = runner.prepare(self.scan_id)["run_id"]
            counter = TokenCounter(runner.client, config)
            plan_run(store, run_id, config, counter)
            self.assertEqual(counter.cache, {})


class DispatcherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.database = self.root / "shrawler.db"
        files = [metadata(f"/c{i:02d}/f.csv") for i in range(24)]
        self.scan_id = make_scan(self.root, files)

    def config(self, **overrides: Any) -> JevConfig:
        base = {
            "endpoint": "https://example.test/v1/systemone",
            "model": "jev-fake",
            "packing_scope": "directory",
        }
        base.update(overrides)
        return JevConfig.from_mapping(base)

    def test_never_exceeds_configured_workers(self) -> None:
        ConcurrencyClient.peak = 0
        config = self.config(workers=4)
        with JevStore(self.database) as store:
            runner = JevRunner(
                self.database, config, store, client=ConcurrencyClient(config)
            )
            run_id = runner.prepare(self.scan_id)["run_id"]
            runner.plan(run_id)
            outcome = runner.run(run_id, "owner")
            self.assertEqual(outcome["status"], "completed")
            self.assertGreaterEqual(ConcurrencyClient.peak, 2)
            self.assertLessEqual(ConcurrencyClient.peak, 4)

    def test_one_run_completes_all_files_with_reconciliation(self) -> None:
        config = self.config(workers=8, packing_scope="multi-directory")
        with JevStore(self.database) as store:
            runner = JevRunner(
                self.database, config, store, client=CountingClient(config)
            )
            run_id = runner.prepare(self.scan_id)["run_id"]
            runner.plan(run_id)
            outcome = runner.run(run_id, "owner")
            status = runner.status(run_id)
            self.assertEqual(outcome["status"], "completed")
            self.assertEqual(status["assessed"], 24)
            self.assertTrue(status["reconciled"])
            self.assertTrue(store.verify_status_counts(run_id))

    def test_auth_canary_stops_the_pool(self) -> None:
        config = self.config(workers=8, retries=5)
        client = AuthedClient(config, fail_auth_for=1)
        with JevStore(self.database) as store:
            runner = JevRunner(self.database, config, store, client=client)
            run_id = runner.prepare(self.scan_id)["run_id"]
            runner.plan(run_id)
            outcome = runner.run(run_id, "owner")
            self.assertEqual(outcome["status"], "failed")
            self.assertEqual(client.calls, 1)

    def test_cache_reuse_avoids_resending(self) -> None:
        config = self.config(packing_scope="multi-directory")
        with JevStore(self.database) as store:
            first = CountingClient(config)
            runner = JevRunner(self.database, config, store, client=first)
            run1, scan_id = runner.prepare(self.scan_id)["run_id"], self.scan_id
            runner.plan(run1)
            runner.run(run1, "owner-1")
            self.assertEqual(first.calls, 1)
            second = CountingClient(config)
            runner2 = JevRunner(self.database, config, store, client=second)
            run2 = runner2.prepare(scan_id)["run_id"]
            runner2.plan(run2)
            outcome = runner2.run(run2, "owner-2")
            self.assertEqual(second.calls, 0)
            self.assertEqual(outcome["counts"].get("assessed"), 24)
            self.assertEqual(runner2.metrics.get("reused_requests"), 1)
            sources = {
                row["source"]
                for row in store.connection.execute(
                    "SELECT source FROM decision_results WHERE run_id=?", (run2,)
                )
            }
            self.assertEqual(sources, {"cache"})

    def test_rate_limiter_window(self) -> None:
        limiter = RateLimiter(2)
        self.assertFalse(limiter.blocked(100.0))
        limiter.record(100.0)
        limiter.record(100.1)
        self.assertTrue(limiter.blocked(100.2))
        # The earliest admission ages out after the 60s window.
        self.assertFalse(limiter.blocked(160.2))

    def test_rate_limiter_unlimited_by_default(self) -> None:
        limiter = RateLimiter(0)
        for i in range(1000):
            limiter.record(float(i))
        self.assertFalse(limiter.blocked(1000.0))


class StoreMigrationTests(unittest.TestCase):
    V1 = """
    CREATE TABLE assessment_runs (
     id TEXT PRIMARY KEY, source_path TEXT NOT NULL, scan_id TEXT NOT NULL,
     scan_json TEXT NOT NULL, source_fingerprint TEXT NOT NULL, objective TEXT NOT NULL,
     config_json TEXT NOT NULL, config_fingerprint TEXT NOT NULL,
     deployment_revision TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL,
     started_at TEXT, finished_at TEXT, heartbeat_at TEXT, lease_owner TEXT,
     owner_pid INTEGER, budget_seconds INTEGER NOT NULL DEFAULT 0,
     total_observed INTEGER NOT NULL DEFAULT 0, ledger_complete INTEGER NOT NULL DEFAULT 0,
     file_count INTEGER NOT NULL DEFAULT 0, context_count INTEGER NOT NULL DEFAULT 0,
     counters_json TEXT, error TEXT);
    CREATE TABLE directory_contexts (run_id TEXT NOT NULL, directory_id INTEGER NOT NULL,
     host TEXT NOT NULL, share TEXT NOT NULL, parent TEXT NOT NULL, context_json TEXT NOT NULL,
     context_hash TEXT NOT NULL, observed_files INTEGER NOT NULL, context_tokens INTEGER NOT NULL,
     truncated INTEGER NOT NULL DEFAULT 0, omitted_json TEXT,
     enumeration TEXT NOT NULL DEFAULT 'x', PRIMARY KEY(run_id,directory_id));
    CREATE TABLE assessment_files (run_id TEXT NOT NULL, file_id TEXT NOT NULL,
     directory_id INTEGER NOT NULL, file_name TEXT NOT NULL, remote_path TEXT NOT NULL,
     unc_path TEXT NOT NULL, size_bytes INTEGER NOT NULL, mtime_utc TEXT, extension TEXT NOT NULL,
     feature_json TEXT NOT NULL, feature_hash TEXT NOT NULL, priority INTEGER NOT NULL DEFAULT 0,
     status TEXT NOT NULL, batch_id TEXT, result_id INTEGER, attempts INTEGER NOT NULL DEFAULT 0,
     error TEXT, updated_at TEXT NOT NULL, PRIMARY KEY(run_id,file_id));
    CREATE TABLE request_batches (id TEXT PRIMARY KEY, run_id TEXT NOT NULL,
     directory_id INTEGER NOT NULL, request_id TEXT NOT NULL, ordinal INTEGER NOT NULL,
     payload_json TEXT NOT NULL, payload_sha256 TEXT NOT NULL, input_tokens INTEGER NOT NULL,
     state_json TEXT NOT NULL, question_json TEXT NOT NULL, status TEXT NOT NULL,
     attempts INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, dispatched_at TEXT,
     finished_at TEXT, error TEXT, usage_json TEXT, http_status INTEGER,
     remote_model TEXT, duration_ms INTEGER, cache_key TEXT NOT NULL DEFAULT '');
    CREATE TABLE batch_members (run_id TEXT NOT NULL, batch_id TEXT NOT NULL, file_id TEXT NOT NULL,
     ordinal INTEGER NOT NULL, PRIMARY KEY(batch_id,file_id));
    CREATE TABLE decision_results (id INTEGER PRIMARY KEY, run_id TEXT NOT NULL,
     batch_id TEXT NOT NULL, request_id TEXT NOT NULL, file_id TEXT NOT NULL, choice TEXT NOT NULL,
     distribution_json TEXT, deployment_revision TEXT NOT NULL, model TEXT NOT NULL,
     adapter_version TEXT NOT NULL, rubric_version TEXT NOT NULL, context_hash TEXT NOT NULL,
     created_at TEXT NOT NULL);
    CREATE TABLE assessment_labels (id INTEGER PRIMARY KEY, run_id TEXT NOT NULL,
     file_id TEXT NOT NULL, label TEXT NOT NULL, source TEXT NOT NULL,
     note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL);
    """

    def build_v1(self) -> Path:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        database = Path(self.tmp.name) / "shrawler.db"
        connection = sqlite3.connect(database.with_name("shrawler.jev.db"))
        connection.executescript(self.V1)
        connection.execute(
            "INSERT INTO assessment_runs(id,source_path,scan_id,scan_json,"
            "source_fingerprint,objective,config_json,config_fingerprint,"
            "deployment_revision,status,created_at,total_observed,context_count) "
            "VALUES ('run1','p','s','{}','fp','obj','{}','cf','rev1','completed',"
            "'now',2,1)"
        )
        connection.execute(
            "INSERT INTO directory_contexts VALUES ('run1',1,'h','sh','/d',"
            '\'{"directory":"/d"}\',\'ch1\',2,10,0,NULL,\'x\')'
        )
        for file_id, status in (("F1", "assessed"), ("F2", "pending")):
            connection.execute(
                "INSERT INTO assessment_files(run_id,file_id,directory_id,file_name,"
                "remote_path,unc_path,size_bytes,extension,feature_json,feature_hash,"
                "status,updated_at) VALUES ('run1',?,1,?,?,?,10,'.txt','{}','fh',?,'now')",
                (file_id, file_id, file_id, file_id, status),
            )
        connection.execute(
            "INSERT INTO request_batches(id,run_id,directory_id,request_id,ordinal,"
            "payload_json,payload_sha256,input_tokens,state_json,question_json,status,"
            "created_at,cache_key) VALUES ('b1','run1',1,'b1',1,'{\"a\":1}','sha',5,"
            "'s','q','completed','now','ck')"
        )
        connection.execute(
            "INSERT INTO batch_members VALUES ('run1','b1','F1',0)"
        )
        connection.execute(
            "INSERT INTO decision_results(run_id,batch_id,request_id,file_id,choice,"
            "deployment_revision,model,adapter_version,rubric_version,context_hash,"
            "created_at) VALUES ('run1','b1','b1','F1','3','rev1','m','a','r','ch1','now')"
        )
        connection.execute("PRAGMA user_version=1")
        connection.commit()
        connection.close()
        return database

    def test_migrates_v1_without_losing_state(self) -> None:
        database = self.build_v1()
        with JevStore(database) as store:
            self.assertEqual(
                store.connection.execute("PRAGMA user_version").fetchone()[0],
                SCHEMA_VERSION,
            )
            self.assertTrue(store.verify_status_counts("run1"))
            self.assertEqual(store.status_counts("run1").get("assessed"), 1)
            self.assertEqual(store.status_counts("run1").get("pending"), 1)
            # The batch is preserved and mapped to its directory context.
            row = store.batch_rows("run1")[0]
            self.assertEqual(row["status"], "completed")
            self.assertEqual(row["cache_key"], "ck")
            self.assertEqual(store.batch_directory_hashes("b1"), {1: "ch1"})
            self.assertEqual(len(store.results_for_batch("run1", "b1")), 1)
            self.assertEqual(
                store.connection.execute(
                    "SELECT COUNT(*) FROM assessment_files WHERE run_id='run1'"
                ).fetchone()[0],
                2,
            )
        # Re-opening is idempotent.
        with JevStore(database) as store:
            self.assertEqual(
                store.connection.execute("PRAGMA user_version").fetchone()[0],
                SCHEMA_VERSION,
            )

    def test_counters_stay_reconciled_through_transitions(self) -> None:
        database = self.build_v1()
        with JevStore(database) as store:
            store.set_file_status("run1", ["F2"], "planned", batch_id="b2")
            self.assertEqual(store.status_counts("run1").get("planned"), 1)
            self.assertEqual(store.status_counts("run1").get("pending", 0), 0)
            self.assertTrue(store.verify_status_counts("run1"))
            store.set_file_status("run1", ["F2"], "assessed")
            self.assertEqual(store.status_counts("run1").get("assessed"), 2)
            self.assertTrue(store.verify_status_counts("run1"))

    def test_status_queries_do_not_load_payloads(self) -> None:
        database = self.build_v1()
        with JevStore(database) as store:
            # A payload larger than any sane status query; loading it would be
            # detectable by size but the durable counter path never selects it.
            store.connection.execute(
                "UPDATE request_batches SET payload_json=? WHERE id='b1'",
                ("x" * 5_000_000,),
            )
            store.connection.commit()

            runner = JevRunner(
                database,
                JevConfig.from_mapping({"endpoint": "https://x/v1"}),
                store,
            )
            payload = runner.status("run1")
            self.assertNotIn("payload_json", json.dumps(payload))
            self.assertEqual(payload["batches"]["total"], 1)


if __name__ == "__main__":
    unittest.main()
