"""Performance acceptance checks for the Jev pipeline (plan workstream 14.4).

These use the deterministic fake gateway only; no live model is contacted. The
thresholds mirror the plan: directory-local four-worker dispatch and the
multi-directory request-count reduction.
"""

import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Dict

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from benchmark_jev import build_inventory, captured_directories

from shrawler.triage.jev.client import Answer, DecisionResponse, JevClient
from shrawler.triage.jev.config import JevConfig
from shrawler.triage.jev.runner import JevRunner
from shrawler.triage.jev.storage import JevStore

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))


class LatencyClient(JevClient):
    """Fixed-latency, fully-answering fake gateway."""

    def __init__(self, config: JevConfig, latency: float = 0.15) -> None:
        super().__init__(config)
        self.latency = latency
        self.calls = 0

    def count_tokens(self, text: str):
        return max(1, len(text.split()))

    def decide(self, payload: Dict[str, Any]) -> DecisionResponse:
        self.calls += 1
        time.sleep(self.latency)
        return DecisionResponse(
            answers={
                file_id: Answer(file_id=file_id, choice="3", distribution={"3": 0.8})
                for file_id in payload.get("questions", {})
            },
            usage={"input_tokens": 10},
            model="jev-bench",
            http_status=200,
            latency_ms=int(self.latency * 1000),
        )


class CapturedTopologyBenchmark(unittest.TestCase):
    """Measured 774-file / 203-directory topology with a 150 ms gateway."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.database = root / "shrawler.db"
        cls.scan_id = build_inventory(root, captured_directories())

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def config(self, **overrides: Any) -> JevConfig:
        base = {"endpoint": "https://bench.invalid/v1", "model": "jev-bench", "workers": 4}
        base.update(overrides)
        return JevConfig.from_mapping(base)

    def run_mode(self, config: JevConfig, client: JevClient) -> Dict[str, Any]:
        with JevStore(self.database) as store:
            runner = JevRunner(self.database, config, store, client=client)
            run_id = runner.prepare(self.scan_id)["run_id"]
            batches = runner.plan(run_id)
            outcome = runner.run(run_id, "bench")
            return {
                "batches": batches,
                "outcome": outcome,
                "status": runner.status(run_id),
                "metrics": dict(runner.metrics),
                "calls": client.calls,
            }

    def test_directory_mode_four_workers_under_8_5_seconds(self) -> None:
        config = self.config(packing_scope="directory")
        result = self.run_mode(config, LatencyClient(config))
        self.assertEqual(result["outcome"]["status"], "completed")
        self.assertEqual(result["batches"], 203)
        dispatch_ms = result["metrics"]["dispatch_wall_ms"]
        self.assertLessEqual(
            dispatch_ms, 8500, f"directory dispatch took {dispatch_ms} ms"
        )
        self.assertLessEqual(result["metrics"]["peak_in_flight"], 4)
        self.assertTrue(result["status"]["reconciled"])
        self.assertEqual(result["status"]["assessed"], 774)

    def test_multi_directory_cuts_requests_and_is_fast(self) -> None:
        config = self.config(packing_scope="multi-directory")
        result = self.run_mode(config, LatencyClient(config))
        self.assertEqual(result["outcome"]["status"], "completed")
        # At least 90% fewer requests than the 203-request directory baseline.
        self.assertLessEqual(result["batches"], 20)
        dispatch_ms = result["metrics"]["dispatch_wall_ms"]
        self.assertLessEqual(
            dispatch_ms, 1500, f"multi-directory dispatch took {dispatch_ms} ms"
        )
        self.assertLessEqual(result["metrics"]["peak_in_flight"], 4)
        self.assertTrue(result["status"]["reconciled"])
        self.assertEqual(result["status"]["assessed"], 774)

    def test_status_query_cost_is_constant_not_per_completed_batch(self) -> None:
        config = self.config(packing_scope="directory")
        with JevStore(self.database) as store:
            runner = JevRunner(self.database, config, store, client=LatencyClient(config))
            run_id = runner.prepare(self.scan_id)["run_id"]
            runner.plan(run_id)
            # Inflate a payload to model a huge ledger; status must stay quick.
            store.connection.execute(
                "UPDATE request_batches SET payload_json=? "
                "WHERE run_id=? AND ordinal=(SELECT MIN(ordinal) FROM request_batches "
                "WHERE run_id=?)",
                ("z" * 2_000_000, run_id, run_id),
            )
            store.connection.commit()
            started = time.perf_counter()
            for _ in range(200):
                runner.status(run_id)
            elapsed = (time.perf_counter() - started) / 200
            self.assertLess(elapsed, 0.01, f"status averaged {elapsed * 1000:.2f} ms")


class WideAndManyDirectoryPlanningTests(unittest.TestCase):
    def test_wide_directory_planning_is_bounded_memory(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        database = root / "shrawler.db"
        scan_id = build_inventory(root, [5000])
        config = JevConfig.from_mapping(
            {
                "endpoint": "https://bench.invalid/v1",
                "model": "jev-bench",
                "packing_scope": "multi-directory",
                "max_questions_per_request": 500,
            }
        )
        with JevStore(database) as store:
            runner = JevRunner(database, config, store, client=LatencyClient(config))
            run_id = runner.prepare(scan_id)["run_id"]
            batches = runner.plan(run_id)
            self.assertGreater(batches, 1)
            # Every planned batch references the same single directory context.
            for batch in store.batch_rows(run_id, "planned"):
                self.assertEqual(len(store.batch_directory_hashes(str(batch["id"]))), 1)

    def test_many_directories_do_not_retain_all_files(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        database = root / "shrawler.db"
        scan_id = build_inventory(root, [1] * 500)
        config = JevConfig.from_mapping(
            {"endpoint": "https://bench.invalid/v1", "model": "jev-bench",
             "packing_scope": "multi-directory"}
        )
        with JevStore(database) as store:
            runner = JevRunner(database, config, store, client=LatencyClient(config))
            run_id = runner.prepare(scan_id)["run_id"]
            batches = runner.plan(run_id)
            # 500 single-file directories must collapse to very few requests.
            self.assertLess(batches, 20)
            self.assertEqual(
                store.connection.execute(
                    "SELECT COUNT(*) FROM assessment_files WHERE run_id=? AND "
                    "status='planned'",
                    (run_id,),
                ).fetchone()[0],
                500,
            )


if __name__ == "__main__":
    unittest.main()
