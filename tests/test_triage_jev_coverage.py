"""Coverage and throughput regression tests for the Jev pipeline.

These lock in the guarantees added while making assessment faster: cache reuse
must not end a run early, byte-budget overflow is re-queued rather than dropped,
candidates dispatch highest presentation priority first, and gateway throttling
backs off instead of failing.
"""

import json
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional

from shrawler.store import ScanStore
from shrawler.triage.jev.client import (
    Answer,
    DecisionResponse,
    JevClient,
    ThrottleError,
    _retry_after,
)
from shrawler.triage.jev.config import JevConfig
from shrawler.triage.jev.planner import (
    TokenCounter,
    _fallback_tokens,
    _pending_candidates,
    answer_keys,
    binding_key,
    plan_run,
    resolve_binding_keys,
)
from shrawler.triage.jev.runner import JevRunner
from shrawler.triage.jev.storage import JevStore


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


def make_scan(root: Path, files: List[Dict[str, Any]]) -> str:
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

    def __init__(self, config: JevConfig) -> None:
        super().__init__(config)
        self.calls = 0

    def count_tokens(self, text: str) -> Optional[int]:
        return max(1, len(text.split()))

    def decide(self, payload: Dict[str, Any]) -> DecisionResponse:
        self.calls += 1
        return DecisionResponse(
            answers={
                file_id: Answer(file_id=file_id, choice="3", distribution={"3": 0.7})
                for file_id in payload.get("questions", {})
            },
            usage={"input_tokens": 5},
            model="jev-fake",
            http_status=200,
            latency_ms=1,
        )


class _Response:
    def __init__(
        self,
        status: int,
        body: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
        reason: str = "ERR",
    ) -> None:
        self.status_code = status
        self._body = body
        self.headers = headers or {}
        self.reason = reason

    def json(self) -> Dict[str, Any]:
        return self._body


class BaseCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.database = self.root / "shrawler.db"

    def config(self, **overrides: Any) -> JevConfig:
        base = {"endpoint": "https://example.test/v1/systemone", "model": "jev-fake"}
        base.update(overrides)
        return JevConfig.from_mapping(base)


class BindingKeyTests(BaseCase):
    """The short request-local key must bind an answer to the exact file ID."""

    def test_key_is_deterministic_and_short(self) -> None:
        # Replanning the same candidates must reproduce the same keys, so the
        # exact-request cache and resume stay valid.
        self.assertEqual(binding_key("a"), binding_key("a"))
        self.assertEqual(len(binding_key("a")), 8)
        self.assertNotEqual(binding_key("a"), binding_key("b"))

    def test_keys_are_unique_within_a_request_even_on_prefix_collision(self) -> None:
        entries = [{"file_id": "ADkMO1"}, {"file_id": "ADkMO2"}]
        keys = resolve_binding_keys(entries)
        self.assertEqual(len(keys), 2)
        self.assertEqual(len(set(keys.values())), 2)
        # The mapping is a pure function of the file IDs, not of position, so a
        # replan reproduces exactly the same keys.
        self.assertEqual(keys, resolve_binding_keys(list(reversed(entries))))

    def test_a_prefix_collision_is_widened_not_merged(self) -> None:
        # Two distinct file IDs forced onto the same short prefix must widen, not
        # share a key. Widening must not depend on the entry's position, so the
        # request stays reproducible after a replan.
        class OnlyCollides:
            def __init__(self) -> None:
                self.calls: int = 0

            def __call__(self, file_id: str) -> str:
                self.calls += 1
                return binding_key("shared-prefix")

        entries = [{"file_id": "one"}, {"file_id": "two"}]
        keys = resolve_binding_keys(entries, OnlyCollides())
        self.assertEqual(len(set(keys.values())), 2)
        self.assertEqual(keys, resolve_binding_keys(entries, OnlyCollides()))

    def test_planned_batch_round_trips_keys_through_the_stored_payload(self) -> None:
        files = [
            metadata(f"/a/f{index:03d}.txt") for index in range(12)
        ]
        scan_id = make_scan(self.root, files)
        config = self.config(packing_scope="multi-directory")
        with JevStore(self.database) as store:
            runner = JevRunner(
                self.database, config, store, client=CountingClient(config)
            )
            run_id = runner.prepare(scan_id)["run_id"]
            plan_run(store, run_id, config, TokenCounter(runner.client, config))
            for row in store.batch_rows(run_id):
                members = (
                    str(item["file_id"])
                    for item in store.connection.execute(
                        "SELECT file_id FROM batch_members WHERE batch_id=? "
                        "ORDER BY ordinal",
                        (str(row["id"]),),
                    )
                )
                file_ids = list(members)
                payload = json.loads(row["payload_json"])
                keys = answer_keys(payload, file_ids)
                self.assertEqual(len(keys), len(file_ids))
                for file_id in file_ids:
                    key = keys[file_id]
                    self.assertEqual(key, binding_key(file_id))
                    # The key appears in both the candidate line and the question.
                    self.assertIn(f"  {key} |", payload["state"])
                    self.assertIn(key, payload["questions"][key]["instructions"])
                    # A question key is a binding key, never a raw file ID.
                    self.assertNotIn(file_id, payload["state"])

    def test_a_retied_batch_reproduces_the_same_request(self) -> None:
        # A batch that is dropped and replanned must render the identical
        # request, otherwise the exact-request cache stops working after a crash.
        scan_id = make_scan(
            self.root, [metadata(f"/b/f{index}.txt") for index in range(4)]
        )
        config = self.config(packing_scope="multi-directory")
        with JevStore(self.database) as store:
            first = CountingClient(config)
            runner = JevRunner(self.database, config, store, client=first)
            run_id = runner.prepare(scan_id)["run_id"]
            runner.plan(run_id)
            first_keys = [str(row["cache_key"]) for row in store.batch_rows(run_id)]
            first_payloads = [
                json.loads(row["payload_json"])["questions"] for row in store.batch_rows(run_id)
            ]
            # Replan the same pending candidates into a fresh run over the same
            # database; the cache identity must not change.
            runner.plan(run_id)
            second_payloads = [
                json.loads(row["payload_json"])["questions"] for row in store.batch_rows(run_id)
            ]
            self.assertEqual(first_payloads, second_payloads * 1)
            self.assertEqual(len(set(first_keys)), len(first_keys))


    def test_cache_hit_does_not_end_run_with_later_batches(self) -> None:
        config = self.config(packing_scope="directory")
        scan_a = make_scan(
            self.root, [metadata("/a/f1.txt"), metadata("/b/f2.txt")]
        )
        with JevStore(self.database) as store:
            first = CountingClient(config)
            runner = JevRunner(self.database, config, store, client=first)
            run1 = runner.prepare(scan_a)["run_id"]
            self.assertEqual(runner.plan(run1), 2)
            runner.run(run1, "owner-1")
            self.assertEqual(first.calls, 2)

            # A second capture adds a directory. The first two directory-local
            # requests are exact cache hits; the third is new work. The cached
            # first batch must not stop admission before the third is dispatched.
            scan_b = make_scan(
                self.root,
                [
                    metadata("/a/f1.txt"),
                    metadata("/b/f2.txt"),
                    metadata("/c/f3.txt"),
                ],
            )
            second = CountingClient(config)
            runner2 = JevRunner(self.database, config, store, client=second)
            run2 = runner2.prepare(scan_b)["run_id"]
            self.assertEqual(runner2.plan(run2), 3)
            outcome = runner2.run(run2, "owner-2")
            status = runner2.status(run2)
            self.assertEqual(outcome["status"], "completed")
            self.assertEqual(status["assessed"], 3)
            self.assertTrue(status["reconciled"])
            self.assertEqual(second.calls, 1)
            self.assertEqual(runner2.metrics.get("reused_requests"), 2)


class ProvenCredentialsTests(BaseCase):
    def test_proven_credentials_skips_the_repeat_canary(self) -> None:
        scan_id = make_scan(self.root, [metadata("/p/f1.txt")])
        config = self.config()
        with JevStore(self.database) as store:
            self.assertFalse(store.has_proven_credentials(config.fingerprint()))
            runner = JevRunner(self.database, config, store, client=CountingClient(config))
            run_id = runner.prepare(scan_id)["run_id"]
            runner.plan(run_id)
            runner.run(run_id, "owner")
            # Same config now has a completed batch; a deployment change has not.
            self.assertTrue(store.has_proven_credentials(config.fingerprint()))
            self.assertFalse(
                store.has_proven_credentials(
                    self.config(deployment_revision="rev-different").fingerprint()
                )
            )


class ByteBudgetCoverageTests(BaseCase):
    def test_byte_limited_batches_keep_every_file(self) -> None:
        files = [metadata(f"/wide/export_{i:03d}.csv") for i in range(12)]
        scan_id = make_scan(self.root, files)
        config = self.config(
            packing_scope="directory",
            max_questions_per_request=12,
            max_request_bytes=2000,
        )
        with JevStore(self.database) as store:
            runner = JevRunner(self.database, config, store, client=CountingClient(config))
            run_id = runner.prepare(scan_id)["run_id"]
            counter = TokenCounter(runner.client, config)
            result = plan_run(store, run_id, config, counter)
            self.assertGreater(result.batches, 1, "byte cap should force several requests")
            planned = store.connection.execute(
                "SELECT COUNT(*) FROM assessment_files WHERE run_id=? AND status='planned'",
                (run_id,),
            ).fetchone()[0]
            self.assertEqual(planned, 12)
            members = set()
            for batch_id in result.batch_ids:
                members.update(store.batch_members(batch_id))
            self.assertEqual(len(members), 12)
            self.assertEqual(
                store.status_counts(run_id).get("pending", 0),
                0,
                "trailing candidates must be re-queued, not left pending",
            )


class PriorityOrderTests(BaseCase):
    def test_pending_candidates_are_highest_priority_first(self) -> None:
        scan_id = make_scan(
            self.root, [metadata(f"/d/f{i}.txt") for i in range(4)]
        )
        config = self.config()
        with JevStore(self.database) as store:
            runner = JevRunner(self.database, config, store, client=CountingClient(config))
            run_id = runner.prepare(scan_id)["run_id"]
            for name, priority in {"f0.txt": 1, "f1.txt": 3, "f2.txt": 0, "f3.txt": 2}.items():
                store.connection.execute(
                    "UPDATE assessment_files SET priority=? WHERE run_id=? AND file_name=?",
                    (priority, run_id, name),
                )
            store.connection.commit()
            order = [entry["file_name"] for entry in _pending_candidates(store, run_id)]
            self.assertEqual(order, ["f1.txt", "f3.txt", "f0.txt", "f2.txt"])


class DefaultConfigTests(unittest.TestCase):
    def test_default_packing_scope_is_multi_directory(self) -> None:
        # Multi-directory passed the live rubric evaluation (6/6 at 17/17).
        self.assertEqual(JevConfig().packing_scope, "multi-directory")


class PayloadShapeTests(BaseCase):
    def test_payload_sends_only_filename_and_directory_context(self) -> None:
        scan_id = make_scan(
            self.root,
            [
                metadata("/Finance/Passwords/logins.txt"),
                metadata("/srv/reports/export.csv"),
            ],
        )
        config = self.config(packing_scope="multi-directory")
        with JevStore(self.database) as store:
            runner = JevRunner(
                self.database, config, store, client=CountingClient(config)
            )
            run_id = runner.prepare(scan_id)["run_id"]
            runner.plan(run_id)
            rows = store.batch_rows(run_id)
            self.assertTrue(rows)
            for row in rows:
                payload = json.loads(row["payload_json"])
                state = payload["state"]
                questions = payload["questions"]
                blob = state + json.dumps(questions)
                # Signals with no classification value must not be sent.
                self.assertNotIn("2026-01-01", blob)
                self.assertNotIn("bytes |", blob)
                self.assertNotIn("Observed files", state)
                self.assertNotIn("Extensions:", state)
                self.assertNotIn("Ancestors:", state)
                self.assertNotIn("Completeness:", state)
                # The filename is present as data, but never in instructions.
                self.assertIn("logins.txt", state)
                member_rows = store.connection.execute(
                    "SELECT file_id FROM batch_members WHERE batch_id=? ORDER BY ordinal",
                    (str(row["id"]),),
                ).fetchall()
                member_ids = [str(item["file_id"]) for item in member_rows]
                keys = resolve_binding_keys([{"file_id": item} for item in member_ids])
                self.assertEqual(list(questions), [
                    keys[item] for item in member_ids
                ])
                for key in sorted(questions):
                    question = questions[key]
                    # The binding key names the candidate and its question, and
                    # is shorter than the file ID it stands for.
                    self.assertIn(f"  {key} |", state)
                    self.assertIn(key, question["instructions"])
                    self.assertEqual(set(question["criteria"]), {"0", "1", "2", "3", "4"})
                    self.assertNotIn("logins.txt", question["instructions"])
                    self.assertNotIn("export.csv", question["instructions"])

    def test_answers_map_to_real_file_ids(self) -> None:
        scan_id = make_scan(
            self.root, [metadata(f"/d/f{index}.txt") for index in range(4)]
        )
        config = self.config(packing_scope="multi-directory")
        with JevStore(self.database) as store:
            runner = JevRunner(
                self.database, config, store, client=CountingClient(config)
            )
            run_id = runner.prepare(scan_id)["run_id"]
            runner.plan(run_id)
            runner.run(run_id, "owner")
            stored = {
                str(row["file_id"])
                for row in store.connection.execute(
                    "SELECT DISTINCT file_id FROM decision_results WHERE run_id=?",
                    (run_id,),
                )
            }
            expected = {
                str(row["file_id"])
                for row in store.connection.execute(
                    "SELECT file_id FROM assessment_files WHERE run_id=?", (run_id,)
                )
            }
            self.assertEqual(stored, expected)
            status = runner.status(run_id)
            self.assertTrue(status["reconciled"])
            # Real billed usage from the gateway is surfaced for cost checks.
            self.assertGreater(status["usage"]["billed_input_tokens"], 0)
            self.assertGreater(status["usage"]["tokens_per_file"], 0)


class ThrottleClassificationTests(unittest.TestCase):
    def test_retry_after_seconds_and_http_date(self) -> None:
        self.assertEqual(_retry_after(_Response(429, {}, {"Retry-After": "2.5"})), 2.5)
        self.assertEqual(_retry_after(_Response(429, {})), 0.0)
        self.assertGreater(
            _retry_after(
                _Response(429, {}, {"Retry-After": "Wed, 21 Oct 2099 07:28:00 GMT"})
            ),
            0.0,
        )

    def test_429_is_a_throttle_error_with_retry_after(self) -> None:
        client = JevClient(self._config())
        response = _Response(
            429, {"error": {"message": "rate limited"}}, {"Retry-After": "3"}
        )
        client.session.post = lambda *a, **k: response  # type: ignore[assignment]
        with self.assertRaises(ThrottleError) as ctx:
            client.decide(
                {
                    "model": "m",
                    "state": "s",
                    "questions": {"F1": {"type": "choice", "criteria": {"3": "x"}}},
                }
            )
        self.assertEqual(ctx.exception.retry_after, 3.0)

    def test_503_is_a_throttle_error(self) -> None:
        client = JevClient(self._config())
        response = _Response(503, {"error": {"message": "overloaded"}}, {}, "Unavailable")
        client.session.post = lambda *a, **k: response  # type: ignore[assignment]
        with self.assertRaises(ThrottleError):
            client.decide(
                {
                    "model": "m",
                    "state": "s",
                    "questions": {"F1": {"type": "choice", "criteria": {"3": "x"}}},
                }
            )

    @staticmethod
    def _config() -> JevConfig:
        return JevConfig.from_mapping({"endpoint": "https://example.test/v1/systemone"})


class ThrottleRetryTests(BaseCase):
    def test_throttled_batch_is_retried_and_run_completes(self) -> None:
        scan_id = make_scan(
            self.root, [metadata(f"/t/f{i}.txt") for i in range(3)]
        )
        config = self.config(max_questions_per_request=3, retries=2)

        class ThrottleOnceClient(CountingClient):
            def __init__(self, inner: JevConfig) -> None:
                super().__init__(inner)
                self._failed = False
                self._lock = threading.Lock()

            def decide(self, payload: Dict[str, Any]) -> DecisionResponse:
                with self._lock:
                    first = not self._failed
                    if first:
                        self._failed = True
                if first:
                    self.calls += 1
                    raise ThrottleError("throttled", retry_after=0.01)
                return super().decide(payload)

        client = ThrottleOnceClient(config)
        with JevStore(self.database) as store:
            runner = JevRunner(self.database, config, store, client=client)
            run_id = runner.prepare(scan_id)["run_id"]
            runner.plan(run_id)
            outcome = runner.run(run_id, "owner")
            status = runner.status(run_id)
            self.assertEqual(outcome["status"], "completed")
            self.assertEqual(status["assessed"], 3)
            self.assertTrue(status["reconciled"])
            self.assertGreaterEqual(client.calls, 2)


class EstimatorTests(unittest.TestCase):
    def test_fallback_estimator_is_calibrated(self) -> None:
        # Three UTF-8 bytes per estimated token, with a floor of one.
        self.assertEqual(_fallback_tokens("a" * 3000), 1000)
        self.assertEqual(_fallback_tokens(""), 1)


if __name__ == "__main__":
    unittest.main()
