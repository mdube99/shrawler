# Multi-directory request packing and worker pool

The assessment planner builds the requests the model sees. Two constraints
shape it:

* each request must stay inside the gateway's token and byte budgets, and
* each candidate needs its own directory context so the model is not asked to
  judge a file without knowing where it lives.

The planner packs several small directories into one request using explicit,
isolated directory blocks, and dispatch overlapped network waits inside a bounded
worker pool.

## Why packing

A captured 774-file run contained 203 directories and, before this work,
produced exactly 203 requests. Because dispatch was serial, that run took
~30 seconds of gateway waiting. Packing and bounded concurrency are independent
fixes; both are needed for large inventories where directory count dominates
request count.

Two further costs dominated the payload itself. Every per-file question repeated
the entire rubric, and the token estimator charged one token per UTF-8 byte, so
requests filled early. The rubric is now stated once in the shared objective
while each question carries compact criterion labels, and a calibrated estimator
packs roughly three bytes per token. On the same captured shape this cuts
question bytes by about 61% (607 kB to 235 kB) without dropping a file or
changing which priority levels the model may choose. `packing_scope = "directory"`
remains the default; `multi-directory` is an opt-in that now collapses the same
774 files into 4 requests instead of 14.

## Request shape

One request carries a shared `state` plus a map of `choice` questions keyed by
exact file ID. In multi-directory mode the state contains one labeled block per
source directory:

```text
Objective: ...

Directory D000001:
  Path: \\host\share\Finance\Payroll
  Observed files: 8
  Extensions: .csv=7, .txt=1
  Ancestors: Finance/Payroll
  Sibling markers: readme.txt
  Completeness: observed listing complete
  Candidates:
    F... | export.csv | 1234 bytes | 2026-01-01T00:00:00+00:00
    F... | readme.txt | 512 bytes | 2026-01-01T00:00:00+00:00

Directory D000002:
  ...
```

Filenames and paths are data, never instructions. The question instructions
name the candidate's directory block so an answer is attributed to the correct
context, and every answer is stored against the exact file ID and that file's
own `context_hash`.

## Bounded packing rules

The global planner streams pending candidates in stable
`(directory order, file_id)` order and adds them to the current batch until one
of these limits would be exceeded:

* `state_tokens + sum(question_tokens) <= max_input_tokens`
* `state_tokens + max(question_tokens) <= max_state_longest_question_tokens`
* `max_questions_per_request` candidates
* `max_request_bytes` exact canonical request bytes, when configured
* `token_headroom_percent` safety margin applied to both token budgets

The complete rendered payload is validated against the exact byte cap and the
measured token total before it is persisted, not only against the estimator the
packer used. When a candidate does not fit a non-empty batch, the batch is
flushed and the candidate is retried against an empty one. If exact validation
trims the tail of a flushed batch, those trailing candidates are re-queued at
the front of the planner and packed into the next request. A directory that
spans several requests repeats its complete context block in each. A single
candidate that cannot fit an empty request becomes a visible `input-error` file;
it is never silently dropped, and planning alone still accounts for every
pending file.

### Input-limit adaptation

If the gateway still reports an input-limit error (`413`,
`max_tokens_exceeded`, or "too long"), the oversized batch is marked terminal for
auditability and split deterministically into two child batches by approximate
token weight. Each child is retried with complete directory context. Only a
proven single-candidate case is recorded as a file input error. The same
oversized payload is never resent unchanged.

## Packing scope

`packing_scope` selects the planner policy:

| Value | Behavior |
| :--- | :--- |
| `directory` | One source directory per request. Conservative default. |
| `multi-directory` | Pack independent directory blocks into shared requests. |

`directory` remains available for comparison and rollback. Switch to
`multi-directory` after validating model quality on a pinned corpus; see the
rollout notes below.

## Concurrency

`workers` bounds the number of simultaneous decision requests. One coordinator
thread owns every database read, status transition, result write, retry
decision, and progress snapshot; HTTP workers only serialize the request, call
the endpoint, and parse the response. Each worker owns its own
`requests.Session`; sessions are never shared.

Design points:

* **Admission.** The coordinator submits at most `workers` requests and never
  builds an unbounded queue.
* **Canary.** If the run has no completed request and the same
  endpoint/model/objective and input-shaping versions have not already answered
  a request, one planned batch is dispatched alone first. An authentication
  failure then stops the run immediately instead of fanning out. Repeat
  assessments skip the serial round-trip; a deployment change forces a fresh
  canary.
* **Rate limiting.** `rate_limit_per_minute` is enforced in the coordinator
  with a monotonic sliding window. `0` is unlimited. A blocked admission never
  occupies a sleeping worker slot.
* **Deadline and cancellation.** Admission stops when the time budget expires or
  cancellation is requested; requests already in flight are allowed to finish
  so their valid answers survive.
* **Retries.** Retryable transport/5xx failures use bounded exponential
  backoff with jitter. Unresolved files return to the global planner rather than
  recreating one batch per old directory, and two batches can never claim the
  same pending file. Authentication and deterministic input errors are not
  retried unchanged.
* **Throttling.** A `429`/`503`, or any response carrying `Retry-After`, pauses
  admission across every worker for the server's requested cooldown (clamped to
  60 s). The batch then returns to the planner like any other retryable failure,
  so concurrent workers do not amplify a rate limit.
* **Useful results first.** Pending candidates are packed in
  `(rule priority, directory, file)` order, so the files the deterministic rules
  already flagged are assessed and surfaced earliest. The main view can select an
  in-progress run and shows assessed files as batches land, rather than waiting
  for the whole inventory.

## Progress and status

Status is served from durable, transactionally maintained file-status counters
(`assessment_status_counts`) and cheap batch aggregates. It never scans the whole
ledger and never loads request payloads, so its cost does not grow with
`files × completed batches`. Progress callbacks are throttled (about four per
second) and the final status is always emitted. `triage jev status` reports file
coverage, batch states, active workers, packing scope, phase timings, request
latency percentiles, and inferred-versus-cache-reused counts.

## Token counting

Packing uses a conservative local estimator so it never issues a network request
per candidate. Fixed question and rubric costs are estimated once. The optional
`tokenize_endpoint` is used only to measure complete tentative payload sections,
once per batch, cached by exact text. A tokenizer outage falls back to the
estimator without blocking assessment, and the fallback is recorded in run
metrics. Input-limit responses still trigger the deterministic split path.

## Exact-request cache reuse

Repeat runs reuse a previously validated response only when the exact effective
request matches: canonical payload, every directory context hash, deployment
revision, adapter/rubric/planner/context/preprocessing versions, objective, and
relevant model settings. Reused answers are materialized into the new run's
ledger with `source='cache'`, counted separately from inferred answers, and are
subject to the same full-coverage reconciliation. Answers are never reused
per-file from a differently packed shared state. Cache reuse happens inside the
admission loop and skips to the next planned batch; it can never end a run while
later batches remain, and finalization counts anything still planned or
in-flight as unresolved.

## Resume and compatibility

Planned and in-flight batches are durable. A crash leaves expired `in-flight`
batches that the next owner requeues exactly once. Stored payloads remain the
source of truth for resume; existing batches are never rewritten in place.

Schema version 2 migrates version-1 assessment databases in a single
transaction. Historical runs, batches, members, payloads, and results are
preserved; each migrated batch is mapped to its directory context and counters
are reconciled from the ledger. `user_version` is left unchanged if migration
fails.

## Configuration

Add these to the `[jev]` table:

```toml
[jev]
enabled = true
workers = 8                      # the primary lever after request count is minimal
rate_limit_per_minute = 0        # 0 disables the limiter
max_questions_per_request = 200
max_request_bytes = 0            # 0 disables the exact byte cap
packing_scope = "directory"      # default; "multi-directory" to pack more per request
token_headroom_percent = 10
```

## Rollout

1. Ship the schema migration and status/storage changes first.
2. Keep `workers = 8` (the default) and confirm it against the live route with
   `--sweep-workers`; back off if the gateway serializes or throttles.
3. Keep `packing_scope = "directory"` for established deployments.
4. Enable `multi-directory` in test environments and collect quality and
   throughput evidence.
5. Switch the default only after the cross-directory quality gate:
   at least 98% exact-label agreement on deterministic runs, no systematic
   priority reduction tied to directory position or batch size, and no increase
   in missing, unknown, or malformed answer IDs.
6. Roll back to `directory` by configuration alone.

Increasing `workers` beyond the gateway's capacity can reduce throughput by
queueing requests behind GPU contention. Measure 1, 2, 4, and 8 workers against
a live deployment, and stop when p95 latency, failures, or total throughput
worsens.

## Benchmark

`scripts/benchmark_jev.py` measures staging, planning, and dispatch against an
in-process fake gateway. It needs no credentials and incurs no inference cost:

```bash
python scripts/benchmark_jev.py --fixture captured --packing-scope directory
python scripts/benchmark_jev.py --fixture captured --packing-scope multi-directory
python scripts/benchmark_jev.py --fixture wide --files 100000 --sql-count
# Do not assume the largest batch is fastest: sweep concurrency, batch size,
# and packing scope together. Each combination uses a fresh ledger so the
# exact-request cache cannot mask a real dispatch.
python scripts/benchmark_jev.py --fixture captured \
  --sweep-workers 1,2,4,8,16 --sweep-questions 25,50,100,200 \
  --sweep-scopes directory,multi-directory
```

Fixtures: `captured` (774 files / 203 directories), `wide`, `many-tiny`,
`mixed`, and `retry`. The report includes request counts, files/directories per
request, estimated tokens, dispatch wall time, achieved concurrency, latency
percentiles, persistence time, peak RSS, and final reconciliation.
