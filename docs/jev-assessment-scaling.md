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

Three further costs dominated the payload itself. Every per-file question
repeated the entire rubric, then every question repeated its own five criterion
descriptions and repeated the 22-character file ID twice, and the token estimator
charged one token per UTF-8 byte so requests filled early. Today the rubric is
stated once in the shared objective, each question carries only the five level
keys, each candidate is named by a short key derived from its file ID, and a
calibrated estimator packs roughly three bytes per token.
`packing_scope = "multi-directory"` collapses the captured 774 files into 2
requests; `directory` remains selectable for comparison.

## Content sent to the model

Only the signals the rubric uses are sent. Each directory block carries its path
(which already contains the ancestor directory names) and its sibling markers;
each candidate line is a short binding key plus the filename. Size, mtime,
observed-file counts, extension histograms, the ancestor list, and the completeness
phrase are not sent.

The binding key is *derived from the file ID* (`planner.binding_key`: 8
base64url characters of the ID's SHA-256, widened on collision) rather than
generated, so replanning the same candidates reproduces the identical request and
the exact-request cache keeps working after a crash. It is short because the
22-character file ID costs about 29 tokens per candidate line while the derived
key costs about 14. A *sequential* alias (`c1..cN`) was tried earlier and
reverted because it broke answer attribution; the derived key does not. The key
is used in the record, the question's map key, and the candidate's instruction,
and `runner` maps each answer back to the exact file ID before persisting it.
The filename is never placed in the instruction channel, so a hostile filename
cannot become an instruction.

## Request shape

One request carries a shared `state` plus a map of `choice` questions keyed by
the candidate's binding key. In multi-directory mode the state contains one
labeled block per source directory:

```text
Objective: ...

D000001 \\host\share\Finance\Payroll:
  Siblings: readme.txt
  Candidates:
    <key> | export.csv
    <key> | readme.txt

D000002 \\host\share\Legal:
  ...
```

Filenames and paths are data, never instructions. Every answer is stored against
the exact file ID and that file's own `context_hash`.## Governing constraints (measured)

The pipeline was evaluated live against the default TypeSafe route
(`jev-latest`, $0.042/M input, output free) on 2026-10-04. Two results govern
every design choice here.

**The model is stochastic.** Repeating the same labeled evaluation gives
different answers. The shipped shape scored 17/17 credential cases with zero
benign false positives in 10 consecutive runs of the 36-case fixture; a shorter
objective variant produced a credential miss in one of five runs and one benign
false negative, and was rejected. A single 17/17 is not proof; the gate needs
repeats.

**The instruction must name the candidate.** Removing the question's
instructions entirely (36 tokens per question instead of 119) made the model stop
discriminating: every one of the 12 benign controls in the fixture was promoted
to level 4 in 5/5 runs, while every credential case still reached 4. The short
instruction (`Rate <key>.`) is what keeps attribution and the benign gate
working; a verbose per-question rubric is what was removed.

**Batch size is not the quality limit.** The labeled fixture passed 5/5 runs at
178 and 534 candidates per request with full coverage and zero benign false
positives, and the endpoint answered 1000 questions in one request. The previous
shape failed at 500 questions with `max_tokens_exceeded`.

## Real cost model

`triage jev status` reports the gateway's actual `usage`, not the local estimate.
The request's cost decomposes into three measured parts, all read from the
endpoint's `usage` field with `jev-latest` ($0.042/M input, output free):

* a fixed part per request, dominated by the objective: the dispatched request is
  billed at `356 + 0.214 × objective_chars` tokens even with one question;
* a marginal part per candidate line in the shared state;
* a marginal part per question.

Measured 2026-10-04 through the real planner on labeled and synthetic bodies:

| Variant | Batch | Tokens/file | Cost per 1M |
| :--- | ---: | ---: | ---: |
| `payload_version = "3"` (directory scope) | 36 / 15 req | 554 | $23.25 |
| `payload_version = "3"` (multi-directory) | 36 / 1 req | 178.7 | $7.50 |
| `payload_version = "3"`, pushed to 200/req | 200 / 3 req | 127.2 | $5.34 |
| `payload_version = "4"` (shipped), 36-case fixture | 36 / 1 req | 111.9 | $4.70 |
| `payload_version = "4"`, 177-case stress fixture | 177 / 1 req | 80.6 | $3.39 |
| `payload_version = "4"`, 20 files/dir | 500 / 1 req | 81.6 | $3.43 |
| `payload_version = "4"`, 5 files/dir | 500 / 1 req | 90.2 | $3.79 |
| `payload_version = "4"`, 1 file/dir | 500 / 2 req | 120.2 | $5.05 |
| `payload_version = "4"`, shallow paths, short names | 500 / 1 req | 68.3 | $2.87 |

Within a batch the split is roughly 57 tokens per question, the directory header
(about 11 tokens per directory at this fixture's path depth) times the number of
directories per file, and a few tokens per candidate line. The fixed part is
amortized: at 500 candidates a request costs about 2 tokens per file, so batch
size matters far more than objective length. Shortening the objective by 2.2 kB
moved the cost by about 2 tokens per file at 200 candidates and cost a credential
case in one of five live runs, so the objective was left at full length.

**Below $3 per million needs an inventory with shallow paths and at least 20
files per directory.** Dense shares with short paths land at $2.87/M; the same
shape with deeper paths costs $3.4/M. Shares of single-file directories pay the
directory header per file and rise to $5/M; that is a property of what is
scanned, not of the request. The remaining per-file cost is the five level keys
of the `choice` question (about 36 tokens of scaffolding and criteria no matter
how the instruction is phrased), which is what a `noul`-style binary question
would remove if a cheaper answer type were ever acceptable.

On a self-hosted route the constraint is compute and request count rather than
dollars: 1M files at 500 per request is 2,000 requests. At the previous shape the
endpoint rejected 500 questions per request with `max_tokens_exceeded`, and 200
per request cost 5,000 requests for 1M files.


## Rubric and content-free level 4

The assessment is full-coverage and metadata-only: the pipeline never sends file
contents, and this will not change for the foreseeable future. The rubric is
therefore written so that a filename plus its directory context can reach every
level, including the top one.

* Level 4 (Immediate) is for a filename that unambiguously denotes
  authentication credentials, secrets, or private keys — for example
  `logins.txt`, `payroll login.txt`, `password.txt`, `credentials`, `id_rsa`,
  `*.pem`, `*.ppk`, `.env`, `service-account.json`, or `secrets.yml`. It does
  not depend on file contents.
* Level 3 (Strong) is for strong sensitive-record evidence (personal, medical,
  financial, or confidential business) or an ambiguous credential-adjacent name.
* Level 2 (Likely) is for a specific but non-credential sensitive indicator,
  such as a sensitive directory or a suggestive filename.
* A sensitive directory such as `Passwords` or `HR`, or a credential-like
  sibling file, raises a candidate's priority but does not by itself make a
  benign filename level 4. Conversely, an unambiguous credential filename is
  level 4 even in an ordinary directory.

`RUBRIC_VERSION = "5"` marks this change. The objective text is part of the run
provenance and the exact-request cache key, so shipping a new objective
invalidates cached answers rather than silently reusing them.

`scripts/jev_rubric_cases_stress.json` expands the base fixture to 177 cases
generated deterministically from it (seed 99) and is used to gate performance at
packed batch sizes. Several of its credential cases use names that were missing
from the objective's level-4 list — `ftp_users.txt`, `keystore.dat`,
`pwd_list.csv` — which is how that list was found to be incomplete and then
extended. Genuinely ambiguous names are excluded from the `credential` class, so
the gate keeps asserting level 4.

`scripts/evaluate_jev_rubric.py` dispatches the labeled
`scripts/jev_rubric_cases.json` fixture through the endpoint configured in
`config.toml` using the real planner and runner. It reports every case's
achieved label and the endpoint's per-file distribution, exits non-zero if any
credential-indicator case is below level 4 or any benign control reaches level
4, and reports PII/PHI/financial cases without asserting their exact label.

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
| `directory` | One source directory per request. Comparison mode. |
| `multi-directory` | Pack independent directory blocks into shared requests. Default. |

`multi-directory` is the default: it minimizes request count and tokens by
sharing the objective and fixed request overhead, and it passed 10/10 live runs
at 17/17 credential cases. `directory` remains selectable.

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
latency percentiles, inferred-versus-cache-reused counts, and the real billed
input tokens from the gateway's usage, with tokens per file, files per request,
and an estimated cost at the published route price.

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
max_questions_per_request = 500
max_request_bytes = 0            # 0 disables the exact byte cap
packing_scope = "multi-directory"  # default; "directory" for one directory per request
token_headroom_percent = 10
```

## Rollout

1. Ship the schema migration and status/storage changes first.
2. Keep `workers = 8` (the default) and confirm it against the live route with
   `--sweep-workers`; back off if the gateway serializes or throttles.
3. `packing_scope = "multi-directory"` is the default and passed 10/10 live runs at
   17/17 with zero benign false positives. Because the model is stochastic,
   re-run the labeled evaluation several times on any corpus and model change
   before trusting a single pass. Derive the binding key from the file ID and
   keep the instruction naming the candidate; both are load-bearing.
4. Record the real billed tokens and cost per file from `triage jev status` on a
   representative slice before scaling to a full million-file run. Dense shares
   land near $3/M; single-file directories cost more because the directory
   header bills per file.
5. Roll back to `directory` by configuration alone if quality regresses.

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
  --sweep-workers 1,2,4,8,16 --sweep-questions 50,200,500 \
  --sweep-scopes directory,multi-directory
```

Fixtures: `captured` (774 files / 203 directories), `wide`, `many-tiny`,
`mixed`, and `retry`. The report includes request counts, files/directories per
request, estimated tokens, dispatch wall time, achieved concurrency, latency
percentiles, persistence time, peak RSS, and final reconciliation.
