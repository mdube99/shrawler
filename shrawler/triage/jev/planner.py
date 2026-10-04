"""Deterministic, token-bounded request planning.

Two upstream budgets are enforced explicitly for every packed request:

* ``state_tokens + sum(question_tokens) <= max_input_tokens``
* ``state_tokens + max(question_tokens) <= max_state_longest_question_tokens``

Planning is global and streaming: candidates are read from SQLite in stable
``(directory order, file_id)`` order, packed into token/byte/question-bounded
batches, and persisted before dispatch so resume never has to reselect work.
A batch may carry one directory (``packing_scope=directory``) or several
independent, explicitly labeled directory blocks (``multi-directory``).

Remote tokenizers are never called per candidate. Packing uses a conservative
local estimator; a configured tokenizer validates complete state/question
sections once per batch and its result is cached by exact text.
"""

import base64
import hashlib
import json
import uuid
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)

from .config import (
    CONTEXT_VERSION,
    PAYLOAD_VERSION,
    PLANNER_VERSION,
    PREPROCESSING_VERSION,
    RUBRIC_CRITERIA,
    JevConfig,
    canonical,
    fingerprint,
)
from .storage import JevStore

BATCH_CHUNK = 500
# Streaming read size for pending candidates; never materializes a directory.
STREAM_CHUNK = 1000
# Bounded per-run directory-context cache while packing.
CONTEXT_CACHE_SIZE = 256
# Group planning writes into one transaction and commit every N batches. A
# single fsync per batch dominated planning at scale; a lost uncommitted tail
# is safe because those files remain pending and are replanned.
COMMIT_EVERY_BATCHES = 64
# Conservative fallback when no tokenizer is configured. Natural-language and
# JSON fragments average roughly three to four UTF-8 bytes per token, so one
# token per three bytes keeps a safety margin without the ~4x overcount of a
# pure one-token-per-byte estimator. A configured ``tokenize_endpoint`` still
# measures complete payload sections exactly.
FALLBACK_BYTES_PER_TOKEN = 3
# Characters of the binding key that names a candidate in one request. The key
# is derived from the file ID rather than generated, so replanning the same
# candidates reproduces the same request and the exact-request cache still hits.
# Eight base64url characters carry 48 bits, far more than a request's candidate
# count can ever exercise; measured cost is about 14 tokens per candidate line
# where the 22-character file ID costs about 29.
BINDING_KEY_LENGTH = 8
# Widening attempts before a colliding candidate falls back to its full file ID.
# The fallback cannot itself collide because file IDs are unique within a run.
BINDING_KEY_ATTEMPTS = 8


def binding_key(file_id: str) -> str:
    """Short, deterministic, request-local key derived from a file ID.

    The key ties a candidate line in the shared state to its question and its
    answer. It is a pure function of the file ID, so a batch that is replanned
    after a crash or a split produces byte-identical requests and the
    exact-request cache keeps working.

    Random high-entropy characters matter here: an earlier *sequential* alias
    (``c1..cN``) collapsed answer attribution once a request carried more than a
    few candidates, while a derived key reproduced the full-ID behaviour in every
    live run up to 534 candidates per request.
    """
    digest = hashlib.sha256(file_id.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii")[:BINDING_KEY_LENGTH]


def resolve_binding_keys(
    entries: Sequence[Mapping[str, Any]],
    key_for: Callable[[str], str] = binding_key,
) -> Dict[str, str]:
    """Map each entry's file ID to a key that is unique within one request.

    Two file IDs can theoretically share a short prefix. Widening is
    deterministic, and a candidate that still collides falls back to its full
    file ID, so a request can never contain two identical binding keys.
    """
    keys: Dict[str, str] = {}
    used: Dict[str, str] = {}
    for entry in entries:
        file_id = str(entry["file_id"])
        if file_id in keys:
            continue
        key = key_for(file_id)
        attempt = 0
        while key in used:
            attempt += 1
            if attempt > BINDING_KEY_ATTEMPTS:
                key = file_id
                break
            key = key_for(f"{file_id}#{attempt}")
        keys[file_id] = key
        used[key] = file_id
    return keys


def _fallback_tokens(text: str) -> int:
    """Token estimate for text when no tokenizer is available."""
    return max(1, -(-len(text.encode("utf-8")) // FALLBACK_BYTES_PER_TOKEN))


def token_budgets(config: JevConfig) -> Tuple[int, int]:
    """Effective (input, longest-question) token budgets after headroom."""
    headroom = (100 - config.token_headroom_percent) / 100.0
    max_input = max(1, int(config.max_input_tokens * headroom))
    max_longest = max(1, int(config.max_state_longest_question_tokens * headroom))
    return max_input, max_longest


class CandidateTooLargeError(ValueError):
    """A single candidate cannot fit even an empty context budget."""


class TokenCounter:
    """Conservative local estimator plus optional per-batch remote validation.

    ``estimate`` is additive and never performs network I/O, so incremental
    packing never issues a request per fragment. ``measure`` prefers the
    gateway tokenizer when configured and caches by exact text.
    """

    def __init__(self, client: Any, config: JevConfig) -> None:
        self.client = client
        self.config = config
        self.cache: Dict[str, int] = {}

    def estimate(self, text: str) -> int:
        # When no tokenizer endpoint is configured the client's ``count_tokens``
        # is a cheap local probe (production returns None without I/O; tests may
        # inject a deterministic counter). When a remote tokenizer *is*
        # configured we deliberately use the byte estimator here and only call
        # the endpoint once per completed batch via ``measure``.
        if not self.config.tokenize_endpoint:
            value = self.client.count_tokens(text)
            if value is not None:
                return int(value) + self.config.state_overhead_tokens
        # A calibrated per-byte estimate plus a fixed per-fragment overhead. It
        # stays conservative enough that a real 413 is handled by the split
        # path, never by silently dropping candidates.
        return _fallback_tokens(text) + self.config.state_overhead_tokens

    def measure(self, text: str) -> int:
        if not self.config.tokenize_endpoint:
            return self.estimate(text)
        cached = self.cache.get(text)
        if cached is not None:
            return cached
        value = self.client.count_tokens(text)
        resolved = int(value) if value is not None else self.estimate(text)
        self.cache[text] = resolved
        return resolved

    # Back-compat name used by older callers; prefers the remote measurement.
    def count(self, text: str) -> int:
        return self.measure(text)


def question_for(
    key: str, config: JevConfig, directory_label: str = ""
) -> Dict[str, Any]:
    """One choice question keyed elsewhere by the candidate's binding key.

    The instruction names the candidate and nothing else. Measured against the
    live endpoint it is the dominant per-question cost (119 input tokens per
    question with the previous verbose instruction, 82 with compact criteria, 36
    with no instruction at all), so it is kept as short as attribution allows.
    It cannot be dropped: with no instruction the model stopped discriminating and
    promoted every benign control in the labeled fixture.

    The instruction never names the filename: a filename is data and must not be
    interpolated into the instruction channel. The five level keys are sent
    without descriptions because the objective already states the full rubric
    once per request and the endpoint reads a bare criterion from its name alone.
    """
    where = f" in {directory_label}" if directory_label else ""
    return {
        "type": "choice",
        "instructions": f"Rate {key}{where}.",
        "criteria": dict(RUBRIC_CRITERIA),
    }


def candidate_record(member: Dict[str, Any], key: str) -> str:
    """Candidate line: binding key plus the filename.

    The key is the model's binding key, not the ledger file ID; the runner maps
    it back to the file ID when it persists the answer. Size, mtime, and the
    extension histogram are deliberately not sent; none of them help classify the
    file.
    """
    return f"  {key} | {member['file_name']}"


def directory_header(context: Dict[str, Any]) -> str:
    """Directory block carrying only the signals the rubric actually uses.

    The path supplies the directory names and the sibling markers supply the
    credential-adjacent-sibling signal. Observed file counts, extension
    histograms, the ancestor list (already inside the path), and the
    completeness phrase were low-value overhead and are no longer sent. The label
    and the path share one line because a block is repeated for every directory
    in the request and an inventory of tiny directories pays that per file.
    """
    label = context.get("label", "D000001")
    return "\n".join(
        [
            f"{label} \\\\{context['host']}\\{context['share']}{context['directory']}:",
            "  Siblings: "
            + (", ".join(context.get("sibling_markers", [])) or "(none)"),
            "  Candidates:",
        ]
    )


def state_text(context: Dict[str, Any], candidates: List[Dict[str, Any]]) -> str:
    """Back-compat single-directory renderer used by preview tooling."""
    stored = {**context, "objective": context.get("objective", "")}
    keys = resolve_binding_keys(candidates)
    sections = [
        f"Objective: {stored.get('objective', '')}",
        "",
        directory_header({**stored, "label": context.get("label", "D000001")}),
    ]
    sections.extend(
        candidate_record(candidate, keys[str(candidate["file_id"])])
        for candidate in candidates
    )
    return "\n".join(sections)


@dataclass
class Batch:
    entries: List[Dict[str, Any]] = field(default_factory=list)
    # Ordered (directory_id, context, context_hash) for every directory block.
    directories: List[Tuple[int, Dict[str, Any], str]] = field(default_factory=list)
    state: str = ""
    questions: Dict[str, Any] = field(default_factory=dict)
    payload: Dict[str, Any] = field(default_factory=dict)
    input_tokens: int = 0
    byte_length: int = 0
    cache_key: str = ""

    @property
    def members(self) -> List[str]:
        return [str(entry["file_id"]) for entry in self.entries]

    @property
    def primary_directory_id(self) -> Optional[int]:
        return self.directories[0][0] if self.directories else None


def render_batch(
    objective: str,
    entries: List[Dict[str, Any]],
    context_loader: Callable[[int], Tuple[Dict[str, Any], str]],
    config: JevConfig,
    counter: TokenCounter,
) -> Batch:
    """Build a complete request payload from an ordered candidate list."""
    directory_order: List[int] = []
    members_by_directory: Dict[int, List[Dict[str, Any]]] = {}
    for entry in entries:
        directory_id = int(entry["directory_id"])
        if directory_id not in members_by_directory:
            members_by_directory[directory_id] = []
            directory_order.append(directory_id)
        members_by_directory[directory_id].append(entry)
    directories: List[Tuple[int, Dict[str, Any], str]] = []
    for directory_id in directory_order:
        context, context_hash = context_loader(directory_id)
        directories.append((directory_id, context, context_hash))
    labels = {
        directory_id: f"D{index + 1:06d}"
        for index, directory_id in enumerate(directory_order)
    }
    # One short key per candidate binds the candidate line, its question, and its
    # answer. Keys are derived from the file ID so replanning reproduces this
    # request exactly; they are resolved per batch so a short-prefix collision can
    # never put two candidates under one key.
    keys = resolve_binding_keys(entries)
    sections = [f"Objective: {objective}"]
    for directory_id, context, _hash in directories:
        sections.append("")
        sections.append(directory_header({**context, "label": labels[directory_id]}))
        for member in members_by_directory[directory_id]:
            sections.append(
                candidate_record(member, keys[str(member["file_id"])])
            )
    state = "\n".join(sections)
    questions = {
        keys[str(entry["file_id"])]: question_for(
            keys[str(entry["file_id"])],
            config,
            labels[int(entry["directory_id"])],
        )
        for entry in entries
    }
    payload = {"model": config.model, "state": state, "questions": questions}
    return Batch(
        entries=list(entries),
        directories=directories,
        state=state,
        questions=questions,
        payload=payload,
        input_tokens=counter.measure(state) + counter.measure(canonical(questions)),
        byte_length=len(canonical(payload).encode("utf-8")),
    )


class _Packer:
    """Incrementally enforce token, longest-question, question, and byte caps."""

    def __init__(
        self,
        config: JevConfig,
        counter: TokenCounter,
        context_loader: Callable[[int], Tuple[Dict[str, Any], str]],
        max_directories: int,
    ) -> None:
        self.config = config
        self.counter = counter
        self.context_loader = context_loader
        self.max_directories = max_directories
        # Apply the estimator safety headroom once, up front.
        self.max_input, self.max_longest = token_budgets(config)
        # Entry cap. It starts at the configured question cap and can shrink when
        # exact byte validation drops trailing entries, so future batches stop
        # at the size that actually fit instead of re-accumulating overflow.
        self.max_entries = config.max_questions_per_request
        self.reset()

    def reset(self) -> None:
        self.entries: List[Dict[str, Any]] = []
        self.directory_ids: List[int] = []
        self.state_tokens = 0
        self.question_tokens = 0
        self.longest_question = 0

    @property
    def empty(self) -> bool:
        return not self.entries

    def _dir_cost(self, directory_id: int) -> int:
        context, _hash = self.context_loader(directory_id)
        return self.counter.estimate(directory_header({**context, "label": "D000000"}) + "\n")

    def _question_cost(self) -> int:
        placeholder = canonical(
            question_for(binding_key("F000000000000"), self.config, "D000000")
        )
        return self.counter.estimate(placeholder) + self.config.instruction_overhead_tokens

    def add(self, entry: Dict[str, Any]) -> bool:
        """Add a candidate if it fits. Returns False when the batch is full.

        Raises ``CandidateTooLargeError`` when a single candidate cannot fit an
        otherwise empty request; that is a visible input error, never a silent
        omission.
        """
        directory_id = int(entry["directory_id"])
        new_directory = directory_id not in self.directory_ids
        if new_directory and len(self.directory_ids) >= self.max_directories:
            return False
        record_cost = self.counter.estimate(
            candidate_record(entry, binding_key(str(entry["file_id"]))) + "\n"
        )
        dir_cost = self._dir_cost(directory_id) if new_directory else 0
        question_cost = self._question_cost()
        projected_state = self.state_tokens + dir_cost + record_cost
        projected_questions = self.question_tokens + question_cost
        if not self.empty:
            if projected_state + projected_questions > self.max_input:
                return False
            if projected_state + max(self.longest_question, question_cost) > self.max_longest:
                return False
            if len(self.entries) >= self.max_entries:
                return False
        if (
            projected_state + projected_questions > self.max_input
            or projected_state + max(self.longest_question, question_cost) > self.max_longest
        ):
            raise CandidateTooLargeError(
                f"candidate {entry['file_id']} exceeds the request budget; "
                "reduce context or raise the limit"
            )
        if new_directory:
            self.directory_ids.append(directory_id)
            self.state_tokens += dir_cost
        self.state_tokens += record_cost
        self.question_tokens += question_cost
        self.longest_question = max(self.longest_question, question_cost)
        self.entries.append(entry)
        return True


def _pending_candidates(
    store: JevStore,
    run_id: str,
    cancelled: Optional[Callable[[], bool]] = None,
) -> Iterator[Dict[str, Any]]:
    """Stream pending candidates highest presentation priority first.

    The assessment is full-coverage, but dispatching the rule-most-interesting
    files first means useful results land in the analyst's view during a long
    run rather than only at the end. Ordering keyset is
    ``(priority DESC, directory_id, file_id)`` so it stays stable, streams
    without materializing the directory, and needs no sort buffer.
    """
    last: Optional[Tuple[int, int, str]] = None
    while True:
        if cancelled and cancelled():
            raise KeyboardInterrupt
        clause = ""
        values: List[Any] = [run_id]
        if last is not None:
            clause = (
                " AND (priority<? OR (priority=? AND (directory_id>? OR "
                "(directory_id=? AND file_id>?))))"
            )
            values.extend([last[0], last[0], last[1], last[1], last[2]])
        values.append(STREAM_CHUNK)
        rows = store.connection.execute(
            "SELECT file_id,file_name,size_bytes,directory_id,priority "
            "FROM assessment_files WHERE run_id=? AND status='pending'" + clause +
            " ORDER BY priority DESC,directory_id,file_id LIMIT ?",
            values,
        ).fetchall()
        if not rows:
            return
        for row in rows:
            yield {
                "file_id": str(row["file_id"]),
                "file_name": str(row["file_name"]),
                "size_bytes": int(row["size_bytes"]),
                "directory_id": int(row["directory_id"]),
            }
        last_row = rows[-1]
        last = (
            int(last_row["priority"]),
            int(last_row["directory_id"]),
            str(last_row["file_id"]),
        )


def _context_loader(store: JevStore, run_id: str) -> Callable[[int], Tuple[Dict[str, Any], str]]:
    cache: OrderedDict[int, Tuple[Dict[str, Any], str]] = OrderedDict()

    def load(directory_id: int) -> Tuple[Dict[str, Any], str]:
        found = cache.get(directory_id)
        if found is not None:
            cache.move_to_end(directory_id)
            return found
        row = store.context_for(run_id, directory_id)
        if row is None:
            raise CandidateTooLargeError(
                f"directory {directory_id} has no stored context"
            )
        context = json.loads(row["context_json"])
        context["directory_id"] = int(row["directory_id"])
        value = (context, str(row["context_hash"]))
        cache[directory_id] = value
        if len(cache) > CONTEXT_CACHE_SIZE:
            cache.popitem(last=False)
        return value

    return load


def _cache_key(batch: Batch, config: JevConfig, objective: str) -> str:
    return fingerprint(
        {
            "request": canonical(batch.payload),
            "directories": [
                {"directory_id": directory_id, "context_hash": context_hash}
                for directory_id, _context, context_hash in batch.directories
            ],
            "deployment_revision": config.deployment_revision or config.model,
            "adapter_version": config.provenance()["adapter_version"],
            "planner_version": PLANNER_VERSION,
            "payload_version": PAYLOAD_VERSION,
            "context_version": CONTEXT_VERSION,
            "preprocessing_version": PREPROCESSING_VERSION,
            "rubric_version": config.provenance()["rubric_version"],
            "objective": objective,
        }
    )


def _trim_to_limits(
    batch: Batch,
    objective: str,
    context_loader: Callable[[int], Tuple[Dict[str, Any], str]],
    config: JevConfig,
    counter: TokenCounter,
) -> Batch:
    """Drop trailing candidates until the exact payload fits every budget.

    Validates the complete rendered payload (measured tokens and canonical
    bytes) rather than only the estimator the packer used, so a configured
    tokenizer or exact byte cap is honoured before persistence.
    """
    max_input, _max_longest = token_budgets(config)
    byte_limit = config.max_request_bytes

    def over_limit(candidate: Batch) -> bool:
        if byte_limit and candidate.byte_length > byte_limit:
            return True
        return candidate.input_tokens > max_input

    if not over_limit(batch):
        return batch
    entries = list(batch.entries)
    while len(entries) > 1 and over_limit(batch):
        entries.pop()
        batch = render_batch(objective, entries, context_loader, config, counter)
    return batch


def _flush_batch(
    packer: "_Packer",
    objective: str,
    context_loader: Callable[[int], Tuple[Dict[str, Any], str]],
    config: JevConfig,
    counter: TokenCounter,
) -> Tuple[Batch, List[Dict[str, Any]]]:
    """Render and trim the packer's entries; return the batch and overflow.

    Overflow entries are the trailing candidates that did not fit the exact
    limits. Callers re-queue them so they are packed into the next request
    instead of being silently dropped.
    """
    entries = list(packer.entries)
    batch = _trim_to_limits(
        render_batch(objective, entries, context_loader, config, counter),
        objective,
        context_loader,
        config,
        counter,
    )
    dropped = entries[len(batch.entries):]
    if dropped:
        # Keep future batches at the size that actually fit the exact limit so a
        # trim does not force repeated re-accumulation of the same overflow.
        packer.max_entries = min(packer.max_entries, max(1, len(batch.entries)))
    packer.reset()
    return batch, dropped


def _persist_batch(
    store: JevStore,
    run_id: str,
    batch: Batch,
    config: JevConfig,
    objective: str,
    ordinal: int,
    commit: bool = True,
) -> str:
    batch_id = uuid.uuid4().hex
    batch.cache_key = _cache_key(batch, config, objective)
    store.insert_batch(
        batch_id,
        run_id,
        batch.primary_directory_id,
        request_id=batch_id,
        ordinal=ordinal,
        payload=batch.payload,
        input_tokens=batch.input_tokens,
        state=batch.state,
        questions=batch.questions,
        members=batch.members,
        directories=[
            (directory_id, context_hash)
            for directory_id, _context, context_hash in batch.directories
        ],
        cache_key=batch.cache_key,
        commit=commit,
    )
    return batch_id


def _iter_batches(
    candidates: Iterator[Dict[str, Any]],
    config: JevConfig,
    counter: TokenCounter,
    context_loader: Callable[[int], Tuple[Dict[str, Any], str]],
    objective: str,
    max_directories: int,
    oversized: Callable[[str, str], None],
) -> Iterator[Batch]:
    packer = _Packer(config, counter, context_loader, max_directories)
    # Candidates that did not fit a flushed batch are re-queued at the front so
    # no file is dropped when a byte or measured-token limit trims the tail.
    queue: "deque[Dict[str, Any]]" = deque()
    source = iter(candidates)
    exhausted = False

    def pull() -> Optional[Dict[str, Any]]:
        nonlocal exhausted
        if queue:
            return queue.popleft()
        if exhausted:
            return None
        try:
            return next(source)
        except StopIteration:
            exhausted = True
            return None

    def requeue(dropped: List[Dict[str, Any]], following: List[Dict[str, Any]]) -> None:
        # Preserve order: overflow entries first, then whatever triggered the
        # flush, so the stream's stable ordering survives the reshuffle.
        for item in reversed([*dropped, *following]):
            queue.appendleft(item)

    while True:
        entry = pull()
        if entry is None:
            break
        added = False
        while True:
            try:
                added = packer.add(entry)
            except CandidateTooLargeError as exc:
                if packer.empty:
                    # A single candidate cannot fit an empty request: it is a
                    # visible input error, never a silent omission.
                    oversized(str(entry["file_id"]), str(exc))
                    break
                batch, dropped = _flush_batch(
                    packer, objective, context_loader, config, counter
                )
                yield batch
                requeue(dropped, [entry])
                break
            if added:
                break
            # Batch full: flush and retry the same entry in a fresh batch.
            batch, dropped = _flush_batch(
                packer, objective, context_loader, config, counter
            )
            yield batch
            requeue(dropped, [entry])
            break
        if added and len(packer.entries) >= packer.max_entries:
            batch, dropped = _flush_batch(
                packer, objective, context_loader, config, counter
            )
            yield batch
            requeue(dropped, [])
    if not packer.empty:
        batch, _dropped = _flush_batch(
            packer, objective, context_loader, config, counter
        )
        yield batch


@dataclass
class PlanResult:
    persisted: bool
    batch_specs: List[Batch] = field(default_factory=list)
    batch_ids: List[str] = field(default_factory=list)
    oversized_files: List[str] = field(default_factory=list)

    @property
    def batches(self) -> int:
        return len(self.batch_ids) if self.persisted else len(self.batch_specs)

    def summary(self, limit: int = 3) -> Dict[str, Any]:
        specs = self.batch_specs
        if not specs and self.persisted:
            return {}
        candidates = [len(spec.entries) for spec in specs]
        directories = [len(spec.directories) for spec in specs]
        tokens = [spec.input_tokens for spec in specs]
        bytes_ = [spec.byte_length for spec in specs]
        return {
            "planned_batches": len(specs),
            "pending_candidates": sum(candidates),
            "min_candidates_per_request": min(candidates) if candidates else 0,
            "max_candidates_per_request": max(candidates) if candidates else 0,
            "average_candidates_per_request": (
                round(sum(candidates) / len(candidates), 2) if candidates else 0
            ),
            "min_directories_per_request": min(directories) if directories else 0,
            "max_directories_per_request": max(directories) if directories else 0,
            "average_directories_per_request": (
                round(sum(directories) / len(directories), 2) if directories else 0
            ),
            "estimated_input_tokens": sum(tokens),
            "estimated_request_bytes": sum(bytes_),
            "examples": [
                {"state": spec.state, "questions": spec.questions,
                 "estimated_input_tokens": spec.input_tokens}
                for spec in specs[:limit]
            ],
        }


def plan_run(
    store: JevStore,
    run_id: str,
    config: JevConfig,
    counter: TokenCounter,
    objective: Optional[str] = None,
    cancelled: Optional[Callable[[], bool]] = None,
    persist: bool = True,
    preview_limit: int = 0,
) -> PlanResult:
    """Global streaming planner over every pending file in a run."""
    objective = config.objective if objective is None else objective
    max_directories = 1 if config.packing_scope == "directory" else max(
        1, config.max_questions_per_request
    )
    context_loader = _context_loader(store, run_id)
    result = PlanResult(persisted=persist)
    ordinal = store.max_batch_ordinal(run_id) + 1

    def oversized(file_id: str, detail: str) -> None:
        result.oversized_files.append(file_id)
        if persist:
            store.set_file_status(run_id, [file_id], "input-error", error=detail)
            store.commit()

    candidates = _pending_candidates(store, run_id, cancelled)
    pending_since_commit = 0
    for batch in _iter_batches(
        candidates, config, counter, context_loader, objective, max_directories, oversized
    ):
        if persist:
            batch_id = _persist_batch(
                store, run_id, batch, config, objective, ordinal, commit=False
            )
            result.batch_ids.append(batch_id)
            ordinal += 1
            pending_since_commit += 1
            if pending_since_commit >= COMMIT_EVERY_BATCHES:
                store.commit()
                pending_since_commit = 0
        else:
            result.batch_specs.append(batch)
    if persist:
        store.commit()
        # Record specs for preview-style summaries without loading them back.
        result.batch_specs = []
    return result


def plan_directory(
    store: JevStore,
    run_id: str,
    directory: Any,
    config: JevConfig,
    counter: TokenCounter,
    objective: str,
    context_override: Optional[Dict[str, Any]] = None,
    cancelled: Optional[Callable[[], bool]] = None,
) -> List[str]:
    """Plan one directory in isolation (``packing_scope=directory`` path).

    Retained as a stable entry point for tests and diagnostics; the global
    planner is the production path.
    """
    context = (
        context_override
        if context_override is not None
        else json.loads(directory["context_json"])
    )
    directory_id = int(directory["directory_id"])
    context = {**context, "directory_id": directory_id}
    context_hash = str(directory["context_hash"])
    rows = store.connection.execute(
        "SELECT file_id,file_name,size_bytes,directory_id "
        "FROM assessment_files WHERE run_id=? AND directory_id=? AND status='pending' "
        "ORDER BY file_id",
        (run_id, directory_id),
    ).fetchall()
    candidates = [
        {
            "file_id": str(row["file_id"]),
            "file_name": str(row["file_name"]),
            "size_bytes": int(row["size_bytes"]),
            "directory_id": int(row["directory_id"]),
        }
        for row in rows
    ]

    def loader(_directory_id: int) -> Tuple[Dict[str, Any], str]:
        return context, context_hash

    batch_ids: List[str] = []
    ordinal = store.max_batch_ordinal(run_id) + 1
    for batch in _iter_batches(
        iter(candidates), config, counter, loader, objective, 1, lambda *_a: None
    ):
        batch_ids.append(
            _persist_batch(store, run_id, batch, config, objective, ordinal)
        )
        ordinal += 1
    return batch_ids


def answer_keys(payload: Mapping[str, Any], members: Sequence[str]) -> Dict[str, str]:
    """Map each ledger file ID to the binding key used in a stored request.

    ``render_batch`` emits questions in member order, so inverting the stored
    question map reconstructs the mapping the planner used. A payload whose
    question count does not match its membership cannot be inverted safely and
    yields an empty mapping; callers then fall back to the file ID itself, which
    is exactly what pre-payload-4 requests keyed questions by.
    """
    keys = list(payload.get("questions") or {})
    if len(keys) != len(members):
        return {}
    return {str(file_id): str(key) for file_id, key in zip(members, keys)}


def _member_weight(member: Dict[str, Any], config: JevConfig, counter: TokenCounter) -> int:
    key = binding_key(str(member["file_id"]))
    return (
        len(candidate_record(member, key).encode("utf-8"))
        + len(canonical(question_for(key, config, "D000000")).encode("utf-8"))
    )


def split_input_error_batch(
    store: JevStore,
    run_id: str,
    batch: Any,
    config: JevConfig,
    counter: TokenCounter,
    objective: str,
    error: str,
    cancelled: Optional[Callable[[], bool]] = None,
) -> int:
    """Deterministically split an oversized batch; return child-batch count.

    The original batch is left terminal with its error for auditability. A
    single remaining candidate is recorded as a visible file input error.
    """
    batch_id = str(batch["id"])
    rows = store.connection.execute(
        "SELECT f.file_id,f.file_name,f.size_bytes,f.directory_id "
        "FROM batch_members m JOIN assessment_files f ON f.run_id=m.run_id "
        "AND f.file_id=m.file_id WHERE m.batch_id=? ORDER BY m.ordinal",
        (batch_id,),
    ).fetchall()
    members = [
        {
            "file_id": str(row["file_id"]),
            "file_name": str(row["file_name"]),
            "size_bytes": int(row["size_bytes"]),
            "directory_id": int(row["directory_id"]),
        }
        for row in rows
    ]
    if len(members) <= 1:
        store.mark_input_error(
            run_id, batch_id, [member["file_id"] for member in members], error
        )
        return 0
    # Halve by approximate token weight while staying deterministic.
    ordered = sorted(
        members,
        key=lambda member: (-_member_weight(member, config, counter), member["file_id"]),
    )
    groups: List[List[Dict[str, Any]]] = [[], []]
    weights = [0, 0]
    for member in ordered:
        target = 0 if weights[0] <= weights[1] else 1
        groups[target].append(member)
        weights[target] += _member_weight(member, config, counter)
    store.finish_batch(batch_id, "input-error", error=error)
    context_loader = _context_loader(store, run_id)
    ordinal = store.max_batch_ordinal(run_id) + 1
    created = 0
    for group in groups:
        if not group:
            continue
        group.sort(key=lambda member: (member["directory_id"], member["file_id"]))
        batch_spec = render_batch(objective, group, context_loader, config, counter)
        _persist_batch(store, run_id, batch_spec, config, objective, ordinal)
        ordinal += 1
        created += 1
    return created
