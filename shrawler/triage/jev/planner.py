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

import json
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from .config import (
    CONTEXT_VERSION,
    PAYLOAD_VERSION,
    PLANNER_VERSION,
    PREPROCESSING_VERSION,
    RUBRIC,
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
        # One token per UTF-8 byte plus a fixed per-fragment overhead. This is
        # deliberately conservative so a real 413 is handled by the split path,
        # not by silently dropping candidates.
        return len(text.encode("utf-8")) + self.config.state_overhead_tokens

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
    file_id: str, config: JevConfig, directory_label: str = ""
) -> Dict[str, Any]:
    where = f" in directory block {directory_label}" if directory_label else ""
    return {
        "type": "choice",
        "instructions": (
            f"Assess candidate {file_id}{where} using that directory block and "
            "the candidate's own metadata. Return the inspection-priority level "
            "that the declared objective and rubric support."
        ),
        "criteria": dict(RUBRIC),
    }


def candidate_record(member: Dict[str, Any]) -> str:
    return (
        f"  {member['file_id']} | {member['file_name']} | "
        f"{member['size_bytes']} bytes | {member['mtime_utc'] or 'unknown'}"
    )


def directory_header(context: Dict[str, Any]) -> str:
    lines = [
        f"Directory {context.get('label', 'D000001')}:",
        f"  Path: \\\\{context['host']}\\{context['share']}{context['directory']}",
        f"  Observed files: {context['observed_files']}",
        "  Extensions: "
        + (
            ", ".join(
                f"{item['extension']}={item['count']}"
                for item in context.get("extensions", [])
            )
            or "(none)"
        ),
        "  Ancestors: " + ("/".join(context.get("ancestors", [])) or "(none)"),
        "  Sibling markers: "
        + (", ".join(context.get("sibling_markers", [])) or "(none)"),
        f"  Completeness: {context['enumeration']}",
        "  Candidates:",
    ]
    return "\n".join(lines)


def state_text(context: Dict[str, Any], candidates: List[Dict[str, Any]]) -> str:
    """Back-compat single-directory renderer used by preview tooling."""
    stored = {**context, "objective": context.get("objective", "")}
    sections = [
        f"Objective: {stored.get('objective', '')}",
        "",
        directory_header({**stored, "label": context.get("label", "D000001")}),
    ]
    sections.extend(candidate_record(candidate) for candidate in candidates)
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
    sections = [f"Objective: {objective}"]
    for directory_id, context, _hash in directories:
        sections.append("")
        sections.append(directory_header({**context, "label": labels[directory_id]}))
        for member in members_by_directory[directory_id]:
            sections.append(candidate_record(member))
    state = "\n".join(sections)
    questions = {
        str(entry["file_id"]): question_for(
            str(entry["file_id"]), config, labels[int(entry["directory_id"])]
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
        headroom = (100 - config.token_headroom_percent) / 100.0
        self.max_input = max(1, int(config.max_input_tokens * headroom))
        self.max_longest = max(1, int(config.max_state_longest_question_tokens * headroom))
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
        placeholder = canonical(question_for("F000000000000", self.config, "D000000"))
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
        record_cost = self.counter.estimate(candidate_record(entry) + "\n")
        dir_cost = self._dir_cost(directory_id) if new_directory else 0
        question_cost = self._question_cost()
        projected_state = self.state_tokens + dir_cost + record_cost
        projected_questions = self.question_tokens + question_cost
        if not self.empty:
            if projected_state + projected_questions > self.max_input:
                return False
            if projected_state + max(self.longest_question, question_cost) > self.max_longest:
                return False
            if len(self.entries) >= self.config.max_questions_per_request:
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
    """Stream pending candidates in stable order without loading a directory."""
    last_directory = -1
    last_file = ""
    while True:
        if cancelled and cancelled():
            raise KeyboardInterrupt
        rows = store.connection.execute(
            "SELECT file_id,file_name,size_bytes,mtime_utc,directory_id "
            "FROM assessment_files WHERE run_id=? AND status='pending' "
            "AND (directory_id>? OR (directory_id=? AND file_id>?)) "
            "ORDER BY directory_id,file_id LIMIT ?",
            (run_id, last_directory, last_directory, last_file, STREAM_CHUNK),
        ).fetchall()
        if not rows:
            return
        for row in rows:
            yield {
                "file_id": str(row["file_id"]),
                "file_name": str(row["file_name"]),
                "size_bytes": int(row["size_bytes"]),
                "mtime_utc": row["mtime_utc"],
                "directory_id": int(row["directory_id"]),
            }
        last_directory = int(rows[-1]["directory_id"])
        last_file = str(rows[-1]["file_id"])


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


def _trim_to_byte_limit(
    batch: Batch,
    objective: str,
    context_loader: Callable[[int], Tuple[Dict[str, Any], str]],
    config: JevConfig,
    counter: TokenCounter,
) -> Batch:
    """Drop trailing candidates until the exact canonical payload fits."""
    if not config.max_request_bytes:
        return batch
    entries = list(batch.entries)
    while len(entries) > 1 and batch.byte_length > config.max_request_bytes:
        entries.pop()
        batch = render_batch(objective, entries, context_loader, config, counter)
    return batch


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
    for entry in candidates:
        while True:
            try:
                added = packer.add(entry)
            except CandidateTooLargeError as exc:
                if not packer.empty:
                    # Flush and retry the entry against an empty request.
                    yield _trim_to_byte_limit(
                        render_batch(objective, packer.entries, context_loader, config, counter),
                        objective,
                        context_loader,
                        config,
                        counter,
                    )
                    packer.reset()
                    continue
                # A single candidate cannot fit even an empty request: it is a
                # visible input error, never a silent omission.
                oversized(str(entry["file_id"]), str(exc))
                break
            if added:
                break
            # Batch full: flush and retry the same entry in a fresh batch.
            yield _trim_to_byte_limit(
                render_batch(objective, packer.entries, context_loader, config, counter),
                objective,
                context_loader,
                config,
                counter,
            )
            packer.reset()
        if len(packer.entries) >= config.max_questions_per_request:
            yield _trim_to_byte_limit(
                render_batch(objective, packer.entries, context_loader, config, counter),
                objective,
                context_loader,
                config,
                counter,
            )
            packer.reset()
    if not packer.empty:
        yield _trim_to_byte_limit(
            render_batch(objective, packer.entries, context_loader, config, counter),
            objective,
            context_loader,
            config,
            counter,
        )


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
        "SELECT file_id,file_name,size_bytes,mtime_utc,directory_id "
        "FROM assessment_files WHERE run_id=? AND directory_id=? AND status='pending' "
        "ORDER BY file_id",
        (run_id, directory_id),
    ).fetchall()
    candidates = [
        {
            "file_id": str(row["file_id"]),
            "file_name": str(row["file_name"]),
            "size_bytes": int(row["size_bytes"]),
            "mtime_utc": row["mtime_utc"],
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


def _member_weight(member: Dict[str, Any], config: JevConfig, counter: TokenCounter) -> int:
    return (
        len(candidate_record(member).encode("utf-8"))
        + len(canonical(question_for(str(member["file_id"]), config, "D000000")).encode("utf-8"))
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
        "SELECT f.file_id,f.file_name,f.size_bytes,f.mtime_utc,f.directory_id "
        "FROM batch_members m JOIN assessment_files f ON f.run_id=m.run_id "
        "AND f.file_id=m.file_id WHERE m.batch_id=? ORDER BY m.ordinal",
        (batch_id,),
    ).fetchall()
    members = [
        {
            "file_id": str(row["file_id"]),
            "file_name": str(row["file_name"]),
            "size_bytes": int(row["size_bytes"]),
            "mtime_utc": row["mtime_utc"],
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
