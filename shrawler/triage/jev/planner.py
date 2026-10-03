"""Deterministic, token-bounded request planning.

Two upstream budgets are enforced explicitly:

* ``state_tokens + sum(question_tokens) <= max_input_tokens``
* ``state_tokens + max(question_tokens) <= max_state_longest_question_tokens``

Batches are directory-local, stable-ordered by file ID, and persisted before
dispatch so resume never has to reselect work.
"""

import json
import uuid
from typing import Any, Callable, Dict, Iterator, List, Optional

from .config import RUBRIC, JevConfig, canonical, fingerprint
from .storage import JevStore, utc_now

BATCH_CHUNK = 500


class CandidateTooLargeError(ValueError):
    """A single candidate cannot fit even an empty context budget."""


class TokenCounter:
    """Prefer the gateway tokenizer; fall back to a conservative estimator."""

    def __init__(self, client: Any, config: JevConfig) -> None:
        self.client = client
        self.config = config
        self.cache: Dict[str, int] = {}

    def count(self, text: str) -> int:
        cached = self.cache.get(text)
        if cached is not None:
            return cached
        value = self.client.count_tokens(text)
        if value is None:
            # Conservative: one token per byte, plus a small overhead. Split on
            # real input-limit errors rather than trusting the estimate.
            value = len(text.encode()) + self.config.state_overhead_tokens
        self.cache[text] = value
        return value


def question_for(file_id: str, config: JevConfig) -> Dict[str, Any]:
    return {
        "type": "choice",
        "instructions": (
            f"Assess candidate {file_id} using the shared directory context and "
            "its own metadata. Return the inspection-priority level that the "
            "declared objective and rubric support."
        ),
        "criteria": dict(RUBRIC),
    }


def state_text(context: Dict[str, Any], candidates: List[Dict[str, Any]]) -> str:
    """Human-readable, stable state holding shared context plus file records."""
    lines = [
        f"Objective: {context.get('objective', '')}",
        f"Directory: \\\\{context['host']}\\{context['share']}{context['directory']}",
        f"Observed files in directory: {context['observed_files']}",
        "Extensions: "
        + ", ".join(
            f"{item['extension']}={item['count']}" for item in context["extensions"]
        ),
        "Ancestors: " + "/".join(context.get("ancestors", [])),
        "Sibling markers: " + (", ".join(context.get("sibling_markers", [])) or "(none)"),
        f"Completeness: {context['enumeration']}",
        "Candidates:",
    ]
    for candidate in candidates:
        lines.append(
            f"{candidate['file_id']} | {candidate['file_name']} | "
            f"{candidate['size_bytes']} bytes | {candidate['mtime_utc'] or 'unknown'}"
        )
    return "\n".join(lines)


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
    """Create and persist every batch for one directory. Returns batch IDs."""
    context = (
        context_override
        if context_override is not None
        else json.loads(directory["context_json"])
    )
    context_hash = str(directory["context_hash"])
    directory_id = int(directory["directory_id"])
    state_context = {"objective": objective, **context}
    batch_ids: List[str] = []
    pending = _pending_members(store, run_id, directory_id)
    ordinal = _next_ordinal(store, run_id, directory_id)
    for candidates in _pack(state_context, pending, config, counter, cancelled):
        batch_id = uuid.uuid4().hex
        state = state_text(state_context, candidates)
        questions = {item["file_id"]: question_for(item["file_id"], config) for item in candidates}
        payload = {"model": config.model, "state": state, "questions": questions}
        payload_json = canonical(payload)
        # Requests where candidates share a state are batch-dependent; the full
        # state and membership are part of the cache identity. The hash is
        # computed here so it can never diverge from the persisted payload.
        cache_key = fingerprint(
            {
                "request": payload_json,
                "context_hash": context_hash,
                "deployment_revision": config.deployment_revision or config.model,
                "adapter_version": config.provenance()["adapter_version"],
                "rubric_version": config.provenance()["rubric_version"],
                "objective": config.objective,
            }
        )
        store.insert_batch(
            batch_id,
            run_id,
            directory_id,
            request_id=batch_id,
            ordinal=ordinal,
            payload=payload,
            input_tokens=_batch_tokens(state, questions, counter),
            state=state,
            questions=questions,
            members=[item["file_id"] for item in candidates],
            cache_key=cache_key,
        )
        _claim_members(store, run_id, batch_id, [item["file_id"] for item in candidates])
        batch_ids.append(batch_id)
        ordinal += 1
    return batch_ids


def _pack(
    context: Dict[str, Any],
    members: List[Dict[str, Any]],
    config: JevConfig,
    counter: TokenCounter,
    cancelled: Optional[Callable[[], bool]],
) -> Iterator[List[Dict[str, Any]]]:
    """Greedy pack respecting both token budgets, question cap, and bytes."""
    base_state_tokens = counter.count(state_text(context, []))
    fixed_question = counter.count(json.dumps(question_for("F000000000000", config), sort_keys=True))
    batch: List[Dict[str, Any]] = []
    state_tokens = base_state_tokens
    question_total = 0
    longest_question = 0
    byte_total = 0
    for member in members:
        if cancelled and cancelled():
            raise KeyboardInterrupt
        record = f"{member['file_id']} | {member['file_name']} | {member['size_bytes']} bytes | {member['mtime_utc'] or 'unknown'}"
        record_tokens = counter.count(record) + 1
        question_tokens = fixed_question + config.instruction_overhead_tokens
        projected = state_tokens + record_tokens
        if (
            batch
            and (
                projected + question_total + question_tokens > config.max_input_tokens
                or projected + max(longest_question, question_tokens)
                > config.max_state_longest_question_tokens
                or len(batch) >= config.max_questions_per_request
                or (
                    config.max_request_bytes
                    and byte_total + len(record.encode()) > config.max_request_bytes
                )
            )
        ):
            yield batch
            batch = []
            state_tokens = base_state_tokens
            question_total = 0
            longest_question = 0
            byte_total = 0
            # Recompute against the emptied batch; the previous projection was
            # measured against the batch that was just flushed.
            projected = state_tokens + record_tokens
        # A single candidate must still fit an otherwise empty batch; context
        # reduction is a documented policy, not a silent filename drop.
        if (
            projected + question_tokens > config.max_input_tokens
            or projected + question_tokens > config.max_state_longest_question_tokens
        ):
            raise CandidateTooLargeError(
                f"candidate {member['file_id']} exceeds the request budget; reduce context"
            )
        state_tokens += record_tokens
        question_total += question_tokens
        longest_question = max(longest_question, question_tokens)
        byte_total += len(record.encode())
        batch.append(member)
        if len(batch) >= BATCH_CHUNK:
            yield batch
            batch = []
            state_tokens = base_state_tokens
            question_total = 0
            longest_question = 0
            byte_total = 0
    if batch:
        yield batch


def _pending_members(store: JevStore, run_id: str, directory_id: int) -> List[Dict[str, Any]]:
    rows = store.connection.execute(
        "SELECT file_id, file_name, size_bytes, mtime_utc, remote_path "
        "FROM assessment_files WHERE run_id=? AND directory_id=? AND status='pending' "
        "ORDER BY file_id",
        (run_id, directory_id),
    )
    return [dict(row) for row in rows]


def _next_ordinal(store: JevStore, run_id: str, directory_id: int) -> int:
    row = store.connection.execute(
        "SELECT COALESCE(MAX(ordinal),0) FROM request_batches WHERE run_id=? AND directory_id=?",
        (run_id, directory_id),
    ).fetchone()
    return int(row[0]) + 1


def _batch_tokens(state: str, questions: Dict[str, Any], counter: TokenCounter) -> int:
    return counter.count(state) + sum(
        counter.count(json.dumps(value, sort_keys=True)) for value in questions.values()
    )


def _claim_members(store: JevStore, run_id: str, batch_id: str, file_ids: List[str]) -> None:
    with store.connection:
        store.connection.executemany(
            "UPDATE assessment_files SET status='planned', batch_id=?, updated_at=? "
            "WHERE run_id=? AND file_id=?",
            [(batch_id, utc_now(), run_id, file_id) for file_id in file_ids],
        )
