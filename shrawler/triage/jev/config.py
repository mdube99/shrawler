"""Versioned configuration and rubric for the Jev decision path.

Everything that can change an effective model input is versioned here and
folded into cache fingerprints: the adapter, context builder, planner, rubric,
preprocessing policy, served model, and immutable deployment revision.
"""

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

ADAPTER_VERSION = "systemone-1"
CONTEXT_VERSION = "1"
PLANNER_VERSION = "1"
RUBRIC_VERSION = "1"
PREPROCESSING_VERSION = "1"

# Default Jev (TypeSafe System One) route. The hosted route
# ``https://jevtypesafeai.com/api/v1/decide`` and a team LiteLLM proxy that
# forwards the same request shape are drop-in alternates.
DEFAULT_ENDPOINT = "https://api.typesafe.ai/v1/systemone"

DEFAULT_OBJECTIVE = (
    "Rank each observed file for how likely an analyst should inspect it for "
    "sensitive information. Sensitivity includes credentials, private keys, "
    "sensitive configuration, personal records, financial data, and other "
    "engagement-specific sensitive content."
)

# One unordered ``choice`` question per file. "insufficient" is deliberately a
# peer option, not the bottom of an ordinal scale.
RUBRIC = {
    "high": "Strong metadata evidence the file merits review for sensitive information.",
    "moderate": "Some metadata evidence the file merits review for sensitive information.",
    "low": "Little metadata evidence the file merits review for sensitive information.",
    "insufficient": "The supplied metadata is not sufficient to judge review value.",
}
REVIEW_LABELS = tuple(RUBRIC)
HIGH_LABEL = "high"
INSUFFICIENT_LABEL = "insufficient"

ALLOWED_FIELDS = frozenset(
    {
        "enabled",
        "endpoint",
        "api_key_env",
        "api_key",
        "model",
        "deployment_revision",
        "objective",
        "max_input_tokens",
        "max_state_longest_question_tokens",
        "max_questions_per_request",
        "request_timeout_seconds",
        "retries",
        "workers",
        "rate_limit_per_minute",
        "time_budget_seconds",
        "max_request_bytes",
        "tokenize_endpoint",
        "instruction_overhead_tokens",
        "state_overhead_tokens",
    }
)


def canonical(value: Any) -> str:
    """Deterministic JSON used for fingerprints and request bodies."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def fingerprint(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def _require_bool(value: Any, field_name: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"[jev] {field_name} must be a boolean")
    return value


def _require_str(value: Any, field_name: str, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise ValueError(f"[jev] {field_name} must be a string")
    return value


def _require_int(
    value: Any, field_name: str, minimum: int = 0, maximum: int = 2**31 - 1
) -> int:
    # bool is an int subclass; reject it explicitly.
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(
            f"[jev] {field_name} must be an integer between {minimum} and {maximum}"
        )
    return value


@dataclass(frozen=True)
class JevConfig:
    enabled: bool = False
    endpoint: str = DEFAULT_ENDPOINT
    api_key_env: str = "JEV_API_KEY"
    api_key: str = ""
    model: str = "jev-latest"
    deployment_revision: str = ""
    objective: str = DEFAULT_OBJECTIVE
    max_input_tokens: int = 60000
    max_state_longest_question_tokens: int = 30000
    max_questions_per_request: int = 200
    request_timeout_seconds: int = 120
    retries: int = 2
    workers: int = 4
    rate_limit_per_minute: int = 0
    time_budget_seconds: int = 0
    max_request_bytes: int = 0
    tokenize_endpoint: str = ""
    instruction_overhead_tokens: int = 24
    state_overhead_tokens: int = 8

    @classmethod
    def from_mapping(cls, data: Optional[Mapping[str, Any]]) -> "JevConfig":
        table = dict(data or {})
        unknown = set(table) - ALLOWED_FIELDS
        if unknown:
            raise ValueError(f"[jev] unknown fields: {sorted(unknown)}")
        values: Dict[str, Any] = {}
        if "enabled" in table:
            values["enabled"] = _require_bool(table["enabled"], "enabled")
        if "endpoint" in table:
            endpoint = _require_str(table["endpoint"], "endpoint")
            if not endpoint.startswith(("http://", "https://")):
                raise ValueError("[jev] endpoint must be an http(s) URL")
            values["endpoint"] = endpoint
        if "api_key_env" in table:
            values["api_key_env"] = _require_str(table["api_key_env"], "api_key_env")
        if "api_key" in table:
            values["api_key"] = _require_str(
                table["api_key"], "api_key", allow_empty=True
            )
        if "model" in table:
            values["model"] = _require_str(table["model"], "model")
        if "deployment_revision" in table:
            values["deployment_revision"] = _require_str(
                table["deployment_revision"], "deployment_revision", allow_empty=True
            )
        if "objective" in table:
            objective = _require_str(table["objective"], "objective", allow_empty=True)
            values["objective"] = objective.strip() or DEFAULT_OBJECTIVE
        for name, minimum in (
            ("max_input_tokens", 1000),
            ("max_state_longest_question_tokens", 500),
            ("max_questions_per_request", 1),
            ("request_timeout_seconds", 1),
        ):
            if name in table:
                values[name] = _require_int(table[name], name, minimum)
        for name in (
            "retries",
            "workers",
            "rate_limit_per_minute",
            "time_budget_seconds",
            "max_request_bytes",
            "instruction_overhead_tokens",
            "state_overhead_tokens",
        ):
            if name in table:
                values[name] = _require_int(table[name], name, 0)
        if values.get("workers", 1) < 1:
            raise ValueError("[jev] workers must be at least 1")
        if "tokenize_endpoint" in table:
            tokenize = _require_str(
                table["tokenize_endpoint"], "tokenize_endpoint", allow_empty=True
            )
            if tokenize and not tokenize.startswith(("http://", "https://")):
                raise ValueError("[jev] tokenize_endpoint must be an http(s) URL")
            values["tokenize_endpoint"] = tokenize
        return cls(**values)

    def resolved_api_key(self) -> str:
        if self.api_key:
            return self.api_key
        return os.environ.get(self.api_key_env, "")

    def to_table(self) -> Dict[str, Any]:
        """All fields as a mapping acceptable to ``from_mapping``."""
        from dataclasses import asdict

        return asdict(self)

    def provenance(self) -> Dict[str, Any]:
        """Everything that changes an effective input or its interpretation."""
        return {
            "endpoint": self.endpoint,
            "model": self.model,
            "deployment_revision": self.deployment_revision or self.model,
            "adapter_version": ADAPTER_VERSION,
            "context_version": CONTEXT_VERSION,
            "planner_version": PLANNER_VERSION,
            "rubric_version": RUBRIC_VERSION,
            "preprocessing_version": PREPROCESSING_VERSION,
            "objective": self.objective,
            "max_input_tokens": self.max_input_tokens,
            "max_state_longest_question_tokens": self.max_state_longest_question_tokens,
            "max_questions_per_request": self.max_questions_per_request,
        }

    def fingerprint(self) -> str:
        return fingerprint(self.provenance())
