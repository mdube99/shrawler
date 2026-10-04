"""Versioned configuration and rubric for the Jev decision path.

Everything that can change an effective model input is versioned here and
folded into cache fingerprints: the adapter, context builder, planner, rubric,
preprocessing policy, served model, and immutable deployment revision.
"""

import hashlib
import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

ADAPTER_VERSION = "systemone-1"
# Context and payload layout changed with multi-directory packing: directory
# blocks are now labeled inside one shared state. Historical runs keep their
# stored context hashes and payloads; these versions only affect new work.
CONTEXT_VERSION = "2"
# Planner version 4 packs independent directories by default and re-queues
# byte-budget overflow into the next batch (instead of dropping it). Both change
# which files share a request, so the exact-request cache identity changes.
PLANNER_VERSION = "4"
# Payload version 4 sends only the signals the rubric uses: the filename, the
# directory context (path and sibling markers), and a short deterministic binding
# key that ties a candidate line to its question. Size, mtime, observed counts,
# extension histograms, the ancestor list, and the completeness phrase are not
# sent. The binding key is derived from the file ID (see ``planner.binding_key``)
# so it stays stable across replanning, which keeps the exact-request cache and
# resume valid. A *sequential* alias (c1..cN) was tried and rejected: it broke
# answer attribution once a request carried more than a few candidates.
PAYLOAD_VERSION = "4"
# Rubric version 5 stops repeating the level descriptions on every question. The
# objective already states the full 0-4 rubric once per request and the endpoint
# reads a criterion with no description from its name alone, so each question now
# carries only the five level keys. It also names three credential indicators the
# level-4 list was missing (ftp_users, a bare keystore basename, pwd).
RUBRIC_VERSION = "5"
PREPROCESSING_VERSION = "1"

# Planning scopes. ``directory`` keeps one source directory per request (the
# conservative default while the cross-directory quality gate is pending);
# ``multi-directory`` packs independent directory blocks into shared requests.
PACKING_SCOPES = ("directory", "multi-directory")

# Default Jev (TypeSafe System One) route. The hosted route
# ``https://jevtypesafeai.com/api/v1/decide`` and a team LiteLLM proxy that
# forwards the same request shape are drop-in alternates.
DEFAULT_ENDPOINT = "https://api.typesafe.ai/v1/systemone"

# Published list price for the default TypeSafe route, used only to turn real
# billed input tokens into an estimated dollar figure for reporting. The hosted
# route (jevtypesafeai.com) is $0.25-$0.42/M. This never affects what is sent.
DEFAULT_INPUT_PRICE_PER_MTOK = 0.042

DEFAULT_OBJECTIVE = (
    "Assess how strongly the available evidence supports prioritizing this file for analyst inspection to identify sensitive information exposed through a file share.\n\n"
    "Sensitive information includes authentication credentials, passwords, private keys, tokens and secrets; personal and medical records; financial records; and confidential business information.\n\n"
    "Evidence available: the candidate's filename and its directory context, which is the directory path including ancestor directory names plus the sibling filenames. File contents, size, and modification time are not available; do not require them, and never treat missing evidence as making a file safe. Judge the candidate's own filename together with its directory context.\n\n"
    "Apply this inspection-priority rubric:\n"
    "0 — Minimal: The filename and directory context indicate ordinary, public, or nonsensitive material.\n"
    "1 — Possible: Weak or generic indicators of sensitive information warrant lower-priority review.\n"
    "2 — Likely: A specific sensitive indicator, such as a suggestive filename or a sensitive directory (for example HR, Finance, Medical, or Passwords), without strong sensitive-record or credential evidence, warrants analyst inspection.\n"
    "3 — Strong: Strong indicators of sensitive personal, medical, financial, or confidential records (for example SSN, patient, medical, payroll, invoice, tax, or credit-card names), or a credential-adjacent filename that is only suggestive (for example 'compass' or 'mapping'), warrant prompt inspection.\n"
    "4 — Immediate: The filename alone, or the filename together with its directory context, unambiguously denotes authentication credentials, secrets, or private keys. Treat a candidate as level 4 whenever its own name contains or matches any of: password, passwd, pwd, passphrase, login, logon, credential(s), secret(s), token, api-key, apikey, private-key, private key, ssh key; the SSH key names id_rsa, id_dsa, id_ecdsa, id_ed25519; authorized_keys; account files such as ftp_users; credential or private-key extensions such as .pem, .key, .ppk, .p12, .pfx, .jks, and .keystore, or a basename of keystore; password-database names such as .kdbx; environment and cloud credential files such as .env, .netrc, .npmrc, aws_credentials, azure_credentials, service-account.json, and kubeconfig; and secret-store names such as secrets.yml or vault-token. Rate level 4 even when the extension is a common data format such as .json, .yml, .txt, .xlsx, or .csv, because these names are unambiguous credential indicators on their own. Do not reserve level 4 for confirmed contents.\n\n"
    "Combination rule: if a filename contains a credential word together with another sensitive word, the credential word controls. For example, 'payroll login.txt' and 'admin password.xlsx' are level 4, not level 3, because they denote credentials.\n\n"
    "Level-4 guidance: Reserve level 4 for candidates whose own filename indicates credentials, secrets, or private keys. A sensitive directory name such as 'Passwords' or 'HR', or a credential-like sibling file, on its own raises priority but does not make a benign filename level 4. Never downgrade an unambiguous credential filename to level 3 because its contents are unavailable.\n\n"
    "Assess inspection priority, not confirmed vulnerability severity. Score every candidate on the same 0-4 scale."
)

# One ordered ``choice`` question per file on a 0-4 inspection-priority scale.
# Keys are the numeric levels so the model's answer is directly rankable.
RUBRIC = {
    "0": "Minimal: The filename and directory context indicate ordinary, public, or nonsensitive material.",
    "1": "Possible: Weak or generic indicators of sensitive information warrant lower-priority review.",
    "2": "Likely: A specific sensitive indicator, such as a suggestive filename or a sensitive directory, suggests sensitive information and warrants analyst inspection.",
    "3": "Strong: Strong indicators of sensitive personal, medical, financial, or confidential records, or an ambiguous credential-related filename, warrant prompt inspection.",
    "4": "Immediate: The filename, alone or with its directory context, unambiguously denotes authentication credentials, secrets, or private keys; warrants immediate review even without file contents.",
}
# Ordered numeric levels; dict insertion order above is the source of truth.
PRIORITY_LEVELS = tuple(RUBRIC)
PRIORITY_NAMES = {
    "0": "Minimal",
    "1": "Possible",
    "2": "Likely",
    "3": "Strong",
    "4": "Immediate",
}
# Per-question criteria. The objective states every level's full description
# once per request, and the endpoint reads a criterion with no description from
# its name alone, so only the level keys are sent. Keys must match
# ``RUBRIC``/``PRIORITY_LEVELS``; the client validates the model's returned
# choice against these keys.
RUBRIC_CRITERIA: Dict[str, None] = dict.fromkeys(RUBRIC)
# A rule-missed file is surfaced for rule expansion only when the model rates it
# at least this strongly (3 = "Strong", 4 = "Immediate").
PRIORITY_INSPECT_MIN = 3


def priority_score(value: Any) -> int:
    """Numeric priority for a stored model answer, or -1 if unparseable."""
    try:
        return int(float(str(value)))
    except (TypeError, ValueError):
        return -1


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
        "packing_scope",
        "token_headroom_percent",
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


def _require_env_name(value: Any, field_name: str) -> str:
    """Validate a variable *name*, never a secret value.

    Catching this at load time stops a key being pasted into ``api_key_env``,
    which would otherwise silently leave ``api_key`` empty and echo the secret
    in later error messages. Names are conventionally upper-case; anything long
    or mixed-case looks like a credential and is rejected.
    """
    text = _require_str(value, field_name)
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", text) or len(text) > 64:
        raise ValueError(
            f"[jev] {field_name} must be an environment variable name such as "
            f"JEV_API_KEY (upper case); put the credential itself in api_key"
        )
    return text


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
    # Candidates per request. Larger batches amortize the fixed per-request cost
    # (the objective plus the gateway's own scaffolding) over more files. At the
    # payload-4 request shape the endpoint answered 1000 questions in one request,
    # and 500 stayed inside every local budget; the previous shape failed at 500
    # with ``max_tokens_exceeded``. The token budget is still the binding limit.
    max_questions_per_request: int = 500
    request_timeout_seconds: int = 120
    retries: int = 2
    # Bounded simultaneous decision requests. Higher values are the primary
    # lever once request count is minimal; sweep 1/2/4/8 against the real route
    # (scripts/benchmark_jev.py --sweep-workers) and back off if the gateway
    # serializes or throttles.
    workers: int = 8
    rate_limit_per_minute: int = 0
    time_budget_seconds: int = 0
    max_request_bytes: int = 0
    tokenize_endpoint: str = ""
    instruction_overhead_tokens: int = 24
    state_overhead_tokens: int = 8
    # Multi-directory packing is the default: it shares the objective and fixed
    # request overhead across packed directories, cutting request count and
    # tokens. On 2026-10-04 the live rubric evaluation passed 6/6 at 17/17
    # credential cases with zero benign false positives (one request for 36
    # cases), and a 20-file wide directory passed 10/10. ``directory`` remains
    # selectable. Retain the real file ID as the binding key: a short alias
    # broke attribution and is reverted. See docs/jev-assessment-scaling.md.
    packing_scope: str = "multi-directory"
    token_headroom_percent: int = 10

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
            values["api_key_env"] = _require_env_name(
                table["api_key_env"], "api_key_env"
            )
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
        if "token_headroom_percent" in table:
            values["token_headroom_percent"] = _require_int(
                table["token_headroom_percent"], "token_headroom_percent", 0, 90
            )
        if "packing_scope" in table:
            scope = _require_str(table["packing_scope"], "packing_scope")
            if scope not in PACKING_SCOPES:
                raise ValueError(
                    f"[jev] packing_scope must be one of {list(PACKING_SCOPES)}"
                )
            values["packing_scope"] = scope
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

    def key_source(self) -> str:
        """Describe where the credential is expected to come from.

        Used for auth-failure messages. The environment variable branch is only
        taken when api_key is empty, and validation guarantees api_key_env is a
        bare variable name rather than a pasted secret.
        """
        if self.api_key:
            return "the [jev] api_key in the Shrawler configuration file"
        return f"the ${self.api_key_env} environment variable"

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
            "payload_version": PAYLOAD_VERSION,
            "rubric_version": RUBRIC_VERSION,
            "preprocessing_version": PREPROCESSING_VERSION,
            "objective": self.objective,
            "max_input_tokens": self.max_input_tokens,
            "max_state_longest_question_tokens": self.max_state_longest_question_tokens,
            "max_questions_per_request": self.max_questions_per_request,
            "packing_scope": self.packing_scope,
            "token_headroom_percent": self.token_headroom_percent,
        }

    def fingerprint(self) -> str:
        return fingerprint(self.provenance())
