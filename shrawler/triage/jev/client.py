"""HTTP client and protocol adapter for the Jev System One decision shape.

One request carries a shared ``state`` plus a map of typed ``questions`` and
returns an ``answers`` map keyed by question ID. The requests are issued with
``requests`` so the transport is easy to fake in tests.
"""

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests

from .config import ADAPTER_VERSION, JevConfig

# Only these answer keys are ever read from a response.
QUESTION_TYPES = ("choice", "score", "noul")


class ProtocolError(ValueError):
    """A response that cannot be attributed to the request that produced it."""


class InputError(ValueError):
    """The request exceeded an input budget and must be reshaped."""


@dataclass
class Answer:
    file_id: str
    choice: str
    distribution: Optional[Dict[str, Any]]
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DecisionResponse:
    answers: Dict[str, Answer]
    usage: Optional[Dict[str, Any]]
    model: str
    http_status: int
    latency_ms: int


class JevClient:
    """Transport plus capability probe against one decision endpoint."""

    adapter_version = ADAPTER_VERSION

    def __init__(self, config: JevConfig, timeout: Optional[int] = None) -> None:
        self.config = config
        self.timeout = timeout or config.request_timeout_seconds
        self.session = requests.Session()

    def close(self) -> None:
        self.session.close()

    def headers(self) -> Dict[str, str]:
        key = self.config.resolved_api_key()
        headers = {"content-type": "application/json", "accept": "application/json"}
        if key:
            headers["authorization"] = f"Bearer {key}"
        return headers

    # -- capabilities -----------------------------------------------------

    def count_tokens(self, text: str) -> Optional[int]:
        """Gateway tokenizer when configured; otherwise defer to the estimator."""
        if not self.config.tokenize_endpoint:
            return None
        try:
            response = self.session.post(
                self.config.tokenize_endpoint,
                headers=self.headers(),
                json={"model": self.config.model, "text": text},
                timeout=self.timeout,
            )
        except requests.RequestException:
            return None
        if response.status_code != 200:
            return None
        try:
            data = response.json()
        except ValueError:
            return None
        tokens = data.get("tokens")
        return len(tokens) if isinstance(tokens, list) else None

    def probe(self) -> Dict[str, Any]:
        """Synthetic decision that establishes routing and protocol shape."""
        started = time.perf_counter()
        payload = {
            "model": self.config.model,
            "state": "Shrawler capability probe.",
            "questions": {
                "probe": {
                    "type": "choice",
                    "instructions": "Return the first option.",
                    "criteria": {"first": "the first option", "second": "another option"},
                }
            },
        }
        try:
            response = self.session.post(
                self.config.endpoint,
                headers=self.headers(),
                json=payload,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            return {"reachable": False, "error": str(exc)}
        latency_ms = int((time.perf_counter() - started) * 1000)
        report: Dict[str, Any] = {
            "reachable": True,
            "http_status": response.status_code,
            "latency_ms": latency_ms,
            "endpoint": self.config.endpoint,
            "adapter": self.adapter_version,
        }
        try:
            body = response.json()
        except ValueError:
            body = {}
        if isinstance(body, dict):
            report["resolved_model"] = body.get("model")
            answers = body.get("answers")
            report["returns_answers"] = isinstance(answers, dict)
            report["returns_usage"] = isinstance(body.get("usage"), dict)
            # A non-zero status or an error body means the endpoint does not
            # speak System One even when it answers HTTP 200 (for example an
            # OpenAI-compatible server's catch-all route).
            error = _error_message(body)
            if response.status_code != 200 or (error and not report["returns_answers"]):
                report["reachable"] = False
                report["speaks_systemone"] = False
                report["error"] = (
                    f"endpoint does not accept the System One request shape "
                    f"(HTTP {response.status_code}): {error or 'no answers'}"
                )
                return report
            report["speaks_systemone"] = report["returns_answers"]
        return report

    # -- dispatch ---------------------------------------------------------

    def decide(self, payload: Dict[str, Any]) -> DecisionResponse:
        started = time.perf_counter()
        response = self.session.post(
            self.config.endpoint,
            headers=self.headers(),
            json=payload,
            timeout=self.timeout,
        )
        latency_ms = int((time.perf_counter() - started) * 1000)
        body = _json_body(response)
        if response.status_code == 200:
            return DecisionResponse(
                answers=self._parse_answers(payload, body),
                usage=body.get("usage") if isinstance(body.get("usage"), dict) else None,
                model=str(body.get("model") or self.config.model),
                http_status=200,
                latency_ms=latency_ms,
            )
        message = _error_message(body) or response.reason
        if _is_input_error(response.status_code, message):
            raise InputError(f"input budget exceeded ({message})")
        raise ProtocolError(
            f"decision endpoint returned {response.status_code}: {message}"
        )

    def _parse_answers(
        self, payload: Dict[str, Any], body: Dict[str, Any]
    ) -> Dict[str, Answer]:
        questions = payload.get("questions", {})
        answers = body.get("answers")
        if not isinstance(answers, dict):
            # An error body here means the endpoint does not implement the
            # System One request shape (some servers return it on HTTP 200).
            error = _error_message(body)
            if error:
                raise ProtocolError(
                    f"endpoint does not speak the System One request shape: {error}"
                )
            raise ProtocolError("response is missing an answers object")
        expected = set(questions)
        received = set(answers)
        unknown = received - expected
        if unknown:
            raise ProtocolError(f"response contained unknown question IDs: {sorted(unknown)}")
        parsed: Dict[str, Answer] = {}
        for file_id, answer in answers.items():
            if not isinstance(answer, dict):
                raise ProtocolError(f"answer for {file_id} is not an object")
            typed_answer: Dict[str, Any] = answer
            label = _selected_choice(questions[file_id], typed_answer)
            parsed[str(file_id)] = Answer(
                file_id=str(file_id),
                choice=label,
                distribution=_distribution(typed_answer),
                raw=typed_answer,
            )
        return parsed


def _json_body(response: requests.Response) -> Dict[str, Any]:
    try:
        body = response.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def _error_message(body: Dict[str, Any]) -> str:
    error = body.get("error")
    if isinstance(error, dict):
        return str(error.get("message") or error.get("code") or "")
    if isinstance(error, str):
        return error
    return str(body.get("message") or "")


def _is_input_error(status: int, message: str) -> bool:
    lowered = message.casefold()
    return status == 413 or "max_tokens_exceeded" in lowered or "too long" in lowered


def _selected_choice(question: Dict[str, Any], answer: Dict[str, Any]) -> str:
    question_type = question.get("type")
    if question_type == "choice":
        choice = answer.get("choice")
        if not isinstance(choice, str) or choice not in question.get("criteria", {}):
            raise ProtocolError("choice answer is not one of the declared criteria")
        return choice
    if question_type == "score":
        score = answer.get("score")
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise ProtocolError("score answer is not numeric")
        return str(score)
    if question_type == "noul":
        value = answer.get("noul")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ProtocolError("noul answer is not numeric")
        if not 0.0 <= float(value) <= 1.0:
            raise ProtocolError("noul answer is outside 0..1")
        return str(value)
    raise ProtocolError(f"unsupported question type: {question_type}")


def _distribution(answer: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    for key in ("probabilities", "distribution", "confidence"):
        value = answer.get(key)
        if isinstance(value, dict):
            return value
    return None


def load_payload(batch_row: Any) -> Dict[str, Any]:
    return json.loads(batch_row["payload_json"])


def question_ids(batch_row: Any) -> List[str]:
    return list(json.loads(batch_row["payload_json"]).get("questions", {}).keys())
