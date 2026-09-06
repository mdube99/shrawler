"""Pure metadata evaluation with bounded, explainable directory context."""

import re
from collections import OrderedDict
from fnmatch import fnmatchcase
from typing import Any, Callable, Dict, List, Optional, Tuple

from .rules import RuleSet

ENGINE_VERSION = "2"

SiblingLookup = Callable[
    [str, str, Tuple[str, ...], Dict[str, Any]], List[Dict[str, Any]]
]


def segments(path: str) -> Tuple[str, ...]:
    return tuple(part for part in path.replace("\\", "/").split("/") if part)


def tokens(name: str) -> List[str]:
    # Split camelCase before folding case; retain Unicode letters and digits.
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return [part.casefold() for part in re.split(r"[\W_]+", separated) if part]


class Engine:
    def __init__(
        self, rules: RuleSet, sibling_lookup: Optional[SiblingLookup] = None
    ) -> None:
        self.rules = rules
        self.sibling_lookup = sibling_lookup
        self._cache: OrderedDict[
            Tuple[str, str, Tuple[str, ...]], List[Dict[str, Any]]
        ] = OrderedDict()

    def contexts(
        self, host: str, share: str, parent: Tuple[str, ...]
    ) -> List[Dict[str, Any]]:
        key = (host, share, parent)
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        evidence: List[Dict[str, Any]] = []
        for context in self.rules.document.get("contexts", []):
            depth = context["apply_to_descendants"]
            for distance in range(min(depth, len(parent)) + 1):
                ancestor = parent[: len(parent) - distance]
                witnesses: List[Dict[str, Any]] = []
                if "directory_name_any" in context:
                    match = bool(ancestor) and ancestor[-1].casefold() in {
                        name.casefold() for name in context["directory_name_any"]
                    }
                elif "directory_name_contains_any" in context:
                    match = bool(ancestor) and any(
                        term.casefold() in ancestor[-1].casefold()
                        for term in context["directory_name_contains_any"]
                    )
                elif "sibling_name_any" in context:
                    if self.sibling_lookup:
                        witnesses = self.sibling_lookup(host, share, ancestor, context)
                    match = bool(witnesses)
                else:
                    match = (
                        host.casefold() == context["host"].casefold()
                        and share.casefold() == context["share"].casefold()
                        and tuple(p.casefold() for p in ancestor)
                        == tuple(p.casefold() for p in segments(context["path"]))
                    )
                if match:
                    evidence.append(
                        {
                            "context_id": context["id"],
                            "tag": context["tag"],
                            "source_path": "/" + "/".join(ancestor),
                            "distance": distance,
                        }
                    )
                    if witnesses:
                        evidence[-1]["sibling_evidence"] = witnesses
                    break  # nearest source is sufficient for each context definition
        self._cache[key] = evidence
        if len(self._cache) > 4096:
            self._cache.popitem(last=False)
        return evidence

    def evaluate(
        self,
        metadata: Dict[str, Any],
        explain_all: bool = False,
        resolved_contexts: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        name = str(metadata["file_name"])
        path = segments(str(metadata["remote_path"]))
        parent = path[:-1]
        context = (
            resolved_contexts
            if resolved_contexts is not None
            else self.contexts(str(metadata["host"]), str(metadata["share"]), parent)
        )
        folded = name.casefold()
        # Treat .env itself as an extension-bearing candidate as well.
        extension = "." + folded.rsplit(".", 1)[1] if "." in folded else ""
        values: Dict[str, Any] = {
            "extension_any": [extension],
            "filename_any": [folded],
            "filename_glob_any": [folded],
            "filename_token_any": tokens(name),
            "filename_contains_any": [folded],
            "parent_name_any": [parent[-1].casefold()] if parent else [],
            "parent_name_contains_any": [parent[-1].casefold()] if parent else [],
            "host_any": [str(metadata["host"]).casefold()],
            "share_any": [str(metadata["share"]).casefold()],
            "context_any": [item["tag"] for item in context],
        }
        signals: List[Dict[str, Any]] = []
        diagnostics: List[Dict[str, Any]] = []
        groups: Dict[Tuple[str, str], int] = {}
        for rule in self.rules.document.get("rules", []):
            evidence: Dict[str, Any] = {}
            failures: List[str] = []
            for condition, expected in rule["when"].items():
                if condition in {"min_size_bytes", "max_size_bytes"}:
                    actual = metadata["size_bytes"]
                    matched = (
                        actual >= expected
                        if condition == "min_size_bytes"
                        else actual <= expected
                    )
                    evidence[condition] = actual
                else:
                    patterns = (
                        expected
                        if condition == "context_any"
                        else [s.casefold() for s in expected]
                    )
                    hits = (
                        [
                            value
                            for value in values[condition]
                            if any(fnmatchcase(value, pattern) for pattern in patterns)
                        ]
                        if condition == "filename_glob_any"
                        else [value for value in values[condition] if value in patterns]
                    )
                    if condition.endswith("contains_any"):
                        hits = [
                            value
                            for value in values[condition]
                            if any(pattern in value for pattern in patterns)
                        ]
                        evidence[condition + "_matched_terms"] = [
                            pattern
                            for pattern in patterns
                            if any(pattern in value for value in hits)
                        ]
                    matched = bool(hits)
                    evidence[condition] = hits
                    if condition == "context_any":
                        evidence["context_sources"] = [
                            c for c in context if c["tag"] in hits
                        ]
                if not matched:
                    failures.append(condition)
            if explain_all:
                diagnostics.append(
                    {
                        "rule_id": rule["id"],
                        "matched": not failures,
                        "failed_conditions": failures,
                    }
                )
            if failures:
                continue
            group = (rule["category"], rule["signal_group"])
            groups[group] = max(groups.get(group, 0), rule["points"])
            signals.append(
                {
                    "rule_id": rule["id"],
                    "description": rule["description"],
                    "category": rule["category"],
                    "signal_group": rule["signal_group"],
                    "points": rule["points"],
                    "evidence": evidence,
                }
            )
        scores: Dict[str, int] = {}
        for (category, _), points in groups.items():
            scores[category] = scores.get(category, 0) + points
        credited: Dict[Tuple[str, str], str] = {}
        for signal in sorted(
            signals, key=lambda item: (-item["points"], item["rule_id"])
        ):
            key = (signal["category"], signal["signal_group"])
            signal["credited_points"] = 0 if key in credited else signal["points"]
            if key not in credited:
                credited[key] = signal["rule_id"]
            else:
                signal["capped_by_rule"] = credited[key]
        result: Dict[str, Any] = {
            "priority": max(scores.values(), default=0),
            "category_scores": scores,
            "evidence_type": "metadata_only",
            "signals": signals,
            "contexts": context,
        }
        if explain_all:
            result["rule_diagnostics"] = diagnostics
        return result
