"""Versioned, deliberately small declarative metadata rule language."""

import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, cast

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[no-redef]


@dataclass(frozen=True)
class RuleSet:
    document: Dict[str, Any]
    canonical: str
    digest: str


def _keys(
    value: Dict[str, Any], allowed: Set[str], required: Set[str], location: str
) -> None:
    unknown = set(value) - allowed
    missing = required - set(value)
    if unknown or missing:
        raise ValueError(
            f"{location}: unknown fields {sorted(unknown)}; missing fields {sorted(missing)}"
        )


def _strings(value: Any, location: str) -> None:
    if (
        not isinstance(value, list)
        or not value
        or any(
            not isinstance(item, str) or not item.strip()
            for item in cast(List[Any], value)
        )
    ):
        raise ValueError(f"{location}: expected a nonempty array of nonempty strings")


def _text(value: Any, location: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{location}: expected a nonempty string")


def _integer(value: Any, location: str) -> None:
    if type(value) is not int or not 0 <= value <= 1_000_000:
        raise ValueError(f"{location}: expected an integer between 0 and 1000000")


def parse_timestamp(value: Any) -> Optional[datetime]:
    """Parse an ISO 8601 timestamp into an aware UTC datetime, or None.

    Naive values are assumed to be UTC. The trailing ``Z`` form accepted by
    web tooling is normalized before parsing so Python 3.8 behaves like 3.11.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text[-1:] in {"Z", "z"}:
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


CONDITIONS = {
    "extension_any",
    "filename_any",
    "filename_glob_any",
    "filename_token_any",
    "filename_contains_any",
    "parent_name_any",
    "parent_name_contains_any",
    "path_segment_any",
    "context_any",
    "host_any",
    "share_any",
    "min_size_bytes",
    "max_size_bytes",
    "modified_before",
    "modified_after",
}


# Rarity entries describe directory-population thresholds rather than a single
# file, so they are validated separately from per-file rules.
RARITY_FIELDS = {
    "id",
    "description",
    "category",
    "signal_group",
    "points",
    "minimum_directory_files",
    "maximum_same_extension_ratio",
    "minimum_dominant_extension_ratio",
}


def validate(document: Dict[str, Any]) -> RuleSet:
    _keys(
        document,
        {"version", "contexts", "rules", "rarity"},
        {"version"},
        "ruleset",
    )
    if type(document["version"]) is not int or document["version"] != 1:
        raise ValueError("ruleset version must be 1")
    ids: Set[str] = set()
    tags: Set[str] = set()
    for kind in ("contexts", "rules", "rarity"):
        entries = document.get(kind, [])
        if not isinstance(entries, list):
            raise ValueError(f"{kind} must be an array of tables")
        for raw_entry in cast(List[Any], entries):
            if not isinstance(raw_entry, dict):
                raise ValueError(f"{kind} entries must be tables")
            entry = cast(Dict[str, Any], raw_entry)
            _text(entry.get("id"), f"{kind}.id")
            identifier = entry["id"]
            if identifier in ids:
                raise ValueError(f"duplicate rule/context id: {identifier}")
            ids.add(identifier)
            if kind == "contexts":
                _keys(
                    entry,
                    {
                        "id",
                        "tag",
                        "directory_name_any",
                        "directory_name_contains_any",
                        "sibling_name_any",
                        "minimum_distinct_patterns",
                        "host",
                        "share",
                        "path",
                        "apply_to_descendants",
                    },
                    {"id", "tag", "apply_to_descendants"},
                    identifier,
                )
                _text(entry["tag"], identifier)
                tags.add(entry["tag"])
                _integer(entry["apply_to_descendants"], identifier)
                if entry["apply_to_descendants"] > 64:
                    raise ValueError(f"{identifier}: context depth cannot exceed 64")
                named = "directory_name_any" in entry
                partial = "directory_name_contains_any" in entry
                siblings = "sibling_name_any" in entry
                scoped = any(key in entry for key in ("host", "share", "path"))
                if sum((named, partial, siblings, scoped)) != 1:
                    raise ValueError(
                        f"{identifier}: choose one directory-name matcher, sibling_name_any, or host/share/path"
                    )
                if not siblings and "minimum_distinct_patterns" in entry:
                    raise ValueError(
                        f"{identifier}: minimum_distinct_patterns requires sibling_name_any"
                    )
                if named or partial:
                    _strings(
                        entry[
                            "directory_name_any"
                            if named
                            else "directory_name_contains_any"
                        ],
                        identifier,
                    )
                elif siblings:
                    _strings(entry["sibling_name_any"], identifier)
                    patterns = entry["sibling_name_any"]
                    if len(patterns) > 64 or len(
                        {p.casefold() for p in patterns}
                    ) != len(patterns):
                        raise ValueError(
                            f"{identifier}: use at most 64 distinct sibling patterns"
                        )
                    minimum = entry.get("minimum_distinct_patterns")
                    if type(minimum) is not int or not 1 <= minimum <= len(patterns):
                        raise ValueError(
                            f"{identifier}: minimum_distinct_patterns must be between 1 and the pattern count"
                        )
                else:
                    for key in ("host", "share", "path"):
                        _text(entry.get(key), f"{identifier}.{key}")
                    if not entry["path"].startswith(("/", "\\")):
                        raise ValueError(
                            f"{identifier}: path must be share-root-relative, starting with /"
                        )
                    if any(
                        p in {".", ".."}
                        for p in entry["path"].replace("\\", "/").split("/")
                    ):
                        raise ValueError(
                            f"{identifier}: path cannot contain . or .. segments"
                        )
            elif kind == "rarity":
                _keys(entry, RARITY_FIELDS, RARITY_FIELDS, identifier)
                for key in ("description", "category", "signal_group"):
                    _text(entry[key], f"{identifier}.{key}")
                _integer(entry["points"], identifier)
                _integer(entry["minimum_directory_files"], identifier)
                if entry["minimum_directory_files"] < 1:
                    raise ValueError(
                        f"{identifier}: minimum_directory_files must be at least 1"
                    )
                for key in (
                    "maximum_same_extension_ratio",
                    "minimum_dominant_extension_ratio",
                ):
                    ratio = entry[key]
                    if isinstance(ratio, bool) or not isinstance(ratio, (int, float)):
                        raise ValueError(
                            f"{identifier}.{key}: expected a ratio between 0 and 1"
                        )
                    if not 0 <= ratio <= 1:
                        raise ValueError(
                            f"{identifier}.{key}: expected a ratio between 0 and 1"
                        )
                if (
                    entry["maximum_same_extension_ratio"]
                    > entry["minimum_dominant_extension_ratio"]
                ):
                    raise ValueError(
                        f"{identifier}: maximum_same_extension_ratio cannot exceed "
                        "minimum_dominant_extension_ratio"
                    )
            else:
                _keys(
                    entry,
                    {
                        "id",
                        "description",
                        "category",
                        "signal_group",
                        "points",
                        "when",
                    },
                    {"id", "description", "category", "signal_group", "points", "when"},
                    identifier,
                )
                for key in ("description", "category", "signal_group"):
                    _text(entry[key], f"{identifier}.{key}")
                _integer(entry["points"], identifier)
                when = entry["when"]
                if not isinstance(when, dict) or not when:
                    raise ValueError(f"{identifier}: when must be a nonempty table")
                when = cast(Dict[str, Any], when)
                _keys(when, CONDITIONS, set(), identifier)
                for key, value in when.items():
                    if key.endswith("size_bytes"):
                        if type(value) is not int or value < 0:
                            raise ValueError(
                                f"{identifier}.{key}: expected a nonnegative integer"
                            )
                    elif key in {"modified_before", "modified_after"}:
                        _text(value, f"{identifier}.{key}")
                        if parse_timestamp(value) is None:
                            raise ValueError(
                                f"{identifier}.{key}: expected an ISO 8601 timestamp"
                            )
                    else:
                        _strings(value, f"{identifier}.{key}")
                if when.get("min_size_bytes", 0) > when.get(
                    "max_size_bytes", float("inf")
                ):
                    raise ValueError(f"{identifier}: minimum size exceeds maximum")
    for rule in document.get("rules", []):
        unknown_tags = set(rule["when"].get("context_any", [])) - tags
        if unknown_tags:
            raise ValueError(
                f"{rule['id']}: undefined context tags {sorted(unknown_tags)}"
            )
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return RuleSet(document, canonical, hashlib.sha256(canonical.encode()).hexdigest())


def load(paths: Optional[List[Path]] = None, builtins: bool = True) -> RuleSet:
    files = [Path(__file__).with_name("default.toml")] if builtins else []
    for path in paths or []:
        if path.is_dir():
            found = sorted(path.rglob("*.toml"))
            if not found:
                raise ValueError(f"no TOML rules found in {path}")
            files.extend(found)
        else:
            files.append(path)
    document: Dict[str, Any] = {"version": 1, "contexts": [], "rules": [], "rarity": []}
    for path in files:
        with path.open("rb") as handle:
            part = tomllib.load(handle)
        _keys(
            part,
            {"version", "contexts", "rules", "rarity"},
            {"version"},
            str(path),
        )
        if type(part["version"]) is not int or part["version"] != 1:
            raise ValueError(f"{path}: ruleset version must be 1")
        for kind in ("contexts", "rules", "rarity"):
            entries = part.get(kind, [])
            if not isinstance(entries, list):
                raise ValueError(f"{path}: {kind} must be an array of tables")
            document[kind].extend(entries)
    return validate(document)


def load_text(text: str, builtins: bool = True) -> RuleSet:
    """Parse browser/CLI-supplied TOML without interpreting filesystem paths."""
    part = tomllib.loads(text)
    _keys(
        part,
        {"version", "contexts", "rules", "rarity"},
        {"version"},
        "ruleset",
    )
    if type(part["version"]) is not int or part["version"] != 1:
        raise ValueError("ruleset version must be 1")
    document = json.loads(load(builtins=builtins).canonical)
    for kind in ("contexts", "rules", "rarity"):
        entries = part.get(kind, [])
        if not isinstance(entries, list):
            raise ValueError(f"{kind} must be an array of tables")
        document[kind].extend(entries)
    return validate(document)
