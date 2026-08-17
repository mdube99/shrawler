"""Snaffler rule loading and evaluation engine."""

import io
import logging
import os
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Set, Tuple

from colorama import Fore, Style

from .models import SnafflerRule

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]

SUPPORTED_ENUMERATION_SCOPES = {
    "ShareEnumeration",
    "DirectoryEnumeration",
    "FileEnumeration",
    "ContentsEnumeration",
    "PostMatch",
}
SUPPORTED_MATCH_ACTIONS = {"Discard", "Snaffle", "Relay"}
SUPPORTED_WORD_LIST_TYPES = {"Exact", "Contains", "Regex", "EndsWith", "StartsWith"}
SUPPORTED_MATCH_LOCATIONS = {
    "ShareName",
    "FilePath",
    "FileName",
    "FileExtension",
    "FileContentAsString",
    "FileLength",
}
DEFERRED_MATCH_ACTIONS = {"CheckForKeys", "EnterArchive", "SendToNextScope"}
DEFERRED_MATCH_LOCATIONS = {"FileContentAsBytes", "FileMD5"}


class SnafflerEngineMixin:
    """Snaffler behavior shared by the SMB crawler."""

    def _handle_snaffler_rule_error(self, message: str) -> None:
        """Handle Snaffler rule parsing errors in strict/non-strict mode."""
        if self.args.snaffler_strict:
            raise ValueError(message)
        logging.warning(message)

    def _compile_snaffler_pattern(
        self, word_list_type: str, value: str
    ) -> Pattern[str]:
        """Compile a Snaffler word list value into a regex pattern."""
        if word_list_type == "Regex":
            pattern = value
        elif word_list_type == "Contains":
            pattern = value
        elif word_list_type == "Exact":
            pattern = f"^{value}$"
        elif word_list_type == "StartsWith":
            pattern = f"^{value}"
        elif word_list_type == "EndsWith":
            pattern = f"{value}$"
        else:
            raise ValueError(f"Unsupported word list type: {word_list_type}")

        return re.compile(pattern, re.IGNORECASE)

    def _extract_rule_value(self, raw_rule: Dict[str, Any], keys: List[str]) -> Any:
        """Extract the first value that exists from a list of possible keys."""
        for key in keys:
            if key in raw_rule:
                return raw_rule[key]
        return None

    def _normalize_snaffler_rule(
        self, raw_rule: Dict[str, Any], source_file: str
    ) -> Optional[SnafflerRule]:
        """Normalize and validate a raw TOML ClassifierRules entry."""
        rule_name = self._extract_rule_value(
            raw_rule, ["RuleName", "rule_name", "Name"]
        )
        description = self._extract_rule_value(raw_rule, ["Description", "description"])
        scope = self._extract_rule_value(
            raw_rule, ["EnumerationScope", "scope", "Scope"]
        )
        action = self._extract_rule_value(raw_rule, ["MatchAction", "action", "Action"])
        triage = self._extract_rule_value(raw_rule, ["Triage", "triage"])
        match_location = self._extract_rule_value(
            raw_rule,
            ["MatchLocation", "match_location", "Location"],
        )
        word_list_type = self._extract_rule_value(
            raw_rule,
            ["WordListType", "word_list_type"],
        )
        word_list_raw = self._extract_rule_value(raw_rule, ["WordList", "word_list"])
        relay_targets_raw = self._extract_rule_value(
            raw_rule,
            ["RelayTargets", "relay_targets", "RelayTarget", "relay_target"],
        )
        interest_level = self._extract_rule_value(
            raw_rule, ["InterestLevel", "interest_level"]
        )
        match_length_raw = self._extract_rule_value(
            raw_rule, ["MatchLength", "match_length"]
        )
        match_md5_raw = self._extract_rule_value(raw_rule, ["MatchMD5", "match_md5"])

        required_values = {
            "RuleName": rule_name,
            "EnumerationScope": scope,
            "MatchAction": action,
            "MatchLocation": match_location,
            "WordListType": word_list_type,
            "WordList": word_list_raw,
        }
        missing = [name for name, value in required_values.items() if value is None]
        if missing:
            self._handle_snaffler_rule_error(
                f"Skipping malformed rule in {source_file}: missing {', '.join(missing)}"
            )
            return None

        scope_str = str(scope)
        action_str = str(action)
        location_str = str(match_location)
        list_type_str = str(word_list_type)

        if action_str in DEFERRED_MATCH_ACTIONS:
            self._handle_snaffler_rule_error(
                f"Skipping unsupported action '{action_str}' in rule '{rule_name}'"
            )
            return None
        if location_str in DEFERRED_MATCH_LOCATIONS:
            self._handle_snaffler_rule_error(
                f"Skipping unsupported match location '{location_str}' in rule '{rule_name}'"
            )
            return None

        if scope_str not in SUPPORTED_ENUMERATION_SCOPES:
            self._handle_snaffler_rule_error(
                f"Skipping rule '{rule_name}' with unknown scope '{scope_str}'"
            )
            return None
        if action_str not in SUPPORTED_MATCH_ACTIONS:
            self._handle_snaffler_rule_error(
                f"Skipping rule '{rule_name}' with unknown action '{action_str}'"
            )
            return None
        if location_str not in SUPPORTED_MATCH_LOCATIONS:
            self._handle_snaffler_rule_error(
                f"Skipping rule '{rule_name}' with unknown location '{location_str}'"
            )
            return None
        if list_type_str not in SUPPORTED_WORD_LIST_TYPES:
            self._handle_snaffler_rule_error(
                f"Skipping rule '{rule_name}' with unknown list type '{list_type_str}'"
            )
            return None

        if isinstance(word_list_raw, str):
            word_list = [word_list_raw]
        elif isinstance(word_list_raw, list):
            word_list = [
                str(value)
                for value in word_list_raw
                if value is not None and str(value).strip()
            ]
        else:
            self._handle_snaffler_rule_error(
                f"Skipping rule '{rule_name}' due to invalid WordList type"
            )
            return None

        if not word_list:
            self._handle_snaffler_rule_error(
                f"Skipping rule '{rule_name}' due to empty WordList"
            )
            return None

        relay_targets: List[str] = []
        if relay_targets_raw is not None:
            if isinstance(relay_targets_raw, str):
                relay_targets = [
                    item.strip()
                    for item in relay_targets_raw.split(",")
                    if item.strip()
                ]
            elif isinstance(relay_targets_raw, list):
                relay_targets = [
                    str(item).strip()
                    for item in relay_targets_raw
                    if item is not None and str(item).strip()
                ]

        if action_str == "Relay" and not relay_targets:
            self._handle_snaffler_rule_error(
                f"Skipping relay rule '{rule_name}' with no relay targets"
            )
            return None

        compiled_patterns: List[Pattern[str]] = []
        for value in word_list:
            try:
                compiled_patterns.append(
                    self._compile_snaffler_pattern(list_type_str, value)
                )
            except re.error as exc:
                self._handle_snaffler_rule_error(
                    f"Skipping rule '{rule_name}' due to invalid regex '{value}': {exc}"
                )
                return None

        interest_value: Optional[int] = None
        if interest_level is not None:
            try:
                interest_value = int(interest_level)
            except (TypeError, ValueError):
                self._handle_snaffler_rule_error(
                    f"Skipping rule '{rule_name}' due to invalid interest level"
                )
                return None

        if (
            self.args.snaffler_interest_level is not None
            and interest_value is not None
            and interest_value < self.args.snaffler_interest_level
        ):
            return None

        match_length: Optional[int] = None
        if match_length_raw is not None:
            try:
                match_length = int(match_length_raw)
            except (TypeError, ValueError):
                match_length = None

        match_md5 = str(match_md5_raw) if match_md5_raw is not None else None

        return SnafflerRule(
            rule_name=str(rule_name),
            description=str(description or ""),
            scope=scope_str,
            action=action_str,
            triage=str(triage or "Unknown"),
            match_location=location_str,
            word_list_type=list_type_str,
            word_list=word_list,
            compiled_patterns=compiled_patterns,
            relay_targets=relay_targets,
            match_length=match_length,
            match_md5=match_md5,
            interest_level=interest_value,
            source_file=source_file,
        )

    def _initialize_snaffler_rules(self) -> None:
        """Load, normalize, and index Snaffler TOML rules."""
        rules_dir = self.args.snaffler_rules_dir
        if not rules_dir:
            self.snaffler_enabled = False
            return

        if tomllib is None:
            self._handle_snaffler_rule_error(
                "Snaffler mode requires tomllib (Python 3.11+) or tomli"
            )
            self.snaffler_enabled = False
            return

        base_path = Path(rules_dir)
        if not base_path.exists() or not base_path.is_dir():
            self._handle_snaffler_rule_error(
                f"Snaffler rules directory is invalid: {rules_dir}"
            )
            self.snaffler_enabled = False
            return

        loaded_rules: List[SnafflerRule] = []
        for file_path in sorted(base_path.rglob("*.toml")):
            try:
                with file_path.open("rb") as handle:
                    parsed_toml = tomllib.load(handle)
            except Exception as exc:
                self._handle_snaffler_rule_error(
                    f"Failed to parse TOML file {file_path}: {exc}"
                )
                continue

            if not isinstance(parsed_toml, dict):
                self._handle_snaffler_rule_error(
                    f"Skipping {file_path}: TOML root is not a table"
                )
                continue

            classifier_rules = parsed_toml.get("ClassifierRules")
            if classifier_rules is None:
                continue
            if not isinstance(classifier_rules, list):
                self._handle_snaffler_rule_error(
                    f"Skipping {file_path}: ClassifierRules is not a list"
                )
                continue

            for raw_rule in classifier_rules:
                if not isinstance(raw_rule, dict):
                    self._handle_snaffler_rule_error(
                        f"Skipping invalid ClassifierRules entry in {file_path}"
                    )
                    continue

                normalized = self._normalize_snaffler_rule(raw_rule, str(file_path))
                if normalized is not None:
                    loaded_rules.append(normalized)

        self.snaffler_rules = []
        self.snaffler_rules_by_scope = defaultdict(list)
        self.snaffler_rule_lookup = {}

        for rule in loaded_rules:
            if rule.rule_name in self.snaffler_rule_lookup:
                self._handle_snaffler_rule_error(
                    f"Duplicate rule name '{rule.rule_name}' found; skipping duplicate"
                )
                continue

            self.snaffler_rule_lookup[rule.rule_name] = rule
            self.snaffler_rules_by_scope[rule.scope].append(rule)
            self.snaffler_rules.append(rule)

        self.snaffler_enabled = bool(self.snaffler_rules)
        if self.snaffler_enabled:
            logging.info(
                f"Loaded {len(self.snaffler_rules)} Snaffler rules from {rules_dir}"
            )
        else:
            logging.warning("No valid Snaffler rules loaded")

    def _snaffler_value_for_location(
        self,
        match_location: str,
        context: Dict[str, Any],
        content_text: Optional[str] = None,
    ) -> str:
        """Get a matchable value from context for a given location."""
        if match_location == "ShareName":
            return str(context.get("share_name", ""))
        if match_location == "FilePath":
            return str(context.get("remote_path", ""))
        if match_location == "FileName":
            return str(context.get("file_name", ""))
        if match_location == "FileExtension":
            return str(context.get("file_extension", ""))
        if match_location == "FileContentAsString":
            return content_text or ""
        if match_location == "FileLength":
            return str(context.get("size_bytes", ""))
        return ""

    def _snaffler_match_rule(
        self,
        rule: SnafflerRule,
        context: Dict[str, Any],
        content_text: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Evaluate a Snaffler rule against context/content."""
        if rule.match_location == "FileContentAsString" and content_text is None:
            return False, ""

        value = self._snaffler_value_for_location(
            rule.match_location,
            context,
            content_text,
        )
        if not value:
            return False, ""

        for pattern in rule.compiled_patterns:
            match = pattern.search(value)
            if match:
                return True, match.group(0)

        return False, ""

    def _read_remote_file_text(
        self,
        smbclient: Any,
        share: str,
        remote_path: str,
        cache_key: str,
        estimated_size: int,
    ) -> Optional[str]:
        """Read and decode remote file content for Snaffler content matching."""
        with self._state_lock:
            if (
                self.args.max_content_reads is not None
                and self.content_reads >= self.args.max_content_reads
            ):
                return None
            if (
                self.args.content_read_budget is not None
                and self.content_read_bytes + estimated_size
                > self.args.content_read_budget
            ):
                return None
            self.content_reads += 1
            self.content_read_bytes += estimated_size

        started = time.perf_counter()
        try:
            buffer = io.BytesIO()
            smbclient.getFile(share, remote_path, buffer.write)
            data = buffer.getvalue()
        except Exception as exc:
            self._record_operation("content_read", time.perf_counter() - started)
            logging.debug(f"Failed to read file content for Snaffler: {exc}")
            return None
        self._record_operation(
            "content_read", time.perf_counter() - started, len(data)
        )
        with self._state_lock:
            self._prefetched_content[cache_key] = data

        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("latin-1", errors="ignore")

    def _record_snaffler_match(
        self,
        context: Dict[str, Any],
        rule: SnafflerRule,
        matched_string: str,
    ) -> None:
        """Record a Snaffler match for CSV/JSON/reporting output."""
        match_row = {
            "host": context.get("host", ""),
            "share_name": context.get("share_name", ""),
            "remote_path": context.get("remote_path", ""),
            "unc_path": context.get("unc_path", ""),
            "rule_name": rule.rule_name,
            "triage": rule.triage,
            "scope": rule.scope,
            "match_location": rule.match_location,
            "matched_string": matched_string,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
        with self._state_lock:
            self.snaffler_matches.append(match_row)
            self.snaffler_match_counter[rule.rule_name] += 1
            if context.get("unc_path"):
                self.snaffler_matched_file_keys.add(str(context["unc_path"]))

        host = str(context.get("host", ""))
        share_name = str(context.get("share_name", ""))
        if (
            host
            and share_name
            and host in self.scan_results
            and share_name in self.scan_results[host]["shares"]
        ):
            self.scan_results[host]["shares"][share_name].setdefault(
                "snaffler_matches",
                [],
            )
            self.scan_results[host]["shares"][share_name]["snaffler_matches"].append(
                match_row
            )

    def _evaluate_snaffler_share(
        self,
        target: str,
        share_name: str,
    ) -> Tuple[bool, List[SnafflerRule]]:
        """Evaluate share-level Snaffler rules."""
        if not self.snaffler_enabled:
            return False, []

        context = {
            "host": target,
            "share_name": share_name,
            "remote_path": "",
            "file_name": "",
            "file_extension": "",
            "size_bytes": "",
            "unc_path": f"\\\\{target}\\{share_name}",
        }

        matched_snaffles: List[SnafflerRule] = []
        for rule in self.snaffler_rules_by_scope.get("ShareEnumeration", []):
            matched, _ = self._snaffler_match_rule(rule, context)
            if not matched:
                continue
            if rule.action == "Discard":
                return True, matched_snaffles
            if rule.action == "Snaffle":
                matched_snaffles.append(rule)

        return False, matched_snaffles

    def _evaluate_snaffler_directory(
        self,
        target: str,
        share: str,
        remote_path: str,
    ) -> Tuple[bool, Optional[SnafflerRule]]:
        """Evaluate directory-level Snaffler rules."""
        if not self.snaffler_enabled:
            return False, None

        context = {
            "host": target,
            "share_name": share,
            "remote_path": remote_path,
            "file_name": os.path.basename(remote_path.rstrip("/")),
            "file_extension": "",
            "size_bytes": "",
            "unc_path": f"\\\\{target}\\{share}\\{remote_path.lstrip('/')}",
        }

        for rule in self.snaffler_rules_by_scope.get("DirectoryEnumeration", []):
            matched, _ = self._snaffler_match_rule(rule, context)
            if matched and rule.action == "Discard":
                return True, rule

        return False, None

    def _evaluate_snaffler_file(
        self,
        smbclient: Any,
        share: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Evaluate file/content/post-match Snaffler rules for a file."""
        if not self.snaffler_enabled:
            return {
                "discarded": False,
                "discard_rule": None,
                "candidate_matches": [],
            }

        candidate_matches: List[Tuple[SnafflerRule, str]] = []
        relay_queue: List[str] = []
        pending_content_rules: Set[str] = set()
        if self.args.snaffler_content_mode == "all":
            pending_content_rules = {
                rule.rule_name
                for rule in self.snaffler_rules_by_scope.get(
                    "ContentsEnumeration", []
                )
            }
        post_rules: Set[str] = {
            rule.rule_name for rule in self.snaffler_rules_by_scope.get("PostMatch", [])
        }
        evaluated_content_rules: Set[str] = set()
        visited_relay_rules: Set[str] = set()

        content_loaded = False
        content_text: Optional[str] = None
        size_gate_hit = False

        def get_content_text() -> Optional[str]:
            nonlocal content_loaded, content_text, size_gate_hit
            if content_loaded:
                return content_text

            file_size = int(context.get("size_bytes", 0) or 0)
            if file_size > self.args.snaffler_max_size_to_grep:
                size_gate_hit = True
                content_loaded = True
                return None

            content_loaded = True
            content_text = self._read_remote_file_text(
                smbclient,
                share,
                str(context.get("remote_path", "")),
                str(context.get("unc_path", "")),
                file_size,
            )
            return content_text

        def apply_action(
            rule: SnafflerRule, matched_string: str
        ) -> Optional[SnafflerRule]:
            if rule.action == "Discard":
                return rule
            if rule.action == "Snaffle":
                candidate_matches.append((rule, matched_string))
            if rule.action == "Relay":
                relay_queue.extend(rule.relay_targets)
            return None

        for rule in self.snaffler_rules_by_scope.get("FileEnumeration", []):
            matched, matched_string = self._snaffler_match_rule(rule, context)
            if not matched:
                continue
            discarded = apply_action(rule, matched_string)
            if discarded is not None:
                return {
                    "discarded": True,
                    "discard_rule": discarded,
                    "candidate_matches": [],
                }

        while True:
            queue_progress = False

            while relay_queue:
                relay_name = relay_queue.pop(0)
                if relay_name in visited_relay_rules:
                    continue
                visited_relay_rules.add(relay_name)
                queue_progress = True

                relay_rule = self.snaffler_rule_lookup.get(relay_name)
                if relay_rule is None:
                    logging.debug(f"Unknown relay target referenced: {relay_name}")
                    continue

                if relay_rule.scope == "FileEnumeration":
                    matched, matched_string = self._snaffler_match_rule(
                        relay_rule, context
                    )
                    if not matched:
                        continue
                    discarded = apply_action(relay_rule, matched_string)
                    if discarded is not None:
                        return {
                            "discarded": True,
                            "discard_rule": discarded,
                            "candidate_matches": [],
                        }
                elif relay_rule.scope == "ContentsEnumeration":
                    pending_content_rules.add(relay_rule.rule_name)
                elif relay_rule.scope == "PostMatch":
                    post_rules.add(relay_rule.rule_name)

            content_rules_to_run = pending_content_rules - evaluated_content_rules
            content_progress = bool(content_rules_to_run)
            if content_rules_to_run:
                content = get_content_text()
                if content is None:
                    evaluated_content_rules.update(content_rules_to_run)
                else:
                    for rule_name in sorted(content_rules_to_run):
                        content_rule = self.snaffler_rule_lookup.get(rule_name)
                        if content_rule is None:
                            continue
                        matched, matched_string = self._snaffler_match_rule(
                            content_rule,
                            context,
                            content,
                        )
                        if not matched:
                            continue
                        discarded = apply_action(content_rule, matched_string)
                        if discarded is not None:
                            return {
                                "discarded": True,
                                "discard_rule": discarded,
                                "candidate_matches": [],
                            }
                    evaluated_content_rules.update(content_rules_to_run)

            if not queue_progress and not content_progress:
                break

        if candidate_matches:
            post_rule_list = [
                self.snaffler_rule_lookup[name]
                for name in sorted(post_rules)
                if name in self.snaffler_rule_lookup
            ]
            for post_rule in post_rule_list:
                post_content: Optional[str] = None
                if post_rule.match_location == "FileContentAsString":
                    post_content = get_content_text()
                    if post_content is None:
                        continue
                matched, _ = self._snaffler_match_rule(
                    post_rule,
                    context,
                    post_content,
                )
                if matched and post_rule.action == "Discard":
                    return {
                        "discarded": True,
                        "discard_rule": post_rule,
                        "candidate_matches": [],
                    }

        if size_gate_hit:
            logging.debug(
                f"Skipped content matching for {context.get('unc_path')} due to size gate"
            )

        return {
            "discarded": False,
            "discard_rule": None,
            "candidate_matches": candidate_matches,
        }

    def _snaffler_console_marker(
        self,
        candidate_matches: List[Tuple[SnafflerRule, str]],
    ) -> str:
        """Build a concise console marker for Snaffler matches."""
        if not candidate_matches:
            return ""
        rule, _ = candidate_matches[0]
        return (
            f" {Fore.YELLOW}[SNAFFLER: {rule.rule_name}/{rule.triage}]{Style.RESET_ALL}"
        )

    def _display_snaffler_summary(self) -> None:
        """Print end-of-run summary for Snaffler matches."""
        if not self.snaffler_enabled:
            return

        total_matches = len(self.snaffler_matches)
        unique_files = len(self.snaffler_matched_file_keys)
        logging.info(f"Snaffler matches: {total_matches}")
        logging.info(f"Snaffler unique matched files: {unique_files}")

        if self.snaffler_match_counter:
            top_rules = self.snaffler_match_counter.most_common(5)
            formatted = ", ".join([f"{name} ({count})" for name, count in top_rules])
            logging.info(f"Snaffler top matched rules: {formatted}")



