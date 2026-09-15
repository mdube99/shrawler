"""Disk-backed, bounded witnesses for positive sibling context inference."""

import re
import sqlite3
from collections import OrderedDict
from fnmatch import translate
from typing import Any, Dict, List, Tuple

from .engine import segments
from .rules import RuleSet

# Rows are staged in Python while observing and only reach the TEMP table on
# flush(); this halts the per-row INSERT + COUNT(*) WAL/temp churn of the old
# implementation. The DB stays the authoritative, bounded backing store.
_FLUSH_THRESHOLD = 25_000


class SiblingIndex:
    def __init__(self, connection: sqlite3.Connection, rules: RuleSet) -> None:
        self.connection = connection
        self.contexts = [
            context
            for context in rules.document.get("contexts", [])
            if "sibling_name_any" in context
        ]
        # (host, share, parent, context_id, pattern_index) -> {identity: (file_id, name)}
        self._pending: Dict[Tuple[str, str, str, str, int], Dict[str, Tuple[str, str]]] = {}
        self._cache: OrderedDict[Tuple[str, str, Tuple[str, ...], str], List[Dict[str, Any]]] = (
            OrderedDict()
        )
        # Precompiled matchers keyed by context id; avoids casefold + fnmatch per pattern per file.
        self._matchers: Dict[Tuple[str, int], re.Pattern] = {}
        for context in self.contexts:
            for index, pattern in enumerate(context["sibling_name_any"]):
                self._matchers[(context["id"], index)] = re.compile(
                    translate(pattern.casefold())
                )
        connection.execute("PRAGMA temp_store=FILE")
        connection.execute("""CREATE TEMP TABLE sibling_markers (
            host TEXT, share TEXT, parent TEXT, context_id TEXT, pattern INTEGER,
            file_id TEXT, file_name TEXT,
            PRIMARY KEY(host, share, parent, context_id, pattern, file_id)
        ) WITHOUT ROWID""")

    def _prefixed(self, metadata: Dict[str, Any]) -> Tuple[str, str, str]:
        return (
            metadata["host"].casefold(),
            metadata["share"].casefold(),
            "/"
            + "/".join(
                part.casefold() for part in segments(metadata["remote_path"])[:-1]
            ),
        )

    def observe(self, metadata: Dict[str, Any]) -> None:
        folded = metadata["file_name"].casefold()
        prefix = self._prefixed(metadata)
        for context in self.contexts:
            for index, _pattern in enumerate(context["sibling_name_any"]):
                if self._matchers[(context["id"], index)].match(folded) is None:
                    continue
                # K witnesses per pattern suffice to find a matching of size K.
                # A wildcard cannot grow a single directory's evidence without bound.
                binding = (context["id"], index)
                key = (*prefix, *binding)
                witnesses = self._pending.get(key)
                if witnesses is None:
                    if len(self._pending) >= _FLUSH_THRESHOLD:
                        self.flush()
                    witnesses = {}
                    self._pending[key] = witnesses
                cap = context["minimum_distinct_patterns"]
                if len(witnesses) >= cap or folded in witnesses:
                    continue
                witnesses[folded] = (metadata["file_id"], metadata["file_name"])
                if len(witnesses) == cap:
                    self.flush_key(key, witnesses)

    def flush_key(self, key: Tuple[str, str, str, str, int], witnesses: Dict[str, Tuple[str, str]]) -> None:
        self.connection.executemany(
            "INSERT OR IGNORE INTO sibling_markers VALUES (?,?,?,?,?,?,?)",
            [(*key, file_id, name) for _identity, (file_id, name) in witnesses.items()],
        )
        self._pending.pop(key, None)

    def flush(self) -> None:
        if not self._pending:
            return
        rows = []
        for key, witnesses in self._pending.items():
            rows.extend(
                (*key, file_id, name)
                for _identity, (file_id, name) in witnesses.items()
            )
        if rows:
            self.connection.executemany(
                "INSERT OR IGNORE INTO sibling_markers VALUES (?,?,?,?,?,?,?)", rows
            )
        self._pending.clear()

    def lookup(
        self, host: str, share: str, parent: Tuple[str, ...], context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        key = (host.casefold(), share.casefold(), parent, context["id"])
        cached = self._cache.get(key)
        if cached is not None:
            self._cache.move_to_end(key)
            return cached
        rows = self.connection.execute(
            "SELECT pattern,file_id,file_name FROM sibling_markers "
            "WHERE host=? AND share=? AND parent=? AND context_id=? ORDER BY pattern,file_id",
            (
                key[0],
                key[1],
                "/" + "/".join(p.casefold() for p in parent),
                context["id"],
            ),
        )
        candidates: Dict[int, List[str]] = {}
        names: Dict[str, str] = {}
        for index, _file_id, name in rows:
            # Case aliases of the same SMB filename count as one witness.
            identity = name.casefold()
            candidates.setdefault(index, []).append(identity)
            names[identity] = name
        assignments: Dict[str, int] = {}

        def assign(pattern: int, seen: set) -> bool:
            for identity in candidates.get(pattern, []):
                if identity in seen:
                    continue
                seen.add(identity)
                if identity not in assignments or assign(assignments[identity], seen):
                    assignments[identity] = pattern
                    return True
            return False

        evidence: List[Dict[str, Any]] = []
        for index in candidates:
            assign(index, set())
            if len(assignments) >= context["minimum_distinct_patterns"]:
                evidence = [
                    {
                        "pattern": context["sibling_name_any"][pattern],
                        "file_name": names[identity],
                    }
                    for identity, pattern in sorted(assignments.items())
                ]
                break
        self._cache[key] = evidence
        if len(self._cache) > 4096:
            self._cache.popitem(last=False)
        return evidence
