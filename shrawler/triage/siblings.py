"""Disk-backed, bounded witnesses for positive sibling context inference."""

import sqlite3
from fnmatch import fnmatchcase
from typing import Any, Dict, List, Set, Tuple

from .engine import segments
from .rules import RuleSet


class SiblingIndex:
    def __init__(self, connection: sqlite3.Connection, rules: RuleSet) -> None:
        self.connection = connection
        self.contexts = [
            context
            for context in rules.document.get("contexts", [])
            if "sibling_name_any" in context
        ]
        self._cache: Dict[
            Tuple[str, str, Tuple[str, ...], str], List[Dict[str, Any]]
        ] = {}
        connection.execute("PRAGMA temp_store=FILE")
        connection.execute("""CREATE TEMP TABLE sibling_markers (
            host TEXT, share TEXT, parent TEXT, context_id TEXT, pattern INTEGER,
            file_id TEXT, file_name TEXT,
            PRIMARY KEY(host, share, parent, context_id, pattern, file_id)
        ) WITHOUT ROWID""")

    def observe(self, metadata: Dict[str, Any]) -> None:
        prefix = (
            metadata["host"].casefold(),
            metadata["share"].casefold(),
            "/"
            + "/".join(
                part.casefold() for part in segments(metadata["remote_path"])[:-1]
            ),
        )
        for context in self.contexts:
            for index, pattern in enumerate(context["sibling_name_any"]):
                if not fnmatchcase(
                    metadata["file_name"].casefold(), pattern.casefold()
                ):
                    continue
                # K witnesses per pattern suffice to find a matching of size K.
                # A wildcard cannot grow a single directory's evidence without bound.
                key = (*prefix, context["id"], index)
                self.connection.execute(
                    "INSERT OR IGNORE INTO sibling_markers SELECT ?,?,?,?,?,?,? "
                    "WHERE (SELECT COUNT(*) FROM sibling_markers WHERE host=? AND share=? AND parent=? AND context_id=? AND pattern=?) < ?",
                    (
                        *key,
                        metadata["file_name"].casefold(),
                        metadata["file_name"],
                        *key,
                        context["minimum_distinct_patterns"],
                    ),
                )

    def lookup(
        self, host: str, share: str, parent: Tuple[str, ...], context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        key = (host.casefold(), share.casefold(), parent, context["id"])
        if key in self._cache:
            return self._cache[key]
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

        def assign(pattern: int, seen: Set[str]) -> bool:
            for identity in candidates.get(pattern, []):
                if identity in seen:
                    continue
                seen.add(identity)
                if identity not in assignments or assign(assignments[identity], seen):
                    assignments[identity] = pattern
                    return True
            return False

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
                self._cache[key] = evidence
                return evidence
        self._cache[key] = []
        return []
