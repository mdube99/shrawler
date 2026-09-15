"""Snapshot-backed directory rarity and analyst feedback for offline ranking."""

from collections import OrderedDict
from contextlib import closing
from pathlib import Path
from typing import Any, Dict, Tuple

from .storage import connect_readonly

# (host, share, parent, extension) pending counts staged in Python between
# flushes; avoids one upsert statement per observed file.
_PendingKey = Tuple[str, str, str, str]


class InventorySignals:
    def __init__(self, db: Any, database: Path, builtins: bool):
        self.db = db
        self.builtins = builtins
        self._directory_cache = OrderedDict()
        self._pending: Dict[_PendingKey, int] = {}
        self._file_reviews = {}
        self._family_reviews = {}
        db.executescript("""
            CREATE TEMP TABLE IF NOT EXISTS directory_extensions (
                host TEXT,share TEXT,parent TEXT,extension TEXT,n INTEGER,
                PRIMARY KEY(host,share,parent,extension));
            DELETE FROM directory_extensions;
        """)
        review = database.with_name(database.stem + ".review.db")
        if review.exists():
            with closing(connect_readonly(review)) as source:
                rows = source.execute("""SELECT * FROM review_events WHERE id IN
                    (SELECT MAX(id) FROM review_events WHERE undone=0 GROUP BY scope,target)""")
                for row in rows:
                    event = dict(row)
                    destination = (
                        self._file_reviews
                        if row["scope"] == "file"
                        else self._family_reviews
                    )
                    destination[row["target"]] = event

    @staticmethod
    def key(metadata: Dict[str, Any]):
        path = metadata["remote_path"].replace("\\", "/").casefold()
        name = metadata["file_name"].casefold()
        return (
            metadata["host"].casefold(),
            metadata["share"].casefold(),
            path.rsplit("/", 1)[0],
            "." + name.rsplit(".", 1)[1] if "." in name else "",
        )

    def observe(self, metadata: Dict[str, Any]) -> None:
        if self.builtins:
            key = self.key(metadata)
            self._pending[key] = self._pending.get(key, 0) + 1

    def flush(self) -> None:
        """Persist staged counts; pending counts always overlay query results."""
        if not self._pending:
            return
        self.db.executemany(
            """INSERT INTO directory_extensions VALUES (?,?,?,?,?)
            ON CONFLICT(host,share,parent,extension) DO UPDATE SET n=n+1""",
            [(*key, value) for key, value in self._pending.items()],
        )
        self._pending.clear()

    def _directory_counts(self, directory: Tuple[str, str, str]) -> Dict[str, int]:
        rows = self.db.execute(
            "SELECT extension,n FROM directory_extensions WHERE host=? AND share=? AND parent=?",
            directory,
        ).fetchall()
        counts = {row[0]: row[1] for row in rows}
        for (host, share, parent, extension), n in self._pending.items():
            if (host, share, parent) == directory:
                counts[extension] = counts.get(extension, 0) + n
        counts[None] = (
            sum(counts.values()),
            max(counts.values(), default=0),
        )
        return counts

    def apply(self, metadata: Dict[str, Any], result: Dict[str, Any]) -> None:
        from .review import family_key

        if self.builtins:
            key = self.key(metadata)
            directory = key[:3]
            counts = self._directory_cache.get(directory)
            if counts is None:
                counts = self._directory_counts(directory)
                self._directory_cache[directory] = counts
                if len(self._directory_cache) > 4096:
                    self._directory_cache.popitem(last=False)
            else:
                self._directory_cache.move_to_end(directory)
            total, dominant = counts[None]
            matching = counts.get(key[3], 0)
            if total >= 20 and matching * 20 <= total and dominant * 5 >= total * 4:
                result["signals"].append(
                    {
                        "rule_id": "builtin.rare-extension",
                        "category": "unusual-files",
                        "signal_group": "directory-rarity",
                        "description": "Uncommon extension in a repetitive observed directory",
                        "points": 10,
                        "credited_points": 10,
                        "evidence": {
                            "observed_files": total,
                            "same_extension": matching,
                            "dominant_extension_files": dominant,
                            "extension": key[3],
                            "scope": "observed files only",
                        },
                    }
                )
                result["category_scores"]["unusual-files"] = 10
                result["priority"] = max(result["priority"], 10)
        family = family_key(metadata)
        result["family_id"] = family
        # An explicit file decision overrides a family decision. Undo exposes
        # the prior active decision; snapshots keep old rankings reproducible.
        event = self._file_reviews.get(metadata["file_id"])
        if event is None:
            event = self._family_reviews.get(family)
        result["review"] = event
        if event:
            result["unreviewed_priority"] = result["priority"]
            disposition = event["disposition"]
            if disposition == "relevant":
                result["category_scores"]["analyst-review"] = 100
                result["priority"] = max(100, result["priority"])
            else:
                result["unreviewed_category_scores"] = result["category_scores"].copy()
                result["category_scores"] = dict.fromkeys(result["category_scores"], 0)
                result["priority"] = 0
            result["signals"].append(
                {
                    "rule_id": "analyst.review",
                    "category": "analyst-review",
                    "signal_group": "review",
                    "description": "Analyst disposition: " + disposition,
                    "points": 100 if disposition == "relevant" else 0,
                    "credited_points": 100 if disposition == "relevant" else 0,
                    "evidence": event,
                }
            )
