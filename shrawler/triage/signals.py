"""Snapshot-backed directory rarity and analyst feedback for offline ranking."""

from collections import OrderedDict
from contextlib import closing
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .storage import connect_readonly

# (host, share, parent, extension) pending counts staged in Python between
# flushes; avoids one upsert statement per observed file.
_PendingKey = Tuple[str, str, str, str]


class InventorySignals:
    def __init__(
        self,
        db: Any,
        database: Path,
        rarity: List[Dict[str, Any]],
        engine: Any = None,
    ) -> None:
        self.db = db
        self.engine = engine
        self.rarity = list(rarity or [])
        self._directories = [
            config
            for config in self.rarity
            if config.get("scope", "directory") == "directory"
        ]
        self._environments = [
            config
            for config in self.rarity
            if config.get("scope", "directory") == "environment"
        ]
        self._has_when = any("when" in config for config in self.rarity)
        self._directory_cache = OrderedDict()
        self._pending: Dict[_PendingKey, int] = {}
        self._env_pending: Dict[str, int] = {}
        self._env_total = 0
        self._file_reviews = {}
        self._family_reviews = {}
        db.executescript("""
            CREATE TEMP TABLE IF NOT EXISTS directory_extensions (
                host TEXT,share TEXT,parent TEXT,extension TEXT,n INTEGER,
                PRIMARY KEY(host,share,parent,extension));
            DELETE FROM directory_extensions;
            CREATE TEMP TABLE IF NOT EXISTS environment_filenames (
                filename TEXT PRIMARY KEY,n INTEGER) WITHOUT ROWID;
            DELETE FROM environment_filenames;
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
        if self._directories:
            key = self.key(metadata)
            self._pending[key] = self._pending.get(key, 0) + 1
        if self._environments:
            name = metadata["file_name"].casefold()
            self._env_pending[name] = self._env_pending.get(name, 0) + 1
            self._env_total += 1

    def flush(self) -> None:
        """Persist staged counts; pending counts always overlay query results.

        The staged value is the number of files observed for this key since the
        last flush, so an existing row must accumulate the whole value. Using
        ``n=n+1`` silently undercounts whenever a key spans a flush boundary
        (large directories, or repeated flush calls).
        """
        if self._pending:
            self.db.executemany(
                """INSERT INTO directory_extensions VALUES (?,?,?,?,?)
                ON CONFLICT(host,share,parent,extension) DO UPDATE SET n=n+excluded.n""",
                [(*key, value) for key, value in self._pending.items()],
            )
            self._pending.clear()
        if self._env_pending:
            self.db.executemany(
                """INSERT INTO environment_filenames VALUES (?,?)
                ON CONFLICT(filename) DO UPDATE SET n=n+excluded.n""",
                self._env_pending.items(),
            )
            self._env_pending.clear()

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

    def _environment_occurrences(self, metadata: Dict[str, Any]) -> int:
        name = metadata["file_name"].casefold()
        row = self.db.execute(
            "SELECT n FROM environment_filenames WHERE filename=?", (name,)
        ).fetchone()
        return int(row[0]) if row else 0

    def _when_ok(self, config: Dict[str, Any], when_results: Dict[str, bool]) -> bool:
        if "when" not in config:
            return True
        return bool(when_results.get(config["id"], False))

    @staticmethod
    def _record(
        result: Dict[str, Any],
        config: Dict[str, Any],
        evidence: Dict[str, Any],
    ) -> None:
        result["signals"].append(
            {
                "rule_id": config["id"],
                "category": config["category"],
                "signal_group": config["signal_group"],
                "description": config["description"],
                "points": config["points"],
                "credited_points": config["points"],
                "evidence": evidence,
            }
        )

    def apply(self, metadata: Dict[str, Any], result: Dict[str, Any]) -> None:
        from .review import family_key

        if self.rarity:
            when_results = (
                self.engine.rarity_conditions(metadata, result.get("contexts"))
                if self._has_when and self.engine is not None
                else {}
            )
            if self._directories:
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
                total, dominant = counts[None]  # type: ignore[index]
                matching = counts.get(key[3], 0)
                for config in self._directories:
                    if total < config["minimum_directory_files"]:
                        continue
                    if matching > total * config["maximum_same_extension_ratio"]:
                        continue
                    if dominant < total * config["minimum_dominant_extension_ratio"]:
                        continue
                    if not self._when_ok(config, when_results):
                        continue
                    self._record(
                        result,
                        config,
                        {
                            "observed_files": total,
                            "same_extension": matching,
                            "dominant_extension_files": dominant,
                            "extension": key[3],
                            "scope": "observed files only",
                        },
                    )
            if self._environments:
                occurrences = self._environment_occurrences(metadata)
                for config in self._environments:
                    if self._env_total < config.get("minimum_environment_files", 0):
                        continue
                    if occurrences > config["maximum_occurrences"]:
                        continue
                    if not self._when_ok(config, when_results):
                        continue
                    self._record(
                        result,
                        config,
                        {
                            "filename": metadata["file_name"],
                            "occurrences": occurrences,
                            "environment_files": self._env_total,
                            "scope": "environment",
                        },
                    )
            # Recompute at category/signal-group granularity so a rarity
            # population signal cannot add to a rule that already occupies the
            # same group (for example builtin.operational-executable and
            # builtin.stray-executable). Within a group only the highest weight
            # contributes, exactly like Engine.evaluate; category scores are the
            # sum of their independent group maxima.
            groups: Dict[Tuple[str, str], int] = {}
            for signal in result["signals"]:
                key = (signal["category"], signal["signal_group"])
                groups[key] = max(groups.get(key, 0), signal["points"])
            scores: Dict[str, int] = {}
            for (category, _group), points in groups.items():
                scores[category] = scores.get(category, 0) + points
            result["category_scores"] = scores
            result["priority"] = max(scores.values(), default=0)
            credited: Dict[Tuple[str, str], str] = {}
            for signal in sorted(
                result["signals"],
                key=lambda item: (-item["points"], item["rule_id"]),
            ):
                key = (signal["category"], signal["signal_group"])
                if key in credited:
                    signal["credited_points"] = 0
                    signal["capped_by_rule"] = credited[key]
                else:
                    signal["credited_points"] = signal["points"]
                    credited[key] = signal["rule_id"]
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
