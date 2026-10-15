"""Transactionally maintained substring index over the normalized catalog.

A catalog file is stored as a directory row plus a name, so the old per-file
trigram index over ``host share remote_path unc_path file_name extension`` is
replaced by two much smaller trigram indexes: one row per directory and one
row per file *name*. A search term ``t`` (it never contains whitespace) is a
substring of a file's legacy ``search_text`` exactly when one of these holds:

1. ``t`` is inside the directory's text: host, share, directory path (the
   remote path up to and including its last ``/``) or UNC directory prefix.
   That is a property of the directory, so every file in it matches.
2. ``t`` is inside the file name.
3. ``t`` is inside the extension.
4. ``t`` crosses the boundary between the directory part and the name, in the
   remote path or the UNC path. The boundary is a ``/`` (or the ``\\`` after the
   share for files at the root), so ``t`` splits at one of its separator
   characters into a suffix of the directory part and a prefix of the name.

``plan_term`` resolves classes 1, 3 and the directory half of 4 to exact id
lists and probes the name index for class 2. ``predicate`` turns a plan back
into an exact SQL test, so no row is accepted on trigram evidence alone.
"""

import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any, List, Optional, Set, Tuple

# Upper bound on name-index candidates per term. Broader terms page through a
# sort index and test the exact predicate instead of materializing every id.
CANDIDATE_LIMIT = 50_000
NAMES = "catalog_files_search"
DIRS = "catalog_dirs_search"
_SEPARATORS = "/\\"


def available(connection: sqlite3.Connection) -> bool:
    return (
        connection.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN (?, ?)",
            (NAMES, DIRS),
        ).fetchone()[0]
        == 2
    )


def supported() -> bool:
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute(
            "CREATE VIRTUAL TABLE probe USING fts5(text, tokenize='trigram', detail='none')"
        )
        return True
    except sqlite3.OperationalError:
        return False
    finally:
        connection.close()


def ensure(connection: sqlite3.Connection) -> None:
    """Backfill and publish both indexes and their triggers in one transaction.

    ``detail=none`` stores no positions and ``columnsize=0`` drops the per-row
    size table; neither is needed because every candidate is rechecked.
    """
    connection.execute("SAVEPOINT search_index")
    try:
        if not available(connection):
            for table in (NAMES, DIRS):
                connection.execute(f"DROP TABLE IF EXISTS {table}")
            connection.execute(
                f"CREATE VIRTUAL TABLE {NAMES} USING fts5("
                "name, content='catalog_files', content_rowid='id', "
                "tokenize='trigram', detail='none', columnsize=0)"
            )
            connection.execute(
                f"CREATE VIRTUAL TABLE {DIRS} USING fts5("
                "search_text, content='catalog_dirs', content_rowid='id', "
                "tokenize='trigram', detail='none', columnsize=0)"
            )
            # One statement at a time: executescript would commit the savepoint.
            for trigger in (
                f"CREATE TRIGGER IF NOT EXISTS {NAMES}_insert AFTER INSERT ON catalog_files BEGIN "
                f"INSERT INTO {NAMES}(rowid, name) VALUES (new.id, new.name); END",
                f"CREATE TRIGGER IF NOT EXISTS {NAMES}_delete AFTER DELETE ON catalog_files BEGIN "
                f"INSERT INTO {NAMES}({NAMES}, rowid, name) VALUES ('delete', old.id, old.name); END",
                f"CREATE TRIGGER IF NOT EXISTS {NAMES}_update AFTER UPDATE OF name ON catalog_files "
                f"BEGIN INSERT INTO {NAMES}({NAMES}, rowid, name) VALUES ('delete', old.id, old.name); "
                f"INSERT INTO {NAMES}(rowid, name) VALUES (new.id, new.name); END",
                f"CREATE TRIGGER IF NOT EXISTS {DIRS}_insert AFTER INSERT ON catalog_dirs BEGIN "
                f"INSERT INTO {DIRS}(rowid, search_text) VALUES (new.id, new.search_text); END",
                f"CREATE TRIGGER IF NOT EXISTS {DIRS}_delete AFTER DELETE ON catalog_dirs BEGIN "
                f"INSERT INTO {DIRS}({DIRS}, rowid, search_text) "
                "VALUES ('delete', old.id, old.search_text); END",
                # search_text is generated, so watch the columns it is built from.
                f"CREATE TRIGGER IF NOT EXISTS {DIRS}_update AFTER UPDATE OF host, share, path "
                f"ON catalog_dirs BEGIN INSERT INTO {DIRS}({DIRS}, rowid, search_text) "
                "VALUES ('delete', old.id, old.search_text); "
                f"INSERT INTO {DIRS}(rowid, search_text) VALUES (new.id, new.search_text); END",
            ):
                connection.execute(trigger)
            connection.execute(f"INSERT INTO {NAMES}({NAMES}) VALUES ('rebuild')")
            connection.execute(f"INSERT INTO {DIRS}({DIRS}) VALUES ('rebuild')")
        connection.execute("RELEASE search_index")
    except BaseException:
        connection.execute("ROLLBACK TO search_index")
        connection.execute("RELEASE search_index")
        raise


def optimize(connection: sqlite3.Connection) -> None:
    """Merge incrementally written segments into one packed b-tree each."""
    if available(connection):
        for table in (NAMES, DIRS):
            connection.execute(f"INSERT INTO {table}({table}) VALUES ('optimize')")


def like_contains(term: str) -> str:
    return "%" + _escape(term) + "%"


def _escape(term: str) -> str:
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _match(text: str) -> Optional[str]:
    """FTS5 AND-query of the text's trigrams, or None when it has none."""
    grams = dict.fromkeys(text[offset : offset + 3] for offset in range(len(text) - 2))
    if not grams:
        return None
    # Quote every token so punctuation, quotes and FTS operators stay literal.
    # A subset remains a safe superset of matches; bound parser work for long
    # pasted paths rather than constructing an arbitrarily large expression.
    return " AND ".join(
        '"' + gram.replace('"', '""') + '"' for gram in list(grams)[:128]
    )


def _int_list() -> List[int]:
    return []


def _span_list() -> List[Tuple[str, str]]:
    return []


@dataclass
class TermPlan:
    """Exact description of the files whose search text contains one term."""

    term: str
    dir_ids: List[int] = field(default_factory=_int_list)
    ext_ids: List[int] = field(default_factory=_int_list)
    # (LIKE pattern for "directory part ends with the head", LIKE pattern
    # for "name starts with the tail")
    spans: List[Tuple[str, str]] = field(default_factory=_span_list)
    # Superset of the name and span matches (trigram index, span lookups);
    # None when unbounded.
    name_ids: Optional[List[int]] = None
    # Upper bound on matching files; None when the term is too broad to list.
    estimate: Optional[int] = None


_DIR_SELECT = "SELECT id, file_count FROM catalog_dirs"


def _dirs_containing(
    connection: sqlite3.Connection, text: str, indexed: bool
) -> List[Tuple[int, int]]:
    match = _match(text) if indexed else None
    if match is None:
        return connection.execute(
            _DIR_SELECT + " WHERE search_text LIKE ? ESCAPE '\\'",
            (like_contains(text),),
        ).fetchall()
    return connection.execute(
        _DIR_SELECT + f" WHERE id IN (SELECT rowid FROM {DIRS} WHERE {DIRS} MATCH ?) "
        "AND search_text LIKE ? ESCAPE '\\'",
        (match, like_contains(text)),
    ).fetchall()


# True when catalog_dirs row ``{d}`` has a directory path or UNC directory
# prefix ending with the bound pattern (used twice).
_ENDS_SQL = (
    "({d}.path LIKE ? ESCAPE '\\' OR "
    "('\\\\' || {d}.host || '\\' || {d}.share || '\\' || ltrim({d}.path, '/')) "
    "LIKE ? ESCAPE '\\')"
)
_SPAN_SQL = (
    "({f}.name LIKE ? ESCAPE '\\' AND EXISTS (SELECT 1 FROM catalog_dirs s "
    "WHERE s.id = {f}.dir_id AND " + _ENDS_SQL.format(d="s") + "))"
)


def _span_ids(
    connection: sqlite3.Connection, ends: str, prefix: str, head: str, indexed: bool
) -> Optional[List[int]]:
    """Ids of files matching one span, or None when there are too many.

    Narrow by whichever side is selective: the name prefix (name index) or
    the directories whose path ends with the head (directory index).
    """
    rows = (
        connection.execute(
            "SELECT f.id FROM catalog_files f WHERE "
            + _SPAN_SQL.format(f="f")
            + " LIMIT ?",
            (prefix, ends, ends, CANDIDATE_LIMIT + 1),
        ).fetchall()
        if _prefix_is_narrow(connection, prefix)
        else None
    )
    if rows is not None and len(rows) <= CANDIDATE_LIMIT:
        return [int(row[0]) for row in rows]
    match = _match(head) if indexed else None
    dirs = connection.execute(
        "SELECT d.id, d.file_count FROM catalog_dirs d WHERE "
        + (
            ""
            if match is None
            else f"d.id IN (SELECT rowid FROM {DIRS} WHERE {DIRS} MATCH ?) AND "
        )
        + _ENDS_SQL.format(d="d"),
        ((match,) if match is not None else ()) + (ends, ends),
    ).fetchall()
    if sum(int(count) for _, count in dirs) > CANDIDATE_LIMIT:
        return None
    return [
        int(row[0])
        for row in connection.execute(
            "SELECT id FROM catalog_files WHERE dir_id IN (SELECT value FROM json_each(?)) "
            "AND name LIKE ? ESCAPE '\\'",
            (json.dumps([int(dir_id) for dir_id, _ in dirs]), prefix),
        )
    ]


def _prefix_is_narrow(connection: sqlite3.Connection, prefix: str) -> bool:
    """Whether at most CANDIDATE_LIMIT names start with the prefix (index walk)."""
    return (
        connection.execute(
            "SELECT count(*) FROM (SELECT 1 FROM catalog_files WHERE name LIKE ? ESCAPE '\\' "
            "LIMIT ?)",
            (prefix, CANDIDATE_LIMIT + 1),
        ).fetchone()[0]
        <= CANDIDATE_LIMIT
    )


def plan_term(connection: sqlite3.Connection, term: str) -> TermPlan:
    indexed = available(connection)
    plan = TermPlan(term)
    estimate = 0
    for dir_id, count in _dirs_containing(connection, term, indexed):
        plan.dir_ids.append(int(dir_id))
        estimate += int(count)
    for ext_id, count in connection.execute(
        "SELECT e.id, (SELECT count(*) FROM catalog_files WHERE ext_id = e.id) "
        "FROM catalog_extensions e WHERE e.extension LIKE ? ESCAPE '\\'",
        (like_contains(term),),
    ):
        plan.ext_ids.append(int(ext_id))
        estimate += int(count)
    span_ids: Optional[List[int]] = []
    for offset, character in enumerate(term):
        tail = term[offset + 1 :]
        if character not in _SEPARATORS or not tail:
            continue
        head = term[: offset + 1]
        ends, prefix = "%" + _escape(head), _escape(tail) + "%"
        plan.spans.append((ends, prefix))
        found = _span_ids(connection, ends, prefix, head, indexed)
        if found is None or span_ids is None:
            span_ids = None
        else:
            span_ids.extend(found)
    match = _match(term) if indexed else None
    if match is not None:
        # Collect the ids in SQL: building up to CANDIDATE_LIMIT + 1 row tuples
        # in Python costs about twice the FTS probe itself on broad terms.
        found, ids = connection.execute(
            f"SELECT count(*), json_group_array(rowid) FROM (SELECT rowid FROM {NAMES} "
            f"WHERE {NAMES} MATCH ? LIMIT ?)",
            (match, CANDIDATE_LIMIT + 1),
        ).fetchone()
        if int(found) <= CANDIDATE_LIMIT and span_ids is not None:
            plan.name_ids = json.loads(ids) + span_ids
            plan.estimate = estimate + len(plan.name_ids)
    return plan


def predicate(plan: TermPlan, alias: str = "f") -> Tuple[str, List[Any]]:
    """Exact SQL test for "term is a substring of the file's search text"."""
    parts = [f"{alias}.name LIKE ? ESCAPE '\\'"]
    values: List[Any] = [like_contains(plan.term)]
    if plan.dir_ids:
        parts.append(f"{alias}.dir_id IN (SELECT value FROM json_each(?))")
        values.append(json.dumps(plan.dir_ids))
    if plan.ext_ids:
        parts.append(f"{alias}.ext_id IN (SELECT value FROM json_each(?))")
        values.append(json.dumps(plan.ext_ids))
    for ends, prefix in plan.spans:
        parts.append(_SPAN_SQL.format(f=alias))
        values.extend((prefix, ends, ends))
    return "(" + " OR ".join(parts) + ")", values


CANDIDATE_TABLE = "temp.catalog_search_ids"


def materialize(connection: sqlite3.Connection, plan: TermPlan) -> str:
    """Write the term's candidate ids to a connection-local temp table."""
    connection.execute(
        f"CREATE TABLE IF NOT EXISTS {CANDIDATE_TABLE}(id INTEGER PRIMARY KEY)"
    )
    connection.execute(f"DELETE FROM {CANDIDATE_TABLE}")
    insert = f"INSERT OR IGNORE INTO {CANDIDATE_TABLE}(id) "
    if plan.dir_ids:
        connection.execute(
            insert
            + "SELECT id FROM catalog_files WHERE dir_id IN (SELECT value FROM json_each(?))",
            (json.dumps(plan.dir_ids),),
        )
    if plan.ext_ids:
        connection.execute(
            insert
            + "SELECT id FROM catalog_files WHERE ext_id IN (SELECT value FROM json_each(?))",
            (json.dumps(plan.ext_ids),),
        )
    if plan.name_ids:
        connection.execute(
            insert + "SELECT value FROM json_each(?)", (json.dumps(plan.name_ids),)
        )
    return CANDIDATE_TABLE


def plan_ids(connection: sqlite3.Connection, plan: TermPlan) -> Set[int]:
    """The file ids a term's plan can match (an exact superset)."""
    ids: Set[int] = set()
    if plan.dir_ids:
        for row in connection.execute(
            "SELECT id FROM catalog_files "
            "WHERE dir_id IN (SELECT value FROM json_each(?))",
            (json.dumps(plan.dir_ids),),
        ):
            ids.add(int(row[0]))
    if plan.ext_ids:
        for row in connection.execute(
            "SELECT id FROM catalog_files "
            "WHERE ext_id IN (SELECT value FROM json_each(?))",
            (json.dumps(plan.ext_ids),),
        ):
            ids.add(int(row[0]))
    if plan.name_ids:
        ids.update(int(value) for value in plan.name_ids)
    return ids


def bounded_ids(
    connection: sqlite3.Connection, plans: List[TermPlan]
) -> Optional[Set[int]]:
    """Intersection of per-term candidate sets, or None when any term is broad."""
    combined: Optional[Set[int]] = None
    for plan in plans:
        if plan.estimate is None or plan.estimate > CANDIDATE_LIMIT:
            return None
        ids = plan_ids(connection, plan)
        if len(ids) > CANDIDATE_LIMIT:
            return None
        combined = ids if combined is None else (combined & ids)
        if not combined:
            return set()
    return combined


def candidates(connection: sqlite3.Connection, query: str) -> Optional[List[int]]:
    """Bounded superset of matching file ids for a whole query, or None.

    Each whitespace-separated term must itself be bounded by the per-term
    planner; the result is the intersection of the per-term candidate sets.
    A term with no index support or too many candidates falls back to the
    sort-index walk with the exact LIKE predicates. Candidates are computed
    read-only (no temp table), so this works on ``query_only`` connections.
    """
    terms = [term for term in query.casefold().split() if term]
    if not terms or not available(connection):
        return None
    plans = [plan_term(connection, term) for term in terms]
    ids = bounded_ids(connection, plans)
    if ids is None:
        return None
    return sorted(ids)
