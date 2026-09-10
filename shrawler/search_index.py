"""Optional, transactionally maintained substring index for large inventories."""

import sqlite3
from typing import List, Optional

# Bound both the probe and the subsequent primary-key lookups. Broad queries
# should page through a sort index rather than materialize all matching IDs.
CANDIDATE_LIMIT = 4096
TABLE = "files_search"


def available(connection: sqlite3.Connection) -> bool:
    return (
        connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)
        ).fetchone()
        is not None
    )


def supported() -> bool:
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute(
            "CREATE VIRTUAL TABLE probe USING fts5(text, tokenize='trigram case_sensitive 1')"
        )
        return True
    except sqlite3.OperationalError:
        return False
    finally:
        connection.close()


def ensure(connection: sqlite3.Connection) -> None:
    """Backfill and publish the index and its triggers in one transaction."""
    connection.execute("SAVEPOINT search_index")
    try:
        if not available(connection):
            connection.execute(
                "CREATE VIRTUAL TABLE files_search USING fts5("
                "search_text, content='files', content_rowid='id', "
                "tokenize='trigram case_sensitive 1', detail='none')"
            )
            connection.execute(
                "CREATE TRIGGER files_search_insert AFTER INSERT ON files BEGIN "
                "INSERT INTO files_search(rowid, search_text) VALUES (new.id, new.search_text); END"
            )
            connection.execute(
                "CREATE TRIGGER files_search_delete AFTER DELETE ON files BEGIN "
                "INSERT INTO files_search(files_search, rowid, search_text) "
                "VALUES ('delete', old.id, old.search_text); END"
            )
            connection.execute(
                "CREATE TRIGGER files_search_update AFTER UPDATE OF id, search_text ON files "
                "WHEN old.id != new.id OR old.search_text IS NOT new.search_text BEGIN "
                "INSERT INTO files_search(files_search, rowid, search_text) "
                "VALUES ('delete', old.id, old.search_text); "
                "INSERT INTO files_search(rowid, search_text) VALUES (new.id, new.search_text); END"
            )
            connection.execute(
                "INSERT INTO files_search(files_search) VALUES ('rebuild')"
            )
        connection.execute("RELEASE search_index")
    except BaseException:
        connection.execute("ROLLBACK TO search_index")
        connection.execute("RELEASE search_index")
        raise


def candidates(connection: sqlite3.Connection, query: str) -> Optional[List[int]]:
    """Return a bounded superset of matches, or None for the scan/sort path.

    Three-character MATCH tokens work with detail=none (no positions stored).
    Recheck the original LIKE predicates: trigrams may occur out of order or
    in different fields, and short terms do not contribute index constraints.
    """
    terms = query.casefold().split()
    if not terms or "\x00" in query or not available(connection):
        return None
    grams = dict.fromkeys(
        term[offset : offset + 3] for term in terms for offset in range(len(term) - 2)
    )
    if not grams:
        return None
    # Quote every token so punctuation, quotes and FTS operators stay literal.
    # A subset remains a safe superset of matches; bound parser work for long
    # pasted paths rather than constructing an arbitrarily large expression.
    match = " AND ".join(
        '"' + gram.replace('"', '""') + '"' for gram in list(grams)[:128]
    )
    rows = connection.execute(
        "SELECT rowid FROM files_search WHERE files_search MATCH ? LIMIT ?",
        (match, CANDIDATE_LIMIT + 1),
    ).fetchall()
    return [int(row[0]) for row in rows] if len(rows) <= CANDIDATE_LIMIT else None
