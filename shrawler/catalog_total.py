"""Exact catalog result totals for the normalized schema.

The interactive search shows a result count, so the total must stay exact.
These helpers compute it without listing every matching file id, which is what
the pre-normalization flat index made cheap:

* a single term whose name candidates are bounded is counted from the
  maintained per-directory ``file_count`` counters plus the exact extension
  and name/span candidates that sit outside those directories;
* a single term that matches directories and unboundedly many names uses
  inclusion-exclusion over the covering name index;
* with several terms, each bounded term's candidate ids still narrow the count
  even when another term is unbounded.

``DatabaseIndex._search_catalog`` keeps a revision-keyed cache in front of this
module; the functions here are the uncached computation.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, List, Optional, Set, Tuple

from .search_index import (
    CANDIDATE_LIMIT,
    TermPlan,
    like_contains,
    plan_ids,
    predicate,
)


def _json_in(
    column: str, ids: List[int], negate: bool = False
) -> Tuple[str, List[Any]]:
    operator = "NOT IN" if negate else "IN"
    return f"{column} {operator} (SELECT value FROM json_each(?))", [json.dumps(ids)]


def _dir_filters(
    alias: str, hosts: List[str], shares: List[str]
) -> Tuple[List[str], List[Any]]:
    """Host/share filters on a ``catalog_dirs`` alias ("" for the bare table)."""
    prefix = alias + "." if alias else ""
    where: List[str] = []
    values: List[Any] = []
    for column, items in (("host", hosts), ("share", shares)):
        if items:
            where.append(f"{prefix}{column} IN (" + ",".join("?" for _ in items) + ")")
            values.extend(items)
    return where, values


def _count_parts(
    connection: sqlite3.Connection, source: str, parts: List[Tuple[Any, List[Any]]]
) -> int:
    """``COUNT(*)`` over ``source`` with the AND of the given SQL parts."""
    where: List[str] = []
    values: List[Any] = []
    for sql, params in parts:
        where.extend(sql if isinstance(sql, list) else [sql])
        values.extend(params)
    clause = " WHERE " + " AND ".join(where) if where else ""
    return int(
        connection.execute(f"SELECT COUNT(*) FROM {source}{clause}", values).fetchone()[
            0
        ]
    )


def _single_term(
    connection: sqlite3.Connection, plan: TermPlan, hosts: List[str], shares: List[str]
) -> int:
    """Exact count for one term with bounded name candidates.

    The matches are A (file in a matching directory), B (matching extension)
    and C (name or span match, a subset of ``plan.name_ids``). Count
    ``|A| + |B-A| + |C-A-B|``: ``|A|`` comes from the maintained directory
    counters, the rest touches only B's extension entries and C's candidates.
    Host/share filters are directory properties, so they restrict every part.
    """
    count = 0
    if plan.dir_ids:
        filters, filter_values = _dir_filters("", hosts, shares)
        sql, ids = _json_in("id", plan.dir_ids)
        count += int(
            connection.execute(
                "SELECT coalesce(sum(file_count),0) FROM catalog_dirs WHERE "
                + " AND ".join([sql, *filters]),
                ids + filter_values,
            ).fetchone()[0]
        )
    filters, filter_values = _dir_filters("d", hosts, shares)
    source = "catalog_files f" + (
        " JOIN catalog_dirs d ON d.id=f.dir_id" if filters else ""
    )
    outside = [_json_in("f.dir_id", plan.dir_ids, negate=True)] if plan.dir_ids else []
    if plan.ext_ids:
        parts = [_json_in("f.ext_id", plan.ext_ids), *outside]
        count += _count_parts(connection, source, [*parts, (filters, filter_values)])
    if plan.name_ids:
        exact = predicate(TermPlan(plan.term, spans=plan.spans), "f")
        parts = [_json_in("f.id", sorted(set(plan.name_ids))), *outside]
        if plan.ext_ids:
            parts.append(_json_in("f.ext_id", plan.ext_ids, negate=True))
        count += _count_parts(
            connection, source, [*parts, exact, (filters, filter_values)]
        )
    return count


def _unbounded_names(connection: sqlite3.Connection, plan: TermPlan) -> int:
    """Exact count for one term matching directories and unboundedly many names.

    Only used for plans with no extension or span parts:
    ``|A u C| = |A| + |C| - |A n C|``. ``|C|`` is one pass over the covering
    name index and ``|A n C|`` seeks ``(dir_id, name)`` for the matching
    directories only.
    """
    like = [like_contains(plan.term)]
    count = int(
        connection.execute(
            "SELECT COUNT(*) FROM catalog_files WHERE name LIKE ? ESCAPE '\\'", like
        ).fetchone()[0]
    )
    if plan.dir_ids:
        dirs = json.dumps(plan.dir_ids)
        count += int(
            connection.execute(
                "SELECT coalesce(sum(file_count),0) FROM catalog_dirs "
                "WHERE id IN (SELECT value FROM json_each(?))",
                (dirs,),
            ).fetchone()[0]
        )
        count -= int(
            connection.execute(
                "SELECT COUNT(*) FROM catalog_files "
                "WHERE dir_id IN (SELECT value FROM json_each(?)) "
                "AND name LIKE ? ESCAPE '\\'",
                [dirs, *like],
            ).fetchone()[0]
        )
    return count


def _driver_ids(
    connection: sqlite3.Connection, plans: List[TermPlan]
) -> Optional[Set[int]]:
    """Intersection of the bounded terms' candidate sets, or None.

    Unbounded terms are left to their exact predicates, so the restriction
    remains a superset of the matches.
    """
    combined: Optional[Set[int]] = None
    for plan in plans:
        if plan.estimate is None or plan.estimate > CANDIDATE_LIMIT:
            continue
        ids = plan_ids(connection, plan)
        if len(ids) > CANDIDATE_LIMIT:
            continue
        combined = ids if combined is None else (combined & ids)
        if not combined:
            return set()
    return combined


def total(
    connection: sqlite3.Connection,
    terms: List[str],
    plans: List[TermPlan],
    hosts: List[str],
    shares: List[str],
    extensions: List[str],
) -> int:
    """Exact number of catalog files matching the query."""
    source = "catalog_files f"
    if hosts or shares:
        source += " JOIN catalog_dirs d ON d.id=f.dir_id"
    if extensions:
        source += " JOIN catalog_extensions e ON e.id=f.ext_id"
    where, values = _dir_filters("d", hosts, shares)
    if extensions:
        where.append("e.extension IN (" + ",".join("?" for _ in extensions) + ")")
        values.extend(extensions)
    if terms:
        if len(plans) == 1 and not extensions:
            plan = plans[0]
            if plan.name_ids is not None:
                return _single_term(connection, plan, hosts, shares)
            if not (hosts or shares or plan.ext_ids or plan.spans):
                return _unbounded_names(connection, plan)
        for plan in plans:
            sql, params = predicate(plan, "f")
            where.append(sql)
            values.extend(params)
        bounded = _driver_ids(connection, plans)
        if bounded is not None:
            where.append("f.id IN (SELECT value FROM json_each(?))")
            values.append(json.dumps(sorted(bounded)))
        clause = " WHERE " + " AND ".join(where) if where else ""
        return int(
            connection.execute(
                f"SELECT COUNT(*) FROM {source}{clause}", values
            ).fetchone()[0]
        )
    if not extensions:
        # No term and no extension filter: the maintained directory counters
        # answer the total without touching catalog_files.
        dir_where, dir_values = _dir_filters("", hosts, shares)
        dir_clause = " WHERE " + " AND ".join(dir_where) if dir_where else ""
        return int(
            connection.execute(
                "SELECT coalesce(sum(file_count),0) FROM catalog_dirs" + dir_clause,
                dir_values,
            ).fetchone()[0]
        )
    clause = " WHERE " + " AND ".join(where) if where else ""
    return int(
        connection.execute(f"SELECT COUNT(*) FROM {source}{clause}", values).fetchone()[
            0
        ]
    )
