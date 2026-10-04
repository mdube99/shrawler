"""Combined inspection-priority scoring across rules and Jev.

The WebUI shows three related numbers for a file:

* the deterministic rule rating (``ranking_score``) from the offline triage
  rules,
* the model's 0-4 Jev inspection priority (``jev_score``), and
* a combined priority on a 0-100 scale that blends the two.

The blend normalizes each component to 0..1 and takes a weighted mean. A
component only counts toward the blend when its run is selected. When a run is
selected but a file has no result, that component contributes zero *without*
being dropped from the denominator, so partial coverage never inflates a score.
When no run is selected at all, the combined metric is unavailable.
"""

from dataclasses import dataclass
from typing import Any, Mapping, Optional, Tuple

# Rule rating at which the deterministic rules are treated as fully alarmed.
# 80 is the strongest single built-in signal (for example ``ntds.dit`` on a
# domain controller); higher rule totals saturate.
RATING_FULL = 80
WEIGHT_RATING = 0.5
WEIGHT_JEV = 0.5

# Coverage labels reported alongside a combined score.
COVERAGE_BOTH = "both"
COVERAGE_RULES = "rules"
COVERAGE_JEV = "jev"
COVERAGE_NONE = "none"

ALLOWED_FIELDS = frozenset({"rating_full", "rating_weight", "jev_weight"})


@dataclass(frozen=True)
class ScoringConfig:
    """Weights and scale for the combined metric."""

    rating_full: int = RATING_FULL
    rating_weight: float = WEIGHT_RATING
    jev_weight: float = WEIGHT_JEV

    @classmethod
    def from_mapping(cls, data: Optional[Mapping[str, Any]]) -> "ScoringConfig":
        table = dict(data or {})
        unknown = set(table) - ALLOWED_FIELDS
        if unknown:
            raise ValueError(f"[scoring] unknown fields: {sorted(unknown)}")
        values: dict[str, Any] = {}
        if "rating_full" in table:
            value = table["rating_full"]
            if type(value) is not int or value < 1:
                raise ValueError("[scoring] rating_full must be a positive integer")
            values["rating_full"] = value
        for name in ("rating_weight", "jev_weight"):
            if name in table:
                value = table[name]
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise ValueError(f"[scoring] {name} must be a positive number")
                if value <= 0:
                    raise ValueError(f"[scoring] {name} must be a positive number")
                values[name] = float(value)
        return cls(**values)


# Shared immutable default so callables can use it as a plain default value.
DEFAULT_SCORING = ScoringConfig()


def combine_priority(
    rating: Optional[int],
    jev: Optional[int],
    *,
    rating_available: bool,
    jev_available: bool,
    config: ScoringConfig = DEFAULT_SCORING,
) -> Tuple[Optional[int], str]:
    """Blend a rule rating and a Jev priority into a 0-100 combined score.

    ``rating_available`` and ``jev_available`` say whether each run is selected
    *at all*; a selected run whose file has no result contributes zero rather
    than being renormalized away. Returns ``(score, coverage)`` where ``score``
    is ``None`` only when neither component is available and ``coverage`` names
    which components had a value.
    """
    if not rating_available and not jev_available:
        return None, COVERAGE_NONE

    has_rating = rating_available and rating is not None
    has_jev = jev_available and jev is not None
    if not has_rating and not has_jev:
        return None, COVERAGE_NONE

    weight_total = 0.0
    weighted = 0.0
    if rating_available:
        weight_total += config.rating_weight
        if has_rating:
            normalized = min(max(int(rating), 0) / config.rating_full, 1.0)
            weighted += config.rating_weight * normalized
    if jev_available:
        weight_total += config.jev_weight
        if has_jev:
            normalized = min(max(int(jev), 0), 4) / 4.0
            weighted += config.jev_weight * normalized
    if weight_total <= 0:
        return None, COVERAGE_NONE

    score = int(round(100 * weighted / weight_total))
    if has_rating and has_jev:
        coverage = COVERAGE_BOTH
    elif has_rating:
        coverage = COVERAGE_RULES
    else:
        coverage = COVERAGE_JEV
    return score, coverage


def combined_sql(
    rating_expr: str,
    jev_expr: str,
    *,
    rating_available: bool,
    jev_available: bool,
    config: ScoringConfig = DEFAULT_SCORING,
) -> Optional[str]:
    """SQL expression producing the same combined score for ORDER BY.

    ``rating_expr`` is the selected rule score (already coalesced to 0 for a
    missing row) and ``jev_expr`` is the Jev ``choice`` column (a numeric
    string or ``NULL``). Returns ``None`` when neither component is available.
    ``combine_priority`` remains the source of truth for display; this mirrors
    its arithmetic so sorting and filtering agree with the shown number.
    """
    if not rating_available and not jev_available:
        return None
    weight_total = 0.0
    terms = []
    if rating_available:
        weight_total += config.rating_weight
        terms.append(
            f"{config.rating_weight!r} * MIN(MAX(COALESCE({rating_expr}, 0), 0)"
            f" / {float(config.rating_full)!r}, 1.0)"
        )
    if jev_available:
        weight_total += config.jev_weight
        terms.append(
            f"{config.jev_weight!r} * (MIN(MAX(COALESCE(CAST({jev_expr}"
            f" AS INTEGER), 0), 0), 4) / 4.0)"
        )
    return f"(100.0 * ({' + '.join(terms)}) / {weight_total!r})"
