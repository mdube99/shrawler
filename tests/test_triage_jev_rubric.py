"""Offline structural guards for the content-free Jev rubric and its fixture.

The live evaluation runner (``scripts/evaluate_jev_rubric.py``) needs the
network. These checks run offline and fail fast if the built-in objective
reintroduces a content gate that the pipeline can never satisfy, if the rubric
and its compact criteria drift apart, or if the labeled fixture loses a case
class.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, cast

from shrawler.triage.jev.config import (
    DEFAULT_OBJECTIVE,
    PRIORITY_LEVELS,
    RUBRIC,
    RUBRIC_CRITERIA,
    RUBRIC_VERSION,
)

FIXTURE = Path(__file__).resolve().parents[1] / "scripts" / "jev_rubric_cases.json"


def test_level_4_is_not_gated_behind_file_contents() -> None:
    assert RUBRIC_VERSION == "4"
    lowered = DEFAULT_OBJECTIVE.casefold()
    assert "file contents are not available" in lowered
    # The pre-change level 4 required content evidence; it must not return.
    assert "available contents reveal" not in lowered
    assert "contents are unavailable" in lowered


def test_rubric_keys_and_criteria_stay_aligned() -> None:
    assert tuple(RUBRIC) == PRIORITY_LEVELS
    assert set(RUBRIC_CRITERIA) == set(PRIORITY_LEVELS)


def test_fixture_retains_credential_benign_and_secondary_classes() -> None:
    payload = cast(Dict[str, Any], json.loads(FIXTURE.read_text(encoding="utf-8")))
    cases = cast(List[Dict[str, Any]], payload["cases"])
    classes: Dict[str, int] = {}
    for case in cases:
        name = str(case["class"])
        classes[name] = classes.get(name, 0) + 1
    assert classes.get("credential", 0) >= 1
    assert classes.get("benign", 0) >= 1
    assert {"pii", "phi", "financial"} <= set(classes)
    paths = {str(case["remote_path"]) for case in cases}
    # The two pinned inventory targets must remain covered by the fixture.
    assert "/Finance/Accounts Payable/logins.txt" in paths
    assert "/IT/Passwords/payroll login.txt" in paths
