"""Typed models for the Snaffler rule engine."""

from dataclasses import dataclass, field
from typing import List, Optional, Pattern


@dataclass
class SnafflerRule:
    """Normalized Snaffler rule definition."""

    rule_name: str
    description: str
    scope: str
    action: str
    triage: str
    match_location: str
    word_list_type: str
    word_list: List[str]
    compiled_patterns: List[Pattern[str]]
    relay_targets: List[str] = field(default_factory=list)
    match_length: Optional[int] = None
    match_md5: Optional[str] = None
    interest_level: Optional[int] = None
    source_file: str = ""
