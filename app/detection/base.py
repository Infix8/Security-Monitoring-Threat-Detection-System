"""Types shared by all detection rules."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional, Union

from app.detection.severity import Severity


@dataclass(slots=True)
class Finding:
    """A detection hit produced by a rule.

    `severity` accepts either a `Severity` enum member or its string value.
    `mitre_techniques` is a tuple of ATT&CK IDs the rule maps to.
    """

    rule: str
    severity: Union[Severity, str]
    ts: datetime
    source_ip: Optional[str]
    count: int
    window_start: datetime
    window_end: datetime
    summary: str
    mitre_techniques: tuple[str, ...] = ()
    detail: dict[str, Any] = field(default_factory=dict)
    event_indices: list[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        # Coerce string severities to the enum for consistent comparison.
        if isinstance(self.severity, str) and not isinstance(self.severity, Severity):
            object.__setattr__(self, "severity", Severity.from_str(self.severity))

    def key(self) -> str:
        """Stable dedup key for one rule + source + window."""
        return f"{self.rule}|{self.source_ip}|{int(self.window_start.timestamp())}|{int(self.window_end.timestamp())}"
