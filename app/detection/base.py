"""Types shared by all detection rules."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass(slots=True)
class Finding:
    """A detection hit produced by a rule."""

    rule: str
    severity: str                 # "info" | "notice" | "warning" | "error" | "critical"
    ts: datetime                  # when the finding was raised (window end)
    source_ip: Optional[str]
    count: int
    window_start: datetime
    window_end: datetime
    summary: str
    detail: dict[str, Any] = field(default_factory=dict)
    # Indices into the input list that contributed to this finding.
    event_indices: list[int] = field(default_factory=list)

    def key(self) -> str:
        """Stable dedup key for one rule + source + window."""
        return f"{self.rule}|{self.source_ip}|{int(self.window_start.timestamp())}|{int(self.window_end.timestamp())}"
