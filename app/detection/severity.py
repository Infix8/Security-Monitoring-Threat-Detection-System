"""Canonical severity scale used across events, findings, and threats.

`Severity` is a `str` subclass so:
  - it JSON-serializes as its value ("warning")
  - it can be compared/stored as a plain string
  - but we also get `.rank` for ordering and `Severity.escalate(a, b)`

Ranks are deliberately sparse so we can insert new levels later without
renumbering (e.g. an "info+" between info and low).
"""
from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _RANK[self]

    @classmethod
    def from_str(cls, raw: str | None) -> "Severity":
        """Lenient parse. Unknown values fall back to INFO."""
        if not raw:
            return cls.INFO
        try:
            return cls(raw.strip().lower())
        except ValueError:
            return cls.INFO


_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 10,
    Severity.MEDIUM: 20,
    Severity.HIGH: 30,
    Severity.CRITICAL: 40,
}


def escalate(a: Severity, b: Severity) -> Severity:
    """Return the higher of two severities."""
    return a if a.rank >= b.rank else b


def at_least(value: Severity, floor: Severity) -> bool:
    return value.rank >= floor.rank
