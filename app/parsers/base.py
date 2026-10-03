"""Shared types for all log parsers."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass(slots=True)
class ParsedEvent:
    """Normalized representation of one parsed log line."""

    ts: datetime
    event_type: str            # "auth", "syslog", "net", ...
    severity: str              # "info" | "notice" | "warning" | "error" | "critical"
    message: str
    raw: str
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    user: Optional[str] = None
    detail: dict[str, Any] = field(default_factory=dict)

    def to_event_kwargs(self) -> dict[str, Any]:
        """Shape ready for Event(**kwargs) ORM construction."""
        return {
            "ts": self.ts,
            "event_type": self.event_type,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "user": self.user,
            "message": self.message,
            "raw": self.raw,
            "detail": self.detail,
        }
