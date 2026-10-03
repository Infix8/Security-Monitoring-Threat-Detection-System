"""Persistence helpers for the scan audit log."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from app.db import session_scope
from app.models import ScanAudit


def record_request(
    *,
    requester: str,
    target_ip: str,
    ports: list[int],
    allowed: bool,
    reason: Optional[str] = None,
) -> int:
    """Write an audit row BEFORE a scan runs. Returns the audit id."""
    with session_scope() as s:
        row = ScanAudit(
            ts=datetime.now(timezone.utc),
            requester=requester,
            target_ip=target_ip,
            ports_json=ports,
            allowed=allowed,
            reason=reason,
        )
        s.add(row)
        s.flush()
        return row.id


def link_scan(audit_id: int, scan_id: int) -> None:
    """Attach the resulting scan row id to a previously-recorded audit row."""
    with session_scope() as s:
        row = s.get(ScanAudit, audit_id)
        if row is not None:
            row.scan_id = scan_id
