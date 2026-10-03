"""Persist scan results into the `scans` table."""
from __future__ import annotations

from app.db import session_scope
from app.models import Scan


def save_scan(result: dict) -> int:
    with session_scope() as s:
        row = Scan(
            ts=result["ts"],
            target_ip=result["target_ip"],
            scan_type=result["scan_type"],
            open_ports=result["open_ports"],
            services=result["services"],
            duration_ms=result.get("duration_ms"),
            detail=result.get("detail", {}),
        )
        s.add(row)
        s.flush()
        return row.id
