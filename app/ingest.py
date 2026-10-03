"""Ingest pipeline: parse -> persist events -> detect -> persist threats."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Iterable, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.db import session_scope
from app.detection.base import Finding
from app.detection.rules import run_all
from app.models import Event, Threat, ThreatEvent
from app.parsers.base import ParsedEvent


def _event_hash(e: ParsedEvent) -> str:
    """Stable hash of a parsed event's identity. Same line+ts => same hash."""
    h = hashlib.sha256()
    h.update(e.raw.encode("utf-8", errors="replace"))
    h.update(b"|")
    h.update(e.ts.isoformat().encode())
    h.update(b"|")
    h.update(e.event_type.encode())
    return h.hexdigest()


def persist_events(events: Iterable[ParsedEvent]) -> tuple[int, int, dict[str, int]]:
    """Insert events; skip duplicates by dedup_hash.

    Returns (inserted_count, skipped_count, {raw_line: event_id}).
    The raw_line->id map lets us link findings back to their source events.
    """
    inserted = 0
    skipped = 0
    raw_to_id: dict[str, int] = {}

    with session_scope() as s:
        for e in events:
            dh = _event_hash(e)
            # Try to find existing
            existing = s.execute(
                select(Event.id, Event.raw).where(Event.dedup_hash == dh)
            ).first()
            if existing:
                skipped += 1
                if existing.raw:
                    raw_to_id[existing.raw] = existing.id
                continue

            row = Event(
                ts=e.ts,
                event_type=e.event_type,
                severity=e.severity,
                source_ip=e.source_ip,
                source_port=e.source_port,
                dest_ip=e.dest_ip,
                dest_port=e.dest_port,
                user=e.user,
                message=e.message,
                raw=e.raw,
                dedup_hash=dh,
                detail=e.detail,
            )
            s.add(row)
            try:
                s.flush()
            except IntegrityError:
                # Race with concurrent ingest — fetch and move on
                s.rollback()
                existing = s.execute(
                    select(Event.id).where(Event.dedup_hash == dh)
                ).scalar_one()
                skipped += 1
                raw_to_id[e.raw] = existing
                continue
            inserted += 1
            raw_to_id[e.raw] = row.id

    return inserted, skipped, raw_to_id


def persist_findings(
    findings: list[Finding],
    events: list[ParsedEvent],
) -> tuple[int, int]:
    """Insert threats; skip duplicates by dedup_key. Link related events.

    Returns (inserted_count, skipped_count).
    """
    inserted = 0
    skipped = 0

    with session_scope() as s:
        for f in findings:
            existing = s.execute(
                select(Threat.id).where(Threat.dedup_key == f.key())
            ).scalar_one_or_none()
            if existing:
                skipped += 1
                continue

            threat = Threat(
                ts=f.ts,
                rule=f.rule,
                severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                source_ip=f.source_ip,
                count=f.count,
                window_start=f.window_start,
                window_end=f.window_end,
                summary=f.summary,
                dedup_key=f.key(),
                mitre_techniques=list(f.mitre_techniques),
                detail=f.detail,
            )
            s.add(threat)
            s.flush()

            # Link to source events via (ts, raw) match
            linked = 0
            for idx in f.event_indices:
                if idx < 0 or idx >= len(events):
                    continue
                src = events[idx]
                ev_id = s.execute(
                    select(Event.id).where(
                        Event.raw == src.raw,
                        Event.ts == src.ts,
                    )
                ).scalar_one_or_none()
                if ev_id is None:
                    continue
                s.add(ThreatEvent(threat_id=threat.id, event_id=ev_id))
                linked += 1

            threat.detail = {**threat.detail, "linked_events": linked}
            inserted += 1

    return inserted, skipped


def ingest_auth_file(path: str) -> dict[str, int]:
    """One-shot ingest: parse -> persist -> detect -> persist threats."""
    from app.parsers.auth import parse_file

    events = list(parse_file(path))
    e_ins, e_skip, _ = persist_events(events)
    findings = run_all(events)
    t_ins, t_skip = persist_findings(findings, events)

    return {
        "events_parsed": len(events),
        "events_inserted": e_ins,
        "events_skipped": e_skip,
        "findings": len(findings),
        "threats_inserted": t_ins,
        "threats_skipped": t_skip,
    }


def ingest_event_list(events: list[ParsedEvent]) -> dict[str, int]:
    """Same as ingest_auth_file but takes a pre-built list (used for tests/synth)."""
    e_ins, e_skip, _ = persist_events(events)
    findings = run_all(events)
    t_ins, t_skip = persist_findings(findings, events)
    return {
        "events_parsed": len(events),
        "events_inserted": e_ins,
        "events_skipped": e_skip,
        "findings": len(findings),
        "threats_inserted": t_ins,
        "threats_skipped": t_skip,
    }
