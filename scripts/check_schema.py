"""Insert an Event, read it back, print columns, then clean up."""
import sys
sys.path.insert(0, ".")

from datetime import datetime, timezone

from app.db import session_scope
from app.models import Event, Scan, Threat

with session_scope() as s:
    e = Event(
        ts=datetime.now(timezone.utc),
        event_type="auth",
        severity="warning",
        source_ip="203.0.113.42",
        source_port=51234,
        dest_ip="10.0.0.5",
        dest_port=22,
        user="root",
        message="Failed password for root",
        raw="test line",
        detail={"test": True, "reason": "smoke"},
    )
    s.add(e)
    s.flush()
    eid = e.id

with session_scope() as s:
    e = s.get(Event, eid)
    print("inserted id  =>", e.id)
    print("event_type   =>", e.event_type)
    print("severity     =>", e.severity)
    print("source_ip    =>", e.source_ip)
    print("detail       =>", e.detail)
    s.delete(e)

print("models importable =>", Event.__tablename__, Threat.__tablename__, Scan.__tablename__)
