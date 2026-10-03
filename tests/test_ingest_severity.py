"""Regression guard: persisted severity must be the enum's value, not its repr."""
from datetime import datetime, timedelta, timezone

from app.db import session_scope
from app.detection.severity import Severity
from app.ingest import ingest_event_list
from app.models import Threat
from app.parsers.base import ParsedEvent


def _net(ip, off, port):
    return ParsedEvent(
        ts=datetime(2026, 10, 3, 13, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=off),
        event_type="net", severity="notice",
        message=f"SYN -> {port}", raw=f"row-{port}-{ip}",
        source_ip=ip, dest_port=port, detail={"kind": "ufw_block"},
    )


def test_persisted_severity_uses_enum_value():
    events = [_net("198.51.100.42", i, 9000 + i) for i in range(20)]
    ingest_event_list(events)

    with session_scope() as s:
        rows = s.query(Threat).filter(Threat.source_ip == "198.51.100.42").all()

    assert rows, "port_scan threat not persisted"
    for t in rows:
        assert t.severity == Severity.MEDIUM.value, f"got {t.severity!r}"
        assert t.severity != "Severity.MEDIUM"
        assert t.mitre_techniques == ["T1046"]
