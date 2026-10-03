from datetime import datetime, timedelta, timezone

from app.detection import mitre
from app.detection.rules import (
    rule_brute_force,
    rule_port_scan,
    rule_suspicious_connection,
)
from app.detection.severity import Severity, at_least, escalate
from app.parsers.base import ParsedEvent


T0 = datetime(2026, 10, 3, 13, 0, 0, tzinfo=timezone.utc)


def _failed(ip, off, user="root"):
    return ParsedEvent(
        ts=T0 + timedelta(seconds=off), event_type="auth", severity="warning",
        message=f"Failed password for {user}", raw="x", source_ip=ip, user=user,
        detail={"kind": "ssh_failed_password"},
    )


def _net(ip, off, port):
    return ParsedEvent(
        ts=T0 + timedelta(seconds=off), event_type="net", severity="info",
        message=f"SYN to {port}", raw="x", source_ip=ip, dest_port=port,
        detail={"kind": "tcp_syn"},
    )


# ---- severity enum ----

def test_severity_ordering():
    assert Severity.INFO.rank < Severity.LOW.rank < Severity.MEDIUM.rank
    assert Severity.MEDIUM.rank < Severity.HIGH.rank < Severity.CRITICAL.rank


def test_severity_from_str():
    assert Severity.from_str("warning") is Severity.INFO  # unknown → INFO
    assert Severity.from_str("high") is Severity.HIGH
    assert Severity.from_str(None) is Severity.INFO


def test_severity_escalation_helpers():
    assert escalate(Severity.LOW, Severity.HIGH) is Severity.HIGH
    assert at_least(Severity.HIGH, Severity.MEDIUM) is True
    assert at_least(Severity.LOW, Severity.MEDIUM) is False


# ---- MITRE mappings ----

def test_brute_force_maps_to_T1110():
    ev = [_failed("1.2.3.4", i * 5) for i in range(6)]
    fs = rule_brute_force(ev)
    assert fs
    assert "T1110" in fs[0].mitre_techniques
    assert fs[0].severity is Severity.HIGH


def test_brute_force_escalates_to_critical_at_2x():
    ev = [_failed("1.2.3.4", i * 3) for i in range(12)]
    fs = rule_brute_force(ev)
    assert fs
    assert fs[0].severity is Severity.CRITICAL


def test_port_scan_maps_to_T1046():
    ev = [_net("9.9.9.9", i, 1000 + i) for i in range(20)]
    fs = rule_port_scan(ev)
    assert fs
    assert fs[0].mitre_techniques == ("T1046",)
    assert fs[0].severity is Severity.MEDIUM


def test_suspicious_connection_maps_techniques():
    from tests.test_detection_rules import _invalid, _disc
    # invalid-user burst
    ev = [_invalid("5.5.5.5", i * 5, user="a") for i in range(2)]
    fs = rule_suspicious_connection(ev)
    assert any(f.detail["reason"] == "invalid_user_burst" and "T1078" in f.mitre_techniques for f in fs)


def test_catalog_contains_referenced_ids():
    referenced: set[str] = set()
    referenced.update(("T1110", "T1110.001"))
    referenced.update(("T1046",))
    referenced.update(("T1110.001", "T1078"))
    for tid in referenced:
        assert tid in mitre.CATALOG, f"{tid} missing from catalog"
        entry = mitre.CATALOG[tid]
        assert entry["name"]
        assert entry["tactic"]


def test_all_techniques_sorted():
    items = mitre.all_techniques()
    assert items == sorted(items, key=lambda t: t["id"])
