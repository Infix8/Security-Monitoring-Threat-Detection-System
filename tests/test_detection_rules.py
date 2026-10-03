from datetime import datetime, timedelta, timezone

from app.detection.rules import (
    rule_brute_force,
    rule_port_scan,
    rule_suspicious_connection,
    run_all,
)
from app.parsers.base import ParsedEvent


T0 = datetime(2026, 10, 3, 13, 0, 0, tzinfo=timezone.utc)


def _failed(ip, offset_s, user="root"):
    return ParsedEvent(
        ts=T0 + timedelta(seconds=offset_s),
        event_type="auth", severity="warning",
        message=f"Failed password for {user}",
        raw="x", source_ip=ip, user=user,
        detail={"kind": "ssh_failed_password"},
    )


def _net(ip, offset_s, port):
    return ParsedEvent(
        ts=T0 + timedelta(seconds=offset_s),
        event_type="net", severity="info",
        message=f"tcp -> {port}", raw="x",
        source_ip=ip, dest_port=port,
        detail={"kind": "tcp_syn"},
    )


def _invalid(ip, offset_s, user="x"):
    return ParsedEvent(
        ts=T0 + timedelta(seconds=offset_s),
        event_type="auth", severity="warning",
        message=f"Invalid user {user}", raw="x",
        source_ip=ip, user=user,
        detail={"kind": "ssh_invalid_user"},
    )


def _disc(ip, offset_s):
    return ParsedEvent(
        ts=T0 + timedelta(seconds=offset_s),
        event_type="auth", severity="info",
        message="Connection closed", raw="x",
        source_ip=ip,
        detail={"kind": "ssh_conn_closed"},
    )


# ---- brute force ----

def test_brute_force_fires_at_threshold():
    # default threshold=5, window=300s
    ev = [_failed("1.2.3.4", i * 10) for i in range(5)]
    fs = rule_brute_force(ev)
    assert len(fs) == 1
    f = fs[0]
    assert f.rule == "brute_force"
    assert f.source_ip == "1.2.3.4"
    assert f.count == 5
    assert f.severity == "warning"


def test_brute_force_escalates_severity_on_double():
    ev = [_failed("1.2.3.4", i * 5) for i in range(10)]
    fs = rule_brute_force(ev)
    assert fs[0].severity == "critical"


def test_brute_force_ignores_different_ips():
    ev = [_failed(f"10.0.0.{i}", i) for i in range(5)]
    assert rule_brute_force(ev) == []


def test_brute_force_respects_window():
    # 5 events, but spread 400s apart -> should not fire
    ev = [_failed("1.2.3.4", i * 400) for i in range(5)]
    assert rule_brute_force(ev) == []


# ---- port scan ----

def test_port_scan_fires():
    ev = [_net("9.9.9.9", i, 1000 + i) for i in range(20)]
    fs = rule_port_scan(ev)
    assert len(fs) == 1
    assert fs[0].rule == "port_scan"
    assert fs[0].count >= 15


def test_port_scan_ignores_repeats():
    ev = [_net("9.9.9.9", i, 80) for i in range(50)]  # same port
    assert rule_port_scan(ev) == []


# ---- suspicious connection ----

def test_invalid_user_burst():
    ev = [_invalid("5.5.5.5", i * 5, user="a") for i in range(2)]
    fs = rule_suspicious_connection(ev)
    assert any(f.detail["reason"] == "invalid_user_burst" for f in fs)


def test_preauth_disconnect_burst():
    ev = [_disc("6.6.6.6", i * 5) for i in range(3)]
    fs = rule_suspicious_connection(ev)
    assert any(f.detail["reason"] == "preauth_disconnect_burst" for f in fs)


def test_no_findings_on_clean_traffic():
    assert run_all([]) == []
