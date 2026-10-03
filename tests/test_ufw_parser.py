from datetime import datetime, timezone

from app.detection.rules import rule_port_scan
from app.parsers.ufw import parse_file, parse_line


NOW = datetime(2026, 10, 3, 12, 0, 0, tzinfo=timezone.utc)


def test_block_line_basic():
    line = ("Oct  3 13:22:01 edge01 kernel: [98765.001] [UFW BLOCK] IN=eth0 OUT= "
            "SRC=203.0.113.99 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=40001 DPT=21 SYN URGP=0")
    e = parse_line(line, now=NOW)
    assert e is not None
    assert e.event_type == "net"
    assert e.severity == "notice"
    assert e.source_ip == "203.0.113.99"
    assert e.dest_ip == "10.0.0.5"
    assert e.source_port == 40001
    assert e.dest_port == 21
    assert e.detail["kind"] == "ufw_block"
    assert e.detail["proto"] == "TCP"
    assert "SYN" in e.detail["flags"]


def test_allow_line_severity():
    line = ("Oct  3 13:23:11 edge01 kernel: [98767.5] [UFW ALLOW] IN=eth0 OUT= "
            "SRC=192.0.2.10 DST=10.0.0.5 PROTO=TCP SPT=53210 DPT=22 SYN")
    e = parse_line(line, now=NOW)
    assert e is not None
    assert e.severity == "info"
    assert e.detail["kind"] == "ufw_allow"


def test_limit_line_severity():
    line = ("Oct  3 13:24:55 edge01 kernel: [98780.1] [UFW LIMIT] IN=eth0 OUT= "
            "SRC=198.51.100.7 DST=10.0.0.5 PROTO=TCP SPT=53211 DPT=22 SYN")
    e = parse_line(line, now=NOW)
    assert e is not None
    assert e.severity == "warning"
    assert e.detail["kind"] == "ufw_limit"


def test_non_ufw_line_ignored():
    line = "Oct  3 13:10:01 web01 sshd[1001]: Failed password for root from 1.2.3.4 port 22 ssh2"
    assert parse_line(line, now=NOW) is None


def test_garbage_line_ignored():
    assert parse_line("not a syslog line", now=NOW) is None
    assert parse_line("", now=NOW) is None


def test_sample_file_feeds_portscan_rule():
    """End-to-end: sample_logs/ufw.log must trip rule_port_scan."""
    events = list(parse_file("sample_logs/ufw.log"))
    assert len(events) >= 20

    # Every event should be event_type="net"
    assert {e.event_type for e in events} == {"net"}

    findings = rule_port_scan(events)
    assert len(findings) == 1, f"expected exactly 1 port_scan, got {len(findings)}"
    f = findings[0]
    assert f.source_ip == "203.0.113.99"
    assert f.count >= 15
    from app.detection.severity import Severity
    assert f.severity is Severity.MEDIUM
