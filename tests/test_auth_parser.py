from datetime import datetime, timezone

from app.parsers.auth import parse_line


NOW = datetime(2026, 10, 3, 12, 0, 0, tzinfo=timezone.utc)


def test_failed_password():
    line = "Oct  3 13:10:01 web01 sshd[1001]: Failed password for invalid user admin from 203.0.113.42 port 51234 ssh2"
    e = parse_line(line, now=NOW)
    assert e is not None
    assert e.severity == "warning"
    assert e.user == "admin"
    assert e.source_ip == "203.0.113.42"
    assert e.source_port == 51234
    assert e.detail["kind"] == "ssh_failed_password"


def test_accepted_publickey():
    line = "Oct  3 13:11:02 web01 sshd[1100]: Accepted publickey for deploy from 192.0.2.10 port 53210 ssh2: RSA SHA256:abc"
    e = parse_line(line, now=NOW)
    assert e is not None
    assert e.severity == "notice"
    assert e.user == "deploy"
    assert e.detail["method"] == "publickey"


def test_invalid_user():
    line = "Oct  3 13:10:15 web01 sshd[1007]: Invalid user ubuntu from 198.51.100.7 port 40001"
    e = parse_line(line, now=NOW)
    assert e is not None
    assert e.user == "ubuntu"
    assert e.detail["kind"] == "ssh_invalid_user"


def test_non_syslog_line_ignored():
    assert parse_line("this is not a syslog line", now=NOW) is None


def test_blank_line_ignored():
    assert parse_line("", now=NOW) is None


def test_unclassified_syslog_line_kept():
    line = "Oct  3 13:18:00 web01 cron[2000]: (root) CMD (echo hello)"
    e = parse_line(line, now=NOW)
    assert e is not None
    assert e.detail["kind"] == "unclassified"


def test_connection_closed_by_invalid_user_carries_ip():
    line = "Oct  3 13:10:17 web01 sshd[1008]: Connection closed by invalid user ubuntu 198.51.100.7 port 40001 [preauth]"
    e = parse_line(line, now=NOW)
    assert e is not None
    assert e.detail["kind"] == "ssh_conn_closed"
    assert e.user == "ubuntu"
    assert e.source_ip == "198.51.100.7"
    assert e.source_port == 40001


def test_disconnected_authenticating_user_carries_ip():
    line = "Oct  3 13:15:00 web01 sshd[1120]: Disconnected from authenticating user root 198.51.100.7 port 42111 [preauth]"
    e = parse_line(line, now=NOW)
    assert e is not None
    assert e.detail["kind"] == "ssh_disconnected"
    assert e.user == "root"
    assert e.source_ip == "198.51.100.7"
    assert e.source_port == 42111
