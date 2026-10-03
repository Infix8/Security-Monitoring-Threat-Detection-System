"""Parser for Linux SSH auth log lines (rsyslog / auth.log format).

Handles the common patterns emitted by OpenSSH sshd on Ubuntu/Debian:
  - Failed password for <user> from <ip> port <p> ssh2
  - Failed password for invalid user <user> from <ip> port <p> ssh2
  - Accepted password/publickey for <user> from <ip> port <p> ssh2
  - Invalid user <user> from <ip> port <p>
  - Connection closed by (authenticating user <user> | invalid user <user> | <ip>) ...
  - Disconnected from (invalid user <user> | authenticating user <user> | <ip>) ...
  - Received disconnect from <ip> port <p>: ...
  - PAM auth failures / session opened / session closed
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Optional

from dateutil import parser as dtparser

from app.parsers.base import ParsedEvent

SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<msg>.*)$"
)

RE_FAILED_PW = re.compile(
    r"^Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)
RE_ACCEPTED = re.compile(
    r"^Accepted (?P<method>password|publickey) for (?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)
RE_INVALID_USER = re.compile(
    r"^Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)
RE_CONN_CLOSED = re.compile(
    r"^Connection closed by "
    r"(?:authenticating user (?P<au>\S+) (?P<aip>[0-9a-fA-F:.]+)"
    r"|invalid user (?P<iu>\S+) (?P<iip>[0-9a-fA-F:.]+)"
    r"|(?P<ip>[0-9a-fA-F:.]+)) "
    r"(?:port (?P<port>\d+) )?\[preauth\]"
)
RE_DISCONNECTED = re.compile(
    r"^Disconnected from "
    r"(?:invalid user (?P<iu>\S+) (?P<iip>[0-9a-fA-F:.]+)"
    r"|authenticating user (?P<au>\S+) (?P<aip>[0-9a-fA-F:.]+)"
    r"|(?P<ip>[0-9a-fA-F:.]+)) "
    r"(?:port (?P<port>\d+) )?\[preauth\]"
)
RE_RECV_DISCONNECT = re.compile(
    r"^Received disconnect from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+):(?P<reason>.*)$"
)
RE_PAM_AUTH_FAIL = re.compile(
    r"pam_unix\(sshd:auth\): authentication failure;.*rhost=(?P<ip>[0-9a-fA-F:.]+)\s+user=(?P<user>\S+)"
)
RE_SESSION_OPENED = re.compile(
    r"pam_unix\(sshd:session\): session opened for user (?P<user>\S+?)(?:\(uid=\d+\))? by"
)
RE_SESSION_CLOSED = re.compile(
    r"pam_unix\(sshd:session\): session closed for user (?P<user>\S+)"
)


def _parse_ts(ts_str: str, now: Optional[datetime] = None) -> datetime:
    """Parse syslog timestamp. Syslog omits the year, so we default to current year."""
    now = now or datetime.now(timezone.utc)
    dt = dtparser.parse(f"{ts_str} {now.year}", fuzzy=False)
    return dt.replace(tzinfo=timezone.utc)


def parse_line(line: str, now: Optional[datetime] = None) -> Optional[ParsedEvent]:
    """Parse one auth.log line into a ParsedEvent, or None if not recognized."""
    line = line.rstrip("\n")
    if not line:
        return None

    m = SYSLOG_RE.match(line)
    if not m:
        return None

    ts = _parse_ts(m.group("ts"), now=now)
    proc = m.group("proc")
    pid = int(m.group("pid")) if m.group("pid") else None
    msg = m.group("msg").strip()

    # Common kwargs WITHOUT severity/detail — those are passed per-branch.
    common: dict[str, Any] = dict(
        ts=ts,
        event_type="auth",
        message=msg,
        raw=line,
    )
    proc_detail: dict[str, Any] = {"process": proc, "pid": pid}

    def D(**extra: Any) -> dict[str, Any]:
        """Merge process metadata with branch-specific detail."""
        return {**proc_detail, **extra}

    if (mm := RE_FAILED_PW.match(msg)):
        return ParsedEvent(
            **common,
            severity="warning",
            user=mm.group("user"),
            source_ip=mm.group("ip"),
            source_port=int(mm.group("port")),
            detail=D(kind="ssh_failed_password"),
        )

    if (mm := RE_INVALID_USER.match(msg)):
        return ParsedEvent(
            **common,
            severity="warning",
            user=mm.group("user"),
            source_ip=mm.group("ip"),
            source_port=int(mm.group("port")),
            detail=D(kind="ssh_invalid_user"),
        )

    if (mm := RE_ACCEPTED.match(msg)):
        return ParsedEvent(
            **common,
            severity="notice",
            user=mm.group("user"),
            source_ip=mm.group("ip"),
            source_port=int(mm.group("port")),
            detail=D(kind="ssh_accepted", method=mm.group("method")),
        )

    if (mm := RE_PAM_AUTH_FAIL.search(msg)):
        return ParsedEvent(
            **common,
            severity="warning",
            user=mm.group("user"),
            source_ip=mm.group("ip"),
            detail=D(kind="pam_auth_failure"),
        )

    if (mm := RE_CONN_CLOSED.match(msg)):
        ip = mm.group("aip") or mm.group("iip") or mm.group("ip")
        user = mm.group("au") or mm.group("iu")
        return ParsedEvent(
            **common,
            severity="info",
            user=user,
            source_ip=ip,
            source_port=int(mm.group("port")) if mm.group("port") else None,
            detail=D(kind="ssh_conn_closed"),
        )

    if (mm := RE_DISCONNECTED.match(msg)):
        ip = mm.group("aip") or mm.group("iip") or mm.group("ip")
        user = mm.group("au") or mm.group("iu")
        return ParsedEvent(
            **common,
            severity="info",
            user=user,
            source_ip=ip,
            source_port=int(mm.group("port")) if mm.group("port") else None,
            detail=D(kind="ssh_disconnected"),
        )

    if (mm := RE_RECV_DISCONNECT.match(msg)):
        return ParsedEvent(
            **common,
            severity="info",
            source_ip=mm.group("ip"),
            source_port=int(mm.group("port")),
            detail=D(kind="ssh_recv_disconnect", reason=mm.group("reason").strip()),
        )

    if (mm := RE_SESSION_OPENED.search(msg)):
        return ParsedEvent(
            **common,
            severity="info",
            user=mm.group("user"),
            detail=D(kind="session_opened"),
        )
    if (mm := RE_SESSION_CLOSED.search(msg)):
        return ParsedEvent(
            **common,
            severity="info",
            user=mm.group("user"),
            detail=D(kind="session_closed"),
        )

    # Recognized syslog envelope but message not covered — keep it as info.
    return ParsedEvent(**common, severity="info", detail=D(kind="unclassified"))


def parse_file(path: str):
    """Yield ParsedEvent for every recognizable line in a file."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            ev = parse_line(line)
            if ev is not None:
                yield ev
