"""Parser for UFW / kernel firewall log lines.

Handles the format emitted by ufw's LOG target (usually via /var/log/ufw.log
or /var/log/kern.log on Ubuntu):

  Oct  3 13:20:01 host kernel: [12345.678] [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=203.0.113.5 DST=10.0.0.5 LEN=60 PROTO=TCP SPT=54321 DPT=22 SYN URGP=0

Fields extracted:
  event_type = "net"
  source_ip / source_port / dest_ip / dest_port   from SRC / SPT / DST / DPT
  detail.kind = "ufw_block" | "ufw_allow" | "ufw_limit" | "ufw_audit"
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

# [UFW BLOCK] or [UFW ALLOW] etc.
UFW_ACTION_RE = re.compile(r"\[UFW (?P<action>ALLOW|BLOCK|LIMIT|AUDIT)\]")

# Kernel timestamp prefix inside msg: "[12345.678]"
KERNEL_TS_RE = re.compile(r"^\[\s*(?P<ts>\d+\.\d+)\s*\]\s*")

SEVERITY_BY_ACTION = {
    "allow": "info",
    "block": "notice",
    "limit": "warning",
    "audit": "notice",
}


def _parse_ts(ts_str: str, now: Optional[datetime] = None) -> datetime:
    now = now or datetime.now(timezone.utc)
    dt = dtparser.parse(f"{ts_str} {now.year}", fuzzy=False)
    return dt.replace(tzinfo=timezone.utc)


def _kv_pairs(msg: str) -> dict[str, str]:
    """Extract key=value tokens. Safe: doesn't try to be clever."""
    out: dict[str, str] = {}
    for tok in msg.split():
        if "=" in tok:
            k, _, v = tok.partition("=")
            out[k] = v
    return out


def _maybe_int(v: Optional[str]) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def parse_line(line: str, now: Optional[datetime] = None) -> Optional[ParsedEvent]:
    """Parse one UFW/kern.log line into a ParsedEvent, or None if not UFW."""
    line = line.rstrip("\n")
    if not line:
        return None

    m = SYSLOG_RE.match(line)
    if not m:
        return None

    msg = m.group("msg").strip()

    # Strip optional kernel monotonic timestamp
    kernel_ts = None
    km = KERNEL_TS_RE.match(msg)
    if km:
        kernel_ts = float(km.group("ts"))
        msg = msg[km.end():]

    am = UFW_ACTION_RE.search(msg)
    if not am:
        return None  # Not UFW — caller should try other parsers

    action = am.group("action").lower()
    ts = _parse_ts(m.group("ts"), now=now)
    proc = m.group("proc")
    pid = int(m.group("pid")) if m.group("pid") else None

    # Extract key=value fields after the action tag
    after = msg[am.end():]
    kv = _kv_pairs(after)

    src_ip = kv.get("SRC")
    dst_ip = kv.get("DST")
    src_port = _maybe_int(kv.get("SPT"))
    dst_port = _maybe_int(kv.get("DPT"))
    proto = kv.get("PROTO")
    iface_in = kv.get("IN") or None
    iface_out = kv.get("OUT") or None

    flags: list[str] = []
    for flag in ("SYN", "ACK", "FIN", "RST", "URGP", "DF"):
        if flag in after:
            flags.append(flag)

    severity = SEVERITY_BY_ACTION.get(action, "notice")
    # A BLOCK with SYN to many ports is the interesting signal for port_scan;
    # keep it at "notice" — the rule will escalate to "warning".

    detail: dict[str, Any] = {
        "kind": f"ufw_{action}",
        "process": proc,
        "pid": pid,
        "proto": proto,
        "in": iface_in,
        "out": iface_out,
        "flags": flags,
    }
    if kernel_ts is not None:
        detail["kernel_ts"] = kernel_ts

    return ParsedEvent(
        ts=ts,
        event_type="net",
        severity=severity,
        message=msg,
        raw=line,
        source_ip=src_ip,
        source_port=src_port,
        dest_ip=dst_ip,
        dest_port=dst_port,
        user=None,
        detail=detail,
    )


def parse_file(path: str):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            ev = parse_line(line)
            if ev is not None:
                yield ev
