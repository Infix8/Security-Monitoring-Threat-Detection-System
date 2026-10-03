"""Detection rules over ParsedEvent streams.

Each rule is a pure function: (events) -> list[Finding].
Design: one finding per *burst*. A burst anchors on its first event and grows
while subsequent events stay within `window_sec` of that anchor. This avoids
the classic "rolling window emits duplicates" trap and matches how SOC tooling
actually alerts (one alert per attack campaign, not per attempt).
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from app.config import get_settings
from app.detection.base import Finding
from app.parsers.base import ParsedEvent


# ---------- Helpers ----------

def _kind(e: ParsedEvent) -> str:
    return str(e.detail.get("kind", ""))


def _bursts(
    events: Iterable[tuple[int, ParsedEvent]],
    window_sec: int,
) -> Iterable[list[tuple[int, ParsedEvent]]]:
    """Yield disjoint bursts. Assumes input sorted ascending by ts."""
    burst: list[tuple[int, ParsedEvent]] = []
    for idx, ev in events:
        if not burst:
            burst = [(idx, ev)]
            continue
        if (ev.ts - burst[0][1].ts).total_seconds() <= window_sec:
            burst.append((idx, ev))
        else:
            yield burst
            burst = [(idx, ev)]
    if burst:
        yield burst


# ---------- Rule 1: repeated failed logins ----------

FAILED_KINDS = {"ssh_failed_password", "pam_auth_failure", "ssh_invalid_user"}


def rule_brute_force(events: list[ParsedEvent]) -> list[Finding]:
    s = get_settings()
    threshold = s.FAILED_LOGIN_THRESHOLD
    window_sec = s.FAILED_LOGIN_WINDOW_SEC

    per_ip: dict[str, list[tuple[int, ParsedEvent]]] = defaultdict(list)
    for idx, ev in enumerate(events):
        if _kind(ev) in FAILED_KINDS and ev.source_ip:
            per_ip[ev.source_ip].append((idx, ev))

    findings: list[Finding] = []
    for ip, seq in per_ip.items():
        seq.sort(key=lambda t: t[1].ts)
        for group in _bursts(seq, window_sec):
            count = len(group)
            if count < threshold:
                continue
            win_start = group[0][1].ts
            win_end = group[-1][1].ts
            usernames = sorted({e.user for _, e in group if e.user})
            findings.append(
                Finding(
                    rule="brute_force",
                    severity="critical" if count >= threshold * 2 else "warning",
                    ts=win_end,
                    source_ip=ip,
                    count=count,
                    window_start=win_start,
                    window_end=win_end,
                    summary=(
                        f"{count} failed auth attempts from {ip} within "
                        f"{int((win_end - win_start).total_seconds())}s "
                        f"(threshold {threshold}); targets={usernames}"
                    ),
                    detail={"usernames": usernames, "threshold": threshold},
                    event_indices=[i for i, _ in group],
                )
            )
    return findings


# ---------- Rule 2: port scan (from network events) ----------

def rule_port_scan(events: list[ParsedEvent]) -> list[Finding]:
    s = get_settings()
    distinct_ports = s.PORTSCAN_DISTINCT_PORTS
    window_sec = s.PORTSCAN_WINDOW_SEC

    per_ip: dict[str, list[tuple[int, ParsedEvent]]] = defaultdict(list)
    for idx, ev in enumerate(events):
        if ev.event_type == "net" and ev.source_ip and ev.dest_port is not None:
            per_ip[ev.source_ip].append((idx, ev))

    findings: list[Finding] = []
    for ip, seq in per_ip.items():
        seq.sort(key=lambda t: t[1].ts)
        for group in _bursts(seq, window_sec):
            ports = sorted({e.dest_port for _, e in group if e.dest_port is not None})
            if len(ports) < distinct_ports:
                continue
            win_start = group[0][1].ts
            win_end = group[-1][1].ts
            findings.append(
                Finding(
                    rule="port_scan",
                    severity="warning",
                    ts=win_end,
                    source_ip=ip,
                    count=len(ports),
                    window_start=win_start,
                    window_end=win_end,
                    summary=(
                        f"Possible port scan: {ip} touched {len(ports)} distinct "
                        f"ports in {int((win_end - win_start).total_seconds())}s"
                    ),
                    detail={"ports": ports, "threshold": distinct_ports},
                    event_indices=[i for i, _ in group],
                )
            )
    return findings


# ---------- Rule 3: suspicious connection ----------

def rule_suspicious_connection(events: list[ParsedEvent]) -> list[Finding]:
    """- >= 2 invalid-user hits from same IP -> notice
       - >= 3 preauth disconnects from same IP -> warning
    """
    inv: dict[str, list[tuple[int, ParsedEvent]]] = defaultdict(list)
    disc: dict[str, list[tuple[int, ParsedEvent]]] = defaultdict(list)

    for idx, ev in enumerate(events):
        if not ev.source_ip:
            continue
        k = _kind(ev)
        if k == "ssh_invalid_user":
            inv[ev.source_ip].append((idx, ev))
        elif k in {"ssh_conn_closed", "ssh_disconnected", "ssh_recv_disconnect"}:
            disc[ev.source_ip].append((idx, ev))

    findings: list[Finding] = []
    for ip, seq in inv.items():
        if len(seq) >= 2:
            seq.sort(key=lambda t: t[1].ts)
            findings.append(
                Finding(
                    rule="suspicious_connection",
                    severity="notice",
                    ts=seq[-1][1].ts,
                    source_ip=ip,
                    count=len(seq),
                    window_start=seq[0][1].ts,
                    window_end=seq[-1][1].ts,
                    summary=f"Multiple invalid-user attempts ({len(seq)}) from {ip}",
                    detail={"reason": "invalid_user_burst"},
                    event_indices=[i for i, _ in seq],
                )
            )
    for ip, seq in disc.items():
        if len(seq) >= 3:
            seq.sort(key=lambda t: t[1].ts)
            findings.append(
                Finding(
                    rule="suspicious_connection",
                    severity="warning",
                    ts=seq[-1][1].ts,
                    source_ip=ip,
                    count=len(seq),
                    window_start=seq[0][1].ts,
                    window_end=seq[-1][1].ts,
                    summary=f"Burst of preauth disconnects ({len(seq)}) from {ip}",
                    detail={"reason": "preauth_disconnect_burst"},
                    event_indices=[i for i, _ in seq],
                )
            )
    return findings


ALL_RULES = (rule_brute_force, rule_port_scan, rule_suspicious_connection)


def run_all(events: list[ParsedEvent]) -> list[Finding]:
    """Run every rule and return the combined, deduplicated findings."""
    out: list[Finding] = []
    for rule in ALL_RULES:
        out.extend(rule(events))
    order = {"info": 0, "notice": 1, "warning": 2, "error": 3, "critical": 4}
    best: dict[str, Finding] = {}
    for f in out:
        k = f.key()
        if k not in best or order[f.severity] > order[best[k].severity]:
            best[k] = f
    return sorted(best.values(), key=lambda f: f.ts)
