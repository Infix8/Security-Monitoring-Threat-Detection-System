"""Parse sample_logs/auth.log, synthesize a port-scan trace, run all rules."""
import sys
sys.path.insert(0, ".")

from datetime import datetime, timedelta, timezone

from app.detection.rules import run_all
from app.parsers.auth import parse_file
from app.parsers.base import ParsedEvent

# 1) Real auth events from our fixture
events = list(parse_file("sample_logs/auth.log"))

# 2) Synthetic network events simulating a port scan from 10.9.9.9
base = datetime(2026, 10, 3, 13, 20, 0, tzinfo=timezone.utc)
for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                          993, 995, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 8080]):
    events.append(ParsedEvent(
        ts=base + timedelta(seconds=i * 2),
        event_type="net",
        severity="info",
        message=f"SYN to 10.0.0.5:{port}",
        raw="synthetic",
        source_ip="10.9.9.9",
        source_port=40000 + i,
        dest_ip="10.0.0.5",
        dest_port=port,
        detail={"kind": "tcp_syn"},
    ))

findings = run_all(events)

print(f"input events  => {len(events)}")
print(f"findings      => {len(findings)}\n")
for f in findings:
    print(
        f"[{f.severity:<8}] {f.rule:<22} src={f.source_ip:<16} "
        f"count={f.count:<3} window={int((f.window_end - f.window_start).total_seconds())}s"
    )
    print(f"    {f.summary}")
    print(f"    key={f.key()}")
    print(f"    events={len(f.event_indices)}")
