"""Run the auth parser over sample_logs/auth.log and print a summary."""
import sys
from collections import Counter
sys.path.insert(0, ".")

from app.parsers.auth import parse_file

path = "sample_logs/auth.log"
events = list(parse_file(path))

print(f"parsed {len(events)} events from {path}\n")
print(f"{'ts':<25} {'sev':<8} {'user':<10} {'src_ip':<16} {'sport':<6} kind")
print("-" * 90)
for e in events:
    print(
        f"{e.ts.strftime('%Y-%m-%d %H:%M:%S'):<25} "
        f"{e.severity:<8} "
        f"{(e.user or '-'):<10} "
        f"{(e.source_ip or '-'):<16} "
        f"{(str(e.source_port) if e.source_port else '-'):<6} "
        f"{e.detail.get('kind')}"
    )

print("\n--- severities ---")
for k, v in Counter(e.severity for e in events).most_common():
    print(f"  {k:<10} {v}")

print("\n--- kinds ---")
for k, v in Counter(e.detail.get('kind') for e in events).most_common():
    print(f"  {k:<22} {v}")
