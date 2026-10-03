"""Ingest sample_logs/auth.log twice; second run must insert nothing new."""
import sys
sys.path.insert(0, ".")

from app.db import session_scope
from app.ingest import ingest_auth_file
from app.models import Event, Threat, ThreatEvent
from sqlalchemy import func, select

PATH = "sample_logs/auth.log"


def counts():
    with session_scope() as s:
        return {
            "events": s.scalar(select(func.count()).select_from(Event)),
            "threats": s.scalar(select(func.count()).select_from(Threat)),
            "links": s.scalar(select(func.count()).select_from(ThreatEvent)),
        }


print(f"--- run #1 over {PATH} ---")
r1 = ingest_auth_file(PATH)
for k, v in r1.items():
    print(f"  {k:<20} {v}")
c1 = counts()
print(f"  db counts -> {c1}")

print(f"\n--- run #2 (idempotency check) ---")
r2 = ingest_auth_file(PATH)
for k, v in r2.items():
    print(f"  {k:<20} {v}")
c2 = counts()
print(f"  db counts -> {c2}")

assert r2["events_inserted"] == 0, "second run inserted duplicate events!"
assert r2["threats_inserted"] == 0, "second run inserted duplicate threats!"
assert c1 == c2, "row counts changed on second run"
print("\nidempotency OK")
