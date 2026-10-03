"""Hit every endpoint once and print a compact summary."""
import json
import sys
import urllib.request

BASE = "http://127.0.0.1:8000"


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=5) as r:
        return r.status, json.loads(r.read().decode())


def show(path):
    try:
        status, body = get(path)
    except Exception as e:
        print(f"  GET {path:<40} ERROR {e}")
        return None
    preview = json.dumps(body)[:120]
    print(f"  GET {path:<40} {status}  {preview}...")
    return body


print(f"API smoke test against {BASE}\n")
show("/")
show("/healthz")
show("/api/events?limit=3")
show("/api/events/1")
show("/api/threats")
show("/api/threats/1")
show("/api/summary")

# Assertions for exit code
try:
    _, h = get("/healthz")
    _, s = get("/api/summary")
    _, t = get("/api/threats")
    assert h["status"] == "ok", h
    assert s["threats"]["total"] >= 1, s
    assert t["count"] >= 1, t
    print("\nall smoke checks OK")
except AssertionError as e:
    print("FAILED:", e); sys.exit(1)
