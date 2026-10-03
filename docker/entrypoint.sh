#!/usr/bin/env bash
# Wait for DB, run migrations, then exec the CMD.
set -euo pipefail

echo "[entrypoint] waiting for postgres at ${POSTGRES_HOST}:${POSTGRES_PORT} ..."
python - <<'PY'
import os, time, socket, sys
host = os.getenv("POSTGRES_HOST", "db")
port = int(os.getenv("POSTGRES_PORT", "5432"))
for i in range(60):
    try:
        with socket.create_connection((host, port), timeout=1):
            print(f"[entrypoint] postgres reachable after {i} attempt(s)")
            sys.exit(0)
    except OSError:
        time.sleep(1)
print("[entrypoint] postgres unreachable after 60s", file=sys.stderr)
sys.exit(1)
PY

echo "[entrypoint] running alembic migrations ..."
alembic upgrade head

echo "[entrypoint] launching: $*"
exec "$@"
