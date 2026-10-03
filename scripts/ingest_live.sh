#!/usr/bin/env bash
# Copy /var/log/auth.log into the API container and run the ingest pipeline.
# Run on the target host (needs read access to /var/log/auth.log).
set -euo pipefail
cd "$(dirname "$0")/.."

SRC="${1:-/var/log/auth.log}"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

echo "==> copying $SRC"
sudo cat "$SRC" > "$TMP"

echo "==> running ingest inside container"
docker compose exec -T api python - <<PY
import sys
sys.path.insert(0, "/app")
from app.ingest import ingest_auth_file
result = ingest_auth_file("$TMP")
for k, v in result.items():
    print(f"  {k:<18} {v}")
PY
