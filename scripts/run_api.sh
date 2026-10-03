#!/usr/bin/env bash
# Launch Flask dev server for local development.
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate
export FLASK_APP=wsgi:app
export FLASK_DEBUG=1
exec flask --app wsgi:app run --host 0.0.0.0 --port "${API_PORT:-8000}"
