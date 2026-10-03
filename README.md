# secmon — Security Monitoring & Threat Detection System

Python + Postgres + Flask stack that ingests Linux auth logs, runs detection
rules, exposes findings over a REST API, and scans authorized hosts for open
ports. Fully containerized; runs the same on a laptop or on EC2.

## Stack
- Python 3.12, SQLAlchemy 2, Alembic, psycopg 3
- Flask 3 + gunicorn
- PostgreSQL 16 (Docker)
- Docker + Compose

## Layout
    app/
      config.py         settings loaded from env
      db.py             engine, session_scope, Base
      models.py         events, threats, threat_events, scans
      ingest.py         parse -> persist events -> detect -> persist threats
      parsers/
        base.py         ParsedEvent dataclass
        auth.py         SSH auth.log parser
      detection/
        base.py         Finding dataclass
        rules.py        brute_force, port_scan, suspicious_connection
      scanner/
        portscan.py     allow-listed TCP connect scanner
        store.py        persist scan results
      api/
        app.py          Flask factory
        routes.py       /events, /threats, /summary, /scans
    alembic/            migrations
    docker/entrypoint.sh
    scripts/            dev + deploy helpers
    sample_logs/        fixtures for tests and demos
    tests/              pytest suite

## Quickstart (local dev, DB in Docker)
    cp .env.example .env       # then edit secrets
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    docker compose up -d db
    alembic upgrade head
    python scripts/ingest_sample.py
    bash scripts/run_api.sh
    # -> http://localhost:8000/healthz

## Full stack in Docker
    docker compose up -d --build
    curl -s localhost:8000/api/summary | python -m json.tool

## REST API (excerpt)
| Method | Path                | Notes                                |
|--------|---------------------|--------------------------------------|
| GET    | /healthz            | Liveness + DB ping                   |
| GET    | /api/events         | ?limit=&severity=&source_ip=&since=  |
| GET    | /api/events/<id>    | Single event                         |
| GET    | /api/threats        | ?limit=&rule=&severity=&since=       |
| GET    | /api/threats/<id>   | Threat + linked_event_ids            |
| GET    | /api/summary        | Counts by severity/rule, top IPs     |
| GET    | /api/scans          | Recent scans                         |
| POST   | /api/scans          | {"target":"127.0.0.1","ports":[...]} |

`since` accepts ISO-8601 or short forms like `30m`, `24h`, `7d`.

## Detection rules
- **brute_force** — >= `FAILED_LOGIN_THRESHOLD` failed auths from one IP
  within `FAILED_LOGIN_WINDOW_SEC`. Escalates to `critical` at 2x threshold.
- **port_scan** — one source touching >= `PORTSCAN_DISTINCT_PORTS` distinct
  dest ports within `PORTSCAN_WINDOW_SEC`.
- **suspicious_connection** — invalid-user bursts (>=2) and preauth
  disconnect bursts (>=3).

## Safety
`app/scanner/portscan.py` refuses any target outside `SCAN_ALLOWED_CIDRS`.
Only scan systems you own or have written authorization to test.

## Deploy to EC2
    git clone <repo> secmon && cd secmon
    cp .env.example .env && $EDITOR .env
    sudo bash scripts/deploy_ec2.sh
    # open 8000/tcp in the Security Group

## Tests
    pytest -q

## See also
- docs/security-notes.md — common web vulns + remediation
