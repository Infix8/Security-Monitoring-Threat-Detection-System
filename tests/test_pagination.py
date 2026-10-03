from datetime import datetime, timedelta, timezone

import pytest

from app.api.app import create_app
from app.db import session_scope
from app.models import Event


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _seed(n: int):
    base = datetime(2026, 10, 3, 12, 0, 0, tzinfo=timezone.utc)
    with session_scope() as s:
        for i in range(n):
            s.add(Event(
                ts=base + timedelta(seconds=i),
                event_type="auth", severity="info",
                message=f"event {i}", raw=f"raw-{i}",
                dedup_hash=f"hash-{i}",
                detail={},
            ))


def test_pagination_walks_forward(client):
    _seed(7)
    seen = []
    cursor = None
    for _ in range(10):
        qs = "limit=3" + (f"&cursor={cursor}" if cursor else "")
        r = client.get(f"/api/events?{qs}")
        assert r.status_code == 200
        body = r.get_json()
        seen.extend(e["id"] for e in body["items"])
        cursor = body["next_cursor"]
        if not cursor:
            break
    assert len(seen) == 7
    assert len(set(seen)) == 7


def test_limit_bounds(client):
    _seed(3)
    r = client.get("/api/events?limit=99999")  # capped to 500
    assert r.status_code == 200
    assert r.get_json()["count"] == 3
