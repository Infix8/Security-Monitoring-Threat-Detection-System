import hashlib
import os

import pytest

from app.api.app import create_app
from app.db import session_scope
from app.models import ApiKey


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _add_key(name: str, scope: str, raw: str) -> None:
    with session_scope() as s:
        s.add(ApiKey(name=name, key_hash=hashlib.sha256(raw.encode()).hexdigest(), scope=scope))


def test_no_auth_needed_when_disabled(client, monkeypatch):
    monkeypatch.setenv("API_AUTH_ENABLED", "false")
    r = client.get("/api/events?limit=1")
    assert r.status_code == 200


def test_missing_key_rejected(client, monkeypatch):
    monkeypatch.setenv("API_AUTH_ENABLED", "true")
    r = client.get("/api/events?limit=1")
    assert r.status_code == 401
    assert r.get_json()["error"] == "unauthorized"


def test_invalid_key_rejected(client, monkeypatch):
    monkeypatch.setenv("API_AUTH_ENABLED", "true")
    r = client.get("/api/events?limit=1", headers={"X-API-Key": "nope"})
    assert r.status_code == 401


def test_read_only_key_cannot_write(client, monkeypatch):
    monkeypatch.setenv("API_AUTH_ENABLED", "true")
    _add_key("reader", "read", "raw-reader-key")
    r = client.post(
        "/api/scans",
        headers={"X-API-Key": "raw-reader-key"},
        json={"target": "127.0.0.1", "ports": [22]},
    )
    assert r.status_code == 403
    assert "lacks scope" in r.get_json()["detail"]


def test_valid_write_key_can_write(client, monkeypatch):
    monkeypatch.setenv("API_AUTH_ENABLED", "true")
    _add_key("writer", "read,write", "raw-writer-key")
    r = client.post(
        "/api/scans",
        headers={"X-API-Key": "raw-writer-key"},
        json={"target": "127.0.0.1", "ports": [22], "banners": False},
    )
    assert r.status_code == 201


def test_revoked_key_rejected(client, monkeypatch):
    from datetime import datetime, timezone
    monkeypatch.setenv("API_AUTH_ENABLED", "true")
    _add_key("dying", "read,write", "raw-dying-key")
    with session_scope() as s:
        from sqlalchemy import select
        row = s.execute(select(ApiKey).where(ApiKey.name == "dying")).scalar_one()
        row.revoked_at = datetime.now(timezone.utc)
    r = client.get("/api/events?limit=1", headers={"X-API-Key": "raw-dying-key"})
    assert r.status_code == 401
