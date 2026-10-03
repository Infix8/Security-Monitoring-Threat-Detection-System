import pytest

from app.api.app import create_app
from app.db import session_scope
from app.models import ScanAudit


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _audit_rows():
    with session_scope() as s:
        return s.query(ScanAudit).order_by(ScanAudit.id).all()


def test_allowed_scan_creates_audit_row(client, monkeypatch):
    monkeypatch.setenv("API_AUTH_ENABLED", "false")
    r = client.post(
        "/api/scans",
        json={"target": "127.0.0.1", "ports": [22], "banners": False},
    )
    assert r.status_code == 201
    body = r.get_json()
    assert "audit_id" in body

    rows = _audit_rows()
    assert len(rows) == 1
    a = rows[0]
    assert a.target_ip == "127.0.0.1"
    assert a.allowed is True
    assert a.scan_id == body["id"]
    assert a.requester == "anonymous"  # auth disabled


def test_forbidden_scan_leaves_audit_row(client, monkeypatch):
    monkeypatch.setenv("API_AUTH_ENABLED", "false")
    r = client.post(
        "/api/scans",
        json={"target": "8.8.8.8", "ports": [80], "banners": False},
    )
    assert r.status_code == 403

    rows = _audit_rows()
    assert len(rows) == 1
    a = rows[0]
    assert a.target_ip == "8.8.8.8"
    assert a.allowed is False
    assert "not inside SCAN_ALLOWED_CIDRS" in (a.reason or "")
    assert a.scan_id is None


def test_audit_records_requester_from_api_key(client, monkeypatch):
    import hashlib
    from app.models import ApiKey

    monkeypatch.setenv("API_AUTH_ENABLED", "true")
    with session_scope() as s:
        s.add(ApiKey(
            name="alice",
            key_hash=hashlib.sha256(b"alice-key").hexdigest(),
            scope="read,write",
        ))

    r = client.post(
        "/api/scans",
        headers={"X-API-Key": "alice-key"},
        json={"target": "127.0.0.1", "ports": [22], "banners": False},
    )
    assert r.status_code == 201

    rows = _audit_rows()
    assert rows[0].requester == "alice"


def test_list_endpoint_returns_audit_rows(client, monkeypatch):
    monkeypatch.setenv("API_AUTH_ENABLED", "false")
    client.post("/api/scans", json={"target": "127.0.0.1", "ports": [22], "banners": False})
    client.post("/api/scans", json={"target": "8.8.8.8", "ports": [80]})

    r = client.get("/api/scan_audit")
    assert r.status_code == 200
    body = r.get_json()
    assert body["count"] == 2
    targets = sorted(x["target_ip"] for x in body["items"])
    assert targets == ["127.0.0.1", "8.8.8.8"]


def test_list_endpoint_filter_by_allowed(client, monkeypatch):
    monkeypatch.setenv("API_AUTH_ENABLED", "false")
    client.post("/api/scans", json={"target": "127.0.0.1", "ports": [22], "banners": False})
    client.post("/api/scans", json={"target": "8.8.8.8", "ports": [80]})

    denied = client.get("/api/scan_audit?allowed=false").get_json()
    assert denied["count"] == 1
    assert denied["items"][0]["target_ip"] == "8.8.8.8"

    ok = client.get("/api/scan_audit?allowed=true").get_json()
    assert ok["count"] == 1
    assert ok["items"][0]["target_ip"] == "127.0.0.1"
