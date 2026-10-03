"""API key auth: X-API-Key header, scope-checked.

`API_AUTH_ENABLED` is read at *request time* (not module import) so tests can
toggle it per-case. When disabled (default in dev), the decorator is a no-op.
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from functools import wraps
from typing import Callable, Optional

from flask import current_app, g, jsonify, request
from sqlalchemy import select

from app.db import session_scope
from app.models import ApiKey


def _auth_enabled() -> bool:
    return os.getenv("API_AUTH_ENABLED", "false").strip().lower() in ("1", "true", "yes", "on")


def hash_key(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _lookup(raw: str) -> Optional[ApiKey]:
    """Return the ApiKey row if the raw key matches and is not revoked."""
    if not raw:
        return None
    kh = hash_key(raw)
    with session_scope() as s:
        row = s.execute(select(ApiKey).where(ApiKey.key_hash == kh)).scalar_one_or_none()
        if row is None or row.revoked_at is not None:
            return None
        # Best-effort last_used stamp (not critical if it fails)
        try:
            row.last_used_at = datetime.now(timezone.utc)
        except Exception:  # pragma: no cover
            pass
        return row


def _scopes_of(row: ApiKey) -> set[str]:
    return {s.strip() for s in (row.scope or "").split(",") if s.strip()}


def require_scope(scope: str) -> Callable:
    """Decorator: reject unless the caller holds `scope` (or auth is disabled)."""

    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not _auth_enabled():
                g.api_key_name = "anonymous"
                g.api_key_scope = "read,write"
                return fn(*args, **kwargs)

            raw = request.headers.get("X-API-Key", "").strip()
            if not raw:
                return jsonify({"error": "unauthorized", "detail": "missing X-API-Key"}), 401

            row = _lookup(raw)
            if row is None:
                return jsonify({"error": "unauthorized", "detail": "invalid or revoked key"}), 401

            if scope not in _scopes_of(row):
                return jsonify({
                    "error": "forbidden",
                    "detail": f"key '{row.name}' lacks scope '{scope}'",
                }), 403

            g.api_key_name = row.name
            g.api_key_scope = row.scope
            return fn(*args, **kwargs)

        return wrapper

    return decorator
