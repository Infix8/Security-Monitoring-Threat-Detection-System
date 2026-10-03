"""Flask-Limiter instance.

Storage is in-memory. In a multi-worker deployment each gunicorn worker keeps
its own counter, so the effective rate is N x the configured value. For a
single-source-of-truth limit, point `storage_uri` at Redis.
"""
from __future__ import annotations

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri="memory://",
    headers_enabled=True,
)
