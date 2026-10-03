"""Flask application factory for the secmon REST API."""
from __future__ import annotations

from datetime import datetime, timezone

from flask import Flask, jsonify

from app.config import get_settings
from app.db import ping
from app.api.routes import bp


def create_app() -> Flask:
    settings = get_settings()
    app = Flask(settings.APP_NAME)

    app.register_blueprint(bp, url_prefix="/api")

    @app.get("/")
    def root():
        return jsonify({
            "service": settings.APP_NAME,
            "env": settings.APP_ENV,
            "time": datetime.now(timezone.utc).isoformat(),
            "api_root": "/api",
        })

    @app.get("/healthz")
    def healthz():
        try:
            ok = ping()
        except Exception as exc:  # pragma: no cover
            return jsonify({"status": "error", "error": str(exc)}), 503
        code = 200 if ok else 503
        return jsonify({"status": "ok" if ok else "degraded", "db": ok}), code

    return app
