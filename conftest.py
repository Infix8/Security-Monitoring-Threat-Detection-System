"""Pytest configuration: run tests against an isolated database.

CRITICAL: this file must set POSTGRES_DB before any `app.*` module is imported,
because `app.config.get_settings()` reads the env once and caches it.
"""
import os
os.environ["POSTGRES_DB"] = "secmon_test"

import subprocess  # noqa: E402
import pytest  # noqa: E402

from sqlalchemy import text  # noqa: E402

from app.db import engine  # noqa: E402


def _psql(sql: str, db: str = "postgres") -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "exec", "secmon-db", "psql", "-U", "secmon", "-d", db, "-tAc", sql],
        capture_output=True, text=True,
    )


@pytest.fixture(scope="session", autouse=True)
def _prepare_test_db():
    """Create secmon_test if missing and run migrations against it."""
    r = _psql("SELECT 1 FROM pg_database WHERE datname='secmon_test'")
    if "1" not in r.stdout:
        subprocess.run(
            ["docker", "exec", "secmon-db", "psql", "-U", "secmon", "-d", "postgres",
             "-c", "CREATE DATABASE secmon_test"],
            check=True, capture_output=True,
        )
    env = {**os.environ, "POSTGRES_DB": "secmon_test"}
    subprocess.run(["alembic", "upgrade", "head"], check=True, env=env,
                   capture_output=True)
    yield


@pytest.fixture(autouse=True)
def _clean_tables():
    """Wipe the test DB tables before each test."""
    with engine.begin() as conn:
        conn.execute(text(
            "TRUNCATE threat_events, threats, events, scans, api_keys RESTART IDENTITY CASCADE"
        ))
    yield
