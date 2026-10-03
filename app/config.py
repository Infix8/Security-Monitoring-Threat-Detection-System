"""Central configuration loaded from environment variables."""
from __future__ import annotations

import os
from functools import lru_cache

from dotenv import load_dotenv

load_dotenv()


def _get_int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, default))
    except (TypeError, ValueError):
        return default


class Settings:
    # App
    APP_NAME: str = os.getenv("APP_NAME", "secmon")
    APP_ENV: str = os.getenv("APP_ENV", "dev")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = _get_int("API_PORT", 8000)

    # Database
    POSTGRES_HOST: str = os.getenv("POSTGRES_HOST", "localhost")
    POSTGRES_PORT: int = _get_int("POSTGRES_PORT", 5432)
    POSTGRES_DB: str = os.getenv("POSTGRES_DB", "secmon")
    POSTGRES_USER: str = os.getenv("POSTGRES_USER", "secmon")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "secmon")

    # Ingestion
    AUTH_LOG_PATH: str = os.getenv("AUTH_LOG_PATH", "/var/log/auth.log")
    SYSLOG_PATH: str = os.getenv("SYSLOG_PATH", "/var/log/syslog")

    # Detection
    FAILED_LOGIN_THRESHOLD: int = _get_int("FAILED_LOGIN_THRESHOLD", 5)
    FAILED_LOGIN_WINDOW_SEC: int = _get_int("FAILED_LOGIN_WINDOW_SEC", 300)
    PORTSCAN_DISTINCT_PORTS: int = _get_int("PORTSCAN_DISTINCT_PORTS", 15)
    PORTSCAN_WINDOW_SEC: int = _get_int("PORTSCAN_WINDOW_SEC", 60)

    # Scanner
    SCAN_ALLOWED_CIDRS: str = os.getenv(
        "SCAN_ALLOWED_CIDRS", "127.0.0.1/32,10.0.0.0/8,192.168.0.0/16"
    )

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+psycopg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
