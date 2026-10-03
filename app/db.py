"""SQLAlchemy engine + session factory."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings

settings = get_settings()

engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    future=True,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    """Base class for all ORM models."""


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope around a series of operations."""
    s = SessionLocal()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def ping() -> bool:
    """Return True if the DB answers SELECT 1."""
    with engine.connect() as conn:
        return conn.execute(text("SELECT 1")).scalar() == 1
