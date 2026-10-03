"""SQLAlchemy ORM models: events, threats, threat_events, scans."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class Event(Base):
    """A single parsed log line from auth, syslog, or network capture."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="info", index=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), index=True)
    source_port: Mapped[Optional[int]] = mapped_column(Integer)
    dest_ip: Mapped[Optional[str]] = mapped_column(String(45), index=True)
    dest_port: Mapped[Optional[int]] = mapped_column(Integer)
    user: Mapped[Optional[str]] = mapped_column(String(128))
    message: Mapped[Optional[str]] = mapped_column(Text)
    raw: Mapped[Optional[str]] = mapped_column(Text)
    dedup_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    threat_links = relationship(
        "ThreatEvent", back_populates="event", cascade="all, delete-orphan"
    )


class Threat(Base):
    """A detection rule hit, aggregated over a window of events."""

    __tablename__ = "threats"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    rule: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), index=True)
    count: Mapped[int] = mapped_column(Integer, default=1)
    window_start: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    summary: Mapped[Optional[str]] = mapped_column(Text)
    dedup_key: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    event_links = relationship(
        "ThreatEvent", back_populates="threat", cascade="all, delete-orphan"
    )


class ThreatEvent(Base):
    """Join table: which events contributed to which threat."""

    __tablename__ = "threat_events"

    threat_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("threats.id", ondelete="CASCADE"), primary_key=True
    )
    event_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("events.id", ondelete="CASCADE"), primary_key=True
    )

    threat = relationship("Threat", back_populates="event_links")
    event = relationship("Event", back_populates="threat_links")


class Scan(Base):
    """A port-scan run against an authorized target."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    target_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    scan_type: Mapped[str] = mapped_column(String(32), nullable=False, default="tcp_connect")
    open_ports: Mapped[list[int]] = mapped_column(JSONB, default=list)
    services: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer)
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )



class ApiKey(Base):
    """API keys for the REST layer. Only the SHA-256 hash is stored."""

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    scope: Mapped[str] = mapped_column(String(64), nullable=False, default="read")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
