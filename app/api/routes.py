"""REST endpoints for events, threats, and summary."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request
from sqlalchemy import desc, func, select

from app.db import session_scope
from app.models import Event, Threat, ThreatEvent

bp = Blueprint("api", __name__)


# ---------- helpers ----------

def _iso(dt: datetime | None) -> str | None:
    return dt.astimezone(timezone.utc).isoformat() if dt else None


def _int_arg(name: str, default: int, lo: int, hi: int) -> int:
    try:
        v = int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, v))


def _since_arg() -> datetime | None:
    """`since` accepts ISO-8601 or `<N><s|m|h|d>` (e.g. 30m, 24h)."""
    raw = request.args.get("since")
    if not raw:
        return None
    raw = raw.strip()
    if raw and raw[-1] in "smhd" and raw[:-1].isdigit():
        n = int(raw[:-1])
        unit = {"s": 1, "m": 60, "h": 3600, "d": 86400}[raw[-1]]
        return datetime.now(timezone.utc) - timedelta(seconds=n * unit)
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _event_to_dict(e: Event) -> dict:
    return {
        "id": e.id,
        "ts": _iso(e.ts),
        "event_type": e.event_type,
        "severity": e.severity,
        "source_ip": e.source_ip,
        "source_port": e.source_port,
        "dest_ip": e.dest_ip,
        "dest_port": e.dest_port,
        "user": e.user,
        "message": e.message,
        "detail": e.detail,
    }


def _threat_to_dict(t: Threat, linked_ids: list[int] | None = None) -> dict:
    return {
        "id": t.id,
        "ts": _iso(t.ts),
        "rule": t.rule,
        "severity": t.severity,
        "source_ip": t.source_ip,
        "count": t.count,
        "window_start": _iso(t.window_start),
        "window_end": _iso(t.window_end),
        "summary": t.summary,
        "detail": t.detail,
        "linked_event_ids": linked_ids,
    }


# ---------- events ----------

@bp.get("/events")
def list_events():
    limit = _int_arg("limit", 50, 1, 500)
    severity = request.args.get("severity")
    source_ip = request.args.get("source_ip")
    event_type = request.args.get("event_type")
    since = _since_arg()

    with session_scope() as s:
        q = select(Event)
        if severity:
            q = q.where(Event.severity == severity)
        if source_ip:
            q = q.where(Event.source_ip == source_ip)
        if event_type:
            q = q.where(Event.event_type == event_type)
        if since:
            q = q.where(Event.ts >= since)
        q = q.order_by(desc(Event.ts)).limit(limit)
        rows = s.execute(q).scalars().all()
        return jsonify({
            "count": len(rows),
            "items": [_event_to_dict(e) for e in rows],
        })


@bp.get("/events/<int:eid>")
def get_event(eid: int):
    with session_scope() as s:
        e = s.get(Event, eid)
        if not e:
            return jsonify({"error": "not found"}), 404
        return jsonify(_event_to_dict(e))


# ---------- threats ----------

@bp.get("/threats")
def list_threats():
    limit = _int_arg("limit", 50, 1, 500)
    rule = request.args.get("rule")
    severity = request.args.get("severity")
    since = _since_arg()

    with session_scope() as s:
        q = select(Threat)
        if rule:
            q = q.where(Threat.rule == rule)
        if severity:
            q = q.where(Threat.severity == severity)
        if since:
            q = q.where(Threat.ts >= since)
        q = q.order_by(desc(Threat.ts)).limit(limit)
        rows = s.execute(q).scalars().all()
        return jsonify({
            "count": len(rows),
            "items": [_threat_to_dict(t) for t in rows],
        })


@bp.get("/threats/<int:tid>")
def get_threat(tid: int):
    with session_scope() as s:
        t = s.get(Threat, tid)
        if not t:
            return jsonify({"error": "not found"}), 404
        linked = s.execute(
            select(ThreatEvent.event_id).where(ThreatEvent.threat_id == tid)
        ).scalars().all()
        return jsonify(_threat_to_dict(t, linked_ids=list(linked)))


# ---------- summary ----------

@bp.get("/summary")
def summary():
    window = request.args.get("window", "24h")
    since = _since_arg() or (datetime.now(timezone.utc) - timedelta(hours=24))
    _ = window  # currently informational

    with session_scope() as s:
        total_events = s.scalar(select(func.count()).select_from(Event).where(Event.ts >= since))
        total_threats = s.scalar(select(func.count()).select_from(Threat).where(Threat.ts >= since))

        by_sev = dict(s.execute(
            select(Event.severity, func.count())
            .where(Event.ts >= since)
            .group_by(Event.severity)
        ).all())

        by_rule = dict(s.execute(
            select(Threat.rule, func.count())
            .where(Threat.ts >= since)
            .group_by(Threat.rule)
        ).all())

        top_src = [
            {"source_ip": ip, "threats": cnt}
            for ip, cnt in s.execute(
                select(Threat.source_ip, func.count())
                .where(Threat.ts >= since, Threat.source_ip.is_not(None))
                .group_by(Threat.source_ip)
                .order_by(func.count().desc())
                .limit(5)
            ).all()
        ]

        return jsonify({
            "since": _iso(since),
            "events": {"total": total_events, "by_severity": by_sev},
            "threats": {"total": total_threats, "by_rule": by_rule},
            "top_source_ips": top_src,
        })


# ---------- scans ----------

from app.models import Scan  # noqa: E402
from app.scanner.portscan import (  # noqa: E402
    DEFAULT_TOP_PORTS,
    ScanNotAllowed,
    scan_target,
)
from app.scanner.store import save_scan  # noqa: E402


def _scan_to_dict(s: Scan) -> dict:
    return {
        "id": s.id,
        "ts": _iso(s.ts),
        "target_ip": s.target_ip,
        "scan_type": s.scan_type,
        "open_ports": s.open_ports,
        "services": s.services,
        "duration_ms": s.duration_ms,
        "detail": s.detail,
    }


@bp.get("/scans")
def list_scans():
    limit = _int_arg("limit", 50, 1, 500)
    target = request.args.get("target_ip")
    with session_scope() as s:
        q = select(Scan)
        if target:
            q = q.where(Scan.target_ip == target)
        q = q.order_by(desc(Scan.ts)).limit(limit)
        rows = s.execute(q).scalars().all()
        return jsonify({"count": len(rows), "items": [_scan_to_dict(x) for x in rows]})


@bp.get("/scans/<int:sid>")
def get_scan(sid: int):
    with session_scope() as s:
        row = s.get(Scan, sid)
        if not row:
            return jsonify({"error": "not found"}), 404
        return jsonify(_scan_to_dict(row))


@bp.post("/scans")
def create_scan():
    body = request.get_json(silent=True) or {}
    target = body.get("target")
    ports = body.get("ports") or DEFAULT_TOP_PORTS
    banners = bool(body.get("banners", True))

    if not target:
        return jsonify({"error": "target is required"}), 400
    if not isinstance(ports, list) or not ports:
        return jsonify({"error": "ports must be a non-empty list"}), 400
    try:
        ports = [int(p) for p in ports]
    except (TypeError, ValueError):
        return jsonify({"error": "ports must be integers"}), 400

    try:
        result = scan_target(target, ports, banners=banners)
    except ScanNotAllowed as exc:
        return jsonify({"error": "forbidden", "detail": str(exc)}), 403
    except OSError as exc:
        return jsonify({"error": "scan failed", "detail": str(exc)}), 500

    sid = save_scan(result)
    return jsonify({"id": sid, **{k: (v.isoformat() if hasattr(v, "isoformat") else v)
                                  for k, v in result.items()}}), 201
