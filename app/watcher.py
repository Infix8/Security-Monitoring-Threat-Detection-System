"""Polling log tailer that feeds new lines into the ingest pipeline.

Design choices:
  - Polling, not inotify: works on overlayfs, NFS, and inside containers.
  - State is a JSON file keyed by inode + offset: restarts resume cleanly.
  - Rotation detection: if inode changes, restart from offset 0.
  - Same parse -> persist -> detect pipeline as scripts/ingest_sample.py.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from app.ingest import persist_events, persist_findings
from app.detection.rules import run_all
from app.parsers.auth import parse_line as parse_auth_line
from app.parsers.ufw import parse_line as parse_ufw_line
from app.parsers.base import ParsedEvent

log = logging.getLogger("secmon.watcher")

PARSERS = {
    "auth": parse_auth_line,
    "ufw":  parse_ufw_line,
}

STATE_DIR = Path(os.getenv("WATCHER_STATE_DIR", ".state"))


# ---------- state ----------

@dataclass
class WatcherState:
    inode: int = -1
    offset: int = 0
    processed_lines: int = 0
    rotations: int = 0

    def to_json(self) -> dict:
        return {
            "inode": self.inode,
            "offset": self.offset,
            "processed_lines": self.processed_lines,
            "rotations": self.rotations,
        }

    @classmethod
    def from_json(cls, d: dict) -> "WatcherState":
        return cls(
            inode=int(d.get("inode", -1)),
            offset=int(d.get("offset", 0)),
            processed_lines=int(d.get("processed_lines", 0)),
            rotations=int(d.get("rotations", 0)),
        )


def state_path(name: str) -> Path:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    return STATE_DIR / f"watcher-{name}.json"


def load_state(name: str) -> WatcherState:
    p = state_path(name)
    if p.exists():
        try:
            return WatcherState.from_json(json.loads(p.read_text()))
        except (json.JSONDecodeError, OSError, ValueError):
            log.warning("state file %s unreadable, starting fresh", p)
    return WatcherState()


def save_state(name: str, st: WatcherState) -> None:
    p = state_path(name)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(st.to_json()))
    tmp.replace(p)


# ---------- tailer ----------

@dataclass
class TailerStats:
    lines_seen: int = 0
    lines_parsed: int = 0
    lines_ignored: int = 0
    events_inserted: int = 0
    events_skipped: int = 0
    findings: int = 0
    threats_inserted: int = 0
    threats_skipped: int = 0
    rotations: int = 0
    errors: int = 0
    started_at: float = field(default_factory=time.time)

    def summary(self) -> dict:
        return {**self.__dict__, "uptime_sec": int(time.time() - self.started_at)}


def read_new_lines(path: Path, st: WatcherState) -> tuple[list[str], bool]:
    """Return (new_lines, rotated). Updates st.inode/st.offset in place."""
    if not path.exists():
        return [], False

    cur_inode = path.stat().st_ino
    rotated = False

    if cur_inode != st.inode:
        if st.inode != -1:
            log.info("rotation detected on %s (inode %s -> %s)",
                     path, st.inode, cur_inode)
            rotated = True
        st.inode = cur_inode
        st.offset = 0

    lines: list[str] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        fh.seek(st.offset)
        for raw in fh:
            lines.append(raw)
        st.offset = fh.tell()
    return lines, rotated


def process_batch(raw_lines: list[str], parser_fn, stats: TailerStats) -> None:
    parsed: list[ParsedEvent] = []
    for raw in raw_lines:
        stats.lines_seen += 1
        ev = parser_fn(raw)
        if ev is None:
            stats.lines_ignored += 1
            continue
        parsed.append(ev)

    stats.lines_parsed += len(parsed)
    if not parsed:
        return

    e_ins, e_skip, _ = persist_events(parsed)
    stats.events_inserted += e_ins
    stats.events_skipped += e_skip

    findings = run_all(parsed)
    stats.findings += len(findings)
    if findings:
        t_ins, t_skip = persist_findings(findings, parsed)
        stats.threats_inserted += t_ins
        stats.threats_skipped += t_skip


def watch(
    name: str,
    path: Path,
    interval: float = 2.0,
    once: bool = False,
    run_seconds: Optional[float] = None,
) -> TailerStats:
    parser_fn = PARSERS.get(name)
    if parser_fn is None:
        raise ValueError(f"no parser registered for source '{name}'")

    st = load_state(name)
    stats = TailerStats()
    stop = False

    def _signal(_signum, _frame):
        nonlocal stop
        stop = True
        log.info("stop signal received, finishing current batch")

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _signal)
        except ValueError:
            pass

    started = time.time()
    log.info("watching %s (source=%s, interval=%.1fs)", path, name, interval)

    while not stop:
        try:
            lines, rotated = read_new_lines(path, st)
            if rotated:
                st.rotations += 1
                stats.rotations += 1
            if lines:
                process_batch(lines, parser_fn, stats)
            if lines or rotated:
                save_state(name, st)
        except Exception as exc:  # noqa: BLE001
            stats.errors += 1
            log.exception("watcher iteration failed: %s", exc)

        if once:
            break
        if run_seconds is not None and (time.time() - started) >= run_seconds:
            break
        time.sleep(interval)

    save_state(name, st)
    log.info("watcher exiting; stats=%s", stats.summary())
    return stats


# ---------- CLI ----------

def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="python -m app.watcher")
    p.add_argument("--source", default="auth", choices=sorted(PARSERS.keys()))
    p.add_argument("--path", required=True, help="path to log file")
    p.add_argument("--interval", type=float, default=2.0)
    p.add_argument("--once", action="store_true",
                   help="process whatever is new and exit")
    p.add_argument("--run-seconds", type=float, default=None,
                   help="exit after N seconds (for CI/smoke)")
    p.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "INFO"))
    args = p.parse_args(argv)

    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    stats = watch(
        name=args.source,
        path=Path(args.path),
        interval=args.interval,
        once=args.once,
        run_seconds=args.run_seconds,
    )
    print(json.dumps(stats.summary(), indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
