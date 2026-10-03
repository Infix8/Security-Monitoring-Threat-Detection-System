"""Authorized TCP connect port scanner with CIDR allow-list."""
from __future__ import annotations

import ipaddress
import select
import socket
import time
from datetime import datetime, timezone
from typing import Iterable, Optional

from app.config import get_settings


class ScanNotAllowed(PermissionError):
    """Raised when a target is outside the configured allow-list."""


def _allowed_networks() -> list:
    raw = get_settings().SCAN_ALLOWED_CIDRS
    nets = []
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if chunk:
            nets.append(ipaddress.ip_network(chunk, strict=False))
    return nets


def is_allowed(target: str) -> bool:
    ip = ipaddress.ip_address(target)
    return any(ip in net for net in _allowed_networks())


def assert_allowed(target: str) -> None:
    if not is_allowed(target):
        raise ScanNotAllowed(f"target {target} is not inside SCAN_ALLOWED_CIDRS")


def _tcp_connect(host: str, port: int, timeout: float = 0.4) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(False)
    try:
        err = s.connect_ex((host, port))
        if err == 0:
            return True
        _, w, _ = select.select([], [s], [], timeout)
        if not w:
            return False
        return s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0
    except OSError:
        return False
    finally:
        s.close()


def _banner(host: str, port: int, timeout: float = 0.5) -> Optional[str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(128)
            except socket.timeout:
                return None
            return data.decode("utf-8", errors="replace").strip() or None
    except OSError:
        return None


BANNER_PORTS = {21, 22, 23, 25, 80, 110, 143, 443, 587, 993, 995, 3306, 5432, 6379, 8080}


def scan_target(
    target: str,
    ports: Iterable[int],
    *,
    timeout: float = 0.4,
    banners: bool = True,
) -> dict:
    assert_allowed(target)
    ports = list(ports)
    t0 = time.perf_counter()
    open_ports: list[int] = []
    services: dict[str, str] = {}

    for p in ports:
        if _tcp_connect(target, p, timeout=timeout):
            open_ports.append(p)
            if banners and p in BANNER_PORTS:
                b = _banner(target, p)
                if b:
                    services[str(p)] = b[:200]

    duration_ms = int((time.perf_counter() - t0) * 1000)
    return {
        "ts": datetime.now(timezone.utc),
        "target_ip": target,
        "scan_type": "tcp_connect",
        "open_ports": sorted(open_ports),
        "services": services,
        "duration_ms": duration_ms,
        "detail": {"ports_scanned": len(ports)},
    }


DEFAULT_TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    631, 993, 995, 1080, 1433, 1521, 2049, 3000, 3306, 3389, 5000, 5432,
    5900, 6379, 8000, 8080, 8443, 9000, 27017,
]


def scan_top_ports(target: str, *, banners: bool = True) -> dict:
    return scan_target(target, DEFAULT_TOP_PORTS, banners=banners)
