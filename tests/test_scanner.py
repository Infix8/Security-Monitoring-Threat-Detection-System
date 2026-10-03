import pytest

from app.scanner.portscan import (
    DEFAULT_TOP_PORTS,
    ScanNotAllowed,
    assert_allowed,
    is_allowed,
    scan_target,
)


def test_allowed_localhost():
    assert is_allowed("127.0.0.1")


def test_allowed_private_ranges():
    assert is_allowed("10.1.2.3")
    assert is_allowed("192.168.50.10")


def test_public_ip_refused():
    assert not is_allowed("8.8.8.8")
    with pytest.raises(ScanNotAllowed):
        assert_allowed("1.2.3.4")


def test_scan_localhost_returns_shape():
    r = scan_target("127.0.0.1", [1, 9999], banners=False)
    assert r["target_ip"] == "127.0.0.1"
    assert r["scan_type"] == "tcp_connect"
    assert isinstance(r["open_ports"], list)
    assert isinstance(r["services"], dict)
    assert r["duration_ms"] >= 0


def test_default_top_ports_nonempty():
    assert len(DEFAULT_TOP_PORTS) >= 20
