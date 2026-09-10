from unittest.mock import patch

from backhoe.backends import portscan


def test_scan_ports_reports_open_and_closed():
    class FakeConn:
        def __init__(self, addr, timeout):
            self.addr = addr

        def __enter__(self):
            host, port = self.addr
            if port not in (80, 443):
                raise OSError("refused")
            return self

        def __exit__(self, *exc):
            return False

    with patch("socket.create_connection", side_effect=lambda addr, timeout: FakeConn(addr, timeout)):
        results = portscan.scan_ports("example.com", {80: "http", 443: "https", 22: "ssh"})

    assert results == {80: True, 443: True, 22: False}


def test_scan_ports_covers_every_requested_port():
    with patch("socket.create_connection", side_effect=OSError("refused")):
        results = portscan.scan_ports("example.com", portscan.COMMON_PORTS)
    assert set(results.keys()) == set(portscan.COMMON_PORTS.keys())
    assert all(is_open is False for is_open in results.values())
