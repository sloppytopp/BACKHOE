"""
Lightweight TCP connect scan — a small, fixed set of commonly-exposed
ports, not a full sweep. This is active scanning, not passive OSINT:
only ever run it against infrastructure you own or are explicitly
authorized to test.

Note: from behind a network that transparently intercepts outbound
connections (many corporate networks, CI sandboxes, some VPNs), every
port will falsely appear "open" because the connection succeeds against
the interceptor, not the real host. Trust these results only when run
from a direct, unproxied network.
"""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    80: "http",
    443: "https",
    3306: "mysql",
    3389: "rdp",
    8080: "http-alt",
    8443: "https-alt",
}


def scan_ports(
    host: str,
    ports: dict[int, str] | None = None,
    *,
    timeout: float = 3.0,
    workers: int = 10,
) -> dict[int, bool]:
    ports = ports if ports is not None else COMMON_PORTS
    results: dict[int, bool] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_is_open, host, port, timeout): port for port in ports}
        for future in as_completed(futures):
            results[futures[future]] = future.result()
    return results


def _is_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
