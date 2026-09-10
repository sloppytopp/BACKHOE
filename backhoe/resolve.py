"""
Live DNS resolution — the cheapest signal that exists for "is this
subdomain still real" and it needs zero API keys. A subdomain that hasn't
resolved in years but still shows up in cert-transparency results is a very
different finding from one that's live today; nothing upstream (crt.sh)
tells you which is which.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def resolve_many(hostnames: list[str], *, workers: int = 20, timeout: float = 5.0) -> dict[str, bool]:
    """Return {hostname: True/False} for whether each hostname resolves.

    Sets a process-wide socket timeout for the duration of the batch so one
    unresponsive lookup can't hang the whole run; restored when done.
    """
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    results: dict[str, bool] = {}
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_resolves, host): host for host in hostnames}
            for future in as_completed(futures):
                results[futures[future]] = future.result()
    finally:
        socket.setdefaulttimeout(old_timeout)
    return results


def _resolves(hostname: str) -> bool:
    try:
        socket.gethostbyname(hostname)
        return True
    except (socket.gaierror, socket.timeout, OSError):
        return False
