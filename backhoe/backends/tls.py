"""
TLS certificate metadata fetched with a real handshake against the live
host — issuer, expiry, SANs. This is a different (and often more current)
signal than crt.sh: crt.sh shows every cert ever *issued*; this shows
what's actually being *served* right now.

Note: behind a network that transparently intercepts TLS connections (see
portscan.py's caveat — the same applies here), the certificate returned
may be a re-signed stand-in produced by the interceptor, not the origin's
real certificate. Trust these results only when run from a direct,
unproxied network.
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone


class TlsError(Exception):
    """Raised when the target doesn't speak TLS on the given port, or the
    connection/handshake fails outright."""


def get_certificate_info(host: str, port: int = 443, *, timeout: float = 10.0) -> dict:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except (OSError, ssl.SSLError) as e:
        raise TlsError(f"TLS handshake with {host}:{port} failed: {e}") from e

    not_after = _parse_cert_date(cert.get("notAfter"))
    not_before = _parse_cert_date(cert.get("notBefore"))
    days_until_expiry = (not_after - datetime.now(timezone.utc)).days if not_after else None

    return {
        "subject": _flatten(cert.get("subject")),
        "issuer": _flatten(cert.get("issuer")),
        "not_before": not_before,
        "not_after": not_after,
        "days_until_expiry": days_until_expiry,
        "san": [value for key, value in cert.get("subjectAltName", ()) if key == "DNS"],
    }


def _parse_cert_date(value: str | None):
    if not value:
        return None
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def _flatten(name_tuple) -> dict:
    flat: dict[str, str] = {}
    for rdn in name_tuple or ():
        for key, value in rdn:
            flat[key] = value
    return flat
