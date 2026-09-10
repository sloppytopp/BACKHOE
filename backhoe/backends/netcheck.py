"""
Detects whether outbound TCP/TLS traffic is being transparently
intercepted (a corporate proxy, security sandbox, some VPNs). Port scans
and raw TLS-certificate fetches are worthless under interception: every
port looks "open" and every certificate is the interceptor's re-signed
stand-in, not the real target's — not a hypothetical, this is exactly
what happened testing against a real domain in a sandboxed environment
during development (the "certificate" came back issued by the sandbox's
own egress gateway, not any real CA).

Detected by handshaking against a guaranteed-unassigned IP (TEST-NET-3,
RFC 5737) — a real network can never route there, so a completed
handshake proves something is answering on its behalf.
"""
from __future__ import annotations

import socket
import ssl

_CANARY_IP = "203.0.113.1"  # RFC 5737 TEST-NET-3 — reserved, never routed
_CANARY_PORT = 443


def tcp_tls_is_intercepted(*, timeout: float = 5.0) -> bool:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((_CANARY_IP, _CANARY_PORT), timeout=timeout) as sock:
            with ctx.wrap_socket(sock):
                return True
    except OSError:
        return False
