"""
Gravatar existence check — a long-standing, well-known OSINT technique:
Gravatar exposes whether a public profile exists for an email's hash with
no authentication required. This is only ever a positive signal (a live,
human-managed inbox with a public profile), never a breach or exposure
by itself.
"""
from __future__ import annotations

import hashlib

import requests

GRAVATAR_URL = "https://www.gravatar.com/avatar/{h}?d=404"


class GravatarError(Exception):
    """Raised on a network failure — never for a legitimate 404 (no profile)."""


def check_gravatar(email: str, *, timeout: float = 10.0) -> bool:
    digest = hashlib.sha256(email.strip().lower().encode()).hexdigest()
    url = GRAVATAR_URL.format(h=digest)
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": "backhoe/0.1"})
    except requests.RequestException as e:
        raise GravatarError(f"Gravatar check failed: {e}") from e

    if resp.status_code == 200:
        return True
    if resp.status_code == 404:
        return False
    raise GravatarError(f"Gravatar returned unexpected status {resp.status_code}")
