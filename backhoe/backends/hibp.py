"""
HaveIBeenPwned (HIBP) backend — breach-hit enrichment for person-check.
Plain requests calls against HIBP's REST API v3, no SDK dependency, same
pattern as shodan.py/censys.py.

Needs an API key: backhoe.keys.get_api_key(HIBP_PROVIDER) resolves one
(HIBP_API_KEY env var, then a locally stored key, then an interactive
prompt — see keys.py).

Unlike Shodan (/api-info) and Censys (/accounts/users/credits), HIBP has
no free endpoint to confirm a key is valid without consuming a real
request against the subscription's rate limit — confirmed against HIBP's
own current API docs (haveibeenpwned.com/API/v3) during design.
validate_key() therefore only checks the key's documented format (a
32-character hexadecimal string) and never touches the network; an
actually-wrong key surfaces at lookup time as a normal HIBPAPIError
(401), caught the same non-fatal way as any other backend error in
cli.py. There is deliberately no HIBPValidationError/KeyValidationError
subclass here, unlike Shodan/Censys — validate_key() never raises.

check_breaches() requires a User-Agent header — HIBP returns 403 without
one, a failure mode neither Shodan nor Censys has (neither sends any
custom headers at all).
"""
from __future__ import annotations

import re
from urllib.parse import quote

import requests

from ..keys import KeyProvider
from ..schema import Finding, FindingType

BASE_URL = "https://haveibeenpwned.com/api/v3"
DEFAULT_TIMEOUT = 10
USER_AGENT = "BACKHOE-OSINT-Tool"
_KEY_FORMAT_RE = re.compile(r"^[0-9a-fA-F]{32}$")


class HIBPError(Exception):
    """A real failure calling HIBP — never raised for "no breaches for
    this email", which is a legitimate empty result (see check_breaches)."""


class HIBPAPIError(HIBPError):
    """check_breaches() failed: bad key, missing User-Agent, rate
    limited, HIBP's own server error, network failure, or an unparseable
    response."""


def _redact_key(text: str, key: str) -> str:
    """Defensive belt-and-suspenders, same rationale as censys.py's
    _redact_key: the key is sent as a header value, not a URL query
    param, so it shouldn't normally appear in a requests exception's
    message — but a key containing a stray control character can trigger
    InvalidHeader, which embeds repr(key) (the escaped form) rather than
    the raw string, so redact both forms."""
    if not key:
        return text
    text = text.replace(key, "<redacted>")
    escaped = repr(key)[1:-1]
    if escaped and escaped != key:
        text = text.replace(escaped, "<redacted>")
    return text


def validate_key(key: str) -> bool:
    """Format check only — see module docstring for why HIBP can't get
    the free live-validation treatment Shodan/Censys do."""
    return bool(_KEY_FORMAT_RE.match(key))


def check_breaches(email: str, key: str) -> list[Finding]:
    url = f"{BASE_URL}/breachedaccount/{quote(email, safe='')}"
    try:
        resp = requests.get(
            url,
            params={"truncateResponse": "false"},
            headers={"hibp-api-key": key, "User-Agent": USER_AGENT},
            timeout=DEFAULT_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise HIBPAPIError(f"network error contacting HIBP: {_redact_key(str(exc), key)}") from exc

    if resp.status_code == 404:
        return []
    if resp.status_code == 429:
        retry_after = resp.headers.get("Retry-After")
        suffix = f" (retry after {retry_after}s)" if retry_after else ""
        raise HIBPAPIError(f"HIBP rate limit exceeded{suffix}")
    if resp.status_code != 200:
        raise HIBPAPIError(f"HIBP breach lookup returned status {resp.status_code}")

    try:
        data = resp.json()
    except ValueError as exc:
        raise HIBPAPIError(f"unparseable JSON from HIBP: {exc}") from exc

    if not isinstance(data, list):
        raise HIBPAPIError("unexpected HIBP response shape: expected a list of breaches")

    return _to_findings(data)


def _to_findings(data: list) -> list[Finding]:
    findings: list[Finding] = []
    for breach in data:
        title = breach.get("Title")
        if not title:
            continue
        findings.append(
            Finding(
                type=FindingType.BREACH_HIT,
                value=title,
                source="hibp",
                raw={
                    "name": breach.get("Name"),
                    "title": title,
                    "domain": breach.get("Domain"),
                    "breach_date": breach.get("BreachDate"),
                    "pwn_count": breach.get("PwnCount"),
                    "data_classes": breach.get("DataClasses") or [],
                    "is_verified": breach.get("IsVerified"),
                    "is_fabricated": breach.get("IsFabricated"),
                    "is_sensitive": breach.get("IsSensitive"),
                    "is_retired": breach.get("IsRetired"),
                    "is_spam_list": breach.get("IsSpamList"),
                },
            )
        )
    return findings


HIBP_PROVIDER = KeyProvider(
    name="hibp",
    env_var="HIBP_API_KEY",
    prompt_label="HaveIBeenPwned API key",
    validate=validate_key,
)
