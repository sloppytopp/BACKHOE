"""
Censys backend — a second richer-port-data source for infra-check,
alongside Shodan (backends/shodan.py), whose shape this module
deliberately mirrors: same raw dict field names (port/service/product/
version/vulns), same source-key-first exception hierarchy, same
KeyProvider registration pattern. That's what lets scoring.py and
report.py handle Censys findings with zero changes — they already
handle this shape generically, built for and validated against Shodan.

Needs an API key: backhoe.keys.get_api_key(CENSYS_PROVIDER) resolves one
(CENSYS_API_KEY env var, then a locally stored key, then an interactive
prompt — see keys.py). The "key" here is a Censys Personal Access Token
(PAT), used as a Bearer token, not the older API-ID+secret pair Censys's
now-deprecated v2 Search API used — confirmed live against Censys's
current docs (docs.censys.com) during development: their own docs say
"all scripted access should use" the newer Platform API (v3) this module
targets, not the legacy one. This is a real API generation Shodan-style
memory-only development couldn't have caught.

validate_key() hits /v3/accounts/users/credits, confirmed live in
Censys's docs — quoted twice — to cost no credits, letting keys.py
re-validate a stored token on every call without burning quota (same
role as Shodan's /api-info).

What's NOT confirmed live (docs summarization truncated the raw OpenAPI
schema before the exact response shape came through): the precise
404/no-data behavior for the host-lookup endpoint (treated as an empty
result, matching Shodan's precedent and general REST convention), and
the exact shape of a service's `vulns` field. The clearest signal found
says it's a list of {"id": "CVE-...", ...} objects — different from
Shodan's plain-string-or-dict shape — so _extract_vuln_ids() below
handles THREE possible shapes rather than assuming one.
"""
from __future__ import annotations

import requests

from ..keys import KeyProvider, KeyValidationError
from ..schema import Finding, FindingType

BASE_URL = "https://api.platform.censys.io/v3"
DEFAULT_TIMEOUT = 10


class CensysError(Exception):
    """A real failure calling Censys — never raised for "no data for this
    host", which is a legitimate empty result (see lookup_host)."""


class CensysAPIError(CensysError):
    """lookup_host() failed for a reason other than "not indexed": bad
    token, rate limited, Censys's own server error, network failure, or
    an unparseable response."""


class CensysValidationError(CensysError, KeyValidationError):
    """validate_key() itself failed inconclusively (network error, 5xx,
    unparseable response) — NOT the same as the key being confirmed
    wrong. keys.py treats this as "can't confirm, use the key anyway",
    not as a reason to reprompt."""


def _redact_key(text: str, key: str) -> str:
    """Defensive belt-and-suspenders: Censys's Bearer-token auth means the
    key never appears in a request URL/query string the way Shodan's did,
    but some requests error paths (e.g. InvalidHeader on a key containing
    a stray control character) embed repr(key) in their message instead
    of the raw string — the escaped form (\\n, \\r, etc.) never matches a
    literal .replace() against the raw key, so redact both forms."""
    if not key:
        return text
    text = text.replace(key, "<redacted>")
    escaped = repr(key)[1:-1]
    if escaped and escaped != key:
        text = text.replace(escaped, "<redacted>")
    return text


def validate_key(key: str) -> bool:
    try:
        resp = requests.get(
            f"{BASE_URL}/accounts/users/credits",
            headers={"Authorization": f"Bearer {key}"},
            timeout=DEFAULT_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise CensysValidationError(f"network error contacting Censys: {_redact_key(str(exc), key)}") from exc

    if resp.status_code == 200:
        return True
    if resp.status_code == 401:
        return False
    raise CensysValidationError(f"unexpected Censys /accounts/users/credits status {resp.status_code}")


def lookup_host(ip: str, key: str) -> list[Finding]:
    try:
        resp = requests.get(
            f"{BASE_URL}/global/asset/host/{ip}",
            headers={"Authorization": f"Bearer {key}"},
            timeout=DEFAULT_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise CensysAPIError(f"network error contacting Censys: {_redact_key(str(exc), key)}") from exc

    if resp.status_code == 404:
        return []
    if resp.status_code != 200:
        raise CensysAPIError(f"Censys host lookup returned status {resp.status_code}")

    try:
        data = resp.json()
    except ValueError as exc:
        raise CensysAPIError(f"unparseable JSON from Censys: {exc}") from exc

    return _to_findings(ip, data)


def _extract_vuln_ids(entry: dict) -> list[str]:
    """CVE ids for one service entry. Shape not confirmed live (see module
    docstring) — handle a dict keyed by CVE id, a plain list of CVE-id
    strings, and a list of {"id": ...} objects, rather than assuming one."""
    vulns = entry.get("vulns")
    if not vulns:
        return []
    if isinstance(vulns, dict):
        return sorted(vulns.keys())
    if isinstance(vulns, list):
        ids: list[str] = []
        for v in vulns:
            if isinstance(v, dict):
                vid = v.get("id")
                if vid:
                    ids.append(str(vid))
            elif v:
                ids.append(str(v))
        return sorted(ids)
    return []


def _to_findings(ip: str, data: dict) -> list[Finding]:
    # Group by port before building Finding objects, same reason as
    # shodan.py's _to_findings: two service entries for the same port
    # would otherwise share a dedup key AND source ("censys"), letting
    # merge_findings() silently let the second overwrite the first's raw
    # payload (the exact Critical bug Shodan's final review caught).
    result = data.get("result")
    if not isinstance(result, dict):
        raise CensysAPIError("unexpected Censys response shape: no 'result' object in body")
    resource = result.get("resource")
    if not isinstance(resource, dict):
        raise CensysAPIError("unexpected Censys response shape: no 'resource' object in body")

    by_port: dict[int, dict] = {}
    try:
        for svc in resource.get("services", []):
            port = svc.get("port")
            if port is None:
                continue
            try:
                port = int(port)
            except (TypeError, ValueError):
                continue
            merged = by_port.setdefault(
                port, {"service": None, "product": None, "version": None, "vulns": []}
            )
            protocol = svc.get("protocol")
            if merged["service"] is None and protocol is not None:
                merged["service"] = protocol
            for sw in svc.get("software") or []:
                if merged["product"] is None and sw.get("product") is not None:
                    merged["product"] = sw.get("product")
                    merged["version"] = sw.get("version")
            for v in _extract_vuln_ids(svc):
                if v not in merged["vulns"]:
                    merged["vulns"].append(v)
    except (AttributeError, TypeError) as exc:
        raise CensysAPIError(f"unexpected Censys response shape: {exc}") from exc

    findings: list[Finding] = []
    for port, payload in by_port.items():
        findings.append(
            Finding(
                type=FindingType.OPEN_PORT,
                value=f"{ip}:{port}",
                source="censys",
                raw={"port": port, **payload},
            )
        )
    return findings


CENSYS_PROVIDER = KeyProvider(
    name="censys",
    env_var="CENSYS_API_KEY",
    prompt_label="Censys API key (Personal Access Token)",
    validate=validate_key,
)
