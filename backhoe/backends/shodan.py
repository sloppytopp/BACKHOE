"""
Shodan backend — richer per-port service/banner data than BACKHOE's own
bounded TCP connect scan (backends/portscan.py), without doing any more
raw TCP ourselves. Plain requests calls against Shodan's REST API, no
`shodan` SDK dependency — same pattern as crtsh.py/gravatar.py.

Needs an API key: backhoe.keys.get_api_key(SHODAN_PROVIDER) resolves one
(SHODAN_API_KEY env var, then a locally stored key, then an interactive
prompt — see keys.py). Shodan's free tier includes host lookups; which
optional fields (product, version, vulns) actually come back is
plan-dependent and NOT verified live in this environment — no Shodan key
or live network access was available during development (see the design
spec's "Verification honesty note"). Every optional field is read with
.get(), never assumed present. The `vulns` field's shape in particular
(list of CVE strings vs. a dict keyed by CVE ID) isn't confirmed from
Shodan's own docs either — _extract_vuln_ids() below handles both rather
than guessing one.

validate_key() hits /api-info, confirmed via Shodan's own docs to cost no
query credit — this is what lets keys.py live-validate a stored key on
every single call without burning the operator's quota.
"""
from __future__ import annotations

import requests

from ..keys import KeyProvider, KeyValidationError
from ..schema import Finding, FindingType

BASE_URL = "https://api.shodan.io"
DEFAULT_TIMEOUT = 10


class ShodanError(Exception):
    """A real failure calling Shodan — never raised for "no data for this
    host", which is a legitimate empty result (see lookup_host)."""


class ShodanAPIError(ShodanError):
    """lookup_host() failed for a reason other than "not indexed": bad key,
    rate limited, Shodan's own server error, network failure, or an
    unparseable response."""


class ShodanValidationError(ShodanError, KeyValidationError):
    """validate_key() itself failed inconclusively (network error, 5xx,
    unparseable response) — NOT the same as the key being confirmed wrong.
    keys.py treats this as "can't confirm, use the key anyway", not as a
    reason to reprompt."""


def _redact_key(text: str, key: str) -> str:
    """Never let the raw API key reach a message a caller might print
    (click.secho, terminal scrollback, logs) — `requests` embeds the
    full request URL, key querystring included, in a ConnectionError's
    own message."""
    return text.replace(key, "<redacted>") if key else text


def validate_key(key: str) -> bool:
    try:
        resp = requests.get(f"{BASE_URL}/api-info", params={"key": key}, timeout=DEFAULT_TIMEOUT)
    except requests.RequestException as exc:
        raise ShodanValidationError(f"network error contacting Shodan: {_redact_key(str(exc), key)}") from exc

    if resp.status_code == 200:
        return True
    if resp.status_code == 401:
        return False
    raise ShodanValidationError(f"unexpected Shodan /api-info status {resp.status_code}")


def lookup_host(ip: str, key: str) -> list[Finding]:
    try:
        resp = requests.get(f"{BASE_URL}/shodan/host/{ip}", params={"key": key}, timeout=DEFAULT_TIMEOUT)
    except requests.RequestException as exc:
        raise ShodanAPIError(f"network error contacting Shodan: {_redact_key(str(exc), key)}") from exc

    if resp.status_code == 404:
        return []
    if resp.status_code != 200:
        raise ShodanAPIError(f"Shodan host lookup returned status {resp.status_code}")

    try:
        data = resp.json()
    except ValueError as exc:
        raise ShodanAPIError(f"unparseable JSON from Shodan: {exc}") from exc

    return _to_findings(ip, data)


def _extract_vuln_ids(entry: dict) -> list[str]:
    """CVE ids for one data[] entry. Shape not verified live (see module
    docstring) — handle both a dict keyed by CVE id and a plain list of
    CVE id strings rather than assuming one."""
    vulns = entry.get("vulns")
    if not vulns:
        return []
    if isinstance(vulns, dict):
        return sorted(vulns.keys())
    if isinstance(vulns, list):
        return sorted(str(v) for v in vulns)
    return []


def _to_findings(ip: str, data: dict) -> list[Finding]:
    # Shodan can return multiple data[] entries for the same port (different
    # banners/modules/vhosts observed on it). Group by port BEFORE building
    # Finding objects so each port produces exactly one Finding — otherwise
    # two same-port entries would share the same dedup key AND the same
    # source string ("shodan"), and merge_findings() would let the second
    # entry's raw payload silently overwrite the first's (e.g. losing a CVE).
    by_port: dict[int, dict] = {}
    for entry in data.get("data", []):
        port = entry.get("port")
        if port is None:
            continue
        merged = by_port.setdefault(
            port, {"service": None, "product": None, "version": None, "vulns": []}
        )
        service = (entry.get("_shodan") or {}).get("module")
        if merged["service"] is None and service is not None:
            merged["service"] = service
        if merged["product"] is None and entry.get("product") is not None:
            merged["product"] = entry.get("product")
        if merged["version"] is None and entry.get("version") is not None:
            merged["version"] = entry.get("version")
        for v in _extract_vuln_ids(entry):
            if v not in merged["vulns"]:
                merged["vulns"].append(v)

    findings: list[Finding] = []
    for port, payload in by_port.items():
        findings.append(
            Finding(
                type=FindingType.OPEN_PORT,
                value=f"{ip}:{port}",
                source="shodan",
                raw={"port": port, **payload},
            )
        )
    return findings


SHODAN_PROVIDER = KeyProvider(
    name="shodan",
    env_var="SHODAN_API_KEY",
    prompt_label="Shodan API key",
    validate=validate_key,
)
