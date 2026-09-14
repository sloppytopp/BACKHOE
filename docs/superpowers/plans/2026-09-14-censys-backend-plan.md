# Censys Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Censys host-lookup backend (`backhoe/backends/censys.py`) as a second keyed enrichment source for `infra-check`, wired in alongside the existing Shodan backend via a new `--censys/--no-censys` flag.

**Architecture:** `backends/censys.py` mirrors `backends/shodan.py`'s shape exactly — same exception hierarchy pattern, same `KeyProvider` registration via the already-shipped `backhoe/keys.py`, and critically, **the same `raw` dict field names** (`port`, `service`, `product`, `version`, `vulns`) on every `OPEN_PORT` `Finding` it produces. Because `scoring.py`'s `_score_open_port`/`_collect_vulns`/`raw_get` and `report.py`'s readers already operate generically on that shape (built for Shodan, validated by a prior final-review pass), Censys plugs into scoring, rendering, and `merge_findings()` with **zero changes to `scoring.py` or `report.py`**. `cli.py` gets a new `--censys/--no-censys` block, structurally identical to the existing `--shodan/--no-shodan` block, added independently (both can run in the same `infra-check` invocation and merge on shared `ip:port`).

**Tech Stack:** Python 3.10+, `requests` (HTTP, no `censys` SDK — same policy as Shodan), `click`, `pytest` + `unittest.mock`.

**Spec:** None — this was brainstormed as a bounded task (new backend module following an established in-repo pattern, not a new subsystem). The design was proposed and agreed in conversation; this plan's Global Constraints section is the complete record of that agreement.

## Verification note (read before writing code)

Unlike Shodan (built from training-data knowledge only, no live docs access), this backend's API shape was verified this session against Censys's **live, current documentation** at `docs.censys.com` (fetched via WebFetch/WebSearch during brainstorming). This caught a real, important fact a memory-only approach would have missed: **Censys deprecated their old Basic-Auth (API ID + secret) v2 API** in favor of a newer Bearer-token "Platform API" (v3) that their own docs say all new scripted access should use. This plan builds against the new v3 Platform API exclusively.

Confirmed live, this session (quoted from `docs.censys.com`):
- Base URL: `https://api.platform.censys.io/v3/`
- Auth: `Authorization: Bearer <token>` header (a single Personal Access Token string — fits `KeyProvider`'s one-key model with no changes needed)
- Host lookup: `GET /v3/global/asset/host/{ip}`
- Free validate endpoint: `GET /v3/accounts/users/credits` — docs state explicitly, twice: *"This endpoint does not cost any credits to execute."*

**Not confirmed** (same honesty tier as Shodan's unresolved unknowns — the doc-fetch tool summarizes/truncates large OpenAPI schema pages, so these come from a secondary docs page's prose summary, not the primary endpoint's raw schema):
- The exact HTTP status/body for a host with no Censys data (treated as a 404-returns-empty-list convention, matching Shodan and general REST practice, but not confirmed for this specific endpoint)
- The exact shape of the `vulns` field on a service entry — the clearest signal available says it's a list of objects each with an `id` field (e.g. `{"id": "CVE-2019-14540", "severity": "CRITICAL", "kev": true}`), different from Shodan's shape (list of plain CVE-id strings, or a dict keyed by CVE id). Handled defensively for all three possible shapes rather than assuming one — same discipline Shodan's `_extract_vuln_ids` already established.

## Global Constraints

- No new pip dependencies. `backhoe/backends/censys.py` uses `requests` directly, never a `censys` SDK.
- Target Python 3.10+ — no 3.11+-only syntax (`from __future__ import annotations` for `str | None`-style hints, same as every other backend module).
- Auth is `Authorization: Bearer <token>` header, never query-string — this is a real security improvement over Shodan's query-param auth (which is what leaked the key into `ConnectionError` messages in the final Shodan review). Still apply the same `_redact_key()` defensive helper as a belt-and-suspenders safety net, since it's cheap and consistent.
- `raw` dict on every `Finding` this backend produces MUST use exactly these keys, matching `shodan.py`'s shape: `port` (int), `service` (str | None), `product` (str | None), `version` (str | None), `vulns` (list[str]). This is what lets `scoring.py`/`report.py` need zero changes — do not deviate from these field names.
- `source="censys"` on every `Finding` (mirrors `source="shodan"`).
- A Censys host-lookup 404 is treated as a legitimate empty result (`[]`), not an error, matching this project's "fail loud, never fake" rule (see `CLAUDE.md`) and Shodan's precedent — never invent a fabricated failure for "no data," and never invent fabricated data for a real failure.
- The `vulns` field must be parsed defensively for at least three possible shapes (dict keyed by CVE id, list of plain CVE-id strings, list of `{"id": ...}` objects) — never assume one, per the verification note above.
- Censys can return multiple `services` entries; group by `port` before building `Finding`s (same defensive pattern Shodan's `_to_findings` already uses, and for the same reason: two same-port entries sharing a dedup key AND source would let `merge_findings()` silently let the second overwrite the first's `raw`, which is exactly the Critical bug the Shodan final review caught and fixed).
- `--censys/--no-censys` (default on) runs **outside** the `netcheck.tcp_tls_is_intercepted()` guard, same as `--shodan` — it's a passive API call, not raw TCP from this host.
- No `X-Organization-ID` header (Censys docs say it's optional, for multi-org accounts) — out of scope, YAGNI. Add later if an operator needs it.

## File Structure

```
backhoe/
  backends/
    censys.py                NEW — Censys host-lookup backend + CENSYS_PROVIDER
  cli.py                       MODIFY — --censys/--no-censys flag on infra-check
tests/
  test_censys.py                NEW
  test_cli.py                    MODIFY — --no-censys added to 10 existing
                                  infra-check tests, 6 new Censys-wiring tests
CLAUDE.md                        MODIFY — new "Censys" section, remove from
                                  "not built yet", fix stale test count
README.md                        MODIFY — infra-check bullets, new "Optional:
                                  Censys enrichment" section, "coming next"
```

---

### Task 1: `backhoe/backends/censys.py` — Censys host-lookup backend

**Files:**
- Create: `backhoe/backends/censys.py`
- Test: `tests/test_censys.py`

**Interfaces:**
- Consumes: `backhoe.keys.KeyProvider`, `backhoe.keys.KeyValidationError` (existing, unchanged). `backhoe.schema.Finding`, `backhoe.schema.FindingType` (existing, unchanged).
- Produces: `validate_key(key: str) -> bool`, `lookup_host(ip: str, key: str) -> list[Finding]`, `class CensysError(Exception)`, `class CensysAPIError(CensysError)`, `class CensysValidationError(CensysError, KeyValidationError)`, `CENSYS_PROVIDER: KeyProvider` (module-level constant).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_censys.py`:

```python
"""Censys backend tests — network mocked so these run anywhere, including
sandboxes that block outbound traffic. Unlike Shodan, this backend's API
shape WAS verified against Censys's live current documentation during
development (docs.censys.com) — see the plan's "Verification note" for
exactly what was and wasn't confirmed. The `vulns` field's exact shape
(dict keyed by CVE id / list of plain CVE-id strings / list of {"id": ...}
objects) is handled defensively rather than assumed — all three shapes are
exercised below."""
from unittest.mock import MagicMock, patch

import pytest
import requests

from backhoe.backends import censys
from backhoe.backends.censys import CensysAPIError, CensysValidationError
from backhoe.schema import FindingType


def _response(status_code, json_data=None, json_error=None):
    resp = MagicMock(status_code=status_code)
    if json_error is not None:
        resp.json.side_effect = json_error
    else:
        resp.json.return_value = json_data
    return resp


def test_validate_key_true_on_200():
    with patch("backhoe.backends.censys.requests.get", return_value=_response(200)):
        assert censys.validate_key("goodtoken") is True


def test_validate_key_false_on_401():
    with patch("backhoe.backends.censys.requests.get", return_value=_response(401)):
        assert censys.validate_key("badtoken") is False


def test_validate_key_raises_on_network_error():
    with patch("backhoe.backends.censys.requests.get", side_effect=requests.ConnectionError("nope")):
        with pytest.raises(CensysValidationError):
            censys.validate_key("anytoken")


def test_validate_key_raises_on_unexpected_status():
    with patch("backhoe.backends.censys.requests.get", return_value=_response(500)):
        with pytest.raises(CensysValidationError):
            censys.validate_key("anytoken")


def test_validate_key_uses_bearer_auth_header():
    mock_get = MagicMock(return_value=_response(200))
    with patch("backhoe.backends.censys.requests.get", mock_get):
        censys.validate_key("mytoken")
    _, kwargs = mock_get.call_args
    assert kwargs["headers"]["Authorization"] == "Bearer mytoken"
    assert "params" not in kwargs or "key" not in (kwargs.get("params") or {})


def test_lookup_host_returns_empty_list_on_404():
    with patch("backhoe.backends.censys.requests.get", return_value=_response(404)):
        assert censys.lookup_host("1.2.3.4", "token") == []


def test_lookup_host_raises_on_401():
    with patch("backhoe.backends.censys.requests.get", return_value=_response(401)):
        with pytest.raises(CensysAPIError):
            censys.lookup_host("1.2.3.4", "token")


def test_lookup_host_raises_on_network_error():
    with patch("backhoe.backends.censys.requests.get", side_effect=requests.ConnectionError("nope")):
        with pytest.raises(CensysAPIError):
            censys.lookup_host("1.2.3.4", "token")


def test_lookup_host_raises_on_unparseable_json():
    with patch(
        "backhoe.backends.censys.requests.get",
        return_value=_response(200, json_error=ValueError("bad")),
    ):
        with pytest.raises(CensysAPIError):
            censys.lookup_host("1.2.3.4", "token")


def test_lookup_host_sends_bearer_auth_header():
    mock_get = MagicMock(return_value=_response(200, {"result": {"resource": {"services": []}}}))
    with patch("backhoe.backends.censys.requests.get", mock_get):
        censys.lookup_host("1.2.3.4", "mytoken")
    _, kwargs = mock_get.call_args
    assert kwargs["headers"]["Authorization"] == "Bearer mytoken"


def test_lookup_host_parses_multiple_ports():
    payload = {
        "result": {
            "resource": {
                "ip": "1.2.3.4",
                "services": [
                    {
                        "port": 80,
                        "protocol": "HTTP",
                        "software": [{"product": "nginx", "version": "1.18.0"}],
                    },
                    {"port": 22, "protocol": "SSH"},
                ],
            }
        }
    }
    with patch("backhoe.backends.censys.requests.get", return_value=_response(200, payload)):
        findings = censys.lookup_host("1.2.3.4", "token")

    assert {f.value for f in findings} == {"1.2.3.4:80", "1.2.3.4:22"}
    assert all(f.type == FindingType.OPEN_PORT for f in findings)
    assert all(f.source == "censys" for f in findings)
    http_finding = next(f for f in findings if f.value == "1.2.3.4:80")
    assert http_finding.raw["product"] == "nginx"
    assert http_finding.raw["version"] == "1.18.0"
    assert http_finding.raw["service"] == "HTTP"


def test_lookup_host_handles_missing_optional_fields():
    payload = {"result": {"resource": {"services": [{"port": 443}]}}}
    with patch("backhoe.backends.censys.requests.get", return_value=_response(200, payload)):
        findings = censys.lookup_host("1.2.3.4", "token")

    assert len(findings) == 1
    f = findings[0]
    assert f.raw["product"] is None
    assert f.raw["version"] is None
    assert f.raw["vulns"] == []
    assert f.raw["service"] is None


def test_lookup_host_handles_vulns_as_dict():
    payload = {
        "result": {
            "resource": {
                "services": [
                    {"port": 443, "vulns": {"CVE-2021-1234": {}, "CVE-2021-5678": {}}}
                ]
            }
        }
    }
    with patch("backhoe.backends.censys.requests.get", return_value=_response(200, payload)):
        findings = censys.lookup_host("1.2.3.4", "token")
    assert sorted(findings[0].raw["vulns"]) == ["CVE-2021-1234", "CVE-2021-5678"]


def test_lookup_host_handles_vulns_as_list_of_strings():
    payload = {"result": {"resource": {"services": [{"port": 443, "vulns": ["CVE-2021-1234"]}]}}}
    with patch("backhoe.backends.censys.requests.get", return_value=_response(200, payload)):
        findings = censys.lookup_host("1.2.3.4", "token")
    assert findings[0].raw["vulns"] == ["CVE-2021-1234"]


def test_lookup_host_handles_vulns_as_list_of_objects():
    payload = {
        "result": {
            "resource": {
                "services": [
                    {
                        "port": 443,
                        "vulns": [
                            {"id": "CVE-2019-14540", "severity": "CRITICAL", "kev": True},
                            {"id": "CVE-2020-0001", "severity": "HIGH"},
                        ],
                    }
                ]
            }
        }
    }
    with patch("backhoe.backends.censys.requests.get", return_value=_response(200, payload)):
        findings = censys.lookup_host("1.2.3.4", "token")
    assert sorted(findings[0].raw["vulns"]) == ["CVE-2019-14540", "CVE-2020-0001"]


def test_lookup_host_skips_entries_with_no_port():
    payload = {"result": {"resource": {"services": [{"protocol": "HTTP"}]}}}
    with patch("backhoe.backends.censys.requests.get", return_value=_response(200, payload)):
        findings = censys.lookup_host("1.2.3.4", "token")
    assert findings == []


def test_lookup_host_merges_duplicate_entries_on_same_port():
    # Same defensive posture as Shodan's _to_findings: group by port so two
    # service entries for the same port produce exactly ONE Finding, with
    # vulns unioned and a real product value not overwritten by a later
    # entry's None.
    payload = {
        "result": {
            "resource": {
                "services": [
                    {"port": 443, "software": [{"product": "nginx"}], "vulns": ["CVE-2021-1234"]},
                    {"port": 443, "software": [{"product": None}], "vulns": []},
                ]
            }
        }
    }
    with patch("backhoe.backends.censys.requests.get", return_value=_response(200, payload)):
        findings = censys.lookup_host("1.2.3.4", "token")

    port_443_findings = [f for f in findings if f.value == "1.2.3.4:443"]
    assert len(port_443_findings) == 1
    f = port_443_findings[0]
    assert f.raw["vulns"] == ["CVE-2021-1234"]
    assert f.raw["product"] == "nginx"


def test_validate_key_error_never_leaks_raw_key():
    key = "SUPERSECRETTOKEN123"
    err = requests.ConnectionError(
        f"HTTPSConnectionPool(host='api.platform.censys.io', port=443): Max retries exceeded "
        f"with url: /v3/accounts/users/credits (Caused by NewConnectionError(...)) token={key}"
    )
    with patch("backhoe.backends.censys.requests.get", side_effect=err):
        with pytest.raises(CensysValidationError) as excinfo:
            censys.validate_key(key)
    assert key not in str(excinfo.value)


def test_lookup_host_error_never_leaks_raw_key():
    key = "SUPERSECRETTOKEN123"
    err = requests.ConnectionError(
        f"HTTPSConnectionPool(host='api.platform.censys.io', port=443): Max retries exceeded "
        f"with url: /v3/global/asset/host/1.2.3.4 (Caused by NewConnectionError(...)) token={key}"
    )
    with patch("backhoe.backends.censys.requests.get", side_effect=err):
        with pytest.raises(CensysAPIError) as excinfo:
            censys.lookup_host("1.2.3.4", key)
    assert key not in str(excinfo.value)


def test_censys_provider_is_registered_correctly():
    assert censys.CENSYS_PROVIDER.name == "censys"
    assert censys.CENSYS_PROVIDER.env_var == "CENSYS_API_KEY"
    assert censys.CENSYS_PROVIDER.validate is censys.validate_key
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_censys.py -v`
Expected: FAIL (or ERROR) with `ModuleNotFoundError: No module named 'backhoe.backends.censys'`

- [ ] **Step 3: Write the implementation**

Create `backhoe/backends/censys.py`:

```python
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
    key never appears in a request URL/query string the way Shodan's did
    (so this is less likely to ever trigger than Shodan's equivalent), but
    apply the same redaction anyway — cheap, consistent, and a future
    error message or proxy layer could still embed a header value."""
    return text.replace(key, "<redacted>") if key else text


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
    resource = (data.get("result") or {}).get("resource") or {}
    by_port: dict[int, dict] = {}
    for svc in resource.get("services", []):
        port = svc.get("port")
        if port is None:
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
            if merged["version"] is None and sw.get("version") is not None:
                merged["version"] = sw.get("version")
        for v in _extract_vuln_ids(svc):
            if v not in merged["vulns"]:
                merged["vulns"].append(v)

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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_censys.py -v`
Expected: PASS (19 tests)

- [ ] **Step 5: Commit**

```bash
git add backhoe/backends/censys.py tests/test_censys.py
git commit -m "$(cat <<'EOF'
Add Censys host-lookup backend for infra-check

requests-only, no censys SDK dependency, Bearer-token auth (Censys's
newer Platform API v3 — confirmed live against current docs.censys.com
during development that the older Basic-Auth v2 API is deprecated in
favor of this one). Mirrors shodan.py's raw dict shape exactly (port/
service/product/version/vulns) so scoring.py and report.py need zero
changes to handle Censys findings. validate_key() hits
/v3/accounts/users/credits, confirmed free to call in Censys's own
docs. vulns parsed defensively for three possible shapes since the
exact one wasn't confirmable from truncated doc content.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_016NyETLkGrCBagbexj3vkj6
EOF
)"
```

---

### Task 2: `cli.py` — wire Censys into `infra-check`

**Files:**
- Modify: `backhoe/cli.py:1-30` (imports), `backhoe/cli.py:173-192` (the `infra_check` decorators/signature), `backhoe/cli.py:265-278` (add a new block after the existing Shodan block)
- Modify: `tests/test_cli.py:1-11` (add one import), `tests/test_cli.py:140-299` (10 existing infra-check tests need `--no-censys` added; 6 new Censys tests appended)

**Interfaces:**
- Consumes: `censys.lookup_host`, `censys.CensysAPIError`, `censys.CENSYS_PROVIDER` (Task 1). `keys.get_api_key` (existing, unchanged). `schema.merge_findings`, `scoring.score_all` (existing, unchanged — no modifications needed since Task 1's `raw` shape already matches what these expect).
- Produces: new `--censys/--no-censys` CLI flag on `infra-check` (default on).

- [ ] **Step 1: Write the failing tests**

In `tests/test_cli.py`, add this import as the new first backend import (alphabetically, `censys` sorts before `dns_checks`), immediately before the existing `from backhoe.backends.dns_checks import DnsCheckError` line:

```python
from backhoe.backends.censys import CensysAPIError
```

So the full top-of-file import block becomes:

```python
from unittest.mock import patch

from click.testing import CliRunner

from backhoe.backends.censys import CensysAPIError
from backhoe.backends.dns_checks import DnsCheckError
from backhoe.backends.gravatar import GravatarError
from backhoe.backends.shodan import ShodanAPIError
from backhoe.backends.spiderfoot import SpiderFootError, SpiderFootNotInstalled
from backhoe.backends.theharvester import TheHarvesterError, TheHarvesterNotInstalled
from backhoe.cli import cli
from backhoe.schema import Finding, FindingType
```

Then replace the entire block of 10 existing `infra-check` tests (from `def test_infra_check_accepts_a_bare_ip():` through the end of `test_infra_check_merges_shodan_and_portscan_open_port_on_same_ip_port`) with this same block plus `--no-censys` added to every invocation, followed immediately by 6 new tests:

```python
def test_infra_check_accepts_a_bare_ip():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.reverse_dns", return_value=None), patch(
        "backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=True
    ):
        result = runner.invoke(cli, ["infra-check", "1.2.3.4", "--no-shodan", "--no-censys"])
    assert result.exit_code == 0
    assert "1.2.3.4" in result.output


def test_infra_check_skips_ports_and_tls_when_intercepted():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=True), patch(
        "backhoe.cli.portscan.scan_ports"
    ) as scan_mock, patch(
        "backhoe.cli.tls.get_certificate_info"
    ) as tls_mock:
        result = runner.invoke(cli, ["infra-check", "example.com", "--no-shodan", "--no-censys"])

    assert result.exit_code == 0
    assert "transparently intercepts" in result.output
    scan_mock.assert_not_called()
    tls_mock.assert_not_called()


def test_infra_check_scans_every_resolved_ip_not_the_original_hostname():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4", "5.6.7.8"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=False), patch(
        "backhoe.cli.portscan.scan_ports", return_value={}
    ) as scan_mock, patch(
        "backhoe.cli.tls.get_certificate_info", return_value={"days_until_expiry": 60, "issuer": {}, "subject": {}, "san": []}
    ):
        result = runner.invoke(cli, ["infra-check", "cdn.example.com", "--no-shodan", "--no-censys"])

    assert result.exit_code == 0
    scan_mock.assert_any_call("1.2.3.4")
    scan_mock.assert_any_call("5.6.7.8")
    assert scan_mock.call_count == 2


def test_infra_check_tags_open_port_findings_with_the_ip_not_the_hostname():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=False), patch(
        "backhoe.cli.portscan.scan_ports", return_value={443: True}
    ), patch(
        "backhoe.cli.tls.get_certificate_info", return_value={"days_until_expiry": 60, "issuer": {}, "subject": {}, "san": []}
    ):
        result = runner.invoke(cli, ["infra-check", "cdn.example.com", "--no-shodan", "--no-censys"])

    assert result.exit_code == 0
    assert "1.2.3.4:443" in result.output


def test_infra_check_runs_ports_and_tls_when_not_intercepted():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value="host.example.com"
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=False), patch(
        "backhoe.cli.portscan.scan_ports", return_value={443: True, 22: False}
    ), patch(
        "backhoe.cli.tls.get_certificate_info",
        return_value={"days_until_expiry": 60, "issuer": {}, "subject": {}, "san": []},
    ):
        result = runner.invoke(cli, ["infra-check", "example.com", "--no-shodan", "--no-censys"])

    assert result.exit_code == 0
    assert "tls" in result.output
    assert "portscan" in result.output


def test_infra_check_skips_shodan_silently_when_no_key_available():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=True), patch(
        "backhoe.cli.keys.get_api_key", return_value=None
    ) as get_key_mock, patch(
        "backhoe.cli.shodan.lookup_host"
    ) as lookup_mock:
        result = runner.invoke(cli, ["infra-check", "example.com", "--no-censys"])

    assert result.exit_code == 0
    get_key_mock.assert_called_once()
    lookup_mock.assert_not_called()


def test_infra_check_skips_shodan_with_no_shodan_flag():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=True), patch(
        "backhoe.cli.keys.get_api_key"
    ) as get_key_mock:
        result = runner.invoke(cli, ["infra-check", "example.com", "--no-shodan", "--no-censys"])

    assert result.exit_code == 0
    get_key_mock.assert_not_called()


def test_infra_check_runs_shodan_even_when_intercepted():
    # Shodan is a passive API lookup, not raw TCP from this host — it must
    # still run when netcheck reports interception, even though the
    # built-in port scan and TLS fetch are skipped in that case.
    runner = CliRunner()
    shodan_finding = Finding(
        type=FindingType.OPEN_PORT, value="1.2.3.4:80", source="shodan",
        raw={"port": 80, "service": "http", "product": None, "version": None, "vulns": []},
    )
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=True), patch(
        "backhoe.cli.keys.get_api_key", return_value="a-key"
    ), patch("backhoe.cli.shodan.lookup_host", return_value=[shodan_finding]):
        result = runner.invoke(cli, ["infra-check", "example.com", "--no-censys"])

    assert result.exit_code == 0
    assert "1.2.3.4:80" in result.output


def test_infra_check_warns_and_continues_on_shodan_api_error():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=True), patch(
        "backhoe.cli.keys.get_api_key", return_value="a-key"
    ), patch("backhoe.cli.shodan.lookup_host", side_effect=ShodanAPIError("rate limited")):
        result = runner.invoke(cli, ["infra-check", "example.com", "--no-censys"])

    assert result.exit_code == 0
    assert "rate limited" in result.output


def test_infra_check_merges_shodan_and_portscan_open_port_on_same_ip_port():
    runner = CliRunner()
    shodan_finding = Finding(
        type=FindingType.OPEN_PORT, value="1.2.3.4:443", source="shodan",
        raw={"port": 443, "service": "https", "product": "nginx", "version": "1.18", "vulns": []},
    )
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=False), patch(
        "backhoe.cli.portscan.scan_ports", return_value={443: True}
    ), patch(
        "backhoe.cli.tls.get_certificate_info",
        return_value={"days_until_expiry": 60, "issuer": {}, "subject": {}, "san": []},
    ), patch("backhoe.cli.keys.get_api_key", return_value="a-key"), patch(
        "backhoe.cli.shodan.lookup_host", return_value=[shodan_finding]
    ):
        result = runner.invoke(cli, ["infra-check", "cdn.example.com", "--no-censys"])

    assert result.exit_code == 0
    assert result.output.count("1.2.3.4:443") == 1
    assert "portscan" in result.output
    assert "shodan" in result.output


def test_infra_check_skips_censys_silently_when_no_key_available():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=True), patch(
        "backhoe.cli.keys.get_api_key", return_value=None
    ) as get_key_mock, patch(
        "backhoe.cli.censys.lookup_host"
    ) as lookup_mock:
        result = runner.invoke(cli, ["infra-check", "example.com", "--no-shodan"])

    assert result.exit_code == 0
    get_key_mock.assert_called_once()
    lookup_mock.assert_not_called()


def test_infra_check_skips_censys_with_no_censys_flag():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=True), patch(
        "backhoe.cli.keys.get_api_key"
    ) as get_key_mock:
        result = runner.invoke(cli, ["infra-check", "example.com", "--no-shodan", "--no-censys"])

    assert result.exit_code == 0
    get_key_mock.assert_not_called()


def test_infra_check_runs_censys_even_when_intercepted():
    runner = CliRunner()
    censys_finding = Finding(
        type=FindingType.OPEN_PORT, value="1.2.3.4:80", source="censys",
        raw={"port": 80, "service": "HTTP", "product": None, "version": None, "vulns": []},
    )
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=True), patch(
        "backhoe.cli.keys.get_api_key", return_value="a-key"
    ), patch("backhoe.cli.censys.lookup_host", return_value=[censys_finding]):
        result = runner.invoke(cli, ["infra-check", "example.com", "--no-shodan"])

    assert result.exit_code == 0
    assert "1.2.3.4:80" in result.output


def test_infra_check_warns_and_continues_on_censys_api_error():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=True), patch(
        "backhoe.cli.keys.get_api_key", return_value="a-key"
    ), patch("backhoe.cli.censys.lookup_host", side_effect=CensysAPIError("rate limited")):
        result = runner.invoke(cli, ["infra-check", "example.com", "--no-shodan"])

    assert result.exit_code == 0
    assert "rate limited" in result.output


def test_infra_check_merges_censys_and_portscan_open_port_on_same_ip_port():
    runner = CliRunner()
    censys_finding = Finding(
        type=FindingType.OPEN_PORT, value="1.2.3.4:443", source="censys",
        raw={"port": 443, "service": "HTTPS", "product": "nginx", "version": "1.18", "vulns": []},
    )
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=False), patch(
        "backhoe.cli.portscan.scan_ports", return_value={443: True}
    ), patch(
        "backhoe.cli.tls.get_certificate_info",
        return_value={"days_until_expiry": 60, "issuer": {}, "subject": {}, "san": []},
    ), patch("backhoe.cli.keys.get_api_key", return_value="a-key"), patch(
        "backhoe.cli.censys.lookup_host", return_value=[censys_finding]
    ):
        result = runner.invoke(cli, ["infra-check", "cdn.example.com", "--no-shodan"])

    assert result.exit_code == 0
    assert result.output.count("1.2.3.4:443") == 1
    assert "portscan" in result.output
    assert "censys" in result.output


def test_infra_check_merges_shodan_and_censys_and_portscan_on_same_ip_port():
    # The real point of running two keyed backends: prove all three sources
    # compose into one row instead of three, and the CVE from whichever
    # source has one still surfaces.
    runner = CliRunner()
    shodan_finding = Finding(
        type=FindingType.OPEN_PORT, value="1.2.3.4:443", source="shodan",
        raw={"port": 443, "service": "https", "product": "nginx", "version": "1.18", "vulns": []},
    )
    censys_finding = Finding(
        type=FindingType.OPEN_PORT, value="1.2.3.4:443", source="censys",
        raw={"port": 443, "service": "HTTPS", "product": None, "version": None, "vulns": ["CVE-2022-9999"]},
    )
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=False), patch(
        "backhoe.cli.portscan.scan_ports", return_value={443: True}
    ), patch(
        "backhoe.cli.tls.get_certificate_info",
        return_value={"days_until_expiry": 60, "issuer": {}, "subject": {}, "san": []},
    ), patch("backhoe.cli.keys.get_api_key", return_value="a-key"), patch(
        "backhoe.cli.shodan.lookup_host", return_value=[shodan_finding]
    ), patch("backhoe.cli.censys.lookup_host", return_value=[censys_finding]):
        result = runner.invoke(cli, ["infra-check", "cdn.example.com"])

    assert result.exit_code == 0
    assert result.output.count("1.2.3.4:443") == 1
    assert "portscan" in result.output
    assert "shodan" in result.output
    assert "censys" in result.output
    assert "CVE-2022-9999" in result.output
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_cli.py -v -k infra_check`
Expected: FAIL — `click.exceptions.NoSuchOption: --no-censys` on the 10 modified tests, and `AttributeError`-style failures on the 6 new Censys tests (`backhoe.cli.censys` doesn't exist as an attribute on the `cli` module yet).

- [ ] **Step 3: Write the implementation**

In `backhoe/cli.py`, replace the import block (lines 10-30) with:

```python
import ipaddress
import re
import sys

import click

from . import keys
from .backends import censys, crtsh, dns_checks, netcheck, portscan, shodan, spiderfoot, theharvester, tls
from .backends.censys import CENSYS_PROVIDER, CensysAPIError
from .backends.crtsh import CrtShError
from .backends.dns_checks import DnsCheckError
from .backends.gravatar import GravatarError, check_gravatar
from .backends.shodan import SHODAN_PROVIDER, ShodanAPIError
from .backends.spiderfoot import SpiderFootError, SpiderFootNotInstalled
from .backends.theharvester import TheHarvesterError, TheHarvesterNotInstalled
from .backends.tls import TlsError
from .resolve import resolve_many
from .schema import Finding, FindingType, merge_findings
from .scoring import score_all
from .report import render_report

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
```

Then find the `infra_check` command's decorators (starting at `@cli.command("infra-check")`) and add a new `--censys/--no-censys` option immediately after the existing `--shodan/--no-shodan` option, and add `censys_: bool` to the function signature:

```python
@cli.command("infra-check")
@click.argument("target")
@click.option(
    "--ports/--no-ports",
    default=True,
    help="Run the bounded common-port scan (default: on). Only use against infra you own or are authorized to test.",
)
@click.option(
    "--shodan/--no-shodan",
    "shodan_",  # avoid shadowing the imported `shodan` module below
    default=True,
    help=(
        "Enrich open-port findings with Shodan host-lookup data (service, "
        "product/version, known CVEs) if an API key is available (default: "
        "on). Runs even when this network intercepts TCP/TLS, since it's a "
        "passive API lookup, not raw TCP from this host. Prompts for a "
        "SHODAN_API_KEY the first time if none is set or stored."
    ),
)
@click.option(
    "--censys/--no-censys",
    "censys_",  # avoid shadowing the imported `censys` module below
    default=True,
    help=(
        "Enrich open-port findings with Censys host-lookup data (service, "
        "product/version, known CVEs) if an API key is available (default: "
        "on). Runs even when this network intercepts TCP/TLS, since it's a "
        "passive API lookup, not raw TCP from this host. Prompts for a "
        "CENSYS_API_KEY (a Censys Personal Access Token) the first time if "
        "none is set or stored."
    ),
)
def infra_check(target: str, ports: bool, shodan_: bool, censys_: bool):
    """
    Run an infrastructure recon profile against a domain or IP: resolved
    IPs + reverse DNS, a bounded common-port scan, the live TLS
    certificate's expiry, and (if a key is available) Shodan and/or
    Censys host-lookup enrichment.
    """
```

Finally, immediately after the existing Shodan block (the `if shodan_:` block, right before `findings = merge_findings(findings)`), add a new, structurally identical Censys block:

```python
    if shodan_:
        # Deliberately outside the interception guard above: this is a
        # passive API lookup, not raw TCP from this host, so it stays
        # trustworthy even on a network that intercepts TCP/TLS.
        key = keys.get_api_key(SHODAN_PROVIDER)
        if key:
            click.echo("Enriching with Shodan host-lookup data...\n")
            for ip in ips:
                try:
                    findings.extend(shodan.lookup_host(ip, key))
                except ShodanAPIError as exc:
                    click.secho(f"Shodan lookup skipped for {ip}: {exc}", fg="yellow", err=True)

    if censys_:
        # Same rationale as the Shodan block above: a passive API lookup,
        # not raw TCP from this host, so it runs regardless of network
        # interception status.
        key = keys.get_api_key(CENSYS_PROVIDER)
        if key:
            click.echo("Enriching with Censys host-lookup data...\n")
            for ip in ips:
                try:
                    findings.extend(censys.lookup_host(ip, key))
                except CensysAPIError as exc:
                    click.secho(f"Censys lookup skipped for {ip}: {exc}", fg="yellow", err=True)

    findings = merge_findings(findings)
    findings = score_all(findings)
    render_report(target, findings)
```

(The `if shodan_:` block shown above is unchanged — reproduced here only to show exactly where the new `if censys_:` block is inserted, immediately after it.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/ -v`
Expected: PASS — the full suite, including every pre-existing test and all 6 new Censys-wiring tests.

- [ ] **Step 5: Commit**

```bash
git add backhoe/cli.py tests/test_cli.py
git commit -m "$(cat <<'EOF'
Wire Censys enrichment into infra-check alongside Shodan

New --censys/--no-censys flag (default on), structurally identical to
--shodan/--no-shodan: runs outside the netcheck interception guard,
skips silently with no key configured, non-fatal yellow warning on
CensysAPIError. No scoring.py/report.py changes needed — Censys
findings use the same raw dict shape Shodan already established, so
merge_findings()/scoring's Task-3 fix and raw_get() handle both
sources identically. A new integration test proves all three sources
(portscan, Shodan, Censys) merge into one row on a shared ip:port.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_016NyETLkGrCBagbexj3vkj6
EOF
)"
```

---

### Task 3: Documentation — `CLAUDE.md` and `README.md`

**Files:**
- Modify: `CLAUDE.md` (architecture tree, "What's shipped", new "Censys" section, "What's NOT built yet", stale test count)
- Modify: `README.md` (`## Use` infra-check bullet, `## What it does right now` infra-check bullets, new "Optional: Censys enrichment" section, "What's coming next")

No test-writing step — this is documentation, verified by reading the diff, not by pytest. But don't skip it: every prior backend addition in this repo's history updated docs in the same pass as the code, and the Shodan branch's final review specifically flagged an out-of-scope doc update (README.md) as a real gap worth closing, not a nice-to-have.

- [ ] **Step 1: Run the full suite once first to get the final test count**

Run: `pytest -q` and note the final number reported (e.g. `154 passed`) — you'll need this exact number for Step 2 below. Do not guess or copy a number from this plan; the plan was written before Task 1/2 landed and cannot know the true final count.

- [ ] **Step 2: Update `CLAUDE.md`**

In the `## Architecture` section's file tree, change:

```
    shodan.py               Shodan host-lookup enrichment for infra-check,
                        needs an API key via keys.py — see "Shodan" below
```

to:

```
    shodan.py               Shodan host-lookup enrichment for infra-check,
                        needs an API key via keys.py — see "Shodan" below
    censys.py               Censys host-lookup enrichment for infra-check,
                        mirrors shodan.py's shape — see "Censys" below
```

In the `## What's shipped (v0.4)` section, change:

```
- `infra-check <target>` — resolve + reverse DNS, bounded 9-port scan,
  TLS cert expiry, with the interception guard above, plus optional
  Shodan host-lookup enrichment (see below)

123 tests, all passing, `pytest` from repo root (`pip install -e ".[dev]"`
first).
```

to (using the ACTUAL count from Step 1, not the placeholder shown here):

```
- `infra-check <target>` — resolve + reverse DNS, bounded 9-port scan,
  TLS cert expiry, with the interception guard above, plus optional
  Shodan and/or Censys host-lookup enrichment (see below)

<ACTUAL COUNT FROM STEP 1> tests, all passing, `pytest` from repo root
(`pip install -e ".[dev]"` first).
```

Insert a new section immediately after the existing `## Shodan (v0.4) — API-key wizard + host-lookup backend for infra-check` section (i.e. right before `## What's NOT built yet`):

```markdown
## Censys (v0.5) — second host-lookup backend, mirrors Shodan exactly

`backends/censys.py` is a second keyed enrichment source for
`infra-check`, alongside Shodan — same idea (richer per-port
service/product/version/CVE data than the built-in port scan), same
`requests`-only pattern, registered through the same `keys.py` wizard
Shodan already uses. Built to mirror `shodan.py`'s shape deliberately:

- **Same `raw` dict field names** on every `OPEN_PORT` `Finding`
  (`port`, `service`, `product`, `version`, `vulns`) as Shodan's
  backend — this is what let Censys land with **zero changes to
  `scoring.py` or `report.py`**: both already handle this shape
  generically, built for and validated against Shodan's Task 3 fix and
  final review.
- **Unlike Shodan, this backend's API shape was verified against
  Censys's live, current documentation** (`docs.censys.com`) during
  development, not from training-data memory alone — and that caught a
  real, concrete thing memory would have missed: Censys deprecated
  their old Basic-Auth (API-ID + secret) v2 Search API in favor of a
  newer Bearer-token "Platform API" (v3), which their own docs say all
  new scripted access should use. `censys.py` targets the new one
  exclusively.
- Auth is `Authorization: Bearer <token>` — a single Personal Access
  Token, fitting `keys.py`'s one-key `KeyProvider` model with no
  changes needed there. Unlike Shodan's query-param auth (which is what
  let the key leak into a `ConnectionError`'s own message in the Shodan
  final review), a Bearer header doesn't appear in a `requests`
  exception's stringified URL — a real security improvement, not just
  a different flavor of the same risk. `_redact_key()` is still applied
  defensively anyway, cheap insurance against a future error path or
  proxy layer embedding a header value.
- `censys.validate_key()` hits `/v3/accounts/users/credits`, confirmed
  live in Censys's own docs (quoted twice) to cost no credits — same
  role as Shodan's `/api-info`, letting `keys.py` re-validate a stored
  token on every `infra-check` run for free.
- `censys.lookup_host(ip, key)` hits `/v3/global/asset/host/<ip>`. A
  404 is treated as an empty result (not confirmed live for this
  specific endpoint — see the implementation plan's "Verification
  note" — but matches Shodan's precedent and general REST convention).
  Any other non-200, a network error, or unparseable JSON raises
  `CensysAPIError`.
- The `vulns` field's exact on-the-wire shape also wasn't confirmable
  from truncated doc content — the clearest signal found says it's a
  list of `{"id": "CVE-...", ...}` objects, a *different* shape from
  Shodan's (plain CVE-id strings or a dict keyed by CVE id), so
  `_extract_vuln_ids()` handles all three shapes rather than assuming
  the Censys-specific one.
- Censys can return multiple `services` entries; `_to_findings` groups
  them by port before building `Finding`s, for the identical reason
  Shodan's `_to_findings` does — two same-port entries sharing a dedup
  key and source would otherwise let `merge_findings()` silently let
  the second overwrite the first's `raw` (the Critical bug Shodan's
  final review caught and fixed).
- Wired into `infra-check` via `--censys/--no-censys` (default on),
  structurally identical to `--shodan/--no-shodan`: runs outside the
  `netcheck.py` interception guard (passive API call, not raw TCP),
  `CensysAPIError` caught non-fatally (yellow warning), a missing key
  skips silently. Both Shodan and Censys can run in the same
  `infra-check` call and merge on a shared `ip:port` — proven by a
  three-way integration test (portscan + Shodan + Censys all reporting
  the same port).
- **Not run against a live Censys account in this environment** — no
  Censys API key or account was available during development. Live
  documentation confirms the auth model, endpoints, and the free-to-call
  claim for the credits endpoint, but the exact host-lookup response
  shape (particularly `vulns`) and 404 behavior are handled defensively
  rather than confirmed. Worth a real smoke test the first time this
  runs somewhere with a live Censys Personal Access Token.
```

In the `## What's NOT built yet (don't claim otherwise)` section, change:

```
- Censys backend (Shodan is now built — see above; Censys would be a
  similar richer-port-data source, still not built)
```

to (i.e. delete that bullet entirely, since Censys is now built):

```
```

(No replacement line — just remove the Censys bullet. The section's other three bullets — HaveIBeenPwned, WHOIS, API-key setup wizard — are unaffected and stay as-is.)

- [ ] **Step 3: Update `README.md`**

In `## Use`, change:

```
- `infra-check` — resolves the target, reverse-DNS on each IP, a
  bounded common-port scan, the live TLS certificate's expiry, and (if
  a Shodan API key is available) Shodan host-lookup enrichment with
  service/product/version and known-CVE data. Pass `--no-ports` to
  skip the port scan, `--no-shodan` to skip Shodan. With `--shodan`
  (the default) and no `SHODAN_API_KEY` env var or stored key yet,
  `infra-check` prompts for one interactively on first run — see
  "Optional: Shodan enrichment" below.
```

to:

```
- `infra-check` — resolves the target, reverse-DNS on each IP, a
  bounded common-port scan, the live TLS certificate's expiry, and (if
  keys are available) Shodan and/or Censys host-lookup enrichment with
  service/product/version and known-CVE data. Pass `--no-ports` to
  skip the port scan, `--no-shodan`/`--no-censys` to skip either
  enrichment source. With both on by default and no `SHODAN_API_KEY`/
  `CENSYS_API_KEY` env var or stored key yet, `infra-check` prompts for
  each interactively on first run — see "Optional: Shodan enrichment"
  and "Optional: Censys enrichment" below.
```

In `## What it does right now (v0.4)`'s `**infra-check**` bullet list, change:

```
- (Optional) Shodan host-lookup enrichment for open ports — service,
  product/version, and known CVEs, when available — if you provide a
  free Shodan API key. Runs independently of the interception check
  below since it's a passive third-party API call, not raw TCP from
  this host. See "Optional: Shodan enrichment" below.
```

to:

```
- (Optional) Shodan and/or Censys host-lookup enrichment for open
  ports — service, product/version, and known CVEs, when available —
  if you provide a free API key for either or both. Findings from
  multiple sources on the same port merge into one row. Both run
  independently of the interception check below since they're passive
  third-party API calls, not raw TCP from this host. See "Optional:
  Shodan enrichment" and "Optional: Censys enrichment" below.
```

Insert a new section immediately after the existing `## Optional: Shodan enrichment` section (i.e. right before `## What's coming next`):

```markdown
## Optional: Censys enrichment

`infra-check` also enriches open-port findings with
[Censys](https://censys.io/) host-lookup data (service, product/
version, and known CVEs) if you provide a Censys Personal Access
Token — same idea as Shodan enrichment above, and the two can run
together in the same scan.

Resolution order: a `CENSYS_API_KEY` environment variable, then a key
already stored at `~/.config/backhoe/keys.json`, then an interactive
prompt on first run (hidden input) — leave it blank to skip. Skip
Censys entirely with `--no-censys`.

Runs even on a network `infra-check` detects as intercepting TCP/TLS —
it's a passive API call, not raw TCP from this host.

**Verification note:** unlike Shodan, this backend's API shape was
checked against Censys's live current documentation during
development — including catching that Censys's older API (Basic Auth,
API ID + secret) is deprecated in favor of the newer Bearer-token
Platform API this backend uses. Still not run against a live Censys
account end-to-end, though — the exact host-lookup response shape is
handled defensively rather than confirmed live.
```

In `## What's coming next`, change:

```
- Censys backend for richer port/service data (an alternative to, or
  complement of, Shodan)
- HaveIBeenPwned backend for breach hits (needs an API key)
```

to:

```
- HaveIBeenPwned backend for breach hits (needs an API key)
```

(Just remove the Censys bullet — the other three items are unaffected.)

- [ ] **Step 4: Verify the full suite still passes**

Run: `pytest -q`
Expected: PASS, same count as Step 1 (documentation changes don't affect test behavior).

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md README.md
git commit -m "$(cat <<'EOF'
Document Censys backend in CLAUDE.md and README.md

Moves Censys off both docs' "not built yet"/"coming next" lists,
adds a CLAUDE.md section mirroring the existing Shodan section's
depth (design decisions, verification-honesty note, error-handling
tier), and a README "Optional: Censys enrichment" section mirroring
Shodan's. Also fixes CLAUDE.md's stale test count (last updated
before the Shodan final-review fix wave landed more tests).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_016NyETLkGrCBagbexj3vkj6
EOF
)"
```
