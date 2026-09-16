# HIBP Breach-Hit Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `backhoe/backends/hibp.py`, a third keyed backend (alongside Shodan and Censys) that enriches `person-check` with real breach-hit data from HaveIBeenPwned's API v3, and upgrade `scoring.py`'s previously-generic `BREACH_HIT` scoring to use HIBP's actual per-breach data.

**Architecture:** `backends/hibp.py` is a `requests`-only backend (no SDK) registering itself as a `keys.KeyProvider`, mirroring `shodan.py`/`censys.py`'s shape but with a simpler 2-class error hierarchy (`HIBPError`/`HIBPAPIError` only — no `HIBPValidationError`, since `validate_key()` never touches the network). `scoring.py` gains `_score_breach_hit()`, replacing the hardcoded `BREACH_HIT` branch in `score_finding()` with logic driven by HIBP's `DataClasses`/`IsVerified`/`IsFabricated`/`IsSpamList` fields. `cli.py`'s `person-check` gains a `--hibp/--no-hibp` flag wiring the two together. No changes needed to `keys.py` (already provider-agnostic) or `report.py` (already handles `BREACH_HIT` generically).

**Tech Stack:** Python 3.10+, `click`, `requests`, `pytest` + `unittest.mock`. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-16-hibp-breach-backend-design.md`

## Global Constraints

- No new pip dependencies. `backhoe/backends/hibp.py` uses `requests` directly.
- Target Python 3.10+ (repo's `requires-python = ">=3.10"`) — no 3.11+-only syntax.
- Endpoint: `GET https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false`. The `truncateResponse=false` param is required — the default truncated response omits every field scoring needs.
- Required headers: `hibp-api-key: <key>` and a non-empty `User-Agent`. Missing `User-Agent` returns 403 — confirmed in HIBP's own current API v3 docs.
- Status codes: `200` → parse; `404` → legitimate empty result (`[]`), not an error; `401`/`403`/`429`/any other non-200/unparseable JSON → `HIBPAPIError`. A `429` response's error message includes the `Retry-After` header value when present.
- `validate_key(key: str) -> bool` is a **format-only check** (32-character hex string) with **no network call** — HIBP has no free key-validation endpoint (unlike Shodan's `/api-info` or Censys's `/accounts/users/credits`), confirmed against HIBP's current docs. It never raises, so there is deliberately **no `HIBPValidationError` class and no `KeyValidationError` subclass** for this backend — only `HIBPError` (base) and `HIBPAPIError` (lookup failures).
- No changes to `keys.py` or `report.py` — both already handle a new `KeyProvider` / `FindingType.BREACH_HIT` generically.
- No merge-collision defense needed in `_to_findings` (unlike Shodan/Censys's by-port grouping) — each breach's `Title` is naturally distinct within one `check_breaches()` call, and no other backend produces `BREACH_HIT` findings.

## File Structure

```
backhoe/
  backends/
    hibp.py                  NEW — HIBPError, HIBPAPIError, validate_key(),
                              check_breaches(), HIBP_PROVIDER
  scoring.py                  MODIFY — new _score_breach_hit(), replaces the
                              hardcoded BREACH_HIT branch in score_finding()
  cli.py                       MODIFY — --hibp/--no-hibp flag on person-check
tests/
  test_hibp.py                 NEW
  test_scoring_extended.py     MODIFY — new BREACH_HIT scoring cases
  test_cli.py                   MODIFY — --no-hibp added to 2 existing
                              person-check tests, 4 new HIBP-wiring tests
```

---

### Task 1: `backhoe/backends/hibp.py` — HIBP breach-hit backend

**Files:**
- Create: `backhoe/backends/hibp.py`
- Test: `tests/test_hibp.py`

**Interfaces:**
- Consumes: `backhoe.keys.KeyProvider` (existing — no `KeyValidationError` import needed, see Global Constraints). `backhoe.schema.Finding`, `backhoe.schema.FindingType` (existing).
- Produces: `validate_key(key: str) -> bool`, `check_breaches(email: str, key: str) -> list[Finding]`, `class HIBPError(Exception)`, `class HIBPAPIError(HIBPError)`, `HIBP_PROVIDER: KeyProvider` (module-level constant).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_hibp.py`:

```python
"""HIBP backend tests — network mocked so these run anywhere, including
sandboxes that block outbound traffic. No live HIBP API key was available
during development (HIBP's API has required a paid subscription since
2019) — see the design spec's "Verification honesty note". validate_key()
is a pure format check with no network call at all (HIBP has no free
validation endpoint, unlike Shodan/Censys), confirmed by the "never calls
requests.get" tests below."""
from unittest.mock import MagicMock, patch

import pytest
import requests

from backhoe.backends import hibp
from backhoe.backends.hibp import HIBPAPIError
from backhoe.schema import FindingType


def _response(status_code, json_data=None, json_error=None, headers=None):
    resp = MagicMock(status_code=status_code, headers=headers or {})
    if json_error is not None:
        resp.json.side_effect = json_error
    else:
        resp.json.return_value = json_data
    return resp


def test_validate_key_true_on_valid_format():
    assert hibp.validate_key("a" * 32) is True


def test_validate_key_true_on_valid_format_uppercase():
    assert hibp.validate_key("A" * 32) is True


def test_validate_key_false_on_wrong_length():
    assert hibp.validate_key("a" * 31) is False
    assert hibp.validate_key("a" * 33) is False


def test_validate_key_false_on_non_hex_chars():
    assert hibp.validate_key("g" * 32) is False


def test_validate_key_never_makes_a_network_call():
    with patch("backhoe.backends.hibp.requests.get") as mock_get:
        hibp.validate_key("a" * 32)
    mock_get.assert_not_called()


def test_check_breaches_returns_empty_list_on_404():
    with patch("backhoe.backends.hibp.requests.get", return_value=_response(404)):
        assert hibp.check_breaches("user@example.com", "a" * 32) == []


def test_check_breaches_raises_on_401():
    with patch("backhoe.backends.hibp.requests.get", return_value=_response(401)):
        with pytest.raises(HIBPAPIError):
            hibp.check_breaches("user@example.com", "a" * 32)


def test_check_breaches_raises_on_403():
    with patch("backhoe.backends.hibp.requests.get", return_value=_response(403)):
        with pytest.raises(HIBPAPIError):
            hibp.check_breaches("user@example.com", "a" * 32)


def test_check_breaches_raises_on_429_includes_retry_after():
    with patch(
        "backhoe.backends.hibp.requests.get",
        return_value=_response(429, headers={"Retry-After": "5"}),
    ):
        with pytest.raises(HIBPAPIError) as excinfo:
            hibp.check_breaches("user@example.com", "a" * 32)
    assert "5" in str(excinfo.value)


def test_check_breaches_raises_on_429_without_retry_after_header():
    with patch("backhoe.backends.hibp.requests.get", return_value=_response(429)):
        with pytest.raises(HIBPAPIError):
            hibp.check_breaches("user@example.com", "a" * 32)


def test_check_breaches_raises_on_network_error():
    with patch("backhoe.backends.hibp.requests.get", side_effect=requests.ConnectionError("nope")):
        with pytest.raises(HIBPAPIError):
            hibp.check_breaches("user@example.com", "a" * 32)


def test_check_breaches_raises_on_unparseable_json():
    with patch(
        "backhoe.backends.hibp.requests.get",
        return_value=_response(200, json_error=ValueError("bad")),
    ):
        with pytest.raises(HIBPAPIError):
            hibp.check_breaches("user@example.com", "a" * 32)


def test_check_breaches_raises_on_non_list_response():
    with patch("backhoe.backends.hibp.requests.get", return_value=_response(200, {"unexpected": "shape"})):
        with pytest.raises(HIBPAPIError):
            hibp.check_breaches("user@example.com", "a" * 32)


def test_check_breaches_sends_required_headers_and_query_param():
    mock_get = MagicMock(return_value=_response(200, []))
    with patch("backhoe.backends.hibp.requests.get", mock_get):
        hibp.check_breaches("user@example.com", "mykey")
    _, kwargs = mock_get.call_args
    assert kwargs["headers"]["hibp-api-key"] == "mykey"
    assert kwargs["headers"]["User-Agent"]
    assert kwargs["params"]["truncateResponse"] == "false"


def test_check_breaches_url_encodes_the_email():
    mock_get = MagicMock(return_value=_response(200, []))
    with patch("backhoe.backends.hibp.requests.get", mock_get):
        hibp.check_breaches("user+tag@example.com", "mykey")
    args, _ = mock_get.call_args
    assert "user%2Btag%40example.com" in args[0]


def test_check_breaches_parses_multiple_breaches():
    payload = [
        {
            "Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com",
            "BreachDate": "2013-10-04", "PwnCount": 152445165,
            "DataClasses": ["Email addresses", "Passwords"],
            "IsVerified": True, "IsFabricated": False,
            "IsSensitive": False, "IsRetired": False, "IsSpamList": False,
        },
        {
            "Name": "Gawker", "Title": "Gawker", "Domain": "gawker.com",
            "BreachDate": "2010-12-11", "PwnCount": 1247394,
            "DataClasses": ["Email addresses", "Passwords", "Usernames"],
            "IsVerified": True, "IsFabricated": False,
            "IsSensitive": False, "IsRetired": False, "IsSpamList": False,
        },
    ]
    with patch("backhoe.backends.hibp.requests.get", return_value=_response(200, payload)):
        findings = hibp.check_breaches("user@example.com", "a" * 32)

    assert {f.value for f in findings} == {"Adobe", "Gawker"}
    assert all(f.type == FindingType.BREACH_HIT for f in findings)
    assert all(f.source == "hibp" for f in findings)
    adobe = next(f for f in findings if f.value == "Adobe")
    assert adobe.raw["domain"] == "adobe.com"
    assert adobe.raw["breach_date"] == "2013-10-04"
    assert adobe.raw["data_classes"] == ["Email addresses", "Passwords"]
    assert adobe.raw["is_verified"] is True


def test_check_breaches_handles_missing_optional_fields():
    payload = [{"Title": "Mystery Breach"}]
    with patch("backhoe.backends.hibp.requests.get", return_value=_response(200, payload)):
        findings = hibp.check_breaches("user@example.com", "a" * 32)

    assert len(findings) == 1
    f = findings[0]
    assert f.value == "Mystery Breach"
    assert f.raw["data_classes"] == []
    assert f.raw["domain"] is None
    assert f.raw["is_verified"] is None


def test_check_breaches_skips_entries_with_no_title():
    payload = [{"Name": "no-title-entry"}]
    with patch("backhoe.backends.hibp.requests.get", return_value=_response(200, payload)):
        findings = hibp.check_breaches("user@example.com", "a" * 32)
    assert findings == []


def test_check_breaches_error_never_leaks_raw_key():
    key = "SUPERSECRETKEY1234567890ABCDEF0"
    err = requests.ConnectionError(
        f"HTTPSConnectionPool(host='haveibeenpwned.com', port=443): Max retries exceeded "
        f"with url: /api/v3/breachedaccount/user@example.com (Caused by NewConnectionError(...)) key={key}"
    )
    with patch("backhoe.backends.hibp.requests.get", side_effect=err):
        with pytest.raises(HIBPAPIError) as excinfo:
            hibp.check_breaches("user@example.com", key)
    assert key not in str(excinfo.value)


def test_hibp_provider_is_registered_correctly():
    assert hibp.HIBP_PROVIDER.name == "hibp"
    assert hibp.HIBP_PROVIDER.env_var == "HIBP_API_KEY"
    assert hibp.HIBP_PROVIDER.validate is hibp.validate_key
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_hibp.py -v`
Expected: FAIL (or ERROR) with `ModuleNotFoundError: No module named 'backhoe.backends.hibp'`

- [ ] **Step 3: Write the implementation**

Create `backhoe/backends/hibp.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_hibp.py -v`
Expected: PASS (20 tests)

- [ ] **Step 5: Commit**

```bash
git add backhoe/backends/hibp.py tests/test_hibp.py
git commit -F - <<'EOF'
Add HIBP breach-hit backend for person-check

requests-only, no shodan-SDK-style dependency. check_breaches() maps
each breach object to a BREACH_HIT Finding; a 404 (no breaches) is a
legitimate empty result, not an error. Unlike Shodan/Censys,
validate_key() is a format-only check (32-hex-char key) with no
network call at all — HIBP has no free key-validation endpoint,
confirmed against HIBP's current API v3 docs, so there's no
HIBPValidationError/KeyValidationError subclass here. Not run
against a live HIBP account in this environment (no key available —
HIBP's API has been paid-only since 2019) — built from HIBP's
published API docs and tested against mocked HTTP only, same
verification tier Shodan's and Censys's backends carry.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
```

---

### Task 2: `scoring.py` — `_score_breach_hit`, driven by HIBP's real data

**Files:**
- Modify: `backhoe/scoring.py` (the `FindingType.BREACH_HIT` branch inside `score_finding()`, currently at `backhoe/scoring.py:43-46`)
- Test: `tests/test_scoring_extended.py`

**Interfaces:**
- Consumes: the `raw` dict shape Task 1's `hibp.py` produces (`data_classes: list[str]`, `is_verified: bool | None`, `is_fabricated: bool | None`, `is_spam_list: bool | None`, `breach_date: str | None`).
- Produces: no new public names — `score_finding(finding: Finding) -> Finding` keeps its existing signature; a new private `_score_breach_hit(finding: Finding) -> None` is added alongside the other `_score_*` helpers.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_scoring_extended.py`. First, check the file's existing imports at the top (it already imports `Finding`, `FindingType`, `score_finding` — reuse those, don't re-import):

```python
def test_breach_hit_verified_password_breach_scores_highest():
    f = Finding(
        type=FindingType.BREACH_HIT, value="Adobe", source="hibp",
        raw={
            "breach_date": "2013-10-04",
            "data_classes": ["Email addresses", "Passwords"],
            "is_verified": True, "is_fabricated": False, "is_spam_list": False,
        },
    )
    score_finding(f)
    assert f.confidence == 0.85
    assert f.interest == 1.0
    assert "2013 breach" in f.note
    assert "Email addresses" in f.note
    assert "Passwords" in f.note


def test_breach_hit_fabricated_scores_low_confidence():
    f = Finding(
        type=FindingType.BREACH_HIT, value="FakeCo", source="hibp",
        raw={"breach_date": "2020-01-01", "data_classes": ["Email addresses"], "is_fabricated": True},
    )
    score_finding(f)
    assert f.confidence == 0.3
    assert "fabricated" in f.note


def test_breach_hit_unverified_scores_medium_confidence():
    f = Finding(
        type=FindingType.BREACH_HIT, value="UnverifiedCo", source="hibp",
        raw={"breach_date": "2020-01-01", "data_classes": ["Email addresses"], "is_verified": False},
    )
    score_finding(f)
    assert f.confidence == 0.5
    assert "unverified" in f.note


def test_breach_hit_spam_list_scores_lower_interest():
    f = Finding(
        type=FindingType.BREACH_HIT, value="SpamCo", source="hibp",
        raw={
            "breach_date": "2020-01-01", "data_classes": ["Email addresses"],
            "is_verified": True, "is_spam_list": True,
        },
    )
    score_finding(f)
    assert f.interest == 0.5
    assert "spam list" in f.note


def test_breach_hit_without_password_class_scores_baseline_interest():
    f = Finding(
        type=FindingType.BREACH_HIT, value="EmailOnlyCo", source="hibp",
        raw={"breach_date": "2020-01-01", "data_classes": ["Email addresses"], "is_verified": True},
    )
    score_finding(f)
    assert f.interest == 0.9


def test_breach_hit_data_classes_truncated_after_four():
    f = Finding(
        type=FindingType.BREACH_HIT, value="BigLeakCo", source="hibp",
        raw={
            "breach_date": "2020-01-01",
            "data_classes": ["A", "B", "C", "D", "E"],
            "is_verified": True,
        },
    )
    score_finding(f)
    assert "A, B, C, D..." in f.note
    assert "E" not in f.note.split("...")[0]


def test_breach_hit_with_no_data_and_no_flags_falls_back_to_generic_note():
    f = Finding(type=FindingType.BREACH_HIT, value="BareBreach", source="hibp", raw={})
    score_finding(f)
    assert f.confidence == 0.85
    assert f.interest == 0.9
    assert f.note == "credential exposure — verify and rotate"


def test_breach_hit_partial_passwords_still_counts_as_credential_exposure():
    f = Finding(
        type=FindingType.BREACH_HIT, value="PartialPwCo", source="hibp",
        raw={
            "breach_date": "2020-01-01",
            "data_classes": ["Partial passwords"],
            "is_verified": True,
        },
    )
    score_finding(f)
    assert f.interest == 1.0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_scoring_extended.py -v -k breach_hit`
Expected: FAIL — every new test fails because `score_finding()` currently hardcodes `confidence=0.85, interest=0.9, note="credential exposure — verify and rotate"` for every `BREACH_HIT` regardless of `raw`, so e.g. `test_breach_hit_fabricated_scores_low_confidence` (expects `0.3`) and `test_breach_hit_spam_list_scores_lower_interest` (expects `0.5`) fail their assertions; the truncation and note-content tests fail because the current note never mentions the breach date or data classes.

- [ ] **Step 3: Write the implementation**

In `backhoe/scoring.py`, replace the `BREACH_HIT` branch inside `score_finding()`:

```python
    elif finding.type == FindingType.BREACH_HIT:
        finding.confidence = 0.85
        finding.interest = 0.9
        finding.note = finding.note or "credential exposure — verify and rotate"
```

with:

```python
    elif finding.type == FindingType.BREACH_HIT:
        _score_breach_hit(finding)
```

Then add `_score_breach_hit` alongside the other `_score_*` helpers (e.g. directly after `_score_open_port` and its `SENSITIVE_PORTS`/`_parse_port`/`_collect_vulns` block):

```python
# DataClasses substrings that mean actual credentials were exposed, not
# just an email address turning up on a list. Substring match (not exact)
# so "Partial passwords" — one of HIBP's own DataClasses values — still
# counts, matching the substance of a "Passwords" hit.
_CREDENTIAL_DATA_CLASS_HINTS = ("password",)


def _has_credential_exposure(data_classes: list[str]) -> bool:
    return any(
        any(hint in dc.lower() for hint in _CREDENTIAL_DATA_CLASS_HINTS)
        for dc in data_classes
    )


def _score_breach_hit(finding: Finding) -> None:
    raw = finding.raw
    is_fabricated = raw.get("is_fabricated")
    is_verified = raw.get("is_verified")
    is_spam_list = raw.get("is_spam_list")
    data_classes = raw.get("data_classes") or []

    if is_fabricated:
        finding.confidence = 0.3
    elif is_verified is False:
        finding.confidence = 0.5
    else:
        finding.confidence = 0.85

    if is_spam_list:
        finding.interest = 0.5
    elif _has_credential_exposure(data_classes):
        finding.interest = 1.0
    else:
        finding.interest = 0.9

    if finding.note:
        return

    caveats = []
    if is_fabricated:
        caveats.append("flagged by HIBP as fabricated")
    elif is_verified is False:
        caveats.append("unverified, treat with caution")
    if is_spam_list:
        caveats.append("flagged as a spam list, not a confirmed breach")

    if not data_classes and not caveats:
        finding.note = "credential exposure — verify and rotate"
        return

    breach_date = raw.get("breach_date")
    year = str(breach_date)[:4] if breach_date else None
    note = f"{year} breach" if year else "breach"

    if data_classes:
        shown = ", ".join(data_classes[:4]) + ("..." if len(data_classes) > 4 else "")
        note += f" — exposed: {shown}"

    if caveats:
        note += "; " + "; ".join(caveats)

    finding.note = note
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_scoring.py tests/test_scoring_extended.py -v`
Expected: PASS (all tests, including every pre-existing scoring test — none of them touch `BREACH_HIT`, so none should change behavior)

- [ ] **Step 5: Commit**

```bash
git add backhoe/scoring.py tests/test_scoring_extended.py
git commit -F - <<'EOF'
Score BREACH_HIT findings from HIBP's real per-breach data

Replaces the hardcoded confidence=0.85/interest=0.9/static-note
BREACH_HIT branch (written before any real breach backend existed)
with _score_breach_hit(), which reads HIBP's DataClasses/IsVerified/
IsFabricated/IsSpamList fields: a fabricated breach drops confidence
to 0.3, an unverified one to 0.5; a breach exposing passwords (or
"Partial passwords") scores the highest interest, a spam-list hit
the lowest. The note is now built from the actual breach date and
exposed data classes instead of a fixed string, mirroring the
CVE-boost pattern _score_open_port already uses for Shodan/Censys.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
```

---

### Task 3: `cli.py` — wire HIBP into `person-check`

**Files:**
- Modify: `backhoe/cli.py:1-31` (imports), `backhoe/cli.py:111-171` (the `person_check` command — verify exact current line range before editing, since Task 1/2 don't touch `cli.py` and line numbers won't have shifted)
- Modify: `tests/test_cli.py:1-12` (imports), two existing `person-check` tests need `--no-hibp` added, four new tests appended

**Interfaces:**
- Consumes: `keys.get_api_key` (existing), `hibp.check_breaches`, `hibp.HIBPAPIError`, `hibp.HIBP_PROVIDER` (Task 1), `scoring.score_all` (existing, now benefits from Task 2's enrichment).
- Produces: new `--hibp/--no-hibp` CLI flag on `person-check` (default on).

- [ ] **Step 1: Write the failing tests**

In `tests/test_cli.py`, add this import alongside the existing backend imports at the top of the file:

```python
from backhoe.backends.hibp import HIBP_PROVIDER, HIBPAPIError
```

Modify the two existing `person-check` tests that reach the HIBP-wiring point, adding `--no-hibp` (same convention `--no-shodan`/`--no-censys` already use on `infra-check` tests that aren't specifically testing those backends):

```python
def test_person_check_exits_nonzero_on_dns_failure():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.check_mx", side_effect=DnsCheckError("boom")):
        result = runner.invoke(cli, ["person-check", "user@example.com", "--no-hibp"])
    assert result.exit_code != 0


def test_person_check_happy_path_continues_without_gravatar():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.check_mx", return_value=["mail.example.com"]), patch(
        "backhoe.cli.dns_checks.check_spf", return_value="v=spf1 ~all"
    ), patch("backhoe.cli.dns_checks.check_dmarc", return_value=(True, "reject")), patch(
        "backhoe.cli.check_gravatar", side_effect=GravatarError("network down")
    ):
        result = runner.invoke(cli, ["person-check", "user@example.com", "--no-hibp"])
    assert result.exit_code == 0
    assert "Gravatar check skipped" in result.output
    assert "example.com" in result.output
```

(`test_person_check_rejects_invalid_email` is unchanged — it fails email validation before any backend runs, `--hibp` or not.)

Append these four new tests at the end of `tests/test_cli.py`:

```python
def test_person_check_skips_hibp_silently_when_no_key_available():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.check_mx", return_value=["mail.example.com"]), patch(
        "backhoe.cli.dns_checks.check_spf", return_value="v=spf1 ~all"
    ), patch("backhoe.cli.dns_checks.check_dmarc", return_value=(True, "reject")), patch(
        "backhoe.cli.check_gravatar", return_value=False
    ), patch(
        "backhoe.cli.keys.get_api_key", return_value=None
    ) as get_key_mock, patch(
        "backhoe.cli.hibp_backend.check_breaches"
    ) as check_mock:
        result = runner.invoke(cli, ["person-check", "user@example.com"])

    assert result.exit_code == 0
    get_key_mock.assert_called_once_with(HIBP_PROVIDER)
    check_mock.assert_not_called()


def test_person_check_skips_hibp_with_no_hibp_flag():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.check_mx", return_value=["mail.example.com"]), patch(
        "backhoe.cli.dns_checks.check_spf", return_value="v=spf1 ~all"
    ), patch("backhoe.cli.dns_checks.check_dmarc", return_value=(True, "reject")), patch(
        "backhoe.cli.check_gravatar", return_value=False
    ), patch(
        "backhoe.cli.keys.get_api_key"
    ) as get_key_mock:
        result = runner.invoke(cli, ["person-check", "user@example.com", "--no-hibp"])

    assert result.exit_code == 0
    get_key_mock.assert_not_called()


def test_person_check_reports_hibp_breach_hit():
    runner = CliRunner()
    breach_finding = Finding(
        type=FindingType.BREACH_HIT, value="Adobe", source="hibp",
        raw={
            "name": "Adobe", "title": "Adobe", "domain": "adobe.com",
            "breach_date": "2013-10-04", "pwn_count": 152445165,
            "data_classes": ["Email addresses", "Passwords"],
            "is_verified": True, "is_fabricated": False,
            "is_sensitive": False, "is_retired": False, "is_spam_list": False,
        },
    )
    with patch("backhoe.cli.dns_checks.check_mx", return_value=["mail.example.com"]), patch(
        "backhoe.cli.dns_checks.check_spf", return_value="v=spf1 ~all"
    ), patch("backhoe.cli.dns_checks.check_dmarc", return_value=(True, "reject")), patch(
        "backhoe.cli.check_gravatar", return_value=False
    ), patch(
        "backhoe.cli.keys.get_api_key", return_value="a-key"
    ), patch(
        "backhoe.cli.hibp_backend.check_breaches", return_value=[breach_finding]
    ):
        result = runner.invoke(cli, ["person-check", "user@example.com"])

    assert result.exit_code == 0
    assert "Adobe" in result.output
    assert "hibp" in result.output


def test_person_check_warns_and_continues_on_hibp_api_error():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.check_mx", return_value=["mail.example.com"]), patch(
        "backhoe.cli.dns_checks.check_spf", return_value="v=spf1 ~all"
    ), patch("backhoe.cli.dns_checks.check_dmarc", return_value=(True, "reject")), patch(
        "backhoe.cli.check_gravatar", return_value=False
    ), patch(
        "backhoe.cli.keys.get_api_key", return_value="a-key"
    ), patch(
        "backhoe.cli.hibp_backend.check_breaches", side_effect=HIBPAPIError("rate limited")
    ):
        result = runner.invoke(cli, ["person-check", "user@example.com"])

    assert result.exit_code == 0
    assert "rate limited" in result.output
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_cli.py -v -k person_check`
Expected: FAIL — `click.exceptions.NoSuchOption: --no-hibp` on the two modified tests, and `AttributeError: <module 'backhoe.cli'> does not have the attribute 'hibp_backend'` on the four new tests.

- [ ] **Step 3: Write the implementation**

In `backhoe/cli.py`, modify the import block. The current imports are:

```python
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
```

Change the `from .backends import ...` line to add `hibp as hibp_backend` (aliased — the `--hibp` flag's parameter is named `hibp`, which would otherwise shadow a plain `hibp` module import inside `person_check`, the same reason `infra-check` aliases its `shodan`/`censys` flag params instead), and add the `HIBP_PROVIDER`/`HIBPAPIError` import line:

```python
from . import keys
from .backends import censys, crtsh, dns_checks, hibp as hibp_backend, netcheck, portscan, shodan, spiderfoot, theharvester, tls
from .backends.censys import CENSYS_PROVIDER, CensysAPIError
from .backends.crtsh import CrtShError
from .backends.dns_checks import DnsCheckError
from .backends.gravatar import GravatarError, check_gravatar
from .backends.hibp import HIBP_PROVIDER, HIBPAPIError
from .backends.shodan import SHODAN_PROVIDER, ShodanAPIError
from .backends.spiderfoot import SpiderFootError, SpiderFootNotInstalled
from .backends.theharvester import TheHarvesterError, TheHarvesterNotInstalled
from .backends.tls import TlsError
```

Then replace the `person_check` command (currently the `@cli.command("person-check")` block) with:

```python
@cli.command("person-check")
@click.argument("email")
@click.option(
    "--hibp/--no-hibp",
    default=True,
    help=(
        "Check the address against HaveIBeenPwned's breach database if "
        "an API key is available (default: on). Prompts for an "
        "HIBP_API_KEY the first time if none is set or stored."
    ),
)
def person_check(email: str, hibp: bool):
    """
    Run an email recon profile: mail security posture (MX/SPF/DMARC) for
    the domain, a Gravatar existence check for the address itself, and
    (if a key is available) a HaveIBeenPwned breach-hit check.
    """
    email = email.strip()
    if not EMAIL_RE.match(email):
        click.secho(f"'{email}' doesn't look like a valid email address.", fg="red", err=True)
        sys.exit(1)

    domain = email.rsplit("@", 1)[1]
    click.echo(f"Running person-check against {email}...\n")

    findings: list[Finding] = []

    try:
        mx_records = dns_checks.check_mx(domain)
        findings.append(
            Finding(
                type=FindingType.DNS_RECORD,
                value=domain,
                source="dns",
                raw={"record_type": "mx", "present": bool(mx_records), "records": mx_records},
            )
        )

        spf = dns_checks.check_spf(domain)
        findings.append(
            Finding(
                type=FindingType.DNS_RECORD,
                value=domain,
                source="dns",
                raw={"record_type": "spf", "present": spf is not None, "record": spf},
            )
        )

        dmarc_present, dmarc_policy = dns_checks.check_dmarc(domain)
        findings.append(
            Finding(
                type=FindingType.DNS_RECORD,
                value=domain,
                source="dns",
                raw={"record_type": "dmarc", "present": dmarc_present, "policy": dmarc_policy},
            )
        )
    except DnsCheckError as exc:
        click.secho(f"DNS lookup failed: {exc}", fg="red", err=True)
        sys.exit(1)

    try:
        has_gravatar = check_gravatar(email)
        findings.append(
            Finding(type=FindingType.EMAIL, value=email, source="gravatar", raw={"gravatar": has_gravatar})
        )
    except GravatarError as exc:
        click.secho(f"Gravatar check skipped: {exc}", fg="yellow", err=True)

    if hibp:
        key = keys.get_api_key(HIBP_PROVIDER)
        if key:
            click.echo("Checking HaveIBeenPwned for breach hits...\n")
            try:
                findings.extend(hibp_backend.check_breaches(email, key))
            except HIBPAPIError as exc:
                click.secho(f"HIBP check skipped: {exc}", fg="yellow", err=True)

    findings = score_all(findings)
    render_report(email, findings)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/ -v`
Expected: PASS — the full suite, including every pre-existing test and the new/modified `person-check` tests.

- [ ] **Step 5: Commit**

```bash
git add backhoe/cli.py tests/test_cli.py
git commit -F - <<'EOF'
Wire HIBP breach-hit checking into person-check

New --hibp/--no-hibp flag (default on). A missing key (no env var,
nothing stored, blank prompt) skips silently, same tier as Shodan/
Censys with no key in infra-check. HIBPAPIError caught non-fatally
(yellow warning, person-check continues on whatever it already has)
— same tier as a Gravatar failure. The hibp backend module is
imported as hibp_backend to avoid shadowing the --hibp flag's own
boolean parameter, mirroring how infra-check aliases its shodan_/
censys_ flag params instead (there the flag names needed the alias;
here the import does).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
```

---

## Post-implementation: update `CLAUDE.md`

After all three tasks are committed, update the repo's `CLAUDE.md` to move HIBP off the "What's NOT built yet" list and document it alongside Shodan/Censys, including the same verification-honesty caveat carried in this plan and the spec (no live HIBP account was available during development). This isn't a separate task with its own tests — it's documentation — but don't skip it: every other backend addition in this repo's history updated `CLAUDE.md` in the same pass, and an out-of-date handoff doc is exactly the kind of thing this repo's own conventions exist to prevent. Also update the "shipped" test count if it's mentioned there (check for a hardcoded number like "N tests, all passing" and update it to match `pytest`'s actual final count after this plan's three tasks land).
