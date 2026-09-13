# Shodan Backend + API-Key Wizard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a generic API-key resolution subsystem (`backhoe/keys.py`) and build BACKHOE's first keyed backend on top of it — a Shodan host-lookup enrichment for `infra-check` — while fixing a raw-dict/merge interaction bug in `scoring.py` that adding a second `OPEN_PORT`-producing backend exposes.

**Architecture:** `backhoe/keys.py` is a standalone module with no dependency on any backend — a `KeyProvider` dataclass (name, env var, prompt label, validate function) and one `get_api_key()` resolution function backends call instead of touching `os.environ` themselves. `backhoe/backends/shodan.py` is a `requests`-only backend (no SDK) that registers itself as a `KeyProvider` and produces `OPEN_PORT` Findings. `cli.py`'s `infra-check` wires both together behind a `--shodan/--no-shodan` flag, running Shodan lookups independently of the existing `netcheck` sandbox-interception guard. `scoring.py`'s `_score_open_port` is fixed to read the port from `Finding.value` instead of `Finding.raw`, because `merge_findings()` can reshape `raw` once two sources report the same port.

**Tech Stack:** Python 3.10+, `click` (CLI + prompts), `requests` (HTTP), `pytest` + `unittest.mock` (tests). No new dependencies — `requests` is already a project dependency; the official `shodan` SDK is deliberately not used.

**Spec:** `docs/superpowers/specs/2026-09-12-shodan-key-wizard-design.md`

## Global Constraints

- No new pip dependencies. `backhoe/backends/shodan.py` uses `requests` directly, never the `shodan` SDK.
- Target Python 3.10+ (repo's `requires-python = ">=3.10"`, `pyproject.toml`) — no 3.11+-only syntax.
- Key storage: `~/.config/backhoe/keys.json`, directory permissions `0700`, file permissions `0600`.
- `get_api_key()` returning `None` is a normal outcome (operator declined to configure a key) — never raise for it, never warn about it beyond what the resolution flow itself already printed.
- `KeyValidationError` (an inconclusive check — network blip, provider outage) must NEVER trigger a re-prompt or be treated as "the key is wrong." Only a conclusive `validate() == False` does that.
- Shodan's `/api-info` endpoint costs no query credit (confirmed against Shodan's own API docs during design) — this is what makes per-call live validation of a stored key acceptable.
- A Shodan host-lookup 404 is a legitimate empty result ("not indexed"), not an error — matches the project's existing "fail loud, never fake" rule (see `CLAUDE.md`).
- Shodan lookups in `infra-check` run independently of `netcheck.tcp_tls_is_intercepted()` — they are a passive API call, not raw TCP from this host, so they stay trustworthy in a sandboxed/intercepted network where the built-in port scan and TLS fetch are skipped.
- Shodan's per-banner `vulns` field shape (list of CVE strings vs. dict keyed by CVE ID) is NOT verified live in this environment (no API key or live network access during development — see the spec's "Verification honesty note"). Code must handle both shapes defensively via `.get()`/type-checking, never assume one.

## File Structure

```
backhoe/
  keys.py                    NEW — KeyProvider, KeyValidationError, get_api_key()
  backends/
    shodan.py                NEW — Shodan host-lookup backend + SHODAN_PROVIDER
  scoring.py                  MODIFY — _score_open_port fix (port from value, vulns boost)
  cli.py                       MODIFY — --shodan/--no-shodan flag on infra-check
tests/
  test_keys.py                NEW
  test_shodan.py               NEW
  test_scoring_extended.py     MODIFY — new OPEN_PORT cases
  test_cli.py                   MODIFY — new Shodan-wiring tests + --no-shodan on 5 existing tests
```

---

### Task 1: `backhoe/keys.py` — generic API-key resolution

**Files:**
- Create: `backhoe/keys.py`
- Test: `tests/test_keys.py`

**Interfaces:**
- Produces: `KeyProvider(name: str, env_var: str, prompt_label: str, validate: Callable[[str], bool])` (frozen dataclass), `class KeyValidationError(Exception)`, `get_api_key(provider: KeyProvider) -> str | None`, module globals `KEY_DIR: Path`, `KEY_FILE: Path` (tests monkeypatch these to isolate from the real home directory).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_keys.py`:

```python
"""Generic key-wizard tests. KEY_DIR/KEY_FILE are monkeypatched to a temp
path in every test so nothing here ever touches the real
~/.config/backhoe/keys.json."""
import json
import stat
from unittest.mock import MagicMock, patch

from backhoe import keys as keys_module
from backhoe.keys import KeyProvider, KeyValidationError, get_api_key


def _isolate_key_file(tmp_path, monkeypatch):
    key_dir = tmp_path / "backhoe-keys"
    monkeypatch.setattr(keys_module, "KEY_DIR", key_dir)
    monkeypatch.setattr(keys_module, "KEY_FILE", key_dir / "keys.json")


def _provider(validate):
    return KeyProvider(name="testprov", env_var="TESTPROV_API_KEY", prompt_label="Test API key", validate=validate)


def test_env_var_short_circuits_and_never_validates(tmp_path, monkeypatch):
    _isolate_key_file(tmp_path, monkeypatch)
    monkeypatch.setenv("TESTPROV_API_KEY", "from-env")
    validate = MagicMock(side_effect=AssertionError("must not be called"))

    result = get_api_key(_provider(validate))

    assert result == "from-env"
    validate.assert_not_called()


def test_valid_stored_key_used_silently(tmp_path, monkeypatch, capsys):
    _isolate_key_file(tmp_path, monkeypatch)
    monkeypatch.delenv("TESTPROV_API_KEY", raising=False)
    keys_module._write_stored_key("testprov", "stored-key")
    validate = MagicMock(return_value=True)

    result = get_api_key(_provider(validate))

    assert result == "stored-key"
    assert capsys.readouterr().err == ""


def test_invalid_stored_key_triggers_prompt(tmp_path, monkeypatch):
    _isolate_key_file(tmp_path, monkeypatch)
    monkeypatch.delenv("TESTPROV_API_KEY", raising=False)
    keys_module._write_stored_key("testprov", "bad-key")
    validate = MagicMock(side_effect=[False, True])  # stored check fails, fresh entry succeeds

    with patch("backhoe.keys.click.prompt", return_value="new-key"):
        result = get_api_key(_provider(validate))

    assert result == "new-key"
    assert json.loads(keys_module.KEY_FILE.read_text()) == {"testprov": "new-key"}


def test_inconclusive_stored_key_validation_uses_stale_key(tmp_path, monkeypatch, capsys):
    _isolate_key_file(tmp_path, monkeypatch)
    monkeypatch.delenv("TESTPROV_API_KEY", raising=False)
    keys_module._write_stored_key("testprov", "stored-key")
    validate = MagicMock(side_effect=KeyValidationError("network blip"))

    result = get_api_key(_provider(validate))

    assert result == "stored-key"
    assert "network blip" in capsys.readouterr().err


def test_prompt_skip_on_blank_returns_none_and_does_not_write_file(tmp_path, monkeypatch):
    _isolate_key_file(tmp_path, monkeypatch)
    monkeypatch.delenv("TESTPROV_API_KEY", raising=False)
    validate = MagicMock(side_effect=AssertionError("must not be called on blank input"))

    with patch("backhoe.keys.click.prompt", return_value=""):
        result = get_api_key(_provider(validate))

    assert result is None
    assert not keys_module.KEY_FILE.exists()


def test_prompt_success_writes_file_with_restrictive_permissions(tmp_path, monkeypatch):
    _isolate_key_file(tmp_path, monkeypatch)
    monkeypatch.delenv("TESTPROV_API_KEY", raising=False)
    validate = MagicMock(return_value=True)

    with patch("backhoe.keys.click.prompt", return_value="fresh-key"):
        result = get_api_key(_provider(validate))

    assert result == "fresh-key"
    assert json.loads(keys_module.KEY_FILE.read_text()) == {"testprov": "fresh-key"}
    mode = keys_module.KEY_FILE.stat().st_mode
    assert stat.S_IMODE(mode) == stat.S_IRUSR | stat.S_IWUSR


def test_prompt_retries_once_then_gives_up(tmp_path, monkeypatch):
    _isolate_key_file(tmp_path, monkeypatch)
    monkeypatch.delenv("TESTPROV_API_KEY", raising=False)
    validate = MagicMock(return_value=False)

    with patch("backhoe.keys.click.prompt", side_effect=["bad-1", "bad-2"]) as prompt_mock:
        result = get_api_key(_provider(validate))

    assert result is None
    assert prompt_mock.call_count == 2
    assert not keys_module.KEY_FILE.exists()


def test_inconclusive_validation_on_freshly_entered_key_is_saved_anyway(tmp_path, monkeypatch):
    _isolate_key_file(tmp_path, monkeypatch)
    monkeypatch.delenv("TESTPROV_API_KEY", raising=False)
    validate = MagicMock(side_effect=KeyValidationError("provider down"))

    with patch("backhoe.keys.click.prompt", return_value="fresh-key"):
        result = get_api_key(_provider(validate))

    assert result == "fresh-key"
    assert json.loads(keys_module.KEY_FILE.read_text()) == {"testprov": "fresh-key"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_keys.py -v`
Expected: FAIL (or ERROR) with `ModuleNotFoundError: No module named 'backhoe.keys'`

- [ ] **Step 3: Write the implementation**

Create `backhoe/keys.py`:

```python
"""
Generic API-key resolution for backends that need one — Shodan today,
Censys/HIBP later. One shared flow so a new keyed backend is "register a
provider + a validate function", not "write a new wizard".

Resolution order for get_api_key(provider):
  1. provider.env_var set -> used directly, no file I/O, no validation,
     no prompt. This is the escape hatch for CI/scripted runs.
  2. A key stored in ~/.config/backhoe/keys.json for provider.name ->
     live-validated via provider.validate() on every call:
       - confirmed valid -> used silently
       - confirmed invalid (validate() returns False) -> warn, re-prompt
       - inconclusive (validate() raises KeyValidationError, e.g. a
         network blip or provider outage) -> warn once, use the stale
         key anyway. A provider being briefly unreachable is not the
         same as the key being wrong, and forcing a re-prompt over that
         would be actively wrong.
  3. No usable key from 1-2 -> interactive prompt (hidden input). Blank
     input skips (returns None — the caller just doesn't run that
     backend this time, same tier as any other opt-in source being
     unavailable). A non-blank entry is validated before saving; one
     retry is allowed on a confirmed-bad entry before giving up.

get_api_key() returning None is a normal outcome, not an error.
"""
from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import click

KEY_DIR = Path.home() / ".config" / "backhoe"
KEY_FILE = KEY_DIR / "keys.json"


class KeyValidationError(Exception):
    """A provider's validate() couldn't reach a conclusive answer (network
    error, provider outage, unexpected response) — NOT the same as the key
    being confirmed wrong. Callers must not treat this as "reprompt"."""


@dataclass(frozen=True)
class KeyProvider:
    name: str
    env_var: str
    prompt_label: str
    validate: Callable[[str], bool]


def _read_stored_keys() -> dict:
    if not KEY_FILE.exists():
        return {}
    try:
        return json.loads(KEY_FILE.read_text())
    except ValueError:
        return {}


def _write_stored_key(name: str, key: str) -> None:
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(KEY_DIR, stat.S_IRWXU)
    stored = _read_stored_keys()
    stored[name] = key
    KEY_FILE.write_text(json.dumps(stored))
    os.chmod(KEY_FILE, stat.S_IRUSR | stat.S_IWUSR)


def _prompt_for_key(provider: KeyProvider) -> str | None:
    for _attempt in range(2):
        entered = click.prompt(
            f"{provider.prompt_label} (leave blank to skip)",
            default="",
            show_default=False,
            hide_input=True,
        )
        if not entered:
            return None
        try:
            if provider.validate(entered):
                _write_stored_key(provider.name, entered)
                return entered
        except KeyValidationError as exc:
            click.secho(
                f"Couldn't confirm the {provider.prompt_label} you entered is valid "
                f"({exc}) — saving it anyway.",
                fg="yellow",
                err=True,
            )
            _write_stored_key(provider.name, entered)
            return entered
        click.secho(f"That {provider.prompt_label} was rejected.", fg="yellow", err=True)
    return None


def get_api_key(provider: KeyProvider) -> str | None:
    env_value = os.environ.get(provider.env_var)
    if env_value:
        return env_value

    stored = _read_stored_keys().get(provider.name)
    if stored:
        try:
            if provider.validate(stored):
                return stored
            click.secho(
                f"Stored {provider.prompt_label} was rejected — please re-enter it.",
                fg="yellow",
                err=True,
            )
        except KeyValidationError as exc:
            click.secho(
                f"Couldn't confirm the stored {provider.prompt_label} is still valid "
                f"({exc}) — using it anyway.",
                fg="yellow",
                err=True,
            )
            return stored

    return _prompt_for_key(provider)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_keys.py -v`
Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
cd "/home/rhino/Osint tools/BACKHOE"
git add backhoe/keys.py tests/test_keys.py
git commit -F - <<'EOF'
Add generic API-key wizard (backhoe/keys.py)

Env var takes priority, then a live-validated local key file
(~/.config/backhoe/keys.json), then an interactive prompt with a
skip option and one retry. A provider validation check that fails
inconclusively (network blip, outage) never forces a re-prompt over
a key that may still be fine — only a confirmed-invalid check does.
Built generic so the next keyed backend (Censys, HIBP) registers a
KeyProvider instead of rebuilding this flow.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01MM3YtrfZBYdsTJbmAyJULU
EOF
```

---

### Task 2: `backhoe/backends/shodan.py` — Shodan host-lookup backend

**Files:**
- Create: `backhoe/backends/shodan.py`
- Test: `tests/test_shodan.py`

**Interfaces:**
- Consumes: `backhoe.keys.KeyProvider`, `backhoe.keys.KeyValidationError` (Task 1). `backhoe.schema.Finding`, `backhoe.schema.FindingType` (existing).
- Produces: `validate_key(key: str) -> bool`, `lookup_host(ip: str, key: str) -> list[Finding]`, `class ShodanError(Exception)`, `class ShodanAPIError(ShodanError)`, `class ShodanValidationError(ShodanError, KeyValidationError)`, `SHODAN_PROVIDER: KeyProvider` (module-level constant).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_shodan.py`:

```python
"""Shodan backend tests — network mocked so these run anywhere, including
sandboxes that block outbound traffic. No live Shodan key or live network
access was available during development (see the design spec's honesty
note): the vulns field's exact shape (list of CVE strings vs. a dict keyed
by CVE ID) is handled defensively rather than assumed from an unverified
guess — both shapes are exercised below."""
from unittest.mock import MagicMock, patch

import pytest
import requests

from backhoe.backends import shodan
from backhoe.backends.shodan import ShodanAPIError, ShodanValidationError
from backhoe.schema import FindingType


def _response(status_code, json_data=None, json_error=None):
    resp = MagicMock(status_code=status_code)
    if json_error is not None:
        resp.json.side_effect = json_error
    else:
        resp.json.return_value = json_data
    return resp


def test_validate_key_true_on_200():
    with patch("backhoe.backends.shodan.requests.get", return_value=_response(200)):
        assert shodan.validate_key("goodkey") is True


def test_validate_key_false_on_401():
    with patch("backhoe.backends.shodan.requests.get", return_value=_response(401)):
        assert shodan.validate_key("badkey") is False


def test_validate_key_raises_on_network_error():
    with patch("backhoe.backends.shodan.requests.get", side_effect=requests.ConnectionError("nope")):
        with pytest.raises(ShodanValidationError):
            shodan.validate_key("anykey")


def test_validate_key_raises_on_unexpected_status():
    with patch("backhoe.backends.shodan.requests.get", return_value=_response(500)):
        with pytest.raises(ShodanValidationError):
            shodan.validate_key("anykey")


def test_lookup_host_returns_empty_list_on_404():
    with patch("backhoe.backends.shodan.requests.get", return_value=_response(404)):
        assert shodan.lookup_host("1.2.3.4", "key") == []


def test_lookup_host_raises_on_401():
    with patch("backhoe.backends.shodan.requests.get", return_value=_response(401)):
        with pytest.raises(ShodanAPIError):
            shodan.lookup_host("1.2.3.4", "key")


def test_lookup_host_raises_on_network_error():
    with patch("backhoe.backends.shodan.requests.get", side_effect=requests.ConnectionError("nope")):
        with pytest.raises(ShodanAPIError):
            shodan.lookup_host("1.2.3.4", "key")


def test_lookup_host_raises_on_unparseable_json():
    with patch(
        "backhoe.backends.shodan.requests.get",
        return_value=_response(200, json_error=ValueError("bad")),
    ):
        with pytest.raises(ShodanAPIError):
            shodan.lookup_host("1.2.3.4", "key")


def test_lookup_host_parses_multiple_ports():
    payload = {
        "data": [
            {"port": 80, "_shodan": {"module": "http"}, "product": "nginx", "version": "1.18.0"},
            {"port": 22, "_shodan": {"module": "ssh"}},
        ]
    }
    with patch("backhoe.backends.shodan.requests.get", return_value=_response(200, payload)):
        findings = shodan.lookup_host("1.2.3.4", "key")

    assert {f.value for f in findings} == {"1.2.3.4:80", "1.2.3.4:22"}
    assert all(f.type == FindingType.OPEN_PORT for f in findings)
    assert all(f.source == "shodan" for f in findings)
    http_finding = next(f for f in findings if f.value == "1.2.3.4:80")
    assert http_finding.raw["product"] == "nginx"
    assert http_finding.raw["version"] == "1.18.0"
    assert http_finding.raw["service"] == "http"


def test_lookup_host_handles_missing_optional_fields():
    payload = {"data": [{"port": 443}]}
    with patch("backhoe.backends.shodan.requests.get", return_value=_response(200, payload)):
        findings = shodan.lookup_host("1.2.3.4", "key")

    assert len(findings) == 1
    f = findings[0]
    assert f.raw["product"] is None
    assert f.raw["version"] is None
    assert f.raw["vulns"] == []
    assert f.raw["service"] is None


def test_lookup_host_handles_vulns_as_dict():
    payload = {"data": [{"port": 443, "vulns": {"CVE-2021-1234": {}, "CVE-2021-5678": {}}}]}
    with patch("backhoe.backends.shodan.requests.get", return_value=_response(200, payload)):
        findings = shodan.lookup_host("1.2.3.4", "key")
    assert sorted(findings[0].raw["vulns"]) == ["CVE-2021-1234", "CVE-2021-5678"]


def test_lookup_host_handles_vulns_as_list():
    payload = {"data": [{"port": 443, "vulns": ["CVE-2021-1234"]}]}
    with patch("backhoe.backends.shodan.requests.get", return_value=_response(200, payload)):
        findings = shodan.lookup_host("1.2.3.4", "key")
    assert findings[0].raw["vulns"] == ["CVE-2021-1234"]


def test_lookup_host_skips_entries_with_no_port():
    payload = {"data": [{"product": "mystery"}]}
    with patch("backhoe.backends.shodan.requests.get", return_value=_response(200, payload)):
        findings = shodan.lookup_host("1.2.3.4", "key")
    assert findings == []


def test_shodan_provider_is_registered_correctly():
    assert shodan.SHODAN_PROVIDER.name == "shodan"
    assert shodan.SHODAN_PROVIDER.env_var == "SHODAN_API_KEY"
    assert shodan.SHODAN_PROVIDER.validate is shodan.validate_key
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_shodan.py -v`
Expected: FAIL (or ERROR) with `ModuleNotFoundError: No module named 'backhoe.backends.shodan'`

- [ ] **Step 3: Write the implementation**

Create `backhoe/backends/shodan.py`:

```python
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


def validate_key(key: str) -> bool:
    try:
        resp = requests.get(f"{BASE_URL}/api-info", params={"key": key}, timeout=DEFAULT_TIMEOUT)
    except requests.RequestException as exc:
        raise ShodanValidationError(f"network error contacting Shodan: {exc}") from exc

    if resp.status_code == 200:
        return True
    if resp.status_code == 401:
        return False
    raise ShodanValidationError(f"unexpected Shodan /api-info status {resp.status_code}")


def lookup_host(ip: str, key: str) -> list[Finding]:
    try:
        resp = requests.get(f"{BASE_URL}/shodan/host/{ip}", params={"key": key}, timeout=DEFAULT_TIMEOUT)
    except requests.RequestException as exc:
        raise ShodanAPIError(f"network error contacting Shodan: {exc}") from exc

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
    findings: list[Finding] = []
    for entry in data.get("data", []):
        port = entry.get("port")
        if port is None:
            continue
        findings.append(
            Finding(
                type=FindingType.OPEN_PORT,
                value=f"{ip}:{port}",
                source="shodan",
                raw={
                    "port": port,
                    "service": (entry.get("_shodan") or {}).get("module"),
                    "product": entry.get("product"),
                    "version": entry.get("version"),
                    "vulns": _extract_vuln_ids(entry),
                },
            )
        )
    return findings


SHODAN_PROVIDER = KeyProvider(
    name="shodan",
    env_var="SHODAN_API_KEY",
    prompt_label="Shodan API key",
    validate=validate_key,
)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_shodan.py -v`
Expected: PASS (14 tests)

- [ ] **Step 5: Commit**

```bash
cd "/home/rhino/Osint tools/BACKHOE"
git add backhoe/backends/shodan.py tests/test_shodan.py
git commit -F - <<'EOF'
Add Shodan host-lookup backend for infra-check

requests-only, no shodan SDK dependency. lookup_host() maps each
data[] entry to an OPEN_PORT Finding; a 404 (host not indexed) is a
legitimate empty result, not an error. validate_key() hits /api-info,
which costs no query credit, so keys.py can live-check a stored key
on every call. Not run against a live Shodan account in this
environment (no key/network access available) — built from Shodan's
published API docs and tested against mocked HTTP only, same
verification tier theHarvester's backend already carries.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01MM3YtrfZBYdsTJbmAyJULU
EOF
```

---

### Task 3: `scoring.py` — fix `_score_open_port` for the merge landmine

**Files:**
- Modify: `backhoe/scoring.py:64-84`
- Test: `tests/test_scoring_extended.py`

**Interfaces:**
- Consumes: `Finding.merged_raw` (existing field, `backhoe/schema.py:36`), the raw-dict shapes from `backends/portscan.py` (`{"port", "service"}`) and Task 2's `backends/shodan.py` (`{"port", "service", "product", "version", "vulns"}`).
- Produces: no new public names — `_score_open_port(finding: Finding) -> None` keeps its existing signature; behavior changes only.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_scoring_extended.py`:

```python
def test_open_port_parses_port_from_value_after_raw_is_merge_reshaped():
    # Simulates the state merge_findings() leaves behind when a second
    # source collides on the same key: raw becomes {source: {...}}
    # instead of a flat dict, so a value-based port read needs to survive
    # it (raw.get("port") would silently return None here).
    f = Finding(
        type=FindingType.OPEN_PORT,
        value="1.2.3.4:3306",
        source="portscan, shodan",
        raw={"portscan": {"port": 3306, "service": "mysql"}, "shodan": {"port": 3306, "vulns": []}},
    )
    f.merged_raw = True
    score_finding(f)
    assert f.interest >= 0.75


def test_open_port_with_known_cve_scores_highest_regardless_of_port():
    f = Finding(
        type=FindingType.OPEN_PORT, value="1.2.3.4:8080", source="shodan",
        raw={"port": 8080, "vulns": ["CVE-2021-1234"]},
    )
    score_finding(f)
    assert f.interest == 1.0
    assert "CVE-2021-1234" in f.note


def test_open_port_without_vulns_key_scores_normally():
    f = Finding(
        type=FindingType.OPEN_PORT, value="1.2.3.4:443", source="portscan",
        raw={"port": 443, "service": "https"},
    )
    score_finding(f)
    assert f.interest < 0.3


def test_open_port_vulns_boost_survives_merge_reshape():
    f = Finding(
        type=FindingType.OPEN_PORT,
        value="1.2.3.4:443",
        source="portscan, shodan",
        raw={"portscan": {"port": 443, "service": "https"}, "shodan": {"port": 443, "vulns": ["CVE-2022-9999"]}},
    )
    f.merged_raw = True
    score_finding(f)
    assert f.interest == 1.0
    assert "CVE-2022-9999" in f.note
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_scoring_extended.py -v`
Expected: `test_open_port_parses_port_from_value_after_raw_is_merge_reshaped` and `test_open_port_vulns_boost_survives_merge_reshape` FAIL (port reads as `None`, `interest` stays at the "unknown port" fallback of `0.55` and no CVE note appears). The other two new tests already pass against the current code, since they don't hit the merge case.

- [ ] **Step 3: Write the implementation**

Replace `backhoe/scoring.py:64-84` (the `SENSITIVE_PORTS`/`EXPECTED_WEB_PORTS` constants and `_score_open_port` function) with:

```python
# Ports where exposure to the open internet is itself worth flagging —
# databases, remote-admin, and legacy cleartext protocols.
SENSITIVE_PORTS = {21: "ftp", 22: "ssh", 23: "telnet", 3306: "mysql", 3389: "rdp", 5432: "postgres", 6379: "redis", 27017: "mongodb"}
EXPECTED_WEB_PORTS = {80, 443}


def _parse_port(finding: Finding) -> int | None:
    """Port for an OPEN_PORT finding, read from `value` ("ip:port") rather
    than `raw` — `raw` gets reshaped to {source: {...}} by merge_findings()
    the moment a second source collides on the same key (see schema.py),
    at which point `raw.get("port")` silently returns None. `value` is
    never reshaped, so this works whether or not a merge happened."""
    try:
        return int(finding.value.rsplit(":", 1)[-1])
    except (ValueError, IndexError):
        return None


def _iter_raw_payloads(finding: Finding):
    """Yield each source's raw payload dict — handles both the common
    unmerged case (`raw` is one flat dict) and the post-merge case (`raw`
    is `{source_name: {...}, ...}`, per merge_findings()'s contract)."""
    if finding.merged_raw:
        yield from finding.raw.values()
    else:
        yield finding.raw


def _collect_vulns(finding: Finding) -> list[str]:
    vulns: list[str] = []
    for payload in _iter_raw_payloads(finding):
        for v in payload.get("vulns") or []:
            if v not in vulns:
                vulns.append(v)
    return vulns


def _score_open_port(finding: Finding) -> None:
    finding.confidence = 0.95
    port = _parse_port(finding)
    vulns = _collect_vulns(finding)

    if vulns:
        finding.interest = 1.0
        shown = ", ".join(vulns[:3]) + ("..." if len(vulns) > 3 else "")
        finding.note = finding.note or f"{len(vulns)} known CVE(s) reported for this service: {shown}"
    elif port in SENSITIVE_PORTS:
        finding.interest = 0.85
        finding.note = finding.note or (
            f"port {port} ({SENSITIVE_PORTS[port]}) is open — confirm this is "
            "intentional and restricted to trusted sources"
        )
    elif port in EXPECTED_WEB_PORTS:
        finding.interest = 0.2
        finding.note = finding.note or "expected web port"
    else:
        finding.interest = 0.55
        finding.note = finding.note or f"port {port} open — confirm this is expected"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_scoring.py tests/test_scoring_extended.py -v`
Expected: PASS (all tests, including the pre-existing `test_sensitive_port_scores_high_interest` and `test_expected_web_port_scores_low_interest`, which must keep passing unchanged)

- [ ] **Step 5: Commit**

```bash
cd "/home/rhino/Osint tools/BACKHOE"
git add backhoe/scoring.py tests/test_scoring_extended.py
git commit -F - <<'EOF'
Fix OPEN_PORT scoring to read port from value, not raw

_score_open_port read finding.raw.get("port"), which silently
returns None the moment merge_findings() reshapes raw into
{source: {...}} on a collision — exactly the bug class the
theHarvester merge already hit once for subdomain scoring. Parse
the port from Finding.value ("ip:port") instead, which is never
reshaped. Also surfaces a real signal only Shodan can provide:
a known-CVE hit on any source's payload now scores as the highest
possible interest, checked across both flat and merged raw shapes.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01MM3YtrfZBYdsTJbmAyJULU
EOF
```

---

### Task 4: `cli.py` — wire Shodan + the key wizard into `infra-check`

**Files:**
- Modify: `backhoe/cli.py:1-27` (imports), `backhoe/cli.py:171-251` (the `infra_check` command)
- Modify: `tests/test_cli.py:139-217` (5 existing `infra-check` tests need `--no-shodan` added; new Shodan-wiring tests added)

**Interfaces:**
- Consumes: `keys.get_api_key` (Task 1), `shodan.lookup_host`, `shodan.ShodanAPIError`, `shodan.SHODAN_PROVIDER` (Task 2), `schema.merge_findings` (existing, already imported), `scoring.score_all` (existing, now benefits from Task 3's fix).
- Produces: new `--shodan/--no-shodan` CLI flag on `infra-check` (default on).

- [ ] **Step 1: Write the failing tests**

In `tests/test_cli.py`, add this import near the top (alongside the existing backend error imports):

```python
from backhoe.backends.shodan import ShodanAPIError
```

Replace the five existing `infra-check` tests (lines 139-217, from `test_infra_check_accepts_a_bare_ip` through `test_infra_check_runs_ports_and_tls_when_not_intercepted`) with these same tests plus `--no-shodan` added to each invocation, and append the five new Shodan-wiring tests after them:

```python
def test_infra_check_accepts_a_bare_ip():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.reverse_dns", return_value=None), patch(
        "backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=True
    ):
        result = runner.invoke(cli, ["infra-check", "1.2.3.4", "--no-shodan"])
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
        result = runner.invoke(cli, ["infra-check", "example.com", "--no-shodan"])

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
        result = runner.invoke(cli, ["infra-check", "cdn.example.com", "--no-shodan"])

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
        result = runner.invoke(cli, ["infra-check", "cdn.example.com", "--no-shodan"])

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
        result = runner.invoke(cli, ["infra-check", "example.com", "--no-shodan"])

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
        result = runner.invoke(cli, ["infra-check", "example.com"])

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
        result = runner.invoke(cli, ["infra-check", "example.com", "--no-shodan"])

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
        result = runner.invoke(cli, ["infra-check", "example.com"])

    assert result.exit_code == 0
    assert "1.2.3.4:80" in result.output


def test_infra_check_warns_and_continues_on_shodan_api_error():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=True), patch(
        "backhoe.cli.keys.get_api_key", return_value="a-key"
    ), patch("backhoe.cli.shodan.lookup_host", side_effect=ShodanAPIError("rate limited")):
        result = runner.invoke(cli, ["infra-check", "example.com"])

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
        result = runner.invoke(cli, ["infra-check", "cdn.example.com"])

    assert result.exit_code == 0
    assert result.output.count("1.2.3.4:443") == 1
    assert "portscan" in result.output
    assert "shodan" in result.output
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_cli.py -v -k infra_check`
Expected: FAIL — `click.exceptions.NoSuchOption: --no-shodan` on the 5 modified tests, and `AttributeError`/`ModuleNotFoundError`-style failures on the 5 new Shodan tests (`backhoe.cli.keys`/`backhoe.cli.shodan` don't exist as attributes on the `cli` module yet).

- [ ] **Step 3: Write the implementation**

In `backhoe/cli.py`, replace lines 1-27 (the import block) with:

```python
import ipaddress
import re
import sys

import click

from . import keys
from .backends import crtsh, dns_checks, netcheck, portscan, shodan, spiderfoot, theharvester, tls
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

Then replace lines 171-251 (the entire `infra_check` command, from `@cli.command("infra-check")` through its closing `render_report(target, findings)`) with:

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
def infra_check(target: str, ports: bool, shodan_: bool):
    """
    Run an infrastructure recon profile against a domain or IP: resolved
    IPs + reverse DNS, a bounded common-port scan, the live TLS
    certificate's expiry, and (if a key is available) Shodan host-lookup
    enrichment.
    """
    click.echo(f"Running infra-check against {target}...\n")

    findings: list[Finding] = []

    try:
        ipaddress.ip_address(target)
        ips = [target]
    except ValueError:
        try:
            ips = dns_checks.resolve_a_records(target)
        except DnsCheckError as exc:
            click.secho(f"DNS lookup failed: {exc}", fg="red", err=True)
            sys.exit(1)

    for ip in ips:
        try:
            ptr = dns_checks.reverse_dns(ip)
        except DnsCheckError as exc:
            click.secho(f"Reverse DNS lookup skipped for {ip}: {exc}", fg="yellow", err=True)
            ptr = None
        findings.append(
            Finding(type=FindingType.IP_ADDRESS, value=ip, source="dns", raw={"ptr": ptr})
        )

    if netcheck.tcp_tls_is_intercepted():
        click.secho(
            "This network transparently intercepts TCP/TLS traffic (a proxy, "
            "sandbox, or VPN answered on behalf of a guaranteed-unassigned test "
            "IP). Port-scan and TLS-certificate results would be fabricated — "
            "skipping both. Run infra-check from a direct, unproxied network "
            "to get real port and certificate data.",
            fg="yellow",
            err=True,
        )
    else:
        if ports:
            click.echo(
                f"Scanning {len(portscan.COMMON_PORTS)} common ports on "
                f"{len(ips)} resolved IP(s)...\n"
            )
            # Scan every IP `target` actually resolved to, not `target`
            # itself — a hostname behind a CDN/load balancer resolves to
            # multiple IPs, and re-resolving inside portscan.scan_ports()
            # means whichever IP the OS resolver hands back that call gets
            # scanned, silently, with no record of which one it was.
            for ip in ips:
                port_results = portscan.scan_ports(ip)
                for port, is_open in port_results.items():
                    if is_open:
                        findings.append(
                            Finding(
                                type=FindingType.OPEN_PORT,
                                value=f"{ip}:{port}",
                                source="portscan",
                                raw={"port": port, "service": portscan.COMMON_PORTS.get(port, "?")},
                            )
                        )

        try:
            cert = tls.get_certificate_info(target)
            findings.append(
                Finding(type=FindingType.CERTIFICATE, value=f"{target}:443", source="tls", raw=cert)
            )
        except TlsError as exc:
            click.secho(f"TLS certificate check skipped: {exc}", fg="yellow", err=True)

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

    findings = merge_findings(findings)
    findings = score_all(findings)
    render_report(target, findings)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/ -v`
Expected: PASS — the full suite, including every pre-existing test (`domain-audit`, `person-check`, the 5 updated `infra-check` tests, and the 5 new Shodan-wiring tests).

- [ ] **Step 5: Commit**

```bash
cd "/home/rhino/Osint tools/BACKHOE"
git add backhoe/cli.py tests/test_cli.py
git commit -F - <<'EOF'
Wire Shodan enrichment + merge_findings into infra-check

New --shodan/--no-shodan flag (default on). Runs outside the
netcheck interception guard, since it's a passive API lookup rather
than raw TCP from this host — a real capability gain on networks
where the built-in port scan and TLS fetch have to be skipped.
infra-check now calls merge_findings() for the first time (mirrors
domain-audit), since Shodan and the built-in scanner can report the
same ip:port.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01MM3YtrfZBYdsTJbmAyJULU
EOF
```

---

## Post-implementation: update `CLAUDE.md`

After all four tasks are committed, update the repo's `CLAUDE.md` (the project handoff doc) to move Shodan off the "not built yet" list and document it alongside theHarvester/SpiderFoot, including the same verification-honesty caveat carried in this plan and the spec. This isn't a separate task with its own tests — it's documentation — but don't skip it: every other backend addition in this repo's history updated `CLAUDE.md` in the same pass, and an out-of-date handoff doc is exactly the kind of thing this repo's own conventions exist to prevent.
