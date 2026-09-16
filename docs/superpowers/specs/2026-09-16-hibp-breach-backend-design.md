# HaveIBeenPwned (HIBP) Breach-Hit Backend — Design Spec

**Status:** Approved, ready for implementation planning.

## Goal

Add a third keyed backend, `backends/hibp.py`, enriching `person-check`
with real breach-hit data from HaveIBeenPwned's API v3 — the first backend
to actually populate `FindingType.BREACH_HIT`, which `scoring.py` has
scored generically since v0.2 with no real producer behind it.

## Context

BACKHOE already has two keyed backends — `backends/shodan.py` and
`backends/censys.py` — both registered through the generic `keys.py`
wizard (`KeyProvider(name, env_var, prompt_label, validate)` +
`get_api_key()`). HIBP is a third `KeyProvider`; `keys.py` itself needs
no changes.

Verified live against HIBP's current API v3 docs
(`haveibeenpwned.com/API/v3`) during design, not from memory alone —
this caught a real, concrete difference from Shodan/Censys: **HIBP has
no free "check if this key is valid" endpoint.** Shodan's `/api-info`
and Censys's `/accounts/users/credits` both exist specifically to let
`keys.py` re-validate a stored key on every call for free. HIBP has
nothing equivalent — every real call to `breachedaccount` counts against
the subscription's rate limit. This directly shapes `validate_key()`'s
design below.

## `backends/hibp.py`

### Endpoint

```
GET https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false
```

`truncateResponse=false` is required — the default truncated response is
just `[{"Name": "Adobe"}, ...]`, and scoring enrichment (below) needs the
full breach object (`DataClasses`, `IsVerified`, `BreachDate`, etc.).

### Headers

- `hibp-api-key: <key>` — required.
- `User-Agent: <non-empty string>` — required; **missing this returns
  403**, a failure mode neither Shodan nor Censys has (both are queried
  via plain `requests.get` with no custom headers at all). BACKHOE sends
  a fixed descriptive value, e.g. `"BACKHOE-OSINT-Tool"`.

### Status code handling

| Code | Meaning | Behavior |
|------|---------|----------|
| 200  | Breach(es) found | Parse and return `Finding`s |
| 404  | No breaches for this email | Legitimate empty result — return `[]`, not an error (matches Shodan/Censys's 404-as-empty-result convention) |
| 401  | Bad/rejected API key | Raise `HIBPAPIError` |
| 403  | Missing `User-Agent` (a BACKHOE bug, not an operator problem) or other access denial | Raise `HIBPAPIError` |
| 429  | Rate limited | Raise `HIBPAPIError`, including the `Retry-After` header value in the message when present |
| any other non-200 | Unexpected | Raise `HIBPAPIError` |
| unparseable JSON | — | Raise `HIBPAPIError` |

### Error hierarchy — deviates from Shodan/Censys's 3-class shape

Shodan and Censys each have `<X>Error` (base) / `<X>APIError` (lookup
failure) / `<X>ValidationError(<X>Error, KeyValidationError)` (validation
failure). HIBP only needs the first two:

```python
class HIBPError(Exception):
    """A real failure calling HIBP — never raised for "no breaches for
    this email", which is a legitimate empty result (see check_breaches)."""

class HIBPAPIError(HIBPError):
    """check_breaches() failed: bad key, missing User-Agent, rate limited,
    HIBP's own server error, network failure, or an unparseable response."""
```

No `HIBPValidationError` / `KeyValidationError` subclass — because:

### `validate_key()` — format check only, not a network call

```python
def validate_key(key: str) -> bool:
    """HIBP has no free endpoint to confirm a key is valid — unlike
    Shodan's /api-info or Censys's /accounts/users/credits, every real
    call to breachedaccount counts against the subscription's rate
    limit. Doing a real live validation on every keys.py call (as
    Shodan/Censys do) would silently double HIBP request usage on every
    person-check run. Instead, validate the key's documented format (a
    32-character hexadecimal string, per HIBP's own API docs) with no
    network I/O. An actually-wrong key surfaces at lookup time as a
    normal HIBPAPIError (401), caught the same non-fatal way as any
    other backend error in cli.py."""
```

This never raises — `KeyProvider.validate` only needs to return `bool`,
and `keys.py`'s per-call "stored key" path already treats a non-raising,
non-exception-based `validate()` correctly (it only special-cases
`KeyValidationError`; a plain `True`/`False` return works with no changes
to `keys.py`).

### `check_breaches(email: str, key: str) -> list[Finding]`

One `Finding` per breach object returned:

```python
Finding(
    type=FindingType.BREACH_HIT,
    value=breach["Title"],       # human-readable, e.g. "Adobe"
    source="hibp",
    raw={
        "name": breach.get("Name"),
        "title": breach.get("Title"),
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
```

No port-style merge-collision defense needed (unlike Shodan/Censys's
by-port grouping): each breach's `Title` is naturally distinct within one
`check_breaches()` call, and no other backend produces `BREACH_HIT`
findings, so there's no cross-source collision to guard against.

### `HIBP_PROVIDER`

```python
HIBP_PROVIDER = KeyProvider(
    name="hibp",
    env_var="HIBP_API_KEY",
    prompt_label="HaveIBeenPwned API key",
    validate=validate_key,
)
```

## `scoring.py` — `_score_breach_hit` (new, replaces the generic
`FindingType.BREACH_HIT` branch in `score_finding`)

Currently `score_finding()` hardcodes `confidence=0.85, interest=0.9,
note="credential exposure — verify and rotate"` for every `BREACH_HIT`,
written before any real producer existed. HIBP's raw fields let this be
genuinely data-driven, mirroring the CVE-boost pattern `_score_open_port`
already established for Shodan/Censys:

**Confidence** (baseline 0.85):
- `is_fabricated` is `True` → `0.3` (HIBP itself flags this breach as
  not genuine)
- else if `is_verified` is `False` → `0.5` (unconfirmed, meaningfully
  less certain)
- else → `0.85`

**Interest** (baseline 0.9):
- `is_spam_list` is `True` → `0.5` (an email-harvesting list, not a real
  credential breach — still worth knowing about, but not urgent)
- else if `data_classes` contains a credential-like field (`"Passwords"`,
  or anything containing `"password"` case-insensitively, to also catch
  HIBP's `"Partial passwords"` etc.) → `1.0`
- else → `0.9`

**Note** — built from what's actually known, not a static string:
- Lead with the breach year (parsed from `breach_date`, format
  `YYYY-MM-DD`) if present: `"{year} breach"`.
- Append the top few `data_classes` (cap at 4, `"..."` if more, same
  truncation style as `_score_open_port`'s CVE list): `"exposed: {...}"`.
- Append `"; unverified, treat with caution"` if `is_verified is False`.
- Append `"; flagged by HIBP as fabricated"` if `is_fabricated is True`.
- Append `"; flagged as a spam list, not a confirmed breach"` if
  `is_spam_list is True`.
- Falls back to the old generic string if `data_classes` is empty and no
  flags apply, so a finding built from a hand-rolled `raw` (e.g. a test
  fixture) never renders a blank note.

This function follows `_score_open_port`'s existing shape (baseline +
override cascade), so no new scoring abstraction is introduced.

`report.py` needs **no changes** — its `_synthesize_summary()` already
handles `FindingType.BREACH_HIT` generically (`"N breach hit(s) — verify
and rotate any live credentials."`), and the table already renders
`finding.note` and `finding.interest` generically for every type.

## `cli.py` — wire into `person-check`

New `--hibp/--no-hibp` flag (default on), same shape as `infra-check`'s
`--shodan/--no-shodan`:

```python
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
    ...
    if hibp:
        key = keys.get_api_key(HIBP_PROVIDER)
        if key:
            try:
                findings.extend(hibp_backend.check_breaches(email, key))
            except HIBPAPIError as exc:
                click.secho(f"HIBP check skipped: {exc}", fg="yellow", err=True)
```

(Module import aliased as `hibp_backend` or similar to avoid shadowing
the `--hibp` flag's boolean parameter, the same way `infra-check` aliases
its `shodan`/`censys` flag params to `shodan_`/`censys_` to avoid
shadowing the imported backend modules — here it's the flag name that's
short, so the import gets the alias instead.)

`HIBPAPIError` caught non-fatally — same tier as Gravatar/theHarvester/
SpiderFoot/Shodan/Censys errors. No key available (env var unset, nothing
stored, blank prompt) skips silently — same as Shodan/Censys with no key,
not a warning-worthy condition.

## What this does NOT do

- No changes to `keys.py` — HIBP is a third `KeyProvider`, the existing
  resolution flow (env var → stored+validated → prompt) already supports
  it with zero modification.
- No changes to `report.py` — `BREACH_HIT` is already handled generically
  in both the summary and the table.
- No pagination/multi-page handling — HIBP's `breachedaccount` endpoint
  returns all matching breaches in one response, no pagination parameter
  exists for this endpoint.
- No `Pwned Passwords` (k-anonymity password-hash-range) API integration
  — a different HIBP product, out of scope; this is breach-by-email only.

## Verification honesty note

Confirmed live against HIBP's current API v3 documentation
(`haveibeenpwned.com/API/v3`) during design: the endpoint path, required
headers, status codes 200/404/401/403/429, the full (non-truncated)
response shape and field names, and the absence of any free validation
endpoint. **Not exercised against a live HIBP account** — no HIBP API key
was available during development (HIBP's API has required a paid
subscription since 2019). Tests will mock the HTTP boundary against the
response shape confirmed from HIBP's own docs, same verification tier as
Shodan's and Censys's backends. Worth a real smoke test the first time
this runs somewhere with a live HIBP key.

HIBP's docs also mention a special integration-test email
(`account-exists@hibp-integration-tests.com`) that accepts any
correctly-formatted key and returns fixed fake breach data — useful only
for HIBP's own client-library test suites, not for validating a real
operator-supplied key (it bypasses auth entirely for that one test
domain), which is why `validate_key()` above does not attempt to use it
for production key validation.
