# Shodan backend + API-key wizard — design

Date: 2026-09-12
Status: approved for implementation

## Why

BACKHOE's `infra-check` does a bounded 9-port TCP scan (`portscan.py`) and a
live TLS fetch (`tls.py`). Both give useful but shallow data: open/closed
per port, no service/product/version identification, no known-vulnerability
signal. Shodan's host-lookup API fills that gap without BACKHOE doing any
more raw TCP itself.

Adding a keyed backend also exposes a gap the project already knew about
(`CLAUDE.md`'s "not built yet" list): there's no shared way to obtain,
store, or re-validate an API key across backends. Building Shodan's key
handling as a one-off would mean rebuilding the same logic for Censys or
HIBP later. This spec covers both: a generic key-resolution subsystem, and
the first backend built on top of it.

## Scope

In scope:
- `backhoe/keys.py` — provider registry + `get_api_key()` resolution flow,
  generic across future keyed backends.
- `backhoe/backends/shodan.py` — Shodan host-lookup backend, the only
  provider registered for now.
- Wiring into `infra-check` only (not `domain-audit`).
- A fix to `scoring.py`'s `_score_open_port`, required by this change (see
  "The merge landmine" below).

Out of scope (deliberately, YAGNI):
- Censys or HIBP backends themselves — `keys.py` is built generic enough
  that adding them later is "register a provider," not "rebuild the
  wizard," but neither is being built in this pass.
- An upfront/standalone `backhoe keys setup` command — the wizard triggers
  lazily, from inside a backend call, per the design below. A dedicated
  setup command can be added later without changing this design.
- OS keyring integration — plain local file per the decision below.

## Design

### 1. Key storage

`~/.config/backhoe/keys.json`, a flat `{provider_name: key}` map. Directory
created `0700`, file written `0600`. Plain JSON, no encryption — consistent
with how this operator already keeps other API keys as plain local files;
not a secrets-manager replacement.

### 2. Provider registry (`backhoe/keys.py`)

```python
@dataclass(frozen=True)
class KeyProvider:
    name: str            # "shodan" — also the keys.json field name
    env_var: str          # "SHODAN_API_KEY"
    prompt_label: str     # "Shodan API key" — shown in the interactive prompt
    validate: Callable[[str], bool]   # True/False = conclusive; raises
                                        # KeyValidationError if inconclusive
```

`class KeyValidationError(Exception)`: raised by a provider's `validate()`
when the check itself failed (network error, 5xx, unexpected response) —
this is NOT the same as the key being confirmed bad. Callers must not treat
an inconclusive check as a reason to discard a working key.

### 3. Resolution flow — `get_api_key(provider: KeyProvider) -> str | None`

1. `os.environ.get(provider.env_var)` set → return it immediately. No file
   read, no validation call. This is the escape hatch for CI/scripted runs:
   as long as the env var is set, `get_api_key` never touches disk or
   blocks on input.
2. Else read `provider.name` from `keys.json`, if present:
   - `validate(key)` returns `True` → return the key, no output at all.
   - `validate(key)` returns `False` (confirmed invalid, e.g. Shodan 401) →
     print that the stored key was rejected, fall through to step 3.
   - `validate(key)` raises `KeyValidationError` (inconclusive — network
     blip, provider outage) → print a single warning that validation
     couldn't be confirmed, then **return the stored key anyway**. Never
     force a re-prompt because the provider's status page is down; the
     actual backend call will surface a real error if the key truly is bad.
3. No usable key from steps 1-2 → interactive prompt (`click.prompt(...,
   hide_input=True)` — API keys don't belong in shell/terminal scrollback
   any more than a password does). Blank input = skip
   → return `None`. Non-blank → `validate()` it before saving:
   - Valid → write to `keys.json`, return it.
   - Confirmed invalid → one retry allowed, then give up (warn, return
     `None`) rather than loop forever.
   - `KeyValidationError` on a freshly-entered key → treat like a
     confirmed-valid save (can't blame the operator for a provider outage
     at the exact moment they typed a key); write it, return it, warn once
     that it couldn't be confirmed live.

`get_api_key` returning `None` is a normal, expected outcome (operator
chose not to configure this provider right now) — it is not an error and
callers must not raise over it. This matches the project's existing
tiering: Shodan enrichment is opt-in, same tier as Gravatar/theHarvester/
SpiderFoot being unavailable.

### 4. `backhoe/backends/shodan.py`

Plain `requests` calls, no `shodan` SDK dependency — matches `crtsh.py`/
`gravatar.py`'s pattern of talking directly to a keyless-or-keyed REST API
rather than shelling out (that pattern is reserved for tools with no HTTP
API of their own, like theHarvester/SpiderFoot).

- `validate_key(key: str) -> bool`: `GET https://api.shodan.io/api-info?key=...`.
  Confirmed via Shodan's own docs to cost no query credit. 200 → `True`.
  401 → `False`. Anything else (network error, 5xx, unparseable body) →
  raises `ShodanValidationError` (a `KeyValidationError`).
- `lookup_host(ip: str, key: str) -> list[Finding]`:
  `GET https://api.shodan.io/shodan/host/{ip}?key=...`.
  - 404 → `[]` (Shodan has no data for this host — a legitimate empty
    result, not a failure; "fail loud, never fake" means never inventing
    findings, not treating every non-200 as an error).
  - 401/429/5xx/network error/bad JSON → raises `ShodanAPIError`.
  - 200 → for each entry in the response's `data` array, build one
    `Finding(type=OPEN_PORT, value=f"{ip}:{port}", source="shodan",
    raw={"port", "service", "product", "version", "vulns"})`, each field
    read with `.get()` — never assume a field exists; availability is
    plan-dependent and unverified live in this environment (see
    "Verification" below).
- `class ShodanError(Exception)`; `class ShodanAPIError(ShodanError)`;
  `class ShodanValidationError(ShodanError, KeyValidationError)`.

`SHODAN_PROVIDER = KeyProvider(name="shodan", env_var="SHODAN_API_KEY",
prompt_label="Shodan API key", validate=validate_key)` lives in this module
and is imported by `cli.py`.

### 5. `cli.py` — `infra-check`

- New `--shodan/--no-shodan`, default on.
- `key = keys.get_api_key(shodan.SHODAN_PROVIDER)` if the flag is on;
  `None` → skip, no output (the wizard already said whatever needed
  saying, if anything).
- Runs **outside** the existing `netcheck.tcp_tls_is_intercepted()`
  branch — Shodan is a passive API lookup, not raw TCP from this host, so
  it stays trustworthy even in a sandboxed/intercepted network where the
  built-in port scan and TLS fetch get skipped. This is a genuine
  capability gain worth its own echo line in the CLI output.
- For each resolved `ip`, call `shodan.lookup_host(ip, key)`, catch
  `ShodanAPIError` non-fatally (yellow warning, continue), extend
  `findings` with whatever came back.
- `findings = merge_findings(findings)` added before `score_all()` —
  `infra-check` has never called this before (only `domain-audit` does);
  it's needed now because Shodan and the built-in scanner can report the
  same `ip:port`.

### 6. The merge landmine — `scoring.py` fix

`_score_open_port` currently reads `finding.raw.get("port")`. Per
`merge_findings()`'s contract, `raw` stays flat and untouched *unless* a
second source collides on the same key — then it's reshaped to
`{source_name: {...}, other_source_name: {...}}`. The moment Shodan and
`portscan` both report the same `ip:port`, `raw.get("port")` silently
returns `None` post-merge. This is the exact bug class the theHarvester
merge already hit once for subdomain scoring (source-unaware reads against
a raw dict that can be reshaped).

Fix: parse the port from `finding.value` (`"ip:port"`, always present and
never reshaped) instead of `raw`. Works identically whether `raw` is flat
or merged-nested.

Bonus (small, in scope because it directly follows from the same fix):
if any source's payload — checked across flat or per-source-nested `raw`
— carries a non-empty `vulns` list, boost `interest` and note the CVE
count. This is a real, actionable signal only Shodan provides among
current backends, and scoring should surface it rather than silently
dropping it into an unread `raw` field.

## Error handling summary

| Situation | Behavior |
|---|---|
| `SHODAN_API_KEY` env var set | Used directly, no validation, no prompt, no file I/O |
| Stored key, validates OK | Used silently |
| Stored key, confirmed invalid (401) | Warn, re-prompt |
| Stored key, validation inconclusive (network/5xx) | Warn once, use stale key anyway |
| No key anywhere, operator skips prompt | `infra-check` continues without Shodan, no error |
| No key anywhere, operator enters one, confirmed invalid | One retry, then give up (same as skip) |
| `lookup_host` 404 | Empty result, not an error |
| `lookup_host` 401/429/5xx/network/bad JSON | `ShodanAPIError`, non-fatal yellow warning in `cli.py` |

## Testing

- `tests/test_keys.py`: env-var short-circuit (assert `validate` never
  called), stored-valid silent path, stored-invalid triggers prompt,
  inconclusive-validation keeps stale key + single warning, prompt-skip
  returns `None` and leaves `keys.json` untouched, prompt-success writes
  file with `0600`/`0700` perms and correct content, retry-then-give-up on
  a bad freshly-entered key.
- `tests/test_shodan.py`: 404 → `[]`, 401/429/5xx/network/bad-JSON →
  `ShodanAPIError`, `/api-info` 200/401/other → `validate_key` return/raise
  mapping, multi-port `data[]` parsing with missing optional fields.
- `tests/test_cli.py` additions: `--shodan/--no-shodan` flag, Shodan
  findings merging with `portscan` findings on shared `ip:port`, Shodan
  still attempted when `netcheck` reports interception.
- `tests/test_scoring.py` additions: `_score_open_port` reading a
  post-merge nested `raw` correctly via `value`-based port parsing, `vulns`
  presence boosting `interest`.

## Verification honesty note

No Shodan API key or live network access is available in this development
environment. Unlike SpiderFoot (cloned, installed, and run live against
`example.com` during its development), this backend is built from Shodan's
published API documentation (confirmed live via their docs site for the
`/api-info` no-credit-cost claim and the `/shodan/host/{ip}` response
shape) and tested against mocked HTTP responses only. The real CLI-to-API
round trip — actual response field availability by plan tier, rate-limit
behavior, `vulns` field presence — has not been exercised end to end.
Same caveat class as theHarvester's "not run against a live install in
this environment." Worth a real smoke test with an actual key the first
time this runs somewhere that has one.
