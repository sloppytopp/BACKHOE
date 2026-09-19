# BACKHOE — project handoff

This file is context for whichever Claude session picks up work on this
repo next. Read it before touching code.

## What this is, and why

BACKHOE is a CLI OSINT recon tool. The gap it targets: every existing
OSINT tool (SpiderFoot, theHarvester, Amass, recon-ng...) dumps raw
findings and expects the operator to already know what matters. BACKHOE
normalizes backend output into one `Finding` schema, scores every finding
0.0-1.0 by actual relevance, and renders a plain-English summary plus a
sorted table — an answer, not a data dump.

Owner context: this is a side project for the account/business behind
`yellowhammertrader.com` (an Alabama firearms/outdoor trading site, the
owner's main product, built in phpBB, separately maintained — not in this
repo). The owner is a direct business partner, not a casual user: expect
blunt requests, wants the truth over reassurance, and cares about real,
actionable findings over polish. When in doubt, be honest about
limitations rather than papering over them — that ethos is baked into
the codebase itself (see "Fail loud" below), keep it that way in new code.

## Repo

`github.com/sloppytopp/BACKHOE`, MIT licensed, branch `main`. CI runs
pytest on 3.10/3.11/3.12 via `.github/workflows/tests.yml` on every push.

## Architecture

```
backhoe/
  schema.py            Finding dataclass + FindingType enum — every
                        backend's output gets mapped into this one shape
  scoring.py            score_finding()/score_all() — sets .confidence and
                        .interest on each Finding. Hand-written, transparent
                        rules, not a black box — see the module docstring
  report.py             render_report() — plain-English synthesis panel +
                        a sorted, color-coded rich table
  resolve.py             DNS liveness check used by domain-audit
  cli.py                 click group; domain-audit / person-check / infra-check
  keys.py                 generic API-key resolution/storage/prompt wizard —
                        see "Shodan" below for its first consumer
  backends/
    crtsh.py             certificate transparency subdomain enum (no API key)
    dns_checks.py         MX/SPF/DMARC/PTR — real DNS, no API key
    gravatar.py           Gravatar existence check for an email
    portscan.py            bounded common-port TCP connect scan
    tls.py                 live TLS certificate metadata fetch
    netcheck.py            interception canary — see below, read this one
    theharvester.py        shells out to a separately-installed theHarvester
                        CLI (not a pip dependency — see "theHarvester" below)
    shodan.py               Shodan host-lookup enrichment for infra-check,
                        needs an API key via keys.py — see "Shodan" below
    censys.py               Censys host-lookup enrichment for infra-check,
                        mirrors shodan.py's shape — see "Censys" below
tests/                   pytest, everything network-mocked except the two
                        real-DNS tests in test_resolve.py
```

## Fail loud, never fake — the one rule that matters most here

Every backend raises a specific exception on real failure
(`CrtShError`, `DnsCheckError`, `TlsError`, `GravatarError`) instead of
returning empty/fake data. `cli.py` catches these and either exits
non-zero with a red error (fatal to the whole command) or prints a
yellow warning and continues (non-fatal, e.g. Gravatar down shouldn't
kill a person-check). **Never** make a failure look like a legitimate
"no findings" result — that was an actual bug fixed early on (crt.sh
failures used to inject a fake zero-confidence Finding into the results
table). Keep this pattern for every new backend.

## The netcheck.py story — read this before adding network-based checks

While building `infra-check`, testing in a sandboxed dev environment
returned a "successful" TLS handshake and port scan against a real
domain — except the certificate's issuer was literally
`Anthropic / Egress Gateway SDS Issuing CA`, not any real CA. The
sandbox transparently intercepts all outbound port-443/80 traffic and
answers on the real target's behalf for non-allowlisted hosts. This is
a real, general failure mode (corporate proxies, security sandboxes,
some VPNs do the same thing), not just a quirk of one dev environment.

`backends/netcheck.py` detects it generically: handshake against
`203.0.113.1` (RFC 5737 TEST-NET-3, guaranteed unassigned/unroutable on
any real network). If that handshake succeeds, something is answering
on behalf of a nonexistent host, so `infra-check` skips the port scan
and TLS fetch entirely with a clear warning instead of reporting
fabricated data. Any new feature that does raw TCP/TLS work should
check this first — DNS-based checks (dns_checks.py) are unaffected and
don't need it.

## What's shipped (v0.6)

- `domain-audit <domain>` — crt.sh subdomain enum, optional theHarvester
  enrichment (see below), keyword + cert-recency interest scoring, live
  DNS liveness check (`--no-resolve` to skip)
- `person-check <email>` — MX/SPF/DMARC for the domain, Gravatar check
  for the address, plus optional HaveIBeenPwned breach-hit checking (see
  below). Verified live against yellowhammertrader.com during
  development: found DMARC is present but `p=none` (monitor-only, not
  enforcing) — a real, actionable finding, worth following up on for
  the actual business domain independent of this tool's development.
- `infra-check <target>` — resolve + reverse DNS, bounded 9-port scan,
  TLS cert expiry, with the interception guard above, plus optional
  Shodan and/or Censys host-lookup enrichment (see below)

183 tests, all passing, `pytest` from repo root (`pip install -e ".[dev]"`
first).

## Three gap fixes (2026-09-11), applied via TDD after independent verification

These arrived as loose files (a full `schema.py` replacement + two diffs)
in `/home/rhino/Documents/backhoe files first patches/`, described in
oddly self-referential language ("I need to flag something about my own
patch"). Origin unclear — not something this session wrote. Each claim
was independently verified against the live code (not trusted from the
description) before anything was applied, and each fix has its own
TDD-driven failing-then-passing test:

- **`schema.py`**: `Finding.key()` didn't disambiguate `DNS_RECORD`
  findings by `raw["record_type"]` — verified real: `person-check`'s
  three DNS findings (mx/spf/dmarc) share `type:value` and would
  silently collapse to one the moment `merge_findings()` ever ran over
  them (it doesn't today, but nothing guaranteed that stays true).
  `merge_findings()` also now preserves `raw` instead of dropping the
  losing duplicate's payload — reshaping it to `{source: {...}}` *only*
  on an actual collision (verified this never touches any current
  `scoring.py` reader: subdomain scoring never reads `raw`, and no
  domain-audit email finding has ever carried a `"gravatar"` key to
  begin with) — and fills in a blank `note` from a later duplicate too.
- **`scoring.py`**: `score_finding()` now resets `note = ""` before
  scoring. Today this is a pure no-op (nothing re-scores a `Finding`
  yet), but `_score_subdomain` appends onto `note` in two places, and
  without the reset a second scoring pass on the same object would
  silently duplicate them.
- **`cli.py` `infra-check`**: real, verified bug — `portscan.scan_ports(target)`
  was called with the original hostname, not any of the already-resolved
  `ips`, so each of the 9 port-scan connection attempts did its own
  independent DNS resolution via `socket.create_connection`. A
  multi-IP target (anything behind a CDN/load balancer) got scanned
  against whichever IP the OS resolver handed back per-call — untied to
  any of the IPs `infra-check` had already resolved and reported. Now
  scans every IP in `ips` explicitly, and `OPEN_PORT` findings are
  tagged by IP, not hostname.

## theHarvester (v0.4) — subprocess, not a dependency

`backends/theharvester.py` shells out to the separately-installed
`theHarvester` CLI (github.com/laramies/theHarvester) for `domain-audit`.
Verified against that project's actual current source (cloned and read
during development, not assumed from memory) before writing the parser:

- Current theHarvester requires **Python 3.14+** — a different runtime
  than BACKHOE targets (3.10-3.12), so it can never be a pip dependency
  here. It's invoked via `shutil.which("theHarvester")` + `subprocess.run`,
  same as any other external tool the operator installs themselves.
- Its `-f NAME` flag writes `NAME.json` with (among other keys) `hosts`
  and `emails` — the two we map to `Finding`s. `ips` is deliberately
  *not* mapped: that's infra-check's job, and mapping it here without
  also doing the PTR lookup `IP_ADDRESS` scoring assumes would violate
  "fail loud, never fake."
- `DEFAULT_SOURCES` is a curated, keyless-only source list (not `-b all`)
  verified against theHarvester's own source table
  (`lib/source_catalog.py`) — sources needing an unconfigured API key
  are skipped by theHarvester itself with a log line, not a crash, so
  an occasional wrong guess in this list just no-ops rather than erroring.
  Deliberately excludes `crtsh`: `domain-audit` already queries crt.sh
  directly via `backends/crtsh.py`, so including it here would just
  double-query the same data for `merge_findings()` to dedupe back out
  (a review caught this before merge).
- `scoring._score_subdomain`'s confidence is now source-aware: 0.9 (a
  directly-observed cert) only when `crt.sh` is among the finding's
  sources, 0.6 for a theHarvester-only subdomain (passive scraping —
  meaningfully less certain on its own). Previously hardcoded to 0.9
  for every subdomain regardless of provenance, which stopped being
  true the moment a second, lower-trust source existed.
- Not installed → `TheHarvesterNotInstalled` (a `TheHarvesterError`),
  caught non-fatally in `cli.py` (yellow warning, `domain-audit`
  continues on crt.sh alone) — same tier as Gravatar in `person-check`.
  `--no-harvester` skips it outright.
- Added `schema.merge_findings()` in the same pass: `domain-audit` now
  has two subdomain-producing backends for the first time, so
  `Finding.key()`'s existing dedup contract (never wired up before)
  actually needed calling. Also fixed `scoring._score_email`, which
  assumed every `EMAIL` finding had been Gravatar-checked
  (`raw.get("gravatar")` truthy/falsy) — a theHarvester-sourced email
  has no `"gravatar"` key at all, and the old code would have rendered
  a false "no public Gravatar profile" for it.
- **Not run against a live install in this environment** — no way to
  install real theHarvester here (Python 3.14 unavailable in this
  sandbox). Tests mock at the `subprocess.run` boundary against the
  verified JSON shape; the actual CLI invocation (`-d`, `-b`, `-f`
  flags, exit codes) has not been exercised end-to-end. Worth a real
  smoke test the first time this runs somewhere with theHarvester
  actually installed.

## SpiderFoot — removed (2026-09-19), do not re-add without reading this

SpiderFoot enrichment (`backends/spiderfoot.py`, `--spiderfoot/--no-spiderfoot`)
was shipped in v0.4 and removed at the owner's request. It's recoverable
from git history if ever wanted back. `--no-spiderfoot` is now an unknown
option, so any script passing it will fail. What a live run against
yellowhammertrader.com showed just before removal (a manual `sf.py` run
with the same arguments the backend used, capped at 20 minutes):

- **It never finished.** SpiderFoot's `-t INTERNET_NAME,EMAILADDR` pulls in
  the site-crawling module, so on a large phpBB forum it emitted ~2,000
  internal-link events in 10 minutes and was still going at the cap. The
  backend's hardcoded 180s timeout (`DEFAULT_TIMEOUT`, no CLI override) could
  never have been enough for a real site.
- **The stdout JSON stream was not reliably parseable**: ~30 of ~4,140 lines
  failed to parse (cause not determined — interleaved writes or truncation).
  The backend called `json.loads` on all of stdout, so a scan that did
  finish could still be discarded as "unparseable JSON".
- **Value over crt.sh was one row**: `www.yellowhammertrader.com`, found by
  `sfp_dnsbrute`. No emails belonging to the target.
- SpiderFoot 4.0's `requirements.txt` pins `pyyaml>=5.4.1,<6`; PyYAML 5.4.1
  has no Python 3.12 wheel and fails to build from source (`'build_ext'
  object has no attribute 'cython_sources'`). Installing with `pyyaml>=6.0.1`
  works — SpiderFoot only calls `yaml.safe_load`.

If it's ever re-added, the design lessons that still hold: it has no
console-script entry point (find `sf.py` via a `SPIDERFOOT_HOME` env var);
its deps must be installed into the same interpreter BACKHOE runs under
(`sys.executable`, i.e. the pipx venv — not some other venv); set
`SPIDERFOOT_DATA` to a tempdir so scan history doesn't pile up in
`~/.spiderfoot`; filter events by **exact** `type` string (`"Internet Name"`
is the target's; `"Affiliate - Internet Name"` is a third party's, e.g. the
target's DNS provider); and consider restricting modules with `-m`
instead of relying on `-t` so it doesn't crawl the target (untested — an
inference from the crawl behavior above, not something that was tried).

## Shodan (v0.4) — API-key wizard + host-lookup backend for infra-check

`backends/shodan.py` calls Shodan's REST API directly with plain
`requests` (no `shodan` SDK dependency, same pattern as crtsh.py and
gravatar.py) to enrich `infra-check`'s open-port findings with
service/product/version data and known CVEs — richer than what BACKHOE's
own bounded TCP connect scan (`portscan.py`) can see on its own. Unlike
theHarvester, Shodan needs an API key, which is where
`keys.py` comes in:

- **`keys.py` is a generic, provider-agnostic key wizard**, built so
  Shodan isn't a one-off: a new keyed backend (Censys, HIBP) registers a
  `KeyProvider(name, env_var, prompt_label, validate)` and gets the same
  resolution flow for free. Resolution order in `get_api_key(provider)`:
  1. `provider.env_var` (`SHODAN_API_KEY` for Shodan) — used directly, no
     file I/O, no validation, no prompt. The escape hatch for CI/scripted
     runs.
  2. A key already stored in `~/.config/backhoe/keys.json` — re-validated
     live on *every* call via `provider.validate()`. Confirmed invalid ->
     warn and re-prompt. Inconclusive (network blip, provider outage,
     raises `KeyValidationError`) -> warn once and use the stale key
     anyway, since "can't confirm" is not the same as "confirmed wrong."
  3. Neither of the above -> interactive hidden-input prompt. Blank input
     skips and returns `None` (not an error — same tier as any other
     opt-in source being unavailable); a non-blank entry is validated
     before saving, with one retry on a confirmed-bad entry.
  The stored-key file is written with restrictive `0o600`/`0o700`
  permissions set via `os.umask`/`os.open` at creation time, not
  chmod'd down after the fact, to avoid a TOCTOU window where the
  plaintext key is briefly world-readable.
- `shodan.validate_key()` hits Shodan's `/api-info` endpoint, confirmed
  in Shodan's own docs to cost no query credit — what makes it safe for
  `keys.py` to re-validate a stored key on every single `infra-check`
  run without burning the operator's quota.
- `shodan.lookup_host(ip, key)` hits `/shodan/host/<ip>`. A 404 (host not
  indexed by Shodan) returns an empty list — a legitimate empty result,
  not a failure. Any other non-200, a network error, or unparseable JSON
  raises `ShodanAPIError`. Every optional response field (`product`,
  `version`, `vulns`, the module name) is read with `.get()`, never
  assumed present.
- The `vulns` field's on-the-wire shape (a list of CVE-id strings vs. a
  dict keyed by CVE id) isn't confirmed from Shodan's own docs — see the
  verification note below — so `_extract_vuln_ids()` handles both
  instead of guessing one and breaking silently on the other.
- Wired into `infra-check` via a new `--shodan/--no-shodan` flag
  (default on). **Deliberately runs outside the `netcheck.py`
  interception guard**: it's a passive API call to Shodan's servers, not
  raw TCP/TLS from this host, so it stays trustworthy — and is a real
  capability gain — even on a network where the built-in port scan and
  TLS fetch have to be skipped entirely.
- `ShodanAPIError` is caught non-fatally in `cli.py` (yellow warning,
  `infra-check` continues on whatever it already has) — same tier as
  Gravatar and theHarvester. If `keys.get_api_key()` returns
  `None` (no env var, no stored key, blank prompt), Shodan enrichment is
  skipped silently — that's a normal "opted out," not a warning-worthy
  failure.
- `infra-check` now calls `schema.merge_findings()` for the first time
  (mirrors `domain-audit`): Shodan and the built-in port scanner can both
  report an `OPEN_PORT` finding for the same `ip:port`, and
  `scoring._score_open_port`'s Task-3 fix (reads the port from
  `Finding.value`, not `raw`) is what makes merging those two sources
  safe to score correctly.
- **Not run against a live Shodan account in this environment** — no
  Shodan API key or live network access was available during
  development. This backend is built from Shodan's published API docs
  (host-lookup and `/api-info` endpoints) and tested entirely against
  mocked HTTP responses, not exercised against a real account end to
  end. In particular, the exact shape of `vulns` in a live response
  (handled defensively above) and which optional fields Shodan's free
  tier actually populates are unconfirmed — worth a real smoke test the
  first time this runs somewhere with a live Shodan key.

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

## HIBP (v0.5) — breach-hit backend for person-check, format-only key validation

`backends/hibp.py` is `person-check`'s first real `BREACH_HIT` producer —
`FindingType.BREACH_HIT` existed and was scored since v0.2, but nothing
populated it until now. Same `requests`-only, no-SDK pattern as
Shodan/Censys, registered through the same `keys.py` wizard, but with a
real structural difference confirmed against HIBP's own current API v3
docs (`haveibeenpwned.com/API/v3`) during design — not assumed from
memory:

- **HIBP has no free key-validation endpoint at all**, unlike Shodan's
  `/api-info` or Censys's `/accounts/users/credits` — every real call to
  `breachedaccount` counts against the subscription's rate limit.
  `validate_key()` is therefore a **format-only check** (a 32-character
  hex string, HIBP's documented key shape) with **no network call** —
  it never raises, so there's deliberately no `HIBPValidationError` or
  `KeyValidationError` subclass here, unlike Shodan/Censys. An actually-
  wrong key surfaces at lookup time as a normal `HIBPAPIError` (401),
  caught the same non-fatal way as any other backend error.
- `check_breaches(email, key)` hits
  `GET /breachedaccount/{email}?truncateResponse=false` — the
  `truncateResponse=false` param is required; the default truncated
  response omits every field scoring needs (`DataClasses`, `IsVerified`,
  etc.). Requires a `hibp-api-key` header AND a non-empty `User-Agent` —
  **missing `User-Agent` returns 403**, a failure mode neither Shodan
  nor Censys has (neither sends any custom headers at all).
- A 404 (no breaches for this email) is a legitimate empty result, not
  an error, matching the project's existing convention. `429` (rate
  limited) raises `HIBPAPIError` with the `Retry-After` header value
  folded into the message when present.
- `scoring._score_breach_hit` was upgraded in the same pass from a
  hardcoded `confidence=0.85/interest=0.9/static-note` (written before
  any real breach backend existed) to logic driven by HIBP's actual
  `DataClasses`/`IsVerified`/`IsFabricated`/`IsSpamList` fields: a
  fabricated breach drops confidence to 0.3, unverified to 0.5; a
  breach exposing passwords (or "Partial passwords") scores the highest
  interest, a spam-list hit the lowest. The note is built from the real
  breach year and exposed data classes instead of a fixed string,
  mirroring the CVE-boost pattern `_score_open_port` already uses for
  Shodan/Censys.
- Wired into `person-check` via `--hibp/--no-hibp` (default on). A
  missing key skips silently (same tier as Shodan/Censys with no key);
  `HIBPAPIError` is caught non-fatally (yellow warning, same tier as a
  Gravatar failure).
- No changes needed to `keys.py` or `report.py` — both already handle a
  new `KeyProvider` / `FindingType.BREACH_HIT` generically.
- **Not run against a live HIBP account in this environment** — no HIBP
  API key was available during development (HIBP's API has required a
  paid subscription since 2019). Built from HIBP's published API docs
  and tested entirely against mocked HTTP responses, same verification
  tier Shodan's backend carries. Worth a real smoke test the first time
  this runs somewhere with a live HIBP key.

## What's NOT built yet (don't claim otherwise)

- WHOIS-based domain age — note: WHOIS uses TCP port 43, which the
  sandboxed dev environment blocked outright (not even a TCP handshake
  succeeded, unlike 80/443's fake-success interception). Should work
  fine on an unrestricted network; just wasn't verifiable during
  initial development.
- API-key setup wizard (test each key live, report which backends are
  usable before a scan runs)

## GitLab mirror

The repo also mirrors to `gitlab.com/S1gM4/BACKHOE` (private). Mirroring
runs via `.github/workflows/mirror-gitlab.yml` — on every push to `main`
(and manually via workflow_dispatch), GitHub's own CI runner pushes HEAD
to GitLab using a `GITLAB_TOKEN` repository secret.

That secret must be added manually via the GitHub UI (Settings → Secrets
and variables → Actions → New repository secret, name `GITLAB_TOKEN`) —
there's no MCP tool available to set repo secrets programmatically, and
a raw GitLab PAT was deliberately kept out of every file, commit, and
this doc. It was shared once via an uploaded file during development and
used only to create the GitLab project via a single ephemeral API call
(never persisted to disk or git config); a direct `git push` with the
token embedded in the command was attempted and blocked by the coding
environment's own data-exfiltration classifier — which is why the
mirror pushes from GitHub's CI instead of from a local shell. If the
GitLab mirror workflow is failing, the secret probably isn't set yet.

## Environment gotchas worth knowing before debugging "why is this failing"

- Sandboxed/CI environments may intercept ALL outbound port 80/443
  traffic — `netcheck.py` exists because of this. If port-scan or TLS
  results look wrong in some other new environment, check
  `netcheck.tcp_tls_is_intercepted()` first before assuming a code bug.
- DNS (A/MX/TXT/PTR) has been reliable in every environment tested so
  far, including ones that block HTTP(S) and TCP port 43 entirely.
- `requests`-based calls (Gravatar, crt.sh) and raw-socket calls
  (portscan, tls) can behave differently under the same network
  policy — `requests` honors `HTTPS_PROXY`, raw sockets don't, but a
  transparent intercept catches both anyway. Don't assume switching
  libraries fixes a network-policy problem.
