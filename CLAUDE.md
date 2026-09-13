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
    spiderfoot.py           shells out to a separately-installed SpiderFoot
                        checkout (not a pip dependency — see "SpiderFoot" below)
    shodan.py               Shodan host-lookup enrichment for infra-check,
                        needs an API key via keys.py — see "Shodan" below
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

## What's shipped (v0.4)

- `domain-audit <domain>` — crt.sh subdomain enum, optional theHarvester
  and SpiderFoot enrichment (see below), keyword + cert-recency interest
  scoring, live DNS liveness check (`--no-resolve` to skip)
- `person-check <email>` — MX/SPF/DMARC for the domain, Gravatar check
  for the address. Verified live against yellowhammertrader.com during
  development: found DMARC is present but `p=none` (monitor-only, not
  enforcing) — a real, actionable finding, worth following up on for
  the actual business domain independent of this tool's development.
- `infra-check <target>` — resolve + reverse DNS, bounded 9-port scan,
  TLS cert expiry, with the interception guard above, plus optional
  Shodan host-lookup enrichment (see below)

123 tests, all passing, `pytest` from repo root (`pip install -e ".[dev]"`
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

## SpiderFoot (v0.4) — subprocess, not a dependency, actually run live

`backends/spiderfoot.py` shells out to a separately-installed SpiderFoot
checkout (github.com/smicallef/spiderfoot) for `domain-audit`. Unlike
theHarvester, this one wasn't Python-version-blocked — its
`requirements.txt` has no upper bound — so it was cloned, its
dependencies actually installed, and a real scan run live against
`example.com` end to end during development. Stronger verification than
theHarvester got, and it changed the design in a way source-reading alone
hadn't caught:

- **SpiderFoot ships no console-script entry point at all** — no
  `pip install`-able command, unlike theHarvester. It's meant to be
  cloned and run as `python3 sf.py ...`. So instead of `shutil.which`,
  `_find_sf_py()` looks for a `SPIDERFOOT_HOME` env var pointing at the
  checkout, falling back to `shutil.which("sf.py")` only if an operator
  has manually put it on PATH.
- `sf.py -s <target> -t <types> -o json -q` genuinely is a one-shot scan
  (confirmed live) — a built-in `sfp__stor_stdout` module streams a JSON
  array straight to stdout, no server to run first.
- **The live run is what caught the real gotcha**: the JSON stream is
  *not* filtered down to the requested `-t` types — SpiderFoot pulls in
  every module in the dependency chain, so a real scan against
  `example.com` emitted dozens of event types (HTTP headers, raw DNS
  records, PGP keys, Stack Overflow usernames...) far beyond
  `INTERNET_NAME`/`EMAILADDR`. Every event is filtered here by its exact
  `type` string, not the requested types.
- **The gotcha inside the gotcha**: `"Internet Name"` (a real subdomain)
  is a *different* type string than `"Affiliate - Internet Name"` — in
  the live run, Cloudflare's own nameservers (the target's DNS provider,
  not the target) came back labeled `"Affiliate - Internet Name"` while
  `www.example.com` came back as plain `"Internet Name"`. A substring
  match instead of an exact match would have misattributed a third
  party's infrastructure to the target. Same exact-match discipline
  applies to `"Email Address"`.
- `DEFAULT_TYPES = "INTERNET_NAME,EMAILADDR"` passed to `-t` lets
  SpiderFoot auto-select whichever of its own modules can produce those
  types — no manual per-source curation needed like theHarvester's
  `DEFAULT_SOURCES` list.
- SpiderFoot writes persistent scan history to
  `~/.spiderfoot/spiderfoot.db` by default (confirmed in source) —
  overridden via the `SPIDERFOOT_DATA` env var, pointed at a per-call
  tempdir, so nothing accumulates on the host.
- Not found → `SpiderFootNotInstalled` (a `SpiderFootError`), caught
  non-fatally in `cli.py` — same tier as theHarvester and Gravatar.
  `--no-spiderfoot` skips it outright.
- Only `"Internet Name"`→SUBDOMAIN and `"Email Address"`→EMAIL are
  mapped, for the same reason theHarvester's `ips` is skipped: IP
  addresses belong to infra-check's PTR-lookup-backed handling, not here.

## Shodan (v0.4) — API-key wizard + host-lookup backend for infra-check

`backends/shodan.py` calls Shodan's REST API directly with plain
`requests` (no `shodan` SDK dependency, same pattern as crtsh.py and
gravatar.py) to enrich `infra-check`'s open-port findings with
service/product/version data and known CVEs — richer than what BACKHOE's
own bounded TCP connect scan (`portscan.py`) can see on its own. Unlike
theHarvester/SpiderFoot, Shodan needs an API key, which is where
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
  Gravatar, theHarvester, and SpiderFoot. If `keys.get_api_key()` returns
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

## What's NOT built yet (don't claim otherwise)

- Censys backend (Shodan is now built — see above; Censys would be a
  similar richer-port-data source, still not built)
- HaveIBeenPwned breach-hit backend (needs an API key — HIBP's
  by-email lookup hasn't been free/keyless since 2019)
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
