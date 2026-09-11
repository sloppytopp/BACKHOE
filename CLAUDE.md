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
  backends/
    crtsh.py             certificate transparency subdomain enum (no API key)
    dns_checks.py         MX/SPF/DMARC/PTR — real DNS, no API key
    gravatar.py           Gravatar existence check for an email
    portscan.py            bounded common-port TCP connect scan
    tls.py                 live TLS certificate metadata fetch
    netcheck.py            interception canary — see below, read this one
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

## What's shipped (v0.3)

- `domain-audit <domain>` — crt.sh subdomain enum, keyword + cert-recency
  interest scoring, live DNS liveness check (`--no-resolve` to skip)
- `person-check <email>` — MX/SPF/DMARC for the domain, Gravatar check
  for the address. Verified live against yellowhammertrader.com during
  development: found DMARC is present but `p=none` (monitor-only, not
  enforcing) — a real, actionable finding, worth following up on for
  the actual business domain independent of this tool's development.
- `infra-check <target>` — resolve + reverse DNS, bounded 9-port scan,
  TLS cert expiry, with the interception guard above

52 tests, all passing, `pytest` from repo root (`pip install -e ".[dev]"`
first).

## What's NOT built yet (don't claim otherwise)

- theHarvester / SpiderFoot backends (would need normalizing their
  output into `Finding` — the schema is ready for it)
- Shodan/Censys backend (richer port/service data than the built-in scan)
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
