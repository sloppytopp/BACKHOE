# BACKHOE

[![tests](https://github.com/sloppytopp/BACKHOE/actions/workflows/tests.yml/badge.svg)](https://github.com/sloppytopp/BACKHOE/actions/workflows/tests.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

OSINT recon that gives you an answer, not a data dump.

Every other OSINT tool hands you raw findings and expects you to
figure out what matters. BACKHOE normalizes output across backend
tools, scores findings by relevance, and renders a report that reads
like a summary — not a table you have to reverse-engineer.

**Only run BACKHOE against domains, addresses, and infrastructure you
own or are explicitly authorized to test.** `infra-check` performs
active TCP connections (a bounded port scan); treat it like any other
recon tool and get authorization first.

## Install

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

## Use

```bash
backhoe domain-audit yellowhammertrader.com
backhoe person-check admin@yellowhammertrader.com
backhoe infra-check yellowhammertrader.com
```

One command, one target, one readable report — no module picker, no
target-type dropdown.

- `domain-audit` — subdomains from certificate transparency logs, live
  DNS check, interest-scored by name and freshness.
  Pass `--no-resolve` to skip the live DNS check.
- `person-check` — mail security posture for the email's domain
  (MX/SPF/DMARC) plus a Gravatar existence check for the address.
- `infra-check` — resolves the target, reverse-DNS on each IP, a
  bounded common-port scan, and the live TLS certificate's expiry.
  Pass `--no-ports` to skip the port scan.

## Test

```bash
pip install -e ".[dev]"
pytest
```

Every network call is mocked, so the full suite runs offline. (DNS
resolution tests are the one exception — they hit real DNS, resolving
`localhost` and a guaranteed-bogus `.invalid` hostname.)

## What it does right now (v0.3)

**domain-audit**
- Pulls every subdomain seen in certificate transparency logs (crt.sh,
  no API key needed)
- Flags subdomains with names like `admin`, `dev`, `staging`, `vpn`,
  etc. as higher-interest, and ones from certs issued in the last 30
  days (recently stood-up infra you may not know about)
- Checks live DNS resolution for every subdomain and suppresses the
  interest score for ones that no longer resolve — a subdomain that
  showed up on a cert in 2021 and hasn't resolved since is noise, not
  a finding, and the report treats it that way

**person-check**
- MX, SPF, and DMARC lookups for the email's domain — flags a missing
  SPF or DMARC record as high-interest (your domain's mail can be
  spoofed) and a DMARC policy of `p=none` as medium-interest (spoofed
  mail is monitored, not blocked)
- Gravatar existence check for the address itself (a long-standing,
  well-known OSINT technique — no auth required, and only ever a
  positive signal, never a breach)

**infra-check**
- Resolves the target and reverse-DNS's every IP
- A bounded common-port scan (9 ports: ftp/ssh/smtp/http/https/mysql/
  rdp/http-alt/https-alt) — flags database/remote-admin ports as
  high-interest if exposed
- Live TLS certificate expiry — flags an expired or soon-to-expire
  cert as high/medium-interest
- **Detects transparent network interception before trusting any of
  the above.** Corporate proxies, security sandboxes, and some VPNs
  transparently intercept all outbound TCP/TLS traffic and answer on
  the real target's behalf — every port looks "open" and every
  certificate is the interceptor's own, not the target's. This isn't
  hypothetical: it's exactly what happened testing against a real
  domain during development, where the returned "certificate" was
  issued by the sandbox's own egress gateway. BACKHOE detects this by
  handshaking against a guaranteed-unroutable IP (RFC 5737 TEST-NET-3)
  before the real scan — if that handshake succeeds, port-scan and TLS
  results are skipped with a clear warning instead of reported as real
  findings. Run `infra-check` from a direct, unproxied network for
  trustworthy port/certificate data.

**Across all three profiles**
- Fails loud, not quiet: a broken lookup surfaces as a red error and a
  non-zero exit code (or a yellow warning for a non-fatal check like
  Gravatar), never as a fake "finding" mixed into real results
- Renders a plain-English summary line plus a sorted, color-coded
  table — highest interest first

## What's coming next

- theHarvester + SpiderFoot as additional backends, normalized into
  the same `Finding` schema so results merge instead of piling up
  separately
- Shodan/Censys backend for richer port/service data
- HaveIBeenPwned backend for breach hits (needs an API key)
- WHOIS-based domain age lookup
- A setup wizard that tests each API key live and reports which
  backends are actually usable before a scan runs
