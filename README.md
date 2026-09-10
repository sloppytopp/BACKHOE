# BACKHOE

OSINT recon that gives you an answer, not a data dump.

Every other OSINT tool hands you raw findings and expects you to
figure out what matters. BACKHOE normalizes output across backend
tools, scores findings by relevance, and renders a report that reads
like a summary — not a table you have to reverse-engineer.

## Install

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

## Use

```bash
backhoe domain-audit yellowhammertrader.com
```

That's the whole interface for v1. No module picker, no target-type
dropdown — one command, one target, one readable report.

Pass `--no-resolve` to skip the live DNS check (faster, but you lose the
live/dead signal).

## Test

```bash
pip install -e ".[dev]"
pytest
```

crt.sh calls are mocked in tests, so the suite runs offline. DNS
resolution tests hit real DNS (`localhost` and a guaranteed-bogus
`.invalid` hostname).

## What it does right now (v0.2)

- Pulls every subdomain seen in certificate transparency logs (crt.sh,
  no API key needed)
- Flags subdomains with names like `admin`, `dev`, `staging`, `vpn`,
  etc. as higher-interest
- Flags subdomains from certs issued in the last 30 days (recently
  stood-up infra you may not know about)
- Checks live DNS resolution for every subdomain found and suppresses
  the interest score for ones that no longer resolve — a subdomain
  that showed up on a cert in 2021 and hasn't resolved since is noise,
  not a finding, and the report treats it that way
- Fails loud, not quiet: a broken crt.sh lookup surfaces as a red error
  and a non-zero exit code, never as a fake "finding" mixed into real
  results
- Renders a plain-English summary line plus a sorted, color-coded
  table — highest interest first

## What's coming next

- theHarvester + SpiderFoot as additional backends, normalized into
  the same `Finding` schema so results merge instead of piling up
  separately
- Shodan/Censys backend for open ports
- HaveIBeenPwned backend for breach hits
- A setup wizard that tests each API key live and reports which
  backends are actually usable before a scan runs
- `person-check` and `infra-check` profiles alongside `domain-audit`
