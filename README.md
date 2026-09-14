<img src="assets/favicon.png" alt="BACKHOE" width="500" height="500">

# BACKHOE

[![tests](https://github.com/sloppytopp/BACKHOE/actions/workflows/tests.yml/badge.svg)](https://github.com/sloppytopp/BACKHOE/actions/workflows/tests.yml)
[![license](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

**OSINT recon that gives you an answer, not a data dump.**

Every other OSINT tool hands you raw findings and expects you to
already know what matters. BACKHOE scores every finding by actual
relevance and tells you the one thing worth reading, in one command,
against a target you already have in mind — no wiring six tools
together, no reading the source to figure out what the flags do.

## See it work — 30 seconds, no signup, no API key

```bash
pip install backhoe-osint
backhoe person-check admin@yellowhammertrader.com
```

```
Running person-check against admin@yellowhammertrader.com...

╭───────────────────────────── BACKHOE — admin@yellowhammertrader.com ─────────────────────────────╮
│ SPF is present, but DMARC policy is p=none — spoofed mail from this domain is monitored, not     │
│ blocked.                                                                                         │
╰──────────────────────────────────────────────────────────────────────────────────────────────────╯
┏━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Interest ┃ Type         ┃ Value                    ┃  Live  ┃ Source   ┃ Note                    ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ MED      │ dns_record   │ yellowhammertrader.com   │   -    │ dns      │ DMARC policy is p=none  │
│          │              │                          │        │          │ — spoofed mail is       │
│          │              │                          │        │          │ monitored but not       │
│          │              │                          │        │          │ blocked                 │
│ low      │ email        │ admin@yellowhammertrade… │   -    │ gravatar │ no public Gravatar      │
│          │              │                          │        │          │ profile                 │
└──────────┴──────────────┴──────────────────────────┴────────┴──────────┴─────────────────────────┘
```

That's real, live output from a real domain — not a mockup. One command,
zero API keys, and the tool tells you the *actual* finding (this domain's
mail can be spoofed and only gets monitored, not blocked) instead of
handing you an MX record and leaving you to know why that matters.

```bash
backhoe domain-audit some-domain-you-care-about.com
```
is the same deal for subdomain recon — certificate-transparency-log
enumeration, scored by name and freshness, zero keys required.

**`infra-check` does active TCP connections (a bounded port scan) —
only run it against domains, addresses, and infrastructure you own or
are explicitly authorized to test.** `person-check` and `domain-audit`
are fully passive (DNS/HTTP lookups anyone can already make) and don't
carry that restriction.

## Install

```bash
pip install backhoe-osint
```

Or from source:
```bash
git clone https://github.com/sloppytopp/BACKHOE.git
cd BACKHOE
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

## Use

```bash
backhoe domain-audit <target-domain>
backhoe person-check admin@<target-domain>
backhoe infra-check <target-domain-or-ip>
```

One command, one target, one readable report — no module picker, no
target-type dropdown.

- `domain-audit` — subdomains from certificate transparency logs and
  (if installed) theHarvester and SpiderFoot, live DNS check,
  interest-scored by name and freshness. Pass `--no-resolve` to skip
  the live DNS check, `--no-harvester` to skip theHarvester, or
  `--no-spiderfoot` to skip SpiderFoot.
- `person-check` — mail security posture for the email's domain
  (MX/SPF/DMARC) plus a Gravatar existence check for the address.
- `infra-check` — resolves the target, reverse-DNS on each IP, a
  bounded common-port scan, the live TLS certificate's expiry, and (if
  keys are available) Shodan and/or Censys host-lookup enrichment with
  service/product/version and known-CVE data. Pass `--no-ports` to
  skip the port scan, `--no-shodan`/`--no-censys` to skip either
  enrichment source. With both on by default and no `SHODAN_API_KEY`/
  `CENSYS_API_KEY` env var or stored key yet, `infra-check` prompts for
  each interactively on first run — see "Optional: Shodan enrichment"
  and "Optional: Censys enrichment" below.

## Test

```bash
pip install -e ".[dev]"
pytest
```

Every network call is mocked, so the full suite runs offline. (DNS
resolution tests are the one exception — they hit real DNS, resolving
`localhost` and a guaranteed-bogus `.invalid` hostname.)

## What it does right now (v0.5)

**domain-audit**
- Pulls every subdomain seen in certificate transparency logs (crt.sh,
  no API key needed)
- If [theHarvester](https://github.com/laramies/theHarvester) and/or
  [SpiderFoot](https://github.com/smicallef/spiderfoot) are installed
  separately (neither is a BACKHOE dependency — see below), also runs
  them for additional subdomains and emails. Findings for the same
  subdomain from multiple sources merge into one row instead of
  duplicating.
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
- (Optional) Shodan and/or Censys host-lookup enrichment for open
  ports — service, product/version, and known CVEs, when available —
  if you provide a free API key for either or both. Findings from
  multiple sources on the same port merge into one row. Both run
  independently of the interception check below since they're passive
  third-party API calls, not raw TCP from this host. See "Optional:
  Shodan enrichment" and "Optional: Censys enrichment" below.
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

## Optional external tools: theHarvester and SpiderFoot

`domain-audit` shells out to both if it can find them; neither is ever
installed as a BACKHOE dependency.

- **theHarvester** needs to be on `PATH` (current theHarvester requires
  Python 3.14+, a different runtime than BACKHOE targets). Install it
  separately — e.g. `uv tool install theHarvester` or `pipx install
  theHarvester` — per [its own docs](https://github.com/laramies/theHarvester).
  Skip it with `--no-harvester`.
- **SpiderFoot** has no installable command at all — it's a checkout you
  run as `python3 sf.py ...`. Clone
  [its repo](https://github.com/smicallef/spiderfoot) anywhere and set
  `SPIDERFOOT_HOME` to that directory. Skip it with `--no-spiderfoot`.

If either isn't found, `domain-audit` prints a yellow warning and
continues without it — same non-fatal tier as the Gravatar check in
`person-check`.

## Optional: Shodan enrichment

`infra-check` enriches open-port findings with Shodan host-lookup data
(service, product/version, and known CVEs) if you provide a
[Shodan](https://www.shodan.io/) API key — Shodan is a keyed API, not
an installable tool, so this doesn't need anything on `PATH`.

Resolution order: a `SHODAN_API_KEY` environment variable, then a key
already stored at `~/.config/backhoe/keys.json` (created `0600`,
directory `0700`), then an interactive prompt on first run (hidden
input, like a password) — leave it blank to skip. Skip Shodan entirely
with `--no-shodan`.

Runs even on a network `infra-check` detects as intercepting TCP/TLS
(see above) — it's a passive API call to Shodan, not raw TCP from this
host, so it stays trustworthy where the built-in port scan and TLS
fetch don't.

**Verification note:** built from Shodan's published API docs and
tested against mocked HTTP responses only — not yet run against a live
Shodan account end-to-end in this environment.

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

## What's coming next

- HaveIBeenPwned backend for breach hits (needs an API key)
- WHOIS-based domain age lookup
- A standalone setup wizard that tests each configured API key live
  and reports which backends are actually usable before a scan runs
  (the interactive per-backend key prompt already exists — see
  "Optional: Shodan enrichment" above — this would be a single
  upfront command covering all keyed backends at once)
- `pip install backhoe-osint` and a Docker image, both on the way —
  see `.github/workflows/publish.yml` (publishes automatically on a
  GitHub Release once PyPI/Docker Hub are set up)
- A Homebrew tap (`brew install backhoe`) — draft formula at
  `packaging/homebrew/backhoe.rb`, blocked on a real release existing
  to generate correct dependency hashes against

## License

BACKHOE is licensed under the [GNU Affero General Public License
v3.0](LICENSE) (AGPL-3.0). In practical terms: you're free to use,
modify, and self-host it, but if you run a modified version as a
network service (a hosted/SaaS product), you have to make that
modified source available too.

Want to use BACKHOE in a commercial product without those AGPL
obligations? A commercial license is available — open an issue or
reach out to discuss terms.
