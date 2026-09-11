"""
SpiderFoot backend — runs a one-shot passive scan via a separately-installed
SpiderFoot checkout (github.com/smicallef/spiderfoot) and normalizes its
JSON stream into Findings.

Not a pip dependency of BACKHOE, and unlike theHarvester it isn't even
PATH-installable: SpiderFoot ships no console-script entry point at all —
its own docs run it as `python3 sf.py ...` from inside a cloned checkout.
So instead of `shutil.which`, this looks for a `SPIDERFOOT_HOME` env var
pointing at that checkout (falling back to `shutil.which("sf.py")` in case
an operator has manually put it on PATH).

Verified against the actual project (cloned and read, and run live end to
end against example.com) during development, not assumed:

- `sf.py -s <target> -t <types> -o json -q` is genuinely a one-shot scan
  (no separate server to run first) — a built-in `sfp__stor_stdout` module
  streams a JSON array straight to stdout as events are found.
- The stream is NOT filtered down to the requested `-t` types: SpiderFoot
  pulls in every module in the dependency chain, so a real run emits dozens
  of other event types (HTTP headers, raw DNS records, web content, PGP
  keys, ...) alongside the ones asked for. Every event is filtered here by
  its exact `type` string.
- Critically, `"Internet Name"` (a genuine subdomain of the target) is a
  *different* type string than `"Affiliate - Internet Name"` (a third
  party's hostname that showed up incidentally, e.g. the target's DNS
  provider's own nameservers) — confirmed with a live run where Cloudflare's
  nameservers came back as "Affiliate - Internet Name" while
  www.example.com came back as plain "Internet Name". Matching on a
  substring instead of the exact string would misattribute someone else's
  infrastructure to the target. Same reasoning applies to email addresses.
- A module needing an unset API key logs an error and returns without
  crashing the scan (verified in source, e.g. sfp_shodan.py) — same
  non-fatal-per-module behavior theHarvester's sources rely on.
- SpiderFoot writes persistent scan history to `~/.spiderfoot/spiderfoot.db`
  by default. Overridden here via the `SPIDERFOOT_DATA` env var, pointed at
  a per-call tempdir, so nothing accumulates on the host — same
  self-contained-tempdir pattern as theHarvester's `-f` output file.

Only `"Internet Name"` and `"Email Address"` are mapped, for the same
reason theHarvester's `ips` is skipped: everything else either isn't a
Finding this schema has a type for, or (IP addresses) belongs to
infra-check's PTR-lookup-backed IP_ADDRESS handling, not here.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from ..schema import Finding, FindingType

# Event type *codes* passed to `-t` (SpiderFoot auto-selects whichever of
# its own modules can produce these — no manual per-module curation needed,
# unlike theHarvester's DEFAULT_SOURCES).
DEFAULT_TYPES = "INTERNET_NAME,EMAILADDR"

# Event type *labels* as they actually appear in stdout JSON — verified via
# a live run, not assumed from the type codes above (SpiderFoot renames
# them for display, e.g. INTERNET_NAME -> "Internet Name"). Must match
# exactly; "Affiliate - Internet Name" is a deliberately different string.
SUBDOMAIN_EVENT_LABEL = "Internet Name"
EMAIL_EVENT_LABEL = "Email Address"

DEFAULT_TIMEOUT = 180


class SpiderFootError(Exception):
    """A real failure running SpiderFoot or reading its output — never
    raised for "the scan ran and found nothing"."""


class SpiderFootNotInstalled(SpiderFootError):
    """No SpiderFoot checkout found. It's a separate external tool with no
    PATH-installable command of its own (see module docstring), so this is
    expected in many environments and treated as non-fatal by callers."""


def _find_sf_py() -> str:
    home = os.environ.get("SPIDERFOOT_HOME")
    if home:
        candidate = Path(home) / "sf.py"
        if candidate.is_file():
            return str(candidate)

    on_path = shutil.which("sf.py")
    if on_path:
        return on_path

    raise SpiderFootNotInstalled(
        "No SpiderFoot checkout found — set SPIDERFOOT_HOME to point at "
        "your clone of github.com/smicallef/spiderfoot (it has no "
        "PATH-installable command by default). Install it separately to "
        "enable this enrichment source."
    )


def run(domain: str, timeout: float = DEFAULT_TIMEOUT, types: str = DEFAULT_TYPES) -> list[Finding]:
    sf_py = _find_sf_py()

    with tempfile.TemporaryDirectory() as data_dir:
        env = {**os.environ, "SPIDERFOOT_DATA": data_dir}
        try:
            proc = subprocess.run(
                [sys.executable, sf_py, "-s", domain, "-t", types, "-o", "json", "-q"],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=os.path.dirname(sf_py),
                env=env,
            )
        except subprocess.TimeoutExpired as e:
            raise SpiderFootError(f"SpiderFoot timed out after {timeout}s") from e

        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()[-500:]
            raise SpiderFootError(f"SpiderFoot exited {proc.returncode}: {detail}")

        try:
            events = json.loads(proc.stdout)
        except ValueError as e:
            raise SpiderFootError(f"unparseable JSON output from SpiderFoot: {e}") from e

    return _to_findings(events)


def _to_findings(events: list[dict]) -> list[Finding]:
    findings: list[Finding] = []

    for event in events:
        label = event.get("type")
        data = event.get("data")
        if not data:
            continue

        if label == SUBDOMAIN_EVENT_LABEL:
            findings.append(
                Finding(
                    type=FindingType.SUBDOMAIN,
                    value=data,
                    source="spiderfoot",
                    raw={"module": event.get("module", "")},
                )
            )
        elif label == EMAIL_EVENT_LABEL:
            findings.append(Finding(type=FindingType.EMAIL, value=data, source="spiderfoot", raw={}))

    return findings
