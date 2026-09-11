"""
theHarvester backend — shells out to the separately-installed theHarvester
CLI (github.com/laramies/theHarvester) and normalizes its JSON output into
Findings. Not a pip dependency of BACKHOE: current theHarvester requires
Python 3.14+, a different runtime than this project targets, so it's run as
a subprocess against whatever `theHarvester` the operator has installed on
PATH, never imported as a library.

Only `hosts` and `emails` are mapped here. theHarvester's `ips` output is
deliberately left unmapped: infra-check already owns IP/PTR recon, and
mapping IPs here without doing the same reverse-DNS check `IP_ADDRESS`
scoring assumes would risk the exact kind of misleading finding this
codebase's "fail loud, never fake" rule exists to prevent.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from ..schema import Finding, FindingType

# Curated, keyless-only source list verified against theHarvester's own
# source table (lib/source_catalog.py) — sources needing an unconfigured
# API key are skipped by theHarvester itself with a log line rather than
# failing, but keeping this list curated (not `-b all`) keeps runtime and
# behavior predictable. Deliberately excludes "crtsh": domain-audit already
# queries crt.sh directly via backends/crtsh.py, so including it here would
# just double-query the same data for merge_findings() to dedupe back out.
DEFAULT_SOURCES = (
    "certspotter,hackertarget,otx,rapiddns,subdomaincenter,"
    "commoncrawl,waybackarchive,dnsdumpster,urlscan,baidu,duckduckgo"
)

DEFAULT_TIMEOUT = 180


class TheHarvesterError(Exception):
    """A real failure running theHarvester or reading its output — never
    raised for "the tool ran and found nothing"."""


class TheHarvesterNotInstalled(TheHarvesterError):
    """theHarvester isn't on PATH. It's a separate external tool (not a pip
    dependency — see module docstring), so this is expected in many
    environments and treated as non-fatal by callers."""


def run(domain: str, timeout: float = DEFAULT_TIMEOUT, sources: str = DEFAULT_SOURCES) -> list[Finding]:
    binary = shutil.which("theHarvester")
    if binary is None:
        raise TheHarvesterNotInstalled(
            "theHarvester not found on PATH — it's a separate tool "
            "(github.com/laramies/theHarvester, requires Python 3.14+), "
            "not a BACKHOE dependency. Install it separately to enable this "
            "enrichment source."
        )

    with tempfile.TemporaryDirectory() as tmpdir:
        out_base = str(Path(tmpdir) / "report")
        try:
            proc = subprocess.run(
                [binary, "-d", domain, "-b", sources, "-f", out_base],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as e:
            raise TheHarvesterError(f"theHarvester timed out after {timeout}s") from e

        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()[-500:]
            raise TheHarvesterError(f"theHarvester exited {proc.returncode}: {detail}")

        out_path = Path(out_base + ".json")
        if not out_path.exists():
            raise TheHarvesterError("theHarvester produced no JSON output file")

        try:
            data = json.loads(out_path.read_text())
        except ValueError as e:
            raise TheHarvesterError(f"unparseable JSON output from theHarvester: {e}") from e

    return _to_findings(data)


def _to_findings(data: dict) -> list[Finding]:
    findings: list[Finding] = []

    for host in data.get("hosts", []):
        # A host entry is either a bare hostname or "hostname:ip" when
        # theHarvester's own DNS resolution was used (not requested here,
        # but handled defensively since it's cheap and correct either way).
        hostname = host.split(":", 1)[0] if ":" in host else host
        findings.append(
            Finding(type=FindingType.SUBDOMAIN, value=hostname, source="theharvester", raw={"raw_entry": host})
        )

    for email in data.get("emails", []):
        findings.append(Finding(type=FindingType.EMAIL, value=email, source="theharvester", raw={}))

    return findings
