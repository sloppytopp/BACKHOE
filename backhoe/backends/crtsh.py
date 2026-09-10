"""
crt.sh backend — certificate transparency log lookups.

Chosen as BACKHOE's first backend because it needs zero API keys and
zero rate-limit headaches, so `backhoe domain-audit <domain>` works
out of the box with no setup wizard required first.
"""

import requests
from datetime import datetime

from ..schema import Finding, FindingType

CRTSH_URL = "https://crt.sh/"


class CrtShError(Exception):
    """Raised when crt.sh can't be queried or returns something unusable.

    This is a hard failure, not a Finding — a lookup that failed has zero
    subdomains in it, and rendering that as a fake "finding" with
    confidence 0.0 (the old behavior) buries a real error inside the
    results table instead of telling the user their scan didn't run.
    """


def run(domain: str) -> list[Finding]:
    """
    Query crt.sh for every certificate issued for *.{domain} and pull
    out the unique subdomains mentioned in them.

    Raises CrtShError on any failure — callers decide how to surface that,
    but it must never be silently swallowed into an empty-looking result.
    """
    try:
        resp = requests.get(
            CRTSH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=30,
            headers={"User-Agent": "backhoe-osint/0.1"},
        )
        resp.raise_for_status()
        records = resp.json()
    except requests.RequestException as e:
        raise CrtShError(f"crt.sh request failed: {e}") from e
    except ValueError as e:
        raise CrtShError(f"crt.sh returned unparseable data: {e}") from e

    if not isinstance(records, list):
        raise CrtShError(f"crt.sh returned an unexpected response shape: {type(records).__name__}")

    findings: list[Finding] = []
    seen_subdomains: dict[str, datetime | None] = {}

    for rec in records:
        name_value = rec.get("name_value", "")
        not_before = rec.get("not_before")
        parsed_date = None
        if not_before:
            try:
                parsed_date = datetime.strptime(not_before, "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                pass

        # a single cert can list multiple names (SANs) separated by newlines
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if not name or "*" in name:
                continue
            # keep the most recent issue date we've seen for this name
            if name not in seen_subdomains or (
                parsed_date and (seen_subdomains[name] is None or parsed_date > seen_subdomains[name])
            ):
                seen_subdomains[name] = parsed_date

    for name, issued in seen_subdomains.items():
        findings.append(
            Finding(
                type=FindingType.SUBDOMAIN,
                value=name,
                source="crt.sh",
                first_seen=issued,
                raw={"domain": domain},
            )
        )

    return findings
