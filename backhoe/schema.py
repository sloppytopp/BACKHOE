"""
BACKHOE normalized finding schema.

Every backend (crt.sh, theHarvester, Shodan, etc.) outputs
its own format. BACKHOE's whole job is translating all of that into
ONE shape so findings can be scored, deduped, and rendered consistently
no matter which tool produced them.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class FindingType(str, Enum):
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    EMAIL = "email"
    OPEN_PORT = "open_port"
    BREACH_HIT = "breach_hit"
    CERTIFICATE = "certificate"
    DNS_RECORD = "dns_record"


@dataclass
class Finding:
    type: FindingType
    value: str                 # the actual data — e.g. "mail.yellowhammertrader.com"
    source: str                # which backend found it — e.g. "crt.sh"
    first_seen: datetime | None = None
    confidence: float = 0.5    # 0.0-1.0, set by scoring.py, not the backend
    interest: float = 0.0      # 0.0-1.0, "how much does this matter" — set by scoring.py
    note: str = ""             # short human-readable context, e.g. "cert issued 3 days ago"
    live: bool | None = None   # DNS resolution result this run — None if not checked
    raw: dict = field(default_factory=dict)  # original backend payload, kept for debugging
    merged_raw: bool = field(default=False, repr=False)  # internal: has raw been reshaped to {source: {...}}?

    def key(self) -> str:
        """Dedup key — same type+value from two sources should merge, not
        duplicate. DNS_RECORD findings additionally key on raw['record_type']
        because multiple distinct records (mx/spf/dmarc) legitimately share
        the same type+value (the domain) — without this, person-check's
        three DNS findings would collapse into one the moment merge_findings
        ever runs over them.
        """
        if self.type == FindingType.DNS_RECORD:
            record_type = self.raw.get("record_type", "")
            return f"{self.type}:{self.value.lower()}:{record_type}"
        return f"{self.type}:{self.value.lower()}"


# Fields filled in from a later duplicate ONLY when the winning finding
# left them blank. Adding a new field to Finding? Add it here too, or it
# silently never merges.
_FILL_IF_BLANK = ("first_seen", "live", "note")


def merge_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse findings that share a dedup key (same type+value, e.g. the
    same subdomain surfaced by both crt.sh and theHarvester) into one, so
    the report shows one row with combined provenance instead of literal
    duplicates. First finding seen for a key wins for most fields; later
    ones fill in blanks.

    `raw` is preserved, not dropped: a finding with no duplicate keeps its
    original flat `raw` dict untouched, so scoring.py's flat
    `raw.get("port")`-style lookups need no changes. Only the moment a
    second source actually merges into an existing key does `raw` become
    `{source_name: {...}, other_source_name: {...}}`, so a second source's
    payload survives instead of silently being dropped.
    """
    merged: dict[str, Finding] = {}
    for f in findings:
        k = f.key()
        if k not in merged:
            merged[k] = f
            continue

        existing = merged[k]
        sources = existing.source.split(", ")
        if f.source not in sources:
            existing.source = ", ".join([*sources, f.source])

        for attr in _FILL_IF_BLANK:
            if not getattr(existing, attr) and getattr(f, attr):
                setattr(existing, attr, getattr(f, attr))

        if not existing.merged_raw:
            # First real collision for this key — reshape once, namespaced
            # by source, so both payloads survive future merges too.
            original_source = existing.source.split(", ")[0]
            existing.raw = {original_source: existing.raw} if existing.raw else {}
            existing.merged_raw = True

        if f.raw:
            existing.raw[f.source] = f.raw

    return list(merged.values())


def raw_get(finding: Finding, key: str, default=None):
    """Read one field from a Finding's `raw`, correct whether or not
    merge_findings() has reshaped it into {source: {...}}. Returns the
    first non-None value found across sources post-merge, or `default`
    if no source has it. Use this instead of `finding.raw.get(key)` in
    any reader that might run on a finding merge_findings() could touch
    — a flat `.get()` silently returns None post-reshape instead of
    finding the value nested under a source key."""
    if not finding.merged_raw:
        return finding.raw.get(key, default)
    for payload in finding.raw.values():
        value = payload.get(key)
        if value is not None:
            return value
    return default
