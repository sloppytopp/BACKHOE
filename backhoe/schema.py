"""
BACKHOE normalized finding schema.

Every backend (crt.sh, theHarvester, SpiderFoot, Shodan, etc.) outputs
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

    def key(self) -> str:
        """Dedup key — same type+value from two sources should merge, not duplicate."""
        return f"{self.type}:{self.value.lower()}"
