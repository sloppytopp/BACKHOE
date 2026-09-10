"""
Scoring — the layer every other OSINT tool skips.

Raw findings are not equally important. A dead subdomain from 2019 and
a freshly-issued cert for "admin-internal.yourdomain.com" should NOT
render with the same visual weight. This module assigns each Finding
an `interest` score (0-1) so report.py can sort/highlight accordingly
instead of dumping everything flat.

This is intentionally simple and transparent in v1 — hand-written
keyword/recency rules, not a black-box model. You should always be
able to see *why* something scored high.
"""

from datetime import datetime, timedelta, timezone

from .schema import Finding, FindingType

# Subdomain name fragments that tend to indicate higher-value targets —
# admin panels, dev/staging environments, forgotten infra, etc.
INTERESTING_KEYWORDS = [
    "admin", "dev", "staging", "stage", "test", "internal", "intranet",
    "vpn", "backup", "bak", "old", "debug", "cpanel", "webmail", "git",
    "jenkins", "portainer", "phpmyadmin", "db", "database", "api-internal",
    "beta", "demo", "sandbox", "uat", "preprod",
]

RECENT_CERT_WINDOW = timedelta(days=30)


def score_finding(finding: Finding) -> Finding:
    """Mutates and returns the finding with confidence + interest set."""

    if finding.type == FindingType.SUBDOMAIN:
        _score_subdomain(finding)
    elif finding.type == FindingType.BREACH_HIT:
        finding.confidence = 0.85
        finding.interest = 0.9
        finding.note = finding.note or "credential exposure — verify and rotate"
    elif finding.type == FindingType.OPEN_PORT:
        finding.confidence = 0.9
        finding.interest = 0.7
    else:
        finding.confidence = finding.confidence or 0.5
        finding.interest = finding.interest or 0.3

    return finding


def _score_subdomain(finding: Finding) -> None:
    finding.confidence = 0.9  # crt.sh data is directly observed, high trust

    name = finding.value.lower()
    interest = 0.2  # baseline — "just another subdomain"

    for kw in INTERESTING_KEYWORDS:
        if kw in name:
            interest = max(interest, 0.75)
            finding.note = f"name contains '{kw}' — worth a manual look"
            break

    if finding.first_seen:
        first_seen = finding.first_seen
        if first_seen.tzinfo is None:
            first_seen = first_seen.replace(tzinfo=timezone.utc)
        age = datetime.now(timezone.utc) - first_seen
        if age < RECENT_CERT_WINDOW:
            interest = max(interest, 0.6)
            note_suffix = f"cert issued {age.days}d ago — recently stood up"
            finding.note = f"{finding.note}; {note_suffix}" if finding.note else note_suffix

    # Liveness is the strongest real-world signal available: a subdomain
    # that no longer resolves is historical noise, however interesting its
    # name looks; one that's live AND interesting-named is the actual find.
    if finding.live is True:
        interest = min(1.0, interest + 0.15)
    elif finding.live is False:
        interest *= 0.4
        note_suffix = "no longer resolves — likely decommissioned"
        finding.note = f"{finding.note}; {note_suffix}" if finding.note else note_suffix

    finding.interest = interest


def score_all(findings: list[Finding]) -> list[Finding]:
    return [score_finding(f) for f in findings]
