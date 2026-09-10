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
        _score_open_port(finding)
    elif finding.type == FindingType.CERTIFICATE:
        _score_certificate(finding)
    elif finding.type == FindingType.DNS_RECORD:
        _score_dns_record(finding)
    elif finding.type == FindingType.IP_ADDRESS:
        _score_ip_address(finding)
    elif finding.type == FindingType.EMAIL:
        _score_email(finding)
    else:
        finding.confidence = finding.confidence or 0.5
        finding.interest = finding.interest or 0.3

    return finding


# Ports where exposure to the open internet is itself worth flagging —
# databases, remote-admin, and legacy cleartext protocols.
SENSITIVE_PORTS = {21: "ftp", 22: "ssh", 23: "telnet", 3306: "mysql", 3389: "rdp", 5432: "postgres", 6379: "redis", 27017: "mongodb"}
EXPECTED_WEB_PORTS = {80, 443}


def _score_open_port(finding: Finding) -> None:
    finding.confidence = 0.95
    port = finding.raw.get("port")
    if port in SENSITIVE_PORTS:
        finding.interest = 0.85
        finding.note = finding.note or (
            f"port {port} ({SENSITIVE_PORTS[port]}) is open — confirm this is "
            "intentional and restricted to trusted sources"
        )
    elif port in EXPECTED_WEB_PORTS:
        finding.interest = 0.2
        finding.note = finding.note or "expected web port"
    else:
        finding.interest = 0.55
        finding.note = finding.note or f"port {port} open — confirm this is expected"


def _score_certificate(finding: Finding) -> None:
    finding.confidence = 0.9
    days_left = finding.raw.get("days_until_expiry")
    if days_left is None:
        finding.interest = 0.3
    elif days_left < 0:
        finding.interest = 0.95
        finding.note = finding.note or f"certificate EXPIRED {abs(days_left)} day(s) ago"
    elif days_left < 14:
        finding.interest = 0.85
        finding.note = finding.note or f"certificate expires in {days_left} day(s) — renew now"
    elif days_left < 30:
        finding.interest = 0.55
        finding.note = finding.note or f"certificate expires in {days_left} day(s)"
    else:
        finding.interest = 0.1


def _score_dns_record(finding: Finding) -> None:
    finding.confidence = 0.95
    record_type = finding.raw.get("record_type")
    present = finding.raw.get("present")

    if record_type == "spf":
        if present:
            finding.interest = 0.15
        else:
            finding.interest = 0.85
            finding.note = finding.note or (
                "no SPF record — anyone can send mail that appears to be from this domain"
            )
    elif record_type == "dmarc":
        if not present:
            finding.interest = 0.85
            finding.note = finding.note or (
                "no DMARC record — spoofed mail from this domain won't be rejected or reported"
            )
        elif finding.raw.get("policy") == "none":
            finding.interest = 0.5
            finding.note = finding.note or (
                "DMARC policy is p=none — spoofed mail is monitored but not blocked"
            )
        else:
            finding.interest = 0.1
    elif record_type == "mx":
        finding.interest = 0.1 if present else 0.4
        if not present:
            finding.note = finding.note or "no MX records — this domain may not accept mail"
    elif record_type == "ptr":
        finding.interest = 0.1
    else:
        finding.interest = 0.2


def _score_ip_address(finding: Finding) -> None:
    finding.confidence = 0.95
    finding.interest = 0.15
    if not finding.raw.get("ptr"):
        finding.note = finding.note or "no reverse DNS (PTR) record"


def _score_email(finding: Finding) -> None:
    finding.confidence = 0.7
    if finding.raw.get("gravatar"):
        finding.interest = 0.35
        finding.note = finding.note or "public Gravatar profile exists for this address"
    else:
        finding.interest = 0.15
        finding.note = finding.note or "no public Gravatar profile"


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
