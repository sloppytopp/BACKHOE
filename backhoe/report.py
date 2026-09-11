"""
Report rendering — turns scored Findings into a readable terminal
report instead of a raw table dump or JSON wall of text.

This is the other big gap: even tools that DO surface real findings
usually leave you to write the "so what does this mean" sentence
yourself. render_report() writes that sentence.
"""

from collections import defaultdict

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from .schema import Finding, FindingType

console = Console()


def _synthesize_summary(target: str, findings: list[Finding]) -> str:
    by_type: dict[FindingType, list[Finding]] = defaultdict(list)
    for f in findings:
        by_type[f.type].append(f)

    lines = []

    subs = by_type.get(FindingType.SUBDOMAIN, [])
    if subs:
        high_interest = [f for f in subs if f.interest >= 0.6]
        lines.append(
            f"{len(subs)} subdomain(s) found for {target}"
            + (f", {len(high_interest)} flagged as worth a manual look." if high_interest else ".")
        )
        checked = [f for f in subs if f.live is not None]
        if checked:
            live = sum(1 for f in checked if f.live)
            dead = len(checked) - live
            lines.append(f"{live} resolve right now; {dead} do not (cert exists, DNS record gone).")

    breaches = by_type.get(FindingType.BREACH_HIT, [])
    if breaches:
        lines.append(f"{len(breaches)} breach hit(s) — verify and rotate any live credentials.")

    ports = by_type.get(FindingType.OPEN_PORT, [])
    if ports:
        sensitive = [f for f in ports if f.interest >= 0.75]
        lines.append(
            f"{len(ports)} open port(s) found"
            + (f", {len(sensitive)} on sensitive services worth confirming." if sensitive else ".")
        )

    dns_records = by_type.get(FindingType.DNS_RECORD, [])
    mail_gaps = [
        f
        for f in dns_records
        if f.raw.get("record_type") in ("spf", "dmarc") and not f.raw.get("present")
    ]
    weak_dmarc = [
        f
        for f in dns_records
        if f.raw.get("record_type") == "dmarc" and f.raw.get("present") and f.raw.get("policy") == "none"
    ]
    if mail_gaps:
        gap_names = ", ".join(f.raw["record_type"].upper() for f in mail_gaps)
        lines.append(f"Missing {gap_names} — this domain's mail can be spoofed.")
    elif weak_dmarc:
        lines.append(
            "SPF is present, but DMARC policy is p=none — spoofed mail from this "
            "domain is monitored, not blocked."
        )
    elif dns_records:
        lines.append("SPF and DMARC are both present and enforcing (not p=none).")

    certs = by_type.get(FindingType.CERTIFICATE, [])
    for f in certs:
        days_left = f.raw.get("days_until_expiry")
        if days_left is not None and days_left < 30:
            lines.append(f"TLS certificate for {f.value} expires in {days_left} day(s).")

    ips = by_type.get(FindingType.IP_ADDRESS, [])
    if ips:
        no_ptr = sum(1 for f in ips if not f.raw.get("ptr"))
        lines.append(
            f"{len(ips)} IP(s) resolved" + (f", {no_ptr} with no reverse DNS record." if no_ptr else ".")
        )

    emails = by_type.get(FindingType.EMAIL, [])
    for f in emails:
        if f.raw.get("gravatar"):
            lines.append(f"{f.value} has a public Gravatar profile.")

    if not lines:
        lines.append("No findings from the backends run. Try enabling more API keys or a wider scan.")

    return " ".join(lines)


def render_report(target: str, findings: list[Finding]) -> None:
    summary = _synthesize_summary(target, findings)
    console.print(Panel(summary, title=f"BACKHOE — {target}", border_style="cyan"))

    # sort highest interest first — this is the whole point
    findings_sorted = sorted(findings, key=lambda f: f.interest, reverse=True)

    table = Table(show_header=True, header_style="bold")
    table.add_column("Interest", width=8)
    table.add_column("Type", width=12)
    table.add_column("Value")
    table.add_column("Live", width=6, justify="center")
    # No fixed width: a merged finding's source (e.g. "crt.sh, theharvester")
    # can exceed a single narrow column and must not be silently truncated.
    table.add_column("Source")
    table.add_column("Note")

    for f in findings_sorted:
        interest_bar = _interest_marker(f.interest)
        live_marker = _live_marker(f.live)
        table.add_row(interest_bar, f.type.value, f.value, live_marker, f.source, f.note)

    console.print(table)


def _interest_marker(interest: float) -> str:
    if interest >= 0.75:
        return "[bold red]HIGH[/bold red]"
    if interest >= 0.5:
        return "[yellow]MED[/yellow]"
    return "[dim]low[/dim]"


def _live_marker(live: bool | None) -> str:
    if live is True:
        return "[green]yes[/green]"
    if live is False:
        return "[dim]no[/dim]"
    return "[dim]-[/dim]"
