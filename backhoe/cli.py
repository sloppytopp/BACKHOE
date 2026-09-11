"""
BACKHOE CLI — named profiles instead of a module picker.

The whole design bet: you shouldn't have to know which backend tool
does what, or which flags to pass it. You say what you want
("domain-audit yellowhammertrader.com") and BACKHOE decides which
backends to run and how to score/render the result.
"""

import ipaddress
import re
import sys

import click

from .backends import crtsh, dns_checks, netcheck, portscan, theharvester, tls
from .backends.crtsh import CrtShError
from .backends.dns_checks import DnsCheckError
from .backends.gravatar import GravatarError, check_gravatar
from .backends.theharvester import TheHarvesterError, TheHarvesterNotInstalled
from .backends.tls import TlsError
from .resolve import resolve_many
from .schema import Finding, FindingType, merge_findings
from .scoring import score_all
from .report import render_report

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@click.group()
def cli():
    """BACKHOE — OSINT recon that gives you an answer, not a data dump."""
    pass


@cli.command("domain-audit")
@click.argument("domain")
@click.option(
    "--resolve/--no-resolve",
    default=True,
    help="Check live DNS resolution for each subdomain found (default: on).",
)
@click.option(
    "--harvester/--no-harvester",
    default=True,
    help=(
        "Run theHarvester for additional subdomain/email enumeration "
        "(default: on). Requires theHarvester installed separately — "
        "see github.com/laramies/theHarvester; skipped with a warning "
        "if it isn't on PATH."
    ),
)
def domain_audit(domain: str, resolve: bool, harvester: bool):
    """
    Run a domain recon profile: subdomains, certs, and (as more
    backends are wired in) breach data, open ports, and DNS history.
    """
    click.echo(f"Running domain-audit against {domain}...\n")

    try:
        findings = crtsh.run(domain)
    except CrtShError as exc:
        click.secho(f"crt.sh lookup failed: {exc}", fg="red", err=True)
        sys.exit(1)

    if harvester:
        try:
            findings = findings + theharvester.run(domain)
        except TheHarvesterNotInstalled as exc:
            click.secho(f"theHarvester skipped: {exc}", fg="yellow", err=True)
        except TheHarvesterError as exc:
            click.secho(f"theHarvester lookup failed, skipping: {exc}", fg="yellow", err=True)

    findings = merge_findings(findings)

    if resolve and findings:
        subdomains = [f.value for f in findings if f.type == FindingType.SUBDOMAIN]
        click.echo(f"Resolving {len(subdomains)} hostname(s)...\n")
        live_map = resolve_many(subdomains)
        for f in findings:
            if f.type == FindingType.SUBDOMAIN:
                f.live = live_map.get(f.value)

    findings = score_all(findings)
    render_report(domain, findings)


@cli.command("person-check")
@click.argument("email")
def person_check(email: str):
    """
    Run an email recon profile: mail security posture (MX/SPF/DMARC) for
    the domain, plus a Gravatar existence check for the address itself.
    """
    email = email.strip()
    if not EMAIL_RE.match(email):
        click.secho(f"'{email}' doesn't look like a valid email address.", fg="red", err=True)
        sys.exit(1)

    domain = email.rsplit("@", 1)[1]
    click.echo(f"Running person-check against {email}...\n")

    findings: list[Finding] = []

    try:
        mx_records = dns_checks.check_mx(domain)
        findings.append(
            Finding(
                type=FindingType.DNS_RECORD,
                value=domain,
                source="dns",
                raw={"record_type": "mx", "present": bool(mx_records), "records": mx_records},
            )
        )

        spf = dns_checks.check_spf(domain)
        findings.append(
            Finding(
                type=FindingType.DNS_RECORD,
                value=domain,
                source="dns",
                raw={"record_type": "spf", "present": spf is not None, "record": spf},
            )
        )

        dmarc_present, dmarc_policy = dns_checks.check_dmarc(domain)
        findings.append(
            Finding(
                type=FindingType.DNS_RECORD,
                value=domain,
                source="dns",
                raw={"record_type": "dmarc", "present": dmarc_present, "policy": dmarc_policy},
            )
        )
    except DnsCheckError as exc:
        click.secho(f"DNS lookup failed: {exc}", fg="red", err=True)
        sys.exit(1)

    try:
        has_gravatar = check_gravatar(email)
        findings.append(
            Finding(type=FindingType.EMAIL, value=email, source="gravatar", raw={"gravatar": has_gravatar})
        )
    except GravatarError as exc:
        click.secho(f"Gravatar check skipped: {exc}", fg="yellow", err=True)

    findings = score_all(findings)
    render_report(email, findings)


@cli.command("infra-check")
@click.argument("target")
@click.option(
    "--ports/--no-ports",
    default=True,
    help="Run the bounded common-port scan (default: on). Only use against infra you own or are authorized to test.",
)
def infra_check(target: str, ports: bool):
    """
    Run an infrastructure recon profile against a domain or IP: resolved
    IPs + reverse DNS, a bounded common-port scan, and the live TLS
    certificate's expiry.
    """
    click.echo(f"Running infra-check against {target}...\n")

    findings: list[Finding] = []

    try:
        ipaddress.ip_address(target)
        ips = [target]
    except ValueError:
        try:
            ips = dns_checks.resolve_a_records(target)
        except DnsCheckError as exc:
            click.secho(f"DNS lookup failed: {exc}", fg="red", err=True)
            sys.exit(1)

    for ip in ips:
        try:
            ptr = dns_checks.reverse_dns(ip)
        except DnsCheckError as exc:
            click.secho(f"Reverse DNS lookup skipped for {ip}: {exc}", fg="yellow", err=True)
            ptr = None
        findings.append(
            Finding(type=FindingType.IP_ADDRESS, value=ip, source="dns", raw={"ptr": ptr})
        )

    if netcheck.tcp_tls_is_intercepted():
        click.secho(
            "This network transparently intercepts TCP/TLS traffic (a proxy, "
            "sandbox, or VPN answered on behalf of a guaranteed-unassigned test "
            "IP). Port-scan and TLS-certificate results would be fabricated — "
            "skipping both. Run infra-check from a direct, unproxied network "
            "to get real port and certificate data.",
            fg="yellow",
            err=True,
        )
    else:
        if ports:
            click.echo(f"Scanning {len(portscan.COMMON_PORTS)} common ports on {target}...\n")
            port_results = portscan.scan_ports(target)
            for port, is_open in port_results.items():
                if is_open:
                    findings.append(
                        Finding(
                            type=FindingType.OPEN_PORT,
                            value=f"{target}:{port}",
                            source="portscan",
                            raw={"port": port, "service": portscan.COMMON_PORTS.get(port, "?")},
                        )
                    )

        try:
            cert = tls.get_certificate_info(target)
            findings.append(
                Finding(type=FindingType.CERTIFICATE, value=f"{target}:443", source="tls", raw=cert)
            )
        except TlsError as exc:
            click.secho(f"TLS certificate check skipped: {exc}", fg="yellow", err=True)

    findings = score_all(findings)
    render_report(target, findings)


if __name__ == "__main__":
    cli()
