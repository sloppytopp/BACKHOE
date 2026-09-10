"""
BACKHOE CLI — named profiles instead of a module picker.

The whole design bet: you shouldn't have to know which backend tool
does what, or which flags to pass it. You say what you want
("domain-audit yellowhammertrader.com") and BACKHOE decides which
backends to run and how to score/render the result.
"""

import sys

import click

from .backends import crtsh
from .backends.crtsh import CrtShError
from .resolve import resolve_many
from .schema import FindingType
from .scoring import score_all
from .report import render_report


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
def domain_audit(domain: str, resolve: bool):
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

    if resolve and findings:
        subdomains = [f.value for f in findings if f.type == FindingType.SUBDOMAIN]
        click.echo(f"Resolving {len(subdomains)} hostname(s)...\n")
        live_map = resolve_many(subdomains)
        for f in findings:
            if f.type == FindingType.SUBDOMAIN:
                f.live = live_map.get(f.value)

    findings = score_all(findings)
    render_report(domain, findings)


if __name__ == "__main__":
    cli()
