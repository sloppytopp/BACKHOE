"""
DNS-based recon checks — MX/SPF/DMARC (email security posture) and PTR
(reverse DNS). All genuinely verifiable with no API key: DNS just answers
with what's actually published. The only real engineering problem is
telling "this record doesn't exist" (a legitimate finding) apart from
"we couldn't ask" (a real failure) — conflating them is exactly the kind
of silent-failure behavior that makes OSINT tools' results untrustworthy.
"""
from __future__ import annotations

import socket

import dns.exception
import dns.resolver


class DnsCheckError(Exception):
    """A real DNS infrastructure failure (timeout, no nameservers, the
    queried domain doesn't exist at all). Never raised for an authoritative
    'this specific record doesn't exist' answer — that's a finding, not
    an error.
    """


def resolve_a_records(domain: str) -> list[str]:
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
        return ips
    except socket.gaierror as e:
        raise DnsCheckError(f"could not resolve {domain}: {e}") from e


def reverse_dns(ip: str) -> str | None:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return None  # no PTR record — a legitimate, common outcome
    except socket.gaierror as e:
        raise DnsCheckError(f"reverse DNS lookup for {ip} failed: {e}") from e


def check_mx(domain: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, "MX")
        return sorted(str(r.exchange).rstrip(".") for r in answers)
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN as e:
        raise DnsCheckError(f"{domain} does not exist (NXDOMAIN)") from e
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as e:
        raise DnsCheckError(f"MX lookup for {domain} failed: {e}") from e


def check_spf(domain: str) -> str | None:
    try:
        answers = dns.resolver.resolve(domain, "TXT")
    except dns.resolver.NoAnswer:
        return None
    except dns.resolver.NXDOMAIN as e:
        raise DnsCheckError(f"{domain} does not exist (NXDOMAIN)") from e
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as e:
        raise DnsCheckError(f"TXT lookup for {domain} failed: {e}") from e

    for record in answers:
        txt = _join_txt(record)
        if txt.lower().startswith("v=spf1"):
            return txt
    return None


def check_dmarc(domain: str) -> tuple[bool, str | None]:
    """Returns (present, policy). policy is the p= value (none/quarantine/reject)."""
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return False, None
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as e:
        raise DnsCheckError(f"DMARC lookup for {domain} failed: {e}") from e

    for record in answers:
        txt = _join_txt(record)
        if txt.lower().startswith("v=dmarc1"):
            policy = None
            for part in txt.split(";"):
                part = part.strip()
                if part.lower().startswith("p="):
                    policy = part.split("=", 1)[1].strip().lower()
            return True, policy
    return False, None


def _join_txt(record) -> str:
    # A TXT record's value can be split across multiple quoted strings.
    return "".join(
        part.decode() if isinstance(part, bytes) else part for part in record.strings
    )
