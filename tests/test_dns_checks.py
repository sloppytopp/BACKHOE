import socket
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import pytest

from backhoe.backends import dns_checks
from backhoe.backends.dns_checks import DnsCheckError


def _txt_answer(*strings_per_record):
    records = []
    for strings in strings_per_record:
        rec = MagicMock()
        rec.strings = [s.encode() for s in strings]
        records.append(rec)
    return records


def test_resolve_a_records_returns_ips():
    with patch("socket.gethostbyname_ex", return_value=("example.com", [], ["1.2.3.4"])):
        assert dns_checks.resolve_a_records("example.com") == ["1.2.3.4"]


def test_resolve_a_records_raises_on_failure():
    with patch("socket.gethostbyname_ex", side_effect=socket.gaierror("nope")):
        with pytest.raises(DnsCheckError):
            dns_checks.resolve_a_records("example.invalid")


def test_reverse_dns_returns_none_when_no_ptr():
    with patch("socket.gethostbyaddr", side_effect=socket.herror("no ptr")):
        assert dns_checks.reverse_dns("1.2.3.4") is None


def test_reverse_dns_returns_hostname():
    with patch("socket.gethostbyaddr", return_value=("host.example.com", [], ["1.2.3.4"])):
        assert dns_checks.reverse_dns("1.2.3.4") == "host.example.com"


def test_check_mx_returns_sorted_hosts():
    mx1, mx2 = MagicMock(exchange="b.mail.example.com."), MagicMock(exchange="a.mail.example.com.")
    with patch("dns.resolver.resolve", return_value=[mx1, mx2]):
        assert dns_checks.check_mx("example.com") == ["a.mail.example.com", "b.mail.example.com"]


def test_check_mx_empty_on_no_answer():
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NoAnswer()):
        assert dns_checks.check_mx("example.com") == []


def test_check_mx_raises_on_nxdomain():
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
        with pytest.raises(DnsCheckError):
            dns_checks.check_mx("doesnotexist.example")


def test_check_mx_raises_on_timeout():
    with patch("dns.resolver.resolve", side_effect=dns.exception.Timeout()):
        with pytest.raises(DnsCheckError):
            dns_checks.check_mx("example.com")


def test_check_spf_finds_record_among_other_txt():
    answers = _txt_answer(["google-site-verification=abc"], ["v=spf1 include:_spf.example.com ~all"])
    with patch("dns.resolver.resolve", return_value=answers):
        spf = dns_checks.check_spf("example.com")
    assert spf == "v=spf1 include:_spf.example.com ~all"


def test_check_spf_none_when_absent():
    answers = _txt_answer(["google-site-verification=abc"])
    with patch("dns.resolver.resolve", return_value=answers):
        assert dns_checks.check_spf("example.com") is None


def test_check_dmarc_parses_policy():
    answers = _txt_answer(["v=DMARC1; p=none;"])
    with patch("dns.resolver.resolve", return_value=answers):
        present, policy = dns_checks.check_dmarc("example.com")
    assert present is True
    assert policy == "none"


def test_check_dmarc_absent_returns_false_none():
    with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
        present, policy = dns_checks.check_dmarc("example.com")
    assert (present, policy) == (False, None)
