from unittest.mock import patch

from click.testing import CliRunner

from backhoe.backends.censys import CENSYS_PROVIDER, CensysAPIError
from backhoe.backends.dns_checks import DnsCheckError
from backhoe.backends.gravatar import GravatarError
from backhoe.backends.hibp import HIBP_PROVIDER, HIBPAPIError
from backhoe.backends.shodan import SHODAN_PROVIDER, ShodanAPIError
from backhoe.backends.theharvester import TheHarvesterError, TheHarvesterNotInstalled
from backhoe.cli import cli
from backhoe.schema import Finding, FindingType


def test_person_check_rejects_invalid_email():
    runner = CliRunner()
    result = runner.invoke(cli, ["person-check", "not-an-email"])
    assert result.exit_code != 0


def test_person_check_exits_nonzero_on_dns_failure():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.check_mx", side_effect=DnsCheckError("boom")):
        result = runner.invoke(cli, ["person-check", "user@example.com", "--no-hibp"])
    assert result.exit_code != 0


def test_person_check_happy_path_continues_without_gravatar():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.check_mx", return_value=["mail.example.com"]), patch(
        "backhoe.cli.dns_checks.check_spf", return_value="v=spf1 ~all"
    ), patch("backhoe.cli.dns_checks.check_dmarc", return_value=(True, "reject")), patch(
        "backhoe.cli.check_gravatar", side_effect=GravatarError("network down")
    ):
        result = runner.invoke(cli, ["person-check", "user@example.com", "--no-hibp"])
    assert result.exit_code == 0
    assert "Gravatar check skipped" in result.output
    assert "example.com" in result.output


def test_domain_audit_warns_and_continues_when_theharvester_not_installed():
    runner = CliRunner()
    with patch("backhoe.cli.crtsh.run", return_value=[]), patch(
        "backhoe.cli.theharvester.run", side_effect=TheHarvesterNotInstalled("not found")
    ):
        result = runner.invoke(cli, ["domain-audit", "example.com", "--no-resolve"])

    assert result.exit_code == 0
    assert "theHarvester" in result.output


def test_domain_audit_warns_and_continues_on_theharvester_error():
    runner = CliRunner()
    with patch("backhoe.cli.crtsh.run", return_value=[]), patch(
        "backhoe.cli.theharvester.run", side_effect=TheHarvesterError("exited 1: boom")
    ):
        result = runner.invoke(cli, ["domain-audit", "example.com", "--no-resolve"])

    assert result.exit_code == 0
    assert "boom" in result.output


def test_domain_audit_skips_theharvester_with_no_harvester_flag():
    runner = CliRunner()
    with patch("backhoe.cli.crtsh.run", return_value=[]), patch(
        "backhoe.cli.theharvester.run"
    ) as harvester_mock:
        result = runner.invoke(cli, ["domain-audit", "example.com", "--no-resolve", "--no-harvester"])

    assert result.exit_code == 0
    harvester_mock.assert_not_called()


def test_domain_audit_merges_duplicate_subdomains_from_both_sources():
    runner = CliRunner()
    crtsh_finding = Finding(type=FindingType.SUBDOMAIN, value="www.example.com", source="crt.sh")
    harvester_finding = Finding(type=FindingType.SUBDOMAIN, value="www.example.com", source="theharvester")

    with patch("backhoe.cli.crtsh.run", return_value=[crtsh_finding]), patch(
        "backhoe.cli.theharvester.run", return_value=[harvester_finding]
    ):
        result = runner.invoke(cli, ["domain-audit", "example.com", "--no-resolve"])

    assert result.exit_code == 0
    assert result.output.count("www.example.com") == 1
    # both source names present — exact layout may wrap across lines at
    # narrow console widths, so don't assert on the literal joined string
    assert "crt.sh" in result.output
    assert "theharvester" in result.output


def test_infra_check_accepts_a_bare_ip():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.reverse_dns", return_value=None), patch(
        "backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=True
    ):
        result = runner.invoke(cli, ["infra-check", "1.2.3.4", "--no-shodan", "--no-censys"])
    assert result.exit_code == 0
    assert "1.2.3.4" in result.output


def test_infra_check_skips_ports_and_tls_when_intercepted():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=True), patch(
        "backhoe.cli.portscan.scan_ports"
    ) as scan_mock, patch(
        "backhoe.cli.tls.get_certificate_info"
    ) as tls_mock:
        result = runner.invoke(cli, ["infra-check", "example.com", "--no-shodan", "--no-censys"])

    assert result.exit_code == 0
    assert "transparently intercepts" in result.output
    scan_mock.assert_not_called()
    tls_mock.assert_not_called()


def test_infra_check_scans_every_resolved_ip_not_the_original_hostname():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4", "5.6.7.8"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=False), patch(
        "backhoe.cli.portscan.scan_ports", return_value={}
    ) as scan_mock, patch(
        "backhoe.cli.tls.get_certificate_info", return_value={"days_until_expiry": 60, "issuer": {}, "subject": {}, "san": []}
    ):
        result = runner.invoke(cli, ["infra-check", "cdn.example.com", "--no-shodan", "--no-censys"])

    assert result.exit_code == 0
    scan_mock.assert_any_call("1.2.3.4")
    scan_mock.assert_any_call("5.6.7.8")
    assert scan_mock.call_count == 2


def test_infra_check_tags_open_port_findings_with_the_ip_not_the_hostname():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=False), patch(
        "backhoe.cli.portscan.scan_ports", return_value={443: True}
    ), patch(
        "backhoe.cli.tls.get_certificate_info", return_value={"days_until_expiry": 60, "issuer": {}, "subject": {}, "san": []}
    ):
        result = runner.invoke(cli, ["infra-check", "cdn.example.com", "--no-shodan", "--no-censys"])

    assert result.exit_code == 0
    assert "1.2.3.4:443" in result.output


def test_infra_check_runs_ports_and_tls_when_not_intercepted():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value="host.example.com"
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=False), patch(
        "backhoe.cli.portscan.scan_ports", return_value={443: True, 22: False}
    ), patch(
        "backhoe.cli.tls.get_certificate_info",
        return_value={"days_until_expiry": 60, "issuer": {}, "subject": {}, "san": []},
    ):
        result = runner.invoke(cli, ["infra-check", "example.com", "--no-shodan", "--no-censys"])

    assert result.exit_code == 0
    assert "tls" in result.output
    assert "portscan" in result.output


def test_infra_check_skips_shodan_silently_when_no_key_available():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=True), patch(
        "backhoe.cli.keys.get_api_key", return_value=None
    ) as get_key_mock, patch(
        "backhoe.cli.shodan.lookup_host"
    ) as lookup_mock:
        result = runner.invoke(cli, ["infra-check", "example.com", "--no-censys"])

    assert result.exit_code == 0
    get_key_mock.assert_called_once_with(SHODAN_PROVIDER)
    lookup_mock.assert_not_called()


def test_infra_check_skips_shodan_with_no_shodan_flag():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=True), patch(
        "backhoe.cli.keys.get_api_key"
    ) as get_key_mock:
        result = runner.invoke(cli, ["infra-check", "example.com", "--no-shodan", "--no-censys"])

    assert result.exit_code == 0
    get_key_mock.assert_not_called()


def test_infra_check_runs_shodan_even_when_intercepted():
    # Shodan is a passive API lookup, not raw TCP from this host — it must
    # still run when netcheck reports interception, even though the
    # built-in port scan and TLS fetch are skipped in that case.
    runner = CliRunner()
    shodan_finding = Finding(
        type=FindingType.OPEN_PORT, value="1.2.3.4:80", source="shodan",
        raw={"port": 80, "service": "http", "product": None, "version": None, "vulns": []},
    )
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=True), patch(
        "backhoe.cli.keys.get_api_key", return_value="a-key"
    ), patch("backhoe.cli.shodan.lookup_host", return_value=[shodan_finding]):
        result = runner.invoke(cli, ["infra-check", "example.com", "--no-censys"])

    assert result.exit_code == 0
    assert "1.2.3.4:80" in result.output


def test_infra_check_warns_and_continues_on_shodan_api_error():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=True), patch(
        "backhoe.cli.keys.get_api_key", return_value="a-key"
    ), patch("backhoe.cli.shodan.lookup_host", side_effect=ShodanAPIError("rate limited")):
        result = runner.invoke(cli, ["infra-check", "example.com", "--no-censys"])

    assert result.exit_code == 0
    assert "rate limited" in result.output


def test_infra_check_merges_shodan_and_portscan_open_port_on_same_ip_port():
    runner = CliRunner()
    shodan_finding = Finding(
        type=FindingType.OPEN_PORT, value="1.2.3.4:443", source="shodan",
        raw={"port": 443, "service": "https", "product": "nginx", "version": "1.18", "vulns": []},
    )
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=False), patch(
        "backhoe.cli.portscan.scan_ports", return_value={443: True}
    ), patch(
        "backhoe.cli.tls.get_certificate_info",
        return_value={"days_until_expiry": 60, "issuer": {}, "subject": {}, "san": []},
    ), patch("backhoe.cli.keys.get_api_key", return_value="a-key"), patch(
        "backhoe.cli.shodan.lookup_host", return_value=[shodan_finding]
    ):
        result = runner.invoke(cli, ["infra-check", "cdn.example.com", "--no-censys"])

    assert result.exit_code == 0
    assert result.output.count("1.2.3.4:443") == 1
    assert "portscan" in result.output
    assert "shodan" in result.output


def test_infra_check_skips_censys_silently_when_no_key_available():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=True), patch(
        "backhoe.cli.keys.get_api_key", return_value=None
    ) as get_key_mock, patch(
        "backhoe.cli.censys.lookup_host"
    ) as lookup_mock:
        result = runner.invoke(cli, ["infra-check", "example.com", "--no-shodan"])

    assert result.exit_code == 0
    get_key_mock.assert_called_once_with(CENSYS_PROVIDER)
    lookup_mock.assert_not_called()


def test_infra_check_skips_censys_with_no_censys_flag():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=True), patch(
        "backhoe.cli.keys.get_api_key"
    ) as get_key_mock:
        result = runner.invoke(cli, ["infra-check", "example.com", "--no-shodan", "--no-censys"])

    assert result.exit_code == 0
    get_key_mock.assert_not_called()


def test_infra_check_runs_censys_even_when_intercepted():
    runner = CliRunner()
    censys_finding = Finding(
        type=FindingType.OPEN_PORT, value="1.2.3.4:80", source="censys",
        raw={"port": 80, "service": "HTTP", "product": None, "version": None, "vulns": []},
    )
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=True), patch(
        "backhoe.cli.keys.get_api_key", return_value="a-key"
    ), patch("backhoe.cli.censys.lookup_host", return_value=[censys_finding]):
        result = runner.invoke(cli, ["infra-check", "example.com", "--no-shodan"])

    assert result.exit_code == 0
    assert "1.2.3.4:80" in result.output


def test_infra_check_warns_and_continues_on_censys_api_error():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=True), patch(
        "backhoe.cli.keys.get_api_key", return_value="a-key"
    ), patch("backhoe.cli.censys.lookup_host", side_effect=CensysAPIError("rate limited")):
        result = runner.invoke(cli, ["infra-check", "example.com", "--no-shodan"])

    assert result.exit_code == 0
    assert "rate limited" in result.output


def test_infra_check_merges_censys_and_portscan_open_port_on_same_ip_port():
    runner = CliRunner()
    censys_finding = Finding(
        type=FindingType.OPEN_PORT, value="1.2.3.4:443", source="censys",
        raw={"port": 443, "service": "HTTPS", "product": "nginx", "version": "1.18", "vulns": []},
    )
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=False), patch(
        "backhoe.cli.portscan.scan_ports", return_value={443: True}
    ), patch(
        "backhoe.cli.tls.get_certificate_info",
        return_value={"days_until_expiry": 60, "issuer": {}, "subject": {}, "san": []},
    ), patch("backhoe.cli.keys.get_api_key", return_value="a-key"), patch(
        "backhoe.cli.censys.lookup_host", return_value=[censys_finding]
    ):
        result = runner.invoke(cli, ["infra-check", "cdn.example.com", "--no-shodan"])

    assert result.exit_code == 0
    assert result.output.count("1.2.3.4:443") == 1
    assert "portscan" in result.output
    assert "censys" in result.output


def test_infra_check_merges_shodan_and_censys_and_portscan_on_same_ip_port(monkeypatch):
    # The real point of running two keyed backends: prove all three sources
    # compose into one row instead of three, and the CVE from whichever
    # source has one still surfaces. Force a wide terminal so Rich's table
    # doesn't truncate the Note column's CVE text — this test's 3-way merge
    # produces a wider Source column ("portscan, shodan, censys") than any
    # prior test, and without a real tty/COLUMNS set, Rich defaults to an
    # 80-column render that truncates "CVE-2022-9999" to "CVE-2022-99…".
    monkeypatch.setenv("COLUMNS", "200")
    runner = CliRunner()
    shodan_finding = Finding(
        type=FindingType.OPEN_PORT, value="1.2.3.4:443", source="shodan",
        raw={"port": 443, "service": "https", "product": "nginx", "version": "1.18", "vulns": []},
    )
    censys_finding = Finding(
        type=FindingType.OPEN_PORT, value="1.2.3.4:443", source="censys",
        raw={"port": 443, "service": "HTTPS", "product": None, "version": None, "vulns": ["CVE-2022-9999"]},
    )
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=False), patch(
        "backhoe.cli.portscan.scan_ports", return_value={443: True}
    ), patch(
        "backhoe.cli.tls.get_certificate_info",
        return_value={"days_until_expiry": 60, "issuer": {}, "subject": {}, "san": []},
    ), patch("backhoe.cli.keys.get_api_key", return_value="a-key"), patch(
        "backhoe.cli.shodan.lookup_host", return_value=[shodan_finding]
    ), patch("backhoe.cli.censys.lookup_host", return_value=[censys_finding]):
        result = runner.invoke(cli, ["infra-check", "cdn.example.com"])

    assert result.exit_code == 0
    assert result.output.count("1.2.3.4:443") == 1
    assert "portscan" in result.output
    assert "shodan" in result.output
    assert "censys" in result.output
    assert "CVE-2022-9999" in result.output


def test_person_check_skips_hibp_silently_when_no_key_available():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.check_mx", return_value=["mail.example.com"]), patch(
        "backhoe.cli.dns_checks.check_spf", return_value="v=spf1 ~all"
    ), patch("backhoe.cli.dns_checks.check_dmarc", return_value=(True, "reject")), patch(
        "backhoe.cli.check_gravatar", return_value=False
    ), patch(
        "backhoe.cli.keys.get_api_key", return_value=None
    ) as get_key_mock, patch(
        "backhoe.cli.hibp_backend.check_breaches"
    ) as check_mock:
        result = runner.invoke(cli, ["person-check", "user@example.com"])

    assert result.exit_code == 0
    get_key_mock.assert_called_once_with(HIBP_PROVIDER)
    check_mock.assert_not_called()


def test_person_check_skips_hibp_with_no_hibp_flag():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.check_mx", return_value=["mail.example.com"]), patch(
        "backhoe.cli.dns_checks.check_spf", return_value="v=spf1 ~all"
    ), patch("backhoe.cli.dns_checks.check_dmarc", return_value=(True, "reject")), patch(
        "backhoe.cli.check_gravatar", return_value=False
    ), patch(
        "backhoe.cli.keys.get_api_key"
    ) as get_key_mock:
        result = runner.invoke(cli, ["person-check", "user@example.com", "--no-hibp"])

    assert result.exit_code == 0
    get_key_mock.assert_not_called()


def test_person_check_reports_hibp_breach_hit():
    runner = CliRunner()
    breach_finding = Finding(
        type=FindingType.BREACH_HIT, value="Adobe", source="hibp",
        raw={
            "name": "Adobe", "title": "Adobe", "domain": "adobe.com",
            "breach_date": "2013-10-04", "pwn_count": 152445165,
            "data_classes": ["Email addresses", "Passwords"],
            "is_verified": True, "is_fabricated": False,
            "is_sensitive": False, "is_retired": False, "is_spam_list": False,
        },
    )
    with patch("backhoe.cli.dns_checks.check_mx", return_value=["mail.example.com"]), patch(
        "backhoe.cli.dns_checks.check_spf", return_value="v=spf1 ~all"
    ), patch("backhoe.cli.dns_checks.check_dmarc", return_value=(True, "reject")), patch(
        "backhoe.cli.check_gravatar", return_value=False
    ), patch(
        "backhoe.cli.keys.get_api_key", return_value="a-key"
    ), patch(
        "backhoe.cli.hibp_backend.check_breaches", return_value=[breach_finding]
    ):
        result = runner.invoke(cli, ["person-check", "user@example.com"])

    assert result.exit_code == 0
    assert "Adobe" in result.output
    assert "hibp" in result.output


def test_person_check_warns_and_continues_on_hibp_api_error():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.check_mx", return_value=["mail.example.com"]), patch(
        "backhoe.cli.dns_checks.check_spf", return_value="v=spf1 ~all"
    ), patch("backhoe.cli.dns_checks.check_dmarc", return_value=(True, "reject")), patch(
        "backhoe.cli.check_gravatar", return_value=False
    ), patch(
        "backhoe.cli.keys.get_api_key", return_value="a-key"
    ), patch(
        "backhoe.cli.hibp_backend.check_breaches", side_effect=HIBPAPIError("rate limited")
    ):
        result = runner.invoke(cli, ["person-check", "user@example.com"])

    assert result.exit_code == 0
    assert "rate limited" in result.output
