from unittest.mock import patch

from click.testing import CliRunner

from backhoe.backends.dns_checks import DnsCheckError
from backhoe.backends.gravatar import GravatarError
from backhoe.backends.spiderfoot import SpiderFootError, SpiderFootNotInstalled
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
        result = runner.invoke(cli, ["person-check", "user@example.com"])
    assert result.exit_code != 0


def test_person_check_happy_path_continues_without_gravatar():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.check_mx", return_value=["mail.example.com"]), patch(
        "backhoe.cli.dns_checks.check_spf", return_value="v=spf1 ~all"
    ), patch("backhoe.cli.dns_checks.check_dmarc", return_value=(True, "reject")), patch(
        "backhoe.cli.check_gravatar", side_effect=GravatarError("network down")
    ):
        result = runner.invoke(cli, ["person-check", "user@example.com"])
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


def test_domain_audit_warns_and_continues_when_spiderfoot_not_installed():
    runner = CliRunner()
    with patch("backhoe.cli.crtsh.run", return_value=[]), patch(
        "backhoe.cli.theharvester.run", return_value=[]
    ), patch("backhoe.cli.spiderfoot.run", side_effect=SpiderFootNotInstalled("not found")):
        result = runner.invoke(cli, ["domain-audit", "example.com", "--no-resolve"])

    assert result.exit_code == 0
    assert "SpiderFoot" in result.output


def test_domain_audit_warns_and_continues_on_spiderfoot_error():
    runner = CliRunner()
    with patch("backhoe.cli.crtsh.run", return_value=[]), patch(
        "backhoe.cli.theharvester.run", return_value=[]
    ), patch("backhoe.cli.spiderfoot.run", side_effect=SpiderFootError("exited 1: boom")):
        result = runner.invoke(cli, ["domain-audit", "example.com", "--no-resolve"])

    assert result.exit_code == 0
    assert "boom" in result.output


def test_domain_audit_skips_spiderfoot_with_no_spiderfoot_flag():
    runner = CliRunner()
    with patch("backhoe.cli.crtsh.run", return_value=[]), patch(
        "backhoe.cli.theharvester.run", return_value=[]
    ), patch("backhoe.cli.spiderfoot.run") as spiderfoot_mock:
        result = runner.invoke(cli, ["domain-audit", "example.com", "--no-resolve", "--no-spiderfoot"])

    assert result.exit_code == 0
    spiderfoot_mock.assert_not_called()


def test_domain_audit_merges_subdomain_found_by_all_three_sources():
    runner = CliRunner()
    crtsh_finding = Finding(type=FindingType.SUBDOMAIN, value="www.example.com", source="crt.sh")
    harvester_finding = Finding(type=FindingType.SUBDOMAIN, value="www.example.com", source="theharvester")
    spiderfoot_finding = Finding(type=FindingType.SUBDOMAIN, value="www.example.com", source="spiderfoot")

    with patch("backhoe.cli.crtsh.run", return_value=[crtsh_finding]), patch(
        "backhoe.cli.theharvester.run", return_value=[harvester_finding]
    ), patch("backhoe.cli.spiderfoot.run", return_value=[spiderfoot_finding]):
        result = runner.invoke(cli, ["domain-audit", "example.com", "--no-resolve"])

    assert result.exit_code == 0
    assert result.output.count("www.example.com") == 1
    assert "spiderfoot" in result.output


def test_infra_check_accepts_a_bare_ip():
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.reverse_dns", return_value=None), patch(
        "backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=True
    ):
        result = runner.invoke(cli, ["infra-check", "1.2.3.4"])
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
        result = runner.invoke(cli, ["infra-check", "example.com"])

    assert result.exit_code == 0
    assert "transparently intercepts" in result.output
    scan_mock.assert_not_called()
    tls_mock.assert_not_called()


def test_infra_check_scans_every_resolved_ip_not_the_original_hostname():
    # A hostname behind a CDN/load balancer resolves to multiple IPs.
    # portscan.scan_ports() must be called with each concrete IP — not the
    # original hostname, which would let socket.create_connection() do its
    # own independent, untracked resolution on every single connection.
    runner = CliRunner()
    with patch("backhoe.cli.dns_checks.resolve_a_records", return_value=["1.2.3.4", "5.6.7.8"]), patch(
        "backhoe.cli.dns_checks.reverse_dns", return_value=None
    ), patch("backhoe.cli.netcheck.tcp_tls_is_intercepted", return_value=False), patch(
        "backhoe.cli.portscan.scan_ports", return_value={}
    ) as scan_mock, patch(
        "backhoe.cli.tls.get_certificate_info", return_value={"days_until_expiry": 60, "issuer": {}, "subject": {}, "san": []}
    ):
        result = runner.invoke(cli, ["infra-check", "cdn.example.com"])

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
        result = runner.invoke(cli, ["infra-check", "cdn.example.com"])

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
        result = runner.invoke(cli, ["infra-check", "example.com"])

    assert result.exit_code == 0
    assert "tls" in result.output
    assert "portscan" in result.output
