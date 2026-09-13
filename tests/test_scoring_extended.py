from backhoe.schema import Finding, FindingType
from backhoe.scoring import score_finding


def test_missing_spf_scores_high_interest():
    f = Finding(type=FindingType.DNS_RECORD, value="example.com", source="dns",
                raw={"record_type": "spf", "present": False})
    score_finding(f)
    assert f.interest >= 0.75


def test_present_spf_scores_low_interest():
    f = Finding(type=FindingType.DNS_RECORD, value="example.com", source="dns",
                raw={"record_type": "spf", "present": True, "record": "v=spf1 ~all"})
    score_finding(f)
    assert f.interest < 0.3


def test_missing_dmarc_scores_high_interest():
    f = Finding(type=FindingType.DNS_RECORD, value="example.com", source="dns",
                raw={"record_type": "dmarc", "present": False})
    score_finding(f)
    assert f.interest >= 0.75


def test_dmarc_p_none_scores_medium_interest():
    f = Finding(type=FindingType.DNS_RECORD, value="example.com", source="dns",
                raw={"record_type": "dmarc", "present": True, "policy": "none"})
    score_finding(f)
    assert 0.4 <= f.interest < 0.75
    assert "p=none" in f.note


def test_dmarc_reject_scores_low_interest():
    f = Finding(type=FindingType.DNS_RECORD, value="example.com", source="dns",
                raw={"record_type": "dmarc", "present": True, "policy": "reject"})
    score_finding(f)
    assert f.interest < 0.3


def test_expired_certificate_scores_highest():
    f = Finding(type=FindingType.CERTIFICATE, value="example.com:443", source="tls",
                raw={"days_until_expiry": -5})
    score_finding(f)
    assert f.interest >= 0.9
    assert "EXPIRED" in f.note


def test_healthy_certificate_scores_low_interest():
    f = Finding(type=FindingType.CERTIFICATE, value="example.com:443", source="tls",
                raw={"days_until_expiry": 60})
    score_finding(f)
    assert f.interest < 0.3


def test_sensitive_port_scores_high_interest():
    f = Finding(type=FindingType.OPEN_PORT, value="example.com:3306", source="portscan",
                raw={"port": 3306, "service": "mysql"})
    score_finding(f)
    assert f.interest >= 0.75


def test_expected_web_port_scores_low_interest():
    f = Finding(type=FindingType.OPEN_PORT, value="example.com:443", source="portscan",
                raw={"port": 443, "service": "https"})
    score_finding(f)
    assert f.interest < 0.3


def test_ip_without_ptr_notes_it():
    f = Finding(type=FindingType.IP_ADDRESS, value="1.2.3.4", source="dns", raw={"ptr": None})
    score_finding(f)
    assert "no reverse DNS" in f.note


def test_email_with_gravatar_scores_higher_than_without():
    with_g = Finding(type=FindingType.EMAIL, value="a@example.com", source="gravatar", raw={"gravatar": True})
    without_g = Finding(type=FindingType.EMAIL, value="b@example.com", source="gravatar", raw={"gravatar": False})
    score_finding(with_g)
    score_finding(without_g)
    assert with_g.interest > without_g.interest


def test_email_never_claims_a_gravatar_check_that_never_happened():
    # theHarvester surfaces emails with no Gravatar check performed at all —
    # raw simply has no "gravatar" key. Must not read as "no profile found".
    f = Finding(type=FindingType.EMAIL, value="a@example.com", source="theharvester", raw={})
    score_finding(f)
    assert "gravatar" not in f.note.lower()


def test_open_port_parses_port_from_value_after_raw_is_merge_reshaped():
    # Simulates the state merge_findings() leaves behind when a second
    # source collides on the same key: raw becomes {source: {...}}
    # instead of a flat dict, so a value-based port read needs to survive
    # it (raw.get("port") would silently return None here).
    f = Finding(
        type=FindingType.OPEN_PORT,
        value="1.2.3.4:3306",
        source="portscan, shodan",
        raw={"portscan": {"port": 3306, "service": "mysql"}, "shodan": {"port": 3306, "vulns": []}},
    )
    f.merged_raw = True
    score_finding(f)
    assert f.interest >= 0.75


def test_open_port_with_known_cve_scores_highest_regardless_of_port():
    f = Finding(
        type=FindingType.OPEN_PORT, value="1.2.3.4:8080", source="shodan",
        raw={"port": 8080, "vulns": ["CVE-2021-1234"]},
    )
    score_finding(f)
    assert f.interest == 1.0
    assert "CVE-2021-1234" in f.note


def test_open_port_without_vulns_key_scores_normally():
    f = Finding(
        type=FindingType.OPEN_PORT, value="1.2.3.4:443", source="portscan",
        raw={"port": 443, "service": "https"},
    )
    score_finding(f)
    assert f.interest < 0.3


def test_open_port_vulns_boost_survives_merge_reshape():
    f = Finding(
        type=FindingType.OPEN_PORT,
        value="1.2.3.4:443",
        source="portscan, shodan",
        raw={"portscan": {"port": 443, "service": "https"}, "shodan": {"port": 443, "vulns": ["CVE-2022-9999"]}},
    )
    f.merged_raw = True
    score_finding(f)
    assert f.interest == 1.0
    assert "CVE-2022-9999" in f.note


def test_certificate_days_until_expiry_read_survives_merge_reshape():
    # Same landmine as OPEN_PORT: if a CERTIFICATE finding is ever merged
    # (same key colliding across two sources), raw becomes
    # {source: {...}} and a flat raw.get("days_until_expiry") would
    # silently return None instead of finding it nested under a source.
    f = Finding(
        type=FindingType.CERTIFICATE,
        value="example.com",
        source="tls, other",
        raw={"tls": {"days_until_expiry": 5}, "other": {}},
    )
    f.merged_raw = True
    score_finding(f)
    assert f.interest >= 0.85
    assert "5 day(s)" in f.note


def test_ip_address_ptr_read_survives_merge_reshape():
    # A concrete reachable path: DNS resolving the same IP twice produces
    # two IP_ADDRESS findings from the same source ("dns") that collide
    # and reshape. A flat raw.get("ptr") post-reshape would fabricate "no
    # reverse DNS" for a host that actually has a PTR record.
    f = Finding(
        type=FindingType.IP_ADDRESS,
        value="1.2.3.4",
        source="dns",
        raw={"dns": {"ptr": "host.example.com"}},
    )
    f.merged_raw = True
    score_finding(f)
    assert "no reverse DNS" not in f.note
