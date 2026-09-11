from backhoe.schema import Finding, FindingType, merge_findings


def test_merge_findings_combines_sources_for_same_key():
    a = Finding(type=FindingType.SUBDOMAIN, value="www.example.com", source="crt.sh")
    b = Finding(type=FindingType.SUBDOMAIN, value="www.example.com", source="theharvester")

    merged = merge_findings([a, b])

    assert len(merged) == 1
    assert merged[0].source == "crt.sh, theharvester"


def test_merge_findings_passes_through_unique_findings_unchanged():
    a = Finding(type=FindingType.SUBDOMAIN, value="www.example.com", source="crt.sh")
    b = Finding(type=FindingType.SUBDOMAIN, value="mail.example.com", source="theharvester")

    merged = merge_findings([a, b])

    assert len(merged) == 2


def test_key_disambiguates_dns_records_by_record_type():
    # person-check produces three DNS_RECORD findings for the same domain
    # (mx/spf/dmarc) — they must never collide on type+value alone.
    mx = Finding(type=FindingType.DNS_RECORD, value="example.com", source="dns", raw={"record_type": "mx"})
    spf = Finding(type=FindingType.DNS_RECORD, value="example.com", source="dns", raw={"record_type": "spf"})
    assert mx.key() != spf.key()


def test_merge_findings_keeps_flat_raw_when_no_duplicate_exists():
    a = Finding(type=FindingType.SUBDOMAIN, value="www.example.com", source="theharvester", raw={"raw_entry": "www.example.com"})
    merged = merge_findings([a])
    assert merged[0].raw == {"raw_entry": "www.example.com"}


def test_merge_findings_namespaces_raw_by_source_on_actual_merge():
    a = Finding(type=FindingType.SUBDOMAIN, value="www.example.com", source="crt.sh", raw={"cert_age_days": 3})
    b = Finding(type=FindingType.SUBDOMAIN, value="www.example.com", source="theharvester", raw={"raw_entry": "www.example.com"})

    merged = merge_findings([a, b])

    assert len(merged) == 1
    assert merged[0].raw == {
        "crt.sh": {"cert_age_days": 3},
        "theharvester": {"raw_entry": "www.example.com"},
    }


def test_merge_findings_fills_in_first_seen_from_a_later_duplicate():
    from datetime import datetime

    a = Finding(type=FindingType.SUBDOMAIN, value="www.example.com", source="theharvester")
    b = Finding(
        type=FindingType.SUBDOMAIN,
        value="www.example.com",
        source="crt.sh",
        first_seen=datetime(2026, 1, 1),
    )

    merged = merge_findings([a, b])

    assert len(merged) == 1
    assert merged[0].first_seen == datetime(2026, 1, 1)


def test_merge_findings_fills_in_note_from_a_later_duplicate():
    a = Finding(type=FindingType.SUBDOMAIN, value="www.example.com", source="theharvester", note="")
    b = Finding(type=FindingType.SUBDOMAIN, value="www.example.com", source="crt.sh", note="cert issued 3d ago")

    merged = merge_findings([a, b])

    assert len(merged) == 1
    assert merged[0].note == "cert issued 3d ago"
