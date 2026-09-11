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
