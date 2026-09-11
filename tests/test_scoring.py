from datetime import datetime, timedelta, timezone

from backhoe.schema import Finding, FindingType
from backhoe.scoring import score_finding


def _sub(value, first_seen=None, live=None):
    return Finding(type=FindingType.SUBDOMAIN, value=value, source="crt.sh", first_seen=first_seen, live=live)


def test_boring_old_subdomain_scores_low_interest():
    f = _sub("www.example.com", first_seen=datetime.now(timezone.utc) - timedelta(days=800))
    score_finding(f)
    assert f.interest < 0.5


def test_admin_keyword_flags_high_interest():
    f = _sub("admin.example.com", first_seen=datetime.now(timezone.utc) - timedelta(days=800))
    score_finding(f)
    assert f.interest >= 0.6
    assert "admin" in f.note


def test_recently_issued_cert_flags_interest_even_without_keyword():
    f = _sub("www.example.com", first_seen=datetime.now(timezone.utc) - timedelta(days=2))
    score_finding(f)
    assert f.interest >= 0.6
    assert "recently stood up" in f.note


def test_dead_subdomain_gets_interest_suppressed():
    live_f = _sub("admin.example.com", live=True)
    dead_f = _sub("admin.example.com", live=False)
    score_finding(live_f)
    score_finding(dead_f)
    assert dead_f.interest < live_f.interest
    assert "no longer resolves" in dead_f.note


def test_live_high_interest_subdomain_stays_the_top_finding():
    f = _sub("admin.example.com", first_seen=datetime.now(timezone.utc) - timedelta(days=2), live=True)
    score_finding(f)
    assert f.interest >= 0.75


def test_theharvester_only_subdomain_scores_lower_confidence_than_crtsh():
    # crt.sh confidence reflects a directly-observed, issued certificate.
    # theHarvester's own sources here are passive scraping (search engines,
    # wayback, etc.) — meaningfully less certain on their own.
    crtsh_only = Finding(type=FindingType.SUBDOMAIN, value="a.example.com", source="crt.sh")
    harvester_only = Finding(type=FindingType.SUBDOMAIN, value="b.example.com", source="theharvester")
    score_finding(crtsh_only)
    score_finding(harvester_only)
    assert harvester_only.confidence < crtsh_only.confidence


def test_merged_subdomain_keeps_high_confidence_when_crtsh_is_among_sources():
    merged = Finding(type=FindingType.SUBDOMAIN, value="a.example.com", source="crt.sh, theharvester")
    score_finding(merged)
    assert merged.confidence == 0.9


def test_rescoring_the_same_finding_twice_does_not_duplicate_the_note():
    # No keyword match here on purpose — the keyword branch unconditionally
    # overwrites `note`, which would accidentally mask the duplication this
    # test exists to catch. Only the recency branch (which appends onto
    # whatever `note` already holds) actually duplicates on a second pass.
    f = _sub("www.example.com", first_seen=datetime.now(timezone.utc) - timedelta(days=2))
    score_finding(f)
    score_finding(f)
    assert f.note.count("recently stood up") == 1
