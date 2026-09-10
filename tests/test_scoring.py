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
