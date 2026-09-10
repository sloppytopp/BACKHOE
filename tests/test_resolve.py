"""Real DNS lookups against hosts guaranteed to resolve or not, rather than
mocking socket — resolve_many's whole value is real resolution behavior."""
from backhoe.resolve import resolve_many


def test_localhost_resolves_true():
    result = resolve_many(["localhost"])
    assert result["localhost"] is True


def test_bogus_tld_resolves_false():
    result = resolve_many(["this-host-does-not-exist.invalid"])
    assert result["this-host-does-not-exist.invalid"] is False


def test_handles_mixed_batch():
    hosts = ["localhost", "this-host-does-not-exist.invalid"]
    result = resolve_many(hosts)
    assert result["localhost"] is True
    assert result["this-host-does-not-exist.invalid"] is False
    assert set(result.keys()) == set(hosts)
