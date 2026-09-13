"""Shodan backend tests — network mocked so these run anywhere, including
sandboxes that block outbound traffic. No live Shodan key or live network
access was available during development (see the design spec's honesty
note): the vulns field's exact shape (list of CVE strings vs. a dict keyed
by CVE ID) is handled defensively rather than assumed from an unverified
guess — both shapes are exercised below."""
from unittest.mock import MagicMock, patch

import pytest
import requests

from backhoe.backends import shodan
from backhoe.backends.shodan import ShodanAPIError, ShodanValidationError
from backhoe.schema import FindingType


def _response(status_code, json_data=None, json_error=None):
    resp = MagicMock(status_code=status_code)
    if json_error is not None:
        resp.json.side_effect = json_error
    else:
        resp.json.return_value = json_data
    return resp


def test_validate_key_true_on_200():
    with patch("backhoe.backends.shodan.requests.get", return_value=_response(200)):
        assert shodan.validate_key("goodkey") is True


def test_validate_key_false_on_401():
    with patch("backhoe.backends.shodan.requests.get", return_value=_response(401)):
        assert shodan.validate_key("badkey") is False


def test_validate_key_raises_on_network_error():
    with patch("backhoe.backends.shodan.requests.get", side_effect=requests.ConnectionError("nope")):
        with pytest.raises(ShodanValidationError):
            shodan.validate_key("anykey")


def test_validate_key_raises_on_unexpected_status():
    with patch("backhoe.backends.shodan.requests.get", return_value=_response(500)):
        with pytest.raises(ShodanValidationError):
            shodan.validate_key("anykey")


def test_lookup_host_returns_empty_list_on_404():
    with patch("backhoe.backends.shodan.requests.get", return_value=_response(404)):
        assert shodan.lookup_host("1.2.3.4", "key") == []


def test_lookup_host_raises_on_401():
    with patch("backhoe.backends.shodan.requests.get", return_value=_response(401)):
        with pytest.raises(ShodanAPIError):
            shodan.lookup_host("1.2.3.4", "key")


def test_lookup_host_raises_on_network_error():
    with patch("backhoe.backends.shodan.requests.get", side_effect=requests.ConnectionError("nope")):
        with pytest.raises(ShodanAPIError):
            shodan.lookup_host("1.2.3.4", "key")


def test_lookup_host_raises_on_unparseable_json():
    with patch(
        "backhoe.backends.shodan.requests.get",
        return_value=_response(200, json_error=ValueError("bad")),
    ):
        with pytest.raises(ShodanAPIError):
            shodan.lookup_host("1.2.3.4", "key")


def test_lookup_host_parses_multiple_ports():
    payload = {
        "data": [
            {"port": 80, "_shodan": {"module": "http"}, "product": "nginx", "version": "1.18.0"},
            {"port": 22, "_shodan": {"module": "ssh"}},
        ]
    }
    with patch("backhoe.backends.shodan.requests.get", return_value=_response(200, payload)):
        findings = shodan.lookup_host("1.2.3.4", "key")

    assert {f.value for f in findings} == {"1.2.3.4:80", "1.2.3.4:22"}
    assert all(f.type == FindingType.OPEN_PORT for f in findings)
    assert all(f.source == "shodan" for f in findings)
    http_finding = next(f for f in findings if f.value == "1.2.3.4:80")
    assert http_finding.raw["product"] == "nginx"
    assert http_finding.raw["version"] == "1.18.0"
    assert http_finding.raw["service"] == "http"


def test_lookup_host_handles_missing_optional_fields():
    payload = {"data": [{"port": 443}]}
    with patch("backhoe.backends.shodan.requests.get", return_value=_response(200, payload)):
        findings = shodan.lookup_host("1.2.3.4", "key")

    assert len(findings) == 1
    f = findings[0]
    assert f.raw["product"] is None
    assert f.raw["version"] is None
    assert f.raw["vulns"] == []
    assert f.raw["service"] is None


def test_lookup_host_handles_vulns_as_dict():
    payload = {"data": [{"port": 443, "vulns": {"CVE-2021-1234": {}, "CVE-2021-5678": {}}}]}
    with patch("backhoe.backends.shodan.requests.get", return_value=_response(200, payload)):
        findings = shodan.lookup_host("1.2.3.4", "key")
    assert sorted(findings[0].raw["vulns"]) == ["CVE-2021-1234", "CVE-2021-5678"]


def test_lookup_host_handles_vulns_as_list():
    payload = {"data": [{"port": 443, "vulns": ["CVE-2021-1234"]}]}
    with patch("backhoe.backends.shodan.requests.get", return_value=_response(200, payload)):
        findings = shodan.lookup_host("1.2.3.4", "key")
    assert findings[0].raw["vulns"] == ["CVE-2021-1234"]


def test_lookup_host_skips_entries_with_no_port():
    payload = {"data": [{"product": "mystery"}]}
    with patch("backhoe.backends.shodan.requests.get", return_value=_response(200, payload)):
        findings = shodan.lookup_host("1.2.3.4", "key")
    assert findings == []


def test_validate_key_error_never_leaks_raw_key():
    # requests' own ConnectionError message embeds the full request URL,
    # key querystring included — the wrapping ShodanValidationError must
    # never repeat that key, or it leaks into anything a caller prints
    # (click.secho, terminal scrollback).
    key = "SUPERSECRET123"
    err = requests.ConnectionError(
        f"HTTPSConnectionPool(host='api.shodan.io', port=443): Max retries exceeded with "
        f"url: /api-info?key={key} (Caused by NewConnectionError(...))"
    )
    with patch("backhoe.backends.shodan.requests.get", side_effect=err):
        with pytest.raises(ShodanValidationError) as excinfo:
            shodan.validate_key(key)
    assert key not in str(excinfo.value)


def test_lookup_host_error_never_leaks_raw_key():
    key = "SUPERSECRET123"
    err = requests.ConnectionError(
        f"HTTPSConnectionPool(host='api.shodan.io', port=443): Max retries exceeded with "
        f"url: /shodan/host/1.2.3.4?key={key} (Caused by NewConnectionError(...))"
    )
    with patch("backhoe.backends.shodan.requests.get", side_effect=err):
        with pytest.raises(ShodanAPIError) as excinfo:
            shodan.lookup_host("1.2.3.4", key)
    assert key not in str(excinfo.value)


def test_lookup_host_merges_duplicate_entries_on_same_port():
    # Shodan can return multiple data[] entries for the same port (different
    # banners/modules on it). Two entries on the same port must produce
    # exactly ONE Finding, with vulns unioned and a real product value not
    # overwritten by a later entry's None.
    payload = {
        "data": [
            {"port": 443, "product": "nginx", "vulns": ["CVE-2021-1234"]},
            {"port": 443, "product": None, "vulns": []},
        ]
    }
    with patch("backhoe.backends.shodan.requests.get", return_value=_response(200, payload)):
        findings = shodan.lookup_host("1.2.3.4", "key")

    port_443_findings = [f for f in findings if f.value == "1.2.3.4:443"]
    assert len(port_443_findings) == 1
    f = port_443_findings[0]
    assert f.raw["vulns"] == ["CVE-2021-1234"]
    assert f.raw["product"] == "nginx"


def test_shodan_provider_is_registered_correctly():
    assert shodan.SHODAN_PROVIDER.name == "shodan"
    assert shodan.SHODAN_PROVIDER.env_var == "SHODAN_API_KEY"
    assert shodan.SHODAN_PROVIDER.validate is shodan.validate_key
