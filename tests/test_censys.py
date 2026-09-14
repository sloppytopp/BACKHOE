"""Censys backend tests — network mocked so these run anywhere, including
sandboxes that block outbound traffic. Unlike Shodan, this backend's API
shape WAS verified against Censys's live current documentation during
development (docs.censys.com) — see the plan's "Verification note" for
exactly what was and wasn't confirmed. The `vulns` field's exact shape
(dict keyed by CVE id / list of plain CVE-id strings / list of {"id": ...}
objects) is handled defensively rather than assumed — all three shapes are
exercised below."""
from unittest.mock import MagicMock, patch

import pytest
import requests

from backhoe.backends import censys
from backhoe.backends.censys import CensysAPIError, CensysValidationError
from backhoe.schema import FindingType


def _response(status_code, json_data=None, json_error=None):
    resp = MagicMock(status_code=status_code)
    if json_error is not None:
        resp.json.side_effect = json_error
    else:
        resp.json.return_value = json_data
    return resp


def test_validate_key_true_on_200():
    with patch("backhoe.backends.censys.requests.get", return_value=_response(200)):
        assert censys.validate_key("goodtoken") is True


def test_validate_key_false_on_401():
    with patch("backhoe.backends.censys.requests.get", return_value=_response(401)):
        assert censys.validate_key("badtoken") is False


def test_validate_key_raises_on_network_error():
    with patch("backhoe.backends.censys.requests.get", side_effect=requests.ConnectionError("nope")):
        with pytest.raises(CensysValidationError):
            censys.validate_key("anytoken")


def test_validate_key_raises_on_unexpected_status():
    with patch("backhoe.backends.censys.requests.get", return_value=_response(500)):
        with pytest.raises(CensysValidationError):
            censys.validate_key("anytoken")


def test_validate_key_uses_bearer_auth_header():
    mock_get = MagicMock(return_value=_response(200))
    with patch("backhoe.backends.censys.requests.get", mock_get):
        censys.validate_key("mytoken")
    _, kwargs = mock_get.call_args
    assert kwargs["headers"]["Authorization"] == "Bearer mytoken"
    assert "params" not in kwargs or "key" not in (kwargs.get("params") or {})


def test_lookup_host_returns_empty_list_on_404():
    with patch("backhoe.backends.censys.requests.get", return_value=_response(404)):
        assert censys.lookup_host("1.2.3.4", "token") == []


def test_lookup_host_raises_on_401():
    with patch("backhoe.backends.censys.requests.get", return_value=_response(401)):
        with pytest.raises(CensysAPIError):
            censys.lookup_host("1.2.3.4", "token")


def test_lookup_host_raises_on_network_error():
    with patch("backhoe.backends.censys.requests.get", side_effect=requests.ConnectionError("nope")):
        with pytest.raises(CensysAPIError):
            censys.lookup_host("1.2.3.4", "token")


def test_lookup_host_raises_on_unparseable_json():
    with patch(
        "backhoe.backends.censys.requests.get",
        return_value=_response(200, json_error=ValueError("bad")),
    ):
        with pytest.raises(CensysAPIError):
            censys.lookup_host("1.2.3.4", "token")


def test_lookup_host_sends_bearer_auth_header():
    mock_get = MagicMock(return_value=_response(200, {"result": {"resource": {"services": []}}}))
    with patch("backhoe.backends.censys.requests.get", mock_get):
        censys.lookup_host("1.2.3.4", "mytoken")
    _, kwargs = mock_get.call_args
    assert kwargs["headers"]["Authorization"] == "Bearer mytoken"


def test_lookup_host_parses_multiple_ports():
    payload = {
        "result": {
            "resource": {
                "ip": "1.2.3.4",
                "services": [
                    {
                        "port": 80,
                        "protocol": "HTTP",
                        "software": [{"product": "nginx", "version": "1.18.0"}],
                    },
                    {"port": 22, "protocol": "SSH"},
                ],
            }
        }
    }
    with patch("backhoe.backends.censys.requests.get", return_value=_response(200, payload)):
        findings = censys.lookup_host("1.2.3.4", "token")

    assert {f.value for f in findings} == {"1.2.3.4:80", "1.2.3.4:22"}
    assert all(f.type == FindingType.OPEN_PORT for f in findings)
    assert all(f.source == "censys" for f in findings)
    http_finding = next(f for f in findings if f.value == "1.2.3.4:80")
    assert http_finding.raw["product"] == "nginx"
    assert http_finding.raw["version"] == "1.18.0"
    assert http_finding.raw["service"] == "HTTP"


def test_lookup_host_handles_missing_optional_fields():
    payload = {"result": {"resource": {"services": [{"port": 443}]}}}
    with patch("backhoe.backends.censys.requests.get", return_value=_response(200, payload)):
        findings = censys.lookup_host("1.2.3.4", "token")

    assert len(findings) == 1
    f = findings[0]
    assert f.raw["product"] is None
    assert f.raw["version"] is None
    assert f.raw["vulns"] == []
    assert f.raw["service"] is None


def test_lookup_host_handles_vulns_as_dict():
    payload = {
        "result": {
            "resource": {
                "services": [
                    {"port": 443, "vulns": {"CVE-2021-1234": {}, "CVE-2021-5678": {}}}
                ]
            }
        }
    }
    with patch("backhoe.backends.censys.requests.get", return_value=_response(200, payload)):
        findings = censys.lookup_host("1.2.3.4", "token")
    assert sorted(findings[0].raw["vulns"]) == ["CVE-2021-1234", "CVE-2021-5678"]


def test_lookup_host_handles_vulns_as_list_of_strings():
    payload = {"result": {"resource": {"services": [{"port": 443, "vulns": ["CVE-2021-1234"]}]}}}
    with patch("backhoe.backends.censys.requests.get", return_value=_response(200, payload)):
        findings = censys.lookup_host("1.2.3.4", "token")
    assert findings[0].raw["vulns"] == ["CVE-2021-1234"]


def test_lookup_host_handles_vulns_as_list_of_objects():
    payload = {
        "result": {
            "resource": {
                "services": [
                    {
                        "port": 443,
                        "vulns": [
                            {"id": "CVE-2019-14540", "severity": "CRITICAL", "kev": True},
                            {"id": "CVE-2020-0001", "severity": "HIGH"},
                        ],
                    }
                ]
            }
        }
    }
    with patch("backhoe.backends.censys.requests.get", return_value=_response(200, payload)):
        findings = censys.lookup_host("1.2.3.4", "token")
    assert sorted(findings[0].raw["vulns"]) == ["CVE-2019-14540", "CVE-2020-0001"]


def test_lookup_host_skips_entries_with_no_port():
    payload = {"result": {"resource": {"services": [{"protocol": "HTTP"}]}}}
    with patch("backhoe.backends.censys.requests.get", return_value=_response(200, payload)):
        findings = censys.lookup_host("1.2.3.4", "token")
    assert findings == []


def test_lookup_host_merges_duplicate_entries_on_same_port():
    # Same defensive posture as Shodan's _to_findings: group by port so two
    # service entries for the same port produce exactly ONE Finding, with
    # vulns unioned and a real product value not overwritten by a later
    # entry's None.
    payload = {
        "result": {
            "resource": {
                "services": [
                    {"port": 443, "software": [{"product": "nginx"}], "vulns": ["CVE-2021-1234"]},
                    {"port": 443, "software": [{"product": None}], "vulns": []},
                ]
            }
        }
    }
    with patch("backhoe.backends.censys.requests.get", return_value=_response(200, payload)):
        findings = censys.lookup_host("1.2.3.4", "token")

    port_443_findings = [f for f in findings if f.value == "1.2.3.4:443"]
    assert len(port_443_findings) == 1
    f = port_443_findings[0]
    assert f.raw["vulns"] == ["CVE-2021-1234"]
    assert f.raw["product"] == "nginx"


def test_validate_key_error_never_leaks_raw_key():
    key = "SUPERSECRETTOKEN123"
    err = requests.ConnectionError(
        f"HTTPSConnectionPool(host='api.platform.censys.io', port=443): Max retries exceeded "
        f"with url: /v3/accounts/users/credits (Caused by NewConnectionError(...)) token={key}"
    )
    with patch("backhoe.backends.censys.requests.get", side_effect=err):
        with pytest.raises(CensysValidationError) as excinfo:
            censys.validate_key(key)
    assert key not in str(excinfo.value)


def test_lookup_host_error_never_leaks_raw_key():
    key = "SUPERSECRETTOKEN123"
    err = requests.ConnectionError(
        f"HTTPSConnectionPool(host='api.platform.censys.io', port=443): Max retries exceeded "
        f"with url: /v3/global/asset/host/1.2.3.4 (Caused by NewConnectionError(...)) token={key}"
    )
    with patch("backhoe.backends.censys.requests.get", side_effect=err):
        with pytest.raises(CensysAPIError) as excinfo:
            censys.lookup_host("1.2.3.4", key)
    assert key not in str(excinfo.value)


def test_censys_provider_is_registered_correctly():
    assert censys.CENSYS_PROVIDER.name == "censys"
    assert censys.CENSYS_PROVIDER.env_var == "CENSYS_API_KEY"
    assert censys.CENSYS_PROVIDER.validate is censys.validate_key
