"""HIBP backend tests — network mocked so these run anywhere, including
sandboxes that block outbound traffic. No live HIBP API key was available
during development (HIBP's API has required a paid subscription since
2019) — see the design spec's "Verification honesty note". validate_key()
is a pure format check with no network call at all (HIBP has no free
validation endpoint, unlike Shodan/Censys), confirmed by the "never calls
requests.get" tests below."""
from unittest.mock import MagicMock, patch

import pytest
import requests

from backhoe.backends import hibp
from backhoe.backends.hibp import HIBPAPIError
from backhoe.schema import FindingType


def _response(status_code, json_data=None, json_error=None, headers=None):
    resp = MagicMock(status_code=status_code, headers=headers or {})
    if json_error is not None:
        resp.json.side_effect = json_error
    else:
        resp.json.return_value = json_data
    return resp


def test_validate_key_true_on_valid_format():
    assert hibp.validate_key("a" * 32) is True


def test_validate_key_true_on_valid_format_uppercase():
    assert hibp.validate_key("A" * 32) is True


def test_validate_key_false_on_wrong_length():
    assert hibp.validate_key("a" * 31) is False
    assert hibp.validate_key("a" * 33) is False


def test_validate_key_false_on_non_hex_chars():
    assert hibp.validate_key("g" * 32) is False


def test_validate_key_never_makes_a_network_call():
    with patch("backhoe.backends.hibp.requests.get") as mock_get:
        hibp.validate_key("a" * 32)
    mock_get.assert_not_called()


def test_check_breaches_returns_empty_list_on_404():
    with patch("backhoe.backends.hibp.requests.get", return_value=_response(404)):
        assert hibp.check_breaches("user@example.com", "a" * 32) == []


def test_check_breaches_raises_on_401():
    with patch("backhoe.backends.hibp.requests.get", return_value=_response(401)):
        with pytest.raises(HIBPAPIError):
            hibp.check_breaches("user@example.com", "a" * 32)


def test_check_breaches_raises_on_403():
    with patch("backhoe.backends.hibp.requests.get", return_value=_response(403)):
        with pytest.raises(HIBPAPIError):
            hibp.check_breaches("user@example.com", "a" * 32)


def test_check_breaches_raises_on_429_includes_retry_after():
    with patch(
        "backhoe.backends.hibp.requests.get",
        return_value=_response(429, headers={"Retry-After": "5"}),
    ):
        with pytest.raises(HIBPAPIError) as excinfo:
            hibp.check_breaches("user@example.com", "a" * 32)
    assert "5" in str(excinfo.value)


def test_check_breaches_raises_on_429_without_retry_after_header():
    with patch("backhoe.backends.hibp.requests.get", return_value=_response(429)):
        with pytest.raises(HIBPAPIError):
            hibp.check_breaches("user@example.com", "a" * 32)


def test_check_breaches_raises_on_network_error():
    with patch("backhoe.backends.hibp.requests.get", side_effect=requests.ConnectionError("nope")):
        with pytest.raises(HIBPAPIError):
            hibp.check_breaches("user@example.com", "a" * 32)


def test_check_breaches_raises_on_unparseable_json():
    with patch(
        "backhoe.backends.hibp.requests.get",
        return_value=_response(200, json_error=ValueError("bad")),
    ):
        with pytest.raises(HIBPAPIError):
            hibp.check_breaches("user@example.com", "a" * 32)


def test_check_breaches_raises_on_non_list_response():
    with patch("backhoe.backends.hibp.requests.get", return_value=_response(200, {"unexpected": "shape"})):
        with pytest.raises(HIBPAPIError):
            hibp.check_breaches("user@example.com", "a" * 32)


def test_check_breaches_sends_required_headers_and_query_param():
    mock_get = MagicMock(return_value=_response(200, []))
    with patch("backhoe.backends.hibp.requests.get", mock_get):
        hibp.check_breaches("user@example.com", "mykey")
    _, kwargs = mock_get.call_args
    assert kwargs["headers"]["hibp-api-key"] == "mykey"
    assert kwargs["headers"]["User-Agent"]
    assert kwargs["params"]["truncateResponse"] == "false"


def test_check_breaches_url_encodes_the_email():
    mock_get = MagicMock(return_value=_response(200, []))
    with patch("backhoe.backends.hibp.requests.get", mock_get):
        hibp.check_breaches("user+tag@example.com", "mykey")
    args, _ = mock_get.call_args
    assert "user%2Btag%40example.com" in args[0]


def test_check_breaches_parses_multiple_breaches():
    payload = [
        {
            "Name": "Adobe", "Title": "Adobe", "Domain": "adobe.com",
            "BreachDate": "2013-10-04", "PwnCount": 152445165,
            "DataClasses": ["Email addresses", "Passwords"],
            "IsVerified": True, "IsFabricated": False,
            "IsSensitive": False, "IsRetired": False, "IsSpamList": False,
        },
        {
            "Name": "Gawker", "Title": "Gawker", "Domain": "gawker.com",
            "BreachDate": "2010-12-11", "PwnCount": 1247394,
            "DataClasses": ["Email addresses", "Passwords", "Usernames"],
            "IsVerified": True, "IsFabricated": False,
            "IsSensitive": False, "IsRetired": False, "IsSpamList": False,
        },
    ]
    with patch("backhoe.backends.hibp.requests.get", return_value=_response(200, payload)):
        findings = hibp.check_breaches("user@example.com", "a" * 32)

    assert {f.value for f in findings} == {"Adobe", "Gawker"}
    assert all(f.type == FindingType.BREACH_HIT for f in findings)
    assert all(f.source == "hibp" for f in findings)
    adobe = next(f for f in findings if f.value == "Adobe")
    assert adobe.raw["domain"] == "adobe.com"
    assert adobe.raw["breach_date"] == "2013-10-04"
    assert adobe.raw["data_classes"] == ["Email addresses", "Passwords"]
    assert adobe.raw["is_verified"] is True


def test_check_breaches_handles_missing_optional_fields():
    payload = [{"Title": "Mystery Breach"}]
    with patch("backhoe.backends.hibp.requests.get", return_value=_response(200, payload)):
        findings = hibp.check_breaches("user@example.com", "a" * 32)

    assert len(findings) == 1
    f = findings[0]
    assert f.value == "Mystery Breach"
    assert f.raw["data_classes"] == []
    assert f.raw["domain"] is None
    assert f.raw["is_verified"] is None


def test_check_breaches_skips_entries_with_no_title():
    payload = [{"Name": "no-title-entry"}]
    with patch("backhoe.backends.hibp.requests.get", return_value=_response(200, payload)):
        findings = hibp.check_breaches("user@example.com", "a" * 32)
    assert findings == []


def test_check_breaches_error_never_leaks_raw_key():
    key = "SUPERSECRETKEY1234567890ABCDEF0"
    err = requests.ConnectionError(
        f"HTTPSConnectionPool(host='haveibeenpwned.com', port=443): Max retries exceeded "
        f"with url: /api/v3/breachedaccount/user@example.com (Caused by NewConnectionError(...)) key={key}"
    )
    with patch("backhoe.backends.hibp.requests.get", side_effect=err):
        with pytest.raises(HIBPAPIError) as excinfo:
            hibp.check_breaches("user@example.com", key)
    assert key not in str(excinfo.value)


def test_hibp_provider_is_registered_correctly():
    assert hibp.HIBP_PROVIDER.name == "hibp"
    assert hibp.HIBP_PROVIDER.env_var == "HIBP_API_KEY"
    assert hibp.HIBP_PROVIDER.validate is hibp.validate_key
