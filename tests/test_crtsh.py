"""crt.sh backend tests — network mocked so these run anywhere, including
sandboxes that block crt.sh itself at the network policy level."""
from unittest.mock import patch, MagicMock

import pytest

from backhoe.backends import crtsh
from backhoe.backends.crtsh import CrtShError
from backhoe.schema import FindingType

SAMPLE_RECORDS = [
    {
        "name_value": "www.example.com\nexample.com",
        "not_before": "2026-08-01T00:00:00",
    },
    {
        "name_value": "admin.example.com",
        "not_before": "2020-01-01T00:00:00",
    },
    {
        # SAN list includes a wildcard entry — must be filtered, not crash
        "name_value": "*.example.com",
        "not_before": "2026-08-01T00:00:00",
    },
]


def _mock_response(json_data, status_ok=True):
    resp = MagicMock()
    resp.json.return_value = json_data
    if status_ok:
        resp.raise_for_status.return_value = None
    else:
        resp.raise_for_status.side_effect = Exception("boom")
    return resp


def test_run_parses_and_dedupes_subdomains():
    with patch("backhoe.backends.crtsh.requests.get", return_value=_mock_response(SAMPLE_RECORDS)):
        findings = crtsh.run("example.com")

    values = {f.value for f in findings}
    assert values == {"www.example.com", "example.com", "admin.example.com"}
    assert all(f.type == FindingType.SUBDOMAIN for f in findings)
    # wildcard entries must never appear as a literal finding
    assert not any("*" in f.value for f in findings)


def test_run_raises_on_request_failure_instead_of_faking_a_finding():
    import requests

    with patch("backhoe.backends.crtsh.requests.get", side_effect=requests.ConnectionError("nope")):
        with pytest.raises(CrtShError):
            crtsh.run("example.com")


def test_run_raises_on_unparseable_json():
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.side_effect = ValueError("not json")
    with patch("backhoe.backends.crtsh.requests.get", return_value=resp):
        with pytest.raises(CrtShError):
            crtsh.run("example.com")


def test_run_raises_on_unexpected_response_shape():
    with patch("backhoe.backends.crtsh.requests.get", return_value=_mock_response({"not": "a list"})):
        with pytest.raises(CrtShError):
            crtsh.run("example.com")
