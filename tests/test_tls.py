import ssl
from unittest.mock import MagicMock, patch

import pytest

from backhoe.backends.tls import TlsError, get_certificate_info

SAMPLE_CERT = {
    "subject": ((("commonName", "example.com"),),),
    "issuer": ((("organizationName", "Let's Encrypt"), ("commonName", "R3")),),
    "notBefore": "Jan  1 00:00:00 2026 GMT",
    "notAfter": "Apr  1 00:00:00 2026 GMT",
    "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
}


def _mock_cm(inner=None):
    """A MagicMock usable as a context manager whose __exit__ never swallows
    exceptions — the default MagicMock.__exit__ returns a truthy mock, which
    would silently suppress the errors these tests check for."""
    cm = MagicMock()
    cm.__enter__.return_value = inner if inner is not None else cm
    cm.__exit__.return_value = False
    return cm


def _mock_ssl_socket(cert):
    ssock = _mock_cm()
    ssock.getpeercert.return_value = cert
    return ssock


def test_get_certificate_info_parses_fields():
    fake_ctx = MagicMock()
    fake_ctx.wrap_socket.return_value = _mock_ssl_socket(SAMPLE_CERT)

    with patch("ssl.create_default_context", return_value=fake_ctx), patch(
        "socket.create_connection", return_value=_mock_cm()
    ):
        info = get_certificate_info("example.com")

    assert info["issuer"]["organizationName"] == "Let's Encrypt"
    assert info["san"] == ["example.com", "www.example.com"]
    assert info["not_after"].year == 2026
    assert info["days_until_expiry"] is not None


def test_get_certificate_info_raises_on_connection_failure():
    with patch("socket.create_connection", side_effect=OSError("refused")):
        with pytest.raises(TlsError):
            get_certificate_info("example.com")


def test_get_certificate_info_raises_on_handshake_failure():
    fake_ctx = MagicMock()
    fake_ctx.wrap_socket.side_effect = ssl.SSLError("handshake failed")

    with patch("ssl.create_default_context", return_value=fake_ctx), patch(
        "socket.create_connection", return_value=_mock_cm()
    ):
        with pytest.raises(TlsError):
            get_certificate_info("example.com")
