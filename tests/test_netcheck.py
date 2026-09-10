from unittest.mock import MagicMock, patch

from backhoe.backends.netcheck import tcp_tls_is_intercepted


def test_detects_interception_when_canary_handshake_succeeds():
    cm = MagicMock()
    cm.__enter__.return_value = cm
    cm.__exit__.return_value = False
    with patch("socket.create_connection", return_value=cm), patch(
        "ssl.create_default_context"
    ) as ctx_factory:
        ctx_factory.return_value.wrap_socket.return_value = cm
        assert tcp_tls_is_intercepted() is True


def test_no_interception_when_canary_connection_fails():
    with patch("socket.create_connection", side_effect=OSError("no route to host")):
        assert tcp_tls_is_intercepted() is False
