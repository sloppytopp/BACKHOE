from unittest.mock import MagicMock, patch

import pytest
import requests

from backhoe.backends.gravatar import GravatarError, check_gravatar


def test_check_gravatar_true_on_200():
    resp = MagicMock(status_code=200)
    with patch("backhoe.backends.gravatar.requests.get", return_value=resp):
        assert check_gravatar("someone@example.com") is True


def test_check_gravatar_false_on_404():
    resp = MagicMock(status_code=404)
    with patch("backhoe.backends.gravatar.requests.get", return_value=resp):
        assert check_gravatar("someone@example.com") is False


def test_check_gravatar_raises_on_network_error():
    with patch("backhoe.backends.gravatar.requests.get", side_effect=requests.ConnectionError("nope")):
        with pytest.raises(GravatarError):
            check_gravatar("someone@example.com")


def test_check_gravatar_raises_on_unexpected_status():
    resp = MagicMock(status_code=500)
    with patch("backhoe.backends.gravatar.requests.get", return_value=resp):
        with pytest.raises(GravatarError):
            check_gravatar("someone@example.com")
