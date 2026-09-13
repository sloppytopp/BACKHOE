"""Generic key-wizard tests. KEY_DIR/KEY_FILE are monkeypatched to a temp
path in every test so nothing here ever touches the real
~/.config/backhoe/keys.json."""
import json
import stat
from unittest.mock import MagicMock, patch

from backhoe import keys as keys_module
from backhoe.keys import KeyProvider, KeyValidationError, get_api_key


def _isolate_key_file(tmp_path, monkeypatch):
    key_dir = tmp_path / "backhoe-keys"
    monkeypatch.setattr(keys_module, "KEY_DIR", key_dir)
    monkeypatch.setattr(keys_module, "KEY_FILE", key_dir / "keys.json")


def _provider(validate):
    return KeyProvider(name="testprov", env_var="TESTPROV_API_KEY", prompt_label="Test API key", validate=validate)


def test_env_var_short_circuits_and_never_validates(tmp_path, monkeypatch):
    _isolate_key_file(tmp_path, monkeypatch)
    monkeypatch.setenv("TESTPROV_API_KEY", "from-env")
    validate = MagicMock(side_effect=AssertionError("must not be called"))

    result = get_api_key(_provider(validate))

    assert result == "from-env"
    validate.assert_not_called()


def test_valid_stored_key_used_silently(tmp_path, monkeypatch, capsys):
    _isolate_key_file(tmp_path, monkeypatch)
    monkeypatch.delenv("TESTPROV_API_KEY", raising=False)
    keys_module._write_stored_key("testprov", "stored-key")
    validate = MagicMock(return_value=True)

    result = get_api_key(_provider(validate))

    assert result == "stored-key"
    assert capsys.readouterr().err == ""


def test_invalid_stored_key_triggers_prompt(tmp_path, monkeypatch):
    _isolate_key_file(tmp_path, monkeypatch)
    monkeypatch.delenv("TESTPROV_API_KEY", raising=False)
    keys_module._write_stored_key("testprov", "bad-key")
    validate = MagicMock(side_effect=[False, True])  # stored check fails, fresh entry succeeds

    with patch("backhoe.keys.click.prompt", return_value="new-key"):
        result = get_api_key(_provider(validate))

    assert result == "new-key"
    assert json.loads(keys_module.KEY_FILE.read_text()) == {"testprov": "new-key"}


def test_inconclusive_stored_key_validation_uses_stale_key(tmp_path, monkeypatch, capsys):
    _isolate_key_file(tmp_path, monkeypatch)
    monkeypatch.delenv("TESTPROV_API_KEY", raising=False)
    keys_module._write_stored_key("testprov", "stored-key")
    validate = MagicMock(side_effect=KeyValidationError("network blip"))

    result = get_api_key(_provider(validate))

    assert result == "stored-key"
    assert "network blip" in capsys.readouterr().err


def test_prompt_skip_on_blank_returns_none_and_does_not_write_file(tmp_path, monkeypatch):
    _isolate_key_file(tmp_path, monkeypatch)
    monkeypatch.delenv("TESTPROV_API_KEY", raising=False)
    validate = MagicMock(side_effect=AssertionError("must not be called on blank input"))

    with patch("backhoe.keys.click.prompt", return_value=""):
        result = get_api_key(_provider(validate))

    assert result is None
    assert not keys_module.KEY_FILE.exists()


def test_prompt_success_writes_file_with_restrictive_permissions(tmp_path, monkeypatch):
    _isolate_key_file(tmp_path, monkeypatch)
    monkeypatch.delenv("TESTPROV_API_KEY", raising=False)
    validate = MagicMock(return_value=True)

    with patch("backhoe.keys.click.prompt", return_value="fresh-key"):
        result = get_api_key(_provider(validate))

    assert result == "fresh-key"
    assert json.loads(keys_module.KEY_FILE.read_text()) == {"testprov": "fresh-key"}
    mode = keys_module.KEY_FILE.stat().st_mode
    assert stat.S_IMODE(mode) == stat.S_IRUSR | stat.S_IWUSR


def test_prompt_retries_once_then_gives_up(tmp_path, monkeypatch):
    _isolate_key_file(tmp_path, monkeypatch)
    monkeypatch.delenv("TESTPROV_API_KEY", raising=False)
    validate = MagicMock(return_value=False)

    with patch("backhoe.keys.click.prompt", side_effect=["bad-1", "bad-2"]) as prompt_mock:
        result = get_api_key(_provider(validate))

    assert result is None
    assert prompt_mock.call_count == 2
    assert not keys_module.KEY_FILE.exists()


def test_inconclusive_validation_on_freshly_entered_key_is_saved_anyway(tmp_path, monkeypatch):
    _isolate_key_file(tmp_path, monkeypatch)
    monkeypatch.delenv("TESTPROV_API_KEY", raising=False)
    validate = MagicMock(side_effect=KeyValidationError("provider down"))

    with patch("backhoe.keys.click.prompt", return_value="fresh-key"):
        result = get_api_key(_provider(validate))

    assert result == "fresh-key"
    assert json.loads(keys_module.KEY_FILE.read_text()) == {"testprov": "fresh-key"}
