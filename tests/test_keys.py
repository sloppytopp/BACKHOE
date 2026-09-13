"""Generic key-wizard tests. KEY_DIR/KEY_FILE are monkeypatched to a temp
path in every test so nothing here ever touches the real
~/.config/backhoe/keys.json."""
import json
import os
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


def test_corrupt_key_file_triggers_warning_and_continues(tmp_path, monkeypatch, capsys):
    """Corrupted JSON file should trigger a yellow warning, not silently
    treat it as 'no stored keys'. This enforces 'fail loud' principle."""
    _isolate_key_file(tmp_path, monkeypatch)
    monkeypatch.delenv("TESTPROV_API_KEY", raising=False)
    # Write an invalid JSON file
    keys_module.KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    keys_module.KEY_FILE.write_text("not valid json {{{")
    validate = MagicMock(return_value=True)

    with patch("backhoe.keys.click.prompt", return_value="fresh-key"):
        result = get_api_key(_provider(validate))

    # Should proceed to prompt and save a fresh key
    assert result == "fresh-key"
    # Should have printed a warning about the corrupted file
    err_output = capsys.readouterr().err
    assert "corrupted" in err_output or "cannot be parsed" in err_output


def test_write_key_uses_restrictive_permissions_at_creation_time(tmp_path, monkeypatch):
    """Verify that os.open is called with restrictive mode (0o600) to
    avoid TOCTOU race where API key is briefly world-readable."""
    _isolate_key_file(tmp_path, monkeypatch)
    original_open = os.open
    open_calls = []

    def tracking_open(path, flags, mode=None):
        open_calls.append((path, flags, mode))
        return original_open(path, flags, mode)

    monkeypatch.setattr("os.open", tracking_open)

    keys_module._write_stored_key("testprov", "secret-key")

    # Verify os.open was called with mode 0o600
    key_file_open_calls = [c for c in open_calls if str(c[0]).endswith("keys.json")]
    assert len(key_file_open_calls) > 0
    # The mode should be exactly S_IRUSR | S_IWUSR = 0o600
    path, flags, mode = key_file_open_calls[0]
    assert mode == (stat.S_IRUSR | stat.S_IWUSR)
    # Verify the file was actually created with those permissions
    actual_mode = stat.S_IMODE(keys_module.KEY_FILE.stat().st_mode)
    assert actual_mode == stat.S_IRUSR | stat.S_IWUSR


def test_write_failure_propagates_original_exception_not_bad_file_descriptor(tmp_path, monkeypatch):
    """Verify that when a write fails (e.g., disk full, serialization error),
    the original exception propagates cleanly, not masked by 'Bad file descriptor'
    from trying to close an already-closed fd. Regression test: os.fdopen closes
    the fd automatically via context manager; a manual os.close() in an except
    block would double-close and mask the original error."""
    _isolate_key_file(tmp_path, monkeypatch)

    # Mock json.dumps to raise a custom exception (simulating a write failure)
    with patch("backhoe.keys.json.dumps", side_effect=ValueError("Simulated disk full error")):
        try:
            keys_module._write_stored_key("testprov", "key")
            assert False, "Expected ValueError to be raised"
        except ValueError as exc:
            # Verify we get the ORIGINAL error message, not "Bad file descriptor"
            assert "Simulated disk full error" in str(exc)
        except OSError as exc:
            # If we got here, it means os.close() was called on a closed fd
            # and masked the original exception — this is the regression
            assert False, f"Got OSError (likely from double-close fd): {exc}. Original exception was masked!"
