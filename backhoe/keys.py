"""
Generic API-key resolution for backends that need one — Shodan today,
Censys/HIBP later. One shared flow so a new keyed backend is "register a
provider + a validate function", not "write a new wizard".

Resolution order for get_api_key(provider):
  1. provider.env_var set -> used directly, no file I/O, no validation,
     no prompt. This is the escape hatch for CI/scripted runs.
  2. A key stored in ~/.config/backhoe/keys.json for provider.name ->
     live-validated via provider.validate() on every call:
       - confirmed valid -> used silently
       - confirmed invalid (validate() returns False) -> warn, re-prompt
       - inconclusive (validate() raises KeyValidationError, e.g. a
         network blip or provider outage) -> warn once, use the stale
         key anyway. A provider being briefly unreachable is not the
         same as the key being wrong, and forcing a re-prompt over that
         would be actively wrong.
  3. No usable key from 1-2 -> interactive prompt (hidden input). Blank
     input skips (returns None — the caller just doesn't run that
     backend this time, same tier as any other opt-in source being
     unavailable). A non-blank entry is validated before saving; one
     retry is allowed on a confirmed-bad entry before giving up.

get_api_key() returning None is a normal outcome, not an error.
"""
from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import click

KEY_DIR = Path.home() / ".config" / "backhoe"
KEY_FILE = KEY_DIR / "keys.json"


class KeyValidationError(Exception):
    """A provider's validate() couldn't reach a conclusive answer (network
    error, provider outage, unexpected response) — NOT the same as the key
    being confirmed wrong. Callers must not treat this as "reprompt"."""


@dataclass(frozen=True)
class KeyProvider:
    name: str
    env_var: str
    prompt_label: str
    validate: Callable[[str], bool]


def _read_stored_keys() -> dict:
    if not KEY_FILE.exists():
        return {}
    try:
        return json.loads(KEY_FILE.read_text())
    except ValueError:
        click.secho(
            f"Stored key file {KEY_FILE} is corrupted and cannot be parsed — ignoring.",
            fg="yellow",
            err=True,
        )
        return {}


def _write_stored_key(name: str, key: str) -> None:
    # Use restrictive umask at creation time to avoid TOCTOU race where
    # the plaintext API key is briefly readable by other local users.
    old_umask = os.umask(0o077)
    try:
        KEY_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(KEY_DIR, stat.S_IRWXU)
        stored = _read_stored_keys()
        stored[name] = key
        # Use os.open with restrictive mode to ensure the file is created
        # with 0o600 permissions from the start, not world-readable then
        # chmod'd down retroactively.
        fd = os.open(
            KEY_FILE,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            stat.S_IRUSR | stat.S_IWUSR,
        )
        try:
            with os.fdopen(fd, "w") as f:
                f.write(json.dumps(stored))
        except:
            os.close(fd)
            raise
    finally:
        os.umask(old_umask)


def _prompt_for_key(provider: KeyProvider) -> str | None:
    for _attempt in range(2):
        entered = click.prompt(
            f"{provider.prompt_label} (leave blank to skip)",
            default="",
            show_default=False,
            hide_input=True,
        )
        if not entered:
            return None
        try:
            if provider.validate(entered):
                _write_stored_key(provider.name, entered)
                return entered
        except KeyValidationError as exc:
            click.secho(
                f"Couldn't confirm the {provider.prompt_label} you entered is valid "
                f"({exc}) — saving it anyway.",
                fg="yellow",
                err=True,
            )
            _write_stored_key(provider.name, entered)
            return entered
        click.secho(f"That {provider.prompt_label} was rejected.", fg="yellow", err=True)
    return None


def get_api_key(provider: KeyProvider) -> str | None:
    env_value = os.environ.get(provider.env_var)
    if env_value:
        return env_value

    stored = _read_stored_keys().get(provider.name)
    if stored:
        try:
            if provider.validate(stored):
                return stored
            click.secho(
                f"Stored {provider.prompt_label} was rejected — please re-enter it.",
                fg="yellow",
                err=True,
            )
        except KeyValidationError as exc:
            click.secho(
                f"Couldn't confirm the stored {provider.prompt_label} is still valid "
                f"({exc}) — using it anyway.",
                fg="yellow",
                err=True,
            )
            return stored

    return _prompt_for_key(provider)
