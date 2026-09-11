"""SpiderFoot backend tests — subprocess and environment mocked so these
run anywhere, including sandboxes/CI without a SpiderFoot checkout (a
separate external tool, not a pip dependency, and with no PATH-installable
command of its own) available."""
import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from backhoe.backends import spiderfoot
from backhoe.backends.spiderfoot import SpiderFootError, SpiderFootNotInstalled
from backhoe.schema import FindingType


def test_run_raises_not_installed_when_no_checkout_found():
    with patch.dict("os.environ", {}, clear=True), patch(
        "backhoe.backends.spiderfoot.shutil.which", return_value=None
    ):
        with pytest.raises(SpiderFootNotInstalled):
            spiderfoot.run("example.com")


def test_run_uses_spiderfoot_home_env_var_when_sf_py_exists_there(tmp_path):
    sf_py = tmp_path / "sf.py"
    sf_py.write_text("# stub")

    with patch.dict("os.environ", {"SPIDERFOOT_HOME": str(tmp_path)}, clear=True), patch(
        "backhoe.backends.spiderfoot.subprocess.run",
        return_value=MagicMock(returncode=0, stdout="[]", stderr=""),
    ) as run_mock:
        spiderfoot.run("example.com")

    called_cmd = run_mock.call_args[0][0]
    assert str(sf_py) in called_cmd


def test_run_ignores_spiderfoot_home_when_sf_py_missing_there(tmp_path):
    # SPIDERFOOT_HOME is set but doesn't actually contain sf.py — must fall
    # back to the PATH check, not silently point at a nonexistent file.
    with patch.dict("os.environ", {"SPIDERFOOT_HOME": str(tmp_path)}, clear=True), patch(
        "backhoe.backends.spiderfoot.shutil.which", return_value=None
    ):
        with pytest.raises(SpiderFootNotInstalled):
            spiderfoot.run("example.com")


def test_run_raises_on_nonzero_exit():
    with patch.dict("os.environ", {"SPIDERFOOT_HOME": "/opt/spiderfoot"}, clear=True), patch(
        "backhoe.backends.spiderfoot.Path.is_file", return_value=True
    ), patch(
        "backhoe.backends.spiderfoot.subprocess.run",
        return_value=MagicMock(returncode=1, stdout="", stderr="boom"),
    ):
        with pytest.raises(SpiderFootError):
            spiderfoot.run("example.com")


def test_run_raises_on_timeout():
    with patch.dict("os.environ", {"SPIDERFOOT_HOME": "/opt/spiderfoot"}, clear=True), patch(
        "backhoe.backends.spiderfoot.Path.is_file", return_value=True
    ), patch(
        "backhoe.backends.spiderfoot.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="sf.py", timeout=180),
    ):
        with pytest.raises(SpiderFootError):
            spiderfoot.run("example.com")


def test_run_raises_on_unparseable_json():
    with patch.dict("os.environ", {"SPIDERFOOT_HOME": "/opt/spiderfoot"}, clear=True), patch(
        "backhoe.backends.spiderfoot.Path.is_file", return_value=True
    ), patch(
        "backhoe.backends.spiderfoot.subprocess.run",
        return_value=MagicMock(returncode=0, stdout="not json", stderr=""),
    ):
        with pytest.raises(SpiderFootError):
            spiderfoot.run("example.com")


def test_run_maps_exact_internet_name_and_email_address_types():
    events = [
        {"type": "Internet Name", "data": "www.example.com", "module": "sfp_dnsresolve", "source": "example.com"},
        {"type": "Email Address", "data": "admin@example.com", "module": "sfp_pgp", "source": "example.com"},
        # Must NOT be mapped as a subdomain — a different, real event type.
        {"type": "Affiliate - Internet Name", "data": "hera.ns.cloudflare.com", "module": "sfp_dnsraw", "source": "example.com"},
        # Must NOT be mapped at all — an event type with no Finding mapping.
        {"type": "Raw DNS Records", "data": "example.com. 215 IN MX 0 .", "module": "sfp_dnsraw", "source": "example.com"},
    ]

    with patch.dict("os.environ", {"SPIDERFOOT_HOME": "/opt/spiderfoot"}, clear=True), patch(
        "backhoe.backends.spiderfoot.Path.is_file", return_value=True
    ), patch(
        "backhoe.backends.spiderfoot.subprocess.run",
        return_value=MagicMock(returncode=0, stdout=json.dumps(events), stderr=""),
    ):
        findings = spiderfoot.run("example.com")

    subdomains = {f.value for f in findings if f.type == FindingType.SUBDOMAIN}
    emails = {f.value for f in findings if f.type == FindingType.EMAIL}

    assert subdomains == {"www.example.com"}
    assert emails == {"admin@example.com"}
    assert "hera.ns.cloudflare.com" not in subdomains
    assert len(findings) == 2
    assert all(f.source == "spiderfoot" for f in findings)


def test_run_never_fakes_a_finding_on_failure():
    with patch.dict("os.environ", {"SPIDERFOOT_HOME": "/opt/spiderfoot"}, clear=True), patch(
        "backhoe.backends.spiderfoot.Path.is_file", return_value=True
    ), patch(
        "backhoe.backends.spiderfoot.subprocess.run",
        return_value=MagicMock(returncode=1, stdout="", stderr="network unreachable"),
    ):
        with pytest.raises(SpiderFootError):
            spiderfoot.run("example.com")
