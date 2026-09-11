"""theHarvester backend tests — subprocess and filesystem mocked so these
run anywhere, including sandboxes/CI without theHarvester (a separate
external tool, not a pip dependency) installed."""
import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from backhoe.backends import theharvester
from backhoe.backends.theharvester import TheHarvesterError, TheHarvesterNotInstalled
from backhoe.schema import FindingType


def test_run_raises_not_installed_when_binary_missing():
    with patch("backhoe.backends.theharvester.shutil.which", return_value=None):
        with pytest.raises(TheHarvesterNotInstalled):
            theharvester.run("example.com")


def test_run_raises_on_nonzero_exit():
    with patch("backhoe.backends.theharvester.shutil.which", return_value="/usr/bin/theHarvester"), patch(
        "backhoe.backends.theharvester.subprocess.run",
        return_value=MagicMock(returncode=1, stdout="", stderr="boom"),
    ):
        with pytest.raises(TheHarvesterError):
            theharvester.run("example.com")


def test_run_raises_on_timeout():
    with patch("backhoe.backends.theharvester.shutil.which", return_value="/usr/bin/theHarvester"), patch(
        "backhoe.backends.theharvester.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="theHarvester", timeout=180),
    ):
        with pytest.raises(TheHarvesterError):
            theharvester.run("example.com")


def test_run_raises_when_no_json_file_produced():
    with patch("backhoe.backends.theharvester.shutil.which", return_value="/usr/bin/theHarvester"), patch(
        "backhoe.backends.theharvester.subprocess.run",
        return_value=MagicMock(returncode=0, stdout="", stderr=""),
    ):
        # subprocess "succeeds" but never actually wrote <base>.json
        with pytest.raises(TheHarvesterError):
            theharvester.run("example.com")


def test_run_raises_on_unparseable_json(tmp_path):
    def fake_run(cmd, **kwargs):
        out_base = cmd[cmd.index("-f") + 1]
        Path(out_base + ".json").write_text("not json")
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("backhoe.backends.theharvester.shutil.which", return_value="/usr/bin/theHarvester"), patch(
        "backhoe.backends.theharvester.subprocess.run", side_effect=fake_run
    ):
        with pytest.raises(TheHarvesterError):
            theharvester.run("example.com")


def test_run_maps_hosts_and_emails_into_findings():
    def fake_run(cmd, **kwargs):
        out_base = cmd[cmd.index("-f") + 1]
        payload = {
            "hosts": ["www.example.com", "mail.example.com:1.2.3.4"],
            "emails": ["admin@example.com"],
        }
        Path(out_base + ".json").write_text(json.dumps(payload))
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("backhoe.backends.theharvester.shutil.which", return_value="/usr/bin/theHarvester"), patch(
        "backhoe.backends.theharvester.subprocess.run", side_effect=fake_run
    ):
        findings = theharvester.run("example.com")

    subdomains = {f.value for f in findings if f.type == FindingType.SUBDOMAIN}
    emails = {f.value for f in findings if f.type == FindingType.EMAIL}

    assert subdomains == {"www.example.com", "mail.example.com"}
    assert emails == {"admin@example.com"}
    assert all(f.source == "theharvester" for f in findings)


def test_run_never_maps_ips_field_to_findings():
    # Deliberate: mapping theHarvester's `ips` here without also doing the
    # PTR lookup IP_ADDRESS scoring assumes would violate "fail loud, never
    # fake" (see module docstring). This pins that as an enforced contract,
    # not just a comment someone could silently break later.
    def fake_run(cmd, **kwargs):
        out_base = cmd[cmd.index("-f") + 1]
        payload = {
            "hosts": ["www.example.com"],
            "emails": ["admin@example.com"],
            "ips": ["1.2.3.4"],
        }
        Path(out_base + ".json").write_text(json.dumps(payload))
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("backhoe.backends.theharvester.shutil.which", return_value="/usr/bin/theHarvester"), patch(
        "backhoe.backends.theharvester.subprocess.run", side_effect=fake_run
    ):
        findings = theharvester.run("example.com")

    assert not any(f.type == FindingType.IP_ADDRESS for f in findings)
    assert not any(f.value == "1.2.3.4" for f in findings)


def test_run_never_fakes_a_finding_on_failure():
    with patch("backhoe.backends.theharvester.shutil.which", return_value="/usr/bin/theHarvester"), patch(
        "backhoe.backends.theharvester.subprocess.run",
        return_value=MagicMock(returncode=1, stdout="", stderr="network unreachable"),
    ):
        with pytest.raises(TheHarvesterError):
            theharvester.run("example.com")
