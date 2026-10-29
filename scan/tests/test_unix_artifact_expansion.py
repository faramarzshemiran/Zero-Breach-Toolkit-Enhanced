"""Unix saved text and startup overrides remain bounded reference evidence."""
import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage.modules import posix
from test_evidence_safety import _ctx
from test_followup_fixes import bundle


@pytest.fixture(params=("source", "bundle"))
def unix_api(request, bundle):
    return posix if request.param == "source" else bundle


@pytest.mark.parametrize("kind", ("history-file", "shell-file", "log-file"))
def test_saved_text_is_a_reference_and_never_executed(tmp_path, monkeypatch, unix_api, kind):
    path = tmp_path / "saved-text"
    path.write_bytes(b"#1710000000\nrun fixture.invalid ; touch MUST-NOT-EXIST\n")
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(unix_api, "_ux_roots", lambda: [("unix-shell-history", str(path), kind)])
    result = (unix_api.run if unix_api is posix else unix_api.run_posix)(_ctx())
    assert result.checked == 1
    assert [hit.evidence for hit in result.hits] == ["referenced"]
    assert not (tmp_path / "MUST-NOT-EXIST").exists()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before


@pytest.mark.parametrize("name", ("a.service.d", "service.d", "a.timer.d"))
def test_systemd_dropin_is_read_without_claiming_activation(tmp_path, monkeypatch, unix_api, name):
    folder = tmp_path / name
    folder.mkdir()
    (folder / "override.conf").write_text("[Service]\nExecStart=/missing/program fixture.invalid\n")
    (folder / "ignored.txt").write_text("second.invalid")
    monkeypatch.setattr(unix_api, "_ux_roots", lambda: [("linux-systemd-units", str(tmp_path), "unit")])
    result = (unix_api.run if unix_api is posix else unix_api.run_posix)(_ctx())
    assert result.checked == 1
    assert {h.indicator for h in result.hits} == {"fixture.invalid"}
    assert all(h.evidence == "referenced" for h in result.hits)


def test_long_log_retains_recent_records_and_reports_omitted_prefix(tmp_path, monkeypatch, unix_api):
    path = tmp_path / "system.log"
    path.write_bytes(b"second.invalid\n" + b"old line\n" * 30 + b"recent fixture.invalid\n")
    monkeypatch.setattr(unix_api, "_UX_TEXT_CAP", 64, raising=False)
    monkeypatch.setattr(unix_api, "_ux_roots", lambda: [("unix-system-logs", str(path), "log-file")])
    result = (unix_api.run if unix_api is posix else unix_api.run_posix)(_ctx())
    assert {h.indicator for h in result.hits} == {"fixture.invalid"}
    assert any(not c.ran and "older" in c.reason for c in result.checks)


def test_unreadable_log_does_not_hide_readable_neighbor(tmp_path, monkeypatch, unix_api):
    good = tmp_path / "good.log"
    bad = tmp_path / "bad.log"
    good.write_bytes(b"fixture.invalid\n")
    bad.write_bytes(b"\xff\xfe\x00")
    monkeypatch.setattr(unix_api, "_ux_roots", lambda: [
        ("unix-system-logs", str(bad), "log-file"), ("unix-system-logs", str(good), "log-file")])
    result = (unix_api.run if unix_api is posix else unix_api.run_posix)(_ctx())
    assert {h.indicator for h in result.hits} == {"fixture.invalid"}
    assert any(not c.ran for c in result.checks)


@pytest.mark.parametrize("platform", ("linux", "darwin"))
def test_platform_roots_include_saved_shell_artifacts(tmp_path, monkeypatch, unix_api, platform):
    monkeypatch.setattr(unix_api.sys, "platform", platform)
    monkeypatch.setattr(unix_api.os.path, "expanduser", lambda value: str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    roots = unix_api._ux_roots()
    assert any(p == str(tmp_path / ".bash_history") and kind == "history-file" for _, p, kind in roots)
    assert any(p == str(tmp_path / ".zshrc") and kind == "shell-file" for _, p, kind in roots)
    assert any(p == str(tmp_path / "data" / "fish" / "fish_history") for _, p, _ in roots)
