"""Startup links are never followed: masked units, aliases of inspected files and
links between standard locations are not gaps, other links are named gaps, and
unreadable files say why."""
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


def _run(api):
    return (api.run if api is posix else api.run_posix)(_ctx())


def _links(monkeypatch, api, mapping):
    table = {os.path.normpath(str(k)): os.path.normpath(str(v)) if v != os.devnull else v
             for k, v in mapping.items()}
    monkeypatch.setattr(api, "_ux_link_target", lambda path: table.get(os.path.normpath(path)))


def test_alias_in_the_same_folder_is_read_once_without_a_gap(tmp_path, monkeypatch, unix_api):
    (tmp_path / "real.service").write_text("[Service]\nExecStart=/bin/true fixture.invalid\n")
    (tmp_path / "alias.service").write_text("")
    _links(monkeypatch, unix_api, {tmp_path / "alias.service": tmp_path / "real.service"})
    monkeypatch.setattr(unix_api, "_ux_roots", lambda: [("linux-systemd-units", str(tmp_path), "unit")])
    result = _run(unix_api)
    assert [h.indicator for h in result.hits] == ["fixture.invalid"]
    assert result.checked == 1
    assert all(c.ran for c in result.checks)


def test_link_out_of_the_folder_is_not_followed_and_is_named(tmp_path, monkeypatch, unix_api):
    units, elsewhere = tmp_path / "units", tmp_path / "opt"
    units.mkdir()
    elsewhere.mkdir()
    target = elsewhere / "linked.service"
    target.write_text("[Service]\nExecStart=/opt/x fixture.invalid\n")
    (units / "linked.service").write_text("")
    _links(monkeypatch, unix_api, {units / "linked.service": target})
    monkeypatch.setattr(unix_api, "_ux_roots", lambda: [("linux-systemd-units", str(units), "unit")])
    result = _run(unix_api)
    assert result.hits == []
    gaps = [c.reason for c in result.checks if not c.ran]
    assert len(gaps) == 1 and "not followed" in gaps[0] and str(target) in gaps[0]


def test_alias_to_a_file_the_folder_filter_skips_is_a_gap(tmp_path, monkeypatch, unix_api):
    (tmp_path / "notes.txt").write_text("fixture.invalid")
    (tmp_path / "evil.service").write_text("")
    _links(monkeypatch, unix_api, {tmp_path / "evil.service": tmp_path / "notes.txt"})
    monkeypatch.setattr(unix_api, "_ux_roots", lambda: [("linux-systemd-units", str(tmp_path), "unit")])
    result = _run(unix_api)
    assert result.hits == [] and any(not c.ran and "not followed" in c.reason for c in result.checks)


def test_masked_unit_is_not_a_gap(tmp_path, monkeypatch, unix_api):
    (tmp_path / "masked.service").write_text("fixture.invalid")
    _links(monkeypatch, unix_api, {tmp_path / "masked.service": os.devnull})
    monkeypatch.setattr(unix_api, "_ux_roots", lambda: [("linux-systemd-units", str(tmp_path), "unit")])
    result = _run(unix_api)
    assert result.hits == [] and result.checked == 0
    assert all(c.ran for c in result.checks)


def test_standard_location_linked_to_another_is_inspected_once(tmp_path, monkeypatch, unix_api):
    spool, crontabs = tmp_path / "spool-crontabs", tmp_path / "etc-crontabs"
    crontabs.mkdir()
    spool.mkdir()
    (crontabs / "root").write_text("0 * * * * curl https://fixture.invalid/x\n")
    _links(monkeypatch, unix_api, {spool: crontabs})
    monkeypatch.setattr(unix_api, "_ux_roots", lambda: [
        ("linux-cron", str(spool), "user-cron"), ("linux-cron", str(crontabs), "user-cron")])
    result = _run(unix_api)
    assert [h.indicator for h in result.hits] == ["fixture.invalid"]
    assert all(c.ran for c in result.checks)


def test_permission_denied_says_administrator_rights_are_needed(tmp_path, monkeypatch, unix_api):
    locked, readable = tmp_path / "auth.log", tmp_path / "bashrc"
    locked.write_text("second.invalid")
    readable.write_text("fixture.invalid")
    real_read = unix_api._ux_read

    def read(path):
        if os.path.normpath(path) == os.path.normpath(str(locked)):
            raise PermissionError(13, "Permission denied", path)
        return real_read(path)

    monkeypatch.setattr(unix_api, "_ux_read", read)
    monkeypatch.setattr(unix_api, "_ux_roots", lambda: [
        ("unix-shell-profiles", str(locked), "shell-file"), ("unix-shell-profiles", str(readable), "shell-file")])
    result = _run(unix_api)
    assert [h.indicator for h in result.hits] == ["fixture.invalid"]
    gaps = [c.reason for c in result.checks if not c.ran]
    assert len(gaps) == 1 and "administrator" in gaps[0] and str(locked) in gaps[0]


def test_busybox_crontabs_are_a_linux_root(monkeypatch, unix_api):
    monkeypatch.setattr(unix_api.sys, "platform", "linux")
    assert ("linux-cron", "/etc/crontabs", "user-cron") in unix_api._ux_roots()


def test_conditionally_disabled_launch_job_is_searched_not_refused(tmp_path, monkeypatch, unix_api):
    import plistlib
    (tmp_path / "com.example.job.plist").write_bytes(plistlib.dumps({
        "Label": "com.example.job", "ProgramArguments": ["/opt/job", "fixture.invalid"],
        "Disabled": {"SomeCondition": True}}))
    monkeypatch.setattr(unix_api, "_ux_roots", lambda: [("macos-launch-items", str(tmp_path), "plist")])
    result = _run(unix_api)
    assert [h.indicator for h in result.hits] == ["fixture.invalid"]
    assert all(h.evidence == "referenced" for h in result.hits)
    assert all(c.ran for c in result.checks)


def test_macos_reads_the_app_cryptex_launch_folders(monkeypatch, unix_api):
    monkeypatch.setattr(unix_api.sys, "platform", "darwin")
    roots = {root for _check, root, _kind in unix_api._ux_roots()}
    assert "/System/Cryptexes/App/System/Library/LaunchAgents" in roots
    assert "/System/Cryptexes/App/System/Library/LaunchDaemons" in roots


def test_long_log_without_line_breaks_keeps_its_recent_text(tmp_path, monkeypatch, unix_api):
    path = tmp_path / "one-line.log"
    path.write_bytes(b"x" * 200 + b" fixture.invalid")
    monkeypatch.setattr(unix_api, "_UX_TEXT_CAP", 64, raising=False)
    monkeypatch.setattr(unix_api, "_ux_roots", lambda: [("unix-system-logs", str(path), "log-file")])
    result = _run(unix_api)
    assert [h.indicator for h in result.hits] == ["fixture.invalid"]


@pytest.mark.parametrize("growth,readable", ((10, True), (-10, False)))
def test_live_log_may_grow_while_read_but_not_shrink(tmp_path, monkeypatch, unix_api, growth, readable):
    path = tmp_path / "syslog"
    path.write_bytes(b"line one\nresolved fixture.invalid\n")
    real_fstat, calls = os.fstat, []

    class Grown:
        def __init__(self, info):
            self._info = info

        def __getattr__(self, name):
            value = getattr(self._info, name)
            return value + growth if name == "st_size" else value

    def fstat(fd):
        calls.append(fd)
        info = real_fstat(fd)
        return Grown(info) if len(calls) % 2 == 0 else info

    monkeypatch.setattr(os, "fstat", fstat)
    monkeypatch.setattr(unix_api, "_ux_roots", lambda: [("unix-system-logs", str(path), "log-file")])
    result = _run(unix_api)
    assert bool(result.hits) is readable
    assert any(not c.ran for c in result.checks) is (not readable)


@pytest.mark.parametrize("tag", (b"<plist version=\"1.0\">", b"<plist version=1.0>"))
def test_apple_plist_with_unquoted_prolog_is_read(tmp_path, monkeypatch, unix_api, tag):
    body = (tag + b"<dict><key>Label</key><string>com.example.job</string>"
            b"<key>ProgramArguments</key><array><string>/usr/libexec/job</string>"
            b"<string>fixture.invalid</string></array></dict></plist>")
    prolog = (b"<?xml version=1.0 encoding=UTF-8?>" + bytes([10]) +
              b"<!DOCTYPE plist PUBLIC -//Apple//DTD PLIST 1.0//EN http://www.apple.com/DTDs/PropertyList-1.0.dtd>"
              + bytes([10]))
    (tmp_path / "com.example.job.plist").write_bytes(prolog + body)
    (tmp_path / "broken.plist").write_bytes(prolog + b"<plist><dict><key>Label")
    monkeypatch.setattr(unix_api, "_ux_roots", lambda: [("macos-launch-items", str(tmp_path), "plist")])
    result = _run(unix_api)
    assert [h.indicator for h in result.hits] == ["fixture.invalid"]
    assert [c.ran for c in result.checks if not c.ran] == [False]


@pytest.mark.parametrize("link,owner,expected", (
    ("usr/lib", 0, "/usr/lib/systemd/system/a.service"),
    ("/usr/lib", 0, "/usr/lib/systemd/system/a.service"),
    ("usr/lib", 1000, "/lib/systemd/system/a.service"),
    ("/elsewhere", 0, "/lib/systemd/system/a.service"),
))
def test_merged_usr_alias_is_checked_exactly(monkeypatch, unix_api, link, owner, expected):
    import stat as stat_module
    import types
    real_lstat, real_readlink = os.lstat, os.readlink

    def lstat(path):
        if path == "/lib":
            return types.SimpleNamespace(st_mode=stat_module.S_IFLNK | 0o777, st_uid=owner)
        return real_lstat(path)

    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(os, "readlink", lambda path: link if path == "/lib" else real_readlink(path))
    assert unix_api._ux_merged_usr("/lib/systemd/system/a.service") == expected


def test_alias_through_merged_usr_is_not_a_gap(tmp_path, monkeypatch, unix_api):
    (tmp_path / "a.service").write_text("[Service]")
    (tmp_path / "b.service").write_text("")
    _links(monkeypatch, unix_api, {tmp_path / "b.service": "/lib/systemd/system/a.service"})
    monkeypatch.setattr(unix_api, "_ux_merged_usr", lambda path: str(tmp_path / "a.service")
                        if path.endswith("a.service") else path)
    monkeypatch.setattr(unix_api, "_ux_roots", lambda: [("linux-systemd-units", str(tmp_path), "unit")])
    result = _run(unix_api)
    assert all(c.ran for c in result.checks)


def test_unreadable_folder_says_administrator_rights_are_needed(tmp_path, monkeypatch, unix_api):
    locked = tmp_path / "crontabs"
    locked.mkdir()
    real_scandir = os.scandir

    def scandir(path="."):
        if os.path.normpath(os.fspath(path)) == os.path.normpath(str(locked)):
            raise PermissionError(13, "Permission denied", str(locked))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", scandir)
    monkeypatch.setattr(unix_api, "_ux_roots", lambda: [("linux-cron", str(locked), "user-cron")])
    result = _run(unix_api)
    gaps = [c.reason for c in result.checks if not c.ran]
    assert len(gaps) == 1 and "administrator" in gaps[0]
