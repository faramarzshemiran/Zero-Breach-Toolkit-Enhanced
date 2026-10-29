"""Linux/macOS portability with synthetic local artifacts only."""
import hashlib
import json
import os
import plistlib

import pytest

from zbtriage.context import ScanContext
from zbtriage.iocs import Indicator, IocSet
from zbtriage.modules import browser, hashscan, posix
from zbtriage.stix import load_stix
from test_followup_fixes import bundle


def _px_context(extra=()):
    indicators = [Indicator("fixture.invalid", "infrastructure", "primary", "domain", "fixture")]
    indicators += list(extra)
    return ScanContext(IocSet(indicators, "fixture", None), emit=lambda text: None)


def _px_run(monkeypatch, tmp_path, kind, content, filename):
    (tmp_path / filename).write_bytes(content)
    monkeypatch.setattr(posix, "_ux_roots", lambda: [("synthetic", str(tmp_path), kind)])
    return posix.run(_px_context())


@pytest.mark.parametrize("kind,filename,content", [
    ("desktop", "fixture.desktop", b"[Desktop Entry]\nType=Application\nExec=/bin/echo fixture.invalid\n"),
    ("unit", "fixture.service", b"[Service]\nExecStart=/bin/echo fixture.invalid\n"),
    ("cron", "fixture", b"* * * * * root /bin/echo fixture.invalid\n"),
    ("plist", "fixture.plist", plistlib.dumps({"ProgramArguments": ["/bin/echo", "fixture.invalid"]})),
])
def test_network_arguments_are_references(monkeypatch, tmp_path, kind, filename, content):
    result = _px_run(monkeypatch, tmp_path, kind, content, filename)
    assert result.checked == 1
    assert [hit.evidence for hit in result.hits] == ["referenced"]
    assert all(check.ran for check in result.checks)


@pytest.mark.parametrize("disabled", [False, True])
@pytest.mark.parametrize("kind", ["desktop", "plist"])
def test_literal_program_path_without_opening_target(monkeypatch, tmp_path, disabled, kind):
    program = "/does-not-exist/fixture-program"
    indicator = Indicator(program, "artifact", "primary", "file-path", "fixture")
    if kind == "desktop":
        data = ("[Desktop Entry]\nType=Application\nExec=" + program + "\nHidden=" + str(disabled).lower()).encode()
        name = "fixture.desktop"
    else:
        data = plistlib.dumps({"Label": "fixture", "Program": program, "Disabled": disabled})
        name = "fixture.plist"
    (tmp_path / name).write_bytes(data)
    monkeypatch.setattr(posix, "_ux_roots", lambda: [("synthetic", str(tmp_path), kind)])
    result = posix.run(_px_context([indicator]))
    assert result.checked == 1
    assert len(result.hits) == 1
    if result.hits:
        assert result.hits[0].evidence == ("referenced" if disabled else "configured")


@pytest.mark.parametrize("content", [b"not a plist", b"<?xml version='1.0'?><plist><dict>", plistlib.dumps(["fixture.invalid"])])
def test_bad_plist_is_gap_and_neighbour_survives(monkeypatch, tmp_path, content):
    (tmp_path / "a.plist").write_bytes(content)
    (tmp_path / "b.plist").write_bytes(plistlib.dumps({"ProgramArguments": ["/bin/echo", "fixture.invalid"]}))
    monkeypatch.setattr(posix, "_ux_roots", lambda: [("synthetic", str(tmp_path), "plist")])
    result = posix.run(_px_context())
    assert result.checked == 1
    assert result.hits and any(not c.ran for c in result.checks)


def test_limits_are_gaps(monkeypatch, tmp_path):
    monkeypatch.setattr(posix, "_UX_FILE_CAP", 16)
    result = _px_run(monkeypatch, tmp_path, "unit", b"[Service]\nExecStart=fixture.invalid\n", "a.service")
    assert result.skipped == 1
    assert any(not check.ran for check in result.checks)


def test_entry_cap_stops_enumeration(monkeypatch, tmp_path):
    for n in range(4):
        (tmp_path / (str(n) + ".service")).write_text("[Service]\n")
    monkeypatch.setattr(posix, "_UX_COUNT_CAP", 2)
    monkeypatch.setattr(posix, "_ux_roots", lambda: [("synthetic", str(tmp_path), "unit")])
    result = posix.run(_px_context())
    assert any(c.name == "unix-host-limits" and not c.ran for c in result.checks)


def test_refused_root_never_opens(monkeypatch, tmp_path):
    monkeypatch.setattr(posix, "_ux_roots", lambda: [("synthetic", str(tmp_path), "unit")])
    monkeypatch.setattr(posix, "path_problem", lambda path: "fixture refused")
    monkeypatch.setattr(posix, "_ux_read", lambda path: pytest.fail("refused read"))
    result = posix.run(_px_context())
    assert result.checked == 0 and any(not c.ran for c in result.checks)


def test_symbolic_link_refused(monkeypatch, tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"[Service]\nExecStart=/bin/echo fixture.invalid\n")
    try:
        (tmp_path / "link.service").symlink_to(target)
    except OSError:
        pytest.skip("symlink creation unavailable")
    monkeypatch.setattr(posix, "_ux_roots", lambda: [("synthetic", str(tmp_path), "unit")])
    result = posix.run(_px_context())
    assert not result.hits and any(not c.ran for c in result.checks)


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_default_hash_extensionless_native_sample(monkeypatch, tmp_path, platform):
    data = b"\x7fELF harmless fixture only"
    sample = tmp_path / "fixture-program"
    sample.write_bytes(data)
    indicator = Indicator(hashlib.sha256(data).hexdigest(), "sample", "primary", "sha256", "fixture")
    monkeypatch.setattr(hashscan.sys, "platform", platform)
    monkeypatch.setattr(hashscan, "_roots", lambda: [str(tmp_path)])
    result = hashscan.run(_px_context([indicator]))
    assert result.checked == 1 and result.hits[0].evidence == "on-disk"


def test_windows_selection_preserved(monkeypatch, tmp_path):
    monkeypatch.setattr(hashscan.sys, "platform", "win32")
    assert hashscan._hs_candidate(str(tmp_path / "a.exe"), "a.exe")
    assert not hashscan._hs_candidate(str(tmp_path / "a"), "a")
    assert not hashscan._hs_candidate(str(tmp_path / "a.sh"), "a.sh")


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_platform_roots_have_no_windows_defaults(monkeypatch, tmp_path, platform):
    monkeypatch.setattr(hashscan.sys, "platform", platform)
    monkeypatch.setattr(hashscan.os.path, "expanduser", lambda value: str(tmp_path))
    roots = hashscan._roots()
    assert roots and not any("C:\\" in root for root in roots)


def test_xdg_browser_roots(monkeypatch, tmp_path):
    monkeypatch.setattr(browser.sys, "platform", "linux")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    assert dict(browser._chromium_roots())["chrome"] == str(tmp_path / "config" / "google-chrome")
    assert browser._firefox_roots()[0][1] == str(tmp_path / "cache" / "mozilla" / "firefox")


def test_total_budget_reports_unvisited_roots(monkeypatch, tmp_path):
    (tmp_path / "a.service").write_text("[Service]\nExecStart=/bin/echo fixture.invalid\n")
    monkeypatch.setattr(posix, "_UX_TOTAL_CAP", 8)
    monkeypatch.setattr(posix, "_ux_roots", lambda: [
        ("synthetic", str(tmp_path), "unit"),
        ("unvisited", str(tmp_path / "other"), "unit")])
    result = posix.run(_px_context())
    assert not result.hits
    assert any(c.name == "unix-host-limits" and not c.ran for c in result.checks)
    assert not any(c.name == "unvisited" for c in result.checks)


def test_plist_entities_are_not_loaded(monkeypatch, tmp_path):
    content = b'''<?xml version="1.0"?>
<!DOCTYPE plist [<!ENTITY ex SYSTEM "file:///must-not-open">]>
<plist><dict><key>Program</key><string>&ex;</string></dict></plist>'''
    result = _px_run(monkeypatch, tmp_path, "plist", content, "a.plist")
    assert result.checked == 0 and result.skipped == 1


def test_file_changed_during_read_rejected(monkeypatch, tmp_path):
    path = tmp_path / "a.service"
    path.write_bytes(b"[Service]\n")
    real_fstat = posix.os.fstat
    calls = []

    def changed(fd):
        info = real_fstat(fd)
        calls.append(fd)
        if len(calls) == 2:
            return type("Changed", (), {"st_size": info.st_size + 1,
                                        "st_mtime_ns": info.st_mtime_ns})()
        return info

    monkeypatch.setattr(posix.os, "fstat", changed)
    with pytest.raises(OSError, match="changed"):
        posix._ux_read(str(path))


def test_binary_plist_program_supported(monkeypatch, tmp_path):
    result = _px_run(monkeypatch, tmp_path, "plist",
                     plistlib.dumps({"ProgramArguments": ["/bin/echo", "fixture.invalid"]},
                                    fmt=plistlib.FMT_BINARY), "binary.plist")
    assert result.checked == 1 and result.hits[0].evidence == "referenced"


@pytest.mark.parametrize("field", ["Hidden=true", "OnlyShowIn=GNOME;", "TryExec=/absent", "DBusActivatable=true"])
def test_conditional_desktop_program_is_reference(monkeypatch, tmp_path, field):
    program = "/fixture/program"
    indicator = Indicator(program, "artifact", "primary", "file-path", "fixture")
    (tmp_path / "a.desktop").write_text("[Desktop Entry]\nType=Application\nExec=" + program + "\n" + field)
    monkeypatch.setattr(posix, "_ux_roots", lambda: [("synthetic", str(tmp_path), "desktop")])
    result = posix.run(_px_context([indicator]))
    assert [hit.evidence for hit in result.hits] == ["referenced"]


def test_bundle_posix_reader_matches_source(monkeypatch, tmp_path, bundle):
    (tmp_path / "fixture.desktop").write_text(
        "[Desktop Entry]\nType=Application\nExec=/fixture/program fixture.invalid\n")
    roots = [("linux-autostart", str(tmp_path), "desktop")]
    monkeypatch.setattr(posix, "_ux_roots", lambda: roots)
    monkeypatch.setattr(bundle, "_ux_roots", lambda: roots)
    indicator = Indicator("/fixture/program", "artifact", "primary", "file-path", "fixture")
    source = posix.run(_px_context([indicator]))
    bundled = bundle.run_posix(_px_context([indicator]))
    assert source.to_dict() == bundled.to_dict()


@pytest.mark.parametrize("command", ["'/fixture/program'", "/fixture/program %Q",
                                    "/fixture/program %f", "/fixture/program; /bin/true"])
def test_desktop_shell_syntax_and_substitutions_are_references_with_a_note(monkeypatch, tmp_path, bundle, command):
    # The whole entry is searched, so unexpanded launch syntax is not a coverage
    # gap; it only means no program is graded as configured to start.
    (tmp_path / "fixture.desktop").write_text("[Desktop Entry]\nType=Application\nExec=" + command)
    indicator = Indicator("/fixture/program", "artifact", "primary", "file-path", "fixture")
    for module, reader in ((posix, posix.run), (bundle, bundle.run_posix)):
        monkeypatch.setattr(module, "_ux_roots", lambda: [("linux-autostart", str(tmp_path), "desktop")])
        result = reader(_px_context([indicator]))
        assert result.checked == 1
        assert [hit.evidence for hit in result.hits] == ["referenced"]
        assert all(check.ran for check in result.checks)
        assert any("does not expand" in note and "fixture.desktop" in note for note in result.notes)


def test_entry_cap_keeps_prior_findings_source_and_bundle(monkeypatch, tmp_path, bundle):
    for name in ("a.service", "b.service", "c.service"):
        (tmp_path / name).write_text("[Service]\nExecStart=/bin/echo fixture.invalid\n")
    for module, reader in ((posix, posix.run), (bundle, bundle.run_posix)):
        monkeypatch.setattr(module, "_ux_roots", lambda: [("linux-systemd-units", str(tmp_path), "unit")])
        monkeypatch.setattr(module, "_UX_COUNT_CAP", 2)
        result = reader(_px_context())
        assert result.checked == 2 and len(result.hits) == 2
        assert any(c.name == "unix-host-limits" and not c.ran for c in result.checks)


@pytest.mark.parametrize("command,program", [
    ('"/fixture/program" "argument with spaces"', "/fixture/program"),
    ('"/fixture/program with spaces" arg', "/fixture/program with spaces"),
    ("/fixture/program plain-arg", "/fixture/program"),
])
def test_desktop_literal_exec_grammar(command, program):
    assert posix._ux_program(command) == program


@pytest.mark.parametrize("published", [["/opt/Spy"], ["/opt/Spy", "/opt/SPY"]])
@pytest.mark.parametrize("actual", ["/opt/Spy", "/opt/SPY", "/opt/spy", "/opt/SpyExtra", "/opt/Spy/child"])
@pytest.mark.parametrize("reference", [False, True])
def test_stix_paths_preserve_case_after_merge(monkeypatch, tmp_path, bundle, published, actual, reference):
    feed = tmp_path / "fixture.stix2"
    feed.write_text(json.dumps({"type": "bundle", "objects": [
        {"type": "indicator", "pattern": "[file:path='" + value + "']"}
        for value in published]}))
    (tmp_path / "fixture.desktop").write_text(
        "[Desktop Entry]\nType=Application\nExec=" +
        ("/bin/echo\nComment=" if reference else "") + actual)
    for module, reader, loader in ((posix, posix.run, load_stix),
                                    (bundle, bundle.run_posix, bundle.load_stix)):
        imported = loader(str(feed))
        assert len(imported.indicators) == 1
        monkeypatch.setattr(module, "_ux_roots", lambda: [("linux-autostart", str(tmp_path), "desktop")])
        result = reader(_px_context(imported.indicators))
        if actual in published:
            assert len(result.hits) == 1
            assert result.hits[0].evidence == ("referenced" if reference else "configured")
            assert "Exact path: " + actual in result.hits[0].detail
        else:
            assert result.hits == []
