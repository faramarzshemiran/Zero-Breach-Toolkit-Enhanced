"""CMD follow-up regressions; native probes execute authored ECHO markers only."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

from zbtriage import feeds, report
from zbtriage.modules import traces
from zbtriage.result import ModuleResult, EV_PERSISTENCE, EV_REFERENCED
from test_expanded_capabilities import BAD, context
from test_followup_fixes import bundle, fake_registry


@pytest.mark.parametrize("line,persistence,gap", [
    ('rem /? & start http://fixture.invalid', True, False),
    ('@rem/? & start http://fixture.invalid', True, False),
    ('rem   /? & start http://fixture.invalid', True, False),
    ('rem /?foo & start http://fixture.invalid', False, True),
    ('rem /? & rem /? fixture.invalid', False, True),
    ('rem note & start http://fixture.invalid', False, False),
    ('rem note /? & start http://fixture.invalid', False, False),
    ('rem "/?" & start http://fixture.invalid', False, False),
    ('rem /? & echo http://fixture.invalid', False, False),
    ('rem /? & rem note & start http://fixture.invalid', False, False),
    ('powershell -Command \r(Write-Output http://fixture.invalid)', True, False),
    ('echo TEXT\rstart http://fixture.invalid', False, False),
    ('echo TEXT\vstart http://fixture.invalid', False, True),
    ('echo TEXT\u2028start http://fixture.invalid', False, True),
    ('start "" "%APPDATA%\\x.exe" http://fixture.invalid', True, True),
    ('start "" "!APPDATA!\\x.exe" http://fixture.invalid', True, True),
    ('start "" "x^ name.exe" http://fixture.invalid', True, True),
    ('start http://fixture.invalid\necho %PATH%', True, True),
    ('echo %PATH%\nstart http://fixture.invalid', True, True),
    ('start http://fixture.invalid\necho ^\ncontinued data', True, True),
    ('echo ^\nstart http://fixture.invalid', False, True),
    ('rem ignored ^\nstart http://fixture.invalid', True, False),
    ('echo ^ \nstart http://fixture.invalid', True, True),
    ('echo %PATH% http://fixture.invalid', False, True),
    ('echo Write-Output http://fixture.invalid | powershell -', False, True),
    ('echo echo http://fixture.invalid>payload.cmd & call payload.cmd', False, True),
    ('if 1==2 (\nstart http://fixture.invalid\n)', False, True),
    ('echo stop\x1a\nstart http://fixture.invalid', False, True),
])
def test_batch_reader_keeps_command_boundaries_and_prior_evidence(tmp_path, monkeypatch, bundle, line, persistence, gap):
    monkeypatch.setitem(sys.modules, "winreg", fake_registry())
    for key in ("APPDATA", "PROGRAMDATA", "SystemRoot"):
        monkeypatch.setenv(key, str(tmp_path))
    root = tmp_path / "Microsoft/Windows/Start Menu/Programs/Startup"
    root.mkdir(parents=True)
    (root / "fixture.cmd").write_bytes(line.encode("utf-8"))
    for api in (traces, bundle):
        r = ModuleResult("traces")
        api._tr_persistence(r, context())
        hits = [h for h in r.hits if h.indicator == BAD]
        assert hits
        assert any(h.evidence == EV_PERSISTENCE for h in hits) == persistence
        assert any(c.name == "startup-files" and not c.ran for c in r.checks) == gap
        if not persistence:
            assert all(h.evidence == EV_REFERENCED for h in hits)


@pytest.mark.skipif(os.name != "nt", reason="CMD semantics need Windows")
@pytest.mark.parametrize("raw,expected,absent", [
    (b'@echo off\r\nrem /? & echo ZBT_HELP_MARKER\r\n', 'ZBT_HELP_MARKER', None),
    (b'@echo off\r\nrem note & echo ZBT_COMMENT_MARKER\r\n', None, 'ZBT_COMMENT_MARKER'),
    (b'@echo off\r\necho START\rMIDDLE_SAME_COMMAND\r\n', 'STARTMIDDLE_SAME_COMMAND', None),
    (b'@echo off\necho TEXT^\necho ZBT_JOIN_MARKER\n', 'TEXTecho ZBT_JOIN_MARKER', None),
    (b'@echo off\nrem ignored ^\necho ZBT_AFTER_COMMENT\n', 'ZBT_AFTER_COMMENT', None),
])
def test_native_cmd_marker_oracles(tmp_path, raw, expected, absent):
    # Never execute scanned text. These fixed fixtures contain only CMD builtins,
    # no indicator, browser launch, download, real Startup folder or external app.
    cmd = Path(os.environ["SystemRoot"]) / "System32/cmd.exe"
    fixture = tmp_path / "marker.cmd"
    fixture.write_bytes(raw)
    proc = subprocess.run([str(cmd), "/d", "/q", "/c", str(fixture)],
                          cwd=str(tmp_path), capture_output=True, timeout=5)
    text = proc.stdout.decode("utf-8", "replace")
    assert proc.returncode == 0
    if expected:
        assert expected in text
    if absent:
        assert absent not in text


@pytest.mark.parametrize("failure", ["none", "destination", "encoding"])
def test_update_summary_unusual_filename_and_output_failure(tmp_path, bundle, failure):
    for n, api in enumerate((feeds, bundle)):
        odd = "odd\ud800-folder"
        summary = {"cache": str(tmp_path / odd), "sources": [], "ok": 1, "failed": 0}
        dest = tmp_path / (("missing/" if failure == "destination" else "") + "update%d.json" % n)
        console, errors = io.BytesIO(), io.BytesIO()
        stdout = io.TextIOWrapper(console, encoding="utf-8", errors="strict", write_through=True)
        stderr = io.TextIOWrapper(errors, encoding="ascii", errors="strict", write_through=True)
        writer = report if api is feeds else api
        real_write = writer.write_json
        def write(doc, path):
            if failure == "encoding":
                raise UnicodeEncodeError("utf-8", "\ud800", 0, 1, "synthetic")
            real_write(doc, path)
        def update(cache, emit):
            emit("fixture " + odd)
            return summary
        with patch.object(api, "update", side_effect=update) as mocked, patch.object(writer, "write_json", write), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = api.update_command(None, str(dest))
        assert mocked.call_count == 1  # The real updater is never invoked.
        assert code == (0 if failure == "none" else 1)
        assert "\\ud800" in console.getvalue().decode("utf-8")
        if failure == "none":
            assert json.loads(dest.read_text(encoding="utf-8")) == summary
        else:
            assert "could not write" in errors.getvalue().decode("ascii")
        stdout.detach()
        stderr.detach()


def test_shell_links_remain_explicit_unsupported_gaps(tmp_path, monkeypatch, bundle):
    monkeypatch.setitem(sys.modules, "winreg", fake_registry())
    for key in ("APPDATA", "PROGRAMDATA", "SystemRoot"):
        monkeypatch.setenv(key, str(tmp_path))
    root = tmp_path / "Microsoft/Windows/Start Menu/Programs/Startup"
    root.mkdir(parents=True)
    (root / "fixture.lnk").write_bytes(b"synthetic unsupported shortcut")
    for api in (traces, bundle):
        r = ModuleResult("traces")
        api._tr_persistence(r, context())
        assert not r.hits
        assert any(c.name == "startup-files" and not c.ran for c in r.checks)
