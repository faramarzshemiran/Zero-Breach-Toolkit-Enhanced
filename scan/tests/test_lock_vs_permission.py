"""A refused read is only called "the browser was running" when it really is a
lock (SQLite busy/locked, or a Windows sharing violation). Any other refusal is
reported as a permission problem with what to do, and on macOS as privacy
protection without claiming the browser is installed. The empty LevelDB LOCK
sentinel a running browser holds is not a coverage gap."""
import io
import os
import sqlite3
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage.modules import browser  # noqa: E402
from test_browser_launch import BrowserLaunchBase, TEST_DOMAIN  # noqa: E402


def _winerr(code):
    exc = PermissionError(13, "The process cannot access the file")
    exc.winerror = code
    return exc


def test_linux_permission_refusal_is_not_called_running(monkeypatch):
    monkeypatch.setattr(browser.sys, "platform", "linux")
    note = browser._locked_note("/home/u/.config/google-chrome/Default/History",
                                PermissionError(13, "Permission denied"))
    assert "was running" not in note and "permission to read" in note


def test_windows_access_denied_is_permission_but_sharing_violation_is_a_lock(monkeypatch):
    monkeypatch.setattr(browser.sys, "platform", "win32")
    path = r"C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\History"
    assert "was running" in browser._locked_note(path, _winerr(32))
    assert "was running" in browser._locked_note(path, _winerr(33))
    denied = browser._locked_note(path, _winerr(5))
    assert "was running" not in denied and "administrator" in denied


def test_sqlite_lock_is_still_a_lock(monkeypatch):
    monkeypatch.setattr(browser.sys, "platform", "linux")
    note = browser._locked_note("/x/History", sqlite3.OperationalError("database is locked"))
    assert "was running" in note


def test_macos_names_firefox_without_claiming_it_is_installed(monkeypatch):
    monkeypatch.setattr(browser.sys, "platform", "darwin")
    note = browser._locked_note(
        "/Users/u/Library/Application Support/Firefox/Profiles/a.default/places.sqlite",
        PermissionError(1, "Operation not permitted"))
    assert "Full Disk Access" in note and "Firefox" in note
    assert "was running" not in note and "whether Firefox keeps data there" in note


class TestLevelDbLockSentinel(BrowserLaunchBase):
    def _store(self, ud):
        d = os.path.join(ud, "Default", "Local Storage", "leveldb")
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "LOCK"), "wb").close()
        with open(os.path.join(d, "000003.log"), "wb") as fh:
            fh.write(("stored " + TEST_DOMAIN).encode("utf-8"))
        return d

    def _held(self):
        real = io.open

        def fake(path, *a, **k):
            if os.path.basename(str(path)) == "LOCK":
                raise PermissionError(13, "held by the running browser", path)
            return real(path, *a, **k)
        return patch.object(browser.io, "open", fake)

    def test_held_empty_lock_is_not_a_gap(self):
        ud = os.path.join(self.tmp, "User Data")
        self._store(ud)
        with self._held():
            r = self.run_chromium(ud)
        assert any(h.indicator == TEST_DOMAIN for h in r.hits)
        gaps = [c.reason for c in r.checks if not c.ran and "blobs" in c.name]
        assert gaps == [], gaps

    def test_unreadable_lock_with_content_is_still_a_gap(self):
        ud = os.path.join(self.tmp, "User Data")
        d = self._store(ud)
        with open(os.path.join(d, "LOCK"), "wb") as fh:
            fh.write(b"not a sentinel")
        with self._held():
            r = self.run_chromium(ud)
        gaps = [c.reason for c in r.checks if not c.ran and "blobs" in c.name]
        assert gaps and "LOCK" in gaps[0]
