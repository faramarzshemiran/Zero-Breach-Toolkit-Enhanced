"""Two false "not checked" results reported on desktop Safari.

1. macOS links Safari's sandbox Cookies folder to ~/Library/Cookies. The link
   is (rightly) never followed, but its refusal stayed a gap although the same
   store was read directly. The exact standard link is now skipped; any other
   link is still refused.
2. A desktop snapshot may be up to 1 GiB, but its write-ahead log was checked
   against the 256 MiB phone-extraction limit, so a valid log reaching past it
   was called damaged."""
import os
import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage.modules import browser  # noqa: E402


def test_standard_cookie_link_is_an_alias(monkeypatch, tmp_path):
    library = tmp_path / "Library"
    sandbox = library / "Containers" / "com.apple.Safari" / "Data" / "Library"
    alias, direct = str(sandbox / "Cookies"), str(library / "Cookies")
    monkeypatch.setattr(browser.os.path, "islink", lambda p: os.path.normpath(p) == os.path.normpath(alias))
    monkeypatch.setattr(browser.os, "readlink", lambda p: os.path.join("..", "..", "..", "..", "Cookies"))
    assert browser._browser_same_store_alias(alias, direct)


def test_other_links_are_not_aliases(monkeypatch, tmp_path):
    alias = str(tmp_path / "Library" / "Containers" / "com.apple.Safari" / "Data" / "Library" / "Cookies")
    direct = str(tmp_path / "Library" / "Cookies")
    monkeypatch.setattr(browser.os.path, "islink", lambda p: True)
    for target in (os.path.join("..", "..", "..", "Cookies"), "/tmp/elsewhere", os.path.join("..", "Cookies")):
        monkeypatch.setattr(browser.os, "readlink", lambda p, t=target: t)
        assert not browser._browser_same_store_alias(alias, direct), target
    monkeypatch.setattr(browser.os.path, "islink", lambda p: False)
    assert not browser._browser_same_store_alias(alias, direct)


def _wal_fixture():
    """A database header and a WAL whose single committed frame is page 65,537
    (4,096-byte pages): just past 256 MiB, inside the 1 GiB desktop limit."""
    def checksum(raw, a=0, b=0):
        for x, y in struct.iter_unpack("<II", raw):
            a = (a + x + b) & 0xffffffff
            b = (b + y + a) & 0xffffffff
        return a, b
    header = bytearray(100)
    header[:16] = b"SQLite format 3\0"
    struct.pack_into(">H", header, 16, 4096)
    wh = struct.pack(">6I", 0x377f0682, 3007000, 4096, 0, 11, 12)
    a, b = checksum(wh)
    wh += struct.pack(">2I", a, b)
    first = struct.pack(">2I", 65537, 65537)
    payload = bytes(4096)
    a, b = checksum(first, a, b)
    a, b = checksum(payload, a, b)
    return bytes(header), wh + first + struct.pack(">4I", 11, 12, a, b) + payload


def test_desktop_wal_uses_the_desktop_limit():
    header, wal = _wal_fixture()
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "SafariTabs.db"
        path.write_bytes(header)
        Path(str(path) + "-wal").write_bytes(wal)
        copied, issues = browser.copy_locked(str(path))
        try:
            assert issues == [], issues
        finally:
            browser._discard_snapshot(os.path.dirname(copied))


def test_phone_reader_keeps_its_smaller_limit():
    from zbtriage.ios_sources import _is_wal_prefix
    header, wal = _wal_fixture()
    _prefix, issues = _is_wal_prefix(wal, header)
    assert issues and "limit" in issues[0]
