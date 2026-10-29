"""Linux layouts that differ from the classic ones: translated user folders
(user-dirs.dirs), snap browsers whose data sits in a numbered revision folder,
and Firefox 147+'s XDG profile location (plus Flatpak Firefox)."""
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage.modules import hashscan

SCAN = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_translated_user_folders_are_read_from_user_dirs(tmp_path):
    home = tmp_path / "home"
    config = home / ".config"
    config.mkdir(parents=True)
    (config / "user-dirs.dirs").write_text(
        '# comment\n'
        'XDG_DESKTOP_DIR="$HOME/سطح المكتب"\n'
        'XDG_DOWNLOAD_DIR="$HOME/Téléchargements"\n'
        'XDG_DOCUMENTS_DIR="$HOME"\n'
        'XDG_MUSIC_DIR="$HOME/Musique"\n'
        'XDG_PICTURES_DIR="relative/not/used"\n', encoding="utf-8")
    found = hashscan._hs_xdg_user_dirs(str(home), str(config))
    assert found == [os.path.join(str(home), "سطح المكتب"),
                     os.path.join(str(home), "Téléchargements")]


def test_missing_user_dirs_file_is_fine(tmp_path):
    assert hashscan._hs_xdg_user_dirs(str(tmp_path), str(tmp_path / "none")) == []


_PROBE = r'''
import os, sys
sys.path.insert(0, sys.argv[1])
from zbtriage.modules import browser
home = os.environ["HOME"]
chromium = dict(browser._chromium_roots())
firefox = [p for p, _ in browser._firefox_roots()]
print("SNAP_BRAVE", chromium.get("brave-snap", ""))
print("SNAP_OPERA", chromium.get("opera-snap", ""))
print("FF_XDG", os.path.join(home, ".config", "mozilla", "firefox") in firefox)
print("FF_FLATPAK_XDG", os.path.join(home, ".var", "app", "org.mozilla.firefox", "config", "mozilla", "firefox") in firefox)
'''


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux layouts and symlinks")
def test_snap_revision_and_firefox_xdg_roots_are_discovered(tmp_path):
    home = tmp_path / "home"
    for app in ("brave", "opera"):
        (home / "snap" / app / "123").mkdir(parents=True)
        os.symlink("123", str(home / "snap" / app / "current"))
    # A link pointing outside its snap folder is never used.
    (home / "snap" / "vivaldi").mkdir(parents=True)
    os.symlink("/etc", str(home / "snap" / "vivaldi" / "current"))
    env = dict(os.environ, HOME=str(home))
    for var in ("XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"):
        env.pop(var, None)
    out = subprocess.run([sys.executable, "-c", _PROBE, SCAN], env=env, capture_output=True, text=True,
                         check=True).stdout
    lines = dict(line.split(" ", 1) for line in out.splitlines())
    assert lines["SNAP_BRAVE"] == os.path.join(str(home), "snap", "brave", "123", ".config", "BraveSoftware",
                                               "Brave-Browser")
    assert lines["SNAP_OPERA"] == os.path.join(str(home), "snap", "opera", "123", ".config", "opera")
    assert lines["FF_XDG"] == "True" and lines["FF_FLATPAK_XDG"] == "True"
    assert "vivaldi-snap" not in out
