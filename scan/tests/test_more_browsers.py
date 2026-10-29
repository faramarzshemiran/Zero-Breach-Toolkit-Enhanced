"""Browsers beyond the big five: Chromium-based release channels, Opera, Arc,
Yandex, and the Firefox family (LibreWolf, Waterfox, Floorp, Zen, Pale Moon,
Tor Browser), each read in its default location and labelled by its own name."""
import contextlib
import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_discovery_and_fingerprint_gaps import _home
from test_evidence_safety import _ctx, safety_api
from test_followup_fixes import bundle

DOMAIN = "fixture.invalid"


def _places(folder):
    folder.mkdir(parents=True)
    with contextlib.closing(sqlite3.connect(folder / "places.sqlite")) as db:
        db.execute("CREATE TABLE moz_places(id INTEGER PRIMARY KEY,url TEXT,title TEXT,"
                   "last_visit_date INTEGER,visit_count INTEGER)")
        db.execute("INSERT INTO moz_places VALUES(1,?,'',1760000000000000,1)", ("https://" + DOMAIN + "/",))
        db.commit()


def _chromium_history(folder):
    folder.mkdir(parents=True)
    with contextlib.closing(sqlite3.connect(folder / "History")) as db:
        db.executescript("CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,last_visit_time INTEGER);"
                         "CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER,visit_time INTEGER);")
        db.execute("INSERT INTO urls VALUES(1,?,'',13400000000000000)", ("https://" + DOMAIN + "/",))
        db.execute("INSERT INTO visits VALUES(1,1,13400000000000000)")
        db.commit()


@pytest.mark.parametrize("platform,parts,label", (
    ("linux", (".librewolf", "abc.default-default"), "librewolf"),
    ("linux", (".floorp", "abc.default"), "floorp"),
    ("linux", (".zen", "abc.Default (release)"), "zen"),
    ("darwin", ("Library", "Application Support", "Waterfox", "Profiles", "abc.default"), "waterfox"),
    ("darwin", ("Library", "Application Support", "TorBrowser-Data", "Browser", "profile.default"), "tor-browser"),
))
def test_firefox_family_profiles_are_read_and_labelled(tmp_path, monkeypatch, safety_api, platform, parts, label):
    api = safety_api.browser
    home = _home(tmp_path, monkeypatch, api, platform)
    _places(home.joinpath(*parts))
    monkeypatch.setattr(api, "CHROMIUM_ROOTS", [])
    monkeypatch.setattr(api, "APP_ROOTS", [])
    monkeypatch.setattr(api, "FIREFOX_ROOTS", api._firefox_roots())
    result = safety_api.browser_run(_ctx())
    assert [h.indicator for h in result.hits] == [DOMAIN]
    assert any(c.ran and c.name.startswith(label + ":") for c in result.checks)


@pytest.mark.parametrize("platform,parts,label", (
    ("darwin", ("Library", "Application Support", "Arc", "User Data", "Default"), "arc"),
    ("darwin", ("Library", "Application Support", "com.operasoftware.Opera"), "opera"),
    ("darwin", ("Library", "Application Support", "Google", "Chrome Canary", "Default"), "chrome-canary"),
    ("linux", (".config", "microsoft-edge-beta", "Default"), "edge-beta"),
    ("linux", (".config", "yandex-browser", "Default"), "yandex"),
))
def test_more_chromium_browsers_are_read_and_labelled(tmp_path, monkeypatch, safety_api, platform, parts, label):
    api = safety_api.browser
    home = _home(tmp_path, monkeypatch, api, platform)
    _chromium_history(home.joinpath(*parts))
    roots = [(name, path) for name, path in api._chromium_roots() if name == label]
    assert roots
    monkeypatch.setattr(api, "CHROMIUM_ROOTS", roots)
    monkeypatch.setattr(api, "APP_ROOTS", [])
    monkeypatch.setattr(api, "FIREFOX_ROOTS", [])
    result = safety_api.browser_run(_ctx())
    assert DOMAIN in {h.indicator for h in result.hits}
    assert any(c.ran and c.name.startswith(label + ":") for c in result.checks)


def test_opera_cache_on_windows_is_under_local(monkeypatch, safety_api):
    api = safety_api.browser
    monkeypatch.setattr(api.sys, "platform", "win32")
    monkeypatch.setattr(api, "ROAMING", "C:\\Users\\u\\AppData\\Roaming")
    monkeypatch.setattr(api, "LOCAL", "C:\\Users\\u\\AppData\\Local")
    opera = "C:\\Users\\u\\AppData\\Roaming\\Opera Software\\Opera Stable"
    slack = "C:\\Users\\u\\AppData\\Roaming\\Slack"
    if os.name == "nt":
        assert api._browser_cache_profile(opera) == "C:\\Users\\u\\AppData\\Local\\Opera Software\\Opera Stable"
    # Desktop apps in Roaming keep their cache inside their own folder.
    assert api._browser_cache_profile(slack) == slack
