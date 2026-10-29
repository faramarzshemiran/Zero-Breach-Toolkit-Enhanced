"""Desktop-app discovery on every platform, Flatpak/snap caches, discovery gaps
and Android app files that cannot be compared by fingerprint or certificate."""
import json
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_evidence_safety import _ctx, _history, safety_api
from test_followup_fixes import bundle
from zbtriage.iocs import TYPE_APP_CERT, TYPE_SHA256, Indicator, IocSet
from zbtriage.modules import android
from zbtriage.result import ModuleResult

SHA = "ab" * 32
CERT = "cd" * 32


def _app(folder):
    """An Electron-style app data folder: Local State plus its own profile."""
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "Local State").write_bytes(b"{}")
    (folder / "Local Storage" / "leveldb").mkdir(parents=True)


def _home(tmp_path, monkeypatch, api, platform):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(api.sys, "platform", platform)
    monkeypatch.setattr(api.os.path, "expanduser", lambda value: str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", "")
    monkeypatch.setenv("XDG_CACHE_HOME", "")
    return home


def test_linux_apps_are_found_in_config_and_flatpak_config(tmp_path, monkeypatch, safety_api):
    api = safety_api.browser
    home = _home(tmp_path, monkeypatch, api, "linux")
    _app(home / ".config" / "Slack")
    _app(home / ".var" / "app" / "com.discordapp.Discord" / "config" / "discord")
    # Flatpak data folders are not app configuration and are not searched.
    _app(home / ".var" / "app" / "com.valvesoftware.Steam" / "data" / "Steam" / "htmlcache")
    chrome = home / ".config" / "google-chrome"
    _app(chrome)
    (home / ".config" / "NotAnApp" / "Network").mkdir(parents=True)
    monkeypatch.setattr(api, "CHROMIUM_ROOTS", [("chrome", str(chrome))])
    gaps = []
    found = dict(api._app_roots(gaps))
    assert found == {"app:slack": str(home / ".config" / "Slack"),
                     "app:discord": str(home / ".var" / "app" / "com.discordapp.Discord" / "config" / "discord")}
    assert gaps == []


def test_macos_apps_are_found_and_apple_data_is_skipped(tmp_path, monkeypatch, safety_api):
    api = safety_api.browser
    home = _home(tmp_path, monkeypatch, api, "darwin")
    support = home / "Library" / "Application Support"
    _app(support / "Slack")
    _app(support / "com.apple.Safari.Something")
    _app(support / "MobileSync" / "Fake")
    monkeypatch.setattr(api, "CHROMIUM_ROOTS", [])
    assert dict(api._app_roots([])) == {"app:slack": str(support / "Slack")}


def test_unknown_platform_has_no_app_folders(monkeypatch, safety_api):
    api = safety_api.browser
    monkeypatch.setattr(api.sys, "platform", "sunos5")
    assert api._app_roots([]) == []


@pytest.mark.parametrize("name,gap", (("Locked", True), ("ElevatedDiagnostics", False)))
def test_unreadable_discovery_folder_is_a_gap_unless_the_os_owns_it(tmp_path, monkeypatch, safety_api, name, gap):
    api = safety_api.browser
    home = _home(tmp_path, monkeypatch, api, "linux")
    _app(home / ".config" / "Slack")
    locked = home / ".config" / name
    locked.mkdir()
    real_scandir = os.scandir

    def scandir(path="."):
        if os.path.normcase(os.fspath(path)) == os.path.normcase(str(locked)):
            raise PermissionError(13, "Access is denied", str(locked))
        return real_scandir(path)

    monkeypatch.setattr(api.os, "scandir", scandir)
    monkeypatch.setattr(api, "CHROMIUM_ROOTS", [])
    gaps = []
    found = dict(api._app_roots(gaps))
    assert "app:slack" in found
    assert bool(gaps) is gap
    if gap:
        assert str(locked) in gaps[0] and "could not be read" in gaps[0]


def test_discovery_gap_reaches_the_report(monkeypatch, safety_api):
    api = safety_api.browser
    roots = []
    monkeypatch.setattr(api, "CHROMIUM_ROOTS", roots)
    monkeypatch.setattr(api, "_DEFAULT_CHROMIUM_ROOTS", roots)
    monkeypatch.setattr(api, "FIREFOX_ROOTS", [])
    monkeypatch.setattr(api, "APP_ROOTS", None)
    monkeypatch.setattr(api, "_browser_safari_roots", lambda: [])

    def discovered(gaps=None):
        gaps.append("desktop app discovery: 1 folder(s) could not be read")
        return []

    monkeypatch.setattr(api, "_app_roots", discovered)
    result = safety_api.browser_run(_ctx())
    assert [(c.name, c.ran) for c in result.checks if c.name == "app-discovery"] == [("app-discovery", False)]
    assert result.status != "CLEAN"


@pytest.mark.parametrize("profile,cache", (
    ((".var", "app", "com.google.Chrome", "config", "google-chrome", "Default"),
     (".var", "app", "com.google.Chrome", "cache", "google-chrome", "Default")),
    (("snap", "chromium", "common", "chromium", "Default"),
     ("snap", "chromium", "common", ".cache", "chromium", "Default")),
    ((".var", "app-other", "x", "config", "c", "Default"), None),
    ((".var", "app", "x", "data", "c", "Default"), None),
    (("snap", "chromium", "common", ".cache", "chromium", "Default"), None),
))
def test_packaged_browser_caches_are_mapped(tmp_path, monkeypatch, safety_api, profile, cache):
    api = safety_api.browser
    home = _home(tmp_path, monkeypatch, api, "linux")
    path = str(home.joinpath(*profile))
    assert api._browser_cache_profile(path) == (str(home.joinpath(*cache)) if cache else path)


def test_flatpak_browser_cache_is_read(tmp_path, monkeypatch, safety_api):
    api = safety_api.browser
    home = _home(tmp_path, monkeypatch, api, "linux")
    app = home / ".var" / "app" / "com.google.Chrome"
    root = app / "config" / "google-chrome"
    _history(root / "Default", "ordinary.invalid")
    cached = app / "cache" / "google-chrome" / "Default" / "Cache" / "Cache_Data" / "f_000001"
    cached.parent.mkdir(parents=True)
    cached.write_bytes(b"page from https://fixture.invalid/x")
    monkeypatch.setattr(api, "CHROMIUM_ROOTS", [("chrome-flatpak", str(root))])
    monkeypatch.setattr(api, "FIREFOX_ROOTS", [])
    monkeypatch.setattr(api, "APP_ROOTS", [])
    result = safety_api.browser_run(_ctx())
    assert [(h.indicator, h.location) for h in result.hits] == [("fixture.invalid", str(cached))]


@pytest.fixture(params=("source", "bundle"))
def android_api(request, bundle):
    return android if request.param == "source" else bundle


def _packages(api, records, kinds=(TYPE_SHA256, TYPE_APP_CERT)):
    ctx = _ctx()
    values = {TYPE_SHA256: "ef" * 32, TYPE_APP_CERT: "01" * 32}
    ctx.iocs = IocSet([Indicator(values[k], "infrastructure", "primary", k, "fixture") for k in kinds],
                      "fixture", None)
    result = ModuleResult("android") if api is android else api.ModuleResult("android")
    info = {"installed": {}, "appops": {}, "receivers": {}, "notification": set(),
            "accessibility": set(), "admins": set()}
    with tempfile.TemporaryDirectory() as folder:
        with open(os.path.join(folder, "packages.json"), "w", encoding="utf-8") as fh:
            json.dump(records, fh)
        api._an_packages(result, ctx, folder, info)
    return {c.name: (c.ran, c.reason) for c in result.checks if "app-" in c.name}, result.notes


def _file(sha=SHA, cert=CERT):
    return {"path": "/data/app/x/base.apk", "sha256": sha,
            "certificate": {"Sha256": cert, "Sha1": ""} if cert is not None else None}


def test_complete_fingerprints_are_checked(android_api):
    checks, _ = _packages(android_api, [{"name": "com.example", "third_party": True, "files": [_file()]}])
    assert checks == {"android:app-fingerprints": (True, ""), "android:app-certificates": (True, "")}


@pytest.mark.parametrize("record,check", (
    ({"files": [_file(cert="")]}, "android:app-certificates"),
    ({"files": [_file(cert=None)]}, "android:app-certificates"),
    ({"files": [_file(sha="not-a-hash")]}, "android:app-fingerprints"),
    ({"files": [_file(sha="")]}, "android:app-fingerprints"),
    ({"files": ["base.apk"]}, "android:app-fingerprints"),
    ({"files": []}, "android:app-certificates"),
    ({"files": "base.apk"}, "android:app-fingerprints"),
))
def test_user_app_without_fingerprint_or_certificate_is_a_gap(android_api, record, check):
    checks, _ = _packages(android_api, [dict(name="com.example", third_party=True, **record)])
    ran, reason = checks[check]
    assert ran is False and "user-installed" in reason


def test_builtin_app_without_certificate_is_a_note_not_a_gap(android_api):
    checks, notes = _packages(android_api, [
        {"name": "com.android.settings", "system": True, "files": [_file(cert="")]},
        {"name": "com.android.privatespace", "system": False, "third_party": False}])
    assert checks["android:app-certificates"] == (True, "")
    assert any("1 built-in app file(s)" in note for note in notes)


def test_no_loaded_indicator_kind_means_no_check(android_api):
    checks, _ = _packages(android_api, [{"name": "com.example", "third_party": True,
                                         "files": [_file(cert="")]}], kinds=(TYPE_SHA256,))
    assert checks == {"android:app-fingerprints": (True, "")}
