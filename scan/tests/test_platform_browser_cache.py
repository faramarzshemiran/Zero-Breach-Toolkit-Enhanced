"""Separate browser cache locations, explicit scope and source preservation."""
import os
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_evidence_safety import _ctx, _history, safety_api
from test_followup_fixes import bundle
from zbtriage import workflow


@pytest.mark.parametrize("platform", ("linux", "darwin"))
@pytest.mark.parametrize("custom_xdg", (False, True))
@pytest.mark.parametrize("targeted", (False, True))
def test_separate_chromium_cache_is_read_without_expanding_target_scope(tmp_path, monkeypatch, safety_api, platform, custom_xdg, targeted):
    api = safety_api.browser
    home = tmp_path / "home"
    if platform == "linux":
        config = home / ("custom-config" if custom_xdg else ".config")
        cache = home / ("custom-cache" if custom_xdg else ".cache")
        root = config / "google-chrome"
        cache_root = cache / "google-chrome"
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config) if custom_xdg else "")
        monkeypatch.setenv("XDG_CACHE_HOME", str(cache) if custom_xdg else "")
    else:
        root = home / "Library" / "Application Support" / "Google" / "Chrome"
        cache_root = home / "Library" / "Caches" / "Google" / "Chrome"
    _history(root / "Default", "ordinary.invalid")
    cache_file = cache_root / "Default" / "Cache" / "Cache_Data" / "record"
    cache_file.parent.mkdir(parents=True)
    cache_file.write_bytes(b"saved page mentioning fixture.invalid")
    original = cache_file.read_bytes()
    monkeypatch.setattr(api.sys, "platform", platform)
    monkeypatch.setattr(api.os.path, "expanduser", lambda value: str(home))
    monkeypatch.setattr(api, "CHROMIUM_ROOTS", [("chrome", str(root))])
    monkeypatch.setattr(api, "FIREFOX_ROOTS", [])
    monkeypatch.setattr(api, "APP_ROOTS", [])
    result = safety_api.browser_run(_ctx(targets=(str(root),) if targeted else ()))
    cache_hits = [hit for hit in result.hits if hit.indicator == "fixture.invalid"]
    assert bool(cache_hits) is not targeted
    if cache_hits:
        assert all(hit.evidence == "referenced" and hit.location == str(cache_file) for hit in cache_hits)
        assert all(hit.profile == "Default" for hit in cache_hits)
    assert cache_file.read_bytes() == original


@pytest.mark.parametrize("platform", ("linux", "darwin"))
def test_chromium_cache_mapping_does_not_use_a_prefix_sibling(tmp_path, monkeypatch, safety_api, platform):
    api = safety_api.browser
    monkeypatch.setattr(api.sys, "platform", platform)
    monkeypatch.setattr(api.os.path, "expanduser", lambda value: str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", "")
    monkeypatch.setenv("XDG_CACHE_HOME", "")
    prefix = tmp_path / (".config-other" if platform == "linux" else "Library/Application Support-other")
    profile = str(prefix / "chrome" / "Default")
    assert api._browser_cache_profile(profile) == profile


@pytest.mark.parametrize("target", ("profile", "home"))
def test_cache_scope_accepts_only_explicitly_containing_targets(tmp_path, monkeypatch, safety_api, target):
    api = safety_api.browser
    selected = tmp_path / ".config" / "chrome" if target == "profile" else tmp_path
    selected.mkdir(parents=True, exist_ok=True)
    cache = tmp_path / ".cache" / "chrome" / "Default"
    assert api._browser_cache_in_scope(str(cache), [str(selected)]) is (target == "home")


def test_default_cache_evidence_cannot_be_replaced_by_a_report(tmp_path, monkeypatch, safety_api):
    api = safety_api.browser
    guard = workflow if safety_api.entry.__name__ == "zbtriage.cli" else safety_api.entry
    root = tmp_path / ".config" / "google-chrome"
    cache = tmp_path / ".cache" / "google-chrome" / "Default" / "Cache" / "record"
    cache.parent.mkdir(parents=True)
    cache.write_bytes(b"preserve cached evidence")
    monkeypatch.setattr(api.sys, "platform", "linux")
    monkeypatch.setattr(api.os.path, "expanduser", lambda value: str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", "")
    monkeypatch.setenv("XDG_CACHE_HOME", "")
    monkeypatch.setattr(api, "CHROMIUM_ROOTS", [("chrome", str(root))])
    monkeypatch.setattr(api, "FIREFOX_ROOTS", [])
    args = types.SimpleNamespace(target=[], phone=None)
    with pytest.raises(ValueError, match="existing file"):
        guard.workflow_output_guard(args, str(cache))
    assert cache.read_bytes() == b"preserve cached evidence"
    guard.workflow_output_guard(args, str(tmp_path / "report.json"))
