"""Reports must not replace desktop-app records, and app discovery has no
silent depth limit: deep profiles are found, and a walk cut short by its
folder/time budget is a reported gap."""
import argparse
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_discovery_and_fingerprint_gaps import _app, _home
from test_evidence_safety import safety_api
from test_followup_fixes import bundle
from zbtriage import workflow
from zbtriage.modules import browser


def _guard(api):
    return getattr(api.entry, "workflow_output_guard", None) or workflow.workflow_output_guard


@pytest.mark.parametrize("option", ("json", "share_json", "report"))
def test_report_cannot_replace_desktop_app_history(tmp_path, monkeypatch, safety_api, option):
    app = tmp_path / "AppData" / "Slack"
    _app(app)
    history = app / "Default" / "History"
    history.parent.mkdir(parents=True)
    history.write_bytes(b"SQLite format 3\x00")
    monkeypatch.setattr(safety_api.browser, "_app_bases", lambda: [str(tmp_path / "AppData")])
    if safety_api.browser is not browser:
        monkeypatch.setattr(browser, "_app_bases", lambda: [str(tmp_path / "AppData")])
    args = argparse.Namespace(iocs=[], target=[], evidence_file=[], pattern_path=[], collect_android=None,
                              phone=None, json=None, share_json=None, report=None)
    setattr(args, option, str(history))
    with pytest.raises(ValueError):
        _guard(safety_api)(args, str(history))
    assert history.read_bytes() == b"SQLite format 3\x00"
    # A new report file is still allowed, even inside the app data folder.
    _guard(safety_api)(args, str(tmp_path / "report.json"))
    _guard(safety_api)(args, str(tmp_path / "AppData" / "new-report.json"))


def test_deep_app_profile_is_found(tmp_path, monkeypatch, safety_api):
    api = safety_api.browser
    home = _home(tmp_path, monkeypatch, api, "linux")
    deep = home / ".config" / "a" / "b" / "c" / "d" / "e" / "f" / "g" / "h" / "Chat"
    _app(deep)
    monkeypatch.setattr(api, "CHROMIUM_ROOTS", [])
    gaps = []
    assert str(deep) in dict(api._app_roots(gaps)).values()
    assert gaps == []


def test_discovery_budget_is_a_reported_gap(tmp_path, monkeypatch, safety_api):
    api = safety_api.browser
    home = _home(tmp_path, monkeypatch, api, "linux")
    for n in range(10):
        (home / ".config" / ("folder%d" % n) / "inner").mkdir(parents=True)
    monkeypatch.setattr(api, "CHROMIUM_ROOTS", [])
    monkeypatch.setattr(api, "_APP_MAX_FOLDERS", 3)
    gaps = []
    api._app_roots(gaps)
    assert len(gaps) == 1 and "stopped at its 3-folder" in gaps[0]


@pytest.mark.parametrize("platform,cache", (
    ("linux", (".cache", "Slack", "Cache", "data_1")),
    ("linux", (".var", "app", "com.slack.Slack", "cache", "Slack", "Cache", "data_1")),
    ("darwin", ("Library", "Caches", "com.tinyspeck.slackmacgap", "Cache", "data_1")),
))
def test_report_cannot_replace_a_separate_app_cache_file(tmp_path, monkeypatch, safety_api, platform, cache):
    api = safety_api.browser
    home = _home(tmp_path, monkeypatch, api, platform)
    if platform == "linux":
        (home / ".var" / "app" / "com.slack.Slack").mkdir(parents=True, exist_ok=True)
    target = home.joinpath(*cache)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"cached page")
    args = argparse.Namespace(iocs=[], target=[], evidence_file=[], pattern_path=[], collect_android=None,
                              phone=None, json=str(target), share_json=None, report=None)
    with pytest.raises(ValueError):
        _guard(safety_api)(args, str(target))
    assert target.read_bytes() == b"cached page"
