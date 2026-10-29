"""The browser-only scan type and the start-menu entry that leads to it.

The menu entry offers two things: the offline browser check (--scan-type
browser), and a link to the ad-blocking test, which only a browser can run.
Opening that page is the browser's network use, never this tool's, so the tests
make sure it is only ever offered, asked about and handed to the browser.
"""
import contextlib
import io
import json
import os
import sqlite3
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import cli, menu, scope
from zbtriage.modules import browser
from zbtriage.readers import reader_select
from test_expanded_capabilities import BAD, context
from test_followup_fixes import bundle  # noqa: F401  (pytest fixture)


class Terminal(io.StringIO):
    def isatty(self):
        return True


def _user_data(root):
    """A Chromium user-data folder whose Default profile visited BAD."""
    profile = root / "User Data" / "Default"
    profile.mkdir(parents=True)
    (root / "User Data" / "Local State").write_text("{}", encoding="utf-8")
    with contextlib.closing(sqlite3.connect(profile / "History")) as db:
        db.execute("CREATE TABLE urls(url TEXT,title TEXT,last_visit_time INTEGER)")
        db.execute("INSERT INTO urls VALUES(?,?,?)", ("https://" + BAD + "/", "", 13000000000000000))
        db.commit()
    return str(root / "User Data")


# --- which readers run ----------------------------------------------------------

def test_browser_only_runs_just_the_browser_reader():
    assert [s.name for s in reader_select(context(browser_only=True))] == ["browser"]


def test_browser_only_does_not_narrow_a_targeted_or_phone_scan(tmp_path):
    targeted = [s.name for s in reader_select(context(targets=(str(tmp_path),)))]
    assert [s.name for s in reader_select(context(targets=(str(tmp_path),), browser_only=True))] == targeted


def test_the_default_scan_still_runs_more_than_the_browser():
    assert len(reader_select(context())) > 1


def test_browser_scan_type_parses_and_refuses_a_target(tmp_path):
    assert cli._parse(["--scan-type", "browser"]).scan_type == "browser"
    with pytest.raises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
        cli._parse(["--scan-type", "browser", "--target", str(tmp_path)])


def test_preview_names_the_one_check_and_its_limit():
    preview = scope.scope_preview(cli._parse(["--scan-type", "browser"]))
    assert preview["checks"] == ["browser"]
    assert any("Only browser profiles" in limit for limit in preview["limits"])


# --- end to end, in both entry points ---------------------------------------------

def test_a_browser_scan_reports_its_narrow_scope(tmp_path, bundle):
    user_data = _user_data(tmp_path)
    feed = tmp_path / "feed.txt"
    feed.write_text(BAD + "\tinfrastructure\tprimary\tfixture\n", encoding="utf-8")
    for name, api, module in (("source", cli, browser), ("bundle", bundle, bundle)):
        full = tmp_path / (name + ".json")
        out = io.StringIO()
        args = ["--iocs", str(feed), "--scan-type", "browser", "--json", str(full), "--no-banner"]
        if api is bundle:
            args.append("--no-pause")
        with patch.object(module, "CHROMIUM_ROOTS", [("Chrome", user_data)]), \
                patch.object(module, "APP_ROOTS", []), patch.object(module, "FIREFOX_ROOTS", []), \
                patch.object(api, "_force_utf8_io", lambda: None), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = api.main(args)
        assert code == 2, name
        doc = json.loads(full.read_text(encoding="utf-8"))
        assert sorted(doc["modules"]) == ["browser"], name
        assert doc["scope"]["scan_type"] == "browser"
        assert "browser-only" in [x["id"] for x in doc["must_relay"]]
        assert {h["indicator"] for h in doc["modules"]["browser"]["hits"]} == {BAD}
        assert "Only browser profiles were checked" in out.getvalue()


# --- the start menu -----------------------------------------------------------

def _menu(api, keys, opened):
    args = cli._parse([])
    with patch.object(api, "_mn_open_page", lambda url: opened.append(url) or True):
        chosen = api.choose_scan(args, lambda: pytest.fail("update"),
                                 stdin=Terminal(keys), stderr=Terminal())
    return chosen, args


def test_the_menu_entry_starts_a_browser_scan(bundle):
    for api in (menu, bundle):
        opened = []
        chosen, args = _menu(api, "3\n1\n", opened)
        assert chosen and args.scan_type == "browser"
        assert not opened


def test_the_ad_test_asks_before_opening_anything(bundle):
    for api in (menu, bundle):
        opened = []
        chosen, _ = _menu(api, "3\n2\nn\n\n0\n", opened)
        assert not chosen and not opened
        chosen, _ = _menu(api, "3\n2\ny\n\n0\n", opened)
        assert not chosen and opened == ["https://archivegenocide.com/scan/"]


def test_without_a_desktop_no_text_browser_takes_over_the_terminal(monkeypatch):
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(menu.sys, "platform", "linux")
    with patch("webbrowser.open", side_effect=AssertionError("must not open")):
        assert menu._mn_open_page("https://archivegenocide.com/scan/") is False


def test_the_page_is_handed_to_the_browser_not_fetched(monkeypatch):
    monkeypatch.setattr(menu.sys, "platform", "win32")
    with patch("webbrowser.open", return_value=True) as opened:
        assert menu._mn_open_page("https://archivegenocide.com/scan/") is True
    opened.assert_called_once_with("https://archivegenocide.com/scan/", new=2)
