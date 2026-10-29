"""Desktop apps with a built-in Chromium browser (browser.APP_ROOTS / _app_roots).

Pinned here:
  - apps are found by what their folder CONTAINS (Electron layout and WebView2
    layout), not by name; known browsers are not counted twice;
  - an app's data folder is read as a profile, so a cookie set inside Slack or
    Discord is a finding like one set in Chrome;
  - discovery never runs when the caller set the browser roots explicitly (the
    test suite and release fixture do), so tests stay off the real machine.
"""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage.context import ScanContext  # noqa: E402
from zbtriage.iocs import Indicator, IocSet  # noqa: E402
from zbtriage.modules import browser  # noqa: E402
from zbtriage.result import EV_CONTACTED  # noqa: E402

BAD = "bad-c2.example"


def touch(path, data=b""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)


def cookie_db(path, host):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with sqlite3.connect(path) as con:
        con.execute("CREATE TABLE cookies (host_key TEXT, name TEXT, "
                    "creation_utc INTEGER, encrypted_value BLOB)")
        con.execute("INSERT INTO cookies VALUES (?, 'sid', 13300000000000000, ?)",
                    (host, b"secret"))


class TestDiscovery(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.mkdtemp(prefix="appdata_")
        self.roaming = os.path.join(self.base, "Roaming")
        self.local = os.path.join(self.base, "Local")
        # Electron layout: the data folder IS the profile.
        touch(os.path.join(self.roaming, "Slack", "Local State"), b"{}")
        touch(os.path.join(self.roaming, "Slack", "Network", "Cookies"))
        # WebView2 layout: Local State + Default/ under EBWebView, deep in Packages.
        teams = os.path.join(self.local, "Packages", "MSTeams_8wekyb3d8bbwe", "LocalCache",
                             "Microsoft", "MSTeams", "EBWebView")
        touch(os.path.join(teams, "Local State"), b"{}")
        os.makedirs(os.path.join(teams, "Default"))
        # Vendor folder holding two apps.
        for app in ("Proton Drive", "Proton VPN"):
            d = os.path.join(self.local, "Proton", app, "WebView2", "EBWebView")
            touch(os.path.join(d, "Local State"), b"{}")
            os.makedirs(os.path.join(d, "Default"))
        # Not an app: no Local State.
        touch(os.path.join(self.roaming, "NotAnApp", "Network", "Cookies"))
        # A known browser: must not be reported again as an app.
        self.chrome = os.path.join(self.local, "Google", "Chrome", "User Data")
        touch(os.path.join(self.chrome, "Local State"), b"{}")
        os.makedirs(os.path.join(self.chrome, "Default"))

    def discover(self):
        with patch.object(browser, "ROAMING", self.roaming), \
                patch.object(browser, "LOCAL", self.local), \
                patch.object(browser, "CHROMIUM_ROOTS", [("chrome", self.chrome)]), \
                patch.object(browser.sys, "platform", "win32"):
            return dict(browser._app_roots())

    @unittest.skipUnless(sys.platform == "win32", "Windows-only behaviour")
    def test_found_by_contents_with_readable_labels(self):
        found = self.discover()
        self.assertEqual(set(found), {"app:slack", "app:msteams", "app:proton drive",
                                      "app:proton vpn"})
        self.assertTrue(found["app:msteams"].endswith("EBWebView"))
        self.assertNotIn(self.chrome, found.values())

    def test_linux_without_app_folders_finds_nothing(self):
        # Linux and macOS discovery is covered in test_discovery_and_fingerprint_gaps.py.
        home = tempfile.mkdtemp(prefix="home_")
        with patch.object(browser.sys, "platform", "linux"), \
                patch.object(browser.os.path, "expanduser", lambda _v: home), \
                patch.dict(os.environ, {"XDG_CONFIG_HOME": ""}):
            self.assertEqual(browser._app_roots(), [])


class TestAppIsScannedLikeABrowser(unittest.TestCase):
    def test_cookie_inside_an_app_is_a_contact_finding(self):
        app = tempfile.mkdtemp(prefix="discord_")
        touch(os.path.join(app, "Local State"), b"{}")
        cookie_db(os.path.join(app, "Network", "Cookies"), "." + BAD)
        ctx = ScanContext(iocs=IocSet([Indicator(BAD, "cc", "primary", "domain", "t")],
                                      "t.txt", None), emit=lambda _m: None)
        with patch.object(browser, "CHROMIUM_ROOTS", []), \
                patch.object(browser, "FIREFOX_ROOTS", []), \
                patch.object(browser, "APP_ROOTS", [("app:discord", app)]):
            r = browser.run(ctx)
        self.assertEqual([(h.indicator, h.evidence) for h in r.hits], [(BAD, EV_CONTACTED)])
        self.assertTrue(any(c.name.startswith("app:discord:") and c.ran for c in r.checks))
        self.assertEqual(r.submetrics["desktop_apps_found"], 1)


class TestAppWebCacheIsLeftToTheFullScan(unittest.TestCase):
    def run_app(self, full):
        app = tempfile.mkdtemp(prefix="steam_")
        touch(os.path.join(app, "Local State"), b"{}")
        touch(os.path.join(app, "Local Storage", "leveldb", "000001.log"), b"nothing here")
        touch(os.path.join(app, "Cache", "Cache_Data", "f_000001"),
              ("cached page https://" + BAD + "/x").encode())
        ctx = ScanContext(iocs=IocSet([Indicator(BAD, "cc", "primary", "domain", "t")],
                                      "t.txt", None), emit=lambda _m: None, full=full)
        with patch.object(browser, "CHROMIUM_ROOTS", []), \
                patch.object(browser, "FIREFOX_ROOTS", []), \
                patch.object(browser, "APP_ROOTS", [("app:steam", app)]):
            return browser.run(ctx)

    def test_default_skips_it_and_says_so(self):
        r = self.run_app(full=False)
        self.assertEqual(r.hits, [])
        gap = [c for c in r.checks if c.name == "desktop-app web caches"]
        self.assertEqual(len(gap), 1)
        self.assertFalse(gap[0].ran)
        self.assertIn("full scan", gap[0].reason)

    def test_full_scan_reads_it(self):
        r = self.run_app(full=True)
        self.assertEqual([h.indicator for h in r.hits], [BAD])
        self.assertNotIn("desktop-app web caches", [c.name for c in r.checks])


class TestDiscoveryStaysOffWhenScopeIsExplicit(unittest.TestCase):
    def test_patched_roots_never_trigger_discovery(self):
        ctx = ScanContext(iocs=IocSet([Indicator(BAD, "cc", "primary", "domain", "t")],
                                      "t.txt", None), emit=lambda _m: None)
        with patch.object(browser, "CHROMIUM_ROOTS", []), \
                patch.object(browser, "FIREFOX_ROOTS", []), \
                patch.object(browser, "_app_roots",
                             side_effect=AssertionError("read the real AppData")):
            r = browser.run(ctx)
        self.assertEqual(r.submetrics["desktop_apps_found"], 0)


if __name__ == "__main__":
    unittest.main()
