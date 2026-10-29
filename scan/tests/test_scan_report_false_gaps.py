"""Two false "could not run" lines seen in a real Windows report.

1. FreeTube keeps its own text file named history.db; Windows ignores case, so
   it was read as Safari's History.db and reported "Safari history unreadable"
   on a PC without Safari. A non-database history.db inside another app is not
   a gap; for Safari itself, or a folder the person chose, it still is.
2. A problem finding Amcache was also printed under Prefetch, and neither said
   that Windows lets only administrators read these records.
"""
import os
import tempfile
import unittest
from unittest.mock import patch

from zbtriage.context import ScanContext
from zbtriage.iocs import Indicator, IocSet
from zbtriage.modules import browser, execution
from test_windows_execution import _we_context, _we_prefetch


def _ctx():
    return ScanContext(iocs=IocSet([Indicator("fixture.invalid", "cc", "primary", "domain", "t")],
                                   "t.txt", None), emit=lambda _m: None)


class TestAppHistoryDbIsNotSafari(unittest.TestCase):
    def _app(self):
        app = tempfile.mkdtemp(prefix="freetube_")
        with open(os.path.join(app, "History.db"), "w", encoding="utf-8") as fh:
            fh.write('{"videoId":"x","title":"t","_id":"1"}\n')
        return app

    def _safari_gaps(self, r):
        return [c for c in r.checks if c.name.endswith("safari-history") and not c.ran]

    def test_app_text_history_is_not_a_gap(self):
        app = self._app()
        with patch.object(browser, "CHROMIUM_ROOTS", []), patch.object(browser, "FIREFOX_ROOTS", []), \
                patch.object(browser, "APP_ROOTS", [("app:freetube", app)]):
            r = browser.run(_ctx())
        self.assertEqual(self._safari_gaps(r), [])
        self.assertTrue(any("not Safari history" in n for n in r.notes))

    def test_a_chosen_folder_still_reports_it(self):
        app = self._app()
        ctx = _ctx()
        ctx.targets = (app,)
        r = browser.run(ctx)
        self.assertTrue(self._safari_gaps(r))


def test_amcache_problem_stays_with_amcache(tmp_path, monkeypatch):
    system = tmp_path / "Windows"
    (system / "Prefetch").mkdir(parents=True)
    (system / "Prefetch" / "FIXTURE.pf").write_bytes(_we_prefetch())
    amcache = str(system / "AppCompat" / "Programs" / "Amcache.hve")
    real = execution.path_problem

    def problem(path):
        if os.path.normcase(str(path)) == os.path.normcase(amcache):
            return "cannot safely inspect {}: [WinError 5] Access is denied".format(amcache)
        return real(path)
    monkeypatch.setattr(execution, "path_problem", problem)
    monkeypatch.setattr(execution.sys, "platform", "win32")
    monkeypatch.setenv("SystemRoot", str(system))
    ctx = _we_context(tmp_path)
    ctx.targets = ()
    r = execution.run(ctx)
    reasons = {c.name: c.reason for c in r.checks if not c.ran}
    assert "Amcache" not in reasons.get("windows-prefetch", ""), reasons
    assert "administrator" in reasons["windows-amcache"]


def test_missing_defender_log_is_explained(monkeypatch):
    from zbtriage.modules import traces
    from zbtriage.result import ModuleResult
    msg = ("Get-WinEvent : There is not an event log on the localhost computer that matches "
           '"Microsoft-Windows-Windows Defender/Operational".')
    monkeypatch.setattr(traces, "_tr_events", lambda *a, **k: ([], msg))
    r = ModuleResult("traces")
    traces._tr_check_defender(r, None, None)
    reason = [c.reason for c in r.checks if c.name == "defender-history"][0]
    assert "another antivirus" in reason and "Get-WinEvent" not in reason
