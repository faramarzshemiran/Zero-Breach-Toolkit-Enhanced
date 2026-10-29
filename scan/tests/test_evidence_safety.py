"""Evidence safety: reports never replace browser files read during a scan,
profile searches report where they stopped, sidecar files are checked before
use, provenance stays with its own record, and an unknown Safari visit origin
is never treated as a visit on this phone."""
import contextlib
import hashlib
import io
import os
import sqlite3
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import cli
from zbtriage.context import ScanContext
from zbtriage.iocs import Indicator, IocSet
from zbtriage.modules import browser, ios
from test_ios_upgrade import backup, db_bytes
from test_followup_fixes import bundle

VISIT = 13400000000000000


@pytest.fixture(params=("source", "bundle"))
def safety_api(request, bundle):
    if request.param == "bundle":
        return types.SimpleNamespace(entry=bundle, browser=bundle,
                                     browser_run=bundle.run_browser, ios_run=bundle.run_ios)
    return types.SimpleNamespace(entry=cli, browser=browser,
                                 browser_run=browser.run, ios_run=ios.run)


def _ctx(root="", **kw):
    iocs = IocSet([Indicator(v, "infrastructure", "primary", "domain", "fixture")
                   for v in ("fixture.invalid", "second.invalid")], "fixture", None)
    return ScanContext(iocs, phone_path=str(root) if root else "", emit=lambda _: None, **kw)


def _history(folder, host):
    folder.mkdir(parents=True, exist_ok=True)
    with contextlib.closing(sqlite3.connect(str(folder / "History"))) as con:
        con.execute("CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,last_visit_time INTEGER)")
        con.execute("INSERT INTO urls VALUES(1,?,?,?)", ("https://" + host, "", VISIT))
        con.commit()


@pytest.mark.parametrize("output", ("--json", "--share-json", "--report"))
def test_a_report_cannot_replace_a_file_in_the_selected_profile(tmp_path, safety_api, output):
    feed = tmp_path / "fixture.txt"
    feed.write_text("fixture.invalid\tdelivery\tprimary\tfixture\n")
    profile = tmp_path / "Default"
    _history(profile, "ordinary.invalid")
    with contextlib.closing(sqlite3.connect(str(profile / "Cookies"))) as con:
        con.execute("CREATE TABLE cookies(host_key TEXT,name TEXT,creation_utc INTEGER)")
        con.commit()
    before = (profile / "Cookies").read_bytes()
    args = ["--iocs", str(feed), "--scan-type", "targeted", "--target", str(profile / "History"),
            output, str(profile / "Cookies"), "--no-menu", "--no-banner"]
    if safety_api.entry is not cli:
        args.append("--no-pause")
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
            patch.object(safety_api.entry, "_force_utf8_io", lambda: None):
        code = safety_api.entry.main(args)
    assert code != 0
    assert (profile / "Cookies").read_bytes() == before


def test_a_profile_below_the_search_depth_is_a_gap_not_clean(tmp_path, safety_api):
    _history(tmp_path / "shallow", "ordinary.invalid")
    deep = tmp_path.joinpath(*("d{}".format(n) for n in range(browser._TARGET_SEARCH_DEPTH + 2)), "Default")
    _history(deep, "fixture.invalid")
    r = safety_api.browser_run(_ctx(targets=(str(tmp_path),)))
    gaps = [c.reason for c in r.checks if not c.ran]
    assert r.status != "CLEAN"
    assert any("deeper folder" in g for g in gaps)
    assert len(safety_api.browser_run(_ctx(targets=(str(deep),))).hits) == 1


@pytest.mark.parametrize("suffix", ("-wal", "-shm", "-journal"))
def test_sidecar_files_are_checked_before_anything_follows_them(tmp_path, safety_api, suffix):
    browser = safety_api.browser
    main = tmp_path / "History"
    main.write_bytes(b"SQLite format 3\0" + bytes(100))
    wal = str(main) + suffix
    real_guard, real_exists, real_size = browser.path_problem, os.path.exists, os.path.getsize
    touched = []

    def guard(path):
        return "refused planted redirection" if os.fspath(path) == wal else real_guard(path)

    def exists(path):
        if os.fspath(path) == wal:
            touched.append("exists")
        return real_exists(path)

    def getsize(path):
        if os.fspath(path) == wal:
            touched.append("getsize")
        return real_size(path)

    with patch.object(browser, "path_problem", guard), \
            patch.object(browser.os.path, "exists", exists), \
            patch.object(browser.os.path, "getsize", getsize):
        copied, incomplete = browser.copy_locked(str(main))
        browser._discard_snapshot(os.path.dirname(copied))
    assert touched == []
    assert "could not copy " + suffix in incomplete


def test_provenance_stays_with_its_own_record_past_the_listing_limit(tmp_path, safety_api):
    raw1, _ = db_bytes(tmp_path, "CREATE TABLE tabs(url)",
                       [("INSERT INTO tabs VALUES(?)", ("fixture.invalid",))] * 100
                       + [("INSERT INTO tabs VALUES(?)", ("second.invalid",))])
    raw2, _ = db_bytes(tmp_path, "CREATE TABLE tabs(url)",
                       [("INSERT INTO tabs VALUES(?)", ("fixture.invalid",))])
    evidence = tmp_path / "backup"
    backup(evidence, [("HomeDomain", "Library/Safari/BrowserState.db", raw1),
                      ("HomeDomain", "Library/Safari/Profiles/other/BrowserState.db", raw2)])
    r = safety_api.ios_run(_ctx(evidence))
    assert r.submetrics.get("matching_records_not_listed") == 1
    for h in r.hits:
        if not h.provenance:
            continue
        assert h.artifact == h.provenance["source"]
        assert hashlib.sha256(Path(h.artifact).read_bytes()).hexdigest() == h.provenance["sha256"]
        assert h.location.endswith(":record " + h.provenance["record_id"])


def test_an_unknown_safari_visit_origin_is_a_reference_with_a_gap(tmp_path, safety_api):
    raw, _ = db_bytes(tmp_path, "CREATE TABLE history_items(id,url); CREATE TABLE history_visits(history_item,visit_time)",
                      [("INSERT INTO history_items VALUES(1,?)", ("https://fixture.invalid/",)),
                       ("INSERT INTO history_visits VALUES(1,700000000)", ())])
    evidence = tmp_path / "backup"
    backup(evidence, [("HomeDomain", "Library/Safari/History.db", raw)])
    r = safety_api.ios_run(_ctx(evidence))
    assert [h.evidence for h in r.hits] == ["referenced"]
    assert any(not c.ran and c.name.startswith("ios:safari") and "origin" in c.reason for c in r.checks)
