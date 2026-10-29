"""Regressions for launch-readiness fixes.

A selected browser folder one level off no longer reads as clean; Chromium times
are local like every other report time; a damaged database is not called locked;
phone gaps carry no exception dumps or paths; a mistyped phone folder stops with
an error; menu lines fit an 80-column console.
"""
import contextlib
import datetime
import io
import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import cli, menu, report
from zbtriage.modules import android, browser
from zbtriage.result import NOT_APPLICABLE
from test_expanded_capabilities import BAD, context
from test_followup_fixes import bundle  # noqa: F401  (pytest fixture)

VISIT_US = 13400000000000000          # a Chromium timestamp (microseconds since 1601 UTC)


def _chrome_profile(folder):
    folder.mkdir(parents=True)
    with contextlib.closing(sqlite3.connect(folder / "History")) as db:
        db.execute("CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,last_visit_time INTEGER)")
        db.execute("INSERT INTO urls VALUES(1,?,'',?)", ("https://" + BAD + "/", VISIT_US))
        db.commit()
    return folder


def _firefox_profile(folder):
    folder.mkdir(parents=True)
    with contextlib.closing(sqlite3.connect(folder / "places.sqlite")) as db:
        db.execute("CREATE TABLE moz_places(id INTEGER PRIMARY KEY,url TEXT,title TEXT,"
                   "last_visit_date INTEGER,visit_count INTEGER)")
        db.execute("INSERT INTO moz_places VALUES(1,?,'',1760000000000000,1)", ("https://" + BAD + "/",))
        db.commit()
    return folder


# --- targeted browser selection ---------------------------------------------------

@pytest.mark.parametrize("pick", ["browser folder", "history file", "firefox profiles folder"])
def test_a_browser_folder_one_level_off_is_still_read(tmp_path, bundle, pick):
    if pick == "firefox profiles folder":
        _firefox_profile(tmp_path / "Profiles" / "abc.default-release")
        target = tmp_path / "Profiles"
    else:
        _chrome_profile(tmp_path / "Chrome" / "User Data" / "Default")
        (tmp_path / "Chrome" / "User Data" / "Local State").write_text("{}")
        target = tmp_path / "Chrome" if pick == "browser folder" else \
            tmp_path / "Chrome" / "User Data" / "Default" / "History"
    for reader in (browser.run, bundle.run_browser):
        r = reader(context(targets=(str(target),)))
        assert {h.indicator for h in r.hits} == {BAD}, (pick, reader)


def test_no_browser_profile_is_not_applicable_rather_than_clean(tmp_path, bundle):
    (tmp_path / "just files").mkdir()
    (tmp_path / "just files" / "notes.txt").write_text("hello")
    for reader in (browser.run, bundle.run_browser):
        r = reader(context(targets=(str(tmp_path / "just files"),)))
        assert r.status == NOT_APPLICABLE and not r.hits


def test_profile_search_does_not_follow_links(tmp_path):
    outside = _chrome_profile(tmp_path / "outside" / "Default")
    inside = tmp_path / "inside"
    inside.mkdir()
    try:
        os.symlink(str(outside), str(inside / "link"), target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links need extra rights here")
    chromium, firefox, gaps = browser._browser_targeted_roots(str(inside))
    assert chromium == [] and firefox == []
    assert any("not followed" in g for g in gaps)


# --- Chromium times are local ---------------------------------------------------

def test_chromium_visit_time_is_shown_in_local_time(tmp_path):
    _chrome_profile(tmp_path / "Default")
    r = browser.run(context(targets=(str(tmp_path / "Default"),)))
    unix = VISIT_US / 1e6 - 11644473600
    expected = datetime.datetime.fromtimestamp(unix).isoformat(timespec="seconds")
    assert {h.observed for h in r.hits if h.evidence == "contacted"} == {expected}


# --- gap wording ------------------------------------------------------------------

def test_a_damaged_database_is_not_reported_as_locked():
    lines = report._gap_lines(["browser/selected:history: C:/x/History is damaged or is not a "
                               "database a browser writes, so it was not read."])
    assert not any("locked" in line for line in lines)


def test_a_running_browser_is_still_reported_as_locked():
    lines = report._gap_lines(["browser/edge:cookies: Edge was running, so one of its databases "
                               "was locked and could not be checked (Cookies)."])
    assert any("Edge" in line and "locked" in line for line in lines)


def test_a_damaged_database_note_says_so_plainly():
    note = browser._locked_note("C:/x/History", sqlite3.DatabaseError("file is not a database"))
    assert "damaged" in note and "locked" not in note


def test_phone_gaps_carry_no_exception_dump_or_path():
    missing = FileNotFoundError(2, "The system cannot find the file specified", "C:/Users/x/aqf/selinux.txt")
    assert android._an_why(missing) == "not in the collection"
    denied = PermissionError(13, "Permission denied", "C:/Users/x/aqf/logcat.txt")
    assert android._an_why(denied) == "could not be read (Permission denied)"


# --- a mistyped phone folder ------------------------------------------------------

def test_a_missing_phone_folder_stops_with_an_error(tmp_path, capsys):
    with pytest.raises(SystemExit) as stop:
        cli._parse(["--phone", str(tmp_path / "no such folder")])
    assert stop.value.code != 0
    assert "nothing was checked" in capsys.readouterr().err


# --- menu fits an 80-column console --------------------------------------------

class _Terminal(io.StringIO):
    def isatty(self):
        return True


def test_every_menu_line_fits_80_columns():
    err = _Terminal()
    menu.choose_scan(cli._parse([]), lambda: None, stdin=_Terminal("0\n"), stderr=err, stdout_visible=True)
    assert max(len(line) for line in err.getvalue().splitlines()) <= 80


# --- malformed indicator files, unwritable cache, path guard, correlations -------

def _stix(path, objects):
    import json
    path.write_text(json.dumps({"type": "bundle", "id": "bundle--1", "objects": objects}), encoding="utf-8")
    return str(path)


def test_a_relationship_with_a_non_string_target_does_not_crash_the_import(tmp_path):
    from zbtriage.iocs import load_any
    path = _stix(tmp_path / "x.stix2", [
        {"type": "malware", "id": "malware--1", "name": "X"},
        {"type": "indicator", "id": "indicator--1", "pattern_type": "stix",
         "pattern": "[domain-name:value = '" + BAD + "']"},
        {"type": "relationship", "id": "relationship--1", "relationship_type": "indicates",
         "source_ref": "indicator--1", "target_ref": ["not", "a", "string"]}])
    assert [i.value for i in load_any(path).indicators] == [BAD]


def test_absurdly_nested_json_is_a_clean_indicator_error(tmp_path):
    from zbtriage.iocs import IocError, load_any
    path = tmp_path / "deep.stix2"
    path.write_text('{"type":"bundle","objects":' + "[" * 100000 + "]" * 100000 + "}")
    with pytest.raises(IocError):
        load_any(str(path))


def test_update_into_an_unwritable_cache_is_a_clean_error(tmp_path, capsys, monkeypatch):
    from zbtriage import feeds
    blocker = tmp_path / "a file, not a folder"
    blocker.write_text("x")
    monkeypatch.setattr(feeds, "update", lambda cache, emit=None: (_ for _ in ()).throw(
        PermissionError(13, "Permission denied", str(blocker))))
    assert feeds.update_command(str(blocker / "cache"), None) == 1
    assert "indicator cache could not be written" in capsys.readouterr().err


@pytest.mark.skipif(sys.platform != "win32", reason="junctions are a Windows feature")
def test_the_path_guard_sees_a_junction_in_a_forward_slash_path(tmp_path):
    import subprocess
    from zbtriage.localpaths import path_problem
    (tmp_path / "outside").mkdir()
    junction = tmp_path / "junction"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(tmp_path / "outside")],
                   capture_output=True)
    if not junction.exists():
        pytest.skip("junction could not be created")
    assert path_problem(str(junction) + "\\x")
    assert path_problem(str(junction).replace("\\", "/") + "/x")


def test_correlations_tolerate_empty_fields():
    from zbtriage.evidence import evidence_correlations
    modules = {"m": {"hits": [
        {"indicator": BAD, "evidence": "contacted", "observed": None, "location": None,
         "artifact": None, "kind": "domain"},
        {"indicator": BAD, "evidence": "contacted", "observed": 5, "location": "x",
         "artifact": "y", "kind": "domain"}]}}
    assert len(evidence_correlations(modules)) == 1


def test_a_withdrawn_only_match_does_not_also_say_treat_it_as_serious(tmp_path):
    import datetime as _dt
    from zbtriage.iocs import load_any
    from zbtriage.result import EV_CONTACTED, Hit, ModuleResult
    path = _stix(tmp_path / "w.stix2", [
        {"type": "indicator", "id": "indicator--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
         "pattern_type": "stix", "pattern": "[domain-name:value = '" + BAD + "']",
         "modified": "2026-03-01T00:00:00Z", "revoked": True}])
    iocs = load_any(path)
    r = ModuleResult("browser")
    r.ran("history")
    r.add_hit(Hit(BAD, "History", "visit", evidence=EV_CONTACTED,
                  tier=iocs.indicators[0].tier))
    text = report.render_human(report.build_document(iocs, [r], _dt.datetime.now()))
    assert "WITHDRAWN" in text
    assert "treat contact as serious" not in text
