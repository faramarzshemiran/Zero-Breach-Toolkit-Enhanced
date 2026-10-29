"""Regressions for evidence interpretation.

One publisher revoking one STIX object no longer withdraws a different, active
object for the same value. A stalkerware match in Android intrusion logs stays a
phone finding. A Chromium visit synced from another device is not contact by
this computer. A browser database built to run forever is refused as a gap.
"""
import contextlib
import datetime
import json
import os
import sqlite3
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import report
from zbtriage.evidence import _withdrawn_only
from zbtriage.iocs import Indicator, IocSet, load_any
from zbtriage.modules import browser
from zbtriage.result import EV_CONTACTED, EV_REFERENCED, Hit, ModuleResult
from test_expanded_capabilities import BAD, context
from test_followup_fixes import bundle  # noqa: F401  (pytest fixture)

PUBLISHER = "identity--11111111-1111-4111-8111-111111111111"


# --- 1. withdrawals are decided per STIX object --------------------------------

def _indicator(oid, modified, revoked):
    return {"type": "indicator", "spec_version": "2.1", "id": oid, "created_by_ref": PUBLISHER,
            "created": "2026-01-01T00:00:00Z", "modified": modified, "revoked": revoked,
            "pattern_type": "stix", "pattern": "[domain-name:value = '" + BAD + "']",
            "valid_from": "2026-01-01T00:00:00Z"}


def _bundle_file(tmp_path, *indicators):
    objects = [{"type": "identity", "spec_version": "2.1", "id": PUBLISHER, "name": "Publisher",
                "created": "2026-01-01T00:00:00Z", "modified": "2026-01-01T00:00:00Z",
                "identity_class": "organization"}] + list(indicators)
    path = tmp_path / "feed.stix2"
    path.write_text(json.dumps({"type": "bundle", "id": "bundle--22222222-2222-4222-8222-222222222222",
                                "objects": objects}), encoding="utf-8")
    return str(path)


def _status(iocs):
    r = ModuleResult("browser")
    r.ran("history")
    r.add_hit(Hit(BAD, "fixture History", "recorded visit", evidence=EV_CONTACTED))
    d = report.build_document(iocs, [r], datetime.datetime.now())
    return d["verdict"]["status"], d["exit_code"]


def test_revoking_one_object_leaves_another_active_object_in_force(tmp_path):
    path = _bundle_file(tmp_path,
                        _indicator("indicator--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "2026-02-01T00:00:00Z", False),
                        _indicator("indicator--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "2026-03-01T00:00:00Z", True))
    assert _status(load_any(path)) == ("INDICATORS_FOUND", 2)


def test_a_newer_revoked_version_of_the_same_object_still_withdraws_it(tmp_path):
    oid = "indicator--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    old = load_any(_bundle_file(tmp_path, _indicator(oid, "2026-02-01T00:00:00Z", False)))
    new_path = tmp_path / "new"
    new_path.mkdir()
    new = load_any(_bundle_file(new_path, _indicator(oid, "2026-03-01T00:00:00Z", True)))
    records = [json.loads(c) for s in (old, new) for i in s.indicators for c in i.contexts]
    assert _withdrawn_only(records)


def test_records_without_an_id_group_by_publisher_as_before():
    records = [{"publisher": "P", "modified": "2026-02-01", "revoked": False},
               {"publisher": "P", "modified": "2026-03-01", "revoked": True}]
    assert _withdrawn_only(records)


# --- 2. phone readers keep stalkerware findings ------------------------------------

@pytest.mark.parametrize("reader", ["android-intrusion", "android", "ios"])
def test_a_stalkerware_match_on_a_phone_reader_stays_a_finding(bundle, reader):
    source = (IocSet, Indicator, ModuleResult, Hit, report.build_document)
    built = (bundle.IocSet, bundle.Indicator, bundle.ModuleResult, bundle.Hit, bundle.build_document)
    for api in (source, built):
        make_set, make_ind, make_result, make_hit, build = api
        iocs = make_set([make_ind(BAD, "stalkerware", "primary", "domain", "fixture")], "fixture", None)
        r = make_result(reader)
        r.ran("dns")
        r.add_hit(make_hit(BAD, "phone record", "DNS lookup", evidence="dns-record", tier="stalkerware"))
        d = build(iocs, [r], datetime.datetime.now())
        assert (d["verdict"]["status"], d["exit_code"]) == ("INDICATORS_FOUND", 2), (api, reader)


def test_a_computer_reader_still_treats_a_stalkerware_site_as_worth_a_look():
    iocs = IocSet([Indicator(BAD, "stalkerware", "primary", "domain", "fixture")], "fixture", None)
    r = ModuleResult("browser")
    r.ran("history")
    r.add_hit(Hit(BAD, "History", "visit", evidence=EV_CONTACTED, tier="stalkerware"))
    d = report.build_document(iocs, [r], datetime.datetime.now())
    assert d["exit_code"] == 0 and len(d["worth_a_look"]) == 1


def test_every_phone_only_reader_is_exempt():
    assert report._phone_modules() == {"android", "android-intrusion", "ios"}


# --- 3. synced visits ----------------------------------------------------------

def _history(root, visits, visit_source=None, with_guid=True):
    """urls row 1 for BAD; `visits` = [(visit_id, originator_cache_guid)]."""
    with contextlib.closing(sqlite3.connect(root / "History")) as db:
        db.execute("CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,last_visit_time INTEGER)")
        db.execute("INSERT INTO urls VALUES(1,?,'',13000000000000000)", ("https://" + BAD + "/",))
        if visits is not None:
            guid = ",originator_cache_guid TEXT" if with_guid else ""
            db.execute("CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER,visit_time INTEGER" + guid + ")")
            for vid, origin in visits:
                if with_guid:
                    db.execute("INSERT INTO visits VALUES(?,1,13000000000000000,?)", (vid, origin))
                else:
                    db.execute("INSERT INTO visits VALUES(?,1,13000000000000000)", (vid,))
        if visit_source is not None:
            db.execute("CREATE TABLE visit_source(id INTEGER PRIMARY KEY,source INTEGER NOT NULL)")
            db.executemany("INSERT INTO visit_source VALUES(?,?)", visit_source)
        db.commit()


@pytest.mark.parametrize("visits, visit_source, with_guid, grade, lead", [
    ([(1, "OTHER-DEVICE")], None, True, EV_REFERENCED, True),           # synced only
    ([(1, "OTHER-DEVICE"), (2, "")], None, True, EV_CONTACTED, False),   # also visited here
    ([(1, None)], None, True, EV_CONTACTED, False),                      # NULL origin is local
    ([(1, None)], [(1, 0)], False, EV_REFERENCED, True),                 # older sync marker
    ([(1, None)], [(1, 3)], False, EV_CONTACTED, False),                 # imported from Firefox
    (None, None, True, EV_CONTACTED, False),                             # no visits table
])
def test_only_a_local_visit_is_contact(tmp_path, bundle, visits, visit_source, with_guid, grade, lead):
    _history(tmp_path, visits, visit_source, with_guid)
    for reader in (browser.run, bundle.run_browser):
        r = reader(context(targets=(str(tmp_path),)))
        assert {(h.indicator, h.evidence) for h in r.hits} == {(BAD, grade)}
        assert any(l.check == "browser:synced-history" for l in r.leads) is lead


# --- 4. databases built to run forever ----------------------------------------

@pytest.mark.parametrize("schema", [
    "CREATE VIEW urls AS WITH RECURSIVE c(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM c) "
    "SELECT 'https://x.invalid/' || n AS url, '' AS title, 0 AS last_visit_time FROM c;",
    "CREATE TABLE t(x); INSERT INTO t VALUES(1),(2),(3),(4),(5),(6),(7),(8),(9),(10);"
    "CREATE VIEW urls AS SELECT 'https://x.invalid/' AS url, '' AS title, 0 AS last_visit_time "
    "FROM t a, t b, t c, t d, t e, t f, t g, t h, t i, t j;",
])
def test_a_history_view_is_refused_quickly_as_a_gap(tmp_path, bundle, schema):
    with contextlib.closing(sqlite3.connect(tmp_path / "History")) as db:
        db.executescript(schema)
        db.commit()
    for reader in (browser.run, bundle.run_browser):
        started = time.monotonic()
        r = reader(context(targets=(str(tmp_path),)))
        assert time.monotonic() - started < 10
        assert not r.hits
        assert any("structure no browser creates" in (c.reason or "") for c in r.checks if not c.ran)


def test_the_time_limit_turns_a_slow_read_into_a_gap(tmp_path, bundle, monkeypatch):
    _history(tmp_path, [(1, "")])
    # Enough rows that the query runs past SQLite's first progress check.
    with contextlib.closing(sqlite3.connect(tmp_path / "History")) as db:
        db.executemany("INSERT INTO urls(url,title,last_visit_time) VALUES(?,'',0)",
                       [("https://row%d.invalid/" % n,) for n in range(20000)])
        db.commit()
    for module, reader in ((browser, browser.run), (bundle, bundle.run_browser)):
        monkeypatch.setattr(module, "_DB_SECONDS", -1)
        r = reader(context(targets=(str(tmp_path),)))
        assert not r.hits
        assert any("took longer than" in (c.reason or "") for c in r.checks if not c.ran)
