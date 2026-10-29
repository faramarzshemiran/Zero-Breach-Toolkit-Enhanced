"""Phone recovery and additional artifacts; synthetic inputs only."""
import contextlib
import hashlib
import json
import sqlite3
from unittest.mock import patch

import pytest

from zbtriage.iocs import Indicator, IocSet
from zbtriage.modules import android, ios
from zbtriage.result import ModuleResult
from test_expanded_capabilities import BAD, context, ios_fixture
from test_followup_fixes import bundle


def artifact_path(root, domain, relative):
    fid = hashlib.sha1((domain + "-" + relative).encode()).hexdigest()
    return root / fid[:2] / fid


def add_artifact(root, domain, relative, schema):
    path = artifact_path(root, domain, relative)
    path.parent.mkdir(exist_ok=True)
    with contextlib.closing(sqlite3.connect(path)) as db:
        db.executescript(schema)
        db.commit()
    with contextlib.closing(sqlite3.connect(root / "Manifest.db")) as db:
        db.execute("INSERT INTO Files VALUES(?,?,?,?,?)", (path.name, domain, relative, 1, b""))
        db.commit()
    return path


@pytest.mark.parametrize("kind", ["safari", "processes"])
@pytest.mark.parametrize("bad", ["utf8", "oversize"])
def test_nonmessage_bad_row_preserves_both_neighbours(tmp_path, bundle, kind, bad):
    ios_fixture(tmp_path)
    domain, relative = (("HomeDomain", "Library/Safari/History.db") if kind == "safari"
                        else ("WirelessDomain", "Library/Databases/DataUsage.sqlite"))
    path = artifact_path(tmp_path, domain, relative)
    with contextlib.closing(sqlite3.connect(path)) as db:
        if kind == "safari":
            db.executescript("DELETE FROM history_visits; DELETE FROM history_items;")
            db.execute("INSERT INTO history_items VALUES(1,?)", ("https://" + BAD + "/before",))
            if bad == "utf8":
                db.execute("INSERT INTO history_items VALUES(2,CAST(x'80' AS TEXT))")
            else:
                db.execute("INSERT INTO history_items VALUES(2,?)", ("x" * (3 * 1024 * 1024),))
            db.execute("INSERT INTO history_items VALUES(3,?)", ("https://" + BAD + "/after",))
            db.executemany("INSERT INTO history_visits(history_item,visit_time) VALUES(?,700000000)", [(1,), (2,), (3,)])
        else:
            db.execute("DELETE FROM ZPROCESS")
            db.execute("INSERT INTO ZPROCESS VALUES('fixtureproc')")
            if bad == "utf8":
                db.execute("INSERT INTO ZPROCESS VALUES(CAST(x'80' AS TEXT))")
            else:
                db.execute("INSERT INTO ZPROCESS VALUES(?)", ("x" * (3 * 1024 * 1024),))
            db.execute("INSERT INTO ZPROCESS VALUES('fixtureproc')")
        db.commit()
    for reader in (ios.run, bundle.run_ios):
        r = reader(context(phone_path=str(tmp_path)))
        hits = [h for h in r.hits if relative in h.location]
        assert len(hits) == 2
        assert {h.location.rsplit(" ", 1)[-1] for h in hits} == {"1", "3"}
        assert all(h.artifact == str(path) for h in hits)
        assert r.skipped == 1
        gaps = [c.reason for c in r.checks if c.name == "ios:" + kind and not c.ran]
        assert len(gaps) == 1 and "artifact missing" not in gaps[0]
        assert ("undecodable" if bad == "utf8" else "limit") in gaps[0]


def test_safari_date_decode_and_missing_join_are_counted(tmp_path, bundle):
    ios_fixture(tmp_path)
    path = artifact_path(tmp_path, "HomeDomain", "Library/Safari/History.db")
    with contextlib.closing(sqlite3.connect(path)) as db:
        db.execute("UPDATE history_visits SET visit_time=CAST(x'80' AS TEXT)")
        db.execute("INSERT INTO history_visits(history_item,visit_time) VALUES(999,700000000)")
        db.execute("INSERT INTO history_items VALUES(2,?)", ("https://" + BAD,))
        db.execute("INSERT INTO history_visits(history_item,visit_time) VALUES(2,700000001)")
        db.commit()
    for reader in (ios.run, bundle.run_ios):
        r = reader(context(phone_path=str(tmp_path)))
        assert r.skipped == 2
        assert any(h.evidence == "contacted" and "Safari" in h.location for h in r.hits)
        assert sum(not c.ran and c.name == "ios:safari" for c in r.checks) == 2


def browser_fixture(root, browser_kind, local=True, origin_metadata=True):
    if browser_kind == "chrome":
        domain, relative = "AppDomain-com.google.chrome", "Library/Application Support/Google/Chrome/Default/History"
        schema = "CREATE TABLE urls(id INTEGER,url TEXT); CREATE TABLE visits(id INTEGER,url INTEGER,visit_time INTEGER,originator_cache_guid TEXT);"
        if origin_metadata:
            schema += "CREATE TABLE visit_source(id INTEGER,source INTEGER);"
        path = add_artifact(root, domain, relative, schema)
        with contextlib.closing(sqlite3.connect(path)) as db:
            db.execute("INSERT INTO urls VALUES(1,?)", ("https://" + BAD + "/?q=sub." + BAD,))
            db.execute("INSERT INTO visits VALUES(1,1,13000000000000000,?)", ("" if local else "other-device",))
            if origin_metadata and not local:
                db.execute("INSERT INTO visit_source VALUES(1,0)")
            db.commit()
    else:
        domain, relative = "AppDomainGroup-group.org.mozilla.ios.Firefox", "profile.profile/browser.db"
        schema = "CREATE TABLE history(id INTEGER,url TEXT); CREATE TABLE visits(siteID INTEGER,date INTEGER" + (",is_local INTEGER" if origin_metadata else "") + ");"
        path = add_artifact(root, domain, relative, schema)
        with contextlib.closing(sqlite3.connect(path)) as db:
            db.execute("INSERT INTO history VALUES(1,?)", ("https://" + BAD + "/?q=sub." + BAD,))
            db.execute("INSERT INTO visits VALUES(1,1600000000000000" + (",?" if origin_metadata else "") + ")", (int(local),) if origin_metadata else ())
            db.commit()
    return path


@pytest.mark.parametrize("browser_kind", ["chrome", "firefox"])
@pytest.mark.parametrize("local,metadata", [(True, True), (False, True), (True, False)])
def test_ios_browser_history_local_sync_and_unknown_origins(tmp_path, bundle, browser_kind, local, metadata):
    ios_fixture(tmp_path)
    path = browser_fixture(tmp_path, browser_kind, local, metadata)
    for reader in (ios.run, bundle.run_ios):
        ctx = context(phone_path=str(tmp_path))
        ctx.iocs = IocSet([Indicator(v, "infrastructure", "primary", "domain", "fixture") for v in (BAD, "sub." + BAD)], "fixture", None)
        r = reader(ctx)
        hits = [h for h in r.hits if h.artifact == str(path)]
        assert {(h.indicator, h.evidence) for h in hits} == {
            (BAD, "contacted" if local and metadata else "referenced"), ("sub." + BAD, "referenced")}
        assert all(h.observed for h in hits)
        gaps = [c for c in r.checks if c.name == "ios:" + browser_kind + "-history" and not c.ran]
        assert bool(gaps) == (not metadata)


@pytest.mark.parametrize("browser_kind", ["chrome", "firefox"])
def test_optional_browser_present_bad_schema_is_gap(tmp_path, bundle, browser_kind):
    ios_fixture(tmp_path)
    path = browser_fixture(tmp_path, browser_kind)
    with contextlib.closing(sqlite3.connect(path)) as db:
        db.execute("DROP TABLE visits")
        db.execute("CREATE VIEW visits AS SELECT 1")
        db.commit()
    for reader in (ios.run, bundle.run_ios):
        r = reader(context(phone_path=str(tmp_path)))
        assert any(c.name == "ios:" + browser_kind + "-history" and not c.ran for c in r.checks)
        assert any(h.evidence == "received" for h in r.hits)


def test_optional_browser_absence_adds_no_gap(tmp_path, bundle):
    ios_fixture(tmp_path)
    for reader in (ios.run, bundle.run_ios):
        r = reader(context(phone_path=str(tmp_path)))
        assert all(c.ran for c in r.checks)
        assert not any(c.name in ("ios:chrome-history", "ios:firefox-history") for c in r.checks)


def android_context():
    ctx = context()
    ctx.iocs = IocSet([Indicator("com.fixture.spy", "artifact", "primary", "app-id", "fixture")], "fixture", None)
    return ctx


def test_android_json_matches_only_process_identity(tmp_path, bundle):
    records = [
        {"pid": 1, "command_line": ["system_server", "com.fixture.spy"], "env": ["com.fixture.spy"]},
        {"pid": 2, "command_line": ["com.fixture.spy:remote", "unsearched arguments"]},
        {"pid": 3, "command_line": ["com.fixture.spy"]},
    ]
    path = tmp_path / "processes.json"
    path.write_text(json.dumps(records))
    for reader in (android._an_processes, bundle._an_processes):
        r = ModuleResult("android")
        reader(r, android_context(), str(tmp_path))
        assert len(r.hits) == 1 and "com.fixture.spy:remote" in r.hits[0].location
        assert r.hits[0].artifact == str(path)
        assert r.submetrics["android_processes"] == 3
        assert all(c.ran for c in r.checks)


@pytest.mark.parametrize("bad", [None, {}, {"pid": 2, "command_line": "com.fixture.spy"}, {"pid": True, "command_line": ["com.fixture.spy"]}])
def test_android_malformed_json_rows_keep_later_match(tmp_path, bundle, bad):
    (tmp_path / "processes.json").write_text(json.dumps([bad, {"pid": 5, "command_line": ["com.fixture.spy"]}]))
    for reader in (android._an_processes, bundle._an_processes):
        r = ModuleResult("android")
        reader(r, android_context(), str(tmp_path))
        assert len(r.hits) == 1 and r.skipped == 1
        assert any(not c.ran for c in r.checks)


def test_android_bad_json_does_not_hide_readable_text(tmp_path, bundle):
    (tmp_path / "processes.json").write_text('{"unsupported":"schema"}')
    (tmp_path / "processes.txt").write_text("USER PID NAME\nu0_a1 5 com.fixture.spy\n")
    for reader in (android._an_processes, bundle._an_processes):
        r = ModuleResult("android")
        reader(r, android_context(), str(tmp_path))
        assert len(r.hits) == 1
        assert any(not c.ran and "processes.json" in c.reason for c in r.checks)


def test_android_process_path_is_checked_before_exists(tmp_path):
    r = ModuleResult("android")
    with patch.object(android, "path_problem", return_value="refused"), patch.object(android.os.path, "lexists", side_effect=AssertionError("unchecked access")):
        android._an_processes(r, android_context(), str(tmp_path))
    assert not r.hits and any(not c.ran for c in r.checks)
