"""Unreadable message isolation and remaining review cases; synthetic inputs only."""
import contextlib
import datetime
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from unittest.mock import patch

import pytest

from zbtriage import report
from zbtriage.modules import ios, traces
from zbtriage.result import ModuleResult, EV_REFERENCED, EV_PERSISTENCE
from test_expanded_capabilities import context, ios_fixture, BAD
from test_followup_fixes import bundle, fake_registry, sms_path
from test_fix_regressions import build_namespace


@pytest.mark.parametrize("bad", ["70KiB", "over2MiB", "invalid_text", "invalid_date", "large_encoded"])
def test_unreadable_message_preserves_both_neighbours(tmp_path, bundle, bad):
    ios_fixture(tmp_path)
    with contextlib.closing(sqlite3.connect(sms_path(tmp_path))) as db:
        db.execute("DELETE FROM message")
        db.execute("ALTER TABLE message ADD COLUMN attributedBody BLOB")
        db.execute("INSERT INTO message VALUES(?,0,0,NULL)", ("https://" + BAD + "/before",))
        if bad == "invalid_text":
            db.execute("INSERT INTO message VALUES(CAST(x'80' AS TEXT),0,0,NULL)")
        elif bad == "invalid_date":
            db.execute("INSERT INTO message VALUES('ordinary',CAST(x'80' AS TEXT),0,NULL)")
        elif bad == "large_encoded":
            db.execute("INSERT INTO message VALUES(NULL,0,0,?)", (b"x" * (2 * 1024 * 1024 + 100),))
        else:
            db.execute("INSERT INTO message VALUES(?,0,0,NULL)", ("x" * (70000 if bad == "70KiB" else 2 * 1024 * 1024 + 100),))
        db.execute("INSERT INTO message VALUES(?,0,0,NULL)", ("https://" + BAD + "/after",))
        db.commit()
    for reader in (ios.run, bundle.run_ios):
        r = reader(context(phone_path=str(tmp_path)))
        hits = [h for h in r.hits if "SMS/sms.db" in h.location]
        assert len(hits) == 2
        assert {h.location.rsplit(" ", 1)[-1] for h in hits} == {"1", "3"}
        assert r.skipped == 1 and r.checked == 4
        gaps = [c.reason for c in r.checks if c.name == "ios:messages" and not c.ran]
        assert len(gaps) == 1
        expected = ("undecodable text" if bad.startswith("invalid") else
                    "text limit" if bad == "70KiB" else
                    "encoded or unsupported" if bad == "large_encoded" else
                    "database field size limit" if hasattr(sqlite3.Connection, "setlimit") else "text limit")
        # A large encoded body is refused either by SQLite's field-size limit
        # (when the build enforces it on BLOBs) or by the decoder; both are
        # correct, and both keep the neighbouring messages.
        accepted = [expected] + (["database field size limit"] if bad == "large_encoded" else [])
        assert any(text in gaps[0] for text in accepted), gaps[0]
        assert "artifact missing" not in gaps[0]


def test_skipped_oversized_messages_do_not_spend_search_text_budget(tmp_path, bundle):
    ios_fixture(tmp_path)
    with contextlib.closing(sqlite3.connect(sms_path(tmp_path))) as db:
        db.execute("DELETE FROM message")
        db.executemany("INSERT INTO message VALUES(?,0,0)", [("x" * 1000000,)] * 10)
        db.execute("INSERT INTO message VALUES(?,0,0)", ("https://" + BAD,))
        db.commit()
    for reader in (ios.run, bundle.run_ios):
        r = reader(context(phone_path=str(tmp_path)))
        assert any("SMS/sms.db" in h.location for h in r.hits)
        assert r.skipped == 10
        gaps = [c.reason for c in r.checks if c.name == "ios:messages" and not c.ran]
        assert len(gaps) == 1 and "10 occurrences" in gaps[0]


def test_message_recovery_across_row_id_pages(tmp_path, bundle):
    ios_fixture(tmp_path)
    with contextlib.closing(sqlite3.connect(sms_path(tmp_path))) as db:
        db.execute("DELETE FROM message")
        db.executemany("INSERT INTO message VALUES('ordinary',0,0)", [()] * 255)
        db.executemany("INSERT INTO message VALUES(?,0,0)", [
            ("https://" + BAD + "/before",), ("x" * (2 * 1024 * 1024 + 100),),
            ("https://" + BAD + "/after",)])
        db.commit()
    for reader in (ios.run, bundle.run_ios):
        r = reader(context(phone_path=str(tmp_path)))
        hits = [h for h in r.hits if "SMS/sms.db" in h.location]
        assert {h.location.rsplit(" ", 1)[-1] for h in hits} == {"256", "258"}
        assert r.skipped == 1


def test_message_gap_aggregation_retains_counts(tmp_path, bundle):
    ios_fixture(tmp_path)
    with contextlib.closing(sqlite3.connect(sms_path(tmp_path))) as db:
        db.execute("DELETE FROM message")
        db.executemany("INSERT INTO message VALUES(NULL,0,0)", [()] * 1000)
        db.execute("INSERT INTO message VALUES(?,0,0)", ("https://" + BAD,))
        db.commit()
    for api, reader in ((report, ios.run), (bundle, bundle.run_ios)):
        ctx = context(phone_path=str(tmp_path))
        r = reader(ctx)
        assert r.skipped == 1000
        doc = api.build_document(ctx.iocs, [r], datetime.datetime.now())
        gaps = [c for c in doc["modules"]["ios"]["checks"] if not c["ran"]]
        assert len(gaps) == 1 and "1000 occurrences" in gaps[0]["reason"]
        assert len([n for n in doc["modules"]["ios"]["notes"] if "could not run" in n]) == 1
        assert api.render_summary(doc).count("ios:messages") == 1
        assert any("SMS/sms.db" in h.location for h in r.hits)
        lines = api._gap_lines(["fixture: same reason"] * 1000 + ["fixture: different reason"])
        assert len(lines) == 2 and "1000 occurrences" in lines[0]


def _add_shadow_columns(db, columns):
    """Add rowid-alias columns to message. SQLite 3.54 refuses to ADD such a
    column but still creates a table with one, so rebuild the table then."""
    try:
        for column in columns:
            db.execute("ALTER TABLE message ADD COLUMN " + column + " INTEGER DEFAULT 0")
        return
    except sqlite3.OperationalError as exc:
        if "rowid alias" not in str(exc):
            raise
    present = [row[1] for row in db.execute("PRAGMA table_info(message)")]
    sql = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='message'").fetchone()[0]
    missing = [c for c in columns if c not in present]
    db.execute("ALTER TABLE message RENAME TO message_old")
    db.execute(sql[:sql.rindex(")")] + "".join("," + c + " INTEGER DEFAULT 0" for c in missing) + ")")
    names = ",".join(present)
    db.execute("INSERT INTO message(" + names + ") SELECT " + names + " FROM message_old")
    db.execute("DROP TABLE message_old")


@pytest.mark.parametrize("shadow", ["one", "all", "without_rowid"])
def test_message_row_identifier_is_not_a_shadowing_column(tmp_path, bundle, shadow):
    ios_fixture(tmp_path)
    with contextlib.closing(sqlite3.connect(sms_path(tmp_path))) as db:
        if shadow == "without_rowid":
            db.execute("DROP TABLE message")
            db.execute("CREATE TABLE message(id INTEGER PRIMARY KEY,text TEXT,date INTEGER,is_from_me INTEGER) WITHOUT ROWID")
            db.execute("INSERT INTO message VALUES(1,?,0,0)", (BAD,))
        else:
            _add_shadow_columns(db, ["_rowid_"] if shadow == "one" else ["_rowid_", "rowid", "oid"])
        db.commit()
    for reader in (ios.run, bundle.run_ios):
        r = reader(context(phone_path=str(tmp_path)))
        found = any("SMS/sms.db" in h.location for h in r.hits)
        assert found == (shadow == "one")
        gaps = [c.reason for c in r.checks if c.name == "ios:messages" and not c.ran]
        assert bool(gaps) == (shadow != "one")
        if gaps:
            assert "row identif" in gaps[0] or "row index" in gaps[0]


def test_message_row_and_time_limits_still_apply(tmp_path, bundle):
    ios_fixture(tmp_path)
    with contextlib.closing(sqlite3.connect(sms_path(tmp_path))) as db:
        db.execute("INSERT INTO message VALUES(NULL,0,0)")
        db.execute("INSERT INTO message VALUES(?,0,0)", ("https://" + BAD,))
        db.commit()
    for api, reader in ((ios, ios.run), (bundle, bundle.run_ios)):
        with patch.object(api, "_IOS_ROWS", 2):
            r = reader(context(phone_path=str(tmp_path)))
        assert len([h for h in r.hits if "SMS/sms.db" in h.location]) == 1
        assert any(c.name == "ios:messages" and "row limit" in c.reason for c in r.checks)
        # Expired processing deadlines stop even a stream of unreadable rows.
        with contextlib.closing(sqlite3.connect(":memory:")) as db:
            db.execute("CREATE TABLE message(text TEXT,date INTEGER,is_from_me INTEGER)")
            db.execute("INSERT INTO message VALUES(NULL,0,0)")
            result = ModuleResult("ios")
            gaps = []
            with patch.object(api.time, "monotonic", return_value=20):
                rows = list(api._ios_message_rows(db, "SELECT text,date,is_from_me FROM message",
                    {"text","date","is_from_me"}, result, lambda c,r: gaps.append((c,r)), 10))
            assert not rows and "processing budget" in gaps[0][1]


@pytest.mark.parametrize("text,encoding", [
    ("rem. fixture.invalid\r\n", "utf-8"),
    ("rem, fixture.invalid\r\n", "utf-8"),
    (":: note ^\r\nprogram.exe fixture.invalid\r\n", "utf-8"),
    ("program.exe fixture.invalid\r\n", "utf-16"),
])
def test_uninterpreted_batch_forms_are_gaps_not_persistence(tmp_path, monkeypatch, bundle, text, encoding):
    monkeypatch.setitem(sys.modules, "winreg", fake_registry())
    for key in ("APPDATA", "PROGRAMDATA", "SystemRoot"):
        monkeypatch.setenv(key, str(tmp_path))
    root = tmp_path / "Microsoft/Windows/Start Menu/Programs/Startup"
    root.mkdir(parents=True)
    (root / "fixture.cmd").write_bytes(text.encode(encoding))
    for api in (traces, bundle):
        r = ModuleResult("traces")
        api._tr_persistence(r, context())
        assert r.hits and all(h.evidence == EV_REFERENCED for h in r.hits)
        assert any(c.name == "startup-files" and not c.ran for c in r.checks)
        if encoding == "utf-8":
            active, _, supported = api._tr_startup_content(("program.exe " + BAD + "\n" + text).encode(), "x.cmd")
            assert BAD in active and not supported


@pytest.mark.skipif(os.name != "nt", reason="native CMD fixture needs Windows")
@pytest.mark.parametrize("text,encoding", [
    ("rem. echo ZBT_NOT_RUN\r\n", "utf-8"),
    ("rem, echo ZBT_NOT_RUN\r\n", "utf-8"),
    (":: note ^\r\necho ZBT_NOT_RUN\r\n", "utf-8"),
    ("echo ZBT_NOT_RUN\r\n", "utf-16"),
])
def test_native_rare_batch_forms_do_not_execute_markers(tmp_path, text, encoding):
    path = tmp_path / "marker.cmd"
    path.write_bytes(text.encode(encoding))
    cmd = Path(os.environ["SystemRoot"]) / "System32/cmd.exe"
    proc = subprocess.run([str(cmd), "/d", "/q", "/c", str(path)], cwd=str(tmp_path), capture_output=True, timeout=5)
    assert b"ZBT_NOT_RUN" not in proc.stdout


@pytest.mark.parametrize("source,reason", [
    ("NAME='module'\ndef run(ctx):\n try: raise ValueError('fixture')\n except ValueError as NAME: return str(NAME)", "exception"),
    ("class NAME: pass\ndef run(ctx): return NAME", "class"),
    ("class Thing:\n def run(self): return 'ok'\ndef run(ctx): return Thing().run()", "methods"),
    ("def run(ctx):\n def run(x): return x\n return run(ctx)", "nested"),
    ("NAME='x'\ndef run(ctx):\n NAME='local'\n return NAME", "bindings"),
    ("class Thing:\n NAME='member'\ndef run(ctx): return Thing.NAME", "bindings"),
    ("NAME='x'\ndef run(ctx): return [NAME for NAME in ctx]", "bindings"),
    ("NAME='x'\ndef run(ctx): return (NAME := 'other')", "bindings"),
])
def test_bundle_refuses_unsupported_binding_patterns(source, reason):
    with pytest.raises(ValueError, match=reason):
        build_namespace()(source, "fixture")


def test_bundle_offsets_use_source_newlines_only():
    source = "label='one\vtwo'; NAME='fixture'\ndef run(ctx): return NAME, label\n"
    result = {}
    exec(build_namespace()(source, "fixture"), result)
    assert result["run_fixture"](None) == ("fixture", "one\vtwo")
