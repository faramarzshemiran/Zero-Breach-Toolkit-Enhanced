"""Every evidence database copy is opened the same hardened way: query only,
schema code untrusted, and value sizes bounded."""
import contextlib
import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import localpaths
from zbtriage.modules import browser
from test_followup_fixes import bundle


@pytest.fixture(params=("source", "bundle"))
def api(request, bundle):
    return localpaths if request.param == "source" else bundle


def _db(tmp_path):
    path = tmp_path / "copy.sqlite"
    with contextlib.closing(sqlite3.connect(str(path))) as con:
        con.execute("CREATE TABLE t(v)")
        con.execute("INSERT INTO t VALUES ('ok')")
        con.commit()
    return path


def test_opened_copy_cannot_be_written(tmp_path, api):
    con = api.open_evidence_db(str(_db(tmp_path)))
    try:
        assert con.execute("SELECT v FROM t").fetchall() == [("ok",)]
        with pytest.raises(sqlite3.OperationalError):
            con.execute("INSERT INTO t VALUES ('changed')")
        assert con.execute("PRAGMA trusted_schema").fetchone()[0] == 0
    finally:
        con.close()


@pytest.mark.skipif(not hasattr(sqlite3.Connection, "setlimit"), reason="Python 3.11+ sets SQLite limits")
def test_oversized_values_are_refused(tmp_path, api):
    con = api.open_evidence_db(str(_db(tmp_path)))
    try:
        with pytest.raises(sqlite3.DataError):
            con.execute("SELECT zeroblob(3 * 1024 * 1024)").fetchone()
    finally:
        con.close()


def test_browser_and_iphone_readers_use_the_shared_opener():
    from zbtriage import ios_sources
    for module in (browser, ios_sources):
        assert module.open_evidence_db is localpaths.open_evidence_db
        assert "sqlite3.connect(" not in open(module.__file__, encoding="utf-8").read()
