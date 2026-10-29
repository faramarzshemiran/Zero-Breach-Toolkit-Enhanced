"""Selected Safari history keeps origin uncertainty and ambiguous joins visible."""
import contextlib
import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_evidence_safety import _ctx, safety_api
from test_followup_fixes import bundle


@pytest.mark.parametrize("origin,success,grade,gap", (
    (0, 1, "contacted", False), (1, 1, "referenced", False),
    (0, 0, "attempted", False), (None, 1, "referenced", True),
    (7, 1, "referenced", True), (0, None, "referenced", True),
))
def test_safari_visit_origin_and_success_control_evidence(tmp_path, safety_api, origin, success, grade, gap):
    path = tmp_path / "History.db"
    with contextlib.closing(sqlite3.connect(path)) as con:
        con.executescript("CREATE TABLE history_items(id INTEGER PRIMARY KEY,url TEXT);"
                          "CREATE TABLE history_visits(id INTEGER PRIMARY KEY,history_item,visit_time,origin,load_successful);")
        con.execute("INSERT INTO history_items VALUES(1,'https://fixture.invalid/')")
        con.execute("INSERT INTO history_visits VALUES(1,1,700000000,?,?)", (origin, success))
        con.commit()
    before = path.read_bytes()
    result = safety_api.browser_run(_ctx(targets=(str(path),)))
    assert len(result.hits) == 1 and result.hits[0].evidence == grade
    assert result.hits[0].observed.startswith("2023-")
    assert "history" in result.reach
    assert any(not c.ran and "safari-history" in c.name for c in result.checks) is gap
    assert path.read_bytes() == before


def test_safari_duplicate_item_ids_do_not_create_a_contact(tmp_path, safety_api):
    path = tmp_path / "History.db"
    with contextlib.closing(sqlite3.connect(path)) as con:
        con.executescript("CREATE TABLE history_items(id,url);"
                          "INSERT INTO history_items VALUES(1,'https://fixture.invalid/');"
                          "INSERT INTO history_items VALUES(1,'https://ordinary.invalid/');"
                          "CREATE TABLE history_visits(history_item,visit_time,origin,load_successful);"
                          "INSERT INTO history_visits VALUES(1,700000000,0,1);")
        con.commit()
    result = safety_api.browser_run(_ctx(targets=(str(path),)))
    assert not result.hits
    assert any(not c.ran and "safari-history" in c.name for c in result.checks)


def test_default_safari_main_history_and_uuid_profiles_are_both_read(tmp_path, monkeypatch, safety_api):
    root = tmp_path / "Safari"
    profile = root / "Profiles" / "ABCDEF-1234"
    profile.mkdir(parents=True)
    for folder, domain in ((root, "fixture.invalid"), (profile, "second.invalid")):
        with contextlib.closing(sqlite3.connect(folder / "History.db")) as con:
            con.executescript("CREATE TABLE history_items(id,url);"
                              "CREATE TABLE history_visits(history_item,visit_time,origin,load_successful);")
            con.execute("INSERT INTO history_items VALUES(1,?)", ("https://" + domain,))
            con.execute("INSERT INTO history_visits VALUES(1,700000000,0,1)")
            con.commit()
    api = safety_api.browser
    roots = []
    monkeypatch.setattr(api, "CHROMIUM_ROOTS", roots)
    monkeypatch.setattr(api, "_DEFAULT_CHROMIUM_ROOTS", roots)
    monkeypatch.setattr(api, "FIREFOX_ROOTS", [])
    monkeypatch.setattr(api, "APP_ROOTS", [])
    monkeypatch.setattr(api, "_browser_safari_roots", lambda: [("safari", str(root))])
    result = safety_api.browser_run(_ctx())
    assert {h.indicator for h in result.hits} == {"fixture.invalid", "second.invalid"}
    assert len(result.hits) == 2
