"""Regressions for artifact-reader edge cases.

Only the findings that were proven are pinned here: a malformed Mark of the Web
URL no longer ends the traces module, a modified Defender exclusion is reported,
every spelling of a loopback or unspecified sink is treated as a block, a
Chromium history row with no recorded visit is not called contact, and an
ambiguous iPhone record no longer ends the reader.
"""
import contextlib
import os
import sqlite3
import sys
import time
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage.iocs import Indicator, IocSet, TYPE_DOMAIN
from zbtriage.modules import browser, host, ios, traces
from zbtriage.result import EV_CONFIGURED, ModuleResult
from test_expanded_capabilities import BAD, context
from test_followup_fixes import bundle  # noqa: F401  (pytest fixture)

OTHER = "removed-exclusion.invalid"


def _iocs(*values):
    return IocSet([Indicator(v, "infrastructure", "primary", TYPE_DOMAIN, "fixture")
                   for v in values], "fixture", None)


# --- a malformed Mark of the Web URL ------------------------------------------

def test_malformed_motw_url_no_longer_ends_the_traces_module(tmp_path, monkeypatch):
    (tmp_path / "planted.bin").write_bytes(b"x")
    (tmp_path / "real.bin").write_bytes(b"x")
    zones = {"planted.bin": {"hosturl": "http://[::1"},
             "real.bin": {"hosturl": "https://" + BAD + "/payload"}}
    monkeypatch.setattr(traces, "_tr_motw_roots", lambda: [str(tmp_path)])
    monkeypatch.setattr(traces, "_tr_read_zone", lambda p: zones.get(os.path.basename(p)))
    r = ModuleResult("traces")
    traces._tr_check_motw(r, context())        # raised ValueError before the fix
    assert {(h.indicator, h.evidence) for h in r.hits} == {(BAD, "contacted")}
    assert r.skipped >= 1


# --- Defender exclusions --------------------------------------------------------

def test_a_modified_exclusion_is_reported_and_a_deleted_one_is_not(monkeypatch):
    base = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\"
    kept = base + "C:\\Users\\x\\" + BAD
    gone = base + "C:\\Users\\x\\" + OTHER
    settings = [  # newest first, as the log returns them
        {"Id": 5007, "Time": "2026-10-20T10:00:00",
         "Data": {"p2": kept + " = 0x0", "p3": kept + " = 0x1"}},      # modified
        {"Id": 5007, "Time": "2026-10-19T10:00:00",
         "Data": {"p2": gone + " = 0x0", "p3": ""}},                   # deleted
    ]
    calls = iter([([], ""), (settings, "")])
    monkeypatch.setattr(traces, "_tr_events", lambda *a, **k: next(calls))
    ctx = context()
    ctx.iocs = _iocs(BAD, OTHER)
    r = ModuleResult("traces")
    traces._tr_check_defender(r, ctx, traces._TrLeads(r))
    found = {h.indicator for h in r.hits}
    assert BAD in found
    assert OTHER not in found


def test_an_exclusion_seen_twice_is_reported_once(monkeypatch):
    path = "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\" + BAD
    settings = [{"Id": 5007, "Time": "2026-10-20", "Data": {"p2": path + " = 0x0", "p3": path + " = 0x1"}},
                {"Id": 5007, "Time": "2026-10-19", "Data": {"p2": "", "p3": path + " = 0x0"}}]
    calls = iter([([], ""), (settings, "")])
    monkeypatch.setattr(traces, "_tr_events", lambda *a, **k: next(calls))
    r = ModuleResult("traces")
    traces._tr_check_defender(r, context(), traces._TrLeads(r))
    assert r.submetrics["defender_exclusions_added"] == 1


# --- sink addresses -----------------------------------------------------------

@pytest.mark.parametrize("address", ["0.0.0.0", "127.0.0.1", "127.0.0.2", "127.255.255.254",
                                     "::", "::1", "0:0:0:0:0:0:0:1", "0:0:0:0:0:0:0:0",
                                     "::ffff:127.0.0.1", " 127.0.0.2 "])
def test_every_spelling_of_a_loopback_or_unspecified_address_is_a_sink(address):
    assert host._is_sink(address)


@pytest.mark.parametrize("address", ["192.0.2.10", "8.8.8.8", "::ffff:8.8.8.8", "0.0.0.1",
                                     "blocked.invalid", ""])
def test_routable_or_unparseable_values_are_not_sinks(address):
    # 0.0.0.1 is left out on purpose: some current kernels accept it as real.
    assert not host._is_sink(address)


def test_a_dns_block_with_an_uncommon_loopback_is_not_a_finding():
    ctx = context()
    ctx.iocs = _iocs("blocked.invalid", "other.invalid")
    r = ModuleResult("host")
    rows = [{"Entry": "blocked.invalid", "Data": "127.0.0.2"},
            {"Entry": "blocked.invalid", "Data": "::ffff:127.0.0.1"},
            {"Entry": "other.invalid", "Data": "192.0.2.10"}]
    with patch.object(host, "_ps_json", return_value=(rows, "")), \
            patch.object(host, "_boot_time", return_value=("2026-10-18", "")):
        host._check_dns_cache(r, ctx)
    assert [h.indicator for h in r.hits] == ["other.invalid"]


def test_a_hosts_file_block_with_an_uncommon_loopback_is_not_a_finding(tmp_path, monkeypatch):
    etc = tmp_path / "System32" / "drivers" / "etc"
    etc.mkdir(parents=True)
    (etc / "hosts").write_text("127.0.0.2 blocked.invalid\n198.51.100.7 other.invalid\n",
                               encoding="utf-8")
    monkeypatch.setattr(host, "_hosts_path", lambda: str(etc / "hosts"))
    ctx = context()
    ctx.iocs = _iocs("blocked.invalid", "other.invalid")
    r = ModuleResult("host")
    host._check_hosts(r, ctx)
    assert [(h.indicator, h.evidence) for h in r.hits] == [("other.invalid", EV_CONFIGURED)]


# --- Chromium history -----------------------------------------------------------

def _history(tmp_path, with_visit_column, last_visit):
    with contextlib.closing(sqlite3.connect(tmp_path / "History")) as db:
        if with_visit_column:
            db.execute("CREATE TABLE urls(url TEXT,title TEXT,last_visit_time INTEGER)")
            db.execute("INSERT INTO urls VALUES(?,?,?)", ("https://" + BAD + "/", "", last_visit))
        else:
            db.execute("CREATE TABLE urls(url TEXT,title TEXT)")
            db.execute("INSERT INTO urls VALUES(?,?)", ("https://" + BAD + "/", ""))
        db.commit()


@pytest.mark.parametrize("with_column, last_visit, grade", [
    (True, 0, "referenced"),                    # a row with no recorded visit
    (True, 13000000000000000, "contacted"),     # a recorded visit
    (False, None, "contacted"),                 # no column: nothing to downgrade on
])
def test_chromium_contact_needs_a_recorded_visit(tmp_path, bundle, with_column, last_visit, grade):
    _history(tmp_path, with_column, last_visit)
    for reader in (browser.run, bundle.run_browser):
        r = reader(context(targets=(str(tmp_path),)))
        assert {(h.indicator, h.evidence) for h in r.hits} == {(BAD, grade)}


# --- an ambiguous iPhone record -----------------------------------------------

def test_an_ambiguous_iphone_record_is_skipped_and_later_records_are_still_read():
    con = sqlite3.connect(":memory:")
    con.executescript(
        "CREATE TABLE m(text TEXT); CREATE TABLE h(mid INTEGER, v TEXT);"
        "INSERT INTO m(text) VALUES('one'),('two'),('three');"
        # Record 2 joins to two rows, which makes both the batch and that row
        # ambiguous. Each used to raise past its handler and end the reader.
        "INSERT INTO h VALUES(1,'a'),(2,'b'),(2,'c'),(3,'d');")
    gaps = []
    rows = list(ios._ios_record_rows(
        con, "SELECT m.text FROM m JOIN h ON h.mid = m._rowid_", "m", {"text"},
        ModuleResult("ios"), lambda _check, reason: gaps.append(reason),
        time.monotonic() + 30, "messages", label="message", alias="m"))
    assert [row[0] for _ordinal, row in rows] == ["one", "three"]
    assert any("ambiguous" in g for g in gaps)
