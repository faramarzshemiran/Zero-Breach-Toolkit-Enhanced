"""Regressions for hostile-input findings.

A damaged browser write-ahead log is a gap, not a silent clean; one indicator
matched in a flood of records is listed a bounded number of times; progress lines
cannot carry terminal control sequences; a report cannot replace evidence through
a Windows 8.3 short name; the snapshot copy is removed after the chain row limit.
"""
import contextlib
import glob
import os
import shutil
import sqlite3
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import cli, workflow
from zbtriage.context import ScanContext
from zbtriage.modules import browser
from zbtriage.result import EV_CONTACTED, HIT_LIST_LIMIT, Hit, ModuleResult
from test_expanded_capabilities import BAD, context


# --- damaged browser WAL ----------------------------------------------------------

def _history_with_wal(folder):
    """A History whose newest row (the indicator) exists only in its WAL."""
    folder.mkdir(parents=True, exist_ok=True)
    db = folder / "History"
    con = sqlite3.connect(str(db), isolation_level=None)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA wal_autocheckpoint=0")
    con.execute("CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,last_visit_time INTEGER)")
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")      # schema into the main file
    con.execute("INSERT INTO urls VALUES(1,?,'',13400000000000000)", ("https://" + BAD + "/recent",))
    main = db.read_bytes()
    wal = (folder / "History-wal").read_bytes()
    con.close()                                          # closing would checkpoint; restore the copies
    db.write_bytes(main)
    (folder / "History-wal").write_bytes(wal)
    return folder


def test_a_valid_wal_is_read(tmp_path):
    folder = _history_with_wal(tmp_path / "Default")
    r = browser.run(context(targets=(str(folder),)))
    assert BAD in {h.indicator for h in r.hits}


@pytest.mark.parametrize("damage", ["checksum", "truncated"])
def test_a_damaged_wal_is_a_gap_not_a_silent_clean(tmp_path, damage):
    folder = _history_with_wal(tmp_path / "Default")
    wal_path = folder / "History-wal"
    wal = bytearray(wal_path.read_bytes())
    if damage == "checksum":
        wal[-1] ^= 0xFF                                  # last byte of the last frame
    else:
        wal = wal[:-100]
    wal_path.write_bytes(bytes(wal))
    r = browser.run(context(targets=(str(folder),)))
    assert not r.hits
    reasons = " ".join(c.reason or "" for c in r.checks if not c.ran) + " ".join(r.notes)
    assert "write-ahead log is damaged" in reasons


# --- bounded findings ---------------------------------------------------------

def test_a_flood_of_matching_records_is_counted_not_listed():
    r = ModuleResult("android")
    for n in range(HIT_LIST_LIMIT + 500):
        r.add_hit(Hit(BAD, "sms", "message %d" % n, evidence="received"))
    r.add_hit(Hit("other.invalid", "sms", "one", evidence="received"))
    assert len([h for h in r.hits if h.indicator == BAD]) == HIT_LIST_LIMIT
    assert any(h.indicator == "other.invalid" for h in r.hits)
    assert r.submetrics["matching_records_not_listed"] == 500
    assert any("matching_records_not_listed" in n for n in r.notes)


# --- progress lines -------------------------------------------------------------

def test_progress_lines_cannot_carry_terminal_control_sequences():
    seen = []
    ctx = ScanContext(context().iocs, emit=seen.append)
    ctx.emit("[*]   profile: \x1b[2J\x1b[31mevil\u202eeman")
    assert "\x1b" not in seen[0] and "\u202e" not in seen[0]
    assert seen[0].startswith("[*]   profile: ")


# --- 8.3 short names cannot route a report onto evidence -----------------------

@pytest.mark.skipif(sys.platform != "win32", reason="8.3 short names are a Windows feature")
def test_a_short_name_alias_cannot_replace_evidence(tmp_path):
    import ctypes
    folder = tmp_path / "LongFolderName"
    folder.mkdir()
    evidence = folder / "History"
    evidence.write_bytes(b"evidence")
    buf = ctypes.create_unicode_buffer(1024)
    if not ctypes.windll.kernel32.GetShortPathNameW(str(evidence), buf, 1024) or buf.value == str(evidence):
        pytest.skip("8.3 short names are disabled on this volume")
    args = cli._parse(["--scan-type", "targeted", "--target", str(folder)])
    with pytest.raises(ValueError):
        workflow.workflow_output_guard(args, buf.value)


# --- the snapshot copy is removed after the chain row limit --------------------

def test_snapshot_is_removed_after_the_chain_row_limit(tmp_path, monkeypatch):
    work_tmp = tmp_path / "tmp"
    work_tmp.mkdir()
    monkeypatch.setattr(browser, "local_temp_dir", lambda: str(work_tmp))
    folder = tmp_path / "Default"
    folder.mkdir()
    with contextlib.closing(sqlite3.connect(str(folder / "History"))) as db:
        db.execute("CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,last_visit_time INTEGER)")
        db.execute("CREATE TABLE downloads(id INTEGER PRIMARY KEY,current_path TEXT,tab_url TEXT,"
                   "referrer TEXT,state INTEGER,received_bytes INTEGER)")
        db.execute("CREATE TABLE downloads_url_chains(id INTEGER,chain_index INTEGER,url TEXT)")
        db.executemany("INSERT INTO downloads_url_chains VALUES(?,?,?)",
                       ((n, 0, "https://x.invalid/%d" % n) for n in range(200005)))
        db.commit()
    browser.run(context(targets=(str(folder),)))
    assert glob.glob(str(work_tmp / "bscan_*")) == []


# --- Safari visits synced from another iCloud device ---------------------------

def _safari_backup(root, origin):
    import hashlib
    import plistlib
    root.mkdir(parents=True, exist_ok=True)
    man = sqlite3.connect(str(root / "Manifest.db"))
    man.execute("CREATE TABLE Files(fileID TEXT,domain TEXT,relativePath TEXT,flags INTEGER,file BLOB)")
    work = root / "work.db"
    db = sqlite3.connect(str(work))
    db.executescript("CREATE TABLE history_items(id INTEGER,url TEXT);"
                     "CREATE TABLE history_visits(history_item INTEGER,visit_time INTEGER,origin INTEGER);")
    db.execute("INSERT INTO history_items VALUES(1,?)", ("https://" + BAD + "/page",))
    db.execute("INSERT INTO history_visits VALUES(1,700000000,?)", (origin,))
    db.commit()
    db.close()
    fid = hashlib.sha1(b"HomeDomain-Library/Safari/History.db").hexdigest()
    (root / fid[:2]).mkdir(exist_ok=True)
    (root / fid[:2] / fid).write_bytes(work.read_bytes())
    work.unlink()
    man.execute("INSERT INTO Files VALUES(?,?,?,?,?)", (fid, "HomeDomain", "Library/Safari/History.db", 1, b""))
    man.commit()
    man.close()
    (root / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": False}))
    (root / "Info.plist").write_bytes(plistlib.dumps({"Installed Applications": []}))
    return str(root)


@pytest.mark.parametrize("origin, grade", [(0, "contacted"), (1, "referenced")])
def test_a_safari_visit_synced_from_another_device_is_not_contact(tmp_path, origin, grade):
    from zbtriage.modules import ios
    r = ios.run(context(phone_path=_safari_backup(tmp_path / "backup", origin)))
    assert {h.evidence for h in r.hits if h.indicator == BAD} == {grade}


# --- oversized Mark of the Web record ----------------------------------------

def test_an_oversized_download_record_is_a_gap(tmp_path, monkeypatch):
    from zbtriage.modules import traces
    (tmp_path / "file.bin").write_bytes(b"x")
    monkeypatch.setattr(traces, "_tr_motw_roots", lambda: [str(tmp_path)])
    monkeypatch.setattr(traces, "_tr_read_zone", lambda p: {"_oversize": "1"})
    r = ModuleResult("traces")
    traces._tr_check_motw(r, context())
    assert any("too large" in (c.reason or "") for c in r.checks if not c.ran)


# --- hosts file size cap ------------------------------------------------------

def test_an_enormous_hosts_file_is_a_gap_not_read(tmp_path, monkeypatch):
    from zbtriage.modules import host
    etc = tmp_path / "System32" / "drivers" / "etc"
    etc.mkdir(parents=True)
    (etc / "hosts").write_text("198.51.100.7 " + BAD + "\n")
    monkeypatch.setattr(host, "_hosts_path", lambda: str(etc / "hosts"))
    monkeypatch.setattr(host.os.path, "getsize", lambda p: 65 * 1024 * 1024)
    r = ModuleResult("host")
    host._check_hosts(r, context())
    assert not r.hits
    assert any("over 64 MB" in (c.reason or "") for c in r.checks if not c.ran)
