"""iOS version matrix: every reader against the real table layouts of each
recorded iOS release (data/ios_layouts.json, table definitions only, recorded
with tools/capture_ios_layouts.py). Each table is rebuilt empty, one synthetic
row with planted indicators is added, and the evidence is scanned both as a
local backup and as an extracted file system. A reader that stops finding its
row, or reports a gap, on any recorded release fails here."""
import json
import plistlib
import re
import sqlite3
from pathlib import Path

import pytest

from zbtriage.context import ScanContext
from zbtriage.iocs import IocSet, Indicator
from zbtriage.modules import ios
from test_followup_fixes import bundle
from test_ios_upgrade import backup

LAYOUTS = json.loads((Path(__file__).parent / "data" / "ios_layouts.json").read_text(encoding="utf-8"))["versions"]

DOMAIN = "layout-matrix.invalid"
URL = "https://" + DOMAIN + "/path"
PROCESS = "layoutmatrixd"
APP = "com.layoutmatrix.app"
EMAIL = "person@layout-matrix.invalid"

ROWS = {
    "message": {"text": "see " + URL, "date": 1, "is_from_me": 0},
    "handle": {"id": EMAIL},
    "attachment": {"filename": "~/Library/SMS/Attachments/00/fixture.txt"},
    "history_items": {"id": 1, "url": URL},
    "history_visits": {"history_item": 1, "visit_time": 1.0, "origin": 0},
    "ZPROCESS": {"ZPROCNAME": PROCESS},
    "access": {"client": APP, "service": "kTCCServiceCamera", "auth_value": 2, "allowed": 1},
    "ZINTERACTIONS": {"ZBUNDLEID": APP, "ZSTARTDATE": 1},
    "ObservedDomains": {"registrableDomain": DOMAIN, "lastSeen": 1},
    "observed_domains": {"registrableDomain": DOMAIN, "lastSeen": 1},
    "tabs": {"url": URL, "title": "fixture"},
    "bookmarks": {"url": URL, "title": "fixture"},
    "cloud_tabs": {"url": URL, "title": "fixture"},
    "ZCALLRECORD": {"ZADDRESS": EMAIL.encode(), "ZDATE": 1, "ZORIGINATED": 0},
    "CalendarItem": {"summary": URL, "title": URL, "url": URL, "start_date": 1},
    "ZSHORTCUT": {"Z_PK": 1, "ZNAME": "fixture", "ZACTIONSDESCRIPTION": "fixture",
                  "ZWORKFLOWACTIONS": plistlib.dumps([{"WFURLActionURL": URL}], fmt=plistlib.FMT_BINARY)},
    "ZSHORTCUTACTIONS": {"ZSHORTCUT": 1, "ZDATA": plistlib.dumps([{"WFURLActionURL": URL}], fmt=plistlib.FMT_BINARY)},
    "ZWAMESSAGE": {"ZTEXT": URL, "ZISFROMME": 0, "ZMESSAGEDATE": 1},
}

# artifact -> (backup domain, backup path, file-system path, check, planted value)
PLACES = {
    "sms": ("HomeDomain", "Library/SMS/sms.db", "mobile/Library/SMS/sms.db", "ios:messages", DOMAIN),
    "safari-history": ("HomeDomain", "Library/Safari/History.db", "mobile/Library/Safari/History.db", "ios:safari", DOMAIN),
    "data-usage": ("WirelessDomain", "Library/Databases/DataUsage.sqlite",
                   "wireless/Library/Databases/DataUsage.sqlite", "ios:processes", PROCESS),
    "netusage": (None, None, "networkd/db/netusage.sqlite", "ios:processes", PROCESS),
    "tcc": ("HomeDomain", "Library/TCC/TCC.db", "mobile/Library/TCC/TCC.db", "ios:permissions", APP),
    "interactions": ("HomeDomain", "Library/CoreDuet/People/interactionC.db",
                     "mobile/Library/CoreDuet/People/interactionC.db", "ios:interactions", APP),
    "webkit-statistics": ("AppDomain-com.apple.mobilesafari",
                          "Library/WebKit/WebsiteData/ResourceLoadStatistics/observations.db",
                          "mobile/Containers/Data/Application/0A/Library/WebKit/WebsiteData/ResourceLoadStatistics/observations.db",
                          "ios:webkit-statistics", DOMAIN),
    "browser-state": ("HomeDomain", "Library/Safari/BrowserState.db", "mobile/Library/Safari/BrowserState.db",
                      "ios:browser-state", DOMAIN),
    "safari-tabs": ("HomeDomain", "Library/Safari/SafariTabs.db", "mobile/Library/Safari/SafariTabs.db",
                    "ios:browser-state", DOMAIN),
    "cloud-tabs": ("HomeDomain", "Library/Safari/CloudTabs.db", "mobile/Library/Safari/CloudTabs.db",
                   "ios:browser-state", DOMAIN),
    "safari-bookmarks": ("HomeDomain", "Library/Safari/Bookmarks.db", "mobile/Library/Safari/Bookmarks.db",
                         "ios:safari-bookmarks", DOMAIN),
    "calls": ("HomeDomain", "Library/CallHistoryDB/CallHistory.storedata",
              "mobile/Library/CallHistoryDB/CallHistory.storedata", "ios:calls", EMAIL),
    "calendar": ("HomeDomain", "Library/Calendar/Calendar.sqlitedb", "mobile/Library/Calendar/Calendar.sqlitedb",
                 "ios:calendar", DOMAIN),
    "shortcuts": ("HomeDomain", "Library/Shortcuts/Shortcuts.sqlite", "mobile/Library/Shortcuts/Shortcuts.sqlite",
                  "ios:shortcuts", DOMAIN),
    "whatsapp": ("AppDomainGroup-group.net.whatsapp.WhatsApp.shared", "ChatStorage.sqlite",
                 "mobile/Containers/Shared/AppGroup/0B/ChatStorage.sqlite", "ios:whatsapp", DOMAIN),
}


def _filler(declared):
    kind = (declared or "").upper()
    if "INT" in kind or "REAL" in kind or "FLOA" in kind or "DOUB" in kind or "TIMESTAMP" in kind or "NUM" in kind:
        return 0
    if "BLOB" in kind:
        return b""
    return ""


def build(tmp_path, tables):
    """An SQLite file holding the recorded tables and one planted row each."""
    path = tmp_path / "layout.sqlite"
    if path.exists():
        path.unlink()
    con = sqlite3.connect(path)
    for name, sql in tables.items():
        con.execute(sql)
        info = con.execute('PRAGMA table_info("' + name + '")').fetchall()
        planted = {k.lower(): v for k, v in ROWS[name].items()}
        rowid_alias = sum(1 for col in info if col[5]) == 1  # a lone INTEGER PRIMARY KEY numbers itself
        values = {}
        for _cid, column, declared, notnull, default, pk in info:
            if column.lower() in planted:
                values[column] = planted[column.lower()]
            elif pk and rowid_alias and (declared or "").upper() == "INTEGER":
                continue
            elif (notnull or pk) and default is None:
                values[column] = _filler(declared)
        con.execute('INSERT INTO "' + name + '" (' + ",".join('"' + c + '"' for c in values) + ") VALUES ("
                    + ",".join("?" for _ in values) + ")", list(values.values()))
    con.commit()
    con.close()
    raw = path.read_bytes()
    path.unlink()
    return raw


def scan(root, kind, reader):
    indicators = [Indicator(DOMAIN, "fixture", "primary", "domain", "fixture"),
                  Indicator(PROCESS, "fixture", "primary", "process", "fixture"),
                  Indicator(APP, "fixture", "primary", "app-id", "fixture"),
                  Indicator(EMAIL, "fixture", "primary", "email", "fixture")]
    return reader(ScanContext(IocSet(indicators, "fixture", None), phone_path=str(root), ios_input=kind,
                              emit=lambda _: None))


@pytest.fixture(params=("source", "bundle"))
def reader(request, bundle):
    return ios.run if request.param == "source" else bundle.run_ios


def _check(result, recorded, kind):
    gaps = {c.name: c.reason for c in result.checks if not c.ran}
    for artifact in recorded:
        domain, _rel, fs_path, check, value = PLACES[artifact]
        if kind == "backup" and domain is None:
            continue
        base = fs_path.rsplit("/", 1)[-1]
        assert any(h.indicator == value and base in h.location for h in result.hits), (artifact, check, gaps)
        assert check not in gaps, (artifact, gaps[check])
    if "sms" in recorded:
        assert any(h.indicator == EMAIL and "sms.db" in h.location for h in result.hits)


@pytest.mark.parametrize("version", sorted(LAYOUTS))
def test_recorded_layouts_as_backup(tmp_path, reader, version):
    recorded = LAYOUTS[version]
    items = [(PLACES[a][0], PLACES[a][1], build(tmp_path, tables))
             for a, tables in recorded.items() if PLACES[a][0]]
    root = tmp_path / "backup"
    backup(root, items)
    _check(scan(root, "backup", reader), recorded, "backup")


@pytest.mark.parametrize("version", sorted(LAYOUTS))
def test_recorded_layouts_as_file_system(tmp_path, reader, version):
    recorded = LAYOUTS[version]
    root = tmp_path / "filesystem"
    for artifact, tables in recorded.items():
        target = root / "private" / "var" / PLACES[artifact][2]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(build(tmp_path, tables))
    _check(scan(root, "filesystem", reader), recorded, "filesystem")


def test_layouts_hold_table_definitions_only():
    for version, recorded in LAYOUTS.items():
        assert re.fullmatch(r"\d+(\.\d+)*", version)
        for artifact, tables in recorded.items():
            assert artifact in PLACES
            for name, sql in tables.items():
                assert name in ROWS
                assert sql.lstrip().upper().startswith("CREATE TABLE")
