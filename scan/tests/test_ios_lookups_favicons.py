"""iMessage/FaceTime account lookups (idstatuscache) and browser favicon stores
in an iPhone backup, the two MVT iOS sources the reader had not covered."""
import datetime
import plistlib

import pytest

from zbtriage.context import ScanContext
from zbtriage.iocs import IocSet, Indicator
from zbtriage.modules import ios
from test_followup_fixes import bundle  # noqa: F401
from test_ios_upgrade import backup, db_bytes

EMAIL = "operator.account@lookup.invalid"
DOMAIN = "favicon-redirect.invalid"


@pytest.fixture(params=("source", "bundle"))
def reader(request, bundle):  # noqa: F811
    return ios.run if request.param == "source" else bundle.run_ios


def _ctx(root):
    iocs = IocSet([Indicator(EMAIL, "fixture", "primary", "email", "fixture"),
                   Indicator(DOMAIN, "fixture", "primary", "domain", "fixture")], "fixture", None)
    return ScanContext(iocs, phone_path=str(root), ios_input="backup", emit=lambda _: None)


def _gaps(result):
    return {c.name: c.reason for c in result.checks if not c.ran}


@pytest.mark.parametrize("path", ["Library/Preferences/com.apple.identityservices.idstatuscache.plist",
                                  "Library/IdentityServices/idstatuscache.plist"])
@pytest.mark.parametrize("stamp", [740000000.0, datetime.datetime(2024, 6, 13, 10, 0, 0)])
def test_account_lookup_matches_an_email_indicator(tmp_path, reader, path, stamp):
    doc = {"com.apple.madrid": {"mailto:" + EMAIL: {"IDStatus": 1, "LookupDate": stamp},
                                "tel:+15550100": {"IDStatus": 2, "LookupDate": stamp}}}
    root = tmp_path / "backup"
    backup(root, [("HomeDomain", path, plistlib.dumps(doc))])
    result = reader(_ctx(root))
    hits = [h for h in result.hits if h.indicator == EMAIL]
    assert hits and hits[0].evidence == "device-log" and hits[0].observed.startswith("202")
    assert "ios:id-status-cache" not in _gaps(result)


def test_unsupported_lookup_record_is_a_gap(tmp_path, reader):
    doc = {"com.apple.madrid": ["mailto:" + EMAIL]}
    root = tmp_path / "backup"
    backup(root, [("HomeDomain", "Library/Preferences/com.apple.identityservices.idstatuscache.plist",
                   plistlib.dumps(doc))])
    result = reader(_ctx(root))
    assert "ios:id-status-cache" in _gaps(result)


def test_safari_favicons_page_and_icon_addresses(tmp_path, reader):
    raw, _ = db_bytes(tmp_path, "CREATE TABLE page_url(uuid, url); CREATE TABLE icon_info(uuid, url, timestamp);",
                      [("INSERT INTO page_url VALUES('a', ?)", ("https://" + DOMAIN + "/landing",)),
                       ("INSERT INTO icon_info VALUES('a', ?, 0)", ("https://cdn.example/icon.png",))])
    root = tmp_path / "backup"
    backup(root, [("HomeDomain", "Library/Image Cache/Favicons/Favicons.db", raw)])
    result = reader(_ctx(root))
    assert any(h.indicator == DOMAIN for h in result.hits)
    assert "ios:favicons" not in _gaps(result)


def test_chromium_favicons(tmp_path, reader):
    raw, _ = db_bytes(tmp_path, "CREATE TABLE icon_mapping(id, page_url, icon_id); CREATE TABLE favicons(id, url);",
                      [("INSERT INTO icon_mapping VALUES(1, 'https://ordinary.example/', 1)", ()),
                       ("INSERT INTO favicons VALUES(1, ?)", ("https://" + DOMAIN + "/favicon.ico",))])
    root = tmp_path / "backup"
    backup(root, [("AppDomain-com.google.chrome.ios",
                   "Library/Application Support/Google/Chrome/Default/Favicons", raw)])
    result = reader(_ctx(root))
    assert any(h.indicator == DOMAIN for h in result.hits)
    assert "ios:favicons" not in _gaps(result)


def _origin_record(scheme, host):
    def text(value):
        data = value.encode("latin-1")
        return len(data).to_bytes(4, "little") + b"\x01" + data
    one = text(scheme) + text(host) + b"\x00"
    return one + one


WEBKIT = "Library/WebKit/WebsiteData/"


@pytest.mark.parametrize("path,data", [
    (WEBKIT + "Default/abc/abc/origin", _origin_record("https", DOMAIN)),
    (WEBKIT + "LocalStorage/https_" + DOMAIN + "_0.localstorage", b"SQLite format 3\x00"),
    (WEBKIT + "IndexedDB/v1/https_" + DOMAIN + "_0/1A2B/IndexedDB.sqlite3", b"SQLite format 3\x00"),
])
def test_site_that_stored_web_view_data_is_contact(tmp_path, reader, path, data):
    root = tmp_path / "backup"
    backup(root, [("AppDomain-com.example.app", path, data)])
    result = reader(_ctx(root))
    assert [h.evidence for h in result.hits if h.indicator == DOMAIN] == ["contacted"]
    assert "ios:webkit-origins" not in _gaps(result)


def test_local_app_pages_are_not_gaps(tmp_path, reader):
    root = tmp_path / "backup"
    backup(root, [("AppDomain-com.example.app", WEBKIT + "Default/f/f/origin", _origin_record("file", "")),
                  ("AppDomain-com.example.app", WEBKIT + "LocalStorage/file__0.localstorage", b"x")])
    result = reader(_ctx(root))
    assert "ios:webkit-origins" not in _gaps(result) and not result.hits


def test_damaged_origin_record_is_a_gap(tmp_path, reader):
    root = tmp_path / "backup"
    backup(root, [("AppDomain-com.example.app", WEBKIT + "Default/d/d/origin", b"\x05\x00\x00\x00\x01htt")])
    result = reader(_ctx(root))
    assert "ios:webkit-origins" in _gaps(result)


def _analytics_fs(tmp_path, rows):
    import sqlite3
    root = tmp_path / "fs"
    folder = root / "private" / "var" / "Keychains" / "Analytics"
    folder.mkdir(parents=True)
    con = sqlite3.connect(folder / "trust_analytics.db")
    con.execute("CREATE TABLE hard_failures(id INTEGER PRIMARY KEY, timestamp REAL, data BLOB)")
    con.executemany("INSERT INTO hard_failures(timestamp, data) VALUES(?, ?)", rows)
    con.commit()
    con.close()
    (root / "private" / "var" / "mobile").mkdir(parents=True)
    return root


def _fs_ctx(root, indicators):
    return ScanContext(IocSet(indicators, "fixture", None), phone_path=str(root), ios_input="filesystem",
                       emit=lambda _: None)


def test_keychain_analytics_caller_and_host(tmp_path, reader):
    record = plistlib.dumps({"Caller": "com.spy.agent", "eventType": "TrustEvaluationEvent",
                             "Hostname": "https://" + DOMAIN + "/"}, fmt=plistlib.FMT_BINARY)
    root = _analytics_fs(tmp_path, [(1764969616.5, record)])
    result = reader(_fs_ctx(root, [Indicator("com.spy.agent", "fixture", "primary", "app-id", "fixture"),
                                   Indicator(DOMAIN, "fixture", "primary", "domain", "fixture")]))
    found = {(h.indicator, h.evidence) for h in result.hits}
    assert ("com.spy.agent", "device-log") in found and (DOMAIN, "device-log") in found
    assert any(h.observed.startswith("2025-12-05") for h in result.hits)
    assert "ios:keychain-analytics" not in _gaps(result)


def test_keychain_analytics_unreadable_record_is_a_gap(tmp_path, reader):
    root = _analytics_fs(tmp_path, [(1764969616.5, b"not a property list")])
    result = reader(_fs_ctx(root, [Indicator(DOMAIN, "fixture", "primary", "domain", "fixture")]))
    assert "ios:keychain-analytics" in _gaps(result)


@pytest.mark.parametrize("doc", [{}, {"CacheVersion": 1}])
def test_empty_lookup_cache_is_fully_read(tmp_path, reader, doc):
    root = tmp_path / "backup"
    backup(root, [("HomeDomain", "Library/IdentityServices/idstatuscache.plist", plistlib.dumps(doc))])
    result = reader(_ctx(root))
    assert "ios:id-status-cache" not in _gaps(result)


def test_one_bad_analytics_record_does_not_hide_the_rest(tmp_path, reader):
    good = plistlib.dumps({"Caller": "com.spy.agent"}, fmt=plistlib.FMT_BINARY)
    root = _analytics_fs(tmp_path, [(1764969616.5, b"bplist00 broken"), (1764969617.5, good)])
    result = reader(_fs_ctx(root, [Indicator("com.spy.agent", "fixture", "primary", "app-id", "fixture")]))
    assert any(h.indicator == "com.spy.agent" for h in result.hits)
    assert "1 analytics record" in _gaps(result).get("ios:keychain-analytics", "")
