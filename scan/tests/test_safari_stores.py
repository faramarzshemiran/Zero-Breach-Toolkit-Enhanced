"""Desktop Safari beyond History.db: sandboxed tabs, iCloud tabs, URL cache,
WebKit statistics, HSTS and binary cookies, and the bookmark, download, Top
Sites and closed-tab property lists, each with its evidence grade."""
import contextlib
import os
import plistlib
import sqlite3
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_evidence_safety import _ctx, safety_api
from test_followup_fixes import bundle
from zbtriage.iocs import Indicator, IocSet


def _binarycookies(domains):
    """A Cookies.binarycookies file in Safari's layout: one page per cookie."""
    pages = []
    for domain in domains:
        strings = domain.encode() + b"\x00" + b"name\x00" + b"/\x00" + b"value\x00"
        start = 56
        header = struct.pack("<IIII", 56 + len(strings), 0, 0, 0)
        header += struct.pack("<IIII", start, start + len(domain) + 1, start + len(domain) + 6,
                              start + len(domain) + 8)
        header += b"\x00" * 8 + struct.pack("<dd", 900000000.0, 790000000.0)
        cookie = header + strings
        page = b"\x00\x00\x01\x00" + struct.pack("<I", 1) + struct.pack("<I", 16) + b"\x00" * 4 + cookie
        pages.append(page)
    return b"cook" + struct.pack(">I", len(pages)) + b"".join(struct.pack(">I", len(p)) for p in pages) + b"".join(pages)


def _db(path, script, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.closing(sqlite3.connect(path)) as con:
        con.executescript(script)
        for sql, args in rows:
            con.execute(sql, args)
        con.commit()


def _safari(tmp_path):
    library = tmp_path / "Library"
    root = library / "Safari"
    sandbox = library / "Containers" / "com.apple.Safari" / "Data" / "Library"
    root.mkdir(parents=True)
    (root / "Bookmarks.plist").write_bytes(plistlib.dumps(
        {"Children": [{"URLString": "https://bookmark.invalid/", "WebBookmarkType": "WebBookmarkTypeLeaf"}]}))
    (root / "TopSites.plist").write_bytes(plistlib.dumps({"TopSites": [{"TopSiteURLString": "https://top.invalid/"}]}))
    (root / "RecentlyClosedTabs.plist").write_bytes(plistlib.dumps(
        {"ClosedTabOrWindowPersistentStates": [{"PersistentState": {"TabURL": "https://closed.invalid/"}}]}))
    (root / "Downloads.plist").write_bytes(plistlib.dumps({"DownloadHistory": [
        {"DownloadEntryURL": "https://got.invalid/a.pkg", "DownloadEntryProgressBytesSoFar": 1024},
        {"DownloadEntryURL": "https://none.invalid/b.pkg", "DownloadEntryProgressBytesSoFar": 0}]}))
    _db(sandbox / "Safari" / "SafariTabs.db", "CREATE TABLE bookmarks(url,title)",
        [("INSERT INTO bookmarks VALUES(?, 't')", ("https://tab.invalid/",))])
    _db(sandbox / "Safari" / "CloudTabs.db", "CREATE TABLE cloud_tabs(url,title)",
        [("INSERT INTO cloud_tabs VALUES(?, 't')", ("https://cloud.invalid/",))])
    _db(sandbox / "Caches" / "com.apple.Safari" / "Cache.db", "CREATE TABLE cfurl_cache_response(request_key,time_stamp)",
        [("INSERT INTO cfurl_cache_response VALUES(?, 0)", ("https://cache.invalid/x",))])
    _db(sandbox / "WebKit" / "WebsiteData" / "ResourceLoadStatistics" / "observations.db",
        "CREATE TABLE ObservedDomains(registrableDomain,lastSeen)",
        [("INSERT INTO ObservedDomains VALUES(?, 0)", ("seen.invalid",))])
    hsts = sandbox / "Caches" / "WebKit" / "HSTS" / "HSTS.plist"
    hsts.parent.mkdir(parents=True)
    hsts.write_bytes(plistlib.dumps({"com.apple.CFNetwork.defaultStorageSession": {
        "secure.invalid": {"HSTS Host": True, "Include Subdomains": True, "Create Time": 787259791.0}}}))
    cookies = sandbox / "Cookies" / "Cookies.binarycookies"
    cookies.parent.mkdir(parents=True)
    cookies.write_bytes(_binarycookies([".cookie.invalid", "other.example"]))
    return root


EXPECTED = {
    "bookmark.invalid": ("Bookmarks.plist", "referenced"),
    "top.invalid": ("TopSites.plist", "referenced"),
    "closed.invalid": ("RecentlyClosedTabs.plist", "referenced"),
    "got.invalid": ("Downloads.plist", "contacted"),
    "none.invalid": ("Downloads.plist", "attempted"),
    "tab.invalid": ("SafariTabs.db", "referenced"),
    "cloud.invalid": ("CloudTabs.db", "referenced"),
    "cache.invalid": ("Cache.db", "referenced"),
    "seen.invalid": ("observations.db", "referenced"),
    "secure.invalid": ("HSTS.plist", "contacted"),
    "cookie.invalid": ("Cookies.binarycookies", "contacted"),
}


def _run(safety_api, monkeypatch, root):
    api = safety_api.browser
    roots = []
    monkeypatch.setattr(api, "CHROMIUM_ROOTS", roots)
    monkeypatch.setattr(api, "_DEFAULT_CHROMIUM_ROOTS", roots)
    monkeypatch.setattr(api, "FIREFOX_ROOTS", [])
    monkeypatch.setattr(api, "APP_ROOTS", [])
    monkeypatch.setattr(api, "_browser_safari_roots", lambda: [("safari", str(root))])
    ctx = _ctx()
    ctx.iocs = IocSet([Indicator(d, "infrastructure", "primary", "domain", "fixture") for d in EXPECTED],
                      "fixture", None)
    return safety_api.browser_run(ctx)


def test_every_safari_store_is_read_with_its_grade(tmp_path, monkeypatch, safety_api):
    root = _safari(tmp_path)
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    result = _run(safety_api, monkeypatch, root)
    found = {(h.indicator, os.path.basename(h.location), h.evidence) for h in result.hits}
    for domain, (name, grade) in EXPECTED.items():
        assert (domain, name, grade) in found, (domain, sorted(found))
    assert not [c for c in result.checks if not c.ran]
    assert {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()} == before


def test_damaged_safari_cookie_file_is_a_gap(tmp_path, monkeypatch, safety_api):
    root = _safari(tmp_path)
    cookies = tmp_path / "Library" / "Containers" / "com.apple.Safari" / "Data" / "Library" / "Cookies" / "Cookies.binarycookies"
    cookies.write_bytes(cookies.read_bytes()[:40])
    result = _run(safety_api, monkeypatch, root)
    assert any(not c.ran and "safari-cookies" in c.name for c in result.checks)
    assert not any(h.indicator == "cookie.invalid" for h in result.hits)


def test_repeated_download_url_keeps_each_records_grade(tmp_path, monkeypatch, safety_api):
    root = _safari(tmp_path)
    (root / "Downloads.plist").write_bytes(plistlib.dumps({"DownloadHistory": [
        {"DownloadEntryURL": "https://got.invalid/a.pkg", "DownloadEntryProgressBytesSoFar": 1024},
        {"DownloadEntryURL": "https://got.invalid/a.pkg", "DownloadEntryProgressBytesSoFar": 0}]}))
    result = _run(safety_api, monkeypatch, root)
    grades = sorted(h.evidence for h in result.hits if h.indicator == "got.invalid")
    assert grades == ["attempted", "contacted"]


def test_report_cannot_replace_safari_sandbox_files(tmp_path, monkeypatch, safety_api):
    import argparse
    from zbtriage import workflow
    root = _safari(tmp_path)
    tabs = tmp_path / "Library" / "Containers" / "com.apple.Safari" / "Data" / "Library" / "Safari" / "CloudTabs.db"
    cookies = tmp_path / "Library" / "Cookies" / "Cookies.binarycookies"
    cookies.parent.mkdir(parents=True)
    cookies.write_bytes(b"cook")
    api = safety_api.browser
    monkeypatch.setattr(api, "_browser_safari_roots", lambda: [("safari", str(root))])
    from zbtriage.modules import browser as source_browser
    monkeypatch.setattr(source_browser, "_browser_safari_roots", lambda: [("safari", str(root))])
    guard = getattr(safety_api.entry, "workflow_output_guard", None) or workflow.workflow_output_guard
    for target in (tabs, cookies):
        args = argparse.Namespace(iocs=[], target=[], evidence_file=[], pattern_path=[], collect_android=None,
                                  phone=None, json=str(target), share_json=None, report=None)
        before = target.read_bytes()
        with pytest.raises(ValueError):
            guard(args, str(target))
        assert target.read_bytes() == before


def test_unsupported_download_layout_is_a_gap_and_urls_stay_references(tmp_path, monkeypatch, safety_api):
    root = _safari(tmp_path)
    (root / "Downloads.plist").write_bytes(plistlib.dumps({"DownloadHistory": {
        "one": {"DownloadEntryURL": "https://got.invalid/a.pkg", "DownloadEntryProgressBytesSoFar": 1024}}}))
    result = _run(safety_api, monkeypatch, root)
    assert [h.evidence for h in result.hits if h.indicator == "got.invalid"] == ["referenced"]
    assert any(not c.ran and "safari-downloads" in c.name for c in result.checks)


@pytest.mark.parametrize("doc", [
    {"Downloads": [{"DownloadEntryURL": "https://got.invalid/a"}]},
    {"DownloadHistory": [{"record": {"DownloadEntryURL": "https://got.invalid/a"}}]},
    {"DownloadHistory": ["https://got.invalid/a"]},
])
def test_malformed_download_records_keep_their_urls_and_are_gaps(tmp_path, monkeypatch, safety_api, doc):
    root = _safari(tmp_path)
    (root / "Downloads.plist").write_bytes(plistlib.dumps(doc))
    result = _run(safety_api, monkeypatch, root)
    assert [h.evidence for h in result.hits if h.indicator == "got.invalid"] == ["referenced"]
    assert any(not c.ran and "safari-downloads" in c.name for c in result.checks)


def test_well_formed_downloads_are_not_a_gap(tmp_path, monkeypatch, safety_api):
    root = _safari(tmp_path)
    result = _run(safety_api, monkeypatch, root)
    assert not any(not c.ran and "safari-downloads" in c.name for c in result.checks)
