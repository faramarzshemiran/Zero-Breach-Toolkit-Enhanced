"""Saved bookmarks are references; malformed neighbors and bounds stay visible."""
import json
import os
import sys
import stat
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_evidence_safety import _ctx, _history, safety_api
from test_followup_fixes import bundle
from test_ios_upgrade import backup, db_bytes, tree_hashes


@pytest.mark.parametrize("damage", ("none", "neighbor", "deep", "invalid-json"))
def test_chromium_bookmarks_are_checked_as_references(tmp_path, monkeypatch, safety_api, damage):
    profile = tmp_path / "Default"
    _history(profile, "ordinary.invalid")
    nodes = [{"type": "url", "url": "https://fixture.invalid/", "name": "ordinary"}]
    if damage == "neighbor":
        nodes.insert(0, {"type": "url", "url": ["second.invalid"]})
    if damage == "deep":
        node = {"type": "url", "url": "https://second.invalid/"}
        for _ in range(35):
            node = {"type": "folder", "children": [node]}
        nodes.insert(0, node)
    doc = {"roots": {"bookmark_bar": {"type": "folder", "children": nodes}}}
    path = profile / "Bookmarks"
    path.write_text("{" if damage == "invalid-json" else json.dumps(doc), encoding="utf-8")
    original = path.read_bytes()
    api = safety_api.browser
    monkeypatch.setattr(api, "CHROMIUM_ROOTS", [("chrome", str(tmp_path))])
    monkeypatch.setattr(api, "FIREFOX_ROOTS", [])
    monkeypatch.setattr(api, "APP_ROOTS", [])
    result = safety_api.browser_run(_ctx())
    found = [h for h in result.hits if h.location == str(path)]
    assert {h.indicator for h in found} == (set() if damage == "invalid-json" else {"fixture.invalid"})
    assert all(h.evidence == "referenced" for h in found)
    assert any(c.name == "chrome:bookmarks" and c.ran for c in result.checks) is (damage != "invalid-json")
    assert any(c.name.startswith("chrome:bookmarks") and not c.ran for c in result.checks) is (damage != "none")
    assert path.read_bytes() == original


def test_explicit_bookmark_file_selects_only_its_profile(tmp_path, safety_api):
    path = tmp_path / "Bookmarks"
    path.write_text(json.dumps({"roots": {"saved": {"type": "url", "url": "https://fixture.invalid"}}}))
    result = safety_api.browser_run(_ctx(targets=(str(path),)))
    assert [h.indicator for h in result.hits] == ["fixture.invalid"]
    assert result.hits[0].evidence == "referenced"


@pytest.mark.parametrize("failure", ("special", "oversize", "replaced", "changed"))
def test_bookmark_unsafe_or_changing_file_is_a_gap(tmp_path, monkeypatch, safety_api, failure):
    path = tmp_path / "Bookmarks"
    path.write_text(json.dumps({"roots": {"saved": {"type": "url", "url": "https://fixture.invalid"}}}))
    api = safety_api.browser
    original_lstat, original_fstat = api.os.lstat, api.os.fstat
    calls = []

    def adjusted(info, **changes):
        values = {key: getattr(info, key) for key in dir(info) if key.startswith("st_")}
        values.update(changes)
        return types.SimpleNamespace(**values)

    def lstat(selected, *args, **kw):
        info = original_lstat(selected, *args, **kw)
        if str(selected) == str(path):
            if failure == "special":
                return adjusted(info, st_mode=stat.S_IFIFO | 0o600)
            if failure == "oversize":
                return adjusted(info, st_size=16 * 1024 * 1024 + 1)
        return info

    def fstat(fd):
        info = original_fstat(fd)
        calls.append(fd)
        if failure == "replaced":
            return adjusted(info, st_ino=info.st_ino + 1)
        if failure == "changed" and len(calls) == 2:
            return adjusted(info, st_mtime_ns=info.st_mtime_ns + 1)
        return info

    monkeypatch.setattr(api.os, "lstat", lstat)
    monkeypatch.setattr(api.os, "fstat", fstat)
    result = safety_api.browser_run(_ctx(targets=(str(path),)))
    assert not result.hits
    assert any(not check.ran and "bookmarks" in check.name for check in result.checks)
    if failure in ("special", "oversize"):
        assert not calls


@pytest.mark.parametrize("schema", ("valid", "unsupported"))
def test_ios_bookmarks_remain_references_with_source_provenance(tmp_path, safety_api, schema):
    table = "bookmarks" if schema == "valid" else "unknown"
    raw, _ = db_bytes(tmp_path, "CREATE TABLE " + table + "(url TEXT)", [
        ("INSERT INTO " + table + " VALUES(?)", ("https://fixture.invalid/",))])
    root = tmp_path / "backup"
    backup(root, [("HomeDomain", "Library/Safari/Bookmarks.db", raw)])
    before = tree_hashes(root)
    result = safety_api.ios_run(_ctx(root))
    hits = [h for h in result.hits if h.provenance.get("parser") == "ios:safari-bookmarks/1"]
    if schema == "valid":
        assert len(hits) == 1 and hits[0].evidence == "referenced"
        assert hits[0].provenance["sha256"] and hits[0].provenance["record_id"]
    else:
        assert not hits
        assert any(not c.ran and c.name == "ios:safari-bookmarks" for c in result.checks)
    assert tree_hashes(root) == before
