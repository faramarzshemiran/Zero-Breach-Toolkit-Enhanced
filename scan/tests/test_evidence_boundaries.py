"""Evidence grades and source identity survive missing metadata and listing bounds."""
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from zbtriage.evidence import evidence_correlations
from test_evidence_safety import _ctx, safety_api
from test_followup_fixes import bundle
from test_ios_upgrade import backup, db_bytes


@pytest.mark.parametrize("browser", ("safari", "chrome", "firefox"))
@pytest.mark.parametrize("origin", (None, -1, 99, "unknown", "0", b"0"))
def test_unsupported_browser_origin_stays_a_reference_with_a_gap(tmp_path, safety_api, browser, origin):
    if browser == "safari":
        domain, relative, check = "HomeDomain", "Library/Safari/History.db", "ios:safari"
        schema = "CREATE TABLE history_items(id,url); CREATE TABLE history_visits(history_item,visit_time,origin)"
        statements = [("INSERT INTO history_items VALUES(1,'https://fixture.invalid')", ()),
                      ("INSERT INTO history_visits VALUES(1,700000000,?)", (origin,)),
                      ("INSERT INTO history_visits VALUES(1,700000001,0)", ())]
    elif browser == "chrome":
        domain, relative, check = "AppDomain-com.google.chrome", "Library/Application Support/Google/Chrome/Default/History", "ios:chrome-history"
        schema = ("CREATE TABLE urls(id,url); CREATE TABLE visits(id,url,visit_time,originator_cache_guid);"
                  "CREATE TABLE visit_source(id,source)")
        statements = [("INSERT INTO urls VALUES(1,'https://fixture.invalid')", ()),
                      ("INSERT INTO visits VALUES(1,1,13400000000000000,'')", ()),
                      ("INSERT INTO visits VALUES(2,1,13400000000000001,'')", ()),
                      ("INSERT INTO visit_source VALUES(1,?)", (origin,))]
    else:
        domain, relative, check = "AppDomainGroup-group.org.mozilla.ios.Firefox", "profile.profile/browser.db", "ios:firefox-history"
        schema = "CREATE TABLE history(id,url); CREATE TABLE visits(siteID,date,is_local)"
        statements = [("INSERT INTO history VALUES(1,'https://fixture.invalid')", ()),
                      ("INSERT INTO visits VALUES(1,1600000000000000,?)", (origin,)),
                      ("INSERT INTO visits VALUES(1,1600000000000001,1)", ())]
    raw, _ = db_bytes(tmp_path, schema, statements)
    root = tmp_path / "backup"
    backup(root, [(domain, relative, raw)])
    result = safety_api.ios_run(_ctx(root))
    hits = [h for h in result.hits if relative + ":record " in h.location]
    assert [h.evidence for h in hits] == ["referenced", "contacted"]
    assert any(not c.ran and c.name == check and "origin" in c.reason for c in result.checks)


@pytest.mark.parametrize("source,guid,grade,gap", (
    (1, 99, "referenced", True), (1, b"", "referenced", True),
    (3, "", "referenced", False), (6, "", "referenced", False),
    (7, "", "referenced", False), (1, "other-device", "referenced", False),
    (1, "", "contacted", False), (0, "", "referenced", False)))
def test_chrome_source_and_device_metadata_are_interpreted_together(tmp_path, safety_api, source, guid, grade, gap):
    raw, _ = db_bytes(tmp_path,
        "CREATE TABLE urls(id,url); CREATE TABLE visits(id,url,visit_time,originator_cache_guid); CREATE TABLE visit_source(id,source)",
        [("INSERT INTO urls VALUES(1,'https://fixture.invalid')", ()),
         ("INSERT INTO visits VALUES(1,1,13400000000000000,?)", (guid,)),
         ("INSERT INTO visit_source VALUES(1,?)", (source,))])
    root = tmp_path / "backup"
    backup(root, [("AppDomain-com.google.chrome", "Library/Application Support/Google/Chrome/Default/History", raw)])
    result = safety_api.ios_run(_ctx(root))
    assert [h.evidence for h in result.hits] == [grade]
    assert any(not c.ran and c.name == "ios:chrome-history" for c in result.checks) == gap


@pytest.mark.parametrize("count", (99, 100, 101))
@pytest.mark.parametrize("reverse", (False, True))
def test_listing_bounds_preserve_grades_provenance_and_artifact_correlations(tmp_path, safety_api, count, reverse):
    tabs = [("INSERT INTO tabs VALUES(?)", ("fixture.invalid",))] * count
    tabs.insert(0 if reverse else len(tabs), ("INSERT INTO tabs VALUES(?)", ("second.invalid",)))
    raw, _ = db_bytes(tmp_path, "CREATE TABLE tabs(url)", tabs)
    other, _ = db_bytes(tmp_path, "CREATE TABLE tabs(url)",
                       [("INSERT INTO tabs VALUES('fixture.invalid')", ())])
    local, _ = db_bytes(tmp_path,
        "CREATE TABLE history_items(id,url); CREATE TABLE history_visits(history_item,visit_time,origin)",
        [("INSERT INTO history_items VALUES(1,'https://fixture.invalid')", ()),
         ("INSERT INTO history_visits VALUES(1,700000000,0)", ())])
    first = ("HomeDomain", "Library/Safari/BrowserState.db", raw)
    second = ("HomeDomain", "Library/Safari/Profiles/other/BrowserState.db", other)
    items = [second, first] if reverse else [first, second]
    items.append(("HomeDomain", "Library/Safari/History.db", local))
    root = tmp_path / "backup"
    backup(root, items)
    result = safety_api.ios_run(_ctx(root))
    a = [h for h in result.hits if h.indicator == "fixture.invalid"]
    assert sum(h.evidence == "referenced" for h in a) == 100
    assert sum(h.evidence == "contacted" for h in a) == 1
    assert sum(h.indicator == "second.invalid" for h in result.hits) == 1
    assert result.submetrics.get("matching_records_not_listed", 0) == count - 99
    for hit in result.hits:
        assert hit.provenance["source"] == hit.artifact
        assert hashlib.sha256(Path(hit.artifact).read_bytes()).hexdigest() == hit.provenance["sha256"]
        assert hit.location.endswith(":record " + str(hit.provenance["record_id"]))
    correlate = getattr(safety_api.entry, "evidence_correlations", evidence_correlations)
    correlations = correlate({"ios": result.to_dict()})
    assert len(correlations) == 1
    assert correlations[0]["indicator"] == "fixture.invalid"
    assert correlations[0]["artifact_count"] == len({h.artifact for h in a})
    assert all(result.hits[row["hit_index"]].indicator == "fixture.invalid"
               for row in correlations[0]["records"])
