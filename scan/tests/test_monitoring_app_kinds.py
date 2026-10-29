"""Monitoring-app indicators carry their publisher's classification.

ECHAP's STIX export writes iPhone bundle ids and Android packages alike as app
ids, so an iPhone-only id could match on Android (a Pixel names one in a system
flag). The ids the publisher lists only as iPhone bundles are pinned with the
release and marked as such, and the Android checks skip them. ECHAP also marks
each app as "stalkerware" or "watchware" (an app that does not hide itself,
often a family-safety app); the report words a watchware match accordingly,
with the same safety advice."""
import dataclasses
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import feeds, report
from zbtriage.context import ScanContext
from zbtriage.iocs import Indicator, IocSet, ios_only, watchware
from zbtriage.modules import android
from test_android import collection, iocs as base_iocs

IOS_ID = "com.example.parent.ios"
WATCH_ID = "com.example.familysafety"
STALK_ID = "com.example.hidden.spy"


def _bundle():
    objects = [
        {"type": "malware", "id": "malware--w", "name": "FamilyApp", "is_family": True,
         "description": "Watchware application"},
        {"type": "malware", "id": "malware--s", "name": "SpyApp", "is_family": True,
         "description": "Stalkerware application"},
    ]
    for n, (value, target) in enumerate(((IOS_ID, "malware--w"), (WATCH_ID, "malware--w"),
                                         (STALK_ID, "malware--s"))):
        objects += [{"type": "indicator", "id": "indicator--%d" % n, "pattern_type": "stix",
                     "pattern": "[app:id='%s']" % value},
                    {"type": "relationship", "id": "relationship--%d" % n,
                     "relationship_type": "indicates", "source_ref": "indicator--%d" % n,
                     "target_ref": target}]
    return {"type": "bundle", "id": "bundle--1", "objects": objects}


def _load(monkeypatch):
    monkeypatch.setattr(feeds, "FEED_IOS_ONLY_APP_IDS", {"echap-stalkerware": [IOS_ID]})
    src = [s for s in feeds.SOURCES if s["id"] == "echap-stalkerware"][0]
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "stalkerware.stix2")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(_bundle(), fh)
        return {i.value: i for i in feeds._load_source_file(src, path).indicators}


def test_publisher_classification_is_carried(monkeypatch):
    got = _load(monkeypatch)
    assert {i.tier for i in got.values()} == {"stalkerware"}
    assert ios_only(got[IOS_ID]) and not ios_only(got[WATCH_ID]) and not ios_only(got[STALK_ID])
    assert watchware(got[IOS_ID]) and watchware(got[WATCH_ID]) and not watchware(got[STALK_ID])


def _android(extra_indicators, installed):
    folder = collection(spy=False)
    path = os.path.join(folder, "packages.json")
    packages = json.load(open(path))
    for n, name in enumerate(installed):
        packages.append({"name": name, "installer": "com.android.vending", "third_party": True,
                         "system": False, "disabled": False, "uid": 50 + n, "files": []})
    json.dump(packages, open(path, "w"))
    with open(os.path.join(folder, "dumpsys.txt"), "w") as fh:
        fh.write("DUMP OF SERVICE usagestats:\n  package={} totalTime=5\n".format(IOS_ID))
    base = base_iocs()
    ctx = ScanContext(iocs=IocSet(list(base.indicators) + list(extra_indicators), "t", None),
                      emit=lambda _m: None, phone_path=folder)
    return android.run(ctx)


def test_android_never_matches_an_iphone_only_bundle_id(monkeypatch):
    got = _load(monkeypatch)
    result = _android(got.values(), installed=[IOS_ID, WATCH_ID])
    names = {h.indicator for h in result.hits}
    assert IOS_ID not in names
    assert WATCH_ID in names


def test_installed_watchware_is_described_as_not_hidden(monkeypatch):
    got = _load(monkeypatch)
    result = _android(got.values(), installed=[WATCH_ID, STALK_ID])
    detail = {h.indicator: h.detail for h in result.hits}
    assert "does not hide itself" in detail[WATCH_ID]
    assert "does not hide itself" not in detail[STALK_ID]


def test_report_wording_for_watchware_keeps_the_safety_advice():
    watch = {"tier": "stalkerware", "evidence": "on-device",
             "indicator_context": [{"monitoring": "watchware"}]}
    stalk = {"tier": "stalkerware", "evidence": "on-device",
             "indicator_context": [{"monitoring": "stalkerware"}]}
    assert "DOES NOT HIDE ITSELF" in report._headline_for(watch)
    assert "DOES NOT HIDE ITSELF" not in report._headline_for(stalk)
    for hits, openly in (([watch], True), ([watch, stalk], False)):
        lines = []
        report._next_steps(lines.append, hits)
        text = " ".join(lines)
        assert ("does not hide itself" in text) is openly
        assert "stopstalkerware.org" in text


def test_plain_indicators_are_neither():
    plain = Indicator("com.x.y", "artifact", "primary", "app-id", "t")
    assert not ios_only(plain) and not watchware(plain)
    mixed = dataclasses.replace(plain, contexts=(json.dumps({"platforms": ["ios"]}),
                                                 json.dumps({"platforms": ["android"]})))
    assert not ios_only(mixed)
