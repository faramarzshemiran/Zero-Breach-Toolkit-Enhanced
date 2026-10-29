"""Historical Defender protection-off events stay worth a look unless a different
antivirus explains them, and STIX family attribution is counted once per value."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import stix
from zbtriage.modules import traces
from zbtriage.result import ModuleResult
from test_followup_fixes import bundle
from test_stix_import import _ind, write


@pytest.fixture(params=("source", "bundle"))
def api(request, bundle):
    return traces if request.param == "source" else bundle


@pytest.fixture(params=("source", "bundle"))
def stix_api(request, bundle):
    return stix if request.param == "source" else bundle


@pytest.mark.parametrize("products,lead", (
    ([("Microsoft Defender Antivirus", 0)], True),
    ([("Windows Defender", 0)], True),
    ([("Microsoft Defender Antivirus", 0), ("Malwarebytes", 1)], True),
    ([("Microsoft Defender Antivirus", 1), ("Bitdefender", 0)], False),
    ([("Bitdefender", 0)], False),
    ([], True),
))
def test_defender_off_events_explained_only_by_another_antivirus(monkeypatch, api, products, lead):
    monkeypatch.setattr(api, "_tr_antivirus_products", lambda: (
        [{"name": n, "state": s, "signature_status": 1} for n, s in products], ""))
    monkeypatch.setattr(api, "_tr_events", lambda *a, **k: ([{"Id": 5001, "Time": "2026-06-23T03:58:52", "Data": {}}], ""))
    result = ModuleResult("traces") if api is traces else api.ModuleResult("traces")
    leads = api._TrLeads(result)
    protection = api._tr_check_antivirus(result, leads)
    from test_antivirus_status import ctx
    api._tr_check_defender(result, ctx(), leads, protection)
    leads.finish()
    assert any("Defender history records" in l.what for l in result.leads) is lead
    assert any("Defender history records" in n for n in result.notes) is (not lead)


def _bundle_doc(objects):
    return {"type": "bundle", "id": "bundle--1", "objects": objects}


def test_empty_linked_family_name_does_not_block_the_fallback(stix_api):
    doc = _bundle_doc([
        {"type": "malware", "id": "malware--1", "name": "\u0001"},
        _ind(1, "[domain-name:value='one.example']"),
        {"type": "relationship", "relationship_type": "indicates",
         "source_ref": "indicator--1", "target_ref": "malware--1"}])
    imported = stix_api.load_stix(write(doc), family_fallback="Pegasus")
    assert [i.family for i in imported.indicators] == ["Pegasus"]
    assert dict(imported.families) == {"Pegasus": 1}


def test_attributed_value_is_not_also_counted_unattributed(stix_api):
    # Two families, so unlinked indicators are not given a single-family label.
    doc = _bundle_doc([
        {"type": "malware", "id": "malware--1", "name": "Pegasus"},
        {"type": "malware", "id": "malware--2", "name": "Predator"},
        _ind(1, "[domain-name:value='evil.example']"),
        _ind(2, "[domain-name:value='evil.example']"),
        _ind(3, "[domain-name:value='other.example']"),
        {"type": "relationship", "relationship_type": "indicates",
         "source_ref": "indicator--1", "target_ref": "malware--1"}])
    imported = stix_api.load_stix(write(doc))
    assert dict(imported.families) == {"Pegasus": 1, "(unattributed)": 1}
