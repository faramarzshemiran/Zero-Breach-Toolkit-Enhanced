"""Regressions for indicator handling.

Each test pins one behaviour so it cannot drift back:
withdrawn indicators no longer produce an actionable verdict (F1), a publisher's
newest version decides whether it withdrew an indicator (F2), domain names that
IDNA 2003 and browsers encode differently are refused rather than mis-stored
(F3), and hand-written lists refuse non-public addresses as published feeds
already did (F4).
"""
import datetime
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import contract, report
from zbtriage.evidence import _withdrawn_only
from zbtriage.iocs import Indicator, IocError, IocSet, _value_problem, load
from zbtriage.result import Hit, ModuleResult, EV_CONTACTED
from zbtriage.stix import _normalise

BAD = "withdrawn-review.example"
LIVE = "live-review.example"


def _indicator(value, records):
    return Indicator(value, "infrastructure", "primary", "domain", "fixture",
                     contexts=tuple(json.dumps(r) for r in records))


def _document(hits, gap=False):
    """hits: list of (value, records). Every hit has contact evidence."""
    r = ModuleResult("browser")
    r.ran("history")
    if gap:
        r.could_not_run("cookies", "locked by a running browser")
    inds = []
    for value, records in hits:
        inds.append(_indicator(value, records))
        r.add_hit(Hit(value, "fixture", "fixture", tier="infrastructure",
                      evidence=EV_CONTACTED, kind="domain"))
    return report.build_document(IocSet(inds, "fixture", None), [r], datetime.datetime.now())


def _ids(entries):
    return [e["id"] for e in entries]


# --- F1: a withdrawn match is not an actionable finding -----------------------

def test_withdrawn_contact_is_not_a_finding_and_does_not_ask_to_preserve():
    doc = _document([(BAD, [{"source": "pub", "revoked": True}])])
    v = doc["verdict"]
    assert v["status"] == "WITHDRAWN_ONLY"
    assert (v["findings_total"], v["withdrawn_total"], v["references_total"]) == (0, 1, 0)
    assert contract.contract_exit_code(doc) == contract.EXIT_OK
    assert "preserve-evidence" not in _ids(doc["next_steps"])
    assert "self-review" in _ids(doc["next_steps"])
    relay = _ids(doc["must_relay"])
    assert "preserve" not in relay
    assert "withdrawn-only" in relay
    # Not described as references: the grade records real contact.
    assert "references-only" not in relay


def test_withdrawn_with_gaps_keeps_exit_3():
    doc = _document([(BAD, [{"source": "pub", "revoked": True}])], gap=True)
    assert doc["verdict"]["status"] == "WITHDRAWN_ONLY_WITH_GAPS"
    assert contract.contract_exit_code(doc) == contract.EXIT_GAPS


def test_an_active_finding_beside_a_withdrawn_one_is_still_a_finding():
    doc = _document([(BAD, [{"source": "pub", "revoked": True}]),
                     (LIVE, [{"source": "pub", "revoked": False}])])
    v = doc["verdict"]
    assert v["status"] == "INDICATORS_FOUND"
    assert (v["findings_total"], v["withdrawn_total"]) == (1, 1)
    assert contract.contract_exit_code(doc) == contract.EXIT_FOUND
    assert "preserve-evidence" in _ids(doc["next_steps"])


def test_summary_and_verdict_text_agree_with_the_machine_verdict():
    doc = _document([(BAD, [{"source": "pub", "revoked": True}])])
    summary = report.render_summary(doc)
    assert "WITHDRAWN" in summary
    assert "Not an actionable finding" in summary
    assert "potentially SERIOUS" not in summary
    timeline_kinds = {row["kind"] for row in doc["timeline"]}
    assert "finding" not in timeline_kinds


def test_shared_summary_carries_the_withdrawn_count_only():
    doc = _document([(BAD, [{"source": "pub", "revoked": True}])])
    shared = report.share_summary(doc)
    assert shared["verdict"]["withdrawn_total"] == 1
    assert BAD not in json.dumps(shared)


# --- F2: the newest version from each publisher decides ------------------------

def test_stale_active_copy_cannot_outlive_the_same_publishers_withdrawal():
    records = [{"publisher": "Pub", "revoked": False, "modified": "2026-01-01T00:00:00Z"},
               {"publisher": "Pub", "revoked": True, "modified": "2026-10-18T00:00:00Z"}]
    assert _withdrawn_only(records) is True
    assert _document([(BAD, records)])["verdict"]["status"] == "WITHDRAWN_ONLY"


def test_a_publisher_reactivating_after_a_withdrawal_stays_live():
    records = [{"publisher": "Pub", "revoked": True, "modified": "2026-03-01T00:00:00Z"},
               {"publisher": "Pub", "revoked": False, "modified": "2026-09-01T00:00:00Z"}]
    assert _withdrawn_only(records) is False


def test_different_publishers_disagreeing_stays_actionable():
    records = [{"publisher": "A", "revoked": True, "modified": "2026-10-18T00:00:00Z"},
               {"publisher": "B", "revoked": False, "modified": "2026-01-01T00:00:00Z"}]
    assert _withdrawn_only(records) is False
    assert _document([(BAD, records)])["verdict"]["status"] == "INDICATORS_FOUND"


def test_an_undated_active_copy_keeps_it_live():
    records = [{"publisher": "Pub", "revoked": True, "modified": "2026-10-18T00:00:00Z"},
               {"publisher": "Pub", "revoked": False}]
    assert _withdrawn_only(records) is False


# --- F3: IDNA 2003 and browsers disagree on these names -----------------------

@pytest.mark.parametrize("name", ["faß.de", "σοφιας.gr"])
def test_deviation_characters_are_refused_in_published_feeds(name):
    value, problem = _normalise("domain", name)
    assert problem, value
    # The old behaviour stored this, which matches an unrelated real domain.
    assert value != "fass.de"


def test_other_internationalised_names_still_encode():
    assert _normalise("domain", "bücher.de") == ("xn--bcher-kva.de", "")


def test_deviation_characters_stop_a_hand_written_list_with_a_fix(tmp_path):
    path = tmp_path / "mine.txt"
    path.write_text("faß.de\tinfrastructure\tprimary\n", encoding="utf-8")
    with pytest.raises(IocError, match="xn--"):
        load(str(path))


# --- F4: hand-written lists refuse what published feeds already refused --------

@pytest.mark.parametrize("address", ["127.0.0.1", "192.168.1.1", "10.0.0.1", "169.254.1.1",
                                     "fe80::1234:5678", "fc00::1234:5678"])
def test_non_public_addresses_are_refused_everywhere(address):
    assert _value_problem(address, "ip") == "not a public internet address"
    assert _normalise("ip", address)[1]


def test_a_very_short_address_is_refused_by_the_earlier_rule():
    # "::1" is under seven characters, so the broad-match rule refuses it first.
    assert _value_problem("::1", "ip")


def test_a_public_address_is_still_accepted():
    assert _value_problem("5.6.7.8", "ip") == ""


@pytest.mark.parametrize("address", ["203.0.113.8", "198.51.100.7", "192.0.2.1", "2001:db8::1:2"])
def test_documentation_ranges_are_allowed_by_hand_but_refused_from_feeds(address):
    # They never occur on a real network, so they cannot match local traffic,
    # and release fixtures rely on them because no real host has them. A
    # published feed shipping one is corrupt, so feeds still refuse them.
    assert _value_problem(address, "ip") == ""
    assert _normalise("ip", address)[1] == "not a public internet address"


def test_ambiguous_leading_zero_is_refused_not_misread():
    assert _value_problem("052.174.65.77", "ip") == "not a valid IP address"


def test_a_private_address_in_a_hand_written_list_is_reported_by_line(tmp_path):
    path = tmp_path / "mine.txt"
    path.write_text("192.168.1.1\tinfrastructure-ip\tprimary\n", encoding="utf-8")
    with pytest.raises(IocError, match="line 1.*not a public internet address"):
        load(str(path))
