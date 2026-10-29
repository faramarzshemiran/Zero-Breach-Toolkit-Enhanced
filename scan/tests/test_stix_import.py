"""Importing published STIX 2.x bundles (Amnesty, the MVT project, ...).

These bundles are third-party files the tool does not control, read on the
computer of someone who may be a spyware target. The rules tested here:
  - only domain / IP / SHA-256 indicators are scanned for on a computer; every
    other kind is COUNTED as not applicable, never silently dropped;
  - a value that is unsafe to scan for (matches everything, matches local
    traffic, carries control characters) is refused and counted, not scanned;
  - nothing usable must never turn into a report ("searched for nothing, found
    nothing" reads like reassurance);
  - every finding carries the family the researchers attributed it to.
"""

from __future__ import annotations

import datetime
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import report  # noqa: E402
from zbtriage import stix  # noqa: E402
from zbtriage.iocs import (TYPE_DOMAIN, TYPE_IP, TYPE_SHA256, IocError,  # noqa: E402
                        load_any, merge)
from zbtriage.result import EV_CONTACTED, EV_ON_DISK, Hit, ModuleResult  # noqa: E402

HASH_A = "a" * 64
HASH_B = "b" * 64


def _ind(n, pattern):
    return {"type": "indicator", "id": "indicator--%d" % n, "pattern": pattern,
            "pattern_type": "stix", "spec_version": "2.1"}


def bundle(patterns, families=("Pegasus",), link=True):
    """A STIX bundle with one malware object per family. Indicator i is linked
    to family i % len(families) when `link` is set."""
    objects = []
    fam_ids = []
    for k, name in enumerate(families):
        fid = "malware--%d" % k
        fam_ids.append(fid)
        objects.append({"type": "malware", "id": fid, "name": name})
    for n, p in enumerate(patterns):
        objects.append(_ind(n, p))
        if link and fam_ids:
            objects.append({"type": "relationship", "relationship_type": "indicates",
                            "source_ref": "indicator--%d" % n,
                            "target_ref": fam_ids[n % len(fam_ids)]})
    return {"type": "bundle", "id": "bundle--1", "objects": objects}


def write(doc, name="test.stix2"):
    path = os.path.join(tempfile.mkdtemp(prefix="stix_"), name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc if isinstance(doc, str) else json.dumps(doc))
    return path


def write_curated(lines):
    path = os.path.join(tempfile.mkdtemp(prefix="cur_"), "iocs.txt")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("# as-of: 2026-10-20\n" + "\n".join(lines) + "\n")
    return path


class TestParsing(unittest.TestCase):
    def test_domain_ip_and_hash_become_scannable_indicators(self):
        imp = stix.load_stix(write(bundle([
            "[domain-name:value='Evil-Example.COM']",
            "[ipv4-addr:value='5.6.7.8']",
            "[file:hashes.sha256='%s']" % HASH_A.upper(),
            "[file:hashes.'SHA-256'='%s']" % HASH_B,
        ])))
        got = {i.value: (i.type, i.tier, i.family) for i in imp.indicators}
        self.assertEqual(got["evil-example.com"], (TYPE_DOMAIN, "infrastructure", "Pegasus"))
        self.assertEqual(got["5.6.7.8"], (TYPE_IP, "infrastructure-ip", "Pegasus"))
        self.assertEqual(got[HASH_A], (TYPE_SHA256, "sample", "Pegasus"))
        self.assertEqual(got[HASH_B], (TYPE_SHA256, "sample", "Pegasus"))

    def test_device_kinds_are_kept_and_unusable_kinds_counted(self):
        imp = stix.load_stix(write(bundle([
            "[domain-name:value='kept.example']",
            "[app:id='com.example.spy']",
            "[process:name='bh']",
            "[email-addr:value='x@example.org']",
            "[url:value='https://a.example/x']",
        ])))
        kinds = {i.value: (i.type, i.tier) for i in imp.indicators}
        self.assertEqual(kinds["kept.example"], ("domain", "infrastructure"))
        self.assertEqual(kinds["com.example.spy"], ("app-id", "artifact"))
        self.assertEqual(kinds["bh"], ("process", "artifact"))   # short real names kept
        self.assertEqual(kinds["x@example.org"], ("email", "infrastructure"))
        self.assertEqual(dict(imp.not_applicable), {"url:value": 1})
        self.assertEqual(imp.summary()["usable"], 1)
        self.assertEqual(imp.summary()["device_indicators"],
                         {"app-id": 1, "email": 1, "process": 1})
        self.assertEqual(imp.total, 5)

    def test_app_id_shaped_like_a_domain_never_shadows_the_domain(self):
        from zbtriage.iocs import TYPE_APP_ID, TYPE_DOMAIN as D
        s = load_any(write(bundle(["[app:id='same.example']",
                                   "[domain-name:value='same.example']"])))
        self.assertEqual(s.lookup("same.example").type, D)
        self.assertEqual(s.lookup_typed(TYPE_APP_ID, "same.example").type, TYPE_APP_ID)
        self.assertEqual([i.value for i in s.search("visited same.example today")],
                         ["same.example"])
        self.assertEqual(len(s), 2)

    def test_malformed_device_values_are_refused(self):
        for pattern in ("[app:id='not a package']", "[app:cert.sha1='xyz']",
                        "[configuration-profile:id='not-a-uuid']",
                        "[file:path='relative/path']", "[email-addr:value='nobody']"):
            with self.subTest(pattern=pattern):
                imp = stix.load_stix(write(bundle(["[domain-name:value='k.example']", pattern])))
                self.assertEqual(sum(imp.invalid.values()), 1)

    def test_family_comes_from_the_indicates_relationship(self):
        imp = stix.load_stix(write(bundle(
            ["[domain-name:value='one.example']", "[domain-name:value='two.example']"],
            families=("Predator", "KingSpawn"))))
        fam = {i.value: i.family for i in imp.indicators}
        self.assertEqual(fam, {"one.example": "Predator", "two.example": "KingSpawn"})

    def test_single_family_bundle_labels_unlinked_indicators(self):
        imp = stix.load_stix(write(bundle(["[domain-name:value='x.example']"],
                                          families=("Candiru",), link=False)))
        self.assertEqual(imp.indicators[0].family, "Candiru")

    def test_ip_filed_as_domain_is_read_as_ip(self):
        # Seen in a real published bundle: addresses under domain-name.
        imp = stix.load_stix(write(bundle(["[domain-name:value='31.13.0.7']"])))
        self.assertEqual(imp.indicators[0].type, TYPE_IP)
        self.assertEqual(imp.indicators[0].tier, "infrastructure-ip")

    def test_internationalised_domain_is_stored_as_punycode(self):
        imp = stix.load_stix(write(bundle(["[domain-name:value='bücher.example']"])))
        self.assertEqual(imp.indicators[0].value, "xn--bcher-kva.example")

    def test_unparseable_pattern_is_counted(self):
        imp = stix.load_stix(write(bundle([
            "[domain-name:value='ok.example']",
            "[domain-name:value = 'a.example'] OR [domain-name:value = 'b.example']",
        ])))
        self.assertEqual(imp.unparsed, 1)
        self.assertEqual(len(imp.indicators), 1)


class TestHostileValues(unittest.TestCase):
    """A value that would match far more than one server must never be scanned."""

    def refused(self, pattern):
        imp = stix.load_stix(write(bundle(["[domain-name:value='keep.example']", pattern])))
        return [i.value for i in imp.indicators], sum(imp.invalid.values())

    def test_values_that_match_everything_or_local_traffic_are_refused(self):
        for pattern in ("[domain-name:value='.']",
                        "[domain-name:value='localhost']",
                        "[domain-name:value='*.wild.example']",
                        "[ipv4-addr:value='0.0.0.0']",
                        "[ipv4-addr:value='10.1.2.3']",
                        "[ipv4-addr:value='127.0.0.1']",
                        "[ipv4-addr:value='192.168.1.1']",
                        "[ipv6-addr:value='::1']",
                        "[ipv4-addr:value='203.0.113.7']",
                        "[file:hashes.sha256='abc']",
                        "[domain-name:value='bad\u200bzero.example']"):
            with self.subTest(pattern=pattern):
                kept, refused = self.refused(pattern)
                self.assertEqual(kept, ["keep.example"])
                self.assertEqual(refused, 1)

    def test_family_label_is_single_line_and_bounded(self):
        imp = stix.load_stix(write(bundle(["[domain-name:value='x.example']"],
                                          families=("Bad\nName\x07" + "Z" * 200,))))
        fam = imp.indicators[0].family
        self.assertNotIn("\n", fam)
        self.assertNotIn("\x07", fam)
        self.assertLessEqual(len(fam), 80)

    def test_not_a_bundle_is_an_error(self):
        for content in ("not json", json.dumps({"no": "objects"}), json.dumps([1, 2])):
            with self.subTest(content=content[:12]):
                with self.assertRaises(IocError):
                    stix.load_stix(write(content))

    def test_oversized_file_is_refused_before_parsing(self):
        path = write(bundle(["[domain-name:value='x.example']"]))
        with patch.object(stix, "STIX_MAX_BYTES", 10):
            with self.assertRaises(IocError):
                stix.load_stix(path)


class TestEmptyAndMerge(unittest.TestCase):
    def test_phone_only_bundle_alone_is_an_error(self):
        with self.assertRaises(IocError):
            load_any(write(bundle(["[url:value='https://a.example/x']"])))

    def test_phone_only_bundle_among_others_loads_as_empty(self):
        empty = load_any(write(bundle(["[url:value='https://a.example/x']"])), allow_empty=True)
        self.assertEqual(len(empty), 0)
        full = load_any(write(bundle(["[domain-name:value='a.example']"])), allow_empty=True)
        merged = merge([empty, full])
        self.assertEqual([i.value for i in merged.indicators], ["a.example"])
        self.assertEqual(len(merged.sets), 2)

    def test_all_empty_never_produces_a_scan(self):
        a = load_any(write(bundle(["[url:value='https://a.example/1']"])), allow_empty=True)
        b = load_any(write(bundle(["[x-custom:name='b']"])), allow_empty=True)
        with self.assertRaises(IocError):
            merge([a, b])

    def test_merge_keeps_both_attributions_and_the_curated_tier(self):
        curated = load_any(write_curated(["shared.example\tcc\tprimary\tCitizen Lab"]))
        vendor = load_any(write(bundle(["[domain-name:value='shared.example']",
                                        "[domain-name:value='only-vendor.example']"],
                                       families=("Candiru",)), name="amnesty.stix2"))
        merged = merge([curated, vendor])
        shared = merged.lookup("shared.example")
        self.assertEqual(shared.tier, "cc")             # curated file wins the tier
        self.assertIn("Citizen Lab", shared.source)
        self.assertIn("amnesty.stix2", shared.source)
        self.assertEqual(shared.family, "Candiru")
        self.assertIsNotNone(merged.lookup("only-vendor.example"))

    def test_merged_freshness_is_only_as_good_as_the_oldest_curated_date(self):
        new = load_any(write_curated(["a.example\tcc\tprimary"]))
        vendor = load_any(write(bundle(["[domain-name:value='b.example']"])))
        merged = merge([new, vendor])
        # The bundle has no curated date, so the merged set must not claim one.
        self.assertIsNone(merged.asof)


class TestReport(unittest.TestCase):
    def render(self, hit, iocs):
        module = ModuleResult("synthetic")
        module.ran("fixture")
        module.add_hit(hit)
        platform = {"system": "Synthetic", "release": "test", "version": "test",
                    "machine": "test", "python": "test"}
        with patch.object(report, "_platform_info", return_value=platform):
            doc = report.build_document(iocs, [module], datetime.datetime(2026, 10, 25))
        return doc, report.render_human(doc)

    def setUp(self):
        curated = load_any(write_curated(["c.example\tcc\tprimary"]))
        vendor = load_any(write(bundle(["[domain-name:value='pegasus-c2.example']",
                                        "[app:id='com.example']"]), name="pegasus.stix2"))
        self.iocs = merge([curated, vendor])

    def test_family_is_shown_on_the_finding_and_in_json(self):
        ind = self.iocs.lookup("pegasus-c2.example")
        hit = Hit(ind.value, "History", "visited", ind.tier, ind.confidence, ind.source,
                  EV_CONTACTED, "", "", ind.family)
        doc, text = self.render(hit, self.iocs)
        self.assertIn("family : Pegasus", text)
        self.assertEqual(doc["modules"]["synthetic"]["hits"][0]["family"], "Pegasus")
        self.assertEqual(doc["ioc_set"]["families"], {"Pegasus": 2})   # domain + app id

    def test_report_says_what_each_file_could_not_be_used_for(self):
        ind = self.iocs.lookup("pegasus-c2.example")
        hit = Hit(ind.value, "History", "visited", ind.tier, ind.confidence, ind.source,
                  EV_CONTACTED, "", "", ind.family)
        doc, text = self.render(hit, self.iocs)
        self.assertIn("from pegasus.stix2 : 1 for computer checks (1 for phone-backup / mail "
                      "checks)", text)
        self.assertEqual(len(doc["ioc_set"]["sets"]), 2)

    def test_imported_infrastructure_has_a_plain_language_meaning(self):
        self.assertIn("infrastructure", report.TIER_MEANING)
        self.assertIn("infrastructure-ip", report.TIER_MEANING)
        self.assertIn("reassigned", report.TIER_MEANING["infrastructure-ip"])

    def test_imported_ip_contact_gets_the_reassignment_caveat(self):
        hit = {"tier": "infrastructure-ip", "evidence": EV_CONTACTED}
        self.assertIn("IP ADDRESS", report._headline_for(hit))
        self.assertIn("who controlled it", report._evidence_gloss(hit))

    def test_imported_sample_on_disk_is_conclusive(self):
        hit = {"tier": "sample", "evidence": EV_ON_DISK}
        self.assertEqual(report._headline_for(hit), "A KNOWN SPYWARE FILE IS ON THIS MACHINE")


if __name__ == "__main__":
    unittest.main()
