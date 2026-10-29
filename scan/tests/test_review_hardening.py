"""Release hardening regressions. Synthetic artifacts only; no real collectors or downloads."""
import contextlib
import datetime
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import cli, feeds, report
from zbtriage.context import ScanContext
from zbtriage.iocs import Indicator, IocSet, IocError, merge
from zbtriage.modules import android, traces
from zbtriage.result import Hit, ModuleResult, EV_REFERENCED, EV_CONTACTED
from test_feeds import SRC, STIX_OK, fake_fetch


def review_set():
    result = IocSet([Indicator("review.invalid", "infrastructure", "primary", "domain",
                               "synthetic")], "synthetic", 9999999999)
    result.asof = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d")
    return result


def review_document(indicators=None, evidence=None, gap=False):
    module = ModuleResult("browser")
    module.ran("history")
    if gap:
        module.could_not_run("history", "private gap reason")
    if evidence:
        module.add_hit(Hit("review.invalid", "PRIVATE_PATH", "PRIVATE_SMS", evidence=evidence,
                           profile="PRIVATE_PROFILE", observed="2026-01-01T10:00:00"))
    return report.build_document(indicators or review_set(), [module], datetime.datetime.now())


class TestFeedHardening(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="feed_review_")
        self.addCleanup(temp.cleanup)
        self.cache = Path(temp.name)
        p = patch.object(feeds, "SOURCES", [SRC])
        p.start()
        self.addCleanup(p.stop)

    def update(self):
        return feeds.update(str(self.cache), sources=[SRC], fetch=fake_fetch(STIX_OK))

    def test_manifest_paths_never_reach_open(self):
        for name in ("../outside.stix2", "C:/outside.stix2", "//review.invalid/share/x", "nested/x"):
            with self.subTest(name=name), patch.object(feeds, "read_manifest", return_value={
                    SRC["id"]: {"file": name}}), patch("builtins.open") as opened:
                sets, status = feeds.cached_sets(str(self.cache))
                self.assertEqual(sets, [])
                self.assertTrue(status["refused"])
                opened.assert_not_called()

    def test_redirected_manifest_refused_before_open(self):
        with patch.object(feeds, "path_problem", return_value="redirected"), patch("io.open") as opened:
            sets, status = feeds.cached_sets(str(self.cache))
        self.assertFalse(sets)
        self.assertTrue(status["refused"])
        opened.assert_not_called()

    def test_redirected_feed_refused_before_open(self):
        self.update()
        manifest = feeds.read_manifest(str(self.cache))
        with patch.object(feeds, "read_manifest", return_value=manifest), \
                patch.object(feeds, "path_problem", return_value="redirected"), \
                patch("builtins.open") as opened:
            sets, status = feeds.cached_sets(str(self.cache))
        self.assertFalse(sets)
        self.assertTrue(status["refused"])
        opened.assert_not_called()

    def test_malformed_manifest_is_a_gap(self):
        for data in ("{", '{"sources": []}', '{"sources": {"test-src": 42}}'):
            with self.subTest(data=data):
                (self.cache / feeds.MANIFEST).write_text(data)
                sets, status = feeds.cached_sets(str(self.cache))
                self.assertFalse(sets)
                self.assertTrue(status["refused"])

    def test_all_expected_sources_are_enumerated_when_cache_is_empty(self):
        sets, status = feeds.cached_sets(str(self.cache))
        self.assertEqual(status["missing"], [SRC["id"]])

    def test_update_repairs_corrupted_bytes(self):
        self.update()
        (self.cache / "test-src.stix2").write_bytes(b"corrupted")
        result = self.update()
        self.assertEqual(result["sources"][0]["status"], "updated")
        loaded, status = feeds.cached_sets(str(self.cache))
        self.assertEqual(len(loaded), 1)
        self.assertEqual(status["refused"], [])

    def test_update_repairs_a_wrong_manifest_filename(self):
        self.update()
        path = self.cache / feeds.MANIFEST
        old = json.loads(path.read_text())
        old["sources"][SRC["id"]]["file"] = "../outside.stix2"
        path.write_text(json.dumps(old))
        self.assertEqual(self.update()["sources"][0]["status"], "updated")
        loaded, status = feeds.cached_sets(str(self.cache))
        self.assertEqual(len(loaded), 1)
        self.assertFalse(status["refused"])

    def test_unchanged_download_updates_verification_date(self):
        self.update()
        path = self.cache / feeds.MANIFEST
        old = json.loads(path.read_text())
        old["sources"][SRC["id"]]["checked_utc"] = "2020-01-01T00:00:00Z"
        path.write_text(json.dumps(old))
        self.assertEqual(self.update()["sources"][0]["status"], "unchanged")
        loaded, status = feeds.cached_sets(str(self.cache))
        self.assertEqual(loaded[0].age_days(), 0)
        self.assertFalse(status["loaded"][0]["stale"])

    def test_unknown_and_stale_refresh_dates_are_reported(self):
        self.update()
        path = self.cache / feeds.MANIFEST
        original = json.loads(path.read_text())
        for value, field in (("2020-01-01T00:00:00Z", "stale"), ("bad", "freshness_unknown"),
                             ("2099-01-01T00:00:00Z", "freshness_unknown")):
            with self.subTest(value=value):
                original["sources"][SRC["id"]]["checked_utc"] = value
                path.write_text(json.dumps(original))
                loaded, status = feeds.cached_sets(str(self.cache))
                self.assertTrue(status["loaded"][0][field])
                status["used"] = True
                loaded[0].feeds = status
                doc = review_document(loaded[0])
                self.assertEqual(doc["exit_code"], 3)
                self.assertTrue(doc["coverage"]["not_checked"])

    def test_update_json_path_checked_before_download(self):
        with patch.object(feeds, "path_problem", return_value="remote"), \
                patch.object(feeds, "update") as updater, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(feeds.update_command(None, "report.json"), 1)
        updater.assert_not_called()

    def test_cli_update_checks_output_before_dispatch(self):
        with patch.object(cli, "_refuse_remote", return_value=True) as guard, \
                patch.object(cli, "_run_update") as updater:
            self.assertEqual(cli.main(["--no-banner", "--update", "--json", "report.json"]), 1)
        updater.assert_not_called()
        guard.assert_called_once_with("--json", "report.json")


class TestCoverageAndAdvice(unittest.TestCase):
    def test_partial_feeds_cannot_produce_exit_zero(self):
        s = review_set()
        s.feeds = {"used": True, "loaded": [{"id": "present"}], "missing": ["absent"], "refused": []}
        doc = review_document(s)
        self.assertEqual(doc["exit_code"], 3)
        self.assertTrue(doc["coverage"]["not_checked"])
        self.assertIn("feeds-incomplete", [x["id"] for x in doc["must_relay"]])
        self.assertIn("update-indicators", [x["id"] for x in doc["next_steps"]])

    def test_missing_feeds_do_not_hide_real_findings(self):
        s = review_set()
        s.feeds = {"used": True, "loaded": [], "missing": ["absent"]}
        doc = review_document(s, EV_CONTACTED)
        self.assertEqual(doc["exit_code"], 2)
        self.assertTrue(doc["verdict"]["gaps"])

    def test_reference_only_is_not_an_actionable_finding(self):
        for gap in (False, True):
            with self.subTest(gap=gap):
                doc = review_document(evidence=EV_REFERENCED, gap=gap)
                self.assertEqual(doc["exit_code"], 3 if gap else 0)
                self.assertEqual(doc["verdict"]["findings_total"], 0)
                self.assertEqual(doc["verdict"]["references_total"], 1)
                self.assertNotIn("preserve", [x["id"] for x in doc["must_relay"]])
                self.assertNotIn("preserve-evidence", [x["id"] for x in doc["next_steps"]])
                self.assertIn("references-only", [x["id"] for x in doc["must_relay"]])
                self.assertIn("references in saved content only", report.render_human(doc))

    def test_unknown_evidence_remains_actionable(self):
        self.assertEqual(review_document(evidence="misspelled")["exit_code"], 2)

    def test_old_date_survives_merge_with_undated_fresh_copy(self):
        old, undated = review_set(), review_set()
        old.asof = "2020-01-01"
        undated.asof = None
        combined = merge([old, undated])
        self.assertTrue(combined.is_stale())
        self.assertTrue(combined.has_unknown_age())
        self.assertIsNone(undated.age_days())

    def test_unreadable_recorded_program_is_a_gap(self):
        s = IocSet([Indicator("a" * 64, "sample", "primary", "sha256", "synthetic")], "x", None)
        r = ModuleResult("traces")
        with patch.object(traces, "_tr_ran_programs", return_value=(
                [(r"C:\synthetic\blocked.exe", "", "launch list")], {})), \
                patch.object(traces, "path_problem", return_value="refused"):
            traces._tr_check_ran_programs(r, ScanContext(iocs=s))
        self.assertEqual(r.skipped, 1)
        self.assertTrue(any(not c.ran for c in r.checks))

    def test_sharing_summary_omits_all_artifact_text(self):
        doc = review_document(evidence=EV_CONTACTED, gap=True)
        shared = report.share_summary(doc)
        text = json.dumps(shared)
        for secret in ("PRIVATE_PATH", "PRIVATE_SMS", "PRIVATE_PROFILE", "review.invalid",
                       "2026-01-01", "private gap reason"):
            self.assertNotIn(secret, text)
        # Counts only, never artifact text. withdrawn_total joined in schema 1.5.
        self.assertEqual(shared["verdict"], {k: doc["verdict"][k] for k in
                         ("status", "hits_total", "findings_total", "references_total",
                          "withdrawn_total")})
        self.assertEqual(shared["exit_code"], 2)
        self.assertEqual(shared["coverage"]["gap_count"], 1)
        self.assertIn("PRIVATE_SMS", json.dumps(doc))  # complete local evidence retained


class TestAndroidHardening(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="android_review_")
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        self.ctx = ScanContext(iocs=review_set(), phone_path=str(self.folder), emit=lambda s: None)

    def backup(self, members):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for index, raw in enumerate(members):
                member = tarfile.TarInfo("apps/provider/{}_sms_backup".format(index))
                member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))
        (self.folder / "backup.ab").write_bytes(b"ANDROID BACKUP\n5\n0\nnone\n" + stream.getvalue())

    def test_child_locality_is_checked_before_open(self):
        with patch.object(android, "path_problem", return_value="redirected"), \
                patch("builtins.open") as opened:
            with self.assertRaises(OSError):
                android._an_load_json(str(self.folder / "packages.json"))
        opened.assert_not_called()

    def test_actual_symlink_is_not_followed(self):
        outside = self.folder / "outside.json"
        outside.write_text("[]")
        child = self.folder / "packages.json"
        try:
            child.symlink_to(outside)
        except OSError:
            self.skipTest("symlink creation unavailable")
        with self.assertRaises(OSError):
            android._an_load_json(str(child))

    def test_wrong_shape_app_and_file_lists_are_gaps(self):
        for filename, reader in (("packages.json", android._an_packages), ("files.json", android._an_files)):
            for data in ({}, None, [None]):
                with self.subTest(filename=filename, data=data):
                    (self.folder / filename).write_text(json.dumps(data))
                    r = ModuleResult("android")
                    args = (r, self.ctx, str(self.folder))
                    reader(*args, {}) if filename == "packages.json" else reader(*args)
                    self.assertTrue(any(not c.ran for c in r.checks))

    def test_damaged_sms_member_is_a_gap(self):
        self.backup([b"not JSON or compressed JSON"])
        r = ModuleResult("android")
        android._an_messages(r, self.ctx, str(self.folder))
        self.assertTrue(any(not c.ran for c in r.checks))
        self.assertFalse(any(c.ran for c in r.checks))

    def test_valid_sms_hit_survives_damaged_later_member(self):
        self.backup([zlib.compress(json.dumps([{"body": "https://review.invalid", "type": "1"}]).encode()), b"damaged"])
        r = ModuleResult("android")
        android._an_messages(r, self.ctx, str(self.folder))
        self.assertEqual([h.indicator for h in r.hits], ["review.invalid"])
        self.assertTrue(any(not c.ran for c in r.checks))

    def test_sms_empty_list_is_valid_but_no_members_is_a_gap(self):
        self.backup([b"[]"])
        self.assertEqual(android._an_sms_from_backup(str(self.folder / "backup.ab")), ([], ""))
        self.backup([])
        self.assertTrue(android._an_sms_from_backup(str(self.folder / "backup.ab"))[1])

    def test_inflate_detects_truncation_and_expansion_limit(self):
        for data, limit in ((zlib.compress(b"a" * 100), 10), (zlib.compress(b"hello")[:-2], 100)):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                android._an_inflate(data, limit)

    def test_capped_log_retains_earlier_hit_and_reports_gap(self):
        (self.folder / "logcat.txt").write_bytes(b"review.invalid " + b"x" * 100)
        r = ModuleResult("android")
        with patch.object(android, "_AN_MAX_LOG_BYTES", 32):
            android._an_device_logs(r, self.ctx, str(self.folder), set())
        self.assertEqual([h.indicator for h in r.hits], ["review.invalid"])
        self.assertTrue(any("remaining" in c.reason for c in r.checks if not c.ran))

    def test_refused_first_log_does_not_hide_second_log_hit(self):
        (self.folder / "logcat.txt").write_text("review.invalid")
        r = ModuleResult("android")
        guard = android.path_problem
        def refuse_first(path):
            return "redirected" if path.endswith("dumpsys.txt") else guard(path)
        with patch.object(android, "path_problem", side_effect=refuse_first):
            android._an_device_logs(r, self.ctx, str(self.folder), set())
        self.assertEqual([h.indicator for h in r.hits], ["review.invalid"])
        self.assertTrue(any(not c.ran for c in r.checks))

    def test_absent_crashes_and_root_records_are_gaps(self):
        r = ModuleResult("android")
        android._an_crashes(r, self.ctx, str(self.folder))
        android._an_root(r, str(self.folder))
        self.assertEqual({c.name for c in r.checks if not c.ran}, {"android:crashes", "android:root"})


if __name__ == "__main__":
    unittest.main()
