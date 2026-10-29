"""Synthetic regression cases for broader scopes, backup readers and context.

Never reads a real profile, registry, event log or phone collection.
"""
import contextlib
import datetime
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import plistlib
import sqlite3
import struct
import subprocess
import sys
import tempfile
import unittest
import types
import zipfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from zbtriage import cli, report, stix
from zbtriage import phoneguide
from zbtriage.aes import aes_cbc_encrypt
from zbtriage.backupcrypto import backup_android_decrypt, backup_ios_keys
from zbtriage.context import ScanContext
from zbtriage.evidence import evidence_correlations, evidence_enrich
from zbtriage.iocs import Indicator, IocSet, merge
from zbtriage.modules import android, browser, hashscan, host, ios, traces
from zbtriage.result import Hit, ModuleResult, EV_CONTACTED, EV_REFERENCED

BAD = "fixture.invalid"
SAMPLE = b"synthetic harmless file"
DIGEST = hashlib.sha256(SAMPLE).hexdigest()


def context(**kwargs):
    return ScanContext(IocSet([Indicator(BAD, "infrastructure", "primary", "domain", "fixture"),
                              Indicator(DIGEST, "sample", "primary", "sha256", "fixture"),
                              Indicator("fixtureproc", "artifact", "primary", "process", "fixture")],
                             "fixture", None), emit=lambda _: None, **kwargs)


class ExpandedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zbt_expanded_")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_targeted_file_all_extensions_and_no_default_readers(self):
        selected = self.root / "document.unusual"
        selected.write_bytes(SAMPLE)
        ctx = context(targets=(str(selected),))
        with patch.object(hashscan, "_roots", side_effect=AssertionError("default roots")), \
             patch.object(browser, "_app_roots", side_effect=AssertionError("app discovery")), \
             patch.object(host, "run", side_effect=AssertionError("host read")), \
             patch.object(traces, "run", side_effect=AssertionError("trace read")):
            results = cli._run_modules(ctx)
        self.assertEqual([r.name for r in results], ["browser", "hash", "windows-execution"])
        self.assertEqual([h.indicator for r in results for h in r.hits], [DIGEST])

    def test_full_hashes_extensions_and_pruned_directories(self):
        folder = self.root / "node_modules"
        folder.mkdir()
        (folder / "odd.noextension").write_bytes(SAMPLE)
        with patch.object(hashscan, "_roots", lambda: [str(self.root)]):
            self.assertFalse(hashscan.run(context()).hits)
            self.assertEqual(len(hashscan.run(context(full=True)).hits), 1)

    def test_preview_does_not_scan_and_rejects_remote_targets(self):
        with patch.object(cli, "_run_modules", side_effect=AssertionError("scan")), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli.main(["--preview", "--phone", str(self.root)]), 0)
        self.assertFalse(json.loads(out.getvalue())["scanned"])
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            cli._parse(["--scan-type", "targeted", "--target", r"\\example.invalid\share\x"])

    def test_cancel_preserves_prior_finding_and_stops_other_modules(self):
        def interrupted(ctx):
            r = ModuleResult("browser")
            r.add_hit(Hit(BAD, "fixture", "fixture", evidence=EV_CONTACTED))
            ctx.partial = r
            raise KeyboardInterrupt
        ctx = context()
        with patch.object(browser, "run", interrupted), \
             patch.object(hashscan, "run", side_effect=AssertionError("continued")):
            results = cli._run_modules(ctx)
        self.assertTrue(ctx.cancelled)
        self.assertEqual(len(results[0].hits), 1)
        self.assertTrue(any(not c.ran for c in results[0].checks))

    def test_large_file_list_streams_past_old_limit(self):
        path = self.root / "files.json"
        # >64 MiB with two realistic records on either side of padding.
        with path.open("wb") as fh:
            fh.write(b'[{"path":"/data/first"},')
            for _ in range(65):
                fh.write(b" " * (1024 * 1024))
            fh.write(json.dumps({"path": "/data/sample", "sha256": DIGEST}).encode() + b"]")
        r = ModuleResult("android")
        android._an_files(r, context(), str(self.root))
        self.assertEqual(r.submetrics["android_files_listed"], 2)
        self.assertEqual([h.indicator for h in r.hits], [DIGEST])
        self.assertTrue(any(c.name == "android:files" and c.ran for c in r.checks))
        # The first record has no fingerprint: path-only coverage is a gap.
        self.assertTrue(any(c.name == "android:file-hashes" and not c.ran for c in r.checks))

    def test_truncated_file_list_retains_earlier_match(self):
        (self.root / "files.json").write_text(json.dumps([{"path": "/x", "sha256": DIGEST}])[:-1] + ',{"path":')
        r = ModuleResult("android")
        android._an_files(r, context(), str(self.root))
        self.assertEqual(len(r.hits), 1)
        self.assertTrue(any(not c.ran for c in r.checks))

    def test_file_list_cap_and_empty_collection_have_clear_gaps(self):
        (self.root / "files.json").write_text("[]")
        r = ModuleResult("android")
        android._an_files(r, context(), str(self.root))
        self.assertIn("AndroidQF could not list files", r.checks[0].reason)
        (self.root / "files.json").write_text('[{"path":"/long/path"}]')
        with patch.object(android, "_AN_MAX_FILE_LIST_BYTES", 8):
            r = ModuleResult("android")
            android._an_files(r, context(), str(self.root))
        self.assertTrue(any("limit" in c.reason for c in r.checks))

    def test_missing_feeds_are_grouped_in_readable_report(self):
        ctx = context()
        ctx.iocs.feeds = {"used": True, "missing": ["fixture-a", "fixture-b"]}
        r = ModuleResult("synthetic")
        r.ran("fixture")
        doc = report.build_document(ctx.iocs, [r], datetime.datetime.now())
        text = report.render_human(doc)
        self.assertIn("run --update once", text)
        self.assertNotIn("fixture-a: indicator source missing", text)
        self.assertEqual(len(doc["coverage"]["not_checked"]), 2)

    def test_firefox_binary_hsts_checksum_and_partition_host(self):
        slot = bytearray(286)
        slot[2:6] = struct.pack(">HH", 1, 20000)
        key = (BAD + "^partitionKey=(https,innocent.invalid)").encode()
        slot[6:6 + len(key)] = key
        value = b"1900000000000,1,0"
        slot[262:262 + len(value)] = value
        checksum = 0
        for word in struct.unpack(">143H", slot):
            checksum ^= word
        slot[:2] = struct.pack(">H", checksum)
        (self.root / "SiteSecurityServiceState.bin").write_bytes(slot)
        # A marker makes this a selected Firefox profile. No default profile discovery.
        (self.root / "prefs.js").write_text("")
        ctx = context(targets=(str(self.root),))
        with patch.object(browser, "_app_roots", side_effect=AssertionError("default discovery")), \
             patch.object(browser, "_firefox_ini", side_effect=AssertionError("parent read")):
            r = browser.run(ctx)
        self.assertEqual([(h.indicator, h.evidence) for h in r.hits], [(BAD, EV_CONTACTED)])
        slot[10] ^= 1
        entries, invalid = browser._browser_hsts_binary(bytes(slot))
        self.assertEqual((entries, invalid), ([], 1))
        with self.assertRaises(ValueError):
            browser._browser_hsts_binary(bytes(slot[:-1]))

    def test_chromium_download_chain_without_completion_is_attempted(self):
        con = sqlite3.connect(self.root / "History")
        con.execute("CREATE TABLE downloads_url_chains(id INTEGER,chain_index INTEGER,url TEXT)")
        con.execute("INSERT INTO downloads_url_chains VALUES(1,0,?)", ("https://" + BAD + "/file",))
        con.commit()
        con.close()
        r = browser.run(context(targets=(str(self.root),)))
        self.assertEqual([(h.indicator, h.evidence) for h in r.hits], [(BAD, "attempted")])

    def test_publisher_context_survives_duplicates_and_merge(self):
        path = self.root / "feed.stix2"
        base = {"type": "indicator", "pattern": "[domain-name:value='fixture.invalid']", "created_by_ref": "identity--fixture",
                "valid_from": "2020-01-01T00:00:00Z", "valid_until": "2021-01-01T00:00:00Z", "x_platforms": ["iOS"]}
        path.write_text(json.dumps({"objects": [{"type": "identity", "id": "identity--fixture", "name": "Publisher"}, base, dict(base, revoked=True)]}))
        imported = stix.load_stix(str(path))
        combined = merge([context().iocs, IocSet(imported.indicators, "fixture", None)])
        md = {"browser": {"hits": [Hit(BAD, "History", "record", evidence=EV_CONTACTED).to_dict()]}}
        evidence_enrich(md, combined)
        h = md["browser"]["hits"][0]
        self.assertEqual(len(h["indicator_context"]), 3)
        self.assertTrue(any("withdrew" in c for c in h["context_cautions"]))
        self.assertEqual(h["evidence"], EV_CONTACTED)

    def test_correlation_requires_distinct_artifacts_not_duplicate_rows(self):
        hit = Hit(BAD, "History", "record", evidence=EV_REFERENCED).to_dict()
        md = {"browser": {"hits": [hit, dict(hit), dict(hit, detail="another row")]}}
        self.assertEqual(evidence_correlations(md), [])
        same_source = {"android": {"hits": [dict(hit, location="SMS from A", artifact="backup.ab"), dict(hit, location="SMS from B", artifact="backup.ab")]}}
        self.assertEqual(evidence_correlations(same_source), [])
        md["browser"]["hits"].append(dict(hit, location="Cookies", evidence=EV_CONTACTED))
        groups = evidence_correlations(md)
        self.assertEqual(groups[0]["artifact_count"], 2)
        self.assertEqual(len(groups[0]["records"]), 3)
        self.assertIn("not proof", groups[0]["interpretation"])

    def test_related_application_identifiers_remain_readable(self):
        app = "com.fixture.app"
        iocs = IocSet([Indicator(app, "artifact", "primary", "app-id", "fixture")], "fixture", None)
        r = ModuleResult("android")
        for artifact in ("packages.json", "logcat.txt"):
            r.add_hit(Hit(app, artifact, "fixture", evidence="on-device", kind="app-id", artifact=artifact))
        r.ran("android:packages")
        text = report.render_human(report.build_document(iocs, [r], datetime.datetime.now()))
        self.assertIn("RELATED RECORDS: com.fixture.app", text)
        self.assertNotIn("com[.]fixture", text)

    def test_encrypted_android_payload_correct_wrong_and_hostile_rounds(self):
        password = "owner-password"
        salt, check_salt, iv, data_iv = b"s" * 64, b"c" * 64, b"i" * 16, b"v" * 16
        data_key = bytes(range(224, 256))
        checksum_chars = "".join(chr(0xff00 + v) for v in data_key).encode("utf-8")
        checksum = hashlib.pbkdf2_hmac("sha1", checksum_chars, check_salt, 10000, 32)
        master = b"\x10" + data_iv + b"\x20" + data_key + b"\x20" + checksum
        key = hashlib.pbkdf2_hmac("sha1", password.encode(), salt, 10000, 32)
        wrapped = aes_cbc_encrypt(key, iv, master)
        body = b"\n".join([salt.hex().encode(), check_salt.hex().encode(), b"10000", iv.hex().encode(), wrapped.hex().encode(), aes_cbc_encrypt(data_key, data_iv, b"test payload")])
        self.assertEqual(backup_android_decrypt(body, password), b"test payload")
        with self.assertRaises(ValueError):
            backup_android_decrypt(body, "wrong")
        with self.assertRaises(ValueError):
            backup_android_decrypt(body.replace(b"\n10000\n", b"\n999999999\n"), password)

    def test_new_windows_readers_use_saved_input_and_task_actions(self):
        root = str(self.root)
        console = self.root / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine"
        console.mkdir(parents=True)
        (console / "ConsoleHost_history.txt").write_text("echo https://" + BAD)
        tasks = self.root / "System32" / "Tasks"
        tasks.mkdir(parents=True)
        (tasks / "benign-description").write_text('<Task><RegistrationInfo><Description>' + BAD + '</Description></RegistrationInfo><Actions><Exec><Command>ordinary.exe</Command></Exec></Actions></Task>')
        (tasks / "matched-action").write_text('<Task><Actions><Exec><Command>ordinary.exe</Command><Arguments>https://' + BAD + '</Arguments></Exec></Actions></Task>')
        (tasks / "malformed").write_text('<Task>')
        run_path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
        typed = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
        services = r"HKLM\SYSTEM\CurrentControlSet\Services"
        values = {run_path: {"Fixture": "https://" + BAD}, typed: {"url1": "https://" + BAD},
                  services: {}, services + r"\Fixture": {"ImagePath": "https://" + BAD}}
        def open_key(hive, path, *args):
            key = hive + "\\" + path
            if key not in values:
                raise FileNotFoundError
            return contextlib.nullcontext(key)
        def enum_value(key, n):
            items = list(values[key].items())
            if n >= len(items):
                exc = OSError("end")
                exc.winerror = 259
                raise exc
            name, value = items[n]
            return name, value, 1
        fake = types.SimpleNamespace(HKEY_CURRENT_USER="HKCU", HKEY_LOCAL_MACHINE="HKLM", KEY_WOW64_32KEY=1,
                                     KEY_WOW64_64KEY=2, KEY_READ=4, REG_SZ=1, REG_EXPAND_SZ=2,
                                     OpenKey=open_key, EnumValue=enum_value,
                                     QueryInfoKey=lambda key: (1 if key == services else 0, len(values[key]), 0),
                                     EnumKey=lambda key, n: "Fixture", QueryValueEx=lambda key, name: (values[key][name], 1))
        r = ModuleResult("traces")
        with patch.dict(sys.modules, {"winreg": fake}), patch.dict(os.environ, {"APPDATA": root, "PROGRAMDATA": root, "SystemRoot": root}):
            traces._tr_extra_history(r, context())
            traces._tr_persistence(r, context())
        self.assertTrue(any(h.evidence == EV_REFERENCED and "ConsoleHost" in h.location for h in r.hits))
        self.assertTrue(any("TypedPaths" in h.location and h.evidence == EV_REFERENCED for h in r.hits))
        self.assertTrue(any("matched-action" in h.location and h.evidence == "persistence" for h in r.hits))
        self.assertFalse(any("benign-description" in h.location for h in r.hits))
        self.assertTrue(any(not c.ran and c.name == "scheduled-task-actions" for c in r.checks))

    def test_extended_logs_are_opt_in_and_capped(self):
        r = ModuleResult("traces")
        with patch.object(traces, "_tr_events", side_effect=AssertionError("not opted in")):
            traces._tr_extended(r, context())
        rows = [{"Id": 22, "Data": {"QueryName": BAD}, "Time": "2026-01-01T00:00:00"}]
        with patch.object(traces, "_tr_events", return_value=(rows, "")):
            traces._tr_extended(r, context(extended_windows=True))
        self.assertTrue(all(h.evidence == "dns-record" for h in r.hits))


def ios_fixture(root, encrypted=False):
    """Independent synthetic SQLite backups, optionally wrapped with native AES."""
    manifest = {"IsEncrypted": encrypted}
    protection, class_key = 4, b"k" * 32
    def enc(key, data):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        pad = 16 - len(data) % 16
        obj = Cipher(algorithms.AES(key), modes.CBC(b"\0" * 16)).encryptor()
        return obj.update(data + bytes([pad]) * pad) + obj.finalize()
    if encrypted:
        from cryptography.hazmat.primitives.keywrap import aes_key_wrap
        salt = b"s" * 20
        secret = hashlib.pbkdf2_hmac("sha1", b"password", salt, 100, 32)
        def tlv(tag, value):
            return tag + struct.pack(">I", len(value)) + value
        bag = b"".join(tlv(k, v) for k, v in [(b"UUID", b"h" * 16), (b"SALT", salt), (b"ITER", struct.pack(">I", 100)),
                         (b"UUID", b"c" * 16), (b"CLAS", struct.pack(">I", protection)), (b"WRAP", struct.pack(">I", 2)), (b"WPKY", aes_key_wrap(secret, class_key))])
        manifest["BackupKeyBag"] = bag
        manifest["ManifestKey"] = struct.pack("<I", protection) + aes_key_wrap(class_key, b"m" * 32)
    con = sqlite3.connect(root / "Manifest.db")
    con.execute("CREATE TABLE Files(fileID TEXT,domain TEXT,relativePath TEXT,flags INTEGER,file BLOB)")
    for n, (domain, relative, schema, insert, values) in enumerate([
        ("HomeDomain", "Library/SMS/sms.db", "CREATE TABLE message(text TEXT,date INTEGER,is_from_me INTEGER)", "INSERT INTO message VALUES(?,?,?)", ("https://" + BAD, 700000000000000000, 0)),
        ("HomeDomain", "Library/Safari/History.db", "CREATE TABLE history_items(id INTEGER,url TEXT); CREATE TABLE history_visits(history_item INTEGER,visit_time INTEGER,origin INTEGER DEFAULT 0)", "INSERT INTO history_items VALUES(1,?)", ("https://innocent.invalid/?q=" + BAD,)),
        ("WirelessDomain", "Library/Databases/DataUsage.sqlite", "CREATE TABLE ZPROCESS(ZPROCNAME TEXT)", "INSERT INTO ZPROCESS VALUES(?)", ("fixtureproc",)),
    ]):
        work = root / "fixture.db"
        db = sqlite3.connect(work)
        db.executescript(schema)
        db.execute(insert, values)
        if n == 1:
            db.execute("INSERT INTO history_visits(history_item,visit_time) VALUES(1,700000000)")
        db.commit()
        db.close()
        raw = work.read_bytes()
        work.unlink()
        fid = hashlib.sha1((domain + "-" + relative).encode()).hexdigest()
        (root / fid[:2]).mkdir(exist_ok=True)
        metadata = b""
        data = raw
        if encrypted:
            file_key = bytes([n + 1]) * 32
            record = {"Size": len(raw), "EncryptionKey": struct.pack("<I", protection) + aes_key_wrap(class_key, file_key)}
            metadata = plistlib.dumps({"$objects": ["$null", record], "$top": {"root": plistlib.UID(1)}}, fmt=plistlib.FMT_BINARY)
            data = enc(file_key, raw)
        (root / fid[:2] / fid).write_bytes(data)
        con.execute("INSERT INTO Files VALUES(?,?,?,?,?)", (fid, domain, relative, 1, metadata))
    con.commit()
    con.close()
    if encrypted:
        path = root / "Manifest.db"
        path.write_bytes(enc(b"m" * 32, path.read_bytes()))
    (root / "Manifest.plist").write_bytes(plistlib.dumps(manifest))
    (root / "Info.plist").write_bytes(plistlib.dumps({"Installed Applications": []}))


class IosTests(unittest.TestCase):
    setUp = ExpandedTests.setUp

    def test_ios_plaintext_preserves_source_and_grades(self):
        ios_fixture(self.root)
        before = {str(p.relative_to(self.root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in self.root.rglob("*") if p.is_file()}
        r = ios.run(context(phone_path=str(self.root)))
        self.assertEqual([h.evidence for h in r.hits], ["received", "referenced", "device-log"])
        self.assertTrue(all(c.ran for c in r.checks))
        after = {str(p.relative_to(self.root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    @unittest.skipUnless(importlib.util.find_spec("cryptography"), "optional cryptography unavailable")
    def test_ios_encrypted_and_wrong_password(self):
        ios_fixture(self.root, encrypted=True)
        r = ios.run(context(phone_path=str(self.root), backup_password="password"))
        self.assertEqual(len(r.hits), 3)
        self.assertTrue(all(c.ran for c in r.checks))
        r = ios.run(context(phone_path=str(self.root), backup_password="wrong"))
        self.assertFalse(r.hits)
        self.assertTrue(any(not c.ran for c in r.checks))

    def test_ios_path_traversal_is_not_followed(self):
        ios_fixture(self.root)
        con = sqlite3.connect(self.root / "Manifest.db")
        con.execute("UPDATE Files SET fileID='../outside'")
        con.commit()
        con.close()
        r = ios.run(context(phone_path=str(self.root)))
        self.assertFalse(r.hits)
        self.assertTrue(any("invalid manifest" in c.reason for c in r.checks))


class BundleCapabilityTests(unittest.TestCase):
    setUp = ExpandedTests.setUp

    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="zbt_expanded_bundle_")
        repo = Path(__file__).resolve().parents[2]
        output = Path(cls.build.name) / "scanner.py"
        subprocess.run([sys.executable, str(repo / "build/bundle.py"), str(repo), str(output)], check=True, capture_output=True)
        spec = importlib.util.spec_from_file_location("_expanded_bundle", output)
        cls.bundle = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.bundle
        spec.loader.exec_module(cls.bundle)

    @classmethod
    def tearDownClass(cls):
        sys.modules.pop("_expanded_bundle", None)
        cls.build.cleanup()

    def test_targeted_cli_and_summary_privacy_in_both_entrypoints(self):
        selected = self.root / "payload.unusual"
        selected.write_bytes(SAMPLE)
        feed = self.root / "feed.txt"
        feed.write_text(DIGEST + "\tsample\tprimary\tfixture\n")
        for target in (cli, self.bundle):
            full, share = self.root / "report.json", self.root / "share.json"
            args = ["--iocs", str(feed), "--scan-type", "targeted", "--target", str(selected),
                    "--json", str(full), "--share-json", str(share), "--no-banner"]
            if target is self.bundle:
                args.append("--no-pause")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
                 patch.object(target, "_force_utf8_io", lambda: None):
                code = target.main(args)
            self.assertEqual(code, 2)
            doc = json.loads(full.read_text(encoding="utf-8"))
            self.assertEqual(sorted(doc["modules"]), ["browser", "hash", "windows-execution"])
            self.assertEqual(doc["scope"]["scan_type"], "targeted")
            summary = share.read_text(encoding="utf-8")
            self.assertNotIn(DIGEST, summary)
            self.assertNotIn("payload", summary)
            self.assertNotIn("indicator_context", summary)

    def test_ios_reader_bundle_parity(self):
        ios_fixture(self.root)
        ctx = context(phone_path=str(self.root))
        source, bundled = ios.run(ctx), self.bundle.run_ios(ctx)
        self.assertEqual(source.to_dict(), bundled.to_dict())

    def test_phone_preview_and_guide_bundle_do_not_dispatch_scans(self):
        for args in (["--phone", str(self.root), "--preview"], ["--phone-guide", "android"]):
            with patch.object(self.bundle, "run_android", side_effect=AssertionError("scan")), \
                 contextlib.redirect_stdout(io.StringIO()), patch.object(self.bundle, "_force_utf8_io", lambda: None):
                self.assertEqual(self.bundle.main(args + ["--no-pause"]), 0)


class AcquisitionTests(unittest.TestCase):
    setUp = ExpandedTests.setUp

    def test_download_digest_mismatch_is_never_executed(self):
        class Response(io.BytesIO):
            def geturl(self):
                return "https://release-assets.githubusercontent.com/fixture"
        opener = types.SimpleNamespace(open=lambda *a, **k: Response(b"wrong bytes"))
        with patch.object(phoneguide.urllib.request, "build_opener", return_value=opener), \
             patch.object(phoneguide.subprocess, "run", side_effect=AssertionError("executed")):
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                phoneguide._phone_download("androidqf_fixture", "0" * 64, str(self.root / "collector"))
        self.assertFalse(phoneguide._phone_download_url_ok("http://github.com/file"))
        self.assertFalse(phoneguide._phone_download_url_ok("https://example.invalid/file"))

    def test_zip_traversal_links_and_oversize_are_refused(self):
        for name in ("../escape", "/absolute", "C:/device", "NUL", "safe/../../escape"):
            archive = self.root / "input.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr(name, "fixture")
            with self.assertRaises(ValueError):
                phoneguide._phone_extract(str(archive), str(self.root / "output"))
        archive = self.root / "input.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            entry = zipfile.ZipInfo("link")
            entry.create_system = 3
            entry.external_attr = (0o120777 << 16)
            zf.writestr(entry, "outside")
        with self.assertRaises(ValueError):
            phoneguide._phone_extract(str(archive), str(self.root / "output"))

    def test_guided_flow_uses_only_downloaded_executable_and_local_archive(self):
        calls = []
        def download(asset, digest, dest):
            Path(dest).write_bytes(b"harmless fixture, never executed")
        def collector(argv, **kwargs):
            calls.append((argv, kwargs))
            work = Path(kwargs["cwd"])
            with zipfile.ZipFile(work / "fixture.zip", "w") as zf:
                zf.writestr("fixture/packages.json", "[]")
            return types.SimpleNamespace(returncode=0)
        with patch.object(phoneguide, "_phone_download", download), \
             patch.object(phoneguide.subprocess, "run", collector), \
             patch.object(phoneguide.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="YES"), contextlib.redirect_stdout(io.StringIO()):
            folder, code = phoneguide.collect_android(str(self.root))
        self.assertEqual(code, 0)
        self.assertEqual((Path(folder) / "packages.json").read_text(), "[]")
        self.assertEqual(len(calls), 1)
        self.assertTrue(os.path.isabs(calls[0][0][0]))
        self.assertFalse(calls[0][1]["shell"])

    def test_no_consent_means_no_download_or_launch(self):
        with patch.object(phoneguide, "_phone_download", side_effect=AssertionError("download")), \
             patch.object(phoneguide.sys.stdin, "isatty", return_value=True), \
             patch("builtins.input", return_value="NO"), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(phoneguide.collect_android(str(self.root)), (None, 1))


if __name__ == "__main__":
    unittest.main()
