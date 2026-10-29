"""Follow-up review regressions. Synthetic files, mocked acquisition and registry only."""
import base64
import contextlib
import datetime
import hashlib
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys
import tarfile
import types
import zipfile
from unittest.mock import patch

import pytest

from zbtriage import cli, phoneguide, report
from zbtriage.context import ScanContext, scan_recovery
from zbtriage.iocs import Indicator, IocSet
from zbtriage.modules import android, browser, ios, traces
from zbtriage.result import Hit, ModuleResult, EV_CONTACTED, EV_PERSISTENCE, EV_REFERENCED
from test_expanded_capabilities import context, ios_fixture, BAD


@pytest.fixture(scope="module")
def bundle(tmp_path_factory):
    repo = Path(__file__).resolve().parents[2]
    dest = tmp_path_factory.mktemp("followup_bundle") / "scanner.py"
    subprocess.run([sys.executable, str(repo / "build/bundle.py"), str(repo), str(dest)], check=True, capture_output=True)
    spec = importlib.util.spec_from_file_location("followup_scanner", dest)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_phone_process_header_survives_bundle(tmp_path, bundle):
    (tmp_path / "processes.txt").write_text("USER PID NAME\nu0_a1 7 com.fixture.spy\n")
    for api, reader in ((types.SimpleNamespace(ScanContext=ScanContext, IocSet=IocSet, Indicator=Indicator, ModuleResult=ModuleResult), android._an_processes),
                        (bundle, bundle._an_processes)):
        ctx = api.ScanContext(api.IocSet([api.Indicator("com.fixture.spy", "sample", "primary", "app-id", "fixture")], "fixture", None))
        r = api.ModuleResult("android")
        reader(r, ctx, str(tmp_path))
        assert len(r.hits) == 1
        assert all(c.ran for c in r.checks)


def fake_registry():
    def missing(*args):
        raise FileNotFoundError()
    return types.SimpleNamespace(HKEY_CURRENT_USER="CU", HKEY_LOCAL_MACHINE="LM", KEY_READ=1,
                                 KEY_WOW64_32KEY=2, KEY_WOW64_64KEY=4, REG_SZ=1, REG_EXPAND_SZ=2,
                                 OpenKey=missing)


def test_history_documented_path_other_host_tail_and_absence(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "winreg", fake_registry())
    monkeypatch.setenv("APPDATA", str(tmp_path))
    r = ModuleResult("traces")
    traces._tr_extra_history(r, context())
    assert all(c.ran for c in r.checks)
    folder = tmp_path / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine"
    folder.mkdir(parents=True)
    (folder / "Visual Studio Code Host_history.txt").write_text("old\n" * 100 + "https://" + BAD + "\n")
    monkeypatch.setattr(traces, "_TR_HISTORY_LIMIT", 100)
    r = ModuleResult("traces")
    traces._tr_extra_history(r, context())
    assert [h.indicator for h in r.hits] == [BAD]
    assert "tail-line" in r.hits[0].location
    assert any("older records" in c.reason for c in r.checks)
    with patch.object(traces, "path_problem", return_value="refused"):
        r = ModuleResult("traces")
        traces._tr_extra_history(r, context())
    assert any(not c.ran and c.name == "psreadline-history" for c in r.checks)


def sms_path(root):
    fid = hashlib.sha1(b"HomeDomain-Library/SMS/sms.db").hexdigest()
    return root / fid[:2] / fid


def test_encoded_only_messages_are_gaps_and_not_counted(tmp_path, bundle):
    ios_fixture(tmp_path)
    with contextlib.closing(sqlite3.connect(sms_path(tmp_path))) as db:
        db.execute("ALTER TABLE message ADD COLUMN attributedBody BLOB")
        db.execute("UPDATE message SET text=NULL,attributedBody=?", (b"streamtyped NSString https://" + BAD.encode(),))
        db.commit()
    for reader in (ios.run, bundle.run_ios):
        r = reader(context(phone_path=str(tmp_path)))
        assert r.checked == 2
        assert any(c.name == "ios:messages" and "encoded" in c.reason for c in r.checks)
        assert not any(h.evidence == "received" for h in r.hits)


def test_manifest_limit_does_not_hide_required_artifact(tmp_path, monkeypatch):
    ios_fixture(tmp_path)
    with contextlib.closing(sqlite3.connect(tmp_path / "Manifest.db")) as db:
        row = db.execute("SELECT * FROM Files WHERE relativePath='Library/SMS/sms.db'").fetchone()
        db.execute("DELETE FROM Files WHERE relativePath='Library/SMS/sms.db'")
        db.execute("INSERT INTO Files VALUES(?,?,?,?,?)", row)
        db.commit()
    monkeypatch.setattr(ios, "_IOS_ROWS", 2)
    r = ios.run(context(phone_path=str(tmp_path)))
    assert any(c.name == "ios:manifest" and "row limit" in c.reason for c in r.checks)
    assert any(h.evidence == "received" for h in r.hits)


@pytest.mark.parametrize("schema", [
    "CREATE VIEW message AS SELECT hex(zeroblob(500000000)) AS text,0 AS date,0 AS is_from_me",
    "CREATE TABLE message(seed INT, text TEXT GENERATED ALWAYS AS (hex(zeroblob(500000000))), date INT,is_from_me INT)",
])
def test_ios_executable_schema_refused_without_evaluation(tmp_path, schema):
    ios_fixture(tmp_path)
    with contextlib.closing(sqlite3.connect(sms_path(tmp_path))) as db:
        db.execute("DROP TABLE message")
        db.execute(schema)
        db.commit()
    r = ios.run(context(phone_path=str(tmp_path)))
    assert any(c.name == "ios:messages" and not c.ran for c in r.checks)


def test_ios_large_text_skipped_and_later_match_preserved(tmp_path):
    ios_fixture(tmp_path)
    with contextlib.closing(sqlite3.connect(sms_path(tmp_path))) as db:
        db.execute("DELETE FROM message")
        db.executemany("INSERT INTO message VALUES(?,0,0)", [("a" * 70000,), ("https://" + BAD,)])
        db.commit()
    r = ios.run(context(phone_path=str(tmp_path)))
    assert any("text limit" in c.reason for c in r.checks)
    assert any(h.evidence == "received" for h in r.hits)


@pytest.mark.parametrize("state,received,expected", [(1,100,EV_CONTACTED), (4,10,EV_CONTACTED), (2,0,"attempted")])
def test_download_host_grade_and_query_reference(tmp_path, state, received, expected):
    with contextlib.closing(sqlite3.connect(tmp_path / "History")) as db:
        db.executescript("CREATE TABLE downloads(id INTEGER,current_path TEXT,tab_url TEXT,referrer TEXT,state INTEGER,received_bytes INTEGER); CREATE TABLE downloads_url_chains(id INTEGER,chain_index INTEGER,url TEXT)")
        db.execute("INSERT INTO downloads VALUES(1,'','','',?,?)", (state, received))
        db.executemany("INSERT INTO downloads_url_chains VALUES(1,?,?)", [(0,"https://"+BAD+"/file"), (1,"https://ordinary.invalid/?q="+BAD)])
        db.commit()
    r = browser.run(context(targets=(str(tmp_path),)))
    assert sorted(h.evidence for h in r.hits) == sorted([expected, EV_REFERENCED])


def test_startup_commands_comments_and_unsupported_links(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "winreg", fake_registry())
    for name in ("APPDATA", "PROGRAMDATA", "SystemRoot"):
        monkeypatch.setenv(name, str(tmp_path))
    root = tmp_path / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    root.mkdir(parents=True)
    (root / "active.cmd").write_text("@curl https://" + BAD + "\n")
    (root / "comments.cmd").write_text("@rem https://" + BAD + "\necho https://" + BAD + "\n")
    (root / "unknown.lnk").write_bytes(b"unknown shell link")
    r = ModuleResult("traces")
    traces._tr_persistence(r, context())
    assert [h.evidence for h in r.hits if "active.cmd" in h.location] == [EV_PERSISTENCE]
    assert all(h.evidence == EV_REFERENCED for h in r.hits if "comments.cmd" in h.location)
    assert any(c.name == "startup-files" and "unsupported" in c.reason for c in r.checks)
    active, reference, _ = traces._tr_startup_content(b'echo hello & rem fixture.invalid', 'x.cmd')
    assert BAD not in active and BAD in reference
    active, reference, supported = traces._tr_startup_content(b'echo hello & program.exe https://fixture.invalid', 'x.cmd')
    assert not supported and BAD not in active and BAD in reference
    active, reference, supported = traces._tr_startup_content(b'echo(https://fixture.invalid', 'x.cmd')
    assert supported and BAD not in active and BAD in reference
    active, reference, supported = traces._tr_startup_content(b'echo ^\nhttps://fixture.invalid', 'x.cmd')
    assert not supported and BAD not in active


def test_shared_registry_value_is_not_counted_twice(tmp_path, monkeypatch):
    fake = fake_registry()
    def opened(hive, path, *args):
        if hive == "CU" and path.endswith("\\Run"):
            return contextlib.nullcontext("key")
        raise FileNotFoundError()
    fake.OpenKey = opened
    fake.QueryInfoKey = lambda key: (0,1,0)
    fake.EnumValue = lambda key,n: ("Fixture", "https://" + BAD, 1)
    monkeypatch.setitem(sys.modules, "winreg", fake)
    for name in ("APPDATA", "PROGRAMDATA", "SystemRoot"):
        monkeypatch.setenv(name, str(tmp_path))
    r = ModuleResult("traces")
    traces._tr_persistence(r, context())
    assert r.checked == 1 and len(r.hits) == 1


@pytest.mark.skipif(sys.platform != "win32", reason="Windows registry paths require Windows drive syntax")
def test_deleted_programs_are_limitations_existing_unreadable_are_gaps(tmp_path):
    with patch.object(traces, "_tr_ran_programs", return_value=([(str(tmp_path / "deleted.exe"), "", "launch list")], {})):
        r = ModuleResult("traces")
        traces._tr_check_ran_programs(r, context())
    assert all(c.ran for c in r.checks)
    assert r.submetrics["ran_programs_no_longer_on_disk"] == 1
    assert any("Coverage limitation" in n for n in r.notes)


def test_withdrawn_summary_is_explicit_and_mixed_sources_stay_actionable():
    for revoked_values, action in (([True],1), ([True,False],2)):
        ind = Indicator(BAD,"infrastructure","primary","domain","fixture",
                        contexts=tuple(json.dumps({"source":str(n),"revoked":v}) for n,v in enumerate(revoked_values)))
        r = ModuleResult("browser")
        r.ran("history")
        r.add_hit(Hit(BAD,"fixture","fixture",tier="infrastructure",evidence=EV_CONTACTED,kind="domain"))
        doc = report.build_document(IocSet([ind],"fixture",None), [r], datetime.datetime.now())
        assert report._recommended_action(doc["modules"]["browser"]["hits"][0]) == action
        text = report.render_summary(doc)
        assert "withdrew" in text
        if action == 1:
            assert "potentially SERIOUS" not in text
            assert "WITHDRAWN" in text


@pytest.mark.parametrize("failure", ["share", "full", "none"])
def test_output_independence_and_private_targeted_scope(tmp_path, bundle, failure):
    selected = tmp_path / "ordinary.bin"
    selected.write_bytes(b"ordinary")
    for n, entry in enumerate((cli,bundle)):
        full = tmp_path / ("missing/full.json" if failure == "full" else "full%d.json" % n)
        share = tmp_path / ("missing/share.json" if failure == "share" else "share%d.json" % n)
        args = ["--no-banner","--no-feeds","--scan-type","targeted","--target",str(selected),"--json",str(full),"--share-json",str(share)]
        if entry is bundle:
            args += ["--no-pause"]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), patch.object(entry,"_force_utf8_io",lambda:None):
            code = entry.main(args)
        assert code == (0 if failure == "none" else 1)
        assert full.exists() == (failure != "full")
        assert share.exists() == (failure != "share")
        if share.exists():
            doc = json.loads(share.read_text(encoding="utf-8"))
            assert doc["scope"]["scan_type"] == "targeted"
            assert "targeted" in [x["id"] for x in doc["must_relay"]]
            assert "ordinary.bin" not in json.dumps(doc)


def test_atomic_output_interruption_preserves_prior_file(tmp_path):
    dest = tmp_path / "report.json"
    dest.write_text("original")
    with patch.object(report.json,"dump",side_effect=KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            report.write_json({"fixture":True},str(dest))
    assert dest.read_text() == "original"
    assert not list(tmp_path.glob(".zbt_report_*"))


def test_cancel_between_checks_keeps_completed_evidence():
    ctx = context()
    r = ModuleResult("browser")
    r.ran("history")
    r.add_hit(Hit(BAD,"fixture","fixture",evidence=EV_CONTACTED))
    with scan_recovery(ctx):
        ctx.completed.append(r)
        raise KeyboardInterrupt()
    assert ctx.cancelled and ctx.completed[0].hits
    assert any(not c.ran for m in ctx.completed for c in m.checks)


def test_interrupt_during_render_still_saves_report(tmp_path, bundle):
    selected = tmp_path / "x.bin"
    selected.write_bytes(b"ordinary")
    for n, entry in enumerate((cli,bundle)):
        reporting = report if entry is cli else bundle
        original, calls = reporting.render_human, []
        def render(doc):
            calls.append(1)
            if len(calls) == 1:
                raise KeyboardInterrupt()
            return original(doc)
        dest = tmp_path / ("report%d.json" % n)
        args = ["--no-banner","--no-feeds","--scan-type","targeted","--target",str(selected),"--json",str(dest)]
        if entry is bundle:
            args += ["--no-pause"]
        with patch.object(reporting,"render_human",render), patch.object(entry,"_force_utf8_io",lambda:None), contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            assert entry.main(args) == 0
        assert json.loads(dest.read_text(encoding="utf-8"))["scope"]["scanned"]


def test_nested_compressed_android_tar_refused(tmp_path):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw,mode="w") as tf:
        data = b'[{"body":"https://fixture.invalid"}]'
        info = tarfile.TarInfo("apps/telephony/000_sms_backup")
        info.size = len(data)
        tf.addfile(info,io.BytesIO(data))
    backup = tmp_path / "backup.ab"
    backup.write_bytes(b"ANDROID BACKUP\n5\n0\nnone\n" + lzma.compress(raw.getvalue()))
    messages, problem = android._an_sms_from_backup(str(backup))
    assert not messages and problem


def age_bytes():
    token = base64.b64encode(b"x" * 32).rstrip(b"=")
    return b"age-encryption.org/v1\n-> X25519 " + token + b"\n" + token + b"\n--- " + token + b"\n" + bytes(32)


@pytest.mark.parametrize("kind,expected", [("plaintext",1),("renamed",1),("age",0),("leftover",1),("corrupt",1),("method",1),("encryptedzip",1)])
def test_acquisition_encryption_and_cleanup(tmp_path, kind, expected):
    key = tmp_path / "recipient.txt"
    key.write_text("age1" + "q" * 58)
    def download(asset,digest,path):
        Path(path).write_bytes(b"fixture never executed")
    def collector(argv,**kw):
        root = Path(kw["cwd"])
        if kind in ("age","leftover","renamed"):
            (root / "fixture.zip.age").write_bytes(age_bytes() if kind != "renamed" else b"PK plaintext")
            if kind == "leftover":
                (root / "private.txt").write_text("private fixture")
        else:
            dest = root / "fixture.zip"
            with zipfile.ZipFile(dest,"w",zipfile.ZIP_DEFLATED) as z:
                z.writestr("fixture/packages.json","[]")
                z.writestr("fixture/other.txt","x" * 1000)
            raw = bytearray(dest.read_bytes())
            if kind == "corrupt":
                start = raw.find(b"PK\x03\x04",4)
                size = struct.unpack_from("<H",raw,start+26)[0]
                raw[start+30+size:start+33+size] = b"\xff\xff\xff"
            elif kind == "method":
                raw[8:10] = struct.pack("<H",99)
                cd = raw.find(b"PK\x01\x02")
                raw[cd+10:cd+12] = struct.pack("<H",99)
            elif kind == "encryptedzip":
                raw[6] |= 1
                cd = raw.find(b"PK\x01\x02")
                raw[cd+8] |= 1
            dest.write_bytes(raw)
        return types.SimpleNamespace(returncode=0)
    request = str(key) if kind in ("plaintext","renamed","age","leftover") else None
    with patch.object(phoneguide,"_phone_download",download),patch.object(phoneguide.subprocess,"run",collector),patch.object(phoneguide.platform,"machine",return_value="amd64"),patch.object(sys.stdin,"isatty",return_value=True),patch("builtins.input",return_value="YES"),contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
        folder, code = phoneguide.collect_android(str(tmp_path / "collected"),request)
    assert code == expected and folder is None
    work = next((tmp_path / "collected").iterdir())
    assert not list(work.glob("analysis_*"))
    assert list(work.glob("fixture.*"))  # Original acquisition retained.
