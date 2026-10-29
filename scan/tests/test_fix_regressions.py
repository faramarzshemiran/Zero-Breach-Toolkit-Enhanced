"""Second review regressions: synthetic inputs only, source and bundle parity."""
import ast
import contextlib
import datetime
import hashlib
import io
import json
from pathlib import Path
import re
import sqlite3
import sys
import types
from unittest.mock import patch

import pytest

from zbtriage import report
from zbtriage.iocs import Indicator, IocSet
from zbtriage.modules import browser, ios, traces
from zbtriage.result import Hit, ModuleResult, EV_CONTACTED, EV_PERSISTENCE, EV_REFERENCED
from test_expanded_capabilities import context, ios_fixture, BAD
from test_followup_fixes import bundle, fake_registry, sms_path


@pytest.mark.parametrize("output_failure", [False, True])
def test_malformed_unicode_keeps_independent_reports(tmp_path, bundle, output_failure):
    odd = "odd\ud800-file\udfff"
    for n, api in enumerate((report, bundle)):
        r = ModuleResult("browser")
        r.ran("history")
        r.submetrics[odd] = 1
        r.note(odd)
        r.add_hit(Hit(BAD, odd, odd, tier="infrastructure", evidence=EV_CONTACTED, kind="domain"))
        args = types.SimpleNamespace(json=str(tmp_path / ("full%d.json" % n)),
                                     share_json=str(tmp_path / ("share%d.json" % n)),
                                     scan_type="default", target=[], phone=None, quick=False,
                                     app_cache=False, patterns=False, extended_windows=False)
        write = api.write_json
        def writer(doc, path):
            if output_failure and path == args.json:
                raise UnicodeEncodeError("utf-8", "\ud800", 0, 1, "synthetic")
            return write(doc, path)
        out, err = io.BytesIO(), io.BytesIO()
        stdout = io.TextIOWrapper(out, encoding="utf-8", errors="strict", write_through=True)
        stderr = io.TextIOWrapper(err, encoding="ascii", errors="strict", write_through=True)
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), patch.object(api, "write_json", writer):
            code = api.finalize_report(context().iocs, [r], datetime.datetime.now(), args)
        assert code == (1 if output_failure else 2)
        shared = json.loads(Path(args.share_json).read_text(encoding="utf-8"))
        assert shared["verdict"]["findings_total"] == 1
        assert "\\ud800" in out.getvalue().decode("utf-8")
        assert odd not in json.dumps(shared)
        if not output_failure:
            full = json.loads(Path(args.json).read_text(encoding="utf-8"))
            assert full["modules"]["browser"]["hits"][0]["location"] == odd
            assert full["modules"]["browser"]["submetrics"][odd] == 1
        stdout.detach()
        stderr.detach()


@pytest.mark.parametrize("extension", ["hta", "scr", "exe", "pif", "com", "jar", "unknown", ""])
def test_unknown_startup_formats_are_gaps(tmp_path, monkeypatch, bundle, extension):
    monkeypatch.setitem(sys.modules, "winreg", fake_registry())
    for name in ("APPDATA", "PROGRAMDATA", "SystemRoot"):
        monkeypatch.setenv(name, str(tmp_path))
    root = tmp_path / "Microsoft/Windows/Start Menu/Programs/Startup"
    root.mkdir(parents=True)
    (root / ("entry." + extension)).write_text("https://" + BAD)
    for reader in (traces._tr_persistence, bundle._tr_persistence):
        r = ModuleResult("traces")
        reader(r, context())
        assert any(c.name == "startup-files" and not c.ran for c in r.checks)
        assert r.hits and all(h.evidence == EV_REFERENCED for h in r.hits)


@pytest.mark.parametrize("text,supported,active", [
    ("echo Write-Output https://fixture.invalid | powershell -", False, False),
    ("echo echo https://fixture.invalid>payload.cmd & call payload.cmd", False, False),
    ("rem ordinary & https://fixture.invalid", True, False),
    ("@REM ordinary & https://fixture.invalid", True, False),
    ("echo https://fixture.invalid", True, False),
    ("program.exe https://fixture.invalid", True, True),
])
def test_batch_flow_and_whole_line_comments(tmp_path, monkeypatch, bundle, text, supported, active):
    monkeypatch.setitem(sys.modules, "winreg", fake_registry())
    for name in ("APPDATA", "PROGRAMDATA", "SystemRoot"):
        monkeypatch.setenv(name, str(tmp_path))
    root = tmp_path / "Microsoft/Windows/Start Menu/Programs/Startup"
    root.mkdir(parents=True)
    (root / "entry.cmd").write_text(text)
    for api in (traces, bundle):
        launch, reference, understood = api._tr_startup_content(text.encode(), "entry.cmd")
        assert understood == supported
        assert (BAD in launch) == active
        r = ModuleResult("traces")
        api._tr_persistence(r, context())
        assert any(c.name == "startup-files" and not c.ran for c in r.checks) == (not supported)
        assert r.hits and all(h.evidence == (EV_PERSISTENCE if active else EV_REFERENCED) for h in r.hits)


@pytest.mark.parametrize("extension", ["txt", "md", "log", "ini"])
def test_reference_document_allowlist(bundle, extension):
    for api in (traces, bundle):
        active, reference, supported = api._tr_startup_content(BAD.encode(), "entry." + extension)
        assert supported and not active and BAD in reference


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("state,received,grade", [(1,100,"contacted"), (2,0,"attempted")])
def test_download_query_specificity_cannot_hide_host(tmp_path, bundle, reverse, state, received, grade):
    child = "sub." + BAD
    host, query = (child, BAD) if reverse else (BAD, child)
    with contextlib.closing(sqlite3.connect(tmp_path / "History")) as db:
        db.executescript("CREATE TABLE downloads(id INTEGER,current_path TEXT,tab_url TEXT,referrer TEXT,state INTEGER,received_bytes INTEGER); CREATE TABLE downloads_url_chains(id INTEGER,chain_index INTEGER,url TEXT)")
        db.execute("INSERT INTO downloads VALUES(1,'','','',?,?)", (state, received))
        db.execute("INSERT INTO downloads_url_chains VALUES(1,0,?)", ("https://" + host + "/?q=" + query,))
        db.commit()
    for reader in (browser.run, bundle.run_browser):
        ctx = context(targets=(str(tmp_path),))
        ctx.iocs = IocSet([Indicator(value,"infrastructure","primary","domain","fixture") for value in (BAD,child)], "fixture", None)
        r = reader(ctx)
        assert {(h.indicator,h.evidence) for h in r.hits} == {(host,grade), (query,EV_REFERENCED)}


@pytest.mark.parametrize("encoded", [None, b"", b"encoded", "absent-column"])
def test_binary_ios_fields_are_not_searched_empty(tmp_path, bundle, encoded):
    ios_fixture(tmp_path)
    with contextlib.closing(sqlite3.connect(sms_path(tmp_path))) as db:
        if encoded != "absent-column":
            db.execute("ALTER TABLE message ADD COLUMN attributedBody BLOB")
            db.execute("UPDATE message SET attributedBody=?", (encoded,))
        db.execute("UPDATE message SET text=?", (b"https://" + BAD.encode(),))
        db.execute("INSERT INTO message(text,date,is_from_me) VALUES(?,0,0)", ("https://" + BAD,))
        db.commit()
    fid = hashlib.sha1(b"HomeDomain-Library/Safari/History.db").hexdigest()
    with contextlib.closing(sqlite3.connect(tmp_path / fid[:2] / fid)) as db:
        db.execute("UPDATE history_items SET url=?", (b"https://" + BAD.encode(),))
        db.execute("INSERT INTO history_items VALUES(2,?)", ("https://" + BAD,))
        db.execute("INSERT INTO history_visits(history_item,visit_time) VALUES(2,0)")
        db.commit()
    for reader in (ios.run, bundle.run_ios):
        r = reader(context(phone_path=str(tmp_path)))
        assert r.checked == 3 and r.skipped == 2
        for check in ("ios:messages", "ios:safari"):
            assert any(c.name == check and "unsupported field" in c.reason for c in r.checks)
        assert {h.evidence for h in r.hits} >= {"received", "contacted"}


def test_ios_query_budget_is_local_and_explicit(bundle):
    for api in (ios, bundle):
        with contextlib.closing(sqlite3.connect(":memory:")) as db:
            sql = "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100000) SELECT sum(x) FROM n"
            with patch.object(api, "_IOS_QUERY_STEPS", 0):
                with pytest.raises(api._IosQueryLimit, match="query budget exceeded"):
                    with api._ios_query(db, sql) as rows:
                        rows.fetchall()
                with api._ios_query(db, "SELECT 42") as rows:
                    assert rows.fetchone() == (42,)
            # A new query gets a new wall-clock budget, even after long idle time.
            with patch.object(api.time, "monotonic", return_value=1000000):
                with api._ios_query(db, sql) as rows:
                    assert rows.fetchone() == (5000050000,)


@pytest.mark.parametrize("exhaust", [False, True])
def test_ios_later_index_lookup_budget_keeps_prior_findings(tmp_path, bundle, exhaust):
    ios_fixture(tmp_path)
    with contextlib.closing(sqlite3.connect(tmp_path / "Manifest.db")) as db:
        db.executemany("INSERT INTO Files VALUES(?,?,?,?,?)", [("%040x" % n,"Other","dummy",1,b"") for n in range(1000)])
        db.commit()
    for api, reader in ((ios,ios.run),(bundle,bundle.run_ios)):
        query = api._ios_query
        clock = [0]
        @contextlib.contextmanager
        def controlled(con, sql, params=()):
            # A later lookup must either work with its own budget, or report
            # genuine exhaustion precisely, retaining the earlier message hit.
            late = bool(params and params[-1] == "Library/Safari/History.db")
            if late:
                clock[0] += 20
            with patch.object(api, "_IOS_QUERY_STEPS", 0 if exhaust and late else 20000):
                with query(con, sql, params) as rows:
                    yield rows
        with patch.object(api.time, "monotonic", side_effect=lambda: clock[0]), patch.object(api,"_ios_query",controlled):
            r = reader(context(phone_path=str(tmp_path)))
        assert any(h.evidence == "received" for h in r.hits)
        gaps = [c.reason for c in r.checks if not c.ran]
        if exhaust:
            assert gaps and all("backup index lookup: SQLite query budget exceeded" in reason for reason in gaps)
        else:
            assert not gaps


def build_namespace():
    path = Path(__file__).resolve().parents[2] / "build/bundle.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    node = next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name == "namespace")
    env = {"ast":ast, "re":re}
    exec(compile(ast.Module(body=[node],type_ignores=[]),str(path),"exec"),env)
    return env["namespace"]


@pytest.mark.parametrize("expression", ["f'{NAME}'", "f'{NAME=}'", "f'{run}'", "f'{1:{NAME}}'"])
def test_bundle_rejects_version_sensitive_fstring_names(expression):
    with pytest.raises(ValueError, match="f-string"):
        build_namespace()("NAME='fixture'\ndef run(ctx):\n    return " + expression, "fixture")


def test_bundle_ast_rename_preserves_strings_and_unicode_offsets():
    source = '''NAME='fixture'
# NAME and def run(ctx) are literal documentation.
def run(ctx):
    label = "caf\u00e9"; value = NAME
    return value, "USER PID NAME", "def run(ctx)", f"literal NAME {label}"
'''
    transformed = build_namespace()(source,"fixture")
    env = {}
    exec(transformed,env)
    assert env["run_fixture"](None) == ("fixture","USER PID NAME","def run(ctx)","literal NAME caf\u00e9")
    assert "# NAME and def run(ctx)" in transformed
