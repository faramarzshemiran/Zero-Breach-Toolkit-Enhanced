"""Ambiguous evidence, publisher attribution and incomplete private exports."""
import contextlib
import datetime
import errno
import hashlib
import io
import json
import os
import sys
import tarfile
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import iocs, report, stix
from zbtriage.result import Hit, ModuleResult
from test_evidence_safety import _ctx, safety_api
from test_followup_fixes import bundle
from test_handoff import handoff_api, handoff_document
from test_stix_import import bundle as stix_document


@pytest.mark.parametrize("columns", (
    ("fixture.invalid", "cc", "primary", "", "Family Alpha"),
    ("fixture.invalid", "cc", "primary", "Publisher", ""),
    ("fixture.invalid", "cc", "primary", "", ""),
))
def test_empty_optional_curated_columns_keep_their_positions(tmp_path, safety_api, columns):
    path = tmp_path / "curated.txt"
    path.write_text("\t".join(columns) + "\n", encoding="utf-8")
    api = iocs if safety_api.entry.__name__ == "zbtriage.cli" else safety_api.entry
    ind = api.load(str(path)).indicators[0]
    assert (ind.source, ind.family) == columns[3:]


@pytest.mark.parametrize("row", (
    "fixture.invalid\t\tcc\tprimary\tPublisher",
    "fixture.invalid\tcc\t\tprimary\tPublisher",
    "fixture.invalid\tcc\tprimary\tPublisher\tFamily\textra",
))
def test_malformed_curated_columns_are_refused(tmp_path, safety_api, row):
    path = tmp_path / "curated.txt"
    path.write_text(row + "\n", encoding="utf-8")
    api = iocs if safety_api.entry.__name__ == "zbtriage.cli" else safety_api.entry
    with pytest.raises(api.IocError):
        api.load(str(path))


@pytest.mark.parametrize("reverse", (False, True))
@pytest.mark.parametrize("conflict", ("tier", "confidence", "none"))
def test_curated_duplicates_preserve_attribution_or_refuse_conflicting_classifications(tmp_path, safety_api, reverse, conflict):
    rows = ["fixture.invalid\tcc\tprimary\tPublisher Alpha\tFamily Alpha",
            "FIXTURE.INVALID.\t{}\t{}\tPublisher Beta\tFamily Beta".format(
                "stalkerware" if conflict == "tier" else "cc",
                "secondary" if conflict == "confidence" else "primary")]
    if reverse:
        rows.reverse()
    path = tmp_path / "curated.txt"
    path.write_text("\n".join(rows + rows) + "\n", encoding="utf-8")
    api = iocs if safety_api.entry.__name__ == "zbtriage.cli" else safety_api.entry
    if conflict != "none":
        with pytest.raises(api.IocError, match="conflicting.*classification"):
            api.load(str(path))
        return
    loaded = api.load(str(path))
    assert len(loaded) == 1
    ind = loaded.indicators[0]
    assert set(ind.source.split("; ")) == {"Publisher Alpha", "Publisher Beta"}
    assert len(ind.source.split("; ")) == 2
    assert set(ind.family.split("; ")) == {"Family Alpha", "Family Beta"}
    records = [json.loads(raw) for raw in ind.contexts]
    assert {(r["source"], r["family"]) for r in records} == {
        ("Publisher Alpha", "Family Alpha"), ("Publisher Beta", "Family Beta")}
    assert len(records) == 2


def test_conflicting_curated_rows_stop_before_scan_or_report(tmp_path, safety_api, capsys):
    feed = tmp_path / "curated.txt"
    feed.write_text("fixture.invalid\tcc\tprimary\nfixture.invalid\tstalkerware\tprimary\n",
                    encoding="utf-8")
    output = tmp_path / "report.json"
    dispatch = "_run_modules" if safety_api.entry.__name__ == "zbtriage.cli" else "reader_run"
    with patch.object(safety_api.entry, dispatch, side_effect=AssertionError("scan must not start")):
        code = safety_api.entry.main(["--no-menu", "--no-feeds", "--iocs", str(feed), "--json", str(output)])
    assert code == 1
    assert not output.exists()
    assert "conflicting duplicate classification" in capsys.readouterr().err


def test_repeated_feed_merges_keep_each_attribution_once(safety_api):
    api = iocs if safety_api.entry.__name__ == "zbtriage.cli" else safety_api.entry
    first = api.IocSet([api.Indicator("fixture.invalid", "cc", "primary", "domain", "Publisher Alpha", "Family Alpha")], "alpha", None)
    second = api.IocSet([api.Indicator("fixture.invalid", "infrastructure", "primary", "domain", "Publisher Beta", "Family Beta")], "beta", None)
    merged = api.merge([api.merge([first, second]), first, second])
    ind = merged.indicators[0]
    assert ind.tier == "cc"
    assert ind.source == "Publisher Alpha; Publisher Beta"
    assert ind.family == "Family Alpha; Family Beta"
    assert len(ind.contexts) == 2


@pytest.mark.parametrize("kind", ("curated", "stix", "merge"))
@pytest.mark.parametrize("count", (256, 257))
def test_excessive_distinct_assertions_are_refused_instead_of_truncated(tmp_path, safety_api, kind, count):
    api = iocs if safety_api.entry.__name__ == "zbtriage.cli" else safety_api.entry
    error = api.IocError
    if kind == "curated":
        path = tmp_path / "many.txt"
        path.write_text("\n".join("fixture.invalid\tcc\tprimary\tPublisher {}".format(n)
                                  for n in range(count)), encoding="utf-8")
        load = lambda: api.load(str(path))
    elif kind == "stix":
        path = tmp_path / "many.stix2"
        path.write_text(json.dumps(stix_document(["[domain-name:value='fixture.invalid']"] * count)), encoding="utf-8")
        load = lambda: api.load_any(str(path))
    else:
        sets = [api.IocSet([api.Indicator("fixture.invalid", "cc", "primary", "domain", "Publisher {}".format(n))], "fixture", None)
                for n in range(count)]
        load = lambda: api.merge(sets)
    if count > 256:
        with pytest.raises(error, match="publisher assertions"):
            load()
    else:
        loaded = load()
        assert len(loaded.indicators) == 1
        assert len(loaded.indicators[0].contexts) == count


@pytest.mark.parametrize("problem", ("encoding", "line", "total", "growth"))
def test_unreadable_or_oversized_curated_files_have_explicit_errors(tmp_path, safety_api, problem):
    api = iocs if safety_api.entry.__name__ == "zbtriage.cli" else safety_api.entry
    path = tmp_path / "bad.txt"
    raw = b"fixture.invalid\tcc\tprimary\n"
    if problem == "encoding":
        path.write_bytes(raw + b"\xff\xfe\n")
        with pytest.raises(api.IocError, match="UTF-8"):
            api.load(str(path))
    elif problem == "line":
        path.write_bytes(b"#" + b"x" * 65536 + b"\n" + raw)
        with pytest.raises(api.IocError, match="line.*limit"):
            api.load(str(path))
    else:
        path.write_bytes(raw * 4)
        with patch.object(api, "_MAX_CURATED_BYTES", len(raw) * 3):
            with contextlib.ExitStack() as stack:
                if problem == "growth":
                    class SmallStat:
                        st_size = len(raw)
                    stack.enter_context(patch.object(api.os, "fstat", return_value=SmallStat()))
                with pytest.raises(api.IocError, match="byte limit"):
                    api.load(str(path))


def test_identical_repeated_assertions_do_not_use_up_the_distinct_limit(tmp_path, safety_api):
    api = iocs if safety_api.entry.__name__ == "zbtriage.cli" else safety_api.entry
    path = tmp_path / "repeated.txt"
    path.write_text("fixture.invalid\tcc\tprimary\tPublisher\tFamily\n" * 1000, encoding="utf-8")
    loaded = api.load(str(path))
    assert len(loaded.indicators) == 1
    assert len(loaded.indicators[0].contexts) == 1
    assert loaded.indicators[0].family == "Family"


@pytest.mark.parametrize("reverse", (False, True))
def test_duplicate_stix_values_keep_each_family_and_its_assertion(tmp_path, safety_api, reverse):
    doc = stix_document(["[domain-name:value='fixture.invalid']"] * 3,
                        families=("Family Alpha", "Family Beta"))
    if reverse:
        doc["objects"].reverse()
    path = tmp_path / "families.stix2"
    path.write_text(json.dumps(doc), encoding="utf-8")
    built = safety_api.entry.__name__ != "zbtriage.cli"
    importer = safety_api.entry if built else stix
    loader = safety_api.entry if built else iocs
    loaded = importer.load_stix(str(path))
    assert len(loaded.indicators) == 1 and loaded.duplicates == 2
    assert loaded.summary()["families"] == {"Family Alpha": 1, "Family Beta": 1}
    ind = loaded.indicators[0]
    assert ind.family == "Family Alpha; Family Beta"
    records = [json.loads(raw) for raw in ind.contexts]
    assert {r["id"]: r["family"] for r in records} == {
        "indicator--0": "Family Alpha", "indicator--1": "Family Beta", "indicator--2": "Family Alpha"}
    api = safety_api.entry if built else report
    result_class = safety_api.entry.ModuleResult if built else ModuleResult
    hit_class = safety_api.entry.Hit if built else Hit
    result = result_class("browser")
    result.ran("history")
    result.add_hit(hit_class(ind.value, "authored History", "visit", evidence="contacted",
                            tier=ind.tier, family=ind.family))
    output = api.build_document(loader.load_any(str(path)), [result], datetime.datetime(2026, 10, 27))
    hit = output["modules"]["browser"]["hits"][0]
    assert hit["family"] == ind.family
    assert {r["family"] for r in hit["indicator_context"]} == {"Family Alpha", "Family Beta"}
    assert output["exit_code"] == 2


@pytest.mark.parametrize("other_type", (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE,
                                        tarfile.FIFOTYPE, tarfile.REGTYPE))
@pytest.mark.parametrize("reverse", (False, True))
@pytest.mark.parametrize("alias", ("ambiguous.ips", "./ambiguous.ips"))
def test_archive_type_collisions_never_choose_a_winning_member(tmp_path, safety_api, other_type, reverse, alias):
    path = tmp_path / "diagnostics.tar"
    members = [("ambiguous.ips", tarfile.REGTYPE, "ambiguousproc"), (alias, other_type, "ambiguousproc")]
    if reverse:
        members.reverse()
    members.insert(0, ("before.ips", tarfile.REGTYPE, "beforeproc"))
    members.append(("after.ips", tarfile.REGTYPE, "afterproc"))
    with tarfile.open(path, "w") as archive:
        for name, kind, process in members:
            entry = tarfile.TarInfo(name + ("/" if kind == tarfile.DIRTYPE else ""))
            entry.type = kind
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                entry.linkname = "before.ips"
            raw = json.dumps({"procName": process}).encode() if kind == tarfile.REGTYPE else b""
            entry.size = len(raw)
            archive.addfile(entry, io.BytesIO(raw))
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    ctx = _ctx(path, ios_input="sysdiagnose")
    ctx.iocs = iocs.IocSet([iocs.Indicator(p, "artifact", "primary", "process", "fixture")
                           for p in ("beforeproc", "afterproc", "ambiguousproc")], "fixture", None)
    result = safety_api.ios_run(ctx)
    assert {hit.indicator for hit in result.hits} == {"beforeproc", "afterproc"}
    assert any(not c.ran and c.name == "ios:input" and "duplicate" in c.reason for c in result.checks)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before


@pytest.mark.parametrize("collision", (False, True))
def test_archive_repeated_directories_are_harmless_but_cannot_revive_an_ambiguous_file(tmp_path, safety_api, collision):
    path = tmp_path / "diagnostics.tar"
    with tarfile.open(path, "w") as archive:
        for name in ("folder/", "./folder/"):
            entry = tarfile.TarInfo(name)
            entry.type = tarfile.DIRTYPE
            archive.addfile(entry)
        raw = b'{"procName":"fixtureproc"}'
        for kind in ((tarfile.REGTYPE, tarfile.DIRTYPE, tarfile.REGTYPE) if collision else (tarfile.REGTYPE,)):
            entry = tarfile.TarInfo("folder/record.ips")
            entry.type = kind
            entry.size = len(raw) if kind == tarfile.REGTYPE else 0
            archive.addfile(entry, io.BytesIO(raw) if entry.size else None)
    ctx = _ctx(path, ios_input="sysdiagnose")
    ctx.iocs = iocs.IocSet([iocs.Indicator("fixtureproc", "artifact", "primary", "process", "fixture")], "fixture", None)
    result = safety_api.ios_run(ctx)
    assert bool(result.hits) is not collision
    input_gaps = [c for c in result.checks if not c.ran and c.name == "ios:input"]
    assert bool(input_gaps) is collision


@pytest.mark.parametrize("failure", ("read", "fsync", "publish"))
@pytest.mark.parametrize("interrupt", (False, True))
def test_failed_evidence_exports_are_unpublished_and_retryable(tmp_path, handoff_api, failure, interrupt):
    source = tmp_path / "selected.bin"
    source.write_bytes(b"private authored evidence" * 30)
    original = source.read_bytes()
    destination = tmp_path / "handoff.zip"
    error = KeyboardInterrupt if interrupt else OSError
    def fail(*args, **kwargs):
        if interrupt:
            raise KeyboardInterrupt
        raise OSError(errno.EIO, "injected storage failure")
    original_source = handoff_api._handoff_source
    @contextlib.contextmanager
    def failing_source(path, expected):
        with original_source(path, expected) as fh:
            class PartialRead:
                def fileno(self):
                    return fh.fileno()
                def read(self, size):
                    if fh.tell():
                        fail()
                    return fh.read(7)
            yield PartialRead()
    target, name, replacement = ((handoff_api, "_handoff_source", failing_source) if failure == "read" else
                                 (handoff_api.os, "fsync", fail) if failure == "fsync" else
                                 (handoff_api, "_handoff_publish", fail))
    with patch.object(target, name, replacement), pytest.raises(error):
        handoff_api.handoff_write(handoff_document(), destination, [source])
    assert not destination.exists()
    assert not list(tmp_path.glob(".zbt_handoff_*"))
    assert source.read_bytes() == original
    manifest = handoff_api.handoff_write(handoff_document(), destination, [source])
    assert manifest["files"][-1]["sha256"] == hashlib.sha256(original).hexdigest()
    assert source.read_bytes() == original
