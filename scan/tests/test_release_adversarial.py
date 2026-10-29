"""Malformed inputs cannot invent evidence or suppress unrelated readable records."""
import contextlib
import datetime
from decimal import Decimal
import errno
import io
import itertools
import json
import os
from pathlib import Path
import plistlib
import random
import sqlite3
import sys
import tarfile
import tempfile
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from zbtriage import evidence, ios_messages, report, workflow
from zbtriage.iocs import IocSet, Indicator
from zbtriage.modules import ios
from zbtriage.iocs import load_any
from zbtriage.result import Hit, ModuleResult
from test_evidence_safety import _ctx, safety_api
from test_evidence_review import _bundle_file, _indicator, BAD
from test_followup_fixes import bundle
from test_ios_upgrade import backup, db_bytes, keyed_text, typed_text, tree_hashes


@pytest.mark.parametrize("older,newer", (
    ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00.001Z"),
    ("2026-01-01T00:00:00.1Z", "2026-01-01T00:00:00.11Z"),
    ("2026-01-01T00:00:00.1234567Z", "2026-01-01T00:00:00.1234568Z")))
def test_withdrawal_versions_follow_time_not_text_order(bundle, older, newer):
    rows = [{"publisher": "P", "id": "same", "modified": older, "revoked": False},
            {"publisher": "P", "id": "same", "modified": newer, "revoked": True}]
    for order in itertools.permutations(rows):
        assert evidence._withdrawn_only(order)
        assert bundle._withdrawn_only(order)


@pytest.mark.parametrize("stamp", ("2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00.000000000Z"))
def test_equivalent_timestamp_spellings_cannot_hide_an_active_version(bundle, stamp):
    rows = [{"publisher": "P", "id": "same", "modified": stamp, "revoked": False},
            {"publisher": "P", "id": "same", "modified": "2026-01-01T00:00:00Z", "revoked": True}]
    for order in itertools.permutations(rows):
        assert not evidence._withdrawn_only(order)
        assert not bundle._withdrawn_only(order)


@pytest.mark.parametrize("stamp", ("not-a-date", "9999-99-99T99:99:99Z"))
def test_invalid_withdrawal_date_cannot_override_a_dated_active_version(bundle, stamp):
    rows = [{"publisher": "P", "id": "same", "modified": "2026-01-01T00:00:00Z", "revoked": False},
            {"publisher": "P", "id": "same", "modified": stamp, "revoked": True}]
    assert not evidence._withdrawn_only(rows)
    assert not bundle._withdrawn_only(rows)


def test_fractional_withdrawal_order_matches_exact_decimal_order(bundle):
    rng = random.Random(19231)
    for _ in range(500):
        a = "".join(str(rng.randrange(10)) for _ in range(rng.randrange(1, 20)))
        b = "".join(str(rng.randrange(10)) for _ in range(rng.randrange(1, 20)))
        rows = [{"publisher": "P", "id": "same", "modified": "2026-01-01T00:00:00." + a + "Z", "revoked": False},
                {"publisher": "P", "id": "same", "modified": "2026-01-01T00:00:00." + b + "Z", "revoked": True}]
        expected = Decimal("0." + b) > Decimal("0." + a)
        assert evidence._withdrawn_only(rows) == expected
        assert bundle._withdrawn_only(rows) == expected


@pytest.mark.parametrize("active,withdrawn,expected", (
    ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00.001Z", True),
    ("2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00Z", False),
    ("2026-01-01T00:00:00Z", "not-a-date", False)))
def test_withdrawal_time_changes_reach_the_report_verdict(tmp_path, bundle, active, withdrawn, expected):
    oid = "indicator--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    path = _bundle_file(tmp_path, _indicator(oid, active, False), _indicator(oid, withdrawn, True))
    for loader, make_result, make_hit, build in (
            (load_any, ModuleResult, Hit, report.build_document),
            (bundle.load_any, bundle.ModuleResult, bundle.Hit, bundle.build_document)):
        result = make_result("browser")
        result.ran("history")
        result.add_hit(make_hit(BAD, "fixture History", "recorded visit", evidence="contacted"))
        document = build(loader(path), [result], datetime.datetime(2026, 1, 2))
        assert document["modules"]["browser"]["hits"][0]["withdrawn_only"] == expected
        assert (document["exit_code"] == 2) == (not expected)


def test_malformed_stix_fields_preserve_an_independent_valid_indicator(tmp_path, bundle):
    path = tmp_path / "feed.stix2"
    good = {"type": "indicator", "pattern": "[domain-name:value='fixture.invalid']"}
    fields = ("type", "id", "name", "pattern", "created_by_ref", "modified", "revoked", "x_mvt_platforms")
    values = (None, [], {}, ["x"], {"x": "y"}, True, 0, 1.5, "\ud800", "\x1b[2J")
    for field, value in itertools.product(fields, values):
        candidate = {"type": "indicator", "id": "other", "pattern": "[domain-name:value='second.invalid']"}
        candidate[field] = value
        path.write_text(json.dumps({"objects": [candidate, good]}), encoding="utf-8")
        snapshots = []
        for loader in (load_any, bundle.load_any):
            result = loader(str(path))
            snapshots.append([(i.value, i.type, i.contexts) for i in result.indicators])
            assert any(i.value == "fixture.invalid" for i in result.indicators), (field, value)
        assert snapshots[0] == snapshots[1], (field, value)


def _message_mutations():
    rng = random.Random(72931)
    seeds = (keyed_text("ordinary text", "fixture.invalid"), typed_text("ordinary text"))
    samples = [raw[:n] for raw in seeds for n in range(len(raw))]
    for _ in range(1200):
        raw = bytearray(rng.choice(seeds))
        for _ in range(rng.randrange(1, 5)):
            raw[rng.randrange(len(raw))] = rng.randrange(256)
        samples.append(bytes(raw))
    return samples


def test_encoded_message_mutations_have_bounded_matching_outcomes(bundle):
    def outcome(decode, raw):
        try:
            value = decode(raw)
            assert isinstance(value, str) and len(value.encode("utf-8")) <= 65536
            return ("text", value)
        except (ValueError, UnicodeError, plistlib.InvalidFileException):
            return ("unsupported",)
    for n, raw in enumerate(_message_mutations()):
        assert outcome(ios_messages.ios_message_text, raw) == outcome(bundle.ios_message_text, raw), n


def test_malformed_encoded_message_does_not_hide_its_neighbours(tmp_path, safety_api):
    cases = _message_mutations()[::19]
    statements = [("INSERT INTO message VALUES('fixture.invalid',0,0,NULL)", ())]
    statements += [("INSERT INTO message VALUES(NULL,0,0,?)", (raw,)) for raw in cases]
    statements.append(("INSERT INTO message VALUES('second.invalid',0,0,NULL)", ()))
    raw, _ = db_bytes(tmp_path, "CREATE TABLE message(text,date,is_from_me,attributedBody)", statements)
    root = tmp_path / "backup"
    backup(root, [("HomeDomain", "Library/SMS/sms.db", raw)])
    before = tree_hashes(root)
    result = safety_api.ios_run(_ctx(root))
    assert any(h.indicator == "fixture.invalid" and h.location.endswith(":record 1") for h in result.hits)
    assert any(h.indicator == "second.invalid" and h.location.endswith(":record " + str(len(statements))) for h in result.hits)
    assert any(not c.ran and c.name == "ios:messages" for c in result.checks)
    assert tree_hashes(root) == before


@pytest.mark.parametrize("output", ("json", "text"))
@pytest.mark.parametrize("failure", ("write", "fsync", "replace"))
def test_failed_report_save_preserves_previous_bytes(tmp_path, safety_api, output, failure):
    api = (report if output == "json" else workflow) if safety_api.entry.__name__ == "zbtriage.cli" else safety_api.entry
    dest = tmp_path / "report.out"
    dest.write_bytes(b"previous complete report\n")
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    writer = api.write_json if output == "json" else api.workflow_write_text
    original = tempfile.NamedTemporaryFile
    @contextlib.contextmanager
    def bad_writer(*args, **kwargs):
        with original(*args, **kwargs) as fh:
            class Partial:
                name = fh.name
                def write(self, text):
                    fh.write(text[:3])
                    raise OSError(errno.ENOSPC, "No space left on device")
            yield Partial()
    target, name, replacement = ((tempfile, "NamedTemporaryFile", bad_writer) if failure == "write" else
                                 (os, failure, lambda *a: (_ for _ in ()).throw(OSError(errno.EIO, "I/O failure"))))
    with patch.object(target, name, replacement), pytest.raises(OSError):
        writer({"private": "fixture.invalid"} if output == "json" else "new private report", str(dest))
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before


@pytest.mark.parametrize("unsafe", ("../escape.ips", "/absolute.ips", "a/../escape.ips", "a\\escape.ips", "C:/escape.ips"))
def test_unsafe_archive_neighbour_never_selects_an_outside_file(tmp_path, safety_api, unsafe):
    path = tmp_path / "diagnostics.tar"
    with tarfile.open(path, "w") as archive:
        for name, value in (("before.ips", "com.apple.before"), (unsafe, "fixtureproc"), ("after.ips", "com.apple.after")):
            raw = json.dumps({"procName": value}).encode()
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            archive.addfile(member, io.BytesIO(raw))
    ctx = _ctx(path, ios_input="sysdiagnose")
    ctx.iocs = IocSet([Indicator("fixtureproc", "artifact", "primary", "process", "fixture")], "fixture", None)
    result = safety_api.ios_run(ctx)
    assert not result.hits
    assert any(not c.ran and c.name == "ios:input" for c in result.checks)
    assert result.checked >= 2
    assert not (tmp_path / "escape.ips").exists()


@pytest.mark.parametrize("damage", ("truncated", "checksum"))
def test_later_damaged_wal_commit_preserves_the_prior_committed_transaction(tmp_path, safety_api, damage):
    work = tmp_path / "writer.db"
    with contextlib.closing(sqlite3.connect(work)) as con:
        con.execute("CREATE TABLE message(text,date,is_from_me)")
        con.execute("INSERT INTO message VALUES('fixture.invalid',0,0)")
        con.commit()
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA wal_autocheckpoint=0")
        con.execute("INSERT INTO message VALUES('second.invalid',0,0)")
        con.commit()
        first_size = Path(str(work) + "-wal").stat().st_size
        con.execute("INSERT INTO message VALUES('third.invalid',0,0)")
        con.commit()
        raw = work.read_bytes()
        wal = bytearray(Path(str(work) + "-wal").read_bytes())
    assert len(wal) > first_size
    if damage == "truncated":
        wal = wal[:first_size + 25]
    else:
        wal[-1] ^= 1
    root = tmp_path / "backup"
    backup(root, [("HomeDomain", "Library/SMS/sms.db", raw),
                  ("HomeDomain", "Library/SMS/sms.db-wal", bytes(wal))])
    ctx = _ctx(root)
    ctx.iocs = IocSet([Indicator(value, "infrastructure", "primary", "domain", "fixture")
                      for value in ("fixture.invalid", "second.invalid", "third.invalid")], "fixture", None)
    before = tree_hashes(root)
    result = safety_api.ios_run(ctx)
    assert {h.indicator for h in result.hits} == {"fixture.invalid", "second.invalid"}
    assert any(not c.ran and c.name == "ios:messages" and "WAL" in c.reason for c in result.checks)
    assert tree_hashes(root) == before
