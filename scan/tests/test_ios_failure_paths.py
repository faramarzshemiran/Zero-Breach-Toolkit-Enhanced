"""Encrypted evidence remains isolated when individual artifacts cannot be read."""
import builtins
import contextlib
import errno
import hashlib
import os
from pathlib import Path
import plistlib
import shutil
import sqlite3
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from zbtriage import ios_sources, readers
from test_evidence_safety import _ctx, safety_api
from test_followup_fixes import bundle
from test_ios_upgrade import backup, db_bytes, tree_hashes


def _encrypted_evidence(tmp_path, wal=False):
    raw, sidecar = db_bytes(tmp_path, "CREATE TABLE message(text,date,is_from_me)",
        [("INSERT INTO message VALUES(?,700000000,0)", ("fixture.invalid",))])
    if wal:
        work = tmp_path / "with-wal.db"
        work.write_bytes(raw)
        with contextlib.closing(sqlite3.connect(work)) as con:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA wal_autocheckpoint=0")
            con.execute("INSERT INTO message VALUES('second.invalid',700000001,0)")
            con.commit()
            raw, sidecar = work.read_bytes(), Path(str(work) + "-wal").read_bytes()
    safari, _ = db_bytes(tmp_path,
        "CREATE TABLE history_items(id,url); CREATE TABLE history_visits(history_item,visit_time,origin)",
        [("INSERT INTO history_items VALUES(1,'https://fixture.invalid')", ()),
         ("INSERT INTO history_visits VALUES(1,700000000,0)", ())])
    tabs, _ = db_bytes(tmp_path, "CREATE TABLE tabs(url)",
                      [("INSERT INTO tabs VALUES('https://second.invalid')", ())])
    items = [("HomeDomain", "Library/SMS/sms.db", raw),
             ("HomeDomain", "Library/Safari/History.db", safari),
             ("HomeDomain", "Library/Safari/BrowserState.db", tabs)]
    if wal:
        items.append(("HomeDomain", "Library/SMS/sms.db-wal", sidecar))
    root = tmp_path / "backup"
    backup(root, items, encrypted=True, modern=True)
    return root


def _alter_artifact_key(root, work, relative, damage):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    path = root / "Manifest.db"
    decryptor = Cipher(algorithms.AES(b"m" * 32), modes.CBC(bytes(16))).decryptor()
    raw = decryptor.update(path.read_bytes()) + decryptor.finalize()
    work.write_bytes(raw[:-raw[-1]])
    with contextlib.closing(sqlite3.connect(work)) as con:
        encoded = con.execute("SELECT file FROM Files WHERE relativePath=?", (relative,)).fetchone()[0]
        metadata = plistlib.loads(encoded)
        record = metadata["$objects"][1]
        wrapped = record["EncryptionKey"]
        if damage == "class":
            record["EncryptionKey"] = (99).to_bytes(4, "little") + wrapped[4:]
        else:
            record["EncryptionKey"] = wrapped[:-1] + bytes([wrapped[-1] ^ 1])
        con.execute("UPDATE Files SET file=? WHERE relativePath=?",
                    (plistlib.dumps(metadata, fmt=plistlib.FMT_BINARY), relative))
        con.commit()
    raw = work.read_bytes()
    padding = 16 - len(raw) % 16
    encryptor = Cipher(algorithms.AES(b"m" * 32), modes.CBC(bytes(16))).encryptor()
    path.write_bytes(encryptor.update(raw + bytes([padding]) * padding) + encryptor.finalize())


@pytest.mark.parametrize("artifact", ("main", "wal"))
@pytest.mark.parametrize("damage", ("class", "wrapped-key"))
def test_an_unreadable_artifact_key_preserves_readable_neighbours(tmp_path, safety_api, artifact, damage):
    root = _encrypted_evidence(tmp_path, wal=True)
    relative = "Library/SMS/sms.db" + ("-wal" if artifact == "wal" else "")
    _alter_artifact_key(root, tmp_path / "manifest-edit.db", relative, damage)
    before = tree_hashes(root)
    ctx = _ctx(root, backup_password="owner-password")
    result = safety_api.ios_run(ctx)
    messages = [h for h in result.hits if "Library/SMS/sms.db:record" in h.location]
    assert [h.indicator for h in messages] == (["fixture.invalid"] if artifact == "wal" else [])
    assert any("Library/Safari/History.db" in h.location and h.evidence == "contacted" for h in result.hits)
    assert any("BrowserState.db" in h.location for h in result.hits)
    assert any(not c.ran and c.name == "ios:messages" and
               ("protection class" if damage == "class" else "key could not be verified") in c.reason
               for c in result.checks)
    assert tree_hashes(root) == before
    for hit in result.hits:
        assert hit.provenance["encrypted_source"]
        assert hashlib.sha256(Path(hit.artifact).read_bytes()).hexdigest() == hit.provenance["sha256"]


@pytest.mark.parametrize("failure", ("disk-full", "interrupt", "cleanup"))
def test_plaintext_lifetime_and_partial_findings_on_failure(tmp_path, safety_api, monkeypatch, failure):
    root = _encrypted_evidence(tmp_path)
    before = tree_hashes(root)
    temporary = tmp_path / "private-temporary"
    temporary.mkdir()
    api = ios_sources if safety_api.entry.__name__ == "zbtriage.cli" else safety_api.entry
    lifecycle = readers if api is ios_sources else api
    monkeypatch.setattr(api, "local_temp_dir", lambda: str(temporary))
    original_database = api.IosEvidenceSource.database
    attempted, plaintext_seen = [], []

    def database(source, raw, check, wal=b""):
        if check != "ios:safari" or failure == "cleanup":
            return original_database(source, raw, check, wal)
        def failing_open(path, mode="r", *args, **kwargs):
            stream = builtins.open(path, mode, *args, **kwargs)
            if mode != "xb":
                return stream
            @contextlib.contextmanager
            def partial_write():
                with stream:
                    stream.write(raw[:128])
                    stream.flush()
                    plaintext_seen.append(Path(path).read_bytes().startswith(b"SQLite format 3\0"))
                    attempted.append(check)
                    if failure == "interrupt":
                        raise KeyboardInterrupt()
                    raise OSError(errno.ENOSPC, "No space left on device")
                    yield stream
            return partial_write()
        with monkeypatch.context() as local:
            local.setattr(api, "open", failing_open, raising=False)
            return original_database(source, raw, check, wal)

    monkeypatch.setattr(api.IosEvidenceSource, "database", database)
    ctx = _ctx(root, backup_password="owner-password")
    try:
        with monkeypatch.context() as cleanup_patch:
            if failure == "cleanup":
                def refused(path, *args, **kwargs):
                    raise PermissionError(errno.EACCES, "temporary files locked")
                cleanup_patch.setattr(api.shutil, "rmtree", refused)
            lifecycle.reader_run(ctx, lambda spec: safety_api.ios_run)
        result = next(r for r in ctx.completed if r.name == "ios")
        assert any(h.evidence == "received" for h in result.hits)
        assert any(not c.ran for c in result.checks)
        assert tree_hashes(root) == before
        if failure == "cleanup":
            assert list(temporary.iterdir())
            assert any(not c.ran and "plaintext cleanup failed" in c.reason for c in result.checks)
        else:
            assert attempted == ["ios:safari"] and plaintext_seen == [True]
            assert not list(temporary.iterdir())
        public_text = repr(result.to_dict())
        assert "owner-password" not in public_text
        assert ctx.cancelled == (failure == "interrupt")
        if failure == "disk-full":
            assert any(not c.ran and c.name == "ios:safari" and "No space" in c.reason for c in result.checks)
            assert any("BrowserState.db" in h.location for h in result.hits)
    finally:
        for path in temporary.iterdir():
            shutil.rmtree(path)
