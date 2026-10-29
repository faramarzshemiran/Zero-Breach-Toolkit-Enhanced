"""Private evidence exports: authored files only, never a real collection."""
import contextlib
import datetime
import hashlib
import json
import os
from pathlib import Path
import zipfile
from unittest.mock import patch

import pytest

from zbtriage import handoff, report
from zbtriage.result import Hit, ModuleResult, EV_REFERENCED
from test_expanded_capabilities import context, BAD
from test_followup_fixes import bundle


@pytest.fixture(params=("source", "bundle"))
def handoff_api(request, bundle):
    return handoff if request.param == "source" else bundle


def handoff_document():
    result = ModuleResult("browser")
    result.ran("history")
    result.add_hit(Hit(BAD, "private-profile", "PRIVATE REPORT TEXT", evidence=EV_REFERENCED))
    doc = report.build_document(context().iocs, [result], datetime.datetime(2026, 10, 26))
    doc["scope"] = {"scan_type": "targeted", "phone": False, "cancelled": False,
                    "targets": ["PRIVATE TARGET"], "scanned": True}
    doc["completed_at"] = "2026-10-26T12:00:00+00:00"
    doc["indicator_fingerprints"] = {"algorithm": "sha256", "combined": "a" * 64}
    return doc


def test_private_archive_integrity_and_minimal_summary(tmp_path, handoff_api):
    source = tmp_path / "authored.cmd"
    source.write_bytes(b"PRIVATE SELECTED FILE - only copied, never executed\x00\xff")
    original = source.read_bytes()
    doc = handoff_document()
    preview = handoff_api.handoff_preview(doc, [source])
    assert not preview["encrypted"]
    assert "not encrypted" in preview["privacy"]
    assert preview["files"][0]["bytes"] == len(original)
    assert preview["files"][0]["member"] == "artifacts/0001.bin"
    output = tmp_path / "handoff.zip"
    manifest = handoff_api.handoff_write(doc, output, [source])
    assert source.read_bytes() == original
    with zipfile.ZipFile(output) as archive:
        assert set(archive.namelist()) == {"report.json", "sharing-summary.json", "report.txt",
                                              "manifest.json", "artifacts/0001.bin"}
        assert json.loads(archive.read("manifest.json")) == manifest
        assert archive.read("artifacts/0001.bin") == original
        assert "PRIVATE REPORT TEXT" in archive.read("report.json").decode()
        summary = archive.read("sharing-summary.json").decode()
        for secret in ("PRIVATE", "fixture.invalid", "private-profile", str(tmp_path)):
            assert secret not in summary
        assert manifest["indicator_fingerprints"] == doc["indicator_fingerprints"]
        assert manifest["scan_completed_at"] == doc["completed_at"]
        for entry in manifest["files"]:
            data = archive.read(entry["member"])
            assert entry["bytes"] == len(data)
            assert entry["sha256"] == hashlib.sha256(data).hexdigest()
        copied = manifest["files"][-1]
        assert copied["source_stat_before"] == copied["source_stat_after"]
        assert copied["collected_at"]
        assert manifest["scanner_code_identity"]["status"] == "not recorded"
    assert not list(tmp_path.glob(".zbt_handoff_*"))


def test_report_paths_are_not_opened_implicitly(tmp_path, handoff_api):
    doc = handoff_document()
    doc["modules"]["browser"]["hits"][0]["artifact"] = str(tmp_path / "missing-private-file")
    with patch.object(handoff_api, "_handoff_source", side_effect=AssertionError("implicit source access")):
        preview = handoff_api.handoff_preview(doc)
        handoff_api.handoff_write(doc, tmp_path / "reports-only.zip")
    assert not preview["files"]


def test_refuses_overwrite_and_selected_destination(tmp_path, handoff_api):
    existing = tmp_path / "existing.zip"
    existing.write_bytes(b"KEEP ORIGINAL")
    with pytest.raises(FileExistsError):
        handoff_api.handoff_write(handoff_document(), existing)
    with pytest.raises(ValueError, match="destination"):
        handoff_api.handoff_write(handoff_document(), existing, [existing])
    assert existing.read_bytes() == b"KEEP ORIGINAL"


def test_refuses_directory_duplicates_and_hardlink_aliases(tmp_path, handoff_api):
    source = tmp_path / "source"
    source.write_bytes(b"fixture")
    for paths in ([tmp_path], [source, source]):
        with pytest.raises(ValueError):
            handoff_api.handoff_preview(handoff_document(), paths)
    alias = tmp_path / "alias"
    try:
        os.link(source, alias)
    except OSError:
        return  # Duplicate-path refusal above remains portable.
    with pytest.raises(ValueError, match="more than once"):
        handoff_api.handoff_preview(handoff_document(), [source, alias])


@pytest.mark.skipif(os.name != "nt", reason="Windows remote/device syntax")
@pytest.mark.parametrize("path", [r"\\example.invalid\share\evidence", "NUL", "file:stream"])
def test_remote_and_device_files_refused_without_opening(path, handoff_api):
    with patch.object(handoff_api.os, "open", side_effect=AssertionError("opened refused path")):
        with pytest.raises(ValueError):
            handoff_api.handoff_preview(handoff_document(), [path])


def test_source_and_total_caps_are_enforced(tmp_path, handoff_api):
    source = tmp_path / "source"
    source.write_bytes(b"12345")
    with patch.object(handoff_api, "_HANDOFF_FILE_LIMIT", 4):
        with pytest.raises(ValueError, match="limit"):
            handoff_api.handoff_write(handoff_document(), tmp_path / "too-large.zip", [source])
    with patch.object(handoff_api, "_HANDOFF_TOTAL_LIMIT", 4):
        with pytest.raises(ValueError, match="limit"):
            handoff_api.handoff_preview(handoff_document(), [source])
    with patch.object(handoff_api, "_HANDOFF_REPORT_LIMIT", 4):
        with pytest.raises(ValueError, match="metadata limit"):
            handoff_api.handoff_write(handoff_document(), tmp_path / "too-large.zip")
    assert not (tmp_path / "too-large.zip").exists()


def test_changed_source_never_publishes_partial_zip(tmp_path, handoff_api):
    source = tmp_path / "source"
    source.write_bytes(b"before")
    original_open = handoff_api._handoff_source
    @contextlib.contextmanager
    def mutate(path, expected):
        with original_open(path, expected) as fh:
            source.write_bytes(b"changed contents")
            yield fh
    with patch.object(handoff_api, "_handoff_source", mutate):
        with pytest.raises(ValueError, match="grew|changed"):
            handoff_api.handoff_write(handoff_document(), tmp_path / "partial.zip", [source])
    assert not (tmp_path / "partial.zip").exists()
    assert not list(tmp_path.glob(".zbt_handoff_*"))


def test_publish_race_preserves_existing_destination(tmp_path, handoff_api):
    destination = tmp_path / "new.zip"
    publish = handoff_api._handoff_publish
    def race(pending, output):
        destination.write_bytes(b"RACING FILE")
        publish(pending, output)
    with patch.object(handoff_api, "_handoff_publish", race):
        with pytest.raises(OSError):
            handoff_api.handoff_write(handoff_document(), destination)
    assert destination.read_bytes() == b"RACING FILE"
    assert not list(tmp_path.glob(".zbt_handoff_*"))


def test_interruption_cleans_unpublished_archive(tmp_path, handoff_api):
    with patch.object(handoff_api, "_handoff_publish", side_effect=KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            handoff_api.handoff_write(handoff_document(), tmp_path / "interrupted.zip")
    assert not (tmp_path / "interrupted.zip").exists()
    assert not list(tmp_path.glob(".zbt_handoff_*"))
