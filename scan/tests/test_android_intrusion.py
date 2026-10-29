"""Synthetic documented Android intrusion exports; never device acquisition."""
import io
import json
import os
import struct
import zipfile

import pytest

from zbtriage.context import ScanContext
from zbtriage.iocs import Indicator, IocSet
from zbtriage.modules import intrusion
from test_followup_fixes import bundle


@pytest.fixture(params=["source", "bundle"])
def il_api(request):
    return intrusion if request.param == "source" else request.getfixturevalue("bundle")


def il_context(root):
    values = [("fixture.invalid", "domain"), ("sub.fixture.invalid", "domain"),
              ("203.0.113.8", "ip"), ("2001:db8::8", "ip"),
              ("com.fixture.spy", "app-id"), ("spyproc", "process"), ("a" * 64, "sha256")]
    return ScanContext(IocSet([Indicator(v, "fixture", "primary", t, "synthetic")
                               for v, t in values], "fixture", None), phone_path=str(root))


def il_scan(api, root):
    return (api.run if api is intrusion else api.run_intrusion)(il_context(root))


def il_dns(host="fixture.invalid", **extra):
    return {"dns_event": dict(event_time=1746979200000, hostname=host,
                               ip_addresses=["203.0.113.8"], package_name="com.safe.app", **extra)}


def il_connect(address="203.0.113.8"):
    return {"connect_event": {"event_time": 1746979201000, "ip_address": address,
                               "port": 443, "package_name": "com.safe.app"}}


def il_process(name="com.fixture.spy:worker"):
    return {"security_event": {"event_time": 1746979202000, "tag": 210005,
                                "data": [name, 1746979200001, 10001, 77, "default", "a" * 64]}}


def il_write(root, records, name="events.txt"):
    folder = root / "intrusion_logs"
    folder.mkdir(exist_ok=True)
    path = folder / name
    path.write_bytes(b"\n".join(json.dumps(r).encode() if isinstance(r, dict) else r for r in records) + b"\n")
    return path


def il_zip(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return stream.getvalue()


def test_documented_event_types_preserve_evidence_distinctions(tmp_path, il_api):
    path = il_write(tmp_path, [il_dns("sub.fixture.invalid"), il_connect("2001:db8::8"), il_process()])
    result = il_scan(il_api, tmp_path)
    assert result.checked == 3 and not result.skipped
    evidence = {(h.indicator, h.evidence) for h in result.hits}
    assert evidence == {("sub.fixture.invalid", "dns-record"), ("203.0.113.8", "dns-record"),
                        ("2001:db8::8", "device-log"), ("com.fixture.spy", "device-log"),
                        ("a" * 64, "device-log")}
    assert all(h.artifact == str(path) and h.observed.endswith("+00:00") for h in result.hits)
    assert any("successful contact is unverified" in h.detail for h in result.hits)


@pytest.mark.parametrize("bad", [b'{bad json', b'\xff', b'[]',
    b'{"dns_event":{},"connect_event":{}}',
    b'{"dns_event":{"hostname":"fixture.invalid","hostname":"safe.invalid"}}',
    b'{"dns_event":{"event_time":NaN}}'])
def test_bad_row_preserves_neighbours(tmp_path, il_api, bad):
    il_write(tmp_path, [il_dns(), bad, il_connect()])
    result = il_scan(il_api, tmp_path)
    assert result.checked == 2 and result.skipped == 1
    assert {h.evidence for h in result.hits} == {"dns-record", "device-log"}
    assert any(not check.ran for check in result.checks)


def test_untrusted_message_fields_cannot_invent_contact(tmp_path, il_api):
    dns = il_dns("safe.invalid", message="fixture.invalid")
    dns["dns_event"]["ip_addresses"] = ["192.0.2.1"]
    con = il_connect("192.0.2.1")
    con["connect_event"]["message"] = "fixture.invalid 203.0.113.8"
    process = il_process("com.safe.app")
    process["security_event"]["data"][4:] = ["fixture.invalid", ""]
    il_write(tmp_path, [dns, con, process, {"security_event": {
        "event_time": 1746979202000, "tag": 210002, "data": "203.0.113.8 fixture.invalid"}}])
    result = il_scan(il_api, tmp_path)
    assert not result.hits and result.checked == 3 and result.skipped == 1
    assert any(c.name == "android-intrusion:security-events" and not c.ran for c in result.checks)


@pytest.mark.parametrize("mutation", ["url-host", "bad-address", "bad-port", "boolean-tag", "short-process", "bad-time"])
def test_invalid_typed_fields_never_become_findings(tmp_path, il_api, mutation):
    record = il_dns()
    if mutation == "url-host":
        record["dns_event"]["hostname"] = "https://fixture.invalid"
    elif mutation == "bad-address":
        record["dns_event"]["ip_addresses"] = ["203.0.113.8 injected"]
    elif mutation == "bad-time":
        record["dns_event"]["event_time"] = True
    elif mutation == "bad-port":
        record = il_connect()
        record["connect_event"]["port"] = "443"
    else:
        record = il_process()
        if mutation == "boolean-tag":
            record["security_event"]["tag"] = True
        else:
            record["security_event"]["data"] = ["com.fixture.spy"]
    il_write(tmp_path, [record])
    result = il_scan(il_api, tmp_path)
    assert not result.hits and result.skipped == 1 and result.checked == 0


def test_nested_zip_deduplicates_without_extracting(tmp_path, il_api):
    data = (json.dumps(il_dns()) + "\n").encode()
    nested = il_zip([("events.txt", data)])
    path = il_write(tmp_path, [], "placeholder.txt")
    path.unlink()
    outer = path.with_name("export.zip")
    outer.write_bytes(il_zip([("device/day.zip", nested), ("duplicate.txt", data)]))
    before = sorted(str(p) for p in tmp_path.rglob("*"))
    result = il_scan(il_api, tmp_path)
    assert result.checked == 1 and result.submetrics["intrusion_duplicate_events"] == 1
    assert all(h.artifact == str(outer) for h in result.hits)
    assert before == sorted(str(p) for p in tmp_path.rglob("*"))


def test_zip_unsafe_member_and_encryption_keep_safe_neighbour(tmp_path, il_api):
    data = (json.dumps(il_connect()) + "\n").encode()
    folder = tmp_path / "intrusion_logs"
    folder.mkdir()
    (folder / "events.zip").write_bytes(il_zip([("../outside.txt", data), ("good.txt", data)]))
    (folder / "encrypted.age").write_bytes(b"age-encryption.org/v1\n")
    result = il_scan(il_api, tmp_path)
    assert result.checked == 1 and result.skipped == 2
    assert not (tmp_path / "outside.txt").exists()


def test_empty_or_missing_logs_do_not_invent_event_coverage(tmp_path, il_api):
    result = il_scan(il_api, tmp_path)
    assert not result.checks and not result.hits and result.status == "NOT_APPLICABLE"
    assert result.inapplicable_reason
    (tmp_path / "intrusion_logs").mkdir()
    result = il_scan(il_api, tmp_path)
    assert result.checked == 0 and any(not c.ran for c in result.checks)


def test_oversized_line_and_grouped_malformed_records(tmp_path, il_api):
    il_write(tmp_path, [b"x" * (128 * 1024 + 20)] + [b"bad"] * 100 + [il_dns()])
    result = il_scan(il_api, tmp_path)
    assert result.checked == 1 and result.skipped == 101
    assert len([c for c in result.checks if not c.ran]) == 2


def test_input_refused_before_open(tmp_path, il_api, monkeypatch):
    path = il_write(tmp_path, [il_dns()])
    original = il_api.path_problem
    monkeypatch.setattr(il_api, "path_problem", lambda p: "refused" if str(p) == str(path) else original(p))
    import builtins
    original_open = builtins.open
    def guarded(name, *args, **kwargs):
        assert str(name) != str(path)
        return original_open(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "open", guarded)
    result = il_scan(il_api, tmp_path)
    assert not result.hits and result.skipped == 1


def test_zip_index_allocation_guard_and_limits(tmp_path, il_api, monkeypatch):
    raw = bytearray(il_zip([]))
    struct.pack_into("<HH", raw, 8, 5000, 5000)
    with pytest.raises(ValueError):
        il_api._il_zip_guard(bytes(raw))
    il_write(tmp_path, [il_dns(), il_connect()])
    monkeypatch.setattr(il_api, "_IL_EVENT_LIMIT", 1)
    result = il_scan(il_api, tmp_path)
    assert result.checked == 1 and result.hits and any(not c.ran for c in result.checks)


def test_unbounded_zip_codec_rejected_before_decoder(tmp_path, il_api, monkeypatch):
    raw = bytearray(il_zip([("events.txt", b"{}\n")]))
    # Advertise LZMA without constructing or invoking an LZMA decoder.
    struct.pack_into("<H", raw, 8, zipfile.ZIP_LZMA)
    central = raw.index(b"PK\x01\x02")
    struct.pack_into("<H", raw, central + 10, zipfile.ZIP_LZMA)
    folder = tmp_path / "intrusion_logs"
    folder.mkdir()
    (folder / "events.zip").write_bytes(raw)
    monkeypatch.setattr(il_api.zipfile.ZipFile, "open", lambda *a, **kw: pytest.fail("unsupported codec invoked"))
    result = il_scan(il_api, tmp_path)
    assert result.skipped == 1 and not result.hits


@pytest.mark.parametrize("name", ["gatekeeperd", "spyproc"])
def test_ios_process_names_do_not_become_android_findings(tmp_path, il_api, name):
    record = il_process(name)
    record["security_event"]["data"][5] = ""
    il_write(tmp_path, [record, il_process()])
    ctx = il_context(tmp_path)
    ctx.iocs = IocSet(ctx.iocs.indicators + [Indicator("gatekeeperd", "artifact", "primary", "process", "iOS fixture")], "fixture", None)
    result = (il_api.run if il_api is intrusion else il_api.run_intrusion)(ctx)
    assert result.checked == 2 and not result.skipped
    assert {(h.indicator, h.kind) for h in result.hits} == {
        ("com.fixture.spy", "app-id"), ("a" * 64, "sha256")}
