"""Windows execution readers: authored format bytes, never real artifacts."""
import ctypes
import os
from pathlib import Path
import struct
import sys

import pytest

from zbtriage import winrecords
from zbtriage.modules import execution
from zbtriage.context import ScanContext
from zbtriage.iocs import Indicator, IocSet
from test_followup_fixes import bundle


_WE_NAME = "fixture-spy.exe"
_WE_PATH = "C:\\Fixture\\" + _WE_NAME


def _we_context(path):
    indicators = [Indicator(value, "artifact", "primary", kind, "synthetic") for kind, value in (
        ("file-name", _WE_NAME), ("file-path", _WE_PATH.lower()),
        ("file-name", "fixture.dll"), ("domain", "fixture.invalid"),
        ("process-name", "phone-only.exe"))]
    return ScanContext(IocSet(indicators, "fixture", None), targets=(str(path),), verbose=False)


def _we_prefetch(version=30, variant=2, name=_WE_NAME, paths=None, runs=3):
    paths = paths if paths is not None else [_WE_PATH, r"C:\Fixture\fixture.dll"]
    metrics = {17: 152, 23: 240, 26: 304, 30: 296 if variant == 2 else 304, 31: 296}[version]
    width = 20 if version == 17 else 32
    raw = bytearray(metrics + len(paths) * width)
    struct.pack_into("<I4sII", raw, 0, version, b"SCCA", 17, 0)
    encoded = name.encode("utf-16-le")[:58] + b"\0\0"
    raw[16:16 + len(encoded)] = encoded
    strings = b""
    for index, path in enumerate(paths):
        pos = metrics + index * width + (8 if version == 17 else 12)
        data = path.encode("utf-16-le")
        struct.pack_into("<II", raw, pos, len(strings), len(data) // 2)
        strings += data + b"\0\0"
    strings_at = len(raw)
    struct.pack_into("<IIIIIIIII", raw, 84, metrics, len(paths), strings_at, 0,
                     strings_at, len(strings), strings_at + len(strings), 0, 0)
    timestamp = 133500000000000000
    struct.pack_into("<Q", raw, 120 if version == 17 else 128, timestamp)
    run_at = {17: 144, 23: 152, 26: 208}.get(version, 200 if metrics == 296 else 208)
    struct.pack_into("<I", raw, run_at, runs)
    raw += strings
    struct.pack_into("<I", raw, 12, len(raw))
    return bytes(raw)


class _WeHiveFixture:
    def __init__(self):
        self.cells = []
        self.cursor = 32

    def cell(self, data, allocated=True):
        size = (len(data) + 4 + 7) // 8 * 8
        offset = self.cursor
        self.cells.append([offset, bytearray(data), size, allocated])
        self.cursor += size
        return offset

    def key(self, name, parent=0xffffffff):
        data = bytearray(76)
        data[:2] = b"nk"
        struct.pack_into("<H", data, 2, 32)
        struct.pack_into("<I", data, 16, parent)
        struct.pack_into("<H", data, 72, len(name))
        return self.cell(data + name.encode("ascii"))

    def data(self, offset):
        return next(item[1] for item in self.cells if item[0] == offset)

    def children(self, parent, children, kind=b"li"):
        data = (b"li" if kind == b"ri" else kind) + struct.pack("<H", len(children))
        for child in children:
            data += struct.pack("<I", child) + (b"\0" * 4 if kind in (b"lh", b"lf") else b"")
        off = self.cell(data)
        if kind == b"ri":
            off = self.cell(b"ri\x01\0" + struct.pack("<I", off))
        struct.pack_into("<I", self.data(parent), 20, len(children))
        struct.pack_into("<I", self.data(parent), 28, off)
        return off

    def values(self, key, pairs):
        offsets = []
        for name, text in pairs:
            data = text.encode("utf-16-le") + b"\0\0"
            pointer = self.cell(data)
            offsets.append(self.cell(b"vk" + struct.pack("<HIIIHH", len(name), len(data), pointer, 1, 1, 0) + name.encode("ascii")))
        pointer = self.cell(b"".join(struct.pack("<I", off) for off in offsets))
        struct.pack_into("<II", self.data(key), 36, len(pairs), pointer)
        return offsets

    def finish(self, root):
        size = (self.cursor + 4095) // 4096 * 4096
        body = bytearray(size)
        body[:4] = b"hbin"
        struct.pack_into("<II", body, 4, 0, size)
        for offset, data, length, allocated in self.cells:
            struct.pack_into("<i", body, offset, -length if allocated else length)
            body[offset + 4:offset + 4 + len(data)] = data
        if self.cursor < size:
            struct.pack_into("<i", body, self.cursor, size - self.cursor)
        header = bytearray(4096)
        struct.pack_into("<4sII", header, 0, b"regf", 1, 1)
        struct.pack_into("<IIIIIII", header, 20, 1, 5, 0, 1, root, size, 1)
        checksum = 0
        for off in range(0, 508, 4):
            checksum ^= int.from_bytes(header[off:off + 4], "little")
        checksum = 1 if checksum == 0 else (0xfffffffe if checksum == 0xffffffff else checksum)
        struct.pack_into("<I", header, 508, checksum)
        return bytes(header + body)


def _we_amcache(legacy=False, bad_first=False, kind=b"li"):
    fixture = _WeHiveFixture()
    root = fixture.key("Root")
    branch = fixture.key("File" if legacy else "InventoryApplicationFile", root)
    fixture.children(root, [branch])
    parent = branch
    if legacy:
        parent = fixture.key("volume", branch)
        fixture.children(branch, [parent])
    children = []
    if bad_first:
        bad = fixture.key("bad", parent)
        values = fixture.values(bad, [("15" if legacy else "LowerCaseLongPath", "bad")])
        struct.pack_into("<I", fixture.data(values[0]), 8, 0x7fffffff)
        children.append(bad)
    child = fixture.key("good", parent)
    fixture.values(child, [("15", _WE_PATH)] if legacy else [("LowerCaseLongPath", _WE_PATH), ("Name", _WE_NAME)])
    children.append(child)
    fixture.children(parent, children, kind)
    fixture.cell(("https://fixture.invalid " + _WE_NAME).encode("utf-16-le"), allocated=False)
    return fixture.finish(root)


@pytest.mark.parametrize("version,variant", [(17, 1), (23, 1), (26, 1), (30, 1), (30, 2), (31, 2)])
def test_prefetch_real_layout_versions_keep_dlls_separate(bundle, version, variant):
    raw = _we_prefetch(version, variant)
    for api in (winrecords, bundle):
        row = api.read_prefetch(raw)
        assert row["name"] == _WE_NAME and row["runs"] == 3 and row["times"]
        assert row["references"] == [_WE_PATH, r"C:\Fixture\fixture.dll"]


@pytest.mark.parametrize("mutation", ["version", "size", "name", "overlap", "metric-offset", "metric-size", "time", "count"])
def test_malformed_prefetch_cannot_invent_execution(bundle, mutation):
    raw = bytearray(_we_prefetch())
    if mutation == "version":
        struct.pack_into("<I", raw, 0, 99)
    elif mutation == "size":
        struct.pack_into("<I", raw, 12, len(raw) + 1)
    elif mutation == "name":
        raw[16:76] = b"A\0" * 30
    elif mutation == "overlap":
        struct.pack_into("<I", raw, 100, 296)
    elif mutation == "metric-offset":
        struct.pack_into("<I", raw, 296 + 12, 0xffffffff)
    elif mutation == "metric-size":
        struct.pack_into("<I", raw, 296 + 16, 0xffffffff)
    elif mutation == "time":
        struct.pack_into("<Q", raw, 128, 0xffffffffffffffff)
    else:
        struct.pack_into("<I", raw, 88, 100001)
    for api in (winrecords, bundle):
        with pytest.raises(ValueError):
            api.read_prefetch(bytes(raw))


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("kind", [b"li", b"lf", b"lh", b"ri"])
def test_amcache_allocated_structured_records_only(bundle, legacy, kind):
    raw = _we_amcache(legacy=legacy, kind=kind)
    for api in (winrecords, bundle):
        rows = list(api.read_amcache(raw))
        assert len(rows) == 1 and rows[0]["path"] == _WE_PATH and not rows[0]["error"]
        assert "fixture.invalid" not in str(rows)


@pytest.mark.parametrize("legacy", [False, True])
def test_amcache_bad_record_preserves_readable_later_record(bundle, legacy):
    for api in (winrecords, bundle):
        rows = list(api.read_amcache(_we_amcache(legacy, bad_first=True)))
        assert len(rows) == 2 and rows[0]["error"] and rows[1]["path"] == _WE_PATH


@pytest.mark.parametrize("mutation", ["dirty", "checksum", "cell-size", "free-root", "bin-size", "root-offset"])
def test_malformed_amcache_is_a_gap(bundle, mutation):
    raw = bytearray(_we_amcache())
    if mutation == "dirty":
        struct.pack_into("<I", raw, 8, 2)
    elif mutation == "checksum":
        raw[508] ^= 1
    elif mutation == "cell-size":
        struct.pack_into("<i", raw, 4096 + 32, -7)
    elif mutation == "free-root":
        size = abs(struct.unpack_from("<i", raw, 4096 + 32)[0])
        struct.pack_into("<i", raw, 4096 + 32, size)
    elif mutation == "bin-size":
        struct.pack_into("<I", raw, 4096 + 8, 4095)
    else:
        struct.pack_into("<I", raw, 36, 33)
    for api in (winrecords, bundle):
        with pytest.raises(ValueError):
            list(api.read_amcache(bytes(raw)))


def test_explicit_scope_grades_names_and_inventory_without_target_access(tmp_path, monkeypatch, bundle):
    pf, hive = tmp_path / "FIXTURE.pf", tmp_path / "Amcache.hve"
    pf.write_bytes(_we_prefetch())
    hive.write_bytes(_we_amcache())
    import builtins
    original = builtins.open
    def guarded(path, *args, **kwargs):
        assert Path(path) in (pf, hive), "referenced executable/DLL/default root must not be opened"
        assert not args or args[0] == "rb"
        return original(path, *args, **kwargs)
    monkeypatch.setattr(builtins, "open", guarded)
    for run in (execution.run, bundle.run_execution):
        result = run(_we_context(tmp_path))
        grades = {(hit.indicator, hit.evidence) for hit in result.hits}
        assert (_WE_NAME, "execution-record") in grades
        assert (_WE_NAME, "inventory-record") in grades
        assert (_WE_PATH.lower(), "inventory-record") in grades
        assert ("fixture.dll", "referenced") in grades
        assert all(hit.artifact in (str(pf), str(hive)) for hit in result.hits)
        assert all(check.ran for check in result.checks)


@pytest.mark.parametrize("name,runs", [("phone-only.exe", 2), (_WE_NAME, 0), ("a" * 29, 2)])
def test_prefetch_uncertain_or_phone_only_identity_never_promoted(tmp_path, bundle, name, runs):
    path = tmp_path / "test.pf"
    path.write_bytes(_we_prefetch(name=name, runs=runs, paths=[]))
    for run in (execution.run, bundle.run_execution):
        result = run(_we_context(path))
        assert not any(hit.evidence == "execution-record" for hit in result.hits)
        if runs == 0 or len(name) == 29:
            assert any(not check.ran and "Prefetch executable name" in check.reason for check in result.checks)


@pytest.mark.parametrize("raw", [b"MAM\x84" + b"\0" * 20, b"MAM\x04" + struct.pack("<I", 17000000) + b"x"])
def test_prefetch_compression_variant_and_bomb_bound(bundle, raw):
    for api in (winrecords, bundle):
        with pytest.raises(ValueError):
            api.read_prefetch(raw)


def _we_repeated_metrics(count, distinct=False):
    initial = _we_prefetch(paths=["X" * 32767])
    strings = initial[328:]
    raw = bytearray(initial[:296])
    for i in range(count):
        entry = bytearray(initial[296:328])
        if distinct:
            struct.pack_into("<II", entry, 12, i * 2, 32767 - i)
        raw += entry
    start = len(raw)
    raw += strings
    struct.pack_into("<I", raw, 12, len(raw))
    struct.pack_into("<IIIIIIIII", raw, 84, 296, count, start, 0, start, len(strings), len(raw), 0, 0)
    return bytes(raw)


def test_prefetch_duplicate_metrics_cannot_amplify_decoded_memory(bundle):
    raw = _we_repeated_metrics(100000)
    for api in (winrecords, bundle):
        assert api.read_prefetch(raw)["references"] == ["X" * 32767]


def test_prefetch_overlapping_suffix_metrics_have_aggregate_text_bound(bundle):
    raw = _we_repeated_metrics(256, distinct=True)
    for api in (winrecords, bundle):
        with pytest.raises(ValueError, match="budget"):
            api.read_prefetch(raw)


def test_amcache_subkey_cycle_is_rejected(bundle):
    fixture = _WeHiveFixture()
    root = fixture.key("Root")
    branch = fixture.key("InventoryApplicationFile", root)
    pointer = fixture.children(root, [branch], b"ri")
    struct.pack_into("<I", fixture.data(pointer), 4, pointer)
    for api in (winrecords, bundle):
        with pytest.raises(ValueError, match="cyclic"):
            list(api.read_amcache(fixture.finish(root)))


def test_amcache_partial_rows_retain_inventory_and_report_gap(tmp_path, bundle):
    path = tmp_path / "Amcache.hve"
    path.write_bytes(_we_amcache(bad_first=True))
    for run in (execution.run, bundle.run_execution):
        result = run(_we_context(path))
        assert any(hit.evidence == "inventory-record" for hit in result.hits)
        assert any(not check.ran and "unsupported Amcache" in check.reason for check in result.checks)


def test_prefetch_native_error_is_a_gap(tmp_path, bundle):
    path = tmp_path / "test.pf"
    path.write_bytes(b"MAM\x04" + struct.pack("<I", 300) + b"not a compression stream")
    for run in (execution.run, bundle.run_execution):
        result = run(_we_context(path))
        assert not result.hits and any(not check.ran and "Prefetch" in check.reason for check in result.checks)


def test_discovery_bound_is_explicit(tmp_path, monkeypatch, bundle):
    for i in range(3):
        (tmp_path / (str(i) + ".pf")).write_bytes(_we_prefetch())
    for api, run in ((execution, execution.run), (bundle, bundle.run_execution)):
        monkeypatch.setattr(api, "_WX_ENTRY_CAP", 1)
        result = run(_we_context(tmp_path))
        assert any(not check.ran and "discovery exceeded" in check.reason for check in result.checks)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native compression API")
def test_native_xpress_huffman_roundtrip_only_synthetic_bytes(bundle):
    raw = _we_prefetch()
    library = ctypes.WinDLL("ntdll.dll", winmode=0x00000800)
    size = library.RtlGetCompressionWorkSpaceSize
    size.argtypes = [ctypes.c_ushort, ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong)]
    size.restype = ctypes.c_long
    a, b = ctypes.c_ulong(), ctypes.c_ulong()
    assert size(4, ctypes.byref(a), ctypes.byref(b)) == 0 and 0 < a.value < 16 * 1024 * 1024
    workspace = ctypes.create_string_buffer(a.value)
    compress = library.RtlCompressBuffer
    compress.argtypes = [ctypes.c_ushort, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p,
                         ctypes.c_ulong, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p]
    compress.restype = ctypes.c_long
    source, output = ctypes.create_string_buffer(raw), ctypes.create_string_buffer(len(raw) + 65536)
    actual = ctypes.c_ulong()
    assert compress(4, source, len(raw), output, len(output), 4096, ctypes.byref(actual), workspace) == 0
    packed = b"MAM\x04" + struct.pack("<I", len(raw)) + output.raw[:actual.value]
    for api in (winrecords, bundle):
        assert api.read_prefetch(packed) == api.read_prefetch(raw)


def test_empty_target_scope_reports_inapplicability(tmp_path, bundle):
    for run in (execution.run, bundle.run_execution):
        result = run(_we_context(tmp_path))
        assert not result.checks
        assert any("no applicable artifact" in note for note in result.notes)


def test_unrelated_selected_file_is_inapplicable(tmp_path, bundle):
    path = tmp_path / "other.bin"
    path.write_bytes(_we_prefetch())
    for run in (execution.run, bundle.run_execution):
        result = run(_we_context(path))
        assert not result.hits and all(check.ran for check in result.checks)
