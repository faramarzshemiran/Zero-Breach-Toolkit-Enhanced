"""Bounded read-only Prefetch and Amcache format readers.

Independent implementations from format documentation, not third-party code:
https://github.com/libyal/libscca/tree/main/documentation
https://github.com/libyal/libregf/tree/main/documentation
https://www.ssi.gouv.fr/uploads/2019/01/anssi-coriin_2019-analysis_amcache.pdf
No registry mounting, transaction replay, path resolution or referenced-file access.
"""
import datetime
import os
import struct
import sys
import time


_WR_PF_LIMIT = 16 * 1024 * 1024
_WR_HIVE_LIMIT = 64 * 1024 * 1024
_WR_ROW_LIMIT = 100000


def _wr_number(data, offset, width=4, signed=False):
    if offset < 0 or offset + width > len(data):
        raise ValueError("truncated binary field")
    return int.from_bytes(data[offset:offset + width], "little", signed=signed)


def _wr_text(data, ascii_name=False):
    text = bytes(data).decode("ascii" if ascii_name else "utf-16-le")
    if any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise ValueError("control character in record string")
    return text


def _wr_filetime(value):
    if not value:
        return ""
    try:
        return (datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
                + datetime.timedelta(microseconds=value // 10)).isoformat()
    except (OverflowError, ValueError):
        raise ValueError("invalid FILETIME") from None


def _wr_expand_prefetch(raw):
    if len(raw) > _WR_PF_LIMIT:
        raise ValueError("Prefetch input exceeds 16 MiB")
    if not raw.startswith(b"MAM"):
        return raw
    if raw[:4] != b"MAM\x04":
        raise ValueError("unsupported Prefetch compression/checksum variant")
    length = _wr_number(raw, 4)
    if not 152 <= length <= _WR_PF_LIMIT or len(raw) <= 8:
        raise ValueError("invalid Prefetch decompressed length")
    if sys.platform != "win32":
        raise ValueError("compressed Prefetch requires Windows system decompressor")
    # LOAD_LIBRARY_SEARCH_SYSTEM32 avoids CWD/PATH or environment-selected DLLs.
    import ctypes
    library = ctypes.WinDLL("ntdll.dll", winmode=0x00000800)
    workspace_size = library.RtlGetCompressionWorkSpaceSize
    workspace_size.argtypes = [ctypes.c_ushort, ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong)]
    workspace_size.restype = ctypes.c_long
    inflate = library.RtlDecompressBufferEx
    inflate.argtypes = [ctypes.c_ushort, ctypes.c_void_p, ctypes.c_ulong,
                       ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p]
    inflate.restype = ctypes.c_long
    compression, decompression = ctypes.c_ulong(), ctypes.c_ulong()
    if workspace_size(4, ctypes.byref(compression), ctypes.byref(decompression)) != 0:
        raise ValueError("Windows decompression workspace unavailable")
    space_size = max(compression.value, decompression.value)
    if not 0 < space_size <= _WR_PF_LIMIT:
        raise ValueError("Windows decompression workspace exceeds bound")
    workspace = ctypes.create_string_buffer(space_size)
    output, source = ctypes.create_string_buffer(length), ctypes.create_string_buffer(raw[8:])
    actual = ctypes.c_ulong()
    status = inflate(4, output, length, source, len(raw) - 8, ctypes.byref(actual), workspace)
    if status != 0 or actual.value != length:
        raise ValueError("invalid compressed Prefetch stream")
    return output.raw


def read_prefetch(raw):
    """Return executable basename, metric filenames, recorded times/count.

    A metric filename is not necessarily the launched executable, even when
    its basename equals the header. Never infer a full execution path from it.
    """
    data = _wr_expand_prefetch(raw)
    version = _wr_number(data, 0)
    if len(data) < 152 or data[4:8] != b"SCCA" or _wr_number(data, 12) != len(data):
        raise ValueError("invalid Prefetch header/size")
    metrics = _wr_number(data, 84)
    sizes = {17: (152,), 23: (240,), 26: (304,), 30: (296, 304), 31: (296,)}
    if metrics not in sizes.get(version, ()):
        raise ValueError("unsupported Prefetch version/layout")
    name_bytes = data[16:76]
    end = next((i for i in range(0, 60, 2) if name_bytes[i:i + 2] == b"\0\0"), None)
    if end is None:
        raise ValueError("unterminated Prefetch executable name")
    name = _wr_text(name_bytes[:end])
    if not name or any(c in name for c in "\\/:"):
        raise ValueError("invalid Prefetch executable basename")
    if _wr_number(data, 80) != 0:
        raise ValueError("boot or unsupported Prefetch header flags")
    count, chains, chain_count, strings, string_size, volumes, volume_count, volume_size = (
        _wr_number(data, i) for i in range(88, 120, 4))
    if count > _WR_ROW_LIMIT or chain_count > _WR_ROW_LIMIT or volume_count > 4096:
        raise ValueError("Prefetch record count exceeds bound")
    metric_size = 20 if version == 17 else 32
    regions = [(0, metrics)]
    for offset, size in ((metrics, count * metric_size),
                         (chains, chain_count * (8 if version >= 30 else 12)),
                         (strings, string_size), (volumes, volume_size)):
        if size:
            if offset < metrics or offset + size > len(data):
                raise ValueError("Prefetch section outside file")
            regions.append((offset, offset + size))
    ordered = sorted(regions)
    if any(a[1] > b[0] for a, b in zip(ordered, ordered[1:])):
        raise ValueError("overlapping Prefetch sections")
    if string_size % 2:
        raise ValueError("odd Prefetch string section length")
    references, seen, decoded = [], set(), 0
    deadline = time.monotonic() + 10
    for index in range(count):
        if time.monotonic() > deadline:
            raise ValueError("Prefetch parsing time limit reached")
        entry = metrics + index * metric_size
        off = entry + (8 if version == 17 else 12)
        position, chars = _wr_number(data, off), _wr_number(data, off + 4)
        if position % 2 or not 0 < chars <= 32767 or position + chars * 2 + 2 > string_size:
            raise ValueError("invalid Prefetch metric filename extent")
        start = strings + position
        if data[start + chars * 2:start + chars * 2 + 2] != b"\0\0":
            raise ValueError("unterminated Prefetch metric filename")
        if (position, chars) in seen:
            continue
        seen.add((position, chars))
        decoded += chars * 2
        if decoded > 8 * 1024 * 1024:
            raise ValueError("Prefetch decoded filename budget exceeds 8 MiB")
        references.append(_wr_text(data[start:start + chars * 2]))
    time_offset = 120 if version == 17 else 128
    timestamps = [_wr_filetime(_wr_number(data, time_offset + i * 8, 8))
                  for i in range(1 if version in (17, 23) else 8)]
    run_offset = {17: 144, 23: 152, 26: 208}.get(version, 200 if metrics == 296 else 208)
    runs = _wr_number(data, run_offset)
    return {"name": name, "references": references, "times": [t for t in timestamps if t],
            "runs": runs, "version": version, "truncated_name": end >= 58}


class _WrHive:
    """Allocated-cell-only reader; never carves slack/deleted records."""

    def __init__(self, raw):
        self.raw, self.cells, self.decoded = raw, {}, 0
        self.deadline = time.monotonic() + 10
        if not 8192 <= len(raw) <= _WR_HIVE_LIMIT or raw[:4] != b"regf":
            raise ValueError("unsupported Amcache hive header/size")
        if (_wr_number(raw, 20) != 1 or _wr_number(raw, 24) not in (3, 5)
                or _wr_number(raw, 28) != 0 or _wr_number(raw, 32) != 1):
            raise ValueError("unsupported registry hive version/type")
        if _wr_number(raw, 4) != _wr_number(raw, 8):
            raise ValueError("dirty Amcache hive requires unsupported transaction-log replay")
        checksum = 0
        for offset in range(0, 508, 4):
            checksum ^= _wr_number(raw, offset)
        checksum = 0xfffffffe if checksum == 0xffffffff else (1 if checksum == 0 else checksum)
        if checksum != _wr_number(raw, 508):
            raise ValueError("invalid registry hive header checksum")
        extent = _wr_number(raw, 40)
        if extent % 4096 or extent < 4096 or 4096 + extent > len(raw):
            raise ValueError("invalid registry hive bins extent")
        position = 4096
        while position < 4096 + extent:
            self.tick()
            size = _wr_number(raw, position + 8)
            if (raw[position:position + 4] != b"hbin" or _wr_number(raw, position + 4) != position - 4096
                    or size < 4096 or size % 4096 or position + size > 4096 + extent):
                raise ValueError("invalid registry hive bin")
            cursor = position + 32
            while cursor < position + size:
                if len(self.cells) % 1024 == 0:
                    self.tick()
                cell_size = _wr_number(raw, cursor, signed=True)
                length = abs(cell_size)
                if length < 8 or length % 8 or cursor + length > position + size:
                    raise ValueError("invalid registry cell extent")
                if cell_size < 0:
                    self.cells[cursor - 4096] = (cursor + 4, cursor + length)
                    if len(self.cells) > 500000:
                        raise ValueError("registry cell count exceeds bound")
                cursor += length
            position += size
        self.root = _wr_number(raw, 36)

    def tick(self):
        if time.monotonic() > self.deadline:
            raise ValueError("Amcache parsing time limit reached")

    def cell(self, offset):
        self.tick()
        if offset not in self.cells:
            raise ValueError("registry pointer does not name an allocated cell")
        start, end = self.cells[offset]
        return memoryview(self.raw)[start:end]

    def key(self, offset):
        data = self.cell(offset)
        if bytes(data[:2]) != b"nk" or len(data) < 76:
            raise ValueError("invalid registry key cell")
        flags, length = _wr_number(data, 2, 2), _wr_number(data, 72, 2)
        if flags & 0x13 or length > 510 or 76 + length > len(data):
            raise ValueError("unsupported registry key flags/name")
        name = _wr_text(data[76:76 + length], bool(flags & 32))
        if not name or "\\" in name or "/" in name:
            raise ValueError("invalid registry key name")
        return name, data

    def children(self, offset):
        _, key = self.key(offset)
        expected = _wr_number(key, 20)
        if expected > _WR_ROW_LIMIT or _wr_number(key, 24):
            raise ValueError("unsupported registry subkey count")
        if not expected:
            return []
        pending, seen, result = [_wr_number(key, 28)], set(), []
        while pending:
            cursor = pending.pop()
            if cursor in seen or len(seen) >= _WR_ROW_LIMIT:
                raise ValueError("cyclic/oversized registry subkey list")
            seen.add(cursor)
            data = self.cell(cursor)
            kind, count = bytes(data[:2]), _wr_number(data, 2, 2)
            if kind not in (b"li", b"lf", b"lh", b"ri"):
                raise ValueError("unsupported registry subkey list")
            width = 8 if kind in (b"lf", b"lh") else 4
            if 4 + count * width > len(data):
                raise ValueError("truncated registry subkey list")
            entries = [_wr_number(data, 4 + i * width) for i in range(count)]
            (pending if kind == b"ri" else result).extend(entries)
            if len(pending) + len(result) > _WR_ROW_LIMIT:
                raise ValueError("registry subkey count exceeds bound")
        if len(result) != expected or len(set(result)) != len(result):
            raise ValueError("registry subkey count mismatch/duplicates")
        return result

    def named_children(self, offset):
        result = {}
        for child in self.children(offset):
            name, data = self.key(child)
            if _wr_number(data, 16) != offset or name.lower() in result:
                raise ValueError("registry parent/name mismatch")
            result[name.lower()] = child
        return result

    def values(self, offset, wanted):
        _, key = self.key(offset)
        count = _wr_number(key, 36)
        if count > 1024:
            raise ValueError("registry value count exceeds bound")
        result = {}
        if not count:
            return result
        entries = self.cell(_wr_number(key, 40))
        if count * 4 > len(entries):
            raise ValueError("truncated registry value list")
        for index in range(count):
            value = self.cell(_wr_number(entries, index * 4))
            if bytes(value[:2]) != b"vk" or len(value) < 20:
                raise ValueError("invalid registry value cell")
            length, flags = _wr_number(value, 2, 2), _wr_number(value, 16, 2)
            if flags & ~1 or 20 + length > len(value):
                raise ValueError("invalid registry value name extent")
            name = _wr_text(value[20:20 + length], bool(flags & 1)).lower()
            if name not in wanted:
                continue
            if name in result:
                raise ValueError("duplicate registry value name")
            size, kind = _wr_number(value, 4), _wr_number(value, 12)
            inline = bool(size & 0x80000000)
            size &= 0x7fffffff
            if size > 16344 or (inline and size > 4):
                raise ValueError("oversized/segmented registry value unsupported")
            self.decoded += size
            if self.decoded > 8 * 1024 * 1024:
                raise ValueError("Amcache decoded path/name budget exceeds 8 MiB")
            payload = value[8:12] if inline else (self.cell(_wr_number(value, 8)) if size else b"")
            if size > len(payload):
                raise ValueError("registry value outside allocated cell")
            if kind != 1:
                raise ValueError("unsupported Amcache path/name value type")
            raw = bytes(payload[:size])
            if raw.endswith(b"\0\0"):
                raw = raw[:-2]
            result[name] = _wr_text(raw)
        return result


def read_amcache(raw):
    """Yield (path, name, key location); inventory records never prove execution.

    Dirty hives, logs, deleted cells, big-data values and other schemas are not
    interpreted. SHA-1 FileId is intentionally not treated as a full-file hash.
    """
    hive = _WrHive(raw)
    root_name, _ = hive.key(hive.root)
    if root_name.lower() != "root":
        roots = hive.named_children(hive.root)
        if "root" not in roots:
            raise ValueError("Amcache Root key missing")
        root = roots["root"]
    else:
        root = hive.root
    branches = hive.named_children(root)
    found, count = False, 0
    for branch in ("inventoryapplicationfile", "file"):
        if branch not in branches:
            continue
        found = True
        parents = [(branches[branch], "Root\\" + branch)]
        if branch == "file":
            parents = [(offset, "Root\\File\\" + name)
                       for name, offset in hive.named_children(branches[branch]).items()]
        for parent, location in parents:
            for child in hive.children(parent):
                count += 1
                if count > _WR_ROW_LIMIT:
                    raise ValueError("Amcache row count exceeds bound")
                try:
                    name, key = hive.key(child)
                    if _wr_number(key, 16) != parent:
                        raise ValueError("Amcache record parent mismatch")
                    modern = branch == "inventoryapplicationfile"
                    values = hive.values(child, {"lowercaselongpath", "name"} if modern else {"15"})
                    path = values.get("lowercaselongpath" if modern else "15", "")
                    if not path:
                        raise ValueError("Amcache record path missing")
                    yield {"path": path, "name": values.get("name", ""),
                           "key": location + "\\" + name, "error": ""}
                except (ValueError, UnicodeError) as exc:
                    yield {"error": str(exc), "key": location + "\\cell-" + str(child)}
    if not found:
        raise ValueError("supported Amcache file inventory keys missing")
