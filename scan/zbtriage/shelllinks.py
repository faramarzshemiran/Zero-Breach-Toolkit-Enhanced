"""Bounded, data-only reading of MS-SHLLINK launch metadata.

Independently implemented from Microsoft's MS-SHLLINK sections 2.1--2.5:
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/
No shell APIs, path resolution, environment expansion or target access.
IDLists and unfamiliar extra blocks remain explicit coverage limitations.
"""
import struct


_SL_HEADER = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
_SL_LIMIT = 1024 * 1024


def _sl_uint(raw, offset, size=4):
    if offset < 0 or offset + size > len(raw):
        raise ValueError("truncated shortcut field")
    return struct.unpack_from("<H" if size == 2 else "<I", raw, offset)[0]


def _sl_text(raw, wide=False):
    # ANSI codepages belong to the creating machine. Only their common ASCII
    # subset is unambiguous here; arbitrary high bytes must not be guessed.
    value = raw.decode("utf-16-le" if wide else "ascii")
    if any(ord(char) < 32 for char in value):
        raise ValueError("shortcut string contains embedded controls")
    return value


def _sl_string_end(raw, offset, minimum, wide=False):
    unit = 2 if wide else 1
    if not minimum <= offset < len(raw):
        raise ValueError("shortcut string offset is outside its structure")
    for end in range(offset, min(len(raw), offset + 65536), unit):
        if raw[end:end + unit] == b"\0" * unit:
            return end + unit
    raise ValueError("shortcut string is unterminated or oversized")


def _sl_terminated(raw, offset, minimum, wide=False):
    end = _sl_string_end(raw, offset, minimum, wide)
    return _sl_text(raw[offset:end - (2 if wide else 1)], wide)


def _sl_disjoint(spans):
    ordered = sorted(spans)
    if any(left[1] > right[0] for left, right in zip(ordered, ordered[1:])):
        raise ValueError("overlapping shortcut fields")


def _sl_linkinfo(raw):
    """Literal target path components; never open the named volume or share."""
    size, header, flags = (_sl_uint(raw, offset) for offset in (0, 4, 8))
    if size != len(raw) or header not in (28, 36) or header > size or flags & ~3:
        raise ValueError("unsupported shortcut LinkInfo header")
    volume, local, network, suffix = (_sl_uint(raw, offset) for offset in (12, 16, 20, 24))
    local_wide, suffix_wide = (_sl_uint(raw, 28), _sl_uint(raw, 32)) if header == 36 else (0, 0)
    spans = [(0, header), (suffix, _sl_string_end(raw, suffix, header))]
    if suffix_wide:
        spans.append((suffix_wide, _sl_string_end(raw, suffix_wide, header, True)))
    tail = _sl_terminated(raw, suffix_wide or suffix, header, bool(suffix_wide))
    targets = []
    if flags & 1:
        if not header <= volume <= len(raw) - 16:
            raise ValueError("invalid shortcut volume offset")
        volume_size = _sl_uint(raw, volume)
        if volume_size <= 16 or volume + volume_size > len(raw):
            raise ValueError("invalid shortcut volume extent")
        vol = raw[volume:volume + volume_size]
        if _sl_uint(vol, 4) > 6:
            raise ValueError("unsupported shortcut volume drive type")
        label = _sl_uint(vol, 12)
        if label == 20:
            _sl_string_end(vol, _sl_uint(vol, 16), 20, True)
        else:
            _sl_string_end(vol, label, 16)
        spans.extend(((volume, volume + volume_size),
                      (local, _sl_string_end(raw, local, header))))
        if local_wide:
            spans.append((local_wide, _sl_string_end(raw, local_wide, header, True)))
        base = _sl_terminated(raw, local_wide or local, header, bool(local_wide))
        if not base:
            raise ValueError("empty shortcut local target")
        targets.append(base + tail)
    elif volume or local or local_wide:
        raise ValueError("unexpected shortcut local-path offsets")
    if flags & 2:
        if not header <= network <= len(raw) - 20:
            raise ValueError("invalid shortcut network offset")
        net_size = _sl_uint(raw, network)
        if net_size < 20 or network + net_size > len(raw):
            raise ValueError("invalid shortcut network extent")
        net = raw[network:network + net_size]
        spans.append((network, network + net_size))
        net_flags, name, device = (_sl_uint(net, offset) for offset in (4, 8, 12))
        if net_flags & ~3:
            raise ValueError("unsupported shortcut network flags")
        wide = name > 20
        net_header = 28 if wide else 20
        net_spans = [(0, net_header), (name, _sl_string_end(net, name, net_header))]
        if wide:
            name_wide = _sl_uint(net, 20)
            net_spans.append((name_wide, _sl_string_end(net, name_wide, net_header, True)))
        base = _sl_terminated(net, _sl_uint(net, 20) if wide else name, net_header, wide)
        if net_flags & 1:
            net_spans.append((device, _sl_string_end(net, device, net_header)))
            if wide:
                device_wide = _sl_uint(net, 24)
                net_spans.append((device_wide, _sl_string_end(net, device_wide, net_header, True)))
            _sl_terminated(net, _sl_uint(net, 24) if wide else device, net_header, wide)
        elif device or (wide and _sl_uint(net, 24)):
            raise ValueError("unexpected shortcut device offset")
        _sl_disjoint(net_spans)
        if not base.startswith("\\\\"):
            raise ValueError("unsupported shortcut network target")
        targets.append(base + ("\\" if tail and not tail.startswith("\\") else "") + tail)
    elif network:
        raise ValueError("unexpected shortcut network offset")
    _sl_disjoint(spans)
    return targets


def _sl_parse(raw):
    if not 80 <= len(raw) <= _SL_LIMIT or raw[:20] != _SL_HEADER:
        raise ValueError("unsupported or truncated shortcut header")
    flags = _sl_uint(raw, 20)
    # Reserved fields must be zero; do not accept arbitrary data as a shortcut.
    if raw[66:76] != b"\0" * 10:
        raise ValueError("invalid shortcut reserved fields")
    position, supported = 76, True
    target, reference = [], []
    if flags & 1:
        length = _sl_uint(raw, position, 2)
        position += 2
        if length < 2 or position + length > len(raw):
            raise ValueError("invalid shortcut IDList extent")
        items = raw[position:position + length]
        cursor = 0
        while True:
            item_size = _sl_uint(items, cursor, 2)
            if item_size == 0:
                if cursor + 2 != len(items):
                    raise ValueError("invalid shortcut IDList terminator")
                break
            if item_size < 2 or cursor + item_size > len(items):
                raise ValueError("invalid shortcut IDList item")
            cursor += item_size
        position += length
        supported = False  # Shell namespace identifiers are not resolved.
    if flags & 2:
        length = _sl_uint(raw, position)
        if length < 28 or position + length > len(raw):
            raise ValueError("invalid shortcut LinkInfo extent")
        info_targets = _sl_linkinfo(raw[position:position + length])
        # ForceNoLinkInfo and PreferEnvironmentPath make this stored path
        # unsuitable for describing the selected launch target.
        (reference if flags & (0x100 | 0x02000000) else target).extend(info_targets)
        position += length
    strings = {}
    for bit, name in ((4, "description"), (8, "relative"), (16, "working"),
                      (32, "arguments"), (64, "icon")):
        if flags & bit:
            count = _sl_uint(raw, position, 2)
            position += 2
            byte_count = count * (2 if flags & 128 else 1)
            if count > 32767 or position + byte_count > len(raw):
                raise ValueError("oversized or truncated shortcut string")
            strings[name] = _sl_text(raw[position:position + byte_count], bool(flags & 128))
            position += byte_count
    if strings.get("relative"):
        (reference if flags & 0x02000000 else target).append(strings["relative"])
    reference.extend(strings.get(name, "") for name in ("description", "working", "icon"))
    environment = None
    for _ in range(128):
        length = _sl_uint(raw, position)
        if length == 0:
            if position + 4 != len(raw):
                raise ValueError("trailing shortcut data")
            break
        if length < 8 or position + length > len(raw):
            raise ValueError("invalid shortcut extra-data extent")
        block = raw[position:position + length]
        signature = _sl_uint(block, 4)
        if signature == 0xA0000001:
            if length != 788 or environment is not None:
                raise ValueError("invalid shortcut environment block")
            environment = _sl_terminated(block[268:788], 0, 0, True)
            if not environment:
                environment = _sl_terminated(block[8:268], 0, 0)
        else:
            supported = False  # No interpretation of alternate resolution blocks.
        position += length
    else:
        raise ValueError("shortcut extra-data count limit reached")
    if flags & 0x200:
        if environment is None:
            raise ValueError("shortcut environment block missing")
        if flags & 0x00100000:  # DisableLinkPathTracking: environment ignored.
            reference.append(environment)
        else:
            target.append(environment)
    elif environment is not None:
        reference.append(environment)
        supported = False
    if flags & ~0x020003FF:
        supported = False
    if flags & 0x1000:  # Darwin target resolution needs the installer namespace.
        reference.extend(target)
        target = []
    arguments = strings.get("arguments", "")
    if target:
        active = "\n".join(target + ([arguments] if arguments else []))
        if "%" in active:
            supported = False  # Values are retained literally, never expanded.
    else:
        active, supported = "", False
        reference.append(arguments)
    return active, "\n".join(reference), supported


def shelllink_content(raw):
    """Return (literal launch metadata, reference text, completely supported).

    Malformed shortcuts never produce persistence findings from guessed fields.
    Literal targets in well-framed shortcuts are configuration evidence only;
    this does not establish the resolved target, execution or network contact.
    """
    try:
        return _sl_parse(raw)
    except (ValueError, UnicodeError, struct.error):
        data = raw[:_SL_LIMIT]
        return "", data.decode("utf-8", "replace") + "\n" + data.decode("utf-16-le", "replace"), False
