"""Decode only supported literal attributed-message text, never archived code.

NSKeyedArchiver is treated as an inert plist graph. The legacy NSArchiver reader
accepts the leading attributed-string/string class chain and length-delimited
UTF-8 text. It never searches arbitrary archive bytes for a URL or guesses a
body from attachment/attribute strings. Unknown encodings remain coverage gaps.
"""
import plistlib
import struct

from .ios_sources import _is_plist


def ios_message_text(raw):
    if not isinstance(raw, bytes) or not raw or len(raw) > 1024 * 1024:
        raise ValueError("encoded message exceeds the limit or has an unsupported type")
    if raw.startswith((b"bplist00", b"<?xml", b"<plist")):
        return _im_keyed_text(raw)
    return _im_stream_text(raw)


def _im_keyed_text(raw):
    doc = _is_plist(raw)
    if not isinstance(doc, dict) or doc.get("$archiver") != "NSKeyedArchiver":
        raise ValueError("unsupported message archive")
    objects = doc.get("$objects")
    if not isinstance(objects, list) or len(objects) > 10000:
        raise ValueError("unsupported message object table")
    seen = set()
    def resolve(obj, depth=0):
        if depth > 16:
            raise ValueError("message archive nesting limit")
        if isinstance(obj, plistlib.UID):
            if obj.data in seen or not 0 <= obj.data < len(objects):
                raise ValueError("cyclic or invalid message reference")
            seen.add(obj.data)
            return resolve(objects[obj.data], depth + 1)
        if isinstance(obj, str):
            return obj
        if not isinstance(obj, dict):
            raise ValueError("unsupported archived text")
        cls = obj.get("$class")
        if not isinstance(cls, plistlib.UID) or not 0 <= cls.data < len(objects):
            raise ValueError("missing archived string class")
        class_record = objects[cls.data]
        name = class_record.get("$classname") if isinstance(class_record, dict) else None
        if name not in ("NSString", "NSMutableString", "NSAttributedString", "NSMutableAttributedString"):
            raise ValueError("unsupported archived string class")
        if "NS.string" not in obj:
            raise ValueError("archived string has no supported text field")
        return resolve(obj["NS.string"], depth + 1)
    top = doc.get("$top")
    if not isinstance(top, dict) or "root" not in top:
        raise ValueError("message archive root missing")
    text = resolve(top["root"])
    if len(text.encode("utf-8")) > 65536:
        raise ValueError("decoded message text exceeds the limit")
    return text


def _im_stream_text(raw):
    # Format facts: Apple's NSArchiver v4 little/big endian stream headers.
    if raw[:13] not in (b"\x04\x0bstreamtyped", b"\x04\x0btypedstream"):
        raise ValueError("unsupported encoded message format")
    order = "<" if raw[2:13] == b"streamtyped" else ">"
    pos = 13
    def integer():
        nonlocal pos
        if pos >= len(raw):
            raise ValueError("truncated typed message")
        tag = raw[pos]
        pos += 1
        if tag in (0x81, 0x82):
            size, fmt = (2, "h") if tag == 0x81 else (4, "i")
            if pos + size > len(raw):
                raise ValueError("truncated typed length")
            value = struct.unpack_from(order + fmt, raw, pos)[0]
            pos += size
            return value
        if tag >= 0x80:
            raise ValueError("unsupported typed integer/reference")
        return tag
    def take(expected):
        nonlocal pos
        if raw[pos:pos + len(expected)] != expected:
            raise ValueError("unsupported typed message layout")
        pos += len(expected)
    if integer() != 1000:
        raise ValueError("unsupported typed message system version")
    take(b"\x84\x01@\x84")
    # New class records use a shared literal class name and integer version.
    # Reference tokens are accepted only for the already-declared NSObject.
    classes = []
    while raw[pos:pos + 1] == b"\x84":
        take(b"\x84\x84")
        length = integer()
        if not 1 <= length <= 64 or pos + length > len(raw):
            raise ValueError("invalid typed class name")
        name = raw[pos:pos + length].decode("ascii")
        pos += length
        version = integer()
        if name not in ("NSAttributedString", "NSMutableAttributedString", "NSObject") or version != 0:
            raise ValueError("unsupported attributed-string class")
        classes.append(name)
        if len(classes) > 3:
            raise ValueError("typed class chain limit")
    if not classes or classes[0] not in ("NSAttributedString", "NSMutableAttributedString"):
        raise ValueError("typed root is not attributed text")
    take(b"\x85")  # end of root class chain
    # The root's first field must be an NSString object, not an attribute value.
    if raw[pos:pos + 3] == b"\x84\x01@":
        take(b"\x84\x01@")
    else:
        take(b"\x92")  # reference to the first shared type encoding '@'
    take(b"\x84\x84\x84")
    length = integer()
    if raw[pos:pos + length] == b"NSMutableString":
        pos += length
        if integer() != 1:
            raise ValueError("unsupported mutable string version")
        take(b"\x84\x84")
        length = integer()
    if length != 8 or raw[pos:pos + length] != b"NSString":
        raise ValueError("typed body is not a string")
    pos += length
    if integer() != 1:
        raise ValueError("unsupported string version")
    if raw[pos:pos + 1] == b"\x85":
        pos += 1
    elif "NSObject" in classes and raw[pos:pos + 1] == bytes([0x93 + classes.index("NSObject")]):
        pos += 1
    else:
        raise ValueError("unsupported string superclass reference")
    take(b"\x84\x01+")
    size = integer()
    if not 0 <= size <= 65536 or pos + size >= len(raw):
        raise ValueError("invalid typed body length")
    text = raw[pos:pos + size].decode("utf-8", "strict")
    pos += size
    take(b"\x86")
    # Attribute runs are deliberately not interpreted or searched.
    return text
