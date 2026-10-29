"""Desktop toolkit regressions, synthetic artifacts and fixed harmless CMD only."""
import contextlib
import os
from pathlib import Path
import sqlite3
import struct
import subprocess

import pytest

from zbtriage.iocs import Indicator, IocSet
from zbtriage.modules import browser, traces
from zbtriage.shelllinks import shelllink_content
from zbtriage.result import ModuleResult
from test_expanded_capabilities import context, BAD
from test_followup_fixes import bundle, fake_registry


def _dt_iocs():
    return IocSet([Indicator(v, "infrastructure", "primary", "domain", "fixture")
                   for v in (BAD, "sub." + BAD)], "fixture", None)


@pytest.mark.parametrize("field", ["query", "title", "path", "fragment", "username"])
@pytest.mark.parametrize("reverse", [False, True])
def test_history_contact_survives_independent_reference(tmp_path, bundle, field, reverse):
    host, reference = ("sub." + BAD, BAD) if reverse else (BAD, "sub." + BAD)
    url, title = "https://" + host + "/", ""
    if field == "title":
        title = reference
    elif field == "username":
        url = "https://" + reference + "@" + host + "/"
    else:
        url += {"query": "?q=", "path": "", "fragment": "#"}[field] + reference
    with contextlib.closing(sqlite3.connect(tmp_path / "History")) as db:
        db.execute("CREATE TABLE urls(url TEXT,title TEXT,last_visit_time INTEGER)")
        db.execute("INSERT INTO urls VALUES(?,?,13000000000000000)", (url, title))
        db.commit()
    for reader in (browser.run, bundle.run_browser):
        ctx = context(targets=(str(tmp_path),))
        ctx.iocs = _dt_iocs()
        r = reader(ctx)
        assert {(h.indicator, h.evidence) for h in r.hits} == {(host, "contacted"), (reference, "referenced")}
        assert all(c.ran for c in r.checks)


@pytest.mark.parametrize("bitmap", [b"image", b""])
def test_favicon_host_keeps_its_evidence_grade(tmp_path, bundle, bitmap):
    with contextlib.closing(sqlite3.connect(tmp_path / "History")) as db:
        db.execute("CREATE TABLE urls(url TEXT,title TEXT,last_visit_time INTEGER)")
        db.commit()
    with contextlib.closing(sqlite3.connect(tmp_path / "Favicons")) as db:
        db.executescript("CREATE TABLE favicons(id INTEGER,url TEXT); CREATE TABLE favicon_bitmaps(icon_id INTEGER,image_data BLOB)")
        db.execute("INSERT INTO favicons VALUES(1,?)", ("https://" + BAD + "/?q=sub." + BAD,))
        db.execute("INSERT INTO favicon_bitmaps VALUES(1,?)", (bitmap,))
        db.commit()
    for reader in (browser.run, bundle.run_browser):
        ctx = context(targets=(str(tmp_path),))
        ctx.iocs = _dt_iocs()
        r = reader(ctx)
        assert {(h.indicator, h.evidence) for h in r.hits} == {
            (BAD, "contacted" if bitmap else "referenced"), ("sub." + BAD, "referenced")}


def test_url_evidence_does_not_admit_phone_only_indicators(bundle):
    iocs = IocSet([Indicator(BAD, "artifact", "primary", "app-id", "fixture")], "fixture", None)
    for api in (browser, bundle):
        assert not list(api._browser_url_evidence("https://" + BAD, iocs, "contacted"))


@pytest.mark.parametrize("url", [
    "https://safe.invalid:" + BAD + "/",
    "https://safe.invalid\\@" + BAD + "/",
    "https://" + BAD + ":99999/",
    "https://\t" + BAD + "/",
    "https://user name@" + BAD + "/",
])
def test_ambiguous_url_authorities_remain_references(bundle, url):
    for api in (browser, bundle):
        hits = list(api._browser_url_evidence(url, _dt_iocs(), "contacted"))
        assert hits and all(grade == "referenced" for _, grade in hits)
        assert BAD in {ind.value for ind, _ in hits}


@pytest.mark.parametrize("first", ["rem. hello", "rem, hello", "rem.", "rem.\thello"])
def test_rem_punctuation_does_not_erase_next_command(bundle, first):
    for api in (traces, bundle):
        active, reference, supported = api._tr_batch_content(first + "\nprogram.exe " + BAD)
        assert BAD in active and first in reference and not supported


@pytest.mark.parametrize("prefix,active", [
    (':: "x ^\n', True),
    (":: x ^\n\n", False),
    ("echo BEGIN^\n\n", False),
    ("echo BEGIN^\n\n\n", True),
    ("rem. x ^\n", False),
])
def test_batch_quoted_caret_and_blank_continuation(bundle, prefix, active):
    for api in (traces, bundle):
        launch, reference, _ = api._tr_batch_content(prefix + "program.exe " + BAD)
        assert (BAD in launch) == active
        assert (BAD in reference) != active


@pytest.mark.skipif(os.name != "nt", reason="authored native CMD marker needs Windows")
@pytest.mark.parametrize("body,expected", [
    ("rem. harmless\necho ZBT_AFTER", True),
    (':: "x ^\necho ZBT_AFTER', True),
    (":: x ^\n\necho ZBT_AFTER", False),
    ("echo BEGIN^\n\necho ZBT_AFTER", False),
    ("echo BEGIN^\n\n\necho ZBT_AFTER", True),
])
def test_native_batch_boundary_control(tmp_path, body, expected):
    # Compare complete output lines: ECHO data can itself contain "echo MARKER"
    # without executing that command. Every case has a required positive control.
    path = tmp_path / "marker.cmd"
    path.write_bytes(("@echo off\necho ZBT_CONTROL\n" + body + "\n").encode("ascii"))
    command = Path(os.environ["SystemRoot"]) / "System32/cmd.exe"
    proc = subprocess.run([str(command), "/d", "/q", "/c", str(path)], cwd=tmp_path,
                          capture_output=True, timeout=5)
    lines = proc.stdout.splitlines()
    assert proc.returncode == 0 and b"ZBT_CONTROL" in lines
    assert (b"ZBT_AFTER" in lines) == expected


def _dt_shortcut(target=r"C:\Fixture\program.exe", arguments="", description="", icon="",
                 flags_extra=0, info=b"", idlist=b"", extra=b"", wide=True):
    flags = (128 if wide else 0) | flags_extra
    values = []
    for bit, value in ((4, description), (8, target), (32, arguments), (64, icon)):
        if value:
            flags |= bit
            encoded = value.encode("utf-16-le" if wide else "ascii")
            values.append(struct.pack("<H", len(encoded) // (2 if wide else 1)) + encoded)
    prefix = b""
    if idlist:
        flags |= 1
        prefix += struct.pack("<H", len(idlist)) + idlist
    if info:
        flags |= 2
        prefix += info
    header = struct.pack("<I", 76) + bytes.fromhex("0114020000000000c000000000000046")
    header += struct.pack("<I", flags) + b"\0" * 52
    return header + prefix + b"".join(values) + extra + b"\0" * 4


def _dt_linkinfo(path):
    volume = struct.pack("<IIII", 17, 3, 0, 16) + b"\0"
    base = path.encode("ascii") + b"\0"
    # An empty suffix is legal; strings and substructures are fully bounded.
    size = 28 + len(volume) + len(base) + 1
    return struct.pack("<IIIIIII", size, 28, 1, 28, 45, 0, size - 1) + volume + base + b"\0"


def _dt_network_linkinfo(server):
    name = ("\\\\" + server + "\\share").encode("ascii") + b"\0"
    network = struct.pack("<IIIII", 20 + len(name), 0, 20, 0, 0) + name
    suffix = b"program.exe\0"
    size = 28 + len(network) + len(suffix)
    return struct.pack("<IIIIIII", size, 28, 2, 0, 0, 28, 28 + len(network)) + network + suffix


def test_shortcut_network_linkinfo_is_only_parsed_as_text(bundle):
    raw = _dt_shortcut(target="", info=_dt_network_linkinfo(BAD))
    for parser in (shelllink_content, bundle.shelllink_content):
        active, reference, supported = parser(raw)
        assert active == "\\\\" + BAD + "\\share\\program.exe"
        assert supported and not reference.strip()


def test_shortcut_unicode_target_with_non_ascii_characters(bundle):
    raw = _dt_shortcut(target="C:\\ملفات\\program.exe", arguments=BAD)
    for parser in (shelllink_content, bundle.shelllink_content):
        active, _, supported = parser(raw)
        assert "ملفات" in active and BAD in active and supported


@pytest.mark.parametrize("wide", [True, False])
def test_shortcut_arguments_are_config_but_description_and_icon_are_references(bundle, wide):
    raw = _dt_shortcut(arguments="https://" + BAD, description="sub." + BAD,
                       icon="sub." + BAD, wide=wide)
    for parser in (shelllink_content, bundle.shelllink_content):
        active, reference, supported = parser(raw)
        assert supported and "https://" + BAD in active
        assert "sub." + BAD not in active and "sub." + BAD in reference


@pytest.mark.parametrize("force_ignore", [False, True])
def test_shortcut_linkinfo_and_force_ignore(bundle, force_ignore):
    raw = _dt_shortcut(target="", info=_dt_linkinfo("C:\\" + BAD + "\\program.exe"),
                       flags_extra=0x100 if force_ignore else 0)
    for parser in (shelllink_content, bundle.shelllink_content):
        active, reference, supported = parser(raw)
        assert (BAD in active) == (not force_ignore)
        assert (BAD in reference) == force_ignore
        assert supported == (not force_ignore)


@pytest.mark.parametrize("variation", [
    "label-outside", "label-header", "label-unterminated", "drive-type",
    "volume-size", "unicode-outside", "target-overlap", "suffix-overlap",
    "network-overlap",
])
def test_shortcut_nested_structures_cannot_supply_fake_targets(bundle, variation):
    info = bytearray(_dt_linkinfo("C:\\" + BAD + "\\program.exe"))
    if variation == "label-outside":
        struct.pack_into("<I", info, 28 + 12, 0xffffffff)
    elif variation == "label-header":
        struct.pack_into("<I", info, 28 + 12, 4)
    elif variation == "label-unterminated":
        info[44] = 65
    elif variation == "drive-type":
        struct.pack_into("<I", info, 28 + 4, 7)
    elif variation == "volume-size":
        struct.pack_into("<I", info, 28, 16)
    elif variation == "unicode-outside":
        struct.pack_into("<I", info, 28 + 12, 20)
    elif variation == "target-overlap":
        # A plausible path in a volume label is not the LocalBasePath field.
        label = ("C:\\" + BAD + "\\program.exe").encode() + b"\0"
        volume = struct.pack("<IIII", 16 + len(label), 3, 0, 16) + label
        size = 28 + len(volume) + 1
        info = bytearray(struct.pack("<IIIIIII", size, 28, 1, 28, 44, 0, size - 1) + volume + b"\0")
    elif variation == "suffix-overlap":
        struct.pack_into("<I", info, 24, 45)
    else:
        info = bytearray(_dt_network_linkinfo(BAD))
        struct.pack_into("<I", info, 24, 48)
    raw = _dt_shortcut(target="", info=bytes(info))
    for parser in (shelllink_content, bundle.shelllink_content):
        active, reference, supported = parser(raw)
        assert not active and not supported and BAD in reference


def test_shortcut_unicode_volume_label_is_validated_but_not_a_target(bundle):
    label = (BAD + "\0").encode("utf-16-le")
    volume = struct.pack("<IIIII", 20 + len(label), 3, 0, 20, 20) + label
    base = b"C:\\Fixture\\program.exe\0"
    size = 28 + len(volume) + len(base) + 1
    info = struct.pack("<IIIIIII", size, 28, 1, 28, 28 + len(volume), 0, size - 1) + volume + base + b"\0"
    for parser in (shelllink_content, bundle.shelllink_content):
        active, reference, supported = parser(_dt_shortcut(target="", info=info))
        assert supported and active == base[:-1].decode() and BAD not in active + reference


def test_shortcut_environment_path_retained_literally_with_gap(bundle):
    target = "%FIXTURE%\\" + BAD + "\\program.exe"
    ansi = target.encode("ascii") + b"\0"
    wide = target.encode("utf-16-le") + b"\0\0"
    block = struct.pack("<II", 788, 0xA0000001) + ansi.ljust(260, b"\0") + wide.ljust(520, b"\0")
    raw = _dt_shortcut(target="", extra=block, flags_extra=0x200 | 0x02000000)
    for parser in (shelllink_content, bundle.shelllink_content):
        active, _, supported = parser(raw)
        assert active == target and not supported


@pytest.mark.parametrize("variation", ["bad-header", "truncated", "bad-count", "bad-offset", "bad-block", "trailing", "utf16-error"])
def test_malformed_shortcuts_never_invent_launch_evidence(bundle, variation):
    raw = bytearray(_dt_shortcut(arguments=BAD))
    if variation == "bad-header":
        raw[0] = 0
    elif variation == "truncated":
        raw = raw[:-5]
    elif variation == "bad-count":
        raw[76:78] = b"\xff\xff"
    elif variation == "bad-offset":
        raw = bytearray(_dt_shortcut(target="", info=_dt_linkinfo(BAD)))
        raw[92:96] = struct.pack("<I", 0xffffffff)
    elif variation == "bad-block":
        raw = bytearray(_dt_shortcut(arguments=BAD, extra=struct.pack("<II", 0xffffffff, 1)))
    elif variation == "trailing":
        raw += BAD.encode()
    else:
        raw[78:80] = b"\x00\xd8"
    for parser in (shelllink_content, bundle.shelllink_content):
        active, _, supported = parser(bytes(raw))
        assert not active and not supported


def test_unresolved_idlist_keeps_literal_config_with_explicit_gap(bundle):
    raw = _dt_shortcut(arguments=BAD, idlist=b"\x04\x00xx\0\0")
    for parser in (shelllink_content, bundle.shelllink_content):
        active, _, supported = parser(raw)
        assert BAD in active and not supported


def test_idlist_only_target_and_arguments_remain_unresolved(bundle):
    raw = _dt_shortcut(target="", arguments=BAD, idlist=b"\x04\x00xx\0\0")
    for parser in (shelllink_content, bundle.shelllink_content):
        active, reference, supported = parser(raw)
        assert not active and BAD in reference and not supported


def test_startup_shortcut_reader_never_accesses_named_target(tmp_path, monkeypatch, bundle):
    import sys
    monkeypatch.setitem(sys.modules, "winreg", fake_registry())
    for key in ("APPDATA", "PROGRAMDATA", "SystemRoot"):
        monkeypatch.setenv(key, str(tmp_path))
    folder = tmp_path / "Microsoft/Windows/Start Menu/Programs/Startup"
    folder.mkdir(parents=True)
    (folder / "fixture.lnk").write_bytes(_dt_shortcut(target=r"\\fixture.invalid\share\program.exe"))
    import builtins
    original = builtins.open
    def guarded(path, *args, **kwargs):
        assert not str(path).startswith("\\\\"), "shortcut target must never be accessed"
        return original(path, *args, **kwargs)
    monkeypatch.setattr(builtins, "open", guarded)
    for api in (traces, bundle):
        r = ModuleResult("traces")
        api._tr_persistence(r, context())
        assert any(h.indicator == BAD and h.evidence == "persistence" for h in r.hits)
        assert all(c.ran for c in r.checks if c.name == "startup-files")
