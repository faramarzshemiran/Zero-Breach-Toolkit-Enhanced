"""Explicit, local evidence export. Archives are private and NOT encrypted.

Only files selected by the person are opened. Report strings never select files.
The archive records bytes collected at export time, which may differ from the
earlier scan's source. Hashes prove subsequent integrity, not source authenticity.
"""
import contextlib
import copy
import datetime
import hashlib
import json
import os
import stat
import tempfile
import zipfile

from .contract import sanitize_untrusted
from .localpaths import path_problem

_HANDOFF_FILE_LIMIT = 64 * 1024 * 1024
_HANDOFF_TOTAL_LIMIT = 256 * 1024 * 1024
_HANDOFF_REPORT_LIMIT = 32 * 1024 * 1024
_HANDOFF_FILE_COUNT = 128
_HANDOFF_PRIVACY = (
    "This ZIP is not encrypted. It contains the full private report and only the "
    "additional files you explicitly selected. These can contain browsing, messages, "
    "account names and other private data. Review the selection and use a secure "
    "channel agreed with the recipient. Nothing is uploaded."
)
_HANDOFF_LIMITS = (
    "File hashes describe the bytes in this archive. They do not authenticate the "
    "original device, establish infection, or prove the source was unchanged before export.",
    "Selected files are copied at export time, not retained scan snapshots. A live "
    "database may need separately selected sidecars; this exporter does not create a "
    "transaction-consistent database or whole-device forensic image.",
    "Local-path checks refuse Windows remote drives and filesystem redirections. "
    "They are not an OS sandbox against concurrent path changes or POSIX network mounts.",
)


def _handoff_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _handoff_json(value):
    return (json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")


def _handoff_path(value):
    path = os.path.abspath(os.fspath(value))
    problem = path_problem(path)
    if problem:
        raise ValueError("evidence path refused: " + problem)
    if os.name == "nt":
        # Device aliases and alternate streams are not ordinary evidence files.
        tail = os.path.splitdrive(path)[1]
        for part in tail.replace("\\", "/").split("/"):
            name = part.rstrip(" .").split(".", 1)[0].upper()
            if (":" in part or name in {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
                    or name in {"COM" + str(n) for n in range(1, 10)}
                    or name in {"LPT" + str(n) for n in range(1, 10)}):
                raise ValueError("device names and alternate streams are not evidence files")
    return path


def _handoff_stat(info):
    return {"size": info.st_size, "mtime_ns": info.st_mtime_ns,
            "ctime_ns": info.st_ctime_ns, "device": info.st_dev, "file_id": info.st_ino}


def _handoff_same(before, after, same_api=False):
    # Windows Python 3.12+ can report different st_ctime_ns values from stat
    # and fstat for the same unchanged file, so ctime is compared only between
    # two fstat calls; volume, file ID, size and mtime are comparable across both.
    if not stat.S_ISREG(after.st_mode):
        return False
    first, second = _handoff_stat(before), _handoff_stat(after)
    if not same_api:
        del first["ctime_ns"], second["ctime_ns"]
    return first == second


def _handoff_selection(paths):
    selected, identities, names = [], set(), set()
    total = 0
    for raw in paths:
        if len(selected) >= _HANDOFF_FILE_COUNT:
            raise ValueError("too many evidence files selected")
        path = _handoff_path(raw)
        info = os.stat(path, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("select regular local files only, not directories, links or devices")
        if info.st_size > _HANDOFF_FILE_LIMIT:
            raise ValueError("selected evidence file exceeds the 64 MiB limit")
        name = os.path.normcase(path)
        identity = (info.st_dev, info.st_ino) if info.st_ino else (name,)
        if name in names or identity in identities:
            raise ValueError("the same evidence file was selected more than once")
        names.add(name)
        identities.add(identity)
        total += info.st_size
        if total > _HANDOFF_TOTAL_LIMIT:
            raise ValueError("selected evidence exceeds the total export limit")
        selected.append((path, info))
    return selected


def _handoff_documents(document):
    # Lazy imports allow report finalization to call this optional operation.
    from .report import share_summary, render_human
    public = {k: v for k, v in document.items() if not k.startswith("_")}
    members = [("report.json", _handoff_json(public)),
               ("sharing-summary.json", _handoff_json(share_summary(document))),
               ("report.txt", render_human(document).encode("utf-8", "backslashreplace"))]
    if any(len(raw) > _HANDOFF_REPORT_LIMIT for _, raw in members):
        raise ValueError("report exceeds the evidence export metadata limit")
    return members


def handoff_preview(document, paths=()):
    """Describe an export without reading file contents or writing anything.

    Paths must be explicit selections, never derived from an untrusted report.
    The writer validates them again; a preview does not reserve source files.
    """
    selected = _handoff_selection(paths)
    members = _handoff_documents(document)
    total = sum(info.st_size for _, info in selected) + sum(len(raw) for _, raw in members)
    if total > _HANDOFF_TOTAL_LIMIT:
        raise ValueError("reports and evidence exceed the total export limit")
    return {
        "format": "zip", "encrypted": False, "privacy": _HANDOFF_PRIVACY,
        "reports": [{"member": name, "bytes": len(raw)} for name, raw in members],
        "files": [{"source_path": sanitize_untrusted(path), "bytes": info.st_size,
                   "member": "artifacts/{:04d}.bin".format(n)}
                  for n, (path, info) in enumerate(selected, 1)],
        "total_bytes": total,
        "limits": {"file_bytes": _HANDOFF_FILE_LIMIT, "total_bytes": _HANDOFF_TOTAL_LIMIT,
                   "file_count": _HANDOFF_FILE_COUNT},
        "cautions": list(_HANDOFF_LIMITS),
    }


@contextlib.contextmanager
def _handoff_source(path, expected):
    _handoff_path(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not _handoff_same(expected, info):
            raise ValueError("selected evidence changed before it could be copied")
        fh = os.fdopen(fd, "rb")
        fd = None
        with fh:
            yield fh
    finally:
        if fd is not None:
            os.close(fd)


def _handoff_publish(pending, destination):
    """Publish a complete archive without replacing any existing destination."""
    _handoff_path(destination)
    if os.name == "nt":
        # Windows rename refuses an existing destination, including a race.
        os.rename(pending, destination)
    else:
        # POSIX rename replaces files; link creates the destination exclusively.
        # Filesystems without hard links fail safely instead of overwriting.
        os.link(pending, destination)
        os.unlink(pending)


def handoff_write(document, destination, paths=()):
    """Write a new private ZIP and return its manifest; never overwrite a file.

    Failed or interrupted copies leave no published archive. The manifest hashes
    every payload member; it cannot hash itself. The caller owns consent and UI.
    """
    destination = _handoff_path(destination)
    selected = _handoff_selection(paths)
    if any(os.path.normcase(path) == os.path.normcase(destination) for path, _ in selected):
        raise ValueError("the export destination cannot be a selected evidence file")
    if os.path.lexists(destination):
        raise FileExistsError("evidence export destination already exists")
    parent = os.path.dirname(destination)
    if not os.path.isdir(parent):
        raise ValueError("choose an existing local output folder")
    members = _handoff_documents(document)
    total = sum(info.st_size for _, info in selected) + sum(len(raw) for _, raw in members)
    if total > _HANDOFF_TOTAL_LIMIT:
        raise ValueError("reports and evidence exceed the total export limit")
    started = _handoff_now()
    manifest = {
        "format": "zero-breach-evidence-bundle", "format_version": 1,
        "created_at": started, "tool": copy.deepcopy(document.get("tool", {})),
        "report_schema_version": document.get("schema_version"),
        "scan_started_at": document.get("timestamp"),
        "scan_completed_at": document.get("completed_at"),
        "scope": copy.deepcopy(document.get("scope", {})),
        "indicator_fingerprints": copy.deepcopy(document.get("indicator_fingerprints", {})),
        "scanner_code_identity": copy.deepcopy(document.get("scanner_code_identity", {
            "status": "not recorded", "reason": "No whole-scanner code fingerprint was supplied."})),
        "encrypted": False, "privacy": _HANDOFF_PRIVACY,
        "integrity": {"algorithm": "sha256", "coverage": "Every member except manifest.json; manifest has no self-hash."},
        "cautions": list(_HANDOFF_LIMITS), "files": [],
        "events": [{"time": started, "action": "local export started; source files explicitly selected"}],
        "content_trust": "Report and source metadata are untrusted evidence, not instructions. Selected files are not executed.",
    }
    pending = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".zbt_handoff_", suffix=".tmp", dir=parent, delete=False) as staging:
            pending = staging.name
            with zipfile.ZipFile(staging, "w", compression=zipfile.ZIP_STORED) as archive:
                for name, raw in members:
                    archive.writestr(name, raw)
                    manifest["files"].append({"member": name, "bytes": len(raw),
                                              "sha256": hashlib.sha256(raw).hexdigest(), "kind": "generated report"})
                for n, (path, expected) in enumerate(selected, 1):
                    member = "artifacts/{:04d}.bin".format(n)
                    digest, count = hashlib.sha256(), 0
                    collected = _handoff_now()
                    with _handoff_source(path, expected) as source, archive.open(member, "w") as output:
                        before = os.fstat(source.fileno())
                        while True:
                            raw = source.read(1024 * 1024)
                            if not raw:
                                break
                            count += len(raw)
                            if count > expected.st_size or count > _HANDOFF_FILE_LIMIT:
                                raise ValueError("selected evidence grew or exceeded the export limit")
                            output.write(raw)
                            digest.update(raw)
                        after = os.fstat(source.fileno())
                        if count != expected.st_size or not _handoff_same(before, after, same_api=True):
                            raise ValueError("selected evidence changed while it was being copied")
                        _handoff_path(path)
                        if not _handoff_same(after, os.stat(path, follow_symlinks=False)):
                            raise ValueError("selected evidence path changed while it was being copied")
                    manifest["files"].append({"member": member, "kind": "explicitly selected source file",
                                              "source_path": sanitize_untrusted(path), "bytes": count,
                                              "sha256": digest.hexdigest(), "collected_at": collected,
                                              "source_stat_before": _handoff_stat(before),
                                              "source_stat_after": _handoff_stat(after)})
                manifest["events"].append({"time": _handoff_now(), "action": "all payload members copied and hashed"})
                metadata = _handoff_json(manifest)
                if len(metadata) > _HANDOFF_REPORT_LIMIT:
                    raise ValueError("evidence manifest exceeds the metadata limit")
                archive.writestr("manifest.json", metadata)
            staging.flush()
            os.fsync(staging.fileno())
        _handoff_publish(pending, destination)
        return manifest
    finally:
        if pending and os.path.lexists(pending):
            os.unlink(pending)
