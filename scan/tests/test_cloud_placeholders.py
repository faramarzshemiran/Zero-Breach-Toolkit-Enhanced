"""Windows cloud-files placeholders (OneDrive "always keep on this device" or
already-downloaded files, and OneDrive folders) are read in place: their
reparse tag does not redirect anywhere. Placeholders that would need a download
stay a "not downloaded" gap, and real links are still refused."""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import localpaths

CLOUD_TAG = 0x9000701A          # IO_REPARSE_TAG_CLOUD_7, as OneDrive uses
SYMLINK_TAG = 0xA000000C
RECALL = 0x00400000


def _fake_walk(tmp_path, monkeypatch, attrs_by_name):
    real_scandir = os.scandir

    class Entry:
        def __init__(self, entry):
            self._e, self.name, self.path = entry, entry.name, entry.path

        def stat(self, follow_symlinks=True):
            info = self._e.stat(follow_symlinks=False)
            attributes, tag = attrs_by_name.get(self.name, (0, 0))
            return types.SimpleNamespace(st_mode=info.st_mode, st_flags=0,
                                         st_file_attributes=attributes, st_reparse_tag=tag)

    class Listing:
        def __init__(self, path):
            self._it = real_scandir(path)

        def __enter__(self):
            return (Entry(e) for e in self._it)

        def __exit__(self, *a):
            self._it.close()

    monkeypatch.setattr(localpaths.os, "scandir", Listing)
    errors, files = [], []
    for _dirpath, _dirs, names in localpaths.walk_local(str(tmp_path), onerror=errors.append):
        files += names
    return sorted(files), [e.strerror for e in errors]


def test_downloaded_onedrive_file_is_read_not_refused(tmp_path, monkeypatch):
    (tmp_path / "kept.exe").write_bytes(b"x")
    files, errors = _fake_walk(tmp_path, monkeypatch, {"kept.exe": (0x400 | 0x20, CLOUD_TAG)})
    assert files == ["kept.exe"] and errors == []


def test_onedrive_folder_is_walked(tmp_path, monkeypatch):
    (tmp_path / "Desktop").mkdir()
    (tmp_path / "Desktop" / "a.txt").write_text("x")
    files, errors = _fake_walk(tmp_path, monkeypatch, {"Desktop": (0x400 | 0x10, CLOUD_TAG)})
    assert files == ["a.txt"] and errors == []


def test_online_only_file_is_still_a_cloud_gap(tmp_path, monkeypatch):
    (tmp_path / "online.exe").write_bytes(b"x")
    files, errors = _fake_walk(tmp_path, monkeypatch, {"online.exe": (0x400 | RECALL, CLOUD_TAG)})
    assert files == [] and errors == [localpaths.WALK_CLOUD_SKIPPED]


def test_other_reparse_points_are_still_refused(tmp_path, monkeypatch):
    (tmp_path / "link.exe").write_bytes(b"x")
    (tmp_path / "untagged.exe").write_bytes(b"x")
    files, errors = _fake_walk(tmp_path, monkeypatch, {"link.exe": (0x400, SYMLINK_TAG),
                                                        "untagged.exe": (0x400, 0)})
    assert files == [] and errors == [localpaths.WALK_LINK_REFUSED] * 2


def test_cloud_ancestor_folder_is_not_a_path_problem(tmp_path, monkeypatch):
    folder = tmp_path / "OneDrive"
    folder.mkdir()
    real_lstat = os.lstat

    def lstat(path):
        info = real_lstat(path)
        if os.path.normcase(os.path.abspath(path)) == os.path.normcase(str(folder)):
            return types.SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400 | 0x10,
                                         st_reparse_tag=CLOUD_TAG)
        return info

    monkeypatch.setattr(localpaths.os, "lstat", lstat)
    assert localpaths.path_problem(str(folder)) == ""


def test_cloud_ancestor_that_needs_a_download_is_a_problem(tmp_path, monkeypatch):
    folder = tmp_path / "OneDrive"
    folder.mkdir()
    real_lstat = os.lstat

    def lstat(path):
        info = real_lstat(path)
        if os.path.normcase(os.path.abspath(path)) == os.path.normcase(str(folder)):
            return types.SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400 | RECALL,
                                         st_reparse_tag=CLOUD_TAG)
        return info

    monkeypatch.setattr(localpaths.os, "lstat", lstat)
    assert "not downloaded" in localpaths.path_problem(str(folder))


def test_placeholder_detection():
    ns = types.SimpleNamespace
    assert localpaths.cloud_placeholder(ns(st_file_attributes=0x400, st_reparse_tag=0x9000001A))
    assert localpaths.cloud_placeholder(ns(st_file_attributes=0x400, st_reparse_tag=0x9000F01A))
    assert not localpaths.cloud_placeholder(ns(st_file_attributes=0, st_reparse_tag=0x9000001A))
    assert not localpaths.cloud_placeholder(ns(st_file_attributes=0x400, st_reparse_tag=0xA000000C))
    assert not localpaths.cloud_placeholder(ns(st_file_attributes=0x400))
