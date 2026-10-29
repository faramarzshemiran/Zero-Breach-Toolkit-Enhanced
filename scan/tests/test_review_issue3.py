"""Fixes from a public code review: the build refuses indicator text that could
end its embedded string, OneDrive online-only files are cloud gaps rather than
links, zsh history with non-UTF-8 bytes is still searched, long .ips lines are
capped, and indicator values are cleaned in the readable report."""
import os
import re
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import localpaths, report
from zbtriage.modules import posix

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _embeddable():
    source = open(os.path.join(ROOT, "build", "bundle.py"), encoding="utf-8").read()
    func = re.search(r"def _embeddable\(text, label\):.*?\n    return text\n", source, re.S).group(0)
    ns = {}
    exec(func, ns)
    return ns["_embeddable"]


@pytest.mark.parametrize("text", ["a\n# note ''x\n", "a\n# '''''\n", "path\\\n", "x\\y"])
def test_build_refuses_text_that_could_end_the_embedded_string(text):
    with pytest.raises(SystemExit):
        _embeddable()(text, "test")


def test_build_accepts_ordinary_indicator_text():
    assert _embeddable()("evil.example\tcc\tprimary\tsrc\n", "test") == "evil.example\tcc\tprimary\tsrc\n"


def test_onedrive_online_only_file_is_a_cloud_gap_not_a_link(tmp_path, monkeypatch):
    (tmp_path / "online-only.exe").write_bytes(b"x")
    real_scandir = os.scandir

    class Entry:
        def __init__(self, entry):
            self._e, self.name, self.path = entry, entry.name, entry.path

        def stat(self, follow_symlinks=True):
            info = self._e.stat(follow_symlinks=False)
            attributes = 0x400 | 0x00400000 if self.name == "online-only.exe" else 0
            return types.SimpleNamespace(st_mode=info.st_mode, st_flags=0, st_file_attributes=attributes)

    class Listing:
        def __init__(self, path):
            self._it = real_scandir(path)

        def __enter__(self):
            return (Entry(e) for e in self._it)

        def __exit__(self, *a):
            self._it.close()

    monkeypatch.setattr(localpaths.os, "scandir", Listing)
    errors = []
    list(localpaths.walk_local(str(tmp_path), onerror=errors.append))
    assert [e.strerror for e in errors] == [localpaths.WALK_CLOUD_SKIPPED]


def test_zsh_history_with_non_utf8_bytes_is_still_searched():
    data = b": 1700000000:0;cd /home/\x83\xa7\x83\xb3\n: 1700000001:0;curl https://bad.example/x\n"
    text = posix._ux_fields(data, "history-file")[0]
    assert "bad.example" in text


def test_other_configuration_files_stay_strict():
    with pytest.raises(UnicodeDecodeError):
        posix._ux_fields(b"[Unit]\nExecStart=/bin/\x83\n", "unit")


def test_indicator_values_are_cleaned_in_the_readable_report():
    doc = {"modules": {"browser": {"hits": [{"indicator": "bad\x1b[2J.example‮", "location": "x",
                                              "detail": "d", "tier": "cc", "confidence": "primary"}],
                                   "notes": [], "checks": []}},
           "verdict": {"gaps": []}}
    cleaned = report._human_document(doc)
    value = cleaned["modules"]["browser"]["hits"][0]["indicator"]
    assert "\x1b" not in value and "‮" not in value
    assert doc["modules"]["browser"]["hits"][0]["indicator"].startswith("bad\x1b")  # JSON copy untouched
