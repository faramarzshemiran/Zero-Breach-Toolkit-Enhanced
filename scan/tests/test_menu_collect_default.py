"""The guided Android collection saves to the Desktop when the person just
presses Enter, instead of asking them to find or make an empty folder."""
import argparse
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import menu


def _session(tmp_path, answer, monkeypatch, with_desktop=True):
    home = tmp_path / "home"
    (home / "Desktop" if with_desktop else home).mkdir(parents=True)
    monkeypatch.setattr(menu.os.path, "expanduser", lambda p: str(home) if p == "~" else p)
    args = argparse.Namespace(collect_android=None)
    return menu._MnSession(args, lambda: None, io.StringIO(answer), io.StringIO(), True), home


def test_enter_saves_the_collection_on_the_desktop(tmp_path, monkeypatch):
    s, home = _session(tmp_path, "\n", monkeypatch)
    assert menu._mn_collect(s) == "scan"
    assert s.args.collect_android == os.path.join(str(home), "Desktop", "zero-breach-android-collection")


def test_without_a_desktop_folder_the_home_folder_is_used(tmp_path, monkeypatch):
    s, home = _session(tmp_path, "\n", monkeypatch, with_desktop=False)
    assert menu._mn_collect(s) == "scan"
    assert s.args.collect_android == os.path.join(str(home), "zero-breach-android-collection")


def test_zero_still_goes_back(tmp_path, monkeypatch):
    s, _home = _session(tmp_path, "0\n", monkeypatch)
    assert menu._mn_collect(s) == "back" and s.args.collect_android is None
