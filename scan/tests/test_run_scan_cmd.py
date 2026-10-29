"""The Windows launcher in folders whose names contain cmd special characters:
an "&" must never run as a second command, and a "!" must not be stripped
(which once made the launch fail and read as a finding)."""
import os
import shutil
import subprocess
import sys

import pytest

SCAN = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAKE = '''import sys
args = sys.argv[1:]
for flag in ("--json", "--report"):
    open(args[args.index(flag) + 1], "w").write("report")
sys.exit(0)
'''


def test_launcher_does_not_use_delayed_expansion_and_quotes_paths():
    text = open(os.path.join(SCAN, "run-scan.cmd"), encoding="utf-8").read().lower()
    assert "enabledelayedexpansion" not in text
    assert 'echo   saved: "%txt%"' in text and 'echo   saved: "%json%"' in text


@pytest.mark.skipif(sys.platform != "win32", reason="cmd.exe launcher")
def test_special_characters_in_the_folder_name(tmp_path):
    root = tmp_path / "x & echo INJECTED-MARKER y!z"
    scan = root / "scan"
    scan.mkdir(parents=True)
    shutil.copy(os.path.join(SCAN, "run-scan.cmd"), scan / "run-scan.cmd")
    (scan / "zero-breach-toolkit.py").write_text(FAKE)
    out = subprocess.run('echo.| "{}"'.format(scan / "run-scan.cmd"), shell=True, capture_output=True,
                         text=True, timeout=120).stdout
    assert not any(line.strip().startswith("INJECTED-MARKER") for line in out.splitlines())
    saved = [line for line in out.splitlines() if "Saved:" in line]
    assert len(saved) == 2 and all("y!z" in line and '"' in line for line in saved)
    assert len(list((root / "findings").glob("scan-*.json"))) == 1
