"""Android paths keep publisher case and match complete path tokens."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage.iocs import Indicator, IocSet
from zbtriage.modules import android
from zbtriage.result import ModuleResult
from test_evidence_safety import _ctx
from test_followup_fixes import bundle


@pytest.fixture(params=("source", "bundle"))
def android_api(request, bundle):
    return android if request.param == "source" else bundle


@pytest.mark.parametrize("artifact", ("files", "logs", "crashes"))
@pytest.mark.parametrize("path,matched", (
    ("/data/local/tmp/Fixture", True),
    ("/data/local/tmp/fixture", False),
    ("/data/local/tmp/Fixture-extra", False),
    ("/data/local/tmp/Fixture/child", False),
    ("/data/local/tmp/fixture-extra", False),
    ("/data/local/tmp/fixture/child", False),
))
def test_android_paths_do_not_conflate_case_or_prefixes(tmp_path, monkeypatch, android_api, artifact, path, matched):
    ind = Indicator("/data/local/tmp/fixture", "artifact", "primary", "file-path", "fixture", contexts=(
        json.dumps({"case_sensitive_value": "/data/local/tmp/Fixture"}),))
    ctx = _ctx()
    ctx.iocs = IocSet([ind], "fixture", None)
    result = ModuleResult("android") if android_api is android else android_api.ModuleResult("android")
    if artifact == "files":
        (tmp_path / "files.json").write_text(json.dumps([{"path": path}]))
        android_api._an_files(result, ctx, str(tmp_path))
    elif artifact == "logs":
        (tmp_path / "logcat.txt").write_text("program=" + path + " stopped\n")
        (tmp_path / "dumpsys.txt").write_text("")
        android_api._an_device_logs(result, ctx, str(tmp_path), set())
    else:
        monkeypatch.setattr(android_api, "_an_tombstones", lambda folder: [("crash", "", path + " --arg")])
        android_api._an_crashes(result, ctx, str(tmp_path))
    assert bool(result.hits) is matched
