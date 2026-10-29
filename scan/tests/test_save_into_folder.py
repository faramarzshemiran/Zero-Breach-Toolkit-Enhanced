"""Typing a folder at "Save to a local path" asked to replace it and then failed
with WinError 5 / Errno 13. A folder now means: save inside it under a dated
name. A location Windows will not let you write to is explained plainly."""
import io
import os
import sys
from unittest.mock import patch

from zbtriage import cli, workflow
from test_workflow import Terminal, wf_document


def _menu(keys):
    err = io.StringIO()
    with patch.object(sys, "stdin", Terminal(keys)), patch.object(sys, "stderr", err):
        workflow.workflow_menu(wf_document(), cli._parse([]))
    return err.getvalue()


def test_report_and_summary_saved_inside_a_folder(tmp_path):
    out = _menu("3\n{0}\n4\n{0}\n0\n".format(tmp_path))
    names = sorted(os.listdir(tmp_path))
    assert any(n.startswith("zero-breach-report-") and n.endswith(".txt") for n in names), out
    assert any(n.startswith("zero-breach-summary-") and n.endswith(".json") for n in names), out
    assert "Replace the existing file" not in out and "Could not complete" not in out


def test_unwritable_location_is_explained(tmp_path, monkeypatch):
    def refuse(text, path):
        raise PermissionError(13, "Permission denied")
    monkeypatch.setattr(workflow, "workflow_write_text", refuse)
    out = _menu("3\n{}\n0\n".format(tmp_path))
    assert "Documents or Desktop" in out and "administrator" in out
