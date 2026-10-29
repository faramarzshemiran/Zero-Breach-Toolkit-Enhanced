"""Two things people hit on a Mac.

The python.org installer leaves Python without website certificates until its
Install Certificates step runs, so every indicator download failed with a
cryptic CERTIFICATE_VERIFY_FAILED line per source. The update now stops at the
first such failure, keeps the previous lists and says how to fix it.

When the final menu could read no input (end of input), the toolkit closed
without a word and people thought their report was saved. It now says nothing
was saved."""
import contextlib
import io
import ssl
import sys
import urllib.error
from unittest.mock import patch

from zbtriage import cli, feeds, workflow
from test_workflow import Terminal, wf_document

SRC = {"id": "test-src", "name": "Test source", "format": "stix2", "cite": "Test",
       "category": "mercenary", "family": "",
       "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/x/test.stix2"}


def _cert_failure(url):
    raise urllib.error.URLError(ssl.SSLCertVerificationError(
        1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"))


def test_certificate_failure_stops_with_the_fix(tmp_path, monkeypatch):
    calls = []

    def fetch(url):
        calls.append(url)
        _cert_failure(url)

    monkeypatch.setattr(feeds.sys, "platform", "darwin")
    try:
        feeds.update(str(tmp_path), sources=[SRC, dict(SRC, id="second")], fetch=fetch)
    except feeds.IocError as exc:
        message = str(exc)
    else:
        raise AssertionError("expected the update to stop")
    assert len(calls) == 1
    assert "Install Certificates.command" in message and "previous indicator lists were kept" in message


def test_update_command_prints_the_fix(tmp_path, monkeypatch):
    real_update = feeds.update
    # update() binds its downloader as a default argument: inject the failure
    # there, so this test never reaches the network.
    monkeypatch.setattr(feeds, "update", lambda *a, **k: real_update(*a, fetch=_cert_failure, **k))
    monkeypatch.setattr(feeds, "SOURCES", [SRC])
    monkeypatch.setattr(feeds.sys, "platform", "darwin")
    err = io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
        code = feeds.update_command(str(tmp_path), None)
    assert code == 1
    assert "Install Certificates" in err.getvalue()


def test_other_download_failures_still_continue(tmp_path):
    def fetch(url):
        raise urllib.error.URLError("network unreachable")
    summary = feeds.update(str(tmp_path), sources=[SRC, dict(SRC, id="second")], fetch=fetch)
    assert summary["failed"] == 2


def test_menu_says_nothing_was_saved_when_no_input_arrives():
    err = Terminal()
    with patch.object(sys, "stdin", Terminal("")), patch.object(sys, "stderr", err):
        workflow.workflow_menu(wf_document(), cli._parse([]))
    assert "nothing was saved" in err.getvalue()


def test_choosing_finish_stays_quiet():
    err = Terminal()
    with patch.object(sys, "stdin", Terminal("0\n")), patch.object(sys, "stderr", err):
        workflow.workflow_menu(wf_document(), cli._parse([]))
    assert "nothing was saved" not in err.getvalue()
