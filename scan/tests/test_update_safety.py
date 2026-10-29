"""Indicator updates refuse a sudden collapse in a source's count, every list
format drops whole shared services, PowerShell loads only Windows' modules,
and update requests carry a generic user agent."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import feeds
from zbtriage.modules import host


def _src(fmt="domains-txt"):
    return {"id": "t", "name": "T", "url": "https://raw.githubusercontent.com/x/y/main/t.txt",
            "format": fmt, "cite": "c", "category": "mercenary", "family": "f"}


def _body(n):
    return "".join("bad{}.example\n".format(i) for i in range(n)).encode()


def test_update_refuses_a_collapsed_list_and_keeps_the_previous(tmp_path):
    cache = str(tmp_path)
    first = feeds.update(cache, [_src()], fetch=lambda u: _body(100))
    assert first["failed"] == 0
    second = feeds.update(cache, [_src()], fetch=lambda u: _body(10))
    entry = second["sources"][0]
    assert entry["status"] == "failed" and entry["kept_previous"]
    assert "fell from 100 to 10" in entry["error"]
    assert feeds.read_manifest(cache)["t"]["indicators"] == 100


def test_update_accepts_ordinary_changes(tmp_path):
    cache = str(tmp_path)
    feeds.update(cache, [_src()], fetch=lambda u: _body(100))
    assert feeds.update(cache, [_src()], fetch=lambda u: _body(70))["failed"] == 0


def test_every_list_format_drops_shared_services(tmp_path):
    lists = {
        "domains-txt": "github.com\nt.me\nreal-bad.example\n",
        "csv-domain-ip": "domain_name,ip_address\ngithub.com,\nt.me,\nreal-bad.example,\n",
        "misp-csv": "type,value\ndomain,github.com\nurl,https://t.me/x\ndomain,real-bad.example\n",
    }
    for fmt, text in lists.items():
        path = tmp_path / (fmt + ".txt")
        path.write_text(text)
        values = {i.value for i in feeds.load_list(str(path), fmt, "s", "f").indicators}
        assert values == {"real-bad.example"}, (fmt, values)


@pytest.mark.skipif(sys.platform != "win32", reason="PowerShell module path is Windows-only")
def test_powershell_loads_only_windows_modules():
    env = host.powershell_env()
    assert env["PSModulePath"].endswith(os.path.join("System32", "WindowsPowerShell", "v1.0", "Modules"))
    assert os.pathsep not in env["PSModulePath"]


def test_update_request_uses_a_generic_user_agent(monkeypatch):
    seen = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return b"x.example\n"

    class _Opener:
        def open(self, req, timeout):
            seen["ua"] = req.get_header("User-agent")
            return _Resp()

    monkeypatch.setattr(feeds.urllib.request, "build_opener", lambda *a: _Opener())
    feeds._fetch(feeds.SOURCES[0]["url"])
    assert seen["ua"] == "Mozilla/5.0"


def test_interrupted_update_keeps_finished_sources_usable(tmp_path):
    cache = str(tmp_path)
    a, b = dict(_src(), id="a"), dict(_src(), id="b")
    feeds.update(cache, [a, b], fetch=lambda u: _body(30))

    def fetch(url, calls=[]):
        calls.append(url)
        if len(calls) == 2:
            raise KeyboardInterrupt
        return _body(40)

    try:
        feeds.update(cache, [a, b], fetch=fetch)
    except KeyboardInterrupt:
        pass
    manifest = feeds.read_manifest(cache)
    assert manifest["a"]["indicators"] == 40 and manifest["b"]["indicators"] == 30
    for sid in ("a", "b"):
        entry = manifest[sid]
        with open(os.path.join(cache, entry["file"]), "rb") as fh:
            assert feeds._feed_sha256(fh.read()) == entry["sha256"]


def test_a_genuine_shrink_can_be_accepted_for_that_source_only(tmp_path):
    cache = str(tmp_path)
    feeds.update(cache, [_src()], fetch=lambda u: _body(100))
    refused = feeds.update(cache, [_src()], fetch=lambda u: _body(10))
    assert refused["failed"] == 1 and "--accept-shrink t" in refused["sources"][0]["error"]
    accepted = feeds.update(cache, [_src()], fetch=lambda u: _body(40), accept_shrink=["t"])
    assert accepted["failed"] == 0
    assert feeds.read_manifest(cache)["t"]["indicators"] == 40
    other = feeds.update(cache, [_src()], fetch=lambda u: _body(10), accept_shrink=["someone-else"])
    assert other["failed"] == 1


def test_accept_shrink_with_an_unknown_source_is_an_error(tmp_path, capsys):
    assert feeds.update_command(str(tmp_path), None, ["no-such-source"]) == 1
    assert "unknown source id" in capsys.readouterr().err


def test_no_network_request_names_the_tool():
    import glob
    import re
    root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "zbtriage")
    for path in glob.glob(os.path.join(root, "**", "*.py"), recursive=True):
        text = open(path, encoding="utf-8").read()
        for agent in re.findall(r'"User-Agent":\s*"([^"]*)"', text):
            assert "zero" not in agent.lower() and "breach" not in agent.lower(), (path, agent)
