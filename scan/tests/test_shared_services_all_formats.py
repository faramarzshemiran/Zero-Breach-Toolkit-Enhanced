"""A whole shared public service (github.com, t.me, a URL shortener) never loads
as a domain indicator, in any list format; specific subdomains still do."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import feeds, iocs
from test_followup_fixes import bundle
from test_stix_import import _ind, write

SHARED = ("github.com", "www.github.com", "t.me", "bit.ly", "raw.githubusercontent.com")
SPECIFIC = "attacker.blogspot.com"


@pytest.fixture(params=("source", "bundle"))
def api(request, bundle):
    return types_ns(iocs, feeds) if request.param == "source" else types_ns(bundle, bundle)


def types_ns(ioc_module, feed_module):
    import types
    return types.SimpleNamespace(load_any=ioc_module.load_any, load_list=feed_module.load_list)


def _check(loaded, skipped_expected):
    values = {i.value for i in loaded.indicators}
    assert values == {SPECIFIC}
    skipped = sum(v for e in loaded.sets for k, v in (e.get("not_applicable_to_this_scan") or {}).items()
                  if "shared public service" in k)
    assert skipped == skipped_expected
    assert not loaded.search("visit https://api.github.com/x and https://t.me/joinchat/x")
    assert [i.value for i in loaded.search("https://attacker.blogspot.com/post")] == [SPECIFIC]


def test_curated_file(tmp_path, api):
    path = tmp_path / "list.txt"
    path.write_text("".join("{}\tinfrastructure\tprimary\tfixture\n".format(v) for v in SHARED + (SPECIFIC,)))
    _check(api.load_any(str(path)), len(SHARED))


def test_stix_bundle(api):
    objects = [_ind(n, "[domain-name:value='{}']".format(v)) for n, v in enumerate(SHARED + (SPECIFIC,))]
    _check(api.load_any(write({"type": "bundle", "id": "bundle--1", "objects": objects})), len(SHARED))


@pytest.mark.parametrize("fmt", ("domains-txt", "misp-csv"))
def test_plain_lists(tmp_path, api, fmt):
    path = tmp_path / "list"
    if fmt == "domains-txt":
        path.write_text("".join(v + "\n" for v in SHARED + (SPECIFIC,)))
    else:
        path.write_text("type,value\n" + "".join("domain,{}\n".format(v) for v in SHARED + (SPECIFIC,)))
    _check(api.load_list(str(path), fmt, "fixture", ""), len(SHARED))


def test_a_list_of_only_shared_services_is_refused(tmp_path, api):
    path = tmp_path / "list.txt"
    path.write_text("github.com\tinfrastructure\tprimary\tfixture\n")
    with pytest.raises(Exception, match="no indicators"):
        api.load_any(str(path))
