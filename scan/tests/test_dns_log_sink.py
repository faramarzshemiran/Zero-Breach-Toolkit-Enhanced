"""A DNS-Client event answered only with block addresses is an attempt that a
filter stopped, the same judgement the resolver-cache check makes."""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage.context import ScanContext
from zbtriage.iocs import Indicator, IocSet
from zbtriage.modules import host
from zbtriage.result import ModuleResult

BAD = "bad-c2.example"


def _run(message):
    ctx = ScanContext(iocs=IocSet([Indicator(BAD, "cc", "primary", "domain", "test")], "t", None),
                      emit=lambda _m: None)
    r = ModuleResult("host")
    with patch.object(host, "_ps_json", side_effect=[
            ([{"IsEnabled": True, "RecordCount": 1}], ""),
            ([{"Time": "2026-10-01T10:00:00Z", "Message": message}], "")]):
        host._check_dns_log(r, ctx)
    return [h.evidence for h in r.hits]


def test_blocked_answer_is_attempted():
    msg = "DNS query is completed for the name " + BAD + ", type 1, response status 0, results ::ffff:0.0.0.0;"
    assert _run(msg) == ["attempted"]


def test_real_answer_stays_a_dns_record():
    msg = "DNS query is completed for the name " + BAD + ", type 1, response status 0, results 203.0.113.9;"
    assert _run(msg) == ["dns-record"]


def test_mixed_or_missing_results_stay_a_dns_record():
    assert _run("DNS query for " + BAD) == ["dns-record"]
    msg = "results 0.0.0.0;203.0.113.9; for " + BAD
    assert _run(msg) == ["dns-record"]
