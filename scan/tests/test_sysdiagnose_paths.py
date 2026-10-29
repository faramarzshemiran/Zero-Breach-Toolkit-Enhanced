"""A re-packed sysdiagnose archive ("./" member names) is read; escapes are not."""
import io
import os
import sys
import tarfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import ios_sources
from zbtriage.modules import ios

IPS = b'{"bug_type":"109","procName":"x"}\n'


def _archive(tmp_path, names):
    path = tmp_path / "sysdiagnose.tar.gz"
    with tarfile.open(path, "w:gz") as tf:
        for name in names:
            info = tarfile.TarInfo(name)
            info.size = len(IPS)
            tf.addfile(info, io.BytesIO(IPS))
    return str(path)


def _read(tmp_path, names):
    gaps = []
    source = ios_sources.IosEvidenceSource(_archive(tmp_path, names), "sysdiagnose", "",
                                           lambda _c, reason: gaps.append(reason), lambda _m: None,
                                           ios._ios_read, None, None, None)
    source.tmp = str(tmp_path / "work")
    os.makedirs(source.tmp)
    source._archive()
    return source, gaps


def test_dot_slash_members_are_read_under_their_plain_name(tmp_path):
    source, gaps = _read(tmp_path, ["./sysdiagnose_1/crashes_and_spins/a.ips"])
    assert source.entries == [("", "sysdiagnose_1/crashes_and_spins/a.ips")]
    assert source.provenance[("", "sysdiagnose_1/crashes_and_spins/a.ips")]["member"] == \
        "sysdiagnose_1/crashes_and_spins/a.ips"
    assert not gaps


def test_escapes_are_still_refused(tmp_path):
    source, gaps = _read(tmp_path, ["../a.ips", "./../b.ips", "./sysdiagnose_1/../c.ips", "/abs/d.ips"])
    assert source.entries == []
    assert len(gaps) == 4


def test_a_dot_slash_copy_of_a_member_is_a_duplicate(tmp_path):
    source, gaps = _read(tmp_path, ["sysdiagnose_1/a.ips", "./sysdiagnose_1/a.ips"])
    assert source.entries == []
    assert any("duplicate" in g for g in gaps)
