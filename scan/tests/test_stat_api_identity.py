"""Windows Python 3.12+ reports a different st_ctime_ns from stat and fstat for the
same unchanged file. Evidence export must not refuse every file because of it,
and must still refuse a file that really changed."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_handoff import handoff_api, handoff_document  # noqa: F401 (fixture)
from test_followup_fixes import bundle  # noqa: F401 (fixture)


class _Shifted:
    """An fstat result whose ctime differs, as Windows Python 3.12+ reports it."""

    def __init__(self, info, ctime_shift=1_000_000, size_shift=0):
        self._info, self._ctime, self._size = info, ctime_shift, size_shift

    def __getattr__(self, name):
        value = getattr(self._info, name)
        if name == "st_ctime_ns":
            return value + self._ctime
        if name == "st_size":
            return value + self._size
        return value


@pytest.mark.parametrize("size_shift,exported", ((0, True), (1, False)))
def test_export_tolerates_cross_api_ctime_but_not_real_change(tmp_path, monkeypatch, handoff_api, size_shift, exported):
    source = tmp_path / "selected.bin"
    source.write_bytes(b"selected evidence")
    real_fstat = os.fstat
    monkeypatch.setattr(os, "fstat", lambda fd: _Shifted(real_fstat(fd), size_shift=size_shift))
    output = tmp_path / "handoff.zip"
    if exported:
        handoff_api.handoff_write(handoff_document(), output, [source])
        assert output.exists()
    else:
        with pytest.raises(ValueError):
            handoff_api.handoff_write(handoff_document(), output, [source])
        assert not output.exists()
    assert source.read_bytes() == b"selected evidence"
