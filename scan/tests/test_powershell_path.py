"""Every PowerShell launch uses the absolute System32 path and a fixed working
folder - never the bare name, which Windows resolves through the tool's own
folder and the current folder first (planted-binary attack)."""

from __future__ import annotations

import os
import ntpath
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage.modules import host, traces  # noqa: E402


class TestPowerShellLaunch(unittest.TestCase):
    def test_absolute_path_and_fixed_cwd(self):
        for exe, cwd in ((host._PS_EXE, host._PS_CWD), (traces._TR_PS_EXE, traces._TR_PS_CWD)):
            with self.subTest(exe=exe):
                self.assertTrue(ntpath.isabs(exe))
                self.assertTrue(exe.lower().endswith(os.path.join(
                    "system32", "windowspowershell", "v1.0", "powershell.exe")))
                self.assertTrue(ntpath.isabs(cwd))

    def test_traces_passes_the_absolute_path_and_cwd(self):
        seen = {}

        def fake_run(args, **kw):
            seen["args"], seen["cwd"] = args, kw.get("cwd")
            raise OSError("not really running")
        with patch.object(traces.subprocess, "run", fake_run):
            traces._tr_ps_json("Get-Date")
        self.assertEqual(seen["args"][0], traces._TR_PS_EXE)
        self.assertEqual(seen["cwd"], traces._TR_PS_CWD)


if __name__ == "__main__":
    unittest.main()
