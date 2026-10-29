"""The welcome banner: shown to people, never to scripts or AI assistants.

Pinned here:
  - it is written only when stderr is a terminal, never into redirected output;
  - --describe output stays pure JSON, and --no-banner turns it off;
  - no colour codes without a terminal, or with NO_COLOR set;
  - a narrow window gets the compact lettering, and no line overflows it.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import banner, cli  # noqa: E402


class FakeTerminal(io.StringIO):
    def isatty(self):
        return True


class TestRender(unittest.TestCase):
    def test_wide_and_narrow(self):
        wide = banner.render_banner("0.1.0", width=120)
        self.assertIn("███████╗", wide)
        self.assertIn("by archivegenocide", wide)
        self.assertIn("v0.1.0", wide)
        narrow = banner.render_banner("0.1.0", width=60)
        self.assertNotIn("███████╗", narrow)
        self.assertIn("▀▀█", narrow)
        for line in narrow.splitlines():
            self.assertLessEqual(len(line), 60, line)
        for line in wide.splitlines():
            self.assertLessEqual(len(line), 120, line)

    def test_no_colour_codes_unless_asked(self):
        self.assertNotIn("\x1b[", banner.render_banner("0.1.0", width=120, color=False))
        self.assertIn("\x1b[38;2;", banner.render_banner("0.1.0", width=120, color=True))


class TestWhenShown(unittest.TestCase):
    def test_not_a_terminal_means_no_banner(self):
        out = io.StringIO()
        self.assertFalse(banner.show_banner("0.1.0", stream=out))
        self.assertEqual(out.getvalue(), "")

    def test_terminal_gets_it_and_no_color_is_respected(self):
        term = FakeTerminal()
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            self.assertTrue(banner.show_banner("0.1.0", stream=term))
        self.assertIn("archivegenocide", term.getvalue())
        self.assertNotIn("\x1b[", term.getvalue())

    def test_describe_stays_pure_json(self):
        out, err = io.StringIO(), FakeTerminal()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(cli.main(["--describe"]), 0)
        json.loads(out.getvalue())
        self.assertEqual(err.getvalue(), "")

    def test_no_banner_flag(self):
        err = FakeTerminal()
        with patch.object(cli, "_run_modules", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            cli.main(["--no-banner", "--no-feeds"])
        self.assertNotIn("archivegenocide", err.getvalue())


if __name__ == "__main__":
    unittest.main()
