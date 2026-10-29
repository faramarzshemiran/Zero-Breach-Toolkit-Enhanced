"""The single-file build puts every bundled module into ONE namespace.

Two modules defining the same top-level name means the later one silently
replaces the earlier one in the single-file build only. For example,
feeds.py's _sha256(bytes) was replaced by hashscan.py's
_sha256(path), so the single-file build crashed for anyone who had run
--update; and stix.py's 64 MB MAX_BYTES became hashscan's 120 MB. The package
version was fine both times, so ordinary tests could not see it.
"""

from __future__ import annotations

import ast
import collections
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from zbtriage.readers import READER_SPECS
ALLOWED = {"NAME", "run"}         # renamed per module by build/bundle.py namespace()


def bundled_files():
    src = open(os.path.join(REPO, "build", "bundle.py"), encoding="utf-8").read()
    names = re.findall(r'\("[^"]+", "([a-z_]+\.py)"(?:, "[a-z]+")?\)', src)
    out = []
    for name in names:
        for base in ("zbtriage", os.path.join("zbtriage", "modules")):
            path = os.path.join(HERE, base, name)
            if os.path.isfile(path):
                out.append(path)
                break
    for spec in READER_SPECS:
        out.append(os.path.join(HERE, "zbtriage", "modules", spec.module + ".py"))
        out.extend(os.path.join(HERE, "zbtriage", helper) for helper in spec.helpers)
    return list(dict.fromkeys(out))


class TestNoNameCollisions(unittest.TestCase):
    def test_bundle_lists_every_module_it_needs(self):
        files = bundled_files()
        self.assertGreaterEqual(len(files), 17)
        for module in ("feeds.py", "stix.py", "traces.py", "android.py", "heuristics.py"):
            self.assertIn(module, [os.path.basename(f) for f in files])

    def test_no_top_level_name_defined_twice(self):
        defined = collections.defaultdict(list)
        for path in bundled_files():
            tree = ast.parse(open(path, encoding="utf-8").read())
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                    names = [node.name]
                elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    names = [t.id for t in targets if isinstance(t, ast.Name)]
                else:
                    names = []
                for name in names:
                    if name not in ALLOWED:
                        defined[name].append(os.path.basename(path))
        clashes = {n: f for n, f in defined.items() if len(f) > 1}
        self.assertEqual(clashes, {}, "rename these so the single-file build keeps both")


if __name__ == "__main__":
    unittest.main()
