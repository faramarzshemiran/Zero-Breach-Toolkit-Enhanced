"""zbtriage/heuristics.py must stay DATA: it names download tools as patterns to
look for, so it is exempt from the module network-tool guard - and that exemption
is only safe while the file can never run anything."""

from __future__ import annotations

import ast
import os
import unittest

PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "zbtriage", "heuristics.py")


class TestHeuristicsIsDataOnly(unittest.TestCase):
    def test_imports_only_re_and_calls_only_re_compile(self):
        tree = ast.parse(open(PATH, encoding="utf-8").read())
        imports = [n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]
        self.assertEqual([[a.name for a in n.names] for n in imports], [["re"]])
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # ast.unparse is Python 3.9+; compare the call target directly.
                func = node.func
                name = (func.value.id + "." + func.attr
                        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) else "")
                self.assertEqual(name, "re.compile", "heuristics.py may only compile patterns")
        for node in tree.body:
            self.assertIsInstance(node, (ast.Expr, ast.Import, ast.Assign))


if __name__ == "__main__":
    unittest.main()
