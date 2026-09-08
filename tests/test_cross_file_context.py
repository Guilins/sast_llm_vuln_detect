"""Tests for cross-file context resolution and category auto-confirm. No network."""

import tempfile
import unittest
from pathlib import Path

from sast_triage.context import ProjectIndex, expand_calls, render_cross_file

HELPERS = {
    "ThingInterface.java": (
        "package h;\npublic interface ThingInterface {\n String doSomething(String i);\n}\n"),
    "Thing1.java": (
        "package h;\npublic class Thing1 implements ThingInterface {\n"
        "  @Override\n  public String doSomething(String i) {\n    return i;\n  }\n}\n"),
    "Thing2.java": (
        "package h;\npublic class Thing2 implements ThingInterface {\n"
        "  public String doSomething(String i) {\n    return i.replaceAll(\"[^a-z]\", \"\");\n  }\n}\n"),
    "ThingFactory.java": (
        "package h;\npublic class ThingFactory {\n"
        "  public static ThingInterface createThing() {\n    return new Thing1();\n  }\n}\n"),
    "Utils.java": (
        "package h;\npublic class Utils {\n"
        "  public static String encode(String s)\n      throws Exception {\n"
        "    return java.net.URLEncoder.encode(s, \"UTF-8\");\n  }\n}\n"),
}

TESTCASE = """package t;
public class BenchmarkTest99999 {
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws Exception {
        String param = request.getParameter("p");
        h.ThingInterface thing = h.ThingFactory.createThing();
        String bar = thing.doSomething(param);
        java.sql.Statement st = getConn().createStatement();
        st.executeQuery("SELECT * FROM u WHERE x='" + bar + "'");
    }
}
"""


class CrossFileTree(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "h").mkdir()
        for name, body in HELPERS.items():
            (self.root / "h" / name).write_text(body)
        (self.root / "t").mkdir()
        (self.root / "t" / "BenchmarkTest99999.java").write_text(TESTCASE)
        self.index = ProjectIndex.build(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def test_index_finds_methods_with_multiline_signatures(self):
        self.assertIn("doPost", self.index.methods.get("BenchmarkTest99999", {}))
        self.assertIn("encode", self.index.methods.get("Utils", {}))       # signature spans 2 lines
        self.assertIn("createThing", self.index.methods.get("ThingFactory", {}))

    def test_interface_calls_resolve_to_all_implementors(self):
        bodies = self.index.lookup("ThingInterface", "doSomething")
        self.assertEqual({m.class_name for m in bodies}, {"Thing1", "Thing2"})

    def test_expand_pulls_the_helper_chain(self):
        focal = self.index.methods["BenchmarkTest99999"]["doPost"][0].body
        blocks = dict(expand_calls(focal, TESTCASE, self.index))
        self.assertIn("ThingFactory.createThing", blocks)
        self.assertIn("Thing1.doSomething", blocks)   # the one that does NOT sanitize
        self.assertIn("Thing2.doSomething", blocks)

    def test_render_is_empty_when_no_project_calls(self):
        self.assertEqual(render_cross_file("void f() { x.length(); }", "", self.index), "")

    def test_caps_are_respected(self):
        focal = self.index.methods["BenchmarkTest99999"]["doPost"][0].body
        blocks = expand_calls(focal, TESTCASE, self.index, max_methods=1)
        self.assertEqual(len(blocks), 1)


class TestAutoConfirm(unittest.TestCase):
    def test_auto_confirm_class_matching(self):
        from types import SimpleNamespace
        from sast_triage.pipeline.robust import _auto_confirm_class
        cfg = SimpleNamespace(auto_confirm_classes=("cryptographic", "hashing", "cookie"))
        self.assertTrue(_auto_confirm_class(SimpleNamespace(vulnerability_class=["Cryptographic Issues"]), cfg))
        self.assertTrue(_auto_confirm_class(SimpleNamespace(vulnerability_class=["Insecure Hashing Algorithm"]), cfg))
        self.assertFalse(_auto_confirm_class(SimpleNamespace(vulnerability_class=["SQL Injection"]), cfg))
        self.assertFalse(_auto_confirm_class(SimpleNamespace(vulnerability_class=[]),
                                             SimpleNamespace(auto_confirm_classes=())))


if __name__ == "__main__":
    unittest.main()
