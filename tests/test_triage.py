"""Unit tests for the static triage layer and calibration helpers. No Ollama needed.

Run: python -m unittest test_triage -v
"""

import json
import tempfile
import unittest
from pathlib import Path

from sast_triage.calibration import LabelRecord, evaluate_run, load_labels, parse_label_line, sample_for_labeling
from sast_triage.triage import (
    ACTION_BORDERLINE,
    ACTION_DEFER,
    ACTION_ESCALATE,
    BAND_HIGH,
    BAND_LOW,
    BAND_MEDIUM,
    GUARD_HIGH_RISK_SIGNAL,
    GUARD_MISSING_CONTEXT,
    GUARD_MISSING_METADATA,
    GUARD_SEVERITY_ERROR,
    GUARD_SEVERITY_WARNING,
    SNIPPET_FILE_NOT_FOUND,
    SNIPPET_LINE_OUT_OF_RANGE,
    SNIPPET_NO_SOURCE_ROOT,
    SNIPPET_OK,
    SNIPPET_OUTSIDE_ROOT,
    FocalSnippet,
    SourceReader,
    TriageSettings,
    decide,
    normalize_finding,
    normalize_findings,
    parse_cwe_ids,
    raw_finding_key,
    run_triage,
    summarize_decisions,
)


SAFE_JAVA = """package t;
public class Safe {
    public void run() {
        String s = "constant";
        System.out.println(s);
        int x = 1 + 2;
    }
}
"""

TAINTED_SQL_JAVA = """package t;
public class Bad {
    public void doPost(HttpServletRequest request, Connection c) throws Exception {
        String param = request.getParameter("q");
        String sql = "SELECT * FROM t WHERE x='" + param + "'";
        Statement st = c.createStatement();
        st.executeQuery(sql);
    }
}
"""

DESER_JAVA = """package t;
public class Deser {
    public Object doPost(HttpServletRequest request) throws Exception {
        byte[] raw = request.getInputStream().readAllBytes();
        ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(raw));
        return in.readObject();
    }
}
"""


def make_finding(path="t/Safe.java", line=5, severity="WARNING", confidence="MEDIUM",
                 cwe=("CWE-79: XSS",), vuln_class=("Cross-Site-Scripting (XSS)",),
                 check_id="rule.xss", message="xss detected", subcategory=("vuln",), **meta_extra):
    meta = {
        "cwe": list(cwe),
        "confidence": confidence,
        "vulnerability_class": list(vuln_class),
        "subcategory": list(subcategory),
        "category": "security",
    }
    meta.update(meta_extra)
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line, "col": 9},
        "end": {"line": line, "col": 20},
        "extra": {"severity": severity, "message": message, "metadata": meta},
    }


def no_guards():
    return {k: False for k in TriageSettings().guards}


class SourceTree(unittest.TestCase):
    """Creates a small on-disk source root for snippet tests."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / "t").mkdir()
        (self.root / "t" / "Safe.java").write_text(SAFE_JAVA)
        (self.root / "t" / "Bad.java").write_text(TAINTED_SQL_JAVA)
        (self.root / "t" / "Deser.java").write_text(DESER_JAVA)
        self.reader = SourceReader(self.root)

    def tearDown(self):
        self._tmp.cleanup()


class TestNormalization(unittest.TestCase):
    def test_parse_cwe_ids(self):
        self.assertEqual(parse_cwe_ids(["CWE-89: SQLi", "cwe-79", "junk"]), [89, 79])
        self.assertEqual(parse_cwe_ids(["CWE-89", "CWE-89"]), [89])

    def test_stable_key_is_position_independent(self):
        f = make_finding()
        self.assertEqual(raw_finding_key(f), "t/Safe.java:5:9-5:20:rule.xss")
        self.assertEqual(normalize_finding(f, 0).key, normalize_finding(f, 99).key)

    def test_duplicate_keys_are_suffixed_in_order(self):
        keys = [nf.key for nf in normalize_findings([make_finding(), make_finding(), make_finding(line=6)])]
        self.assertEqual(keys, ["t/Safe.java:5:9-5:20:rule.xss",
                                "t/Safe.java:5:9-5:20:rule.xss#2",
                                "t/Safe.java:6:9-6:20:rule.xss"])

    def test_tolerates_missing_fields(self):
        nf = normalize_finding({"check_id": "r"}, 0)
        self.assertEqual(nf.path, "")
        self.assertIsNone(nf.start_line)
        self.assertIsNone(nf.severity)
        self.assertEqual(nf.cwe_ids, [])


class TestSourceReader(SourceTree):
    def test_reads_focal_snippet_with_context(self):
        snip = self.reader.focal_snippet("t/Safe.java", 5, None, context_lines=1)
        self.assertEqual(snip.status, SNIPPET_OK)
        self.assertEqual((snip.first_line, snip.last_line), (4, 6))
        self.assertIn('System.out.println', snip.text)

    def test_missing_file(self):
        self.assertEqual(self.reader.focal_snippet("t/Nope.java", 1).status, SNIPPET_FILE_NOT_FOUND)

    def test_line_out_of_range(self):
        self.assertEqual(self.reader.focal_snippet("t/Safe.java", 500).status, SNIPPET_LINE_OUT_OF_RANGE)
        self.assertEqual(self.reader.focal_snippet("t/Safe.java", None).status, SNIPPET_LINE_OUT_OF_RANGE)

    def test_path_traversal_is_blocked(self):
        outside = Path(self._tmp.name).parent / "escape.txt"
        self.assertEqual(self.reader.focal_snippet("../" + outside.name, 1).status, SNIPPET_OUTSIDE_ROOT)

    def test_no_source_root(self):
        self.assertEqual(SourceReader(None).focal_snippet("t/Safe.java", 1).status, SNIPPET_NO_SOURCE_ROOT)

    def test_unreadable_file_is_cached_as_failure(self):
        big = self.root / "t" / "Big.java"
        big.write_text("x" * 10)
        reader = SourceReader(self.root, max_bytes=5)
        self.assertEqual(reader.focal_snippet("t/Big.java", 1).status, "too_large")
        self.assertEqual(reader.focal_snippet("t/Big.java", 1).status, "too_large")


class TestEnclosingMethod(SourceTree):
    def test_grabs_whole_method_body(self):
        snip = self.reader.enclosing_method_snippet("t/Bad.java", 5)
        self.assertEqual(snip.status, SNIPPET_OK)
        self.assertTrue(snip.text.lstrip().startswith("public void doPost"))
        self.assertIn("executeQuery(sql)", snip.text)
        self.assertEqual(snip.text.count("{"), snip.text.count("}"))

    def test_climbs_past_control_blocks_to_the_method(self):
        (self.root / "t" / "Nested.java").write_text(
            "class N {\n"
            "  void handle(String p) {\n"
            "    if (p != null) {\n"
            "      for (int i = 0; i < 3; i++) {\n"
            "        sink(p);\n"           # line 5 — target
            "      }\n"
            "    }\n"
            "  }\n"
            "}\n")
        snip = self.reader.enclosing_method_snippet("t/Nested.java", 5)
        self.assertIn("void handle(String p)", snip.text)
        self.assertIn("}", snip.text.splitlines()[-1])

    def test_falls_back_to_window_when_method_too_big(self):
        body = "\n".join(f"        int v{i} = {i};" for i in range(300))
        (self.root / "t" / "Huge.java").write_text(f"class H {{\n    void big() {{\n{body}\n    }}\n}}\n")
        snip = self.reader.enclosing_method_snippet("t/Huge.java", 150, fallback_lines=10, max_method_lines=100)
        self.assertEqual(snip.status, SNIPPET_OK)
        self.assertLessEqual(snip.last_line - snip.first_line + 1, 40)

    def test_missing_file(self):
        self.assertEqual(self.reader.enclosing_method_snippet("t/Nope.java", 1).status, SNIPPET_FILE_NOT_FOUND)


class TestHardGuards(SourceTree):
    def _decide(self, finding, settings=None, allow_borderline=True):
        nf = normalize_finding(finding, 0)
        settings = settings or TriageSettings()
        snip = self.reader.focal_snippet(nf.path, nf.start_line, nf.end_line, settings.context_lines)
        method = self.reader.enclosing_method_snippet(
            nf.path, nf.start_line, nf.end_line, settings.method_context_fallback_lines)
        return decide(nf, snip, settings, allow_borderline=allow_borderline, wide_snippet=method)

    def test_error_always_escalates(self):
        d = self._decide(make_finding(severity="ERROR"))
        self.assertEqual(d.action, ACTION_ESCALATE)
        self.assertIn(GUARD_SEVERITY_ERROR, d.hard_guards)

    def test_warning_escalates_when_small_model_not_allowed(self):
        d = self._decide(make_finding(severity="WARNING", confidence="LOW"), allow_borderline=False)
        self.assertEqual(d.action, ACTION_ESCALATE)
        self.assertIn(GUARD_SEVERITY_WARNING, d.hard_guards)

    def test_weak_warning_is_borderline_when_allowed(self):
        d = self._decide(make_finding(severity="WARNING", confidence="LOW"), allow_borderline=True)
        self.assertEqual(d.action, ACTION_BORDERLINE)
        self.assertEqual(d.hard_guards, [GUARD_SEVERITY_WARNING])

    def test_high_confidence_warning_is_never_borderline(self):
        d = self._decide(make_finding(severity="WARNING", confidence="HIGH"), allow_borderline=True)
        self.assertEqual(d.action, ACTION_ESCALATE)

    def test_missing_metadata_escalates(self):
        d = self._decide(make_finding(severity="INFO", cwe=(), vuln_class=()))
        self.assertEqual(d.action, ACTION_ESCALATE)
        self.assertIn(GUARD_MISSING_METADATA, d.hard_guards)
        self.assertIn("cwe", d.missing_metadata)

    def test_unknown_severity_counts_as_missing_metadata(self):
        d = self._decide(make_finding(severity="BOGUS"))
        self.assertIn("severity", d.missing_metadata)
        self.assertEqual(d.action, ACTION_ESCALATE)

    def test_missing_context_escalates(self):
        d = self._decide(make_finding(path="t/Missing.java", severity="INFO"))
        self.assertEqual(d.action, ACTION_ESCALATE)
        self.assertIn(GUARD_MISSING_CONTEXT, d.hard_guards)
        self.assertEqual(d.snippet_status, SNIPPET_FILE_NOT_FOUND)

    def test_source_sink_combo_escalates_non_eligible_class_even_at_info(self):
        # Deserialization is not a small-model-eligible class: a visible source->sink
        # flow forces escalation regardless of severity.
        d = self._decide(make_finding(path="t/Deser.java", line=6, severity="INFO",
                                      cwe=("CWE-502: Deserialization",), vuln_class=("Deserialization",),
                                      check_id="rule.deser"))
        self.assertEqual(d.action, ACTION_ESCALATE)
        self.assertIn("guard:source_sink_combo", d.reasons)
        self.assertIn("deserialization", d.high_risk_signals)
        self.assertTrue(d.taint_source)
        self.assertTrue(d.source_sink_combo)

    def test_high_risk_signal_from_code_alone_still_detected(self):
        # Rule says XSS, but the focal code contains a SQL sink + taint source.
        d = self._decide(make_finding(path="t/Bad.java", line=6, severity="INFO"))
        self.assertIn("sql_injection", d.code_signals)
        self.assertIn(GUARD_HIGH_RISK_SIGNAL, d.hard_guards)

    def test_source_sink_combo_does_not_block_borderline_for_injection_class(self):
        # Almost every Benchmark method has a source and a sink; for injection families
        # that is exactly what the small model should judge, so combo does not escalate.
        d = self._decide(make_finding(path="t/Bad.java", line=6, severity="WARNING",
                                      confidence="LOW", vuln_class=("SQL Injection",),
                                      cwe=("CWE-89: SQLi",), check_id="rule.sqli"))
        self.assertEqual(d.action, ACTION_BORDERLINE)
        self.assertIn("class_borderline", d.reasons)
        self.assertTrue(d.source_sink_combo)
        self.assertEqual(
            self._decide(make_finding(path="t/Bad.java", line=6, severity="WARNING",
                                      confidence="LOW", vuln_class=("SQL Injection",),
                                      cwe=("CWE-89: SQLi",), check_id="rule.sqli"),
                         allow_borderline=False).action,
            ACTION_ESCALATE)

    def test_info_without_signals_defers(self):
        d = self._decide(make_finding(severity="INFO", confidence="LOW", cwe=("CWE-1: x",),
                                      vuln_class=("Other",), check_id="rule.other",
                                      message="style nit", subcategory=("audit",)))
        self.assertEqual(d.action, ACTION_DEFER)
        self.assertEqual(d.hard_guards, [])
        self.assertLess(d.score, TriageSettings().thresholds["borderline_at"])

    def test_injection_class_routes_to_small_model(self):
        for cls, cwe in [("SQL Injection", "CWE-89: x"), ("Cross-Site-Scripting (XSS)", "CWE-79: x"),
                         ("Path Traversal", "CWE-22: x"), ("Command Injection", "CWE-78: x")]:
            d = self._decide(make_finding(path="t/Bad.java", line=5, severity="WARNING",
                                          confidence="MEDIUM", vuln_class=(cls,), cwe=(cwe,),
                                          check_id="r"), allow_borderline=True)
            self.assertEqual(d.action, ACTION_BORDERLINE, cls)
            self.assertIn("class_borderline", d.reasons)

    def test_non_injection_class_still_escalates(self):
        for cls in ("Cryptographic Issues", "Insecure Hashing Algorithm", "Cookie Security"):
            d = self._decide(make_finding(path="t/Bad.java", line=5, severity="WARNING",
                                          confidence="MEDIUM", vuln_class=(cls,), cwe=("CWE-327: x",),
                                          check_id="r"), allow_borderline=True)
            self.assertEqual(d.action, ACTION_ESCALATE, cls)

    def test_borderline_max_severity_gates_error(self):
        error_sqli = make_finding(path="t/Bad.java", line=5, severity="ERROR", confidence="MEDIUM",
                                  vuln_class=("SQL Injection",), cwe=("CWE-89: x",), check_id="r")
        self.assertEqual(self._decide(error_sqli).action, ACTION_ESCALATE)  # default max = WARNING
        widened = TriageSettings(borderline_max_severity="ERROR")
        self.assertEqual(self._decide(error_sqli, widened).action, ACTION_BORDERLINE)

    def test_high_confidence_injection_never_borderline(self):
        d = self._decide(make_finding(path="t/Bad.java", line=5, severity="WARNING", confidence="HIGH",
                                      vuln_class=("SQL Injection",), cwe=("CWE-89: x",), check_id="r"))
        self.assertEqual(d.action, ACTION_ESCALATE)

    def test_custom_borderline_classes(self):
        settings = TriageSettings(borderline_classes=("deserialization",))
        d = self._decide(make_finding(path="t/Deser.java", line=5, severity="WARNING", confidence="MEDIUM",
                                      vuln_class=("Deserialization",), cwe=("CWE-502: x",), check_id="r"),
                         settings)
        self.assertEqual(d.action, ACTION_BORDERLINE)

    def test_guards_can_be_disabled(self):
        settings = TriageSettings(guards=no_guards())
        d = self._decide(make_finding(severity="ERROR", confidence="LOW", cwe=("CWE-1: x",),
                                      vuln_class=("Other",), check_id="r", message="m",
                                      subcategory=("audit",)), settings)
        self.assertEqual(d.hard_guards, [])


class TestScoreBoundaries(SourceTree):
    def _decide_with_score(self, score, allow_borderline=True):
        """Force a score by overriding every contributing weight to zero except one.

        Uses a non-borderline class so routing is driven purely by the score band.
        """
        settings = TriageSettings(guards=no_guards())
        settings.weights = {"severity:INFO": score, "confidence:LOW": 0.0, "subcategory:audit": 0.0}
        f = make_finding(severity="INFO", confidence="LOW", subcategory=("audit",),
                         cwe=("CWE-200: x",), vuln_class=("Other",), check_id="r", message="m")
        nf = normalize_finding(f, 0)
        snip = self.reader.focal_snippet(nf.path, nf.start_line, None, 1)
        method = self.reader.enclosing_method_snippet(nf.path, nf.start_line, None, 40)
        return decide(nf, snip, settings, allow_borderline=allow_borderline, wide_snippet=method)

    def test_at_escalate_threshold(self):
        d = self._decide_with_score(0.60)
        self.assertEqual((d.action, d.band), (ACTION_ESCALATE, BAND_HIGH))

    def test_just_below_escalate_threshold(self):
        d = self._decide_with_score(0.59)
        self.assertEqual((d.action, d.band), (ACTION_BORDERLINE, BAND_MEDIUM))

    def test_at_borderline_threshold(self):
        d = self._decide_with_score(0.30)
        self.assertEqual((d.action, d.band), (ACTION_BORDERLINE, BAND_MEDIUM))

    def test_just_below_borderline_threshold(self):
        d = self._decide_with_score(0.29)
        self.assertEqual((d.action, d.band), (ACTION_DEFER, BAND_LOW))

    def test_borderline_collapses_to_escalate_without_small_model(self):
        d = self._decide_with_score(0.45, allow_borderline=False)
        self.assertEqual(d.action, ACTION_ESCALATE)
        self.assertIn("small_model_disabled", d.reasons[0])

    def test_score_is_clamped_and_breakdown_is_transparent(self):
        d = self._decide_with_score(5.0)
        self.assertEqual(d.score, 1.0)
        self.assertEqual(d.score_breakdown["severity:INFO"], 5.0)

    def test_sanitizer_hint_lowers_score(self):
        (self.root / "t" / "San.java").write_text(
            "class S { void f(HttpServletResponse r, String p) {\n"
            "  r.getWriter().println(ESAPI.encoder().encodeForHTML(p));\n} }\n")
        settings = TriageSettings(guards=no_guards())
        nf = normalize_finding(make_finding(path="t/San.java", line=2), 0)
        d = decide(nf, self.reader.focal_snippet("t/San.java", 2, None, 1), settings)
        self.assertTrue(d.sanitizer_hint)
        self.assertIn("sanitizer_hint", d.score_breakdown)
        self.assertLess(d.score_breakdown["sanitizer_hint"], 0)


class TestRunAndSummary(SourceTree):
    def test_run_triage_preserves_order_and_serializes(self):
        findings = [make_finding(line=5), make_finding(path="t/Bad.java", line=6, severity="ERROR"),
                    make_finding(path="t/Missing.java")]
        run = run_triage(findings, self.root, TriageSettings())
        self.assertEqual([d.index for d in run.decisions], [0, 1, 2])
        self.assertEqual(len(run.normalized), 3)
        for d in run.decisions:
            payload = json.loads(json.dumps(d.to_dict()))
            self.assertEqual(set(payload) >= {"key", "action", "score", "band", "hard_guards", "reasons"}, True)
            self.assertNotIn("focal_code", payload)
        self.assertIn("focal_code", run.decisions[0].to_dict(include_focal_code=True))

    def test_summary_counts(self):
        findings = [make_finding(severity="ERROR"), make_finding(severity="INFO", confidence="LOW",
                    cwe=("CWE-1: x",), vuln_class=("Other",), check_id="r", message="m", subcategory=("audit",))]
        run = run_triage(findings, self.root, TriageSettings())
        s = summarize_decisions(run.decisions, run.settings, batch_size=1, elapsed_seconds=0.5)
        self.assertEqual(s["counts"][ACTION_ESCALATE], 1)
        self.assertEqual(s["counts"][ACTION_DEFER], 1)
        self.assertEqual(s["escalation_rate"], 0.5)
        self.assertEqual(s["estimated_savings"]["deep_model_calls_avoided"], 1)
        self.assertEqual(s["estimated_savings"]["tokens_avoided"], run.settings.est_tokens_per_finding)
        self.assertEqual(s["hard_guards"][GUARD_SEVERITY_ERROR], 1)
        self.assertEqual(sum(s["score_histogram"].values()), 2)

    def test_evidence_summary_mentions_guards_and_signals(self):
        run = run_triage([make_finding(path="t/Bad.java", line=6, severity="ERROR")], self.root)
        text = run.decisions[0].evidence_summary()
        self.assertIn("guards=", text)
        self.assertIn("sql_injection", text)
        self.assertIn("source_sink_combo=yes", text)


class TestLabels(unittest.TestCase):
    def test_parse_valid_and_invalid_lines(self):
        rec, err = parse_label_line('{"key": "k1", "label": "tp", "reviewed": true, "extra": 1}', 1)
        self.assertIsNone(err)
        self.assertEqual((rec.key, rec.label, rec.reviewed, rec.extra), ("k1", "TP", True, {"extra": 1}))
        self.assertEqual(parse_label_line("# comment", 2), (None, None))
        self.assertEqual(parse_label_line("", 3), (None, None))
        self.assertIsNotNone(parse_label_line('{"key": "k", "label": "MAYBE"}', 4)[1])
        self.assertIsNotNone(parse_label_line('{"label": "TP"}', 5)[1])
        self.assertIsNotNone(parse_label_line("not json", 6)[1])

    def test_load_labels_last_wins_and_reviewed_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "labels.jsonl"
            p.write_text('{"key":"a","label":"FP"}\n{"key":"a","label":"TP","reviewed":true}\n'
                         '{"key":"b","label":"FP"}\nbroken\n')
            msgs = []
            labels = load_labels(p, log=msgs.append)
            self.assertEqual({k: v.label for k, v in labels.items()}, {"a": "TP", "b": "FP"})
            self.assertTrue(any("duplicate" in m for m in msgs))
            self.assertTrue(any("line 4" in m for m in msgs))
            self.assertEqual(list(load_labels(p, reviewed_only=True, log=msgs.append)), ["a"])

    def test_missing_labels_file_is_empty(self):
        self.assertEqual(load_labels("/nonexistent/labels.jsonl", log=lambda *_: None), {})


class TestCalibration(SourceTree):
    def test_metrics_and_false_negatives(self):
        findings = [
            make_finding(line=5, severity="ERROR"),                                  # escalate, TP
            make_finding(path="t/Bad.java", line=6, severity="WARNING"),             # escalate, FP
            make_finding(line=4, severity="INFO", confidence="LOW", cwe=("CWE-1: x",),
                         vuln_class=("Other",), check_id="r1", message="m", subcategory=("audit",)),  # defer, TP
            make_finding(line=6, severity="INFO", confidence="LOW", cwe=("CWE-1: x",),
                         vuln_class=("Other",), check_id="r2", message="m", subcategory=("audit",)),  # defer, FP
        ]
        run = run_triage(findings, self.root, TriageSettings())
        keys = [d.key for d in run.decisions]
        labels = {keys[0]: LabelRecord(keys[0], "TP"), keys[1]: LabelRecord(keys[1], "FP"),
                  keys[2]: LabelRecord(keys[2], "TP"), keys[3]: LabelRecord(keys[3], "FP"),
                  "unmatched": LabelRecord("unmatched", "TP")}
        report = evaluate_run(run, labels, batch_size=2)
        m = report["metrics"]
        self.assertEqual(m["tp_recall"], 0.5)
        self.assertEqual(m["escalation_precision"], 0.5)
        self.assertEqual(m["fp_deferral_rate"], 0.5)
        self.assertEqual(m["false_negatives"], 1)
        self.assertEqual(report["false_negative_keys"], [keys[2]])
        self.assertFalse(report["deferral_gate"]["safe_to_enable_deferral"])
        self.assertEqual(report["labels"]["unmatched_keys"], 1)
        self.assertEqual(report["per_vulnerability_class"]["Other"]["deferred_tp"], 1)

    def test_gate_is_safe_when_no_tp_deferred(self):
        run = run_triage([make_finding(severity="ERROR")], self.root)
        labels = {run.decisions[0].key: LabelRecord(run.decisions[0].key, "TP")}
        self.assertTrue(evaluate_run(run, labels, 1)["deferral_gate"]["safe_to_enable_deferral"])

    def test_sampling_skips_labeled_and_is_stratified(self):
        findings = [make_finding(line=i, severity="ERROR") for i in range(2, 7)]
        run = run_triage(findings, self.root)
        existing = {run.decisions[0].key: LabelRecord(run.decisions[0].key, "TP")}
        rows = sample_for_labeling(run, per_stratum=2, seed=1, existing=existing)
        self.assertEqual(len(rows), 2)
        self.assertNotIn(run.decisions[0].key, [r["key"] for r in rows])
        self.assertEqual(rows[0]["label"], "")
        self.assertEqual(rows[0]["band"], BAND_HIGH)


if __name__ == "__main__":
    unittest.main()
