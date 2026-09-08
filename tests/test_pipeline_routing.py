"""Routing, progress and reassembly tests with mocked models. No Ollama needed.

Run: python -m unittest test_pipeline_routing -v
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

from sast_triage.config import PipelineConfig
from sast_triage.pipeline import (
    PROGRESS_SCHEMA,
    ProgressState,
    load_progress,
    save_progress,
    analyze_escalated,
    answer_question,
    assemble_output,
    export_highest_ai_confidence_findings,
    route_findings,
)
from sast_triage.screening import (
    DECISION_DISMISS,
    DECISION_ESCALATE,
    DECISION_UNCERTAIN,
    parse_small_model_response,
    screen_one,
)
from sast_triage.triage import ACTION_DEFER, ACTION_ESCALATE, TriageSettings, normalize_finding, run_triage

from test_triage import SAFE_JAVA, TAINTED_SQL_JAVA, make_finding, no_guards


class _Reply:
    def __init__(self, content):
        self.content = content


class FakeRobustLLM:
    """Returns one analysis object per slim finding, echoing the batch size."""

    def __init__(self, verdict="True Positive", confidence="high", fail_batches=(), mode="ok"):
        self.calls = []
        self.verdict = verdict
        self.confidence = confidence
        self.fail_batches = set(fail_batches)
        self.mode = mode

    def invoke(self, messages):
        system = messages[0].content
        # The slim batch is embedded as JSON in the system prompt.
        start = system.index('{"results": [')
        depth, i = 0, start
        while True:
            depth += {"{": 1, "}": -1}.get(system[i], 0)
            i += 1
            if depth == 0:
                break
        batch = json.loads(system[start:i])["results"]
        self.calls.append({"n": len(batch), "prompt": system})
        call_no = len(self.calls)
        if call_no in self.fail_batches:
            raise RuntimeError("request timed out")
        if self.mode == "garbage":
            return _Reply("I refuse to answer in JSON.")
        items = [{"analysis": {"verdict": self.verdict, "confidence": self.confidence,
                               "severity_assessment": "high", "root_cause": f"rc{k}",
                               "impact": "", "remediation": [], "code_context": "", "additional_notes": ""}}
                 for k in range(len(batch))]
        return _Reply(json.dumps(items))


def small_invoke_factory(reply):
    """Build a small-model invoke stub: reply may be a string, an exception, or a callable."""
    calls = []

    def _invoke(llm, prompt):
        calls.append(prompt)
        if isinstance(reply, BaseException):
            raise reply
        if callable(reply):
            return reply(prompt)
        return reply

    _invoke.calls = calls
    return _invoke


class PipelineTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        (self.tmp / "src" / "t").mkdir(parents=True)
        (self.tmp / "src" / "t" / "Safe.java").write_text(SAFE_JAVA)
        (self.tmp / "src" / "t" / "Bad.java").write_text(TAINTED_SQL_JAVA)
        self.config = PipelineConfig(
            source_root=self.tmp / "src",
            semgrep_input=self.tmp / "semgrep.json",
            output_file=self.tmp / "out.json",
            progress_file=self.tmp / "progress.json",
            triage_report_file=self.tmp / "triage_report.json",
            labels_file=self.tmp / "labels.jsonl",
            batch_size=2,
            max_retries=1,
        )
        self._cwd = os.getcwd()
        os.chdir(self.tmp)  # raw batch dumps land here, not in the repo

    def tearDown(self):
        os.chdir(self._cwd)
        self._tmp.cleanup()

    def write_semgrep(self, findings):
        with open(self.config.semgrep_input, "w") as f:
            json.dump({"version": "1.0", "results": findings}, f)

    @staticmethod
    def escalate_finding(line=5):
        return make_finding(line=line, severity="ERROR")

    @staticmethod
    def deferrable_finding(line=4, check_id="r.low"):
        return make_finding(line=line, severity="INFO", confidence="LOW", cwe=("CWE-1: x",),
                            vuln_class=("Other",), check_id=check_id, message="m", subcategory=("audit",))

    @staticmethod
    def borderline_finding(line=5, check_id="r.warn"):
        return make_finding(line=line, severity="WARNING", confidence="LOW", check_id=check_id)


class TestSmallModelParsing(unittest.TestCase):
    def test_valid_decisions(self):
        for word in (DECISION_ESCALATE, DECISION_DISMISS, DECISION_UNCERTAIN):
            decision, reason, err = parse_small_model_response(f'{{"decision": "{word}", "reason": "r"}}')
            self.assertEqual((decision, reason, err), (word, "r", None))

    def test_case_and_fences_tolerated(self):
        decision, _, err = parse_small_model_response('```json\n{"decision": "Dismiss"}\n```')
        self.assertEqual((decision, err), (DECISION_DISMISS, None))

    def test_invalid_inputs_fail_closed(self):
        for raw in ("", "   ", "yes", '{"decision": "maybe"}', '{"verdict": "dismiss"}', "[1,2]", '{"decision": 3}'):
            decision, _, err = parse_small_model_response(raw)
            self.assertEqual(decision, DECISION_ESCALATE, raw)
            self.assertIsNotNone(err, raw)

    def test_screen_one_swallows_exceptions(self):
        nf = normalize_finding(make_finding(), 0)
        from sast_triage.triage import FocalSnippet, decide
        d = decide(nf, FocalSnippet("ok", "code", 1, 1), TriageSettings())
        verdict = screen_one(None, nf, d, invoke=small_invoke_factory(TimeoutError("read timed out")))
        self.assertEqual(verdict.decision, DECISION_ESCALATE)
        self.assertTrue(verdict.failed_closed)
        self.assertTrue(verdict.error.startswith("timeout"))


class TestRouting(PipelineTestCase):
    def test_small_model_disabled_escalates_borderline(self):
        run = route_findings([self.borderline_finding()], self.config, log=lambda *a, **k: None)
        self.assertEqual(run.decisions[0].action, ACTION_ESCALATE)
        self.assertIn("small_model_disabled", run.decisions[0].reasons)

    def test_deferral_disabled_escalates_static_defer(self):
        run = route_findings([self.deferrable_finding()], self.config, log=lambda *a, **k: None)
        self.assertEqual(run.decisions[0].action, ACTION_ESCALATE)
        self.assertIn("static_would_defer_but_deferral_disabled", run.decisions[0].reasons)

    def test_deferral_enabled_keeps_static_defer(self):
        cfg = self.config.with_overrides(enable_deferral=True)
        run = route_findings([self.deferrable_finding()], cfg, log=lambda *a, **k: None)
        self.assertEqual(run.decisions[0].action, ACTION_DEFER)

    def test_small_model_dismiss_defers_only_with_deferral_enabled(self):
        invoke = small_invoke_factory('{"decision": "dismiss", "reason": "constant input"}')
        quiet = lambda *a, **k: None  # noqa: E731

        cfg = self.config.with_overrides(enable_small_model=True, enable_deferral=False)
        run = route_findings([self.borderline_finding()], cfg, small_llm=object(), small_invoke=invoke, log=quiet)
        d = run.decisions[0]
        self.assertEqual(d.action, ACTION_ESCALATE)
        self.assertEqual(d.small_model["decision"], DECISION_DISMISS)
        self.assertIn("small_model_dismissed_but_deferral_disabled", d.reasons)

        cfg = self.config.with_overrides(enable_small_model=True, enable_deferral=True)
        run = route_findings([self.borderline_finding()], cfg, small_llm=object(), small_invoke=invoke, log=quiet)
        self.assertEqual(run.decisions[0].action, ACTION_DEFER)
        self.assertIn("small_model_dismissed", run.decisions[0].reasons)

    def test_small_model_uncertain_and_escalate_escalate(self):
        cfg = self.config.with_overrides(enable_small_model=True, enable_deferral=True)
        for word in (DECISION_UNCERTAIN, DECISION_ESCALATE):
            invoke = small_invoke_factory(f'{{"decision": "{word}"}}')
            run = route_findings([self.borderline_finding()], cfg, small_llm=object(),
                                 small_invoke=invoke, log=lambda *a, **k: None)
            self.assertEqual(run.decisions[0].action, ACTION_ESCALATE, word)
            self.assertIn(f"small_model_{word}", run.decisions[0].reasons)

    def test_small_model_failures_fail_closed(self):
        cfg = self.config.with_overrides(enable_small_model=True, enable_deferral=True)
        for reply in (RuntimeError("boom"), TimeoutError("timed out"), "", "not json", '{"decision": "nope"}'):
            invoke = small_invoke_factory(reply)
            run = route_findings([self.borderline_finding()], cfg, small_llm=object(),
                                 small_invoke=invoke, log=lambda *a, **k: None)
            d = run.decisions[0]
            self.assertEqual(d.action, ACTION_ESCALATE, repr(reply))
            self.assertIn("small_model_failed_closed", d.reasons, repr(reply))
            self.assertIsNotNone(d.small_model["error"])

    def test_small_model_prompt_carries_code_and_evidence(self):
        cfg = self.config.with_overrides(enable_small_model=True)
        invoke = small_invoke_factory('{"decision": "uncertain"}')
        route_findings([self.borderline_finding()], cfg, small_llm=object(), small_invoke=invoke,
                       log=lambda *a, **k: None)
        prompt = invoke.calls[0]
        self.assertIn("System.out.println", prompt)
        self.assertIn("static_score=", prompt)
        self.assertIn('"rule":"r.warn"', prompt)

    def test_small_model_verdicts_are_cached_in_progress(self):
        cfg = self.config.with_overrides(enable_small_model=True)
        progress = ProgressState(cfg.fingerprint())
        invoke = small_invoke_factory('{"decision": "uncertain"}')
        route_findings([self.borderline_finding()], cfg, progress, small_llm=object(),
                       small_invoke=invoke, log=lambda *a, **k: None)
        self.assertEqual(len(invoke.calls), 1)
        self.assertEqual(len(progress.small_model), 1)

        invoke2 = small_invoke_factory('{"decision": "dismiss"}')
        run = route_findings([self.borderline_finding()], cfg, progress, small_llm=object(),
                             small_invoke=invoke2, log=lambda *a, **k: None)
        self.assertEqual(len(invoke2.calls), 0)  # cached verdict reused, no new call
        self.assertEqual(run.decisions[0].small_model["decision"], DECISION_UNCERTAIN)


class TestProgress(PipelineTestCase):
    def test_roundtrip(self):
        state = ProgressState("fp1", {"k": {"verdict": "x"}}, ["f"], {"k2": {"decision": "dismiss"}})
        save_progress(self.config.progress_file, state)
        loaded = load_progress(self.config.progress_file, "fp1", log=lambda *a: None)
        self.assertEqual(loaded.to_dict(), state.to_dict())
        self.assertFalse(self.config.progress_file.with_suffix(".json.tmp").exists())

    def test_fingerprint_mismatch_starts_fresh(self):
        save_progress(self.config.progress_file, ProgressState("old", {"k": {}}))
        msgs = []
        loaded = load_progress(self.config.progress_file, "new", log=msgs.append)
        self.assertEqual(loaded.completed, {})
        self.assertTrue(any("fingerprint" in m for m in msgs))

    def test_legacy_batch_schema_is_ignored(self):
        with open(self.config.progress_file, "w") as f:
            json.dump({"completed_batches": {"1": [{"analysis": {}}]}, "failed_batches": []}, f)
        loaded = load_progress(self.config.progress_file, "fp", log=lambda *a: None)
        self.assertEqual(loaded.completed, {})

    def test_corrupt_file_starts_fresh(self):
        self.config.progress_file.write_text("{not json")
        loaded = load_progress(self.config.progress_file, "fp", log=lambda *a: None)
        self.assertEqual(loaded.completed, {})

    def test_fingerprint_tracks_routing_settings_only(self):
        base = self.config.fingerprint()
        self.assertEqual(self.config.with_overrides(timeout=1).fingerprint(), base)
        self.assertEqual(self.config.with_overrides(output_file=self.tmp / "x.json").fingerprint(), base)
        self.assertEqual(self.config.with_overrides(batch_size=3).fingerprint(), base)  # execution detail
        self.assertNotEqual(self.config.with_overrides(enable_small_model=True).fingerprint(), base)
        self.assertNotEqual(self.config.with_overrides(robust_model="other").fingerprint(), base)
        tuned = self.config.with_overrides(triage=TriageSettings(thresholds={"escalate_at": 0.9, "borderline_at": 0.1}))
        self.assertNotEqual(tuned.fingerprint(), base)
        self.assertEqual(PROGRESS_SCHEMA, 2)


class TestDeepAnalysisAndAssembly(PipelineTestCase):
    def test_results_keyed_and_resumable(self):
        findings = [self.escalate_finding(5), self.escalate_finding(6), self.escalate_finding(7)]
        run = route_findings(findings, self.config, log=lambda *a, **k: None)
        progress = ProgressState(self.config.fingerprint())
        llm = FakeRobustLLM()
        stats = analyze_escalated(llm, findings, run, self.config, progress, log=lambda *a, **k: None)
        self.assertEqual([c["n"] for c in llm.calls], [2, 1])
        self.assertEqual(stats["analysed"], 3)
        self.assertEqual(set(progress.completed), {d.key for d in run.decisions})
        self.assertIn("[1] static_score=", llm.calls[0]["prompt"])

        # Second run: nothing pending, no calls.
        llm2 = FakeRobustLLM()
        reloaded = load_progress(self.config.progress_file, self.config.fingerprint(), log=lambda *a: None)
        stats2 = analyze_escalated(llm2, findings, run, self.config, reloaded, log=lambda *a, **k: None)
        self.assertEqual(llm2.calls, [])
        self.assertEqual(stats2["pending"], 0)

    def test_timeouts_are_retried_in_sub_batches_then_marked_failed(self):
        findings = [self.escalate_finding(i) for i in range(2, 8)]  # 6 findings, batches of 2
        run = route_findings(findings, self.config, log=lambda *a, **k: None)
        progress = ProgressState(self.config.fingerprint())
        # Call 2 (second batch) fails on its only attempt; the sub-batch retry (call 4) succeeds.
        llm = FakeRobustLLM(fail_batches={2})
        stats = analyze_escalated(llm, findings, run, self.config, progress, log=lambda *a, **k: None)
        self.assertEqual(stats["batch_failures"], 1)
        self.assertEqual(stats["retried_sub_batches"], 1)
        self.assertEqual(stats["unanalysed"], 0)
        self.assertTrue(any(p.name.startswith("llm_analysis_raw_batch_") for p in self.tmp.iterdir()))

    def test_persistent_failure_leaves_finding_without_analysis(self):
        findings = [self.escalate_finding(5)]
        run = route_findings(findings, self.config, log=lambda *a, **k: None)
        progress = ProgressState(self.config.fingerprint())
        llm = FakeRobustLLM(mode="garbage")
        stats = analyze_escalated(llm, findings, run, self.config, progress, log=lambda *a, **k: None)
        self.assertEqual(stats["unanalysed"], 1)
        self.assertEqual(progress.failed_keys, [run.decisions[0].key])

    def test_max_findings_bounds_the_run(self):
        findings = [self.escalate_finding(i) for i in range(2, 7)]
        cfg = self.config.with_overrides(max_findings=3)
        run = route_findings(findings, cfg, log=lambda *a, **k: None)
        progress = ProgressState(cfg.fingerprint())
        llm = FakeRobustLLM()
        stats = analyze_escalated(llm, findings, run, cfg, progress, log=lambda *a, **k: None)
        self.assertEqual(stats["escalated"], 3)
        self.assertEqual(len(progress.completed), 3)

    def test_assembly_preserves_order_and_omits_analysis_for_deferred(self):
        findings = [self.deferrable_finding(4, "r.a"), self.escalate_finding(5), self.deferrable_finding(6, "r.b")]
        cfg = self.config.with_overrides(enable_deferral=True)
        run = route_findings(findings, cfg, log=lambda *a, **k: None)
        progress = ProgressState(cfg.fingerprint())
        analyze_escalated(FakeRobustLLM(), findings, run, cfg, progress, log=lambda *a, **k: None)
        out = assemble_output({"version": "1.0"}, findings, run, progress, cfg, {"analysed": 1})

        self.assertEqual([r["check_id"] for r in out["results"]], ["r.a", "rule.xss", "r.b"])
        self.assertEqual([r["triage"]["action"] for r in out["results"]], [ACTION_DEFER, ACTION_ESCALATE, ACTION_DEFER])
        self.assertNotIn("analysis", out["results"][0])
        self.assertIn("analysis", out["results"][1])
        self.assertNotIn("analysis", out["results"][2])
        self.assertEqual(out["pipeline"]["triage_summary"]["counts"][ACTION_DEFER], 2)
        for original, produced in zip(findings, out["results"]):
            self.assertNotIn("triage", original)  # inputs are not mutated
            self.assertEqual(produced["start"], original["start"])


class TestEndToEnd(PipelineTestCase):
    def test_answer_question_with_mocked_models(self):
        findings = [self.escalate_finding(5), self.borderline_finding(6), self.deferrable_finding(4)]
        self.write_semgrep(findings)
        cfg = self.config.with_overrides(enable_small_model=True, enable_deferral=True)
        small = small_invoke_factory('{"decision": "dismiss", "reason": "constant"}')
        llm = FakeRobustLLM()
        out = answer_question(cfg, llm=llm, small_llm=object(), small_invoke=small, log=lambda *a, **k: None)

        actions = [r["triage"]["action"] for r in out["results"]]
        self.assertEqual(actions, [ACTION_ESCALATE, ACTION_DEFER, ACTION_DEFER])
        self.assertEqual(sum("analysis" in r for r in out["results"]), 1)
        self.assertEqual(len(llm.calls), 1)
        self.assertTrue(cfg.output_file.exists())
        self.assertTrue(cfg.triage_report_file.exists())
        report = json.loads(cfg.triage_report_file.read_text())
        self.assertEqual(report["summary"]["counts"][ACTION_DEFER], 2)
        self.assertEqual(report["deep_model"]["analysed"], 1)
        self.assertEqual(len(report["decisions"]), 3)

    def test_export_skips_deferred_and_reports_counts(self):
        findings = [self.escalate_finding(5), self.deferrable_finding(4), self.escalate_finding(6)]
        self.write_semgrep(findings)
        cfg = self.config.with_overrides(enable_deferral=True)
        answer_question(cfg, llm=FakeRobustLLM(confidence="high"), log=lambda *a, **k: None)
        # Simulate one escalated finding whose analysis failed.
        data = json.loads(cfg.output_file.read_text())
        data["results"][2].pop("analysis")
        cfg.output_file.write_text(json.dumps(data))

        msgs = []
        exported = export_highest_ai_confidence_findings(cfg.output_file, self.tmp / "hc.json", log=msgs.append)
        self.assertEqual(len(exported["results"]), 1)
        self.assertNotIn("analysis", exported["results"][0])
        self.assertNotIn("triage", exported["results"][0])
        self.assertEqual(exported["skipped"]["deferred"], 1)
        self.assertEqual(exported["skipped"]["no_analysis"], 1)
        self.assertTrue(any("1 deferred by triage" in m for m in msgs))


if __name__ == "__main__":
    unittest.main()
