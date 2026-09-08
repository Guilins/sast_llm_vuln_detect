"""Tests for the Anthropic backend: message translation, cost estimate, concurrent and
Batch-API execution paths. No network and no real SDK calls (a fake client is injected).

Run: python -m unittest test_anthropic_backend -v
"""

import json
import unittest
from types import SimpleNamespace

from langchain_core.messages import HumanMessage, SystemMessage

import sast_triage.backends.anthropic as ab
from sast_triage.config import PipelineConfig
from sast_triage.pipeline import ProgressState, analyze_escalated, answer_question, route_findings
from sast_triage.triage import ACTION_DEFER, ACTION_ESCALATE, TriageSettings

from test_pipeline_routing import PipelineTestCase, FakeRobustLLM, small_invoke_factory
from test_triage import SAFE_JAVA


# ---------------------------------------------------------------------------
# Fake anthropic SDK client
# ---------------------------------------------------------------------------

def _text_block(text):
    return SimpleNamespace(type="text", text=text)


def _system_text(params):
    s = params.get("system", "")
    if isinstance(s, list):
        return " ".join(b.get("text", "") for b in s)
    return s or ""


class FakeMessages:
    def __init__(self, parent):
        self.parent = parent

    def create(self, **params):
        self.parent.calls.append(params)
        n = _system_text(params).count('"check_id"') or 1
        if self.parent.raise_exc is not None:
            raise self.parent.raise_exc
        if self.parent.refuse:
            return SimpleNamespace(stop_reason="refusal", content=[], usage=None)
        items = [{"analysis": {"verdict": "True Positive", "confidence": "high",
                               "severity_assessment": "high", "root_cause": f"rc{i}",
                               "impact": "", "remediation": [], "code_context": "",
                               "additional_notes": ""}} for i in range(n)]
        return SimpleNamespace(stop_reason="end_turn", content=[_text_block(json.dumps(items))],
                               usage=SimpleNamespace(input_tokens=10 * n, output_tokens=8 * n,
                                                     cache_creation_input_tokens=0,
                                                     cache_read_input_tokens=0))


class FakeBatches:
    def __init__(self, parent):
        self.parent = parent

    def create(self, requests):
        self.parent.submitted = requests
        return SimpleNamespace(id="msgbatch_fake", processing_status="in_progress",
                               request_counts=SimpleNamespace(succeeded=0, errored=0, processing=len(requests)))

    def retrieve(self, _id):
        return SimpleNamespace(id="msgbatch_fake", processing_status="ended",
                               request_counts=SimpleNamespace(
                                   succeeded=len(self.parent.submitted), errored=0, processing=0))

    def results(self, _id):
        for req in self.parent.submitted:
            p = req["params"]
            n = _system_text(p).count('"check_id"') or 1
            if req["custom_id"] in self.parent.error_ids:
                yield SimpleNamespace(custom_id=req["custom_id"],
                                      result=SimpleNamespace(type="errored",
                                                             error=SimpleNamespace(type="overloaded_error")))
                continue
            items = [{"analysis": {"verdict": "False Positive", "confidence": "high",
                                   "severity_assessment": "info", "root_cause": "x",
                                   "impact": "", "remediation": [], "code_context": "",
                                   "additional_notes": ""}} for i in range(n)]
            yield SimpleNamespace(
                custom_id=req["custom_id"],
                result=SimpleNamespace(type="succeeded",
                                       message=SimpleNamespace(stop_reason="end_turn",
                                                               content=[_text_block(json.dumps(items))])))


class FakeAnthropicClient:
    def __init__(self, refuse=False, error_ids=(), raise_exc=None):
        self.calls = []
        self.submitted = []
        self.refuse = refuse
        self.error_ids = set(error_ids)
        self.raise_exc = raise_exc
        self.messages = FakeMessages(self)
        self.messages.batches = FakeBatches(self)


# ---------------------------------------------------------------------------
# Message translation & cost estimate
# ---------------------------------------------------------------------------

class TestTranslation(unittest.TestCase):
    def test_split_messages(self):
        system, turns = ab.split_messages([
            SystemMessage(content="rules"), HumanMessage(content="do it")])
        self.assertEqual(system, "rules")
        self.assertEqual(turns, [{"role": "user", "content": "do it"}])

    def test_request_params_omits_empty_system(self):
        params = ab.request_params([HumanMessage(content="hi")], "claude-haiku-4-5", 100)
        self.assertNotIn("system", params)
        self.assertNotIn("thinking", params)
        self.assertNotIn("output_config", params)
        self.assertEqual(params["model"], "claude-haiku-4-5")

    def test_request_params_thinking_effort_and_schema(self):
        params = ab.request_params([HumanMessage(content="hi")], "claude-sonnet-5", 16000,
                                   thinking=True, effort="xhigh",
                                   output_schema=ab.ANALYSIS_RESPONSE_SCHEMA)
        self.assertEqual(params["thinking"], {"type": "adaptive"})
        self.assertEqual(params["output_config"]["effort"], "xhigh")
        self.assertEqual(params["output_config"]["format"]["type"], "json_schema")
        self.assertIn("exploitability_evidence",
                      params["output_config"]["format"]["schema"]["properties"]["findings"]
                      ["items"]["required"])

    def test_adapter_forwards_thinking_and_schema(self):
        client = FakeAnthropicClient()
        adapter = ab.AnthropicChatAdapter("claude-sonnet-5", 16000, client=client,
                                          thinking=True, effort="high",
                                          output_schema=ab.ANALYSIS_RESPONSE_SCHEMA)
        adapter.invoke([SystemMessage(content='[{"check_id":"x"}]'), HumanMessage(content="go")])
        sent = client.calls[0]
        self.assertEqual(sent["thinking"], {"type": "adaptive"})
        self.assertEqual(sent["output_config"]["effort"], "high")

    def test_reply_text_joins_blocks_and_handles_refusal(self):
        ok = SimpleNamespace(stop_reason="end_turn",
                             content=[_text_block("a"), SimpleNamespace(type="thinking"), _text_block("b")])
        self.assertEqual(ab._reply_text(ok), "ab")
        refused = SimpleNamespace(stop_reason="refusal", content=[_text_block("nope")])
        self.assertEqual(ab._reply_text(refused), "")

    def test_adapter_invoke_uses_client(self):
        client = FakeAnthropicClient()
        adapter = ab.AnthropicChatAdapter("claude-haiku-4-5", 500, client=client)
        reply = adapter.invoke([SystemMessage(content='[{"check_id": "x"}]'), HumanMessage(content="go")])
        self.assertEqual(len(client.calls), 1)
        self.assertIn("verdict", reply.content)
        self.assertEqual(adapter.usage.calls, 1)

    def test_is_fatal_error(self):
        self.assertTrue(ab.is_fatal_error("Error code: 400 - invalid_request_error: workspace"))
        self.assertTrue(ab.is_fatal_error("AuthenticationError: invalid x-api-key"))
        self.assertTrue(ab.is_fatal_error("your credit balance is too low"))
        self.assertFalse(ab.is_fatal_error("Timeout after 600s"))
        self.assertFalse(ab.is_fatal_error("Empty LLM response"))
        self.assertFalse(ab.is_fatal_error(""))

    def test_workspace_header_passed_to_client(self):
        import anthropic
        from unittest.mock import patch
        with patch.object(anthropic, "Anthropic") as ctor:
            ab.make_client(workspace_id="wrkspc_123")
            self.assertEqual(ctor.call_args.kwargs["default_headers"],
                             {"anthropic-workspace-id": "wrkspc_123"})
            ab.make_client(workspace_id=None)
            self.assertIsNone(ctor.call_args.kwargs["default_headers"])

    def test_estimate_cost_batch_is_half(self):
        live = ab.estimate_cost("claude-haiku-4-5", 2410, batch_api=False)
        batch = ab.estimate_cost("claude-haiku-4-5", 2410, batch_api=True)
        self.assertAlmostEqual(batch.usd_low, live.usd_low / 2, places=6)
        self.assertIn("2410", live.render())
        self.assertIn("Batch API", batch.render())


# ---------------------------------------------------------------------------
# Execution paths through analyze_escalated
# ---------------------------------------------------------------------------

class TestAnthropicPaths(PipelineTestCase):
    def _run(self, config, findings, client):
        run = route_findings(findings, config, log=lambda *a, **k: None)
        progress = ProgressState(config.fingerprint())
        adapter = ab.AnthropicChatAdapter(config.anthropic_model, config.anthropic_max_tokens, client=client)
        stats = analyze_escalated(adapter, findings, run, config, progress, log=lambda *a, **k: None)
        return run, progress, stats

    def test_concurrent_path_analyses_everything_in_order(self):
        findings = [self.escalate_finding(i) for i in range(2, 12)]  # 10 -> 5 batches of 2
        cfg = self.config.with_overrides(backend="anthropic", api_concurrency=4, batch_size=2)
        client = FakeAnthropicClient()
        run, progress, stats = self._run(cfg, findings, client)
        self.assertEqual(len(client.calls), 5)
        self.assertEqual(stats["analysed"], 10)
        self.assertEqual(stats["backend"], "anthropic")
        self.assertEqual(set(progress.completed), {d.key for d in run.decisions})

    def test_concurrent_path_marks_refusals_failed_then_retries(self):
        findings = [self.escalate_finding(i) for i in range(2, 6)]
        cfg = self.config.with_overrides(backend="anthropic", api_concurrency=2, batch_size=2)
        client = FakeAnthropicClient(refuse=True)
        _, progress, stats = self._run(cfg, findings, client)
        # every batch + every sub-batch retry refuses -> nothing analysed, all failed_keys
        self.assertEqual(stats["analysed"], 0)
        self.assertEqual(len(progress.failed_keys), 4)
        self.assertGreater(stats["batch_failures"], 0)

    def test_fatal_error_aborts_without_crashing_or_retrying(self):
        findings = [self.escalate_finding(i) for i in range(2, 8)]  # 3 batches of 2
        cfg = self.config.with_overrides(backend="anthropic", api_concurrency=3, batch_size=2)
        boom = RuntimeError("Error code: 400 - invalid_request_error: workspace")
        client = FakeAnthropicClient(raise_exc=boom)
        _, progress, stats = self._run(cfg, findings, client)
        self.assertEqual(stats["analysed"], 0)
        self.assertIn("workspace", stats["fatal_error"])
        self.assertEqual(stats["retried_sub_batches"], 0)   # retry pass was skipped
        self.assertEqual(len(progress.failed_keys), 6)

    def test_batch_api_path(self):
        findings = [self.escalate_finding(i) for i in range(2, 10)]  # 8 -> 4 batches of 2
        cfg = self.config.with_overrides(backend="anthropic", use_batch_api=True, batch_size=2)
        client = FakeAnthropicClient()
        # patch submit_and_collect to use our fake client
        orig = ab.submit_and_collect
        ab.submit_and_collect = lambda *a, **k: orig(*a, client=client, poll_interval=0, **k)
        try:
            run, progress, stats = self._run(cfg, findings, client)
        finally:
            ab.submit_and_collect = orig
        self.assertEqual(len(client.submitted), 4)
        self.assertEqual(stats["analysed"], 8)
        self.assertEqual(set(progress.completed), {d.key for d in run.decisions})

    def test_batch_api_errored_request_falls_back_to_sequential_retry(self):
        findings = [self.escalate_finding(i) for i in range(2, 6)]  # 4 -> 2 batches of 2
        cfg = self.config.with_overrides(backend="anthropic", use_batch_api=True, batch_size=2)
        client = FakeAnthropicClient(error_ids={"batch-0001"})
        orig = ab.submit_and_collect
        ab.submit_and_collect = lambda *a, **k: orig(*a, client=client, poll_interval=0, **k)
        try:
            _, progress, stats = self._run(cfg, findings, client)
        finally:
            ab.submit_and_collect = orig
        # batch-0001 errored in the batch job, then the sequential retry (FakeMessages) recovers it
        self.assertEqual(stats["analysed"], 4)
        self.assertGreater(len(client.calls), 0)


class TestAnthropicSmallModel(PipelineTestCase):
    def test_make_small_model_returns_adapter(self):
        from sast_triage.backends import make_small_model as _make_small_model
        cfg = self.config.with_overrides(small_backend="anthropic",
                                         small_anthropic_model="claude-haiku-4-5")
        with unittest.mock.patch("sast_triage.backends.anthropic.make_client") as mk:
            m = _make_small_model(cfg)
        self.assertIsInstance(m, ab.AnthropicChatAdapter)
        self.assertEqual(m.model, "claude-haiku-4-5")
        mk.assert_called_once()

    def test_concurrent_screen_defers_and_escalates(self):
        from sast_triage.pipeline import route_findings
        findings = [self.borderline_finding(i, f"r{i}") for i in range(2, 10)]
        cfg = self.config.with_overrides(enable_small_model=True, enable_deferral=True,
                                        small_backend="anthropic", api_concurrency=4)

        def fake_invoke(llm, prompt):
            # dismiss the ones mentioning r3 / r5, else uncertain
            if '"rule":"r3"' in prompt or '"rule":"r5"' in prompt:
                return '{"decision": "dismiss", "reason": "constant"}'
            return '{"decision": "uncertain"}'

        run = route_findings(findings, cfg, small_llm=object(), small_invoke=fake_invoke,
                             log=lambda *a, **k: None)
        actions = {d.reasons[-1]: d.action for d in run.decisions}
        deferred = [d for d in run.decisions if d.action == ACTION_DEFER]
        self.assertEqual(len(deferred), 2)
        self.assertTrue(all("small_model" in d.small_model["reason"] or d.small_model["decision"] == "dismiss"
                            for d in deferred))


import unittest.mock  # noqa: E402


class TestFingerprint(PipelineTestCase):
    def test_backend_and_model_change_the_fingerprint(self):
        base = self.config.fingerprint()
        self.assertNotEqual(self.config.with_overrides(backend="anthropic").fingerprint(), base)
        anth = self.config.with_overrides(backend="anthropic")
        self.assertNotEqual(anth.with_overrides(anthropic_model="claude-sonnet-5").fingerprint(),
                            anth.fingerprint())
        # execution mechanism does not change the output -> progress stays valid
        self.assertEqual(anth.with_overrides(use_batch_api=True).fingerprint(), anth.fingerprint())
        self.assertEqual(anth.with_overrides(api_concurrency=32).fingerprint(), anth.fingerprint())


if __name__ == "__main__":
    unittest.main()
