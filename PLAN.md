# Hierarchical SAST Finding Triage Plan

## Goal

Adapt the paper's hierarchical triage idea to this project while preserving the current workflow:

```text
BenchmarkJava source
  -> Semgrep scan
  -> result/Semgrep-v1.0-results.json
  -> static triage
  -> optional small local Ollama triage
  -> robust qwen3.5:9b analysis
  -> llm_enhanced_sast.json
```

The implementation is finding-level triage, not whole-repository/package classification. Every Semgrep finding remains in the final output in its original order.

## Decisions

- The BenchmarkJava project remains the default scan target and source root:
  `/home/Deus/Projects/BenchmarkJava/src/main/java`.
- Step 5 makes that path an explicit setting or optional argument; it does not replace the benchmark workflow or move Semgrep scanning into this repository.
- Static triage must favor recall. Semgrep `ERROR`/`WARNING`, missing or unknown metadata/context, and high-risk static signals always escalate.
- Deferred findings receive a `triage` object but no fabricated LLM `analysis` object.
- Static triage should use no new dependency initially.
- Small-model triage is optional and fail-closed: malformed, empty, timed-out, or invalid responses escalate to the robust model.
- The small Ollama model is selected during implementation after inspecting locally installed models and confirming the choice with the user.
- Manual labels live under `labels/`; labels must not be guessed from Semgrep severity.
- The existing failed-output recovery script is an operational utility, not an automated test.
- The assistant may ask questions during implementation when a decision affects model choice, safety/recall policy, labels, or calibration.

## Implementation Steps

1. Create `triage.py` with deterministic Semgrep normalization, safe focal-snippet retrieval, static feature extraction, transparent risk scoring, structured `TriageDecision` serialization, and aggregate metrics.

2. Implement high-recall static signals for Semgrep severity/confidence, CWE and vulnerability class, rule/message terms, source-sink combinations, dynamic execution, shell/subprocess calls, query construction, deserialization, file/path operations, network egress, insecure cryptography, secrets, and missing context.

3. Define configurable thresholds and hard escalation guards. Always escalate `ERROR`/`WARNING`, incomplete metadata or code context, and high-risk static signals.

4. Create `labels/README.md` and `labels/triage_labels.jsonl`, documenting stable finding keys and manually reviewed `TP`/`FP` labels.

5. Refactor `model_training.py` to use explicit settings or optional arguments for source root, Semgrep input, output paths, models, batch sizes, and triage thresholds. Keep the current BenchmarkJava source-root default.

6. Integrate static triage into `answer_question()` before batching. Attach triage data to every finding, write a triage report, and send only escalated findings to the robust LLM.

7. Update progress/resume handling to use stable finding identities and a configuration fingerprint, preventing stale results from being applied after filtering or configuration changes.

8. Add a compact strict-JSON prompt and parser for the borderline small-model stage. Inspect installed Ollama models, recommend a suitable small model, and confirm it with the user.

9. Send borderline findings to the small model with slim finding data, focal code, and static evidence. Require `escalate`, `dismiss`, or `uncertain`. Invalid, empty, or timed-out responses fail closed to escalation.

10. Pass Layer 1 and small-model evidence into the robust prompt while preserving the existing exact one-result-per-input analysis contract.

11. Preserve input order in `llm_enhanced_sast.json`. Deferred results receive a `triage` object but no fabricated `analysis` object.

12. Update `export_highest_ai_confidence_findings()` so it intentionally skips deferred results lacking robust LLM analysis and reports their count.

13. Keep the failed-output recovery capability as an operational utility. Rename `test_repair.py` to `repair_broken_findings.py` and refactor it to:

    - put the current top-level loop behind `main()`;
    - accept explicit input/output arguments;
    - validate and summarize each raw batch;
    - preserve the existing JSON-repair behavior;
    - avoid running when imported;
    - remain separate from automated tests.

14. Implement a report-only calibration mode with no LLM calls. It evaluates the triage pass on `Semgrep-v1.0-results.json`, joins `labels/` data, and reports recall, precision, false negatives, escalation rate, and estimated deep-model calls/tokens avoided.

15. Run static calibration against the current Semgrep results, manually label a stratified sample across risk bands and security categories, tune weights/thresholds, and compare a bounded hierarchical run with the current one-stage baseline.

16. Add separate automated tests, such as `test_triage.py` and `test_pipeline_routing.py`. Cover static scoring, hard guards, score boundaries, missing/unreadable source handling, label parsing, output ordering, progress compatibility, mocked model routing, result reassembly, and fail-closed small-model errors.

## Relevant Files

- `model_training.py`: Main pipeline, deep LLM calls, progress/resume, output assembly, and confidence export.
- `constants.py`: Robust analysis prompt and new small-model triage prompt.
- `json_repair.py`: Existing LLM normalization and JSON recovery helpers.
- `main.py`: Explicit modes for calibration, triage report, hierarchical analysis, and export.
- `triage.py`: New dependency-free static scoring module.
- `repair_broken_findings.py`: Renamed operational recovery utility.
- `test_triage.py`: Static triage and calibration tests.
- `test_pipeline_routing.py`: Mocked routing and reassembly tests.
- `labels/README.md`: Manual-labeling contract.
- `labels/triage_labels.jsonl`: Label data source.
- `result/Semgrep-v1.0-results.json`: Current Semgrep benchmark results.

## Validation Sequence

1. Run unit tests without requiring Ollama.
2. Run report-only triage and verify every Semgrep finding is represented exactly once.
3. Verify all `ERROR`/`WARNING`, missing-data, and high-risk findings escalate.
4. Add manually reviewed labels across all score bands and security categories.
5. Require zero observed labeled true positives in the deferred group before enabling automatic deferral.
6. Mock small/deep model failures and verify fail-closed escalation.
7. Inspect installed Ollama model tags and choose the small model with user confirmation.
8. Run a bounded live experiment and compare deep-model calls, duration, failure rate, and retained TP recall against the current one-stage baseline.
9. Run the complete benchmark only after the bounded run validates routing and output artifacts.

## Expected Artifacts

- `triage_report.json`: counts, score distribution, escalation reasons, timing, and estimated savings.
- `llm_enhanced_sast.json`: every original finding in input order, with `triage` data and robust `analysis` only where performed.
- Progress data containing stable finding keys and a configuration fingerprint.
- Calibration metrics covering recall, precision, false negatives, escalation rate, and estimated token/call reduction.
