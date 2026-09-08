# Hierarchical SAST Finding Triage

Reduce false positives in a Semgrep scan of OWASP BenchmarkJava with a three-stage
pipeline:

```
Semgrep results
  → Layer 1: deterministic static triage        (no LLM — routes each finding)
  → Layer 2: cheap-model borderline screen       (optional, fail-closed)
  → Layer 3: robust LLM analysis                 (verdict + traced exploitability path)
  → llm_enhanced_sast.json                       (every finding, in input order)
```

Every stage is resumable per finding, keyed by a stable finding identity and guarded by
a configuration fingerprint, so a re-run only does what changed.

## Result

Official **OWASP Benchmark v1.2** scorecard (`scripts/benchmark_scorecard.py` +
`benchmarkutils-maven-plugin`):

| Variant | TPR | FPR | Score (TPR−FPR) |
|---|---|---|---|
| Raw Semgrep (`p/security-audit`) | 88.1% | 44.1% | 43.96% |
| + hierarchical pipeline, Haiku 4.5 | 84.9% | 37.4% | 47.59% |
| + hierarchical pipeline, Sonnet 5 (skeptical prompt, cross-file context) | 87.3% | 32.5% | **54.83%** |

## Layout

```
main.py                      thin CLI entry point  (python main.py <command>)
pyproject.toml               editable-installable package `sast_triage`
src/sast_triage/
  config.py                  PipelineConfig — every knob, path default, fingerprint
  prompts.py                 robust-analysis + small-model prompt templates
  json_repair.py             recover malformed LLM JSON
  triage.py                  Layer 1: normalization, source reader, signals, scoring, decision
  screening.py               Layer 2: fail-closed borderline screen
  context.py                 cross-file helper resolution + per-batch prompt assembly
  calibration.py             report-only calibration against labels (no LLM)
  rag.py                     legacy embedding helpers (used by the notebook only)
  cli.py                     argument parsing for main.py
  backends/
    __init__.py              make_robust_model / make_small_model
    anthropic.py             Anthropic adapter, structured output, batch API, token/cost
  pipeline/
    __init__.py              answer_question, triage_report_only  (orchestrators)
    progress.py              ProgressState, load_progress, save_progress
    routing.py               route_findings
    robust.py                analyze_escalated + batch runners + auto-confirm
    assembly.py              assemble_output, write_triage_report, load_semgrep
    export.py                highest-confidence export
tests/                       94 unit tests, no network / no Ollama needed
scripts/
  seed_labels.py             seed data/labels/ from the Benchmark ground truth
  benchmark_scorecard.py     turn a pipeline output into a scorable Semgrep file
  repair_broken_findings.py  recover findings from raw failed-batch dumps
data/
  semgrep/Semgrep-v1.0-results.json   the scan under triage
  labels/                     ground truth for calibration (see labels/README.md)
results/                      pipeline outputs + scorecards (git-ignored, regenerable)
progress/                     resumable per-finding progress (git-ignored)
```

## Setup

```bash
python -m pip install -e .        # installs `sast_triage` + deps
```

## Use

```bash
# Layer 1 only — routing report, no model calls
python main.py triage

# Report-only calibration against labels/ — no model calls
python main.py calibrate

# Full hierarchical run (local Ollama by default)
python main.py analyze --enable-small-model

# Full run on the Anthropic API, as scored above
python main.py analyze \
  --backend anthropic --anthropic-model claude-sonnet-5 \
  --anthropic-thinking --anthropic-effort xhigh --anthropic-structured \
  --cross-file-context --auto-confirm-solved-categories --batch-size 1 --api-concurrency 16 \
  --small-backend anthropic --small-anthropic-model claude-haiku-4-5 \
  --enable-small-model --enable-deferral

# Score a finished run on the OWASP Benchmark
python scripts/benchmark_scorecard.py --pipeline "SONNET=results/llm_enhanced_sast.json"
cd /home/Deus/Projects/BenchmarkJava && mvn -q org.owasp:benchmarkutils-maven-plugin:create-scorecard
```

`--backend anthropic` needs `ANTHROPIC_API_KEY` (workspace-scoped) in the environment
or in `.env`.

## Tests

```bash
cd tests && python -m unittest discover -p "test_*.py"
```
