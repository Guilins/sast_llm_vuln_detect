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
`benchmarkutils-maven-plugin`), all runs against the full 2,410-finding Semgrep scan
(`p/security-audit`), full 2,740-test scorecard:

| Variant | TPR | FPR | Score (TPR−FPR) | Cost | Inconclusive |
|---|---|---|---|---|---|
| Raw Semgrep (no triage) | 88.1% | 44.1% | 43.96% | $0 | — |
| + hierarchical pipeline, local qwen3.5:9b (cross-file context) | 84.1% | 36.6% | 47.54% | $0 | low |
| + hierarchical pipeline, Haiku 4.5 | 84.9% | 37.4% | 47.59% | ~$4 | low |
| + hierarchical pipeline, Muse Spark 1.3 (contributor) | 87.3% | 34.9% | 52.39% | $0.93 | 47.6% |
| + hierarchical pipeline, Sonnet 5 (skeptical prompt, cross-file context, xhigh effort) | 87.3% | 32.5% | 54.83% | ~$39 | 0.9% |
| + hierarchical pipeline, DeepSeek V4.1 Flash | 86.2% | 31.1% | **55.12%** | $3.12 | 2.1% |

All variants share the same Layer 1 static triage + cross-file context; they differ only
in which model does the Layer 3 robust analysis. "Inconclusive" is the model refusing to
call a verdict (kept as a positive finding, since the pipeline didn't clear it) — a high
rate usually means the model is starved of context it needs (see Muse Spark) rather than
being unusually cautious.

**A methodological caveat worth keeping in any write-up**: OWASP Benchmark is an old,
fully public dataset (ground truth included) — a frontier model doing suspiciously well
on a small bounded subset of it may be pattern-matching a benchmark it has memorized
rather than reasoning from the code. Both Muse Spark and DeepSeek showed a near-perfect
TPR/FPR on a 150-finding bounded subset that did **not** hold up at full scale — Muse
Spark went from FPR 0.0% (subset) to 34.9% (full), DeepSeek from FPR 0.0% (subset) to
31.1% (full) — treat any bounded-subset number as a sanity check, not a result, and
always confirm on the full run.

**A cost caveat for DeepSeek specifically**: the $3.12 above is over 2x the $1.45
projected from the bounded test. The gap is retry overhead, not per-finding cost: ~39
findings exhausted the 8,192-token budget entirely on hidden reasoning tokens, returning
empty content, and the retry logic resent the *same full prompt* up to 13 times before
some finally got through (each failed attempt still burns input + reasoning tokens for
zero output). 12 findings never got an analysis in the end (0.5% of 2,410) and are kept
as unscored positives. A fix worth making before another run: detect an empty response
caused by `reasoning_tokens` alone consuming the budget and raise `max_tokens` for that
finding's retry instead of blindly resending.

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
    muse_spark.py            Meta Muse Spark 1.3 adapter (OpenAI-compatible), token/cost
    deepseek.py              DeepSeek V4.1 Flash adapter, peak/off-peak token/cost
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

# Full run on Muse Spark 1.3 (Meta Model API)
python main.py analyze \
  --backend muse-spark --muse-spark-model muse-spark-1.3-contributor \
  --cross-file-context --auto-confirm-solved-categories --batch-size 1 --api-concurrency 8

# Full run on DeepSeek V4.1 Flash
python main.py analyze \
  --backend deepseek --cross-file-context --auto-confirm-solved-categories \
  --batch-size 1 --api-concurrency 8

# Score a finished run on the OWASP Benchmark
python scripts/benchmark_scorecard.py --pipeline "SONNET=results/llm_enhanced_sast.json"
cd /home/Deus/Projects/BenchmarkJava && mvn -q org.owasp:benchmarkutils-maven-plugin:create-scorecard
```

`--backend anthropic` needs `ANTHROPIC_API_KEY` (workspace-scoped); `--backend
muse-spark` needs `MUSE_SPARK_API_KEY`; `--backend deepseek` needs `DEEPSEEK_API_KEY` —
all read from the environment or `.env`.

## Tests

```bash
cd tests && python -m unittest discover -p "test_*.py"
```
