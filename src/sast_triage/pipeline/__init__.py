"""Pipeline orchestration: the ``triage_report_only`` and ``answer_question`` entry
points, plus re-exports of the stage functions and progress helpers."""

from __future__ import annotations

import json
from typing import Optional

from ..backends import make_robust_model
from ..config import PipelineConfig
from ..triage import (ACTION_BORDERLINE, ACTION_DEFER, ACTION_ESCALATE, SourceReader,
                      run_triage, summarize_decisions)
from .assembly import assemble_output, load_semgrep, write_triage_report
from .export import export_highest_ai_confidence_findings
from .progress import PROGRESS_SCHEMA, ProgressState, load_progress, save_progress
from .robust import analyze_escalated
from .routing import route_findings

__all__ = [
    "triage_report_only", "answer_question", "route_findings", "analyze_escalated",
    "assemble_output", "write_triage_report", "load_semgrep",
    "export_highest_ai_confidence_findings",
    "ProgressState", "PROGRESS_SCHEMA", "load_progress", "save_progress",
]


def triage_report_only(config: Optional[PipelineConfig] = None, log=print) -> dict:
    """Run Layer-1 triage and write ``triage_report.json`` — no model calls at all."""
    config = config or PipelineConfig()
    json_file, results = load_semgrep(config)
    log(f"[Triage] {len(results)} findings from {config.semgrep_input}")
    run = run_triage(results, config.source_root, config.triage,
                     allow_borderline=config.enable_small_model)
    report = write_triage_report(config.triage_report_file, run, config)
    s = report["summary"]
    log(f"  escalate={s['counts'][ACTION_ESCALATE]} borderline={s['counts'][ACTION_BORDERLINE]} "
        f"defer={s['counts'][ACTION_DEFER]}  ({run.elapsed_seconds:.2f}s)")
    log(f"  report written to {config.triage_report_file}")
    return report


def answer_question(config: Optional[PipelineConfig] = None, llm=None, small_llm=None,
                    small_invoke=None, log=print):
    """Hierarchical analysis: static triage -> optional small model -> robust model."""
    config = config or PipelineConfig()
    reader = SourceReader(config.source_root)

    log("[Step 1] Loading SAST results...")
    json_file, results = load_semgrep(config)
    log(f"  {len(results)} findings (config fingerprint {config.fingerprint()})")

    progress = load_progress(config.progress_file, config.fingerprint(), log)
    if progress.completed:
        log(f"  Resuming: {len(progress.completed)} findings already analysed")

    log("[Step 2] Static triage" + (" + small-model screen" if config.enable_small_model else "") + "...")
    run = route_findings(results, config, progress, small_llm, small_invoke, reader, log)
    counts = summarize_decisions(run.decisions, config.triage, config.batch_size)["counts"]
    log(f"  escalate={counts[ACTION_ESCALATE]} defer={counts[ACTION_DEFER]}  ({run.elapsed_seconds:.2f}s)")
    write_triage_report(config.triage_report_file, run, config)

    pending_count = len([d for d in run.decisions if d.action == ACTION_ESCALATE
                         and d.key not in progress.completed])
    if config.max_findings is not None:
        pending_count = min(pending_count, config.max_findings)
    log(f"[Step 3] Robust model: {config.backend}/{config.effective_robust_model()}"
        + (" (Batch API)" if config.use_batch_api else "") + f" — {pending_count} findings pending")
    if config.backend == "anthropic":
        from ..backends.anthropic import estimate_cost
        log("  " + estimate_cost(config.anthropic_model, pending_count,
                                 config.use_batch_api).render().replace("\n", "\n  "))
    llm = llm or make_robust_model(config)
    deep_stats = analyze_escalated(llm, results, run, config, progress, reader, log)

    small_usage = getattr(run, "small_model_usage", None)
    if small_usage is not None:
        deep_stats["small_model_token_usage"] = small_usage.to_dict(
            config.effective_small_model(), config.use_batch_api)
    if deep_stats.get("token_usage"):
        tu = deep_stats["token_usage"]
        log(f"  robust tokens: {tu['input_tokens']:,} in ({tu['cache_read_tokens']:,} cached) + "
            f"{tu['output_tokens']:,} out  ~${tu.get('cost_usd', 0):.2f}")

    final_output = assemble_output(json_file, results, run, progress, config, deep_stats)
    with open(config.output_file, "w") as f:
        json.dump(final_output, f, indent=2)
    write_triage_report(config.triage_report_file, run, config, deep_stats)

    log(f"\n✅ Done: {len(final_output['results'])} findings written to '{config.output_file}' "
        f"({deep_stats['analysed']} with robust analysis, {counts[ACTION_DEFER]} deferred, "
        f"{deep_stats['unanalysed']} escalated but unanalysed)")
    return final_output
