"""Command-line entry point for the hierarchical SAST triage pipeline.

Modes:
  triage         Layer-1 static triage only; writes triage_report.json (no model calls)
  calibrate      Report-only calibration against labels/ (no model calls)
  evaluate       Score a finished llm_enhanced_sast.json against labels/
  analyze        Full hierarchical run: static triage -> [small model] -> robust model
  export         Export highest-AI-confidence findings from llm_enhanced_sast.json
  sample-labels  Write a stratified sample of unlabeled findings for manual review
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .config import PipelineConfig
from .triage import DEFAULT_GUARDS


def add_config_args(parser: argparse.ArgumentParser):
    defaults = PipelineConfig()
    g = parser.add_argument_group("pipeline settings")
    g.add_argument("--source-root", type=Path, default=defaults.source_root)
    g.add_argument("--semgrep-input", type=Path, default=defaults.semgrep_input)
    g.add_argument("--output", type=Path, default=defaults.output_file, dest="output_file")
    g.add_argument("--progress", type=Path, default=defaults.progress_file, dest="progress_file")
    g.add_argument("--triage-report", type=Path, default=defaults.triage_report_file, dest="triage_report_file")
    g.add_argument("--labels", type=Path, default=defaults.labels_file, dest="labels_file")
    g.add_argument("--backend", choices=("ollama", "anthropic"), default=defaults.backend,
                   help="robust-stage backend (default: ollama / local)")
    g.add_argument("--robust-model", default=defaults.robust_model, help="Ollama model tag")
    g.add_argument("--anthropic-model", default=defaults.anthropic_model)
    g.add_argument("--anthropic-max-tokens", type=int, default=defaults.anthropic_max_tokens)
    g.add_argument("--anthropic-workspace-id", default=None,
                   help="workspace id for API keys not scoped to one (or set ANTHROPIC_WORKSPACE_ID)")
    g.add_argument("--anthropic-thinking", action="store_true",
                   help="adaptive thinking on the robust model (Sonnet/Opus)")
    g.add_argument("--anthropic-effort", choices=("low", "medium", "high", "xhigh", "max"), default=None,
                   help="reasoning depth / token spend for the robust model")
    g.add_argument("--anthropic-structured", action="store_true",
                   help="constrain robust output via output_config.format (valid JSON, enum verdicts, required evidence)")
    g.add_argument("--cross-file-context", action="store_true",
                   help="append called project/helper method bodies to the robust prompt")
    g.add_argument("--auto-confirm-class", action="append", default=[], metavar="SUBSTRING",
                   help="vulnerability-class substring whose findings skip the robust model as confirmed TP "
                        "(repeatable). Shorthand: --auto-confirm-solved-categories")
    g.add_argument("--auto-confirm-solved-categories", action="store_true",
                   help="shorthand for --auto-confirm-class 'cryptographic' 'hashing' 'cookie'")
    g.add_argument("--api-concurrency", type=int, default=defaults.api_concurrency,
                   help="anthropic sync path: batches in flight at once")
    g.add_argument("--batch-api", action="store_true", dest="use_batch_api",
                   help="anthropic backend: use the async Message Batches API (50%% cheaper)")
    g.add_argument("--batch-size", type=int, default=None,
                   help="findings per model call (default: 20 for ollama, 5 for anthropic)")
    g.add_argument("--num-ctx", type=int, default=defaults.num_ctx)
    g.add_argument("--timeout", type=int, default=defaults.timeout)
    g.add_argument("--max-retries", type=int, default=defaults.max_retries)
    g.add_argument("--max-findings", type=int, default=None,
                   help="bounded run: analyse at most this many escalated findings")
    g.add_argument("--enable-small-model", action="store_true",
                   help="screen borderline findings with the small model before the robust model")
    g.add_argument("--small-backend", choices=("ollama", "anthropic"), default=defaults.small_backend,
                   help="borderline-screen backend (default: ollama / local qwen)")
    g.add_argument("--small-model", default=defaults.small_model, help="Ollama tag for the screen")
    g.add_argument("--small-anthropic-model", default=defaults.small_anthropic_model)
    g.add_argument("--small-model-timeout", type=int, default=defaults.small_model_timeout)
    g.add_argument("--enable-deferral", action="store_true",
                   help="allow findings to skip the robust model (only after calibration says it is safe)")
    t = parser.add_argument_group("triage thresholds and guards")
    t.add_argument("--escalate-at", type=float, default=None)
    t.add_argument("--borderline-at", type=float, default=None)
    t.add_argument("--context-lines", type=int, default=None)
    t.add_argument("--method-fallback-lines", type=int, default=None,
                   help="+-lines of context when the enclosing method cannot be brace-matched")
    t.add_argument("--borderline-max-severity", choices=("INFO", "WARNING", "ERROR"), default=None,
                   help="highest severity that may be routed to the small model (default WARNING)")
    t.add_argument("--borderline-class", action="append", default=[], metavar="SUBSTRING",
                   help="replace the default set of small-model-eligible vulnerability classes (repeatable)")
    t.add_argument("--disable-guard", action="append", default=[], choices=sorted(DEFAULT_GUARDS),
                   help="turn off a hard escalation guard (repeatable; lowers recall)")
    t.add_argument("--weight", action="append", default=[], metavar="NAME=VALUE",
                   help="override a scoring weight, e.g. --weight signal:xss=0.2")


def build_config(args) -> PipelineConfig:
    config = PipelineConfig(
        source_root=args.source_root,
        semgrep_input=args.semgrep_input,
        output_file=args.output_file,
        progress_file=args.progress_file,
        triage_report_file=args.triage_report_file,
        labels_file=args.labels_file,
        backend=args.backend,
        robust_model=args.robust_model,
        anthropic_model=args.anthropic_model,
        anthropic_max_tokens=args.anthropic_max_tokens,
        anthropic_workspace_id=args.anthropic_workspace_id or os.environ.get("ANTHROPIC_WORKSPACE_ID"),
        anthropic_thinking=args.anthropic_thinking,
        anthropic_effort=args.anthropic_effort,
        anthropic_structured=args.anthropic_structured,
        cross_file_context=args.cross_file_context,
        auto_confirm_classes=tuple(
            c.lower() for c in (args.auto_confirm_class
                                + (["cryptographic", "hashing", "cookie"]
                                   if args.auto_confirm_solved_categories else []))),
        api_concurrency=args.api_concurrency,
        use_batch_api=args.use_batch_api,
        batch_size=(args.batch_size if args.batch_size is not None
                    else (5 if args.backend == "anthropic" else 20)),
        num_ctx=args.num_ctx,
        timeout=args.timeout,
        max_retries=args.max_retries,
        max_findings=args.max_findings,
        enable_small_model=args.enable_small_model,
        small_backend=args.small_backend,
        small_model=args.small_model,
        small_anthropic_model=args.small_anthropic_model,
        small_model_timeout=args.small_model_timeout,
        enable_deferral=args.enable_deferral,
    )
    if args.escalate_at is not None:
        config.triage.thresholds["escalate_at"] = args.escalate_at
    if args.borderline_at is not None:
        config.triage.thresholds["borderline_at"] = args.borderline_at
    if args.context_lines is not None:
        config.triage.context_lines = args.context_lines
    if args.method_fallback_lines is not None:
        config.triage.method_context_fallback_lines = args.method_fallback_lines
    if args.borderline_max_severity is not None:
        config.triage.borderline_max_severity = args.borderline_max_severity
    if args.borderline_class:
        config.triage.borderline_classes = tuple(c.lower() for c in args.borderline_class)
    for guard in args.disable_guard:
        config.triage.guards[guard] = False
    for spec in args.weight:
        name, _, value = spec.partition("=")
        config.triage.weights[name.strip()] = float(value)
    return config


def cmd_triage(args):
    from .pipeline import triage_report_only
    triage_report_only(build_config(args))
    return 0


def cmd_calibrate(args):
    from .calibration import calibrate, print_report
    config = build_config(args)
    report = calibrate(config, reviewed_only=args.reviewed_only)
    print_report(report)
    if args.report_out:
        with open(args.report_out, "w") as f:
            json.dump(report, f, indent=2)
        print(f"calibration report written to {args.report_out}")
    return 0


def cmd_evaluate(args):
    from .calibration import evaluate_output_file, print_report
    config = build_config(args)
    report = evaluate_output_file(config.output_file, config.labels_file, config.batch_size)
    print_report(report)
    if args.report_out:
        with open(args.report_out, "w") as f:
            json.dump(report, f, indent=2)
    return 0


def cmd_analyze(args):
    from .pipeline import answer_question
    config = build_config(args)
    if config.enable_deferral:
        print("⚠ deferral is ENABLED: findings the triage layer defers will not reach the robust model.")
    if "anthropic" in (config.backend, config.small_backend):
        if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
            print("✗ the anthropic backend needs ANTHROPIC_API_KEY (or ANTHROPIC_AUTH_TOKEN) in the environment.")
            return 2
    answer_question(config)
    return 0


def cmd_export(args):
    from .pipeline import export_highest_ai_confidence_findings
    config = build_config(args)
    export_highest_ai_confidence_findings(config.output_file, args.export_out)
    return 0


def cmd_sample_labels(args):
    from .calibration import load_labels, sample_for_labeling
    from .triage import run_triage
    config = build_config(args)
    with open(config.semgrep_input) as f:
        results = json.load(f)["results"]
    run = run_triage(results, config.source_root, config.triage, allow_borderline=True)
    existing = load_labels(config.labels_file)
    rows = sample_for_labeling(run, per_stratum=args.per_stratum, seed=args.seed, existing=existing)
    with open(args.out, "w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    print(f"wrote {len(rows)} unlabeled findings to {args.out} — fill in 'label' and set reviewed=true")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("triage", help="static triage report only (no LLM)")
    add_config_args(p)
    p.set_defaults(func=cmd_triage)

    p = sub.add_parser("calibrate", help="report-only calibration against labels (no LLM)")
    add_config_args(p)
    p.add_argument("--reviewed-only", action="store_true", help="use only labels with reviewed=true")
    p.add_argument("--report-out", type=Path, default=Path("results/calibration_report.json"))
    p.set_defaults(func=cmd_calibrate)

    p = sub.add_parser("evaluate", help="score a finished output file against labels")
    add_config_args(p)
    p.add_argument("--report-out", type=Path, default=None)
    p.set_defaults(func=cmd_evaluate)

    p = sub.add_parser("analyze", help="full hierarchical analysis (calls Ollama)")
    add_config_args(p)
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("export", help="export highest-AI-confidence findings")
    add_config_args(p)
    p.add_argument("--export-out", type=Path, default=Path("results/llm_enhanced_sast_highest_confidence.json"))
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("sample-labels", help="stratified sample of unlabeled findings for review")
    add_config_args(p)
    p.add_argument("--per-stratum", type=int, default=3)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--out", type=Path, default=Path("data/labels/to_review.jsonl"))
    p.set_defaults(func=cmd_sample_labels)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)

