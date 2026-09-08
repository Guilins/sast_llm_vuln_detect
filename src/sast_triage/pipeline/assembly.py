"""Assemble the ordered output file and the triage report; load the Semgrep input."""

from __future__ import annotations

import json
import time

from ..config import PipelineConfig
from ..triage import TriageRun, summarize_decisions
from .progress import ProgressState


def assemble_output(json_file, results, run: TriageRun, progress: ProgressState,
                    config: PipelineConfig, deep_stats=None) -> dict:
    """Every input finding, in input order, with ``triage`` always and ``analysis``
    only where the robust model actually produced one."""
    out = []
    for finding, d in zip(results, run.decisions):
        item = dict(finding)
        item["triage"] = d.to_dict()
        analysis = progress.completed.get(d.key)
        if analysis is not None:
            item["analysis"] = analysis
        out.append(item)

    summary = summarize_decisions(run.decisions, config.triage, config.batch_size, run.elapsed_seconds)
    return {
        "version": json_file.get("version"),
        "results": out,
        "pipeline": {
            "config": config.to_dict(),
            "triage_summary": summary,
            "deep_model": deep_stats,
        },
    }


def write_triage_report(path, run: TriageRun, config: PipelineConfig, deep_stats=None, extra=None):
    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "config": config.to_dict(),
        "summary": summarize_decisions(run.decisions, config.triage, config.batch_size, run.elapsed_seconds),
        "deep_model": deep_stats,
        "decisions": [d.to_dict() for d in run.decisions],
    }
    if extra:
        report.update(extra)
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    return report


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def load_semgrep(config: PipelineConfig):
    with open(config.semgrep_input, "r") as f:
        json_file = json.load(f)
    return json_file, list(json_file["results"])
