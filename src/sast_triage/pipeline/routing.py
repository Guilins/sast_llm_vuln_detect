"""Route each finding after static triage: escalate, or (small model enabled)
screen borderline findings and let a clean dismiss defer them."""

from __future__ import annotations

from typing import Optional

from ..backends import make_small_model
from ..config import PipelineConfig
from ..screening import SmallModelVerdict, apply_verdict, screen_borderline
from ..triage import ACTION_BORDERLINE, ACTION_DEFER, ACTION_ESCALATE, TriageRun, run_triage
from .progress import ProgressState, save_progress


def route_findings(results, config: PipelineConfig, progress: Optional[ProgressState] = None,
                   small_llm=None, small_invoke=None, reader=None, log=print) -> TriageRun:
    """Run static triage and, when enabled, the small-model screen.

    Returns the ``TriageRun`` with every decision's ``action`` finalised to either
    ``escalate`` or ``defer`` (``borderline`` never survives this function).
    """
    run = run_triage(results, config.source_root, config.triage,
                     allow_borderline=config.enable_small_model, reader=reader)

    # Deferral is a separate policy switch: keep the static verdict visible in
    # ``reasons`` but send the finding to the robust model anyway.
    if not config.enable_deferral:
        for d in run.decisions:
            if d.action == ACTION_DEFER:
                d.action = ACTION_ESCALATE
                d.reasons.append("static_would_defer_but_deferral_disabled")

    borderline = [(nf, d) for nf, d in zip(run.normalized, run.decisions)
                  if d.action == ACTION_BORDERLINE]
    if not borderline:
        return run

    if not config.enable_small_model:
        for _, d in borderline:
            d.action = ACTION_ESCALATE
            d.reasons.append("small_model_disabled")
        return run

    cached = progress.small_model if progress else {}
    to_screen = [(nf, d) for nf, d in borderline if nf.key not in cached]
    log(f"  Small model ({config.small_backend}/{config.effective_small_model()}): "
        f"{len(borderline)} borderline, {len(borderline) - len(to_screen)} cached, "
        f"{len(to_screen)} to screen")

    verdicts = {}
    if to_screen:
        small_llm = small_llm or make_small_model(config)

        def _progress(n, total, verdict):
            mark = "❌" if verdict.failed_closed else {"dismiss": "🟢", "escalate": "🔴"}.get(verdict.decision, "🟡")
            if n % 25 == 0 or n == total:
                log(f"    screened {n}/{total} {mark}")

        verdicts = screen_borderline(small_llm, to_screen, invoke=small_invoke,
                                     progress_cb=_progress, max_workers=config.small_concurrency())
        run.small_model_usage = getattr(small_llm, "usage", None)
        if progress is not None:
            for key, verdict in verdicts.items():
                progress.small_model[key] = verdict.to_dict()
            save_progress(config.progress_file, progress)

    for nf, d in borderline:
        if nf.key in verdicts:
            verdict = verdicts[nf.key]
        else:
            stored = cached[nf.key]
            verdict = SmallModelVerdict(
                key=nf.key, decision=stored["decision"], reason=stored.get("reason"),
                error=stored.get("error"), elapsed_seconds=stored.get("elapsed_seconds", 0.0))
        apply_verdict(d, verdict, allow_dismiss=config.enable_deferral)

    return run
