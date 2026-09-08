"""Report-only calibration of the static triage layer. Makes no model calls.

Joins triage decisions with manually reviewed labels from ``labels/`` and reports
recall of labeled true positives, precision of escalation, the false negatives that a
deferral policy would have hidden, escalation rate, and the deep-model calls/tokens the
policy would avoid. Also evaluates a finished ``llm_enhanced_sast.json`` so a live
hierarchical run can be compared against the one-stage baseline on the same labels.
"""

from __future__ import annotations

import json
import math
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .config import PipelineConfig
from .triage import (
    ACTION_BORDERLINE,
    ACTION_DEFER,
    BAND_HIGH,
    BAND_LOW,
    BAND_MEDIUM,
    TriageRun,
    TriageSettings,
    normalize_findings,
    run_triage,
    summarize_decisions,
)

LABEL_TP = "TP"
LABEL_FP = "FP"
VALID_LABELS = (LABEL_TP, LABEL_FP)


@dataclass
class LabelRecord:
    key: str
    label: str
    source: str = "manual"
    reviewed: bool = False
    note: str = ""
    extra: Optional[dict] = None

    @property
    def is_tp(self) -> bool:
        return self.label == LABEL_TP


# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------

def parse_label_line(line: str, lineno: int = 0):
    """Return ``(LabelRecord | None, error | None)`` for one JSONL line."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None, None
    try:
        data = json.loads(stripped)
    except ValueError as exc:
        return None, f"line {lineno}: invalid JSON ({exc})"
    if not isinstance(data, dict):
        return None, f"line {lineno}: expected an object"
    key = data.get("key")
    label = str(data.get("label", "")).strip().upper()
    if not isinstance(key, str) or not key:
        return None, f"line {lineno}: missing key"
    if label not in VALID_LABELS:
        return None, f"line {lineno}: label must be one of {VALID_LABELS}, got {data.get('label')!r}"
    known = {"key", "label", "source", "reviewed", "note"}
    return LabelRecord(
        key=key,
        label=label,
        source=str(data.get("source") or "manual"),
        reviewed=bool(data.get("reviewed", False)),
        note=str(data.get("note") or ""),
        extra={k: v for k, v in data.items() if k not in known} or None,
    ), None


def load_labels(path, reviewed_only: bool = False, log=print) -> dict:
    """Load ``{key: LabelRecord}`` from a JSONL file. Later lines override earlier ones."""
    path = Path(path)
    labels = {}
    if not path.exists():
        log(f"  ⚠ labels file {path} not found; calibration will have no ground truth")
        return labels
    errors = []
    with open(path, "r") as f:
        for lineno, line in enumerate(f, 1):
            record, error = parse_label_line(line, lineno)
            if error:
                errors.append(error)
                continue
            if record is None:
                continue
            if reviewed_only and not record.reviewed:
                continue
            if record.key in labels:
                log(f"  ⚠ duplicate label for {record.key} (line {lineno}); keeping the later one")
            labels[record.key] = record
    for error in errors[:20]:
        log(f"  ⚠ {error}")
    if len(errors) > 20:
        log(f"  ⚠ ... {len(errors) - 20} more label errors")
    return labels


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def _rate(num, den):
    return round(num / den, 4) if den else None


def _class_of(nf) -> str:
    return nf.vulnerability_class[0] if nf.vulnerability_class else "unknown"


def evaluate_run(run: TriageRun, labels: dict, batch_size: int,
                 settings: Optional[TriageSettings] = None) -> dict:
    """Score a ``TriageRun`` (static or post-small-model) against labels."""
    settings = settings or run.settings
    summary = summarize_decisions(run.decisions, settings, batch_size, run.elapsed_seconds)

    joined = [(nf, d, labels[d.key]) for nf, d in zip(run.normalized, run.decisions) if d.key in labels]
    labeled_tp = [j for j in joined if j[2].is_tp]
    labeled_fp = [j for j in joined if not j[2].is_tp]

    retained = [j for j in joined if j[1].action != ACTION_DEFER]
    tp_retained = [j for j in retained if j[2].is_tp]
    fp_deferred = [j for j in labeled_fp if j[1].action == ACTION_DEFER]
    false_negatives = [j for j in labeled_tp if j[1].action == ACTION_DEFER]
    tp_borderline = [j for j in labeled_tp if j[1].action == ACTION_BORDERLINE]

    per_band = {}
    for band in (BAND_HIGH, BAND_MEDIUM, BAND_LOW):
        rows = [j for j in joined if j[1].band == band]
        per_band[band] = {
            "labeled": len(rows),
            "tp": sum(1 for j in rows if j[2].is_tp),
            "fp": sum(1 for j in rows if not j[2].is_tp),
            "deferred_tp": sum(1 for j in rows if j[2].is_tp and j[1].action == ACTION_DEFER),
        }

    per_class = {}
    for nf, d, label in joined:
        row = per_class.setdefault(_class_of(nf), {"labeled": 0, "tp": 0, "fp": 0,
                                                    "deferred": 0, "deferred_tp": 0, "borderline": 0})
        row["labeled"] += 1
        row["tp" if label.is_tp else "fp"] += 1
        if d.action == ACTION_DEFER:
            row["deferred"] += 1
            if label.is_tp:
                row["deferred_tp"] += 1
        elif d.action == ACTION_BORDERLINE:
            row["borderline"] += 1

    return {
        "labels": {
            "total": len(labels),
            "joined": len(joined),
            "unmatched_keys": len(labels) - len(joined),
            "tp": len(labeled_tp),
            "fp": len(labeled_fp),
            "reviewed": sum(1 for j in joined if j[2].reviewed),
        },
        "metrics": {
            "tp_recall": _rate(len(tp_retained), len(labeled_tp)),
            "escalation_precision": _rate(len(tp_retained), len(retained)),
            "fp_deferral_rate": _rate(len(fp_deferred), len(labeled_fp)),
            "false_negatives": len(false_negatives),
            "tp_in_borderline": len(tp_borderline),
            "escalation_rate": summary["escalation_rate"],
            "deferral_rate": summary["deferral_rate"],
        },
        "false_negative_keys": [j[1].key for j in false_negatives],
        "deferral_gate": {
            "labeled_tp_deferred": len(false_negatives),
            "safe_to_enable_deferral": bool(labeled_tp) and not false_negatives,
            "note": ("No labeled TP would be deferred." if bool(labeled_tp) and not false_negatives
                     else "Do not enable deferral: labeled TPs are deferred or no TP labels exist."),
        },
        "per_band": per_band,
        "per_vulnerability_class": per_class,
        "estimated_savings": summary["estimated_savings"],
        "summary": summary,
    }


def calibrate(config: Optional[PipelineConfig] = None, labels_file=None,
              reviewed_only: bool = False, log=print) -> dict:
    """Static-only calibration on the configured Semgrep input. No LLM calls."""
    config = config or PipelineConfig()
    labels_file = Path(labels_file or config.labels_file)
    t0 = time.time()

    with open(config.semgrep_input, "r") as f:
        results = json.load(f)["results"]
    log(f"[Calibrate] {len(results)} findings, source root {config.source_root}")

    run = run_triage(results, config.source_root, config.triage,
                     allow_borderline=config.enable_small_model)
    labels = load_labels(labels_file, reviewed_only=reviewed_only, log=log)
    report = evaluate_run(run, labels, config.batch_size)
    report["mode"] = "static_only"
    report["config"] = config.to_dict()
    report["labels_file"] = str(labels_file)
    report["elapsed_seconds"] = round(time.time() - t0, 3)
    return report


def evaluate_output_file(output_file, labels_file, batch_size: int = 20, log=print) -> dict:
    """Score a finished ``llm_enhanced_sast.json`` on the same labels.

    Uses the ``triage.action`` stored on each result (post small-model) and checks that
    every retained finding actually received a robust ``analysis``. A legacy one-stage
    output (no ``triage`` block) is scored too: every finding counts as escalated and its
    key is derived from the finding itself, so the baseline and a hierarchical run can be
    compared on the same labels.
    """
    with open(output_file, "r") as f:
        data = json.load(f)
    results = data.get("results", [])
    labels = load_labels(labels_file, log=log)
    derived_keys = [nf.key for nf in normalize_findings(results)]

    counts = {"escalate": 0, "defer": 0, "legacy_no_triage": 0, "escalated_without_analysis": 0}
    joined_tp = joined_fp = tp_retained = fn = 0
    fn_keys = []
    verdicts = {}
    for item, derived_key in zip(results, derived_keys):
        triage = item.get("triage") or {}
        action = triage.get("action")
        key = triage.get("key") or derived_key
        if not action:
            counts["legacy_no_triage"] += 1
            action = "escalate"
        counts[action] = counts.get(action, 0) + 1
        analysis = item.get("analysis")
        if action != ACTION_DEFER and not isinstance(analysis, dict):
            counts["escalated_without_analysis"] += 1
        label = labels.get(key)
        if label is None:
            continue
        if label.is_tp:
            joined_tp += 1
            if action != ACTION_DEFER:
                tp_retained += 1
            else:
                fn += 1
                fn_keys.append(key)
        else:
            joined_fp += 1
        if isinstance(analysis, dict):
            verdict = str(analysis.get("verdict", "")).strip().lower()
            row = verdicts.setdefault(verdict or "missing", {"tp": 0, "fp": 0})
            row["tp" if label.is_tp else "fp"] += 1

    total = len(results)
    deferred = counts["defer"]
    return {
        "mode": "output_file",
        "output_file": str(output_file),
        "total_findings": total,
        "counts": counts,
        "metrics": {
            "tp_recall": _rate(tp_retained, joined_tp),
            "false_negatives": fn,
            "escalation_rate": _rate(total - deferred, total),
            "deferral_rate": _rate(deferred, total),
        },
        "false_negative_keys": fn_keys,
        "labels": {"joined": joined_tp + joined_fp, "tp": joined_tp, "fp": joined_fp},
        "robust_verdicts_by_label": verdicts,
        "deep_model": (data.get("pipeline") or {}).get("deep_model"),
        "estimated_savings": {
            "deep_model_findings_avoided": deferred,
            "deep_model_calls_avoided": math.ceil(total / batch_size) - math.ceil((total - deferred) / batch_size),
        },
    }


# ---------------------------------------------------------------------------
# Stratified sampling for manual review
# ---------------------------------------------------------------------------

def sample_for_labeling(run: TriageRun, per_stratum: int = 3, seed: int = 7,
                        existing: Optional[dict] = None) -> list:
    """Pick up to ``per_stratum`` unlabeled findings per (band, vulnerability class).

    Returns JSONL-ready dicts with an empty ``label`` for the reviewer to fill in.
    """
    rng = random.Random(seed)
    existing = existing or {}
    strata = {}
    for nf, d in zip(run.normalized, run.decisions):
        if d.key in existing:
            continue
        strata.setdefault((d.band, _class_of(nf)), []).append((nf, d))

    rows = []
    for (band, cls), items in sorted(strata.items()):
        rng.shuffle(items)
        for nf, d in items[:per_stratum]:
            rows.append({
                "key": d.key,
                "label": "",
                "source": "manual",
                "reviewed": False,
                "note": "",
                "band": band,
                "score": d.score,
                "action": d.action,
                "vulnerability_class": cls,
                "path": nf.path,
                "line": nf.start_line,
                "check_id": nf.check_id,
            })
    return rows


def print_report(report: dict, log=print):
    m = report["metrics"]
    log("\n=== Calibration ===")
    log(f"mode: {report.get('mode')}")
    if "labels" in report:
        lab = report["labels"]
        log(f"labels: {lab.get('joined')} joined (TP={lab.get('tp')}, FP={lab.get('fp')})"
            + (f", {lab.get('unmatched_keys')} unmatched" if "unmatched_keys" in lab else ""))
    log(f"tp_recall={m.get('tp_recall')}  escalation_precision={m.get('escalation_precision')}  "
        f"false_negatives={m.get('false_negatives')}")
    log(f"escalation_rate={m.get('escalation_rate')}  deferral_rate={m.get('deferral_rate')}")
    if "tp_in_borderline" in m:
        log(f"labeled TP routed to small model: {m['tp_in_borderline']}")
    gate = report.get("deferral_gate")
    if gate:
        log(f"deferral gate: {'SAFE' if gate['safe_to_enable_deferral'] else 'BLOCKED'} — {gate['note']}")
    sav = report.get("estimated_savings") or {}
    log(f"estimated savings: {sav.get('deep_model_findings_avoided')} findings, "
        f"{sav.get('deep_model_calls_avoided')} deep calls"
        + (f", ~{sav.get('tokens_avoided')} tokens" if "tokens_avoided" in sav else ""))
    if report.get("false_negative_keys"):
        log("false negatives:")
        for key in report["false_negative_keys"][:25]:
            log(f"  - {key}")
