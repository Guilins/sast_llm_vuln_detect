"""Export the highest-AI-confidence findings, skipping triage-deferred ones."""

from __future__ import annotations

import json

from ..config import DEFAULT_HIGHEST_CONFIDENCE_FILE, DEFAULT_OUTPUT_FILE
from ..triage import ACTION_DEFER


def export_highest_ai_confidence_findings(
    input_file=DEFAULT_OUTPUT_FILE,
    output_file=DEFAULT_HIGHEST_CONFIDENCE_FILE,
    log=print,
):
    """Create a copy of enhanced SAST output keeping only highest AI confidence findings.

    Highest level is determined from values found in each finding's
    ``analysis.confidence`` field. Findings that were deferred by triage (and therefore
    carry no robust ``analysis``) are skipped on purpose and counted separately from
    findings whose analysis failed. The exported results exclude AI-generated analysis
    and triage fields.
    """
    confidence_order = {
        "info": 0,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    with open(input_file, "r") as f:
        data = json.load(f)

    results = data.get("results", [])
    scored = []
    skipped = {"deferred": 0, "no_analysis": 0, "no_confidence": 0, "unknown_confidence": 0}

    for finding in results:
        analysis = finding.get("analysis")
        if not isinstance(analysis, dict):
            triage = finding.get("triage") or {}
            if triage.get("action") == ACTION_DEFER:
                skipped["deferred"] += 1
            else:
                skipped["no_analysis"] += 1
            continue

        raw_conf = analysis.get("confidence")
        if raw_conf is None:
            skipped["no_confidence"] += 1
            continue

        conf = str(raw_conf).strip().lower()
        score = confidence_order.get(conf)
        if score is None:
            skipped["unknown_confidence"] += 1
            continue

        scored.append((score, finding))

    if not scored:
        filtered = []
    else:
        max_score = max(score for score, _ in scored)
        filtered = [
            {k: v for k, v in finding.items() if k not in ("analysis", "triage")}
            for score, finding in scored
            if score == max_score
        ]

    output_data = {
        "version": data.get("version"),
        "results": filtered,
    }

    with open(output_file, "w") as f:
        json.dump(output_data, f, indent=2)

    log(f"Saved {len(filtered)} highest-confidence findings to '{output_file}'")
    log(f"  skipped: {skipped['deferred']} deferred by triage, {skipped['no_analysis']} without analysis, "
        f"{skipped['no_confidence'] + skipped['unknown_confidence']} with missing/unknown confidence")
    output_data["skipped"] = skipped
    return output_data
