"""Operational utility: recover findings from raw LLM batch dumps.

When a robust-model batch cannot be parsed, ``model_training`` writes the raw reply to
``llm_analysis_raw_batch_<n>.txt``. This script re-runs the JSON repair pipeline over
those dumps, validates what comes back, and optionally writes the recovered analyses to
a JSON file. It is not an automated test and does nothing on import.
"""

from __future__ import annotations

import argparse
import glob
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sast_triage.json_repair import repair_and_parse_json
from sast_triage.context import extract_findings_from_parsed

DEFAULT_GLOB = "llm_analysis_raw_batch_*.txt"
EXPECTED_ANALYSIS_KEYS = ("verdict", "confidence", "severity_assessment")


def validate_findings(findings):
    """Return (valid_count, problems) for a list of parsed finding dicts."""
    problems = []
    valid = 0
    for i, item in enumerate(findings):
        if not isinstance(item, dict):
            problems.append(f"item {i}: not an object ({type(item).__name__})")
            continue
        analysis = item.get("analysis") if isinstance(item.get("analysis"), dict) else item
        missing = [k for k in EXPECTED_ANALYSIS_KEYS if k not in analysis]
        if missing:
            problems.append(f"item {i}: missing {', '.join(missing)}")
            continue
        valid += 1
    return valid, problems


def repair_file(path: Path) -> dict:
    """Repair one raw dump. Returns a summary dict; ``findings`` is None on failure."""
    text = path.read_text(errors="ignore")
    summary = {"file": str(path), "status": "ok", "error": None, "findings": None,
               "count": 0, "valid": 0, "problems": []}
    if not text.strip() or text.strip() == "<EMPTY LLM RESPONSE>":
        summary.update(status="empty", error="empty file")
        return summary

    parsed, err = repair_and_parse_json(text)
    if parsed is None:
        summary.update(status="fail", error=err)
        return summary

    findings = extract_findings_from_parsed(parsed)
    if findings is None:
        summary.update(status="fail", error=f"parsed but no findings extracted (type={type(parsed).__name__})")
        return summary

    valid, problems = validate_findings(findings)
    summary.update(findings=findings, count=len(findings), valid=valid, problems=problems)
    if valid == 0 and findings:
        summary["status"] = "suspect"
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input-glob", default=DEFAULT_GLOB, help=f"raw dump pattern (default: {DEFAULT_GLOB})")
    parser.add_argument("--output", type=Path, default=None,
                        help="write recovered findings as JSON: {\"<file>\": [findings...]}")
    parser.add_argument("--verbose", "-v", action="store_true", help="print per-item validation problems")
    args = parser.parse_args(argv)

    raw_files = sorted(glob.glob(args.input_glob))
    if not raw_files:
        print(f"No files match {args.input_glob!r}")
        return 1

    ok = fail = total = 0
    recovered = {}
    for f in raw_files:
        summary = repair_file(Path(f))
        if summary["status"] in ("empty", "fail"):
            print(f"{f}: {summary['status'].upper()} - {summary['error']}")
            fail += 1
            continue
        flag = " (SUSPECT: no item has the expected analysis keys)" if summary["status"] == "suspect" else ""
        print(f"{f}: OK - {summary['count']} findings, {summary['valid']} valid{flag}")
        if args.verbose:
            for problem in summary["problems"]:
                print(f"    {problem}")
        ok += 1
        total += summary["count"]
        recovered[f] = summary["findings"]

    print(f"\nSummary: {ok} OK, {fail} FAIL, {total} total findings recovered")
    if args.output:
        with open(args.output, "w") as out:
            json.dump(recovered, out, indent=2)
        print(f"Recovered findings written to {args.output}")
    return 0 if fail == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
