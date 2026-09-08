"""Emit OWASP-Benchmark-scorable Semgrep-format result files from pipeline output.

The BenchmarkUtils ``SemgrepReader`` counts every finding in a file as a positive
prediction. To score the *pipeline's judgement* (not raw Semgrep) we write a file
containing only the findings the pipeline keeps as real vulnerabilities:

    kept  <=>  triage.action != "defer"  AND  analysis.verdict is not "False Positive"

("Inconclusive" is kept - the pipeline did not clear it.) Each output file gets a
distinct ``version`` string so the scorer produces a separate scorecard per variant.

Usage:
    python benchmark_scorecard.py            # writes the three files into BenchmarkJava/results/
    python benchmark_scorecard.py --dry-run  # just print the keep/drop counts
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

BENCHMARK_RESULTS_DIR = Path("/home/Deus/Projects/BenchmarkJava/results")

SEMGREP_FIELDS = ("check_id", "path", "start", "end", "extra")


def strip_to_semgrep(finding: dict) -> dict:
    """Keep only the fields SemgrepReader needs; drop triage/analysis."""
    return {k: finding[k] for k in SEMGREP_FIELDS if k in finding}


def _verdict(finding) -> str:
    a = finding.get("analysis")
    return str(a.get("verdict", "")).strip().lower() if isinstance(a, dict) else ""


def keep_finding(finding: dict, drop_inconclusive: bool = False) -> bool:
    """A finding is 'kept as a real vulnerability' when triage did not defer it and the
    robust model did not call it a False Positive. With ``drop_inconclusive`` the
    model's Inconclusive verdicts are dropped too (lower FPR, lower recall)."""
    if (finding.get("triage") or {}).get("action") == "defer":
        return False
    v = _verdict(finding)
    if "false" in v:
        return False
    if drop_inconclusive and "inconclusive" in v:
        return False
    return True


def write_semgrep_file(path: Path, version: str, findings: list) -> None:
    payload = {
        "version": version,
        "results": [strip_to_semgrep(f) for f in findings],
        "errors": [],
    }
    path.write_text(json.dumps(payload))


def summarize(findings: list, drop_inconclusive: bool = False) -> dict:
    not_deferred = [f for f in findings if (f.get("triage") or {}).get("action") != "defer"]
    return {
        "total": len(findings),
        "kept": sum(1 for f in findings if keep_finding(f, drop_inconclusive)),
        "dropped_deferred": len(findings) - len(not_deferred),
        "dropped_fp_verdict": sum(1 for f in not_deferred if "false" in _verdict(f)),
        "dropped_inconclusive": sum(1 for f in not_deferred if "inconclusive" in _verdict(f)) if drop_inconclusive else 0,
        "inconclusive_total": sum(1 for f in not_deferred if "inconclusive" in _verdict(f)),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pipeline", type=Path, action="append", metavar="LABEL=FILE.json",
                    help="a pipeline output to score (repeatable); LABEL becomes the scorecard version")
    ap.add_argument("--hierarchical", type=Path, default=Path("results/llm_enhanced_sast.json"))
    ap.add_argument("--onestage", type=Path, default=Path("results/baseline_onestage.json"))
    ap.add_argument("--raw-semgrep", type=Path, default=Path("data/semgrep/Semgrep-v1.0-results.json"))
    ap.add_argument("--out-dir", type=Path, default=BENCHMARK_RESULTS_DIR)
    ap.add_argument("--drop-inconclusive", action="store_true",
                    help="also drop the model's Inconclusive verdicts (lower FPR, lower recall)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    variants = []  # (label, version, out_name, findings, apply_filter)
    raw = json.loads(args.raw_semgrep.read_text())["results"]
    variants.append(("raw Semgrep (no triage)", "RAW", "Benchmark_1.2-Semgrep-vRAW.json", raw, False))

    if args.pipeline:
        for spec in args.pipeline:
            label, _, path = str(spec).partition("=")
            findings = json.loads(Path(path).read_text())["results"]
            tag = label.upper().replace("_", "-")
            variants.append((label, tag, f"Benchmark_1.2-Semgrep-v{tag}.json", findings, True))
    else:
        hier = json.loads(args.hierarchical.read_text())["results"]
        variants.append(("hierarchical (triage + Haiku)", "HIER-HAIKU",
                         "Benchmark_1.2-Semgrep-vHIER-HAIKU.json", hier, True))
        if args.onestage.exists():
            one = json.loads(args.onestage.read_text())["results"]
            variants.append(("one-stage qwen3.5:9b", "ONESTAGE-QWEN",
                             "Benchmark_1.2-Semgrep-vONESTAGE-QWEN.json", one, True))

    for label, version, out_name, findings, apply_filter in variants:
        kept = ([f for f in findings if keep_finding(f, args.drop_inconclusive)]
                if apply_filter else findings)
        if apply_filter:
            s = summarize(findings, args.drop_inconclusive)
            extra = (f"  (dropped {s['dropped_deferred']} deferred, {s['dropped_fp_verdict']} FP"
                     + (f", {s['dropped_inconclusive']} Inconclusive" if args.drop_inconclusive
                        else f"; {s['inconclusive_total']} Inconclusive kept") + ")")
        else:
            s, extra = {"total": len(findings), "kept": len(findings)}, ""
        print(f"{label:32s} version={version:16s} -> {s['kept']}/{s['total']} findings{extra}")
        if not args.dry_run:
            args.out_dir.mkdir(parents=True, exist_ok=True)
            write_semgrep_file(args.out_dir / out_name, version, kept)

    if not args.dry_run:
        print(f"\nwrote {len(variants)} files to {args.out_dir}")
        print("next:  cd /home/Deus/Projects/BenchmarkJava && "
              "mvn -Djava.awt.headless=true org.owasp:benchmarkutils-maven-plugin:create-scorecard")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
