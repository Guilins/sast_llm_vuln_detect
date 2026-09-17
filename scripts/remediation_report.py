"""Render the manual remediation-quality evaluation into README.md.

Reads results/remediation_eval/grades.json and rewrites the block between
<!-- remediation-results:start --> and <!-- remediation-results:end --> in README.md.
Tables are generated, never hand-edited, so they cannot drift from the grades.

Usage:
    python scripts/remediation_report.py            # rewrite the README block
    python scripts/remediation_report.py --print    # print the block only
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GRADES = ROOT / "results" / "remediation_eval" / "grades.json"
README = ROOT / "README.md"
START, END = "<!-- remediation-results:start -->", "<!-- remediation-results:end -->"

MODELS = ["DeepSeek V4.1 Flash", "GLM-5.3-Flash", "Claude Haiku 4.5",
          "Meta Muse Spark 1.3", "qwen3.5:9b"]
SHORT = {"sqli": "SQLi", "xss": "XSS", "path-traversal": "Path", "cmdi": "Cmd"}


def per_model(findings):
    rows = []
    for m in MODELS:
        grades = [f["grades"][m] for f in findings if m in f["grades"]]
        n = len(grades)
        count = {k: sum(g["grade"] == k for g in grades) for k in ("Adequada", "Parcial", "Inadequada")}
        beyond = sum(bool(g.get("beyond_scanner_hint")) for g in grades)
        issues = sum(g.get("q3", "No") != "No" for g in grades)
        rows.append((m, n, count, beyond, issues))
    rows.sort(key=lambda r: (-r[2]["Adequada"], r[0]))
    return rows


def model_table(findings):
    lines = ["| Model | n | Adequate | Partial | Inadequate | Beyond scanner hint | Flawed side advice |",
             "|---|---|---|---|---|---|---|"]
    for m, n, c, beyond, issues in per_model(findings):
        pct = f" ({c['Adequada'] / n:.0%})" if n else ""
        lines.append(f"| {m} | {n} | {c['Adequada']}{pct} | {c['Parcial']} | {c['Inadequada']} "
                     f"| {beyond}/{n} | {issues}/{n} |")
    return lines


def finding_table(findings):
    head = "| # | Phase | Category | Test case | " + " | ".join(MODELS) + " |"
    lines = [head, "|" + "---|" * (4 + len(MODELS))]
    abbrev = {"Adequada": "Adequate", "Parcial": "Partial", "Inadequada": "Inadequate"}
    for f in findings:
        test = f["finding"].split("/")[-1].split(".java")[0]
        cells = [abbrev[f["grades"][m]["grade"]] for m in MODELS]
        lines.append(f"| {f['n']} | {f.get('phase', '?')} | {SHORT.get(f['category'], f['category'])} "
                     f"| `{test}` | " + " | ".join(cells) + " |")
    return lines


def agreement(findings):
    # Blind grade (before the second reviewer was revealed) when a grade was revised afterwards.
    pairs = [(g.get("blind", g)["grade"], g["second_reviewer"]["grade"])
             for f in findings for g in f["grades"].values() if "second_reviewer" in g]
    if not pairs:
        return None
    n = len(pairs)
    agree = sum(a == b for a, b in pairs)
    cats = ["Adequada", "Parcial", "Inadequada"]
    po = agree / n
    pe = sum((sum(a == c for a, _ in pairs) / n) * (sum(b == c for _, b in pairs) / n) for c in cats)
    kappa = (po - pe) / (1 - pe) if pe < 1 else float("nan")
    return n, agree, po, kappa


def render(data):
    findings = data["findings"]
    indep = [f for f in findings if f.get("phase") == "independent"]
    out = [START, ""]
    out.append(f"*Generated from `results/remediation_eval/grades.json` by "
               f"`scripts/remediation_report.py`. Findings graded so far: {len(findings)} "
               f"({len(findings) - len(indep)} calibration, {len(indep)} independent; "
               f"planned: 4 calibration + "
               f"{sum(data['sampling_plan']['independent'].values())} independent).*")
    out += ["", "**All findings (calibration + independent)**", ""] + model_table(findings)
    out += ["", "**Independent findings only** (sensitivity check)", ""]
    out += model_table(indep) if indep else ["*No independent findings graded yet.*"]
    ag = agreement(indep)
    out += ["", "**Inter-rater agreement (independent findings)**", ""]
    if ag:
        n, agree, po, kappa = ag
        out.append(f"{agree}/{n} suggestions graded identically ({po:.0%}); Cohen's kappa = {kappa:.2f}. "
                   "Computed on the blind grades, given before the second reviewer's grades were revealed. "
                   f"{sum('blind' in g for f in indep for g in f['grades'].values())} suggestion(s) had answers "
                   "(grade or Q3) revised after the reveal; the model tables use the final answers. "
                   "Second reviewer is an LLM (Claude), so this measures how consistently the rules can "
                   "be applied, not that the grades are correct.")
    else:
        out.append("*Not available yet: calibration findings were graded jointly, so they carry no "
                   "independent second grade.*")
    restarts = [f for f in indep if "restart" in f]
    if restarts:
        out.append("")
        out.append("Restarted quizzes (primary grader restarted before any reveal; first attempt discarded "
                   "and logged): " + ", ".join(
                       f"#{f['n']} (`{f['restart']['file']}`)" for f in restarts) + ".")
    out += ["", "**Per finding**", ""] + finding_table(findings)
    out += ["", END]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--print", action="store_true", dest="print_only")
    args = ap.parse_args()
    block = render(json.loads(GRADES.read_text()))
    if args.print_only:
        print(block)
        return
    text = README.read_text()
    if START not in text or END not in text:
        raise SystemExit("README markers not found; add the section first.")
    head, rest = text.split(START, 1)
    _, tail = rest.split(END, 1)
    README.write_text(head + block + tail)
    print("README updated")


if __name__ == "__main__":
    main()
