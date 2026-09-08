"""Seed ``labels/triage_labels.jsonl`` from the OWASP Benchmark ground truth.

For every Semgrep finding on a ``BenchmarkTestNNNNN.java`` file, the Benchmark's
``expectedresults-1.2.csv`` says whether that test case is a real vulnerability and which
CWE it exercises. A finding whose CWE matches the expected CWE is labeled ``TP`` when the
test case is real and ``FP`` otherwise. Findings whose CWE does not match the test case's
category are unscored by the Benchmark and are skipped rather than guessed.

Labels are written with ``reviewed: false``; confirm them by hand before trusting them
with ``--reviewed-only``.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sast_triage.config import DEFAULT_LABELS_FILE, DEFAULT_SEMGREP_INPUT  # noqa: E402
from sast_triage.triage import normalize_findings  # noqa: E402

DEFAULT_EXPECTED = Path("/home/Deus/Projects/BenchmarkJava/expectedresults-1.2.csv")
SOURCE_NAME = "benchmark-expectedresults-1.2"
TEST_FILE_RE = re.compile(r"(BenchmarkTest\d{5})\.java$")

# Semgrep reports a sibling CWE for some Benchmark categories; treat these as equal.
CWE_EQUIVALENTS = {
    326: 327,   # inadequate encryption strength  ~ broken/risky crypto algorithm
    327: 327,
    328: 328,
    330: 330,
    338: 330,   # weak PRNG ~ insufficiently random values
}


def load_expected(path: Path) -> dict:
    expected = {}
    with open(path, newline="") as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#"):
                continue
            name, category, real, cwe = row[0].strip(), row[1].strip(), row[2].strip(), row[3].strip()
            expected[name] = {"category": category, "real": real.lower() == "true", "cwe": int(cwe)}
    return expected


def canonical(cwe: int) -> int:
    return CWE_EQUIVALENTS.get(cwe, cwe)


def seed(semgrep_input: Path, expected_csv: Path, out: Path, keep_manual: bool = True) -> dict:
    with open(semgrep_input) as f:
        results = json.load(f)["results"]
    expected = load_expected(expected_csv)

    stats = {"total": 0, "tp": 0, "fp": 0, "not_testcase": 0, "unknown_testcase": 0, "cwe_mismatch": 0}
    rows = []
    for nf in normalize_findings(results):
        stats["total"] += 1
        match = TEST_FILE_RE.search(nf.path)
        if not match:
            stats["not_testcase"] += 1
            continue
        info = expected.get(match.group(1))
        if info is None:
            stats["unknown_testcase"] += 1
            continue
        if canonical(info["cwe"]) not in {canonical(c) for c in nf.cwe_ids}:
            stats["cwe_mismatch"] += 1
            continue
        label = "TP" if info["real"] else "FP"
        stats["tp" if info["real"] else "fp"] += 1
        rows.append({
            "key": nf.key,
            "label": label,
            "source": SOURCE_NAME,
            "reviewed": False,
            "note": "",
            "test_name": match.group(1),
            "category": info["category"],
            "expected_cwe": info["cwe"],
            "reported_cwe": nf.cwe_ids,
        })

    manual = []
    if keep_manual and out.exists():
        with open(out) as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                try:
                    data = json.loads(stripped)
                except ValueError:
                    continue
                if data.get("source") != SOURCE_NAME:
                    manual.append(stripped)

    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as f:
        f.write(f"# Seeded from {expected_csv.name}; {stats['tp']} TP / {stats['fp']} FP; "
                f"{stats['cwe_mismatch']} CWE-mismatched findings skipped. reviewed=false until confirmed.\n")
        for row in rows:
            f.write(json.dumps(row, separators=(",", ":")) + "\n")
        if manual:
            f.write("# --- manual labels (preserved) ---\n")
            for line in manual:
                f.write(line + "\n")
    stats["manual_preserved"] = len(manual)
    return stats


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--semgrep-input", type=Path, default=DEFAULT_SEMGREP_INPUT)
    parser.add_argument("--expected", type=Path, default=DEFAULT_EXPECTED)
    parser.add_argument("--out", type=Path, default=DEFAULT_LABELS_FILE)
    parser.add_argument("--drop-manual", action="store_true",
                        help="do not preserve non-seeded labels already in the output file")
    args = parser.parse_args(argv)
    stats = seed(args.semgrep_input, args.expected, args.out, keep_manual=not args.drop_manual)
    print(json.dumps(stats, indent=2))
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
