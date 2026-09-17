# -*- coding: utf-8 -*-
"""Pick the next finding for hand-graded remediation review.

usage: remediation_next.py <category-substring> <seed>

Same criteria as the first one (ground truth TP, every model correct, every model gave
a remediation), skipping findings already in grades.json. Prints the Semgrep details,
official answer, the flagged method, the bodies of project methods it calls, and the
suggestions shuffled A-E. The shuffle is redone until it is not the original order;
the key goes to a separate file and is not printed.
"""
import csv
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, "/home/Deus/Projects/sast_vuln_detect/src")
from sast_triage.triage import SourceReader
from sast_triage.context import ProjectIndex, expand_calls

CATEGORY, SEED = sys.argv[1], int(sys.argv[2])
BASE = Path("/home/Deus/Projects/sast_vuln_detect")
BENCH = Path("/home/Deus/Projects/BenchmarkJava")
SRC = BENCH / "src/main/java"
SCRATCH = BASE / "results/remediation_eval/keys"
GRADES = BASE / "results/remediation_eval/grades.json"
FILES = {
    "qwen3.5:9b": "results/qwen_treesitter.json",
    "Claude Haiku 4.5": "results/haiku_treesitter.json",
    "Meta Muse Spark 1.3": "results/muse_spark_treesitter.json",
    "DeepSeek V4.1 Flash": "results/deepseek_treesitter.json",
    "GLM-5.3-Flash": "results/glm53flash.json",
}

done = {f["finding"] for f in json.loads(GRADES.read_text())["findings"]}

labels = {}
for line in (BASE / "data/labels/triage_labels.jsonl").read_text().splitlines():
    line = line.strip()
    if line and not line.startswith("#"):
        d = json.loads(line)
        labels[d["key"]] = d["label"].strip().upper()

per_model = {}
for name, rel in FILES.items():
    by_key = {}
    for f in json.loads((BASE / rel).read_text())["results"]:
        a = f.get("analysis") or {}
        k = (f.get("triage") or {}).get("key")
        if a and k and not a.get("auto_confirmed"):
            by_key[k] = (a, f)
    per_model[name] = by_key

candidates = []
for k in per_model["GLM-5.3-Flash"]:
    if k in done or labels.get(k) != "TP" or CATEGORY not in k:
        continue
    if all(per_model[n].get(k) and "true" in str(per_model[n][k][0].get("verdict", "")).lower()
           and per_model[n][k][0].get("remediation") for n in FILES):
        candidates.append(k)

rng = random.Random(SEED)
key = rng.choice(sorted(candidates))
finding = per_model["GLM-5.3-Flash"][key][1]
test_name = Path(finding["path"]).stem

models = list(FILES)
while models == list(FILES):
    rng.shuffle(models)
letters = "ABCDE"
(SCRATCH / f"remediation_KEY_{test_name}.json").write_text(
    json.dumps({"finding": key, "key": dict(zip(letters, models))}, indent=2))

expected = "?"
with open(BENCH / "expectedresults-1.2.csv") as fh:
    for row in csv.reader(fh):
        if row and row[0] == test_name:
            expected = ",".join(row)

e = finding["extra"]
m = e.get("metadata", {})
print(f"candidates left in '{CATEGORY}': {len(candidates)}")
print(f"FINDING: {key}")
print(f"rule: {finding['check_id']}")
print(f"severity: {e.get('severity')} | confidence: {m.get('confidence')} | impact: {m.get('impact')}")
print(f"cwe: {m.get('cwe')}")
print(f"message: {e.get('message')}")
print(f"official expectedresults row: {expected}")
print(f"flagged: line {finding['start']['line']} col {finding['start']['col']} -> "
      f"line {finding['end']['line']} col {finding['end']['col']}\n")

reader = SourceReader(SRC)
snip = reader.enclosing_method_snippet(finding["path"], finding["start"]["line"],
                                       finding["end"]["line"], 40)
start = snip.first_line or 1
print("=" * 25, "FLAGGED METHOD", "=" * 25)
for i, l in enumerate(snip.text.split("\n")):
    ln = start + i
    mark = ">>" if finding["start"]["line"] <= ln <= finding["end"]["line"] else "  "
    print(f"{mark}{ln:4d} | {l}")

index = ProjectIndex.build(SRC)
file_lines, _ = reader.lines(finding["path"])
calls = expand_calls(snip.text, "\n".join(file_lines), index)
print("\n" + "=" * 25, "CALLED PROJECT METHODS", "=" * 25)
for label, body in calls:
    print(f"\n# {label}\n{body}")

print("\n" + "=" * 25, "SUGGESTIONS (blind)", "=" * 25)
for letter, name in zip(letters, models):
    rem = per_model[name][key][0]["remediation"]
    print(f"\n--- Suggestion {letter} ---")
    for step in (rem if isinstance(rem, list) else [rem]):
        print(f"  - {step}")
