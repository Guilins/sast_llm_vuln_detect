# Triage labels

Ground truth used by `python main.py calibrate` to measure whether the static triage
layer (and, later, the small-model screen) would hide any real vulnerability.

Labels are **never** derived from Semgrep severity, confidence, or the triage score.
They come from one of two places:

1. **Manual review** of the finding in context (`source: "manual"`, `reviewed: true`).
2. **Seeded from the OWASP Benchmark ground truth** (`source: "benchmark-expectedresults-1.2"`,
   `reviewed: false`) via `scripts/seed_labels.py`. These are correct by
   construction for the Benchmark but are still marked unreviewed until a person confirms
   them; pass `--reviewed-only` to calibrate on confirmed labels only.

## File: `triage_labels.jsonl`

One JSON object per line. Blank lines and lines starting with `#` are ignored.

| field      | required | meaning |
|------------|----------|---------|
| `key`      | yes      | Stable finding key (see below). |
| `label`    | yes      | `"TP"` (real vulnerability) or `"FP"` (not exploitable / not a vulnerability). |
| `source`   | no       | `"manual"` (default) or a dataset name. |
| `reviewed` | no       | `true` once a person has confirmed the label. |
| `note`     | no       | Free-text justification. Encouraged for manual labels. |

Any other fields (e.g. `test_name`, `expected_cwe`, `band`) are kept as informational
extras and ignored by the calibration code. If the same key appears twice, the later
line wins — append corrections rather than editing history.

## Stable finding keys

```
<path>:<start_line>:<start_col>-<end_line>:<end_col>:<check_id>
```

Example:

```
org/owasp/benchmark/testcode/BenchmarkTest00001.java:52:9-52:41:java.lang.security.audit.sqli.jdbc-sqli.jdbc-sqli
```

If two Semgrep results share every one of those fields, the second and later ones get a
`#2`, `#3`, ... suffix in input order. Keys are produced by `sast_triage.triage.raw_finding_key` /
`sast_triage.triage.normalize_findings`; do not construct them by hand — copy them from
`triage_report.json` or from the sampling command below.

## Workflow

```bash
# 1. Seed labels from the Benchmark ground truth (safe to re-run; rewrites the file)
python scripts/seed_labels.py

# 2. Pick a stratified sample (band x vulnerability class) of unlabeled findings
python main.py sample-labels --per-stratum 3 --out data/labels/to_review.jsonl

# 3. Fill in "label" and set "reviewed": true, then append to triage_labels.jsonl
cat data/labels/to_review.jsonl >> data/labels/triage_labels.jsonl

# 4. Re-run calibration
python main.py calibrate
```

## Routing knobs

Which findings the small model screens (`borderline`) is decided by vulnerability class,
not by a taint-flow heuristic — on this benchmark no local signal separates a real
injection bug from a sanitized one, so the small model does the judging.

- `--enable-small-model` — turn on the borderline stage (default: everything escalates).
- `--borderline-max-severity {INFO,WARNING,ERROR}` — highest severity eligible for the
  small model. Default `WARNING` keeps the plan's "always escalate ERROR" guard and
  routes ~717 findings (all XSS, WARNING SQLi/LDAP/XPath). `ERROR` widens it to ~1289
  (adds path traversal and command injection, ~75% of all labeled FPs become reachable).
- `--borderline-class SUBSTRING` (repeatable) — replace the eligible-class list.

None of these change recall until `--enable-deferral` is also set: without it, a finding
the small model dismisses still goes to the robust model.

## Deferral gate

Automatic deferral (`--enable-deferral`) must stay off until `calibrate` reports
`safe_to_enable_deferral: true` — i.e. zero labeled true positives land in the deferred
group.
