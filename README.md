# Hierarchical SAST Finding Triage

Reduce false positives in a Semgrep scan of OWASP BenchmarkJava with a three-stage
pipeline:

```
Semgrep results
  → Layer 1: deterministic static triage        (no LLM — routes each finding)
  → Layer 2: cheap-model borderline screen       (optional, fail-closed)
  → Layer 3: robust LLM analysis                 (verdict + traced exploitability path)
  → llm_enhanced_sast.json                       (every finding, in input order)
```

Every stage is resumable per finding, keyed by a stable finding identity and guarded by
a configuration fingerprint, so a re-run only does what changed.

## Result

Official **OWASP Benchmark v1.2** scorecard (`scripts/benchmark_scorecard.py` +
`benchmarkutils-maven-plugin`), all runs against the full 2,410-finding Semgrep scan
(`p/security-audit`), full 2,740-test scorecard:

> **These numbers are not a measure of real-world performance, and shouldn't be read
> as one.** OWASP BenchmarkJava is a well-known, fully public repository — code and
> ground-truth labels both — that predates every model tested here and has almost
> certainly been seen during pretraining, in some form (the repo itself, blog posts
> analyzing it, papers benchmarking tools against it, its results published elsewhere
> online). A model can score well here partly by having internalized what this
> specific, famous benchmark looks like, in a way it could not for a private
> codebase. Treat this table as a comparison of these six configurations *against each
> other, on this instrument* — not as an estimate of what FPR/TPR to expect on your
> own, unseen code. See the "benchmark contamination" and "reasoning grounding"
> sections below for what we actually checked about this, and how far that checking
> goes (and where it stops).

| Variant | TPR | FPR | Score (TPR−FPR) | Cost | Time | Inconclusive | Context resolution |
|---|---|---|---|---|---|---|---|
| Raw Semgrep (no triage) | 88.1% | 44.1% | 43.96% | $0 | seconds | — | — |
| local qwen3.5:9b | 83.5% | 27.9% | 55.64% | $0 | ~6h14m* | 2.0% | **tree-sitter** |
| Haiku 4.5 | 83.4% | 19.9% | 63.54% | ~$8.41† | ~26m | 9.0% | **tree-sitter** |
| Muse Spark 1.3 (contributor) | 87.6% | 19.4% | 68.12% | $0.84 | ~1h18m | 23.2% | **tree-sitter** |
| Sonnet 5 (skeptical prompt, xhigh effort) | 87.3% | 32.5% | 54.83% | ~$39 | not recorded | 0.9% | regex *(pending re-run)* |
| DeepSeek V4.1 Flash | 85.9% | 16.2% | 69.70% | $2.22 | ~52m** | 2.0% | **tree-sitter** |
| GLM-5.3-Flash (OpenRouter) | 86.9% | 16.6% | **70.37%** | $1.99 | ~2h06m | 13.4% | **tree-sitter** |

\* qwen's run was interrupted partway by an unrelated system restart; this is active
processing time with the outage subtracted, not wall-clock across it. It's also the
clearest illustration that the tree-sitter fix isn't free for a local model the way it
is for an API one: the pre-fix run finished in ~47 minutes (`results/local_qwen35.json`
→ `deep_model.seconds`) at the same batch size and context window. Better-resolved
context means bigger prompts, and a local 9B model pays for that in wall-clock time,
not dollars — an API model just bills you more tokens and returns at roughly the same
speed.

\*\* Across two attempts: the first hit a balance-based rate limit partway through and
a resume hit a hard "insufficient balance" error; total reflects both attempts plus a
short pause for a top-up, not pure inference time.

† **Corrected (2026-09-16): this row previously said ~$7.67, which undercounted the run.**
The Anthropic runs (Haiku and Sonnet) are the only ones that used the Layer 2 small-model
screen, and the pipeline records that cost separately from Layer 3. `results/haiku_treesitter.json` has
`deep_model.token_usage.cost_usd` = 7.6686 (Layer 3, 1,630 calls) and
`deep_model.small_model_token_usage.cost_usd` = 0.7374 (Layer 2, 717 calls, also Haiku),
so the run cost ~$8.41. The old figure came from the run log's final summary line
(`robust tokens: ... ~$7.67`), which only prints the Layer 3 tokens. Both values are
token counts × list price ($1/M in, $5/M out), not an invoice; the Anthropic console is
the authoritative number. The "before" ~$4 in the tree-sitter comparison below comes
from an older run that also used Layer 2 but didn't record cost in its output file, so
whether it included the screen isn't known. Sonnet's ~$39 is unaffected once rounded:
`results/llm_enhanced_sast.json` has $38.68 for Layer 3 plus $0.74 for Layer 2, or ~$39.42.

Times come from log file birth/modification timestamps, not instrumented profiling —
treat them as ballpark, not precise. Sonnet's original run log wasn't preserved, so its
time genuinely isn't known rather than omitted for some other reason.

All variants share the same Layer 1 static triage; they differ in which model does the
Layer 3 robust analysis, and — as of the tree-sitter switch below — in which cross-file
context resolver built their prompt. "Inconclusive" is the model refusing to call a
verdict (kept as a positive finding, since the pipeline didn't clear it) — a high rate
usually means the model is starved of context it needs, not that it's unusually cautious.

### Cross-file context resolution: regex → real Java parsing (tree-sitter)

The original `context.py` resolved a finding's helper-method calls with hand-written
regexes (`Recv\.method\(`, brace-counting for method bounds, etc.). That has an
unfixable blind spot: it can only match a **receiver-qualified** call (`x.helper()`),
never a **bare** call to a sibling method in the same class (`helper()`, no `this.`) —
exactly the shape of the real bug this surfaced, `DatabaseHelper.executeSQLCommand()` in
BenchmarkJava calling `getSqlStatement()` unqualified, invisible to the old resolver.

`context.py` now parses with [tree-sitter-java](https://github.com/tree-sitter/tree-sitter-java)
instead: real method/class boundaries, generics, multi-line signatures and comments
fall out of the parse for free, and an unqualified call resolves against the calling
method's actual enclosing class (tracked through the parse tree), not just
dot-qualified ones. Verified against the literal `DatabaseHelper.java` file the gap was
found in (see `tests/test_cross_file_context.py::SameClassUnqualifiedCalls`).

The effect was much larger than expected — this wasn't a minor accuracy tweak, it
roughly **doubled the Score** for every API-backed model re-run, and gave even the
free local model a solid double-digit jump:

| Variant | Score before | Score after | Inconclusive before → after | Cost before → after |
|---|---|---|---|---|
| local qwen3.5:9b | 47.54% | 55.64% | ~3.3% → 2.0% | $0 → $0 |
| Muse Spark 1.3 | 52.39% | 68.12% | 47.6% → 23.2% | $0.93 → $0.84 |
| Haiku 4.5 | 47.59% | 63.54% | ~low → 9.0% | ~$4 → $8.41† |
| DeepSeek V4.1 Flash | 55.12% | 69.70% | 2.1% → 2.0% | $3.12 → $2.22 |

Muse Spark's old 47.6% Inconclusive rate specifically was never the model being overly
cautious — it was correctly refusing to guess when it couldn't see a helper method's
body. Give it that context and it jumps from the weakest configuration tested to
competing for the strongest. (Haiku's re-run also *added* cross-file context and
auto-confirm for the first time — its original run predates both, an older config
schema — so its jump isn't a pure single-variable comparison the way the others are;
its cost also rose rather than fell, since the prompt genuinely grew.) qwen's smaller
jump relative to the API models is itself informative: better context helps every
model, but a 9B local model still can't reason about it as well as the larger ones,
so the ceiling the parser fix raises is lower for it.

**Re-run status**: local qwen3.5:9b, Muse Spark, Haiku and DeepSeek are all done, plus
the new GLM-5.3-Flash backend below. Only **Sonnet** still reflects the old
regex-based resolver and is pending re-run — treat that row as **not yet comparable**
to the rest until that happens.

### A sixth backend: GLM-5.3-Flash via OpenRouter, now the overall leader

Added `backends/openrouter.py`, a generic adapter for any model OpenRouter hosts (not
GLM-specific) — `--backend openrouter --openrouter-model <id>`, defaulting to
`z-ai/glm-5.3-flash`. Cost is read straight from OpenRouter's own `usage.cost` field
(its credits are 1:1 with USD) instead of a hard-coded price table that would go stale.

One thing worth knowing if you point this at a `:free`-suffixed model: OpenRouter can
retire the free variant out from under you with no warning beyond a 404 on the next
call — that happened mid-setup here (`z-ai/glm-5.3-flash:free` → paid-only, "use this
slug instead: z-ai/glm-5.3-flash"), caught by the smoke test before any run spent money
on it, not after.

Built with tree-sitter from the start (no regex-resolver baseline exists for this one),
GLM-5.3-Flash came out **the best-performing configuration of all six tested**, and
one of the cheapest:

| Variant | Score | Cost | Inconclusive |
|---|---|---|---|
| GLM-5.3-Flash | **70.37%** | $1.99 | 13.4% |
| DeepSeek V4.1 Flash | 69.70% | $2.22 | 2.0% |

Its Inconclusive rate (13.4%) sits between DeepSeek's (2.0%) and Muse Spark's (23.2%) —
worth digging into in a write-up if there's time, since it's the one open question this
result doesn't answer: whether that gap is a genuine calibration difference between
models or another context-starvation symptom like Muse Spark's was.

### Benchmark contamination

**A methodological caveat worth keeping in any write-up**: OWASP Benchmark is an old,
fully public dataset (ground truth included) — a frontier model doing suspiciously well
on a small bounded subset of it may be pattern-matching a benchmark it has memorized
rather than reasoning from the code. Both Muse Spark and DeepSeek showed a near-perfect
TPR/FPR on a 150-finding bounded subset that did **not** hold up at full scale, under
either resolver — Muse Spark's full-run FPR went from an apparent 0.0% (subset) to
34.9% (old resolver) / 19.4% (tree-sitter); DeepSeek's from 0.0% (subset) to 31.1% (old
resolver) / 16.2% (tree-sitter) — treat any bounded-subset number as a sanity check,
not a result, and always confirm on the full run.

### Reasoning grounding: did models get correct verdicts for the wrong reasons?

The full-scale FPR degradation above is *outcome*-level evidence against wholesale
memorization (if a model had simply memorized this benchmark's answer key, its FPR
wouldn't degrade at full scale the way it did). This section asks the complementary
*process*-level question directly: on findings where a model's verdict was correct, is
its stated reasoning actually grounded in the code it was shown, or could it be
reciting a plausible-sounding answer it already "knew"?

**Two automated approaches were tried and rejected** (documented here instead of
silently discarded, since a wrong automated number would be worse than none):

1. *Bag-of-identifiers overlap* — extract non-generic identifier-shaped tokens from
   the reasoning text and check how many also appear in the reconstructed code
   context. Every model cleared even a strict version of this trivially (0% "zero
   overlap" across all five) — it turned out to mostly measure whether a model wrote
   in full English sentences at all, not whether it fabricated anything.
2. *Precision of named identifiers* — same idea, inverted: what fraction of the
   specific things a model *names* are real code elements? This produced wildly
   different "fabrication rates" per model (9.7% to 94.0%) that tracked writing
   *style*, not accuracy — terser, code-shorthand answers (Muse Spark) scored as more
   "grounded" than fuller prose (Haiku, DeepSeek) purely because prose has more
   English words per code reference, not because the prose was less accurate. Caught
   by reading the actual flagged examples before trusting the number, which is the
   only reason this didn't ship as a real result.

A **backtick-quotation** heuristic (only checking text models explicitly formatted as
code) was considered and dropped before running fully: backtick usage varies from 3.5%
of responses (qwen) to 66% (DeepSeek) across models, too uneven to compare fairly.

**What was done instead**: a manual audit. Ten reasoning traces (2 findings × all 5
models) were read side-by-side against the actual BenchmarkJava source, chosen to
require genuine multi-step tracing rather than a shallow pattern match:

- **`BenchmarkTest00441` (SQL injection, true positive)** — traces `request.getParameter`
  through a *reflection-based* factory (`ThingFactory.createThing()` picks `Thing1` or
  `Thing2` at runtime from a properties file) into a polymorphic `doSomething()` call,
  into string concatenation, into `Statement.executeUpdate`. All five models correctly
  identified **both** possible implementations as non-sanitizing passthroughs (verified
  against the real `Thing1.java`/`Thing2.java`), and four of five explicitly noted that
  the ESAPI HTML-encoder present elsewhere in the file is a decoy — it encodes for
  display, after execution, and does nothing for the SQL sink. That's a specific,
  non-obvious detail a generic or memorized answer would have no reason to get right.
- **`BenchmarkTest00937` (SQL injection, false positive / dead code)** — a `switch`
  on `"ABC".charAt(1)` that is always `'B'`, so the branches that would assign
  attacker-controlled input to the SQL string are unreachable; separately, the
  "attacker-controlled" source itself (`SeparateClassRequest.getTheValue()`) turns out
  to return a hardcoded constant regardless of the request. **All five models
  independently re-derived both decoys** — computing the actual `charAt` result and
  reading the actual helper method's return value — rather than asserting "this is
  safe" without justification.

Across all ten traces: correct verdicts, technically specific reasoning, no fabricated
API calls or invented sanitizers, and independent agreement on non-obvious details
that a shortcut answer had no reason to include. **No evidence of the
correct-verdict-via-hallucination pattern was found in this sample.**

#### A working metric: the showed-work rate

A later pass found one probe that *does* survive scrutiny. Many BenchmarkJava
false-positive cases are gated on constant arithmetic (`int num = 86; if ((7 * 42) -
num > 200) bar = "This_should_always_happen"; else bar = param;`). Whether a model
states the **correct computed value** (294, then 208) is objectively checkable against
the source, with no style confound: 208 is right and 222 is not, however tersely or
verbosely it's written.

| Model | Guard-condition findings | Showed correct computed value | Benchmark Score |
|---|---|---|---|
| local qwen3.5:9b | 505 | 108 (**21.4%**) | 55.64% |
| Haiku 4.5 | 475 | 136 (**28.6%**) | 63.54% |
| Muse Spark 1.3 | 505 | 296 (**58.6%**) | 68.12% |
| DeepSeek V4.1 Flash | 504 | 295 (**58.5%**) | 69.70% |
| GLM-5.3-Flash | 505 | 317 (**62.8%**) | 70.37% |

The rate tracks benchmark Score monotonically, which is the coherence check you'd want:
the models that demonstrably evaluate the guard are the models that score better.

**Verbosity is ruled out as the explanation** — the obvious confound, and the one that
killed heuristic #2 above. Muse Spark writes the *shortest* reasoning of any model
(98 words average, shorter than qwen's 126 and about half of Haiku's 188) yet shows
the correct computed value more than twice as often as Haiku. Writing more does not
produce a higher rate; actually doing the arithmetic does.

**What this metric is not**: it is *not* a bias/hallucination rate. Not stating the
number isn't evidence of fabricating it — plenty of traces correctly conclude "the
condition is always true" without showing the intermediate. It's a **floor on verified
genuine computation**, i.e. "at least this fraction of the time, the model provably did
the work rather than asserting a conclusion." The inverse direction stays unmeasured,
and three separate attempts to measure it failed.

#### The one confirmed fabrication

Manual review did surface a real instance, worth recording precisely because it's the
thing being looked for. On `BenchmarkTest00625.java`, **qwen3.5:9b** analysed two
findings in the *same file*, against the *same* guard condition:

| Finding | qwen's stated arithmetic | Correct? |
|---|---|---|
| line 61 | "(294 - 86 > 200) => (208 > 200)" | ✅ |
| line 74 | "Calculation: (308) - 86 = 222. 222 > 200" | ❌ — 7×42 is 294, not 308 |

Both reached the correct verdict (False Positive). The second one's stated derivation
is simply invented — and the same model computing it correctly a few lines earlier
shows this is unreliable computation, not a consistent misunderstanding. The other
four models computed 294/208 correctly on both. This is one confirmed case, in the
smallest (9B, local) model, found in a sample of dozens — not a measured rate, but a
demonstration that the failure mode is real and does occur.

A second, larger manual pass used a **stratified random sample** (25 findings — 15
true-positive, 10 false-positive — drawn with a fixed seed from the 740 findings all
five models got right, reviewed across all five models). Two cases from it are worth
recording because they discriminate reasoning from recall:

- `BenchmarkTest02208` inverts the dead-code pattern: `guess.charAt(2)` of `"ABC"` is
  `'C'`, which hits a **tainted** branch, where the more common `charAt(1)`=`'B'` case
  is safe. A model keyed to "hardcoded switch ⇒ safe decoy" fails here. All five
  computed the index and got it right.
- `BenchmarkTest00303` (command injection): DeepSeek alone noted that the Windows
  branch passes the tainted value as a **discrete argv element** while the Unix branch
  concatenates it into an `sh -c` string — a real semantic distinction about
  exploitability, not a detail available from knowing the benchmark's answer key.

**Net**: across ~45 traces reviewed by hand, one confirmed fabricated derivation (qwen,
above), zero invented APIs or sanitizers, and repeated correct evaluation of
non-obvious constant expressions. That rules out "pervasively hallucinating"; it does
not establish a rate, and the showed-work metric measures the positive direction only.
The honest next step for a real *rate* is a larger by-hand sample — not a fourth
automated proxy. Three were tried; each measured something other than what it was
built to measure, and each was only caught by reading the flagged examples.

#### Why there is no exact bias ratio here

Stating one would be false precision, and it's worth being explicit about why, since
this is the number a reader will most want:

- **1 fabrication in ~45 traces** is a 2.2% point estimate with a 95% confidence
  interval of roughly **0.4% – 11.6%** — a 30x spread. Split per model it's worse: the
  single instance was qwen's, on an n of ~9 traces, which supports no estimate at all.
- **The showed-work rate is not its inverse.** A trace that concludes "the condition is
  always true" without printing the intermediate hasn't fabricated anything; it just
  didn't show work. Reading 100% − 62.8% as "37.2% biased" is the most likely way this
  section gets misused.

Sample sizes required for a defensible pooled rate, assuming the true value is near 2%:

| Target precision | Traces to review |
|---|---|
| ±5% | ~30 |
| ±3% | ~85 |
| ±2% | ~190 |
| ±1% | ~750 |

Multiply by five for per-model rates. Because the event is rare, small samples mostly
return zero (at n=30 you'd expect 0.6 instances), so ~150–200 per model is the realistic
floor for a per-model figure. What's reported here instead: the showed-work rate (solid,
verbosity-controlled), the confirmed instance (documented, reproducible), and an explicit
statement that the fabrication rate was **not** measured.

**A cost caveat for DeepSeek, from its first (old-resolver) full run**: that $3.12 was
over 2x the $1.45 projected from the bounded test. The gap was retry overhead, not
per-finding cost: ~39 findings exhausted the 8,192-token budget entirely on hidden
reasoning tokens, returning empty content, and the retry logic resent the *same full
prompt* up to 13 times before some finally got through (each failed attempt still burns
input + reasoning tokens for zero output). 12 findings never got an analysis in the end
(0.5% of 2,410) and were kept as unscored positives. The tree-sitter re-run hit the same
failure mode on a smaller scale (3 findings, 0.1%, never got an analysis even after
retries) — the underlying fix (detect an empty response caused by `reasoning_tokens`
alone consuming the budget and raise `max_tokens` for that finding's retry, instead of
blindly resending) is still worth making, just not urgent at this failure rate.

**A new operational caveat, from the tree-sitter re-run**: DeepSeek's account-balance
handling surfaced two distinct failure modes worth distinguishing when budgeting a
run — an HTTP 429 tied to *remaining balance capping allowed concurrency* (the account
still has funds, but not enough for the requested concurrency) versus a hard HTTP 402
*Insufficient Balance* once funds actually ran out. Both are now caught by the
pipeline's existing fatal-error detection and abort the batch cleanly instead of
retrying into a wall, but only a real top-up (or lower `--api-concurrency`, for the 429
case) gets the run moving again.

### Remediation suggestion quality (manual evaluation, in progress)

Every robust-model verdict also carries a `remediation` field (present in 87–100% of each
model's analyses), but the benchmark scorecard only measures verdicts, not whether the
suggested fix is any good. This evaluation grades those suggestions by hand. No new model
runs are involved; it reads the existing tree-sitter run outputs.

**Sample.** Only findings that are real vulnerabilities (ground truth TP) and that *all
five* models classified correctly, so every model is graded on identical input. Findings
are drawn at random within the four categories below. For each one, the five suggestions
are shuffled and labeled A–E, and which model wrote which is revealed only after grading.

**Grading scale.**

| Grade | Meaning |
|---|---|
| Adequate | A **literal code call applied to the vulnerable value** (e.g. `setString(1, bar)`, `Encode.forHtml(bar)`, `FilenameUtils.getName(bar)`), using an API that really exists, that fixes this code as written. Applies to every category. |
| Partial | Right idea, but generic, only names classes/APIs in prose, calls an API that doesn't exist, would fail as written, or offers a poor fix as an equal alternative. |
| Inadequate | Wrong, or doesn't fix the issue. |

Supporting rules: flawed side advice is recorded but never lowers the grade. It covers
outdated practice (removing `X-XSS-Protection: 0`, which re-enables the deprecated filter),
a bypassable control offered as the protection itself (escaping instead of parameterized
queries, an allowlist regex that still accepts `..`), *and* a weak control offered as an
extra layer behind an otherwise correct fix (a canonical `startsWith` prefix check with no
trailing separator). The last case is deliberate: a suggestion that pads a good fix with a
control that doesn't hold up is still telling the developer something wrong. Plumbing such
as obtaining a JDBC `Connection` or adding a dependency isn't required. Each suggestion also records whether it
goes **beyond the scanner's hint**, i.e. adds code-specific substance instead of repeating
the fix Semgrep's own message already named, since that message is part of the model's
prompt.

**Expected fix per category.**

| Category | Adequate fix |
|---|---|
| SQL injection (CWE-89) | Parameterized query: `PreparedStatement` with every `?` bound |
| XSS (CWE-79) | HTML output encoding of the value before writing it |
| Path traversal (CWE-22) | Strip directory components, or canonicalize and check containment against `base + File.separator` |
| Command injection (CWE-78) | Remove the shell (`sh -c` / `cmd.exe /c`) from the value's path: a Java API, or direct execution with separate arguments plus an allowlist |

**Calibration, disclosed.** The rules were not fixed in advance. Findings 1–4 (one per
category) were graded jointly and each disagreement became a written rule. Examples:
correct-but-generic counts as Partial; a nonexistent API (`HtmlEncoder.encode`) counts as
Partial; a poor alternative offered as an equal option caps the grade at Partial; a literal
code call is required everywhere, including restructuring fixes. All four were then
re-graded under the final rules, so they sit in the same data pool as the rest. The rules
were frozen after finding 4 (SHA-256 recorded in the grades file), and every grade change
made during calibration is kept in the file's history. Because the rules were shaped on
these four, results are reported **with and without** them.

**Independent phase.** 11 more findings (3 SQLi, 3 XSS, 3 path traversal, 2 command
injection) are graded under the frozen rules. The second reviewer's grades are written to
a file *before* the primary grader answers, which gives an inter-rater agreement figure
that the jointly graded calibration findings can't provide.

**Things this already surfaced** (from the calibration findings, so illustrative rather
than measured):

- A suggestion calling a Java API that doesn't exist: `HtmlEncoder.encode(bar)` (qwen). It
  isn't in the project's dependencies or any common Java library; the name matches .NET's
  `System.Text.Encodings.Web.HtmlEncoder`.
- A recommendation that would leave the code vulnerable: Apache Commons Lang
  `StringEscapeUtils` for shell escaping (Haiku). Checked against `commons-lang3` 3.20.0,
  which only escapes CSV, JavaScript, HTML, Java, JSON and XML.
- A containment check with a real bypass: comparing a canonical path against the canonical
  base directory with a plain prefix check (Muse Spark, Haiku). Canonical paths drop the
  trailing separator, so `testfiles_evil/x` passes a check for `testfiles`. Verified by
  running it in Java.
- 4 of 5 models recommended re-enabling `X-XSS-Protection`, which current OWASP guidance
  advises against. The benchmark code's `X-XSS-Protection: 0` is actually today's
  recommended value.
- Under the strict rule, no model reached Adequate on command injection. The better models
  gave the right approach but never wrote the code, so this reflects a lack of code-level
  fixes for restructuring problems, not wrong advice.

<!-- remediation-results:start -->

*Generated from `results/remediation_eval/grades.json` by `scripts/remediation_report.py`. Findings graded so far: 16 (4 calibration, 12 independent; planned: 4 calibration + 12 independent).*

**All findings (calibration + independent)**

| Model | n | Adequate | Partial | Inadequate | Beyond scanner hint | Flawed side advice |
|---|---|---|---|---|---|---|
| Claude Haiku 4.5 | 16 | 11 (69%) | 5 | 0 | 16/16 | 6/16 |
| DeepSeek V4.1 Flash | 16 | 10 (62%) | 6 | 0 | 16/16 | 9/16 |
| GLM-5.3-Flash | 16 | 8 (50%) | 8 | 0 | 16/16 | 9/16 |
| Meta Muse Spark 1.3 | 16 | 4 (25%) | 12 | 0 | 16/16 | 7/16 |
| qwen3.5:9b | 16 | 0 (0%) | 16 | 0 | 7/16 | 5/16 |

**Independent findings only** (sensitivity check)

| Model | n | Adequate | Partial | Inadequate | Beyond scanner hint | Flawed side advice |
|---|---|---|---|---|---|---|
| Claude Haiku 4.5 | 12 | 9 (75%) | 3 | 0 | 12/12 | 3/12 |
| DeepSeek V4.1 Flash | 12 | 7 (58%) | 5 | 0 | 12/12 | 8/12 |
| GLM-5.3-Flash | 12 | 6 (50%) | 6 | 0 | 12/12 | 8/12 |
| Meta Muse Spark 1.3 | 12 | 3 (25%) | 9 | 0 | 12/12 | 5/12 |
| qwen3.5:9b | 12 | 0 (0%) | 12 | 0 | 6/12 | 3/12 |

**Inter-rater agreement (independent findings)**

56/60 suggestions graded identically (93%); Cohen's kappa = 0.86. Computed on the blind grades, given before the second reviewer's grades were revealed. 17 suggestion(s) had answers (grade or Q3) revised after the reveal; the model tables use the final answers. Second reviewer is an LLM (Claude), so this measures how consistently the rules can be applied, not that the grades are correct.

Restarted quizzes (primary grader restarted before any reveal; first attempt discarded and logged): #7 (`results/remediation_eval/second_reviewer/finding_07_restart_log.json`), #12 (`results/remediation_eval/second_reviewer/finding_12_restart_log.json`).

**Per finding**

| # | Phase | Category | Test case | DeepSeek V4.1 Flash | GLM-5.3-Flash | Claude Haiku 4.5 | Meta Muse Spark 1.3 | qwen3.5:9b |
|---|---|---|---|---|---|---|---|---|
| 1 | calibration | SQLi | `BenchmarkTest01890` | Adequate | Partial | Adequate | Partial | Partial |
| 2 | calibration | XSS | `BenchmarkTest02128` | Adequate | Adequate | Partial | Partial | Partial |
| 3 | calibration | Path | `BenchmarkTest02034` | Adequate | Adequate | Adequate | Adequate | Partial |
| 4 | calibration | Cmd | `BenchmarkTest02152` | Partial | Partial | Partial | Partial | Partial |
| 5 | independent | SQLi | `BenchmarkTest02287` | Partial | Partial | Adequate | Partial | Partial |
| 6 | independent | SQLi | `BenchmarkTest00018` | Adequate | Adequate | Adequate | Partial | Partial |
| 7 | independent | SQLi | `BenchmarkTest02455` | Adequate | Adequate | Adequate | Adequate | Partial |
| 8 | independent | XSS | `BenchmarkTest02486` | Adequate | Adequate | Adequate | Adequate | Partial |
| 9 | independent | XSS | `BenchmarkTest02327` | Adequate | Partial | Partial | Partial | Partial |
| 10 | independent | XSS | `BenchmarkTest02493` | Adequate | Adequate | Adequate | Adequate | Partial |
| 11 | independent | Path | `BenchmarkTest02469` | Adequate | Adequate | Adequate | Partial | Partial |
| 12 | independent | Path | `BenchmarkTest00028` | Adequate | Adequate | Adequate | Partial | Partial |
| 13 | independent | Path | `BenchmarkTest00222` | Partial | Partial | Adequate | Partial | Partial |
| 14 | independent | Cmd | `BenchmarkTest01944` | Partial | Partial | Partial | Partial | Partial |
| 15 | independent | Cmd | `BenchmarkTest00568` | Partial | Partial | Partial | Partial | Partial |
| 16 | independent | Cmd | `BenchmarkTest02147` | Partial | Partial | Adequate | Partial | Partial |

<!-- remediation-results:end -->

## Layout

```
main.py                      thin CLI entry point  (python main.py <command>)
pyproject.toml               editable-installable package `sast_triage`
src/sast_triage/
  config.py                  PipelineConfig — every knob, path default, fingerprint
  prompts.py                 robust-analysis + small-model prompt templates
  json_repair.py             recover malformed LLM JSON
  triage.py                  Layer 1: normalization, source reader, signals, scoring, decision
  screening.py               Layer 2: fail-closed borderline screen
  context.py                 cross-file helper resolution (tree-sitter-java) + per-batch prompt assembly
  calibration.py             report-only calibration against labels (no LLM)
  rag.py                     legacy embedding helpers (used by the notebook only)
  cli.py                     argument parsing for main.py
  backends/
    __init__.py              make_robust_model / make_small_model
    anthropic.py             Anthropic adapter, structured output, batch API, token/cost
    muse_spark.py            Meta Muse Spark 1.3 adapter (OpenAI-compatible), token/cost
    deepseek.py              DeepSeek V4.1 Flash adapter, peak/off-peak token/cost
    openrouter.py            generic OpenRouter adapter (any hosted model), live-cost usage field
  pipeline/
    __init__.py              answer_question, triage_report_only  (orchestrators)
    progress.py              ProgressState, load_progress, save_progress
    routing.py               route_findings
    robust.py                analyze_escalated + batch runners + auto-confirm
    assembly.py              assemble_output, write_triage_report, load_semgrep
    export.py                highest-confidence export
tests/                       95 unit tests, no network / no Ollama needed
scripts/
  seed_labels.py             seed data/labels/ from the Benchmark ground truth
  benchmark_scorecard.py     turn a pipeline output into a scorable Semgrep file
  remediation_report.py      render the manual remediation evaluation into README.md
  repair_broken_findings.py  recover findings from raw failed-batch dumps
data/
  semgrep/Semgrep-v1.0-results.json   the scan under triage
  labels/                     ground truth for calibration (see labels/README.md)
results/                      pipeline outputs + scorecards (git-ignored, regenerable)
progress/                     resumable per-finding progress (git-ignored)
```

## Setup

```bash
python -m pip install -e .        # installs `sast_triage` + deps
```

## Use

```bash
# Layer 1 only — routing report, no model calls
python main.py triage

# Report-only calibration against labels/ — no model calls
python main.py calibrate

# Full hierarchical run (local Ollama by default)
python main.py analyze --enable-small-model

# Full run on the Anthropic API, as scored above
python main.py analyze \
  --backend anthropic --anthropic-model claude-sonnet-5 \
  --anthropic-thinking --anthropic-effort xhigh --anthropic-structured \
  --cross-file-context --auto-confirm-solved-categories --batch-size 1 --api-concurrency 16 \
  --small-backend anthropic --small-anthropic-model claude-haiku-4-5 \
  --enable-small-model --enable-deferral

# Full run on Muse Spark 1.3 (Meta Model API)
python main.py analyze \
  --backend muse-spark --muse-spark-model muse-spark-1.3-contributor \
  --cross-file-context --auto-confirm-solved-categories --batch-size 1 --api-concurrency 8

# Full run on DeepSeek V4.1 Flash
python main.py analyze \
  --backend deepseek --cross-file-context --auto-confirm-solved-categories \
  --batch-size 1 --api-concurrency 8

# Full run on any OpenRouter-hosted model (default: GLM-5.3-Flash)
python main.py analyze \
  --backend openrouter --openrouter-model z-ai/glm-5.3-flash \
  --cross-file-context --auto-confirm-solved-categories --batch-size 1 --api-concurrency 8

# Score a finished run on the OWASP Benchmark
python scripts/benchmark_scorecard.py --pipeline "SONNET=results/llm_enhanced_sast.json"
cd /home/Deus/Projects/BenchmarkJava && mvn -q org.owasp:benchmarkutils-maven-plugin:create-scorecard
```

`--backend anthropic` needs `ANTHROPIC_API_KEY` (workspace-scoped); `--backend
muse-spark` needs `MUSE_SPARK_API_KEY`; `--backend deepseek` needs `DEEPSEEK_API_KEY`;
`--backend openrouter` needs `OPENROUTER_API_KEY` — all read from the environment or
`.env`.

## Tests

```bash
cd tests && python -m unittest discover -p "test_*.py"
```
