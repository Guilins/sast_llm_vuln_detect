"""Robust (deep) analysis stage: batch the escalated findings to the model,
auto-confirm ceiling categories, retry partial batches, record per finding."""

from __future__ import annotations

import time

from ..config import PipelineConfig
from ..context import build_batch_messages, extract_findings_from_parsed, _reformat_non_json_response
from ..json_repair import _normalize_llm_content, repair_and_parse_json
from ..triage import ACTION_ESCALATE, SourceReader, TriageRun
from .progress import ProgressState, save_progress


def _invoke_batch(llm, batch, reader, config: PipelineConfig, evidence_lines=None):
    """Send a single batch to the LLM with timeout and retry logic.

    Returns (raw_response, parsed, error).
    Retries up to ``config.max_retries`` times on timeout or empty response.
    """
    messages = build_batch_messages(batch, reader, config, evidence_lines)

    raw = ""
    parsed = None
    err = "No attempts made"

    for attempt in range(1, config.max_retries + 1):
        try:
            response = llm.invoke(messages)
            raw = _normalize_llm_content(response.content)
        except Exception as e:
            err_str = str(e)
            if "timed out" in err_str.lower() or "timeout" in err_str.lower():
                print(f"⏱ timeout (attempt {attempt}/{config.max_retries})", end=" ", flush=True)
                err = f"Timeout after {config.timeout}s"
                continue
            # Any other error (auth, 400, connection, ...): fail this batch, never crash
            # the run. Fatal-looking errors are detected and stop the retry pass upstream.
            return raw, None, f"{type(e).__name__}: {e}"

        if not raw.strip():
            print(f"⚠ empty (attempt {attempt}/{config.max_retries})", end=" ", flush=True)
            err = "Empty LLM response"
            continue

        parsed, err = repair_and_parse_json(raw)
        if parsed is not None:
            break

        # Fallback: ask LLM to reformat if initial parse failed
        try:
            reformatted = _reformat_non_json_response(llm, raw, len(batch))
            parsed, err = repair_and_parse_json(reformatted)
        except Exception:
            pass

        if parsed is not None:
            break

    return raw, parsed, err


def _merge_analysis(original_findings, analysis_list):
    """Merge LLM analysis back onto the original (full) findings (positional)."""
    merged = []
    for i, finding in enumerate(original_findings):
        result = finding.copy()
        if i < len(analysis_list) and isinstance(analysis_list[i], dict):
            result["analysis"] = analysis_list[i].get("analysis", analysis_list[i])
        merged.append(result)
    return merged


def _analysis_payload(item):
    """The LLM may wrap the analysis under ``analysis`` or return it flat.

    Requires a ``verdict`` field so a malformed/empty object is not recorded as a
    completed analysis (it will be retried instead).
    """
    if not isinstance(item, dict):
        return None
    inner = item.get("analysis")
    payload = inner if isinstance(inner, dict) else item
    return payload if "verdict" in payload else None


def _dump_raw(batch_label, raw):
    with open(f"llm_analysis_raw_batch_{batch_label}.txt", "w") as f:
        f.write(raw if raw.strip() else "<EMPTY LLM RESPONSE>")


def _chunks(items, size):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def _record_batch(progress: ProgressState, decisions_batch, analyses, allow_partial=False):
    """Store per-finding analyses by stable key, positionally.

    The analysis objects carry no identifying fields, so a positional merge is only
    trustworthy when the model returned exactly one object per finding. On a count
    mismatch nothing is recorded (the batch is retried in smaller pieces) unless
    ``allow_partial`` — used for size-1 retries where alignment is unambiguous.
    """
    if len(analyses) != len(decisions_batch) and not allow_partial:
        return 0
    recorded = 0
    for d, item in zip(decisions_batch, analyses):
        payload = _analysis_payload(item)
        if payload is not None:
            progress.completed[d.key] = payload
            recorded += 1
    return recorded


def _batches_for(pending, size):
    return list(_chunks(pending, size))


def _auto_confirm_class(nf, config: PipelineConfig) -> bool:
    classes = config.auto_confirm_classes or ()
    if not classes:
        return False
    cls = " ".join(nf.vulnerability_class).lower()
    return any(frag in cls for frag in classes)


def _apply_batch_outcome(progress, dbatch, raw, parsed, err, label, stats, failed_batches,
                         config, log, lock=None):
    """Record a finished batch (or mark it failed). Safe to call from a worker thread
    when ``lock`` is supplied — progress writes stay serialized."""
    analyses = extract_findings_from_parsed(parsed) if parsed is not None else None

    def _commit():
        stats["batches"] += 1
        if analyses is None:
            log(f"  batch {label}: ❌ {err if parsed is None else 'extraction failed'}")
            failed_batches.append(dbatch)
            stats["batch_failures"] += 1
            _dump_raw(label, raw)
            from ..backends.anthropic import is_fatal_error
            if parsed is None and err and is_fatal_error(err):
                stats["fatal_error"] = err
            return
        n_out = len(analyses)
        recorded = _record_batch(progress, dbatch, analyses)
        if recorded:
            save_progress(config.progress_file, progress)
        missing = [d for d in dbatch if d.key not in progress.completed]
        if not missing:
            log(f"  batch {label}: ✅ {recorded}/{len(dbatch)}")
        else:
            reason = "count mismatch" if n_out != len(dbatch) else f"{n_out - recorded} unusable"
            log(f"  batch {label}: ⚠️ {recorded}/{len(dbatch)} ({reason}) — {len(missing)} to retry")
            failed_batches.append(missing)
            stats["batch_failures"] += 1

    if lock is not None:
        with lock:
            _commit()
    else:
        _commit()


def _run_batches_sequential(llm, results, batches, reader, config, progress, stats,
                            failed_batches, log):
    for n, dbatch in enumerate(batches, 1):
        batch = [results[d.index] for d in dbatch]
        evidence = [d.evidence_summary() for d in dbatch]
        t0 = time.time()
        log(f"  Batch {n}/{len(batches)} ({len(batch)} findings)...", end=" ", flush=True)
        raw, parsed, err = _invoke_batch(llm, batch, reader, config, evidence)
        stats["seconds"] += time.time() - t0
        _apply_batch_outcome(progress, dbatch, raw, parsed, err, n, stats,
                             failed_batches, config, log)


def _run_batches_concurrent(llm, results, batches, reader, config, progress, stats,
                            failed_batches, log):
    from ..backends.anthropic import progress_lock, run_concurrent

    # Pre-warm the file cache so worker threads only read (no check-then-set races).
    for dbatch in batches:
        for d in dbatch:
            reader.lines(results[d.index].get("path", ""))

    def process(index, dbatch):
        batch = [results[d.index] for d in dbatch]
        evidence = [d.evidence_summary() for d in dbatch]
        t0 = time.time()
        raw, parsed, err = _invoke_batch(llm, batch, reader, config, evidence)
        return raw, parsed, err, time.time() - t0

    def on_result(index, dbatch, outcome):
        raw, parsed, err = ("", None, "worker crashed") if outcome is None else outcome[:3]
        if outcome is not None:
            stats["seconds"] += outcome[3]
        _apply_batch_outcome(progress, dbatch, raw, parsed, err, index, stats,
                             failed_batches, config, log, lock=progress_lock)

    log(f"  running {len(batches)} batches, {config.api_concurrency} at a time...")
    run_concurrent(process, batches, config.api_concurrency, on_result, log)


def _run_batches_batch_api(llm, results, batches, reader, config, progress, stats,
                           failed_batches, log):
    from ..backends.anthropic import submit_and_collect

    for dbatch in batches:  # cache warm-up, single threaded
        for d in dbatch:
            reader.lines(results[d.index].get("path", ""))

    requests = []
    by_id = {}
    for n, dbatch in enumerate(batches, 1):
        cid = f"batch-{n:04d}"
        by_id[cid] = (n, dbatch)
        batch = [results[d.index] for d in dbatch]
        evidence = [d.evidence_summary() for d in dbatch]
        requests.append((cid, build_batch_messages(batch, reader, config, evidence)))

    from ..backends.anthropic import ANALYSIS_RESPONSE_SCHEMA
    t0 = time.time()
    outcomes = submit_and_collect(
        requests, config.anthropic_model, config.anthropic_max_tokens,
        workspace_id=config.anthropic_workspace_id, thinking=config.anthropic_thinking,
        effort=config.anthropic_effort,
        output_schema=ANALYSIS_RESPONSE_SCHEMA if config.anthropic_structured else None, log=log)
    stats["seconds"] += time.time() - t0

    for cid, (n, dbatch) in by_id.items():
        result = outcomes.get(cid)
        if result is None or result.status != "succeeded":
            reason = "no result" if result is None else f"{result.status}: {result.error}"
            _apply_batch_outcome(progress, dbatch, "", None, reason, n, stats,
                                 failed_batches, config, log)
            continue
        parsed, err = repair_and_parse_json(result.text)
        _apply_batch_outcome(progress, dbatch, result.text, parsed, err, n, stats,
                             failed_batches, config, log)


def analyze_escalated(llm, results, run: TriageRun, config: PipelineConfig,
                      progress: ProgressState, reader=None, log=print) -> dict:
    """Send escalated findings to the robust model in batches, resuming by key.

    Dispatches to a sequential loop (Ollama), a thread pool, or the Message Batches API
    depending on ``config``; all three share progress, retry and output handling.
    """
    reader = reader or SourceReader(config.source_root)
    escalated = [d for d in run.decisions if d.action == ACTION_ESCALATE]
    if config.max_findings is not None:
        escalated = escalated[:config.max_findings]

    # Auto-confirm categories where the scanner's precision is already at ceiling
    # (OWASP Benchmark scorecard) — no LLM call adds value there.
    auto = [d for nf, d in zip(run.normalized, run.decisions)
            if d.action == ACTION_ESCALATE and _auto_confirm_class(nf, config)]
    if auto:
        for d in auto:
            if d.key not in progress.completed:
                progress.completed[d.key] = {
                    "verdict": "True Positive", "confidence": "high", "auto_confirmed": True,
                    "exploitability_evidence": ("auto-confirmed: scanner precision on this "
                                                "vulnerability class is ~100% on the OWASP Benchmark; "
                                                "LLM re-analysis skipped to save cost"),
                }
        save_progress(config.progress_file, progress)
        auto_classes = sorted({c for c in (config.auto_confirm_classes or ())})
        log(f"  auto-confirmed {len(auto)} findings in {auto_classes} (no LLM call)")
        stats_auto = len(auto)
    else:
        stats_auto = 0

    if config.cross_file_context:
        from ..context import ProjectIndex
        t0 = time.time()
        reader.project_index = ProjectIndex.build(config.source_root)
        log(f"  built cross-file index: {len(reader.project_index.class_files)} classes "
            f"({time.time() - t0:.1f}s)")

    pending = [d for d in escalated if d.key not in progress.completed]

    log(f"  {len(escalated)} escalated ({stats_auto} auto-confirmed), "
        f"{len(escalated) - len(pending) - stats_auto} already analysed, "
        f"{len(pending)} to the model in batches of {config.batch_size}")

    stats = {"escalated": len(escalated), "pending": len(pending), "batches": 0,
             "batch_failures": 0, "retried_sub_batches": 0, "seconds": 0.0,
             "backend": config.backend, "model": config.effective_robust_model()}
    failed_batches = []
    batches = _batches_for(pending, config.batch_size)
    progress.failed_keys = []  # recomputed from what is still missing at the end

    if batches:
        if config.backend == "anthropic" and config.use_batch_api:
            _run_batches_batch_api(llm, results, batches, reader, config, progress, stats,
                                   failed_batches, log)
        elif config.concurrency() > 1:
            _run_batches_concurrent(llm, results, batches, reader, config, progress, stats,
                                    failed_batches, log)
        else:
            _run_batches_sequential(llm, results, batches, reader, config, progress, stats,
                                    failed_batches, log)

    if stats.get("fatal_error"):
        log(f"  ✗ aborting robust stage — the backend rejected every request:\n"
            f"    {stats['fatal_error']}\n"
            f"    (nothing was analysed; fix the credential/config and re-run — "
            f"triage progress is cached)")
        failed_batches = []

    # Retry whatever is still missing: first in small sub-batches, then one finding at a
    # time for stragglers (size 1 makes the positional merge unambiguous).
    still_missing = []
    for dbatch in failed_batches:
        still_missing.extend(d for d in dbatch if d.key not in progress.completed)
    still_missing = list({d.key: d for d in still_missing}.values())

    if still_missing:
        for pass_size in (max(3, config.batch_size // 5), 1):
            targets = [d for d in still_missing if d.key not in progress.completed]
            if not targets:
                break
            log(f"\n[Step 3b] Retrying {len(targets)} findings (sub-batch size {pass_size})...")
            for sub_num, sub in enumerate(_chunks(targets, pass_size), 1):
                batch = [results[d.index] for d in sub]
                evidence = [d.evidence_summary() for d in sub]
                t0 = time.time()
                raw, parsed, err = _invoke_batch(llm, batch, reader, config, evidence)
                stats["retried_sub_batches"] += 1
                stats["seconds"] += time.time() - t0
                analyses = extract_findings_from_parsed(parsed) if parsed is not None else None
                if analyses is None:
                    log(f"  retry {sub_num} ({len(sub)}): ❌ {err if parsed is None else 'extraction failed'}")
                    continue
                recorded = _record_batch(progress, sub, analyses, allow_partial=(pass_size == 1))
                if recorded:
                    save_progress(config.progress_file, progress)
                log(f"  retry {sub_num} ({len(sub)}): {'✅' if recorded == len(sub) else '⚠️'} {recorded}/{len(sub)}")

    progress.failed_keys = [d.key for d in escalated if d.key not in progress.completed]
    save_progress(config.progress_file, progress)
    stats["analysed"] = len(escalated) - len(progress.failed_keys)
    stats["unanalysed"] = len(progress.failed_keys)
    stats["auto_confirmed"] = stats_auto
    usage = getattr(llm, "usage", None)
    if usage is not None:
        stats["token_usage"] = usage.to_dict(config.effective_robust_model(), config.use_batch_api)
    return stats
