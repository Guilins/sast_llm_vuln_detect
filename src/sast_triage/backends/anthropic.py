"""Anthropic API backend for the robust analysis stage.

Two execution modes, both keyed by the same stable batch ids so progress and resume
work exactly as with the local Ollama backend:

* **concurrent** (default) - a thread pool of synchronous ``messages.create`` calls.
  Immediate results, full per-batch retry/repair reuse, ~5-15 min for the whole scan.
* **batch** (``use_batch_api``) - the Message Batches API: submit every batch at once,
  poll, then collect. 50% cheaper, asynchronous (minutes to ~1h for this size).

The module never imports ``anthropic`` at import time so the rest of the pipeline (and
its tests) keep working without the SDK installed.
"""

from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Optional

# Rough token accounting for the pre-run cost estimate (Haiku-class prompts).
_EST_INPUT_TOKENS_PER_FINDING = 420
_EST_OUTPUT_TOKENS_PER_FINDING = 260

# USD per 1M tokens, first-party API rates (cached 2026-06). Batch API halves both.
MODEL_PRICING = {
    "claude-haiku-4-5": (1.00, 5.00),
    "claude-sonnet-5": (2.00, 10.00),
    "claude-opus-5": (5.00, 25.00),
}


def _require_sdk():
    try:
        import anthropic  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "The 'anthropic' package is required for --backend anthropic. "
            "Install it with:  python -m pip install anthropic"
        ) from exc
    return anthropic


# Error substrings that mean "every request will fail the same way" - stop retrying.
FATAL_ERROR_MARKERS = (
    "authentication", "invalid x-api-key", "invalid_request_error", "workspace",
    "permission_error", "permission denied", "not_found_error", "billing", "credit balance",
)


def is_fatal_error(message: str) -> bool:
    low = (message or "").lower()
    return any(marker in low for marker in FATAL_ERROR_MARKERS)


def make_client(timeout: float = 600.0, workspace_id: Optional[str] = None, max_retries: int = 4):
    anthropic = _require_sdk()
    headers = {"anthropic-workspace-id": workspace_id} if workspace_id else None
    return anthropic.Anthropic(timeout=timeout, max_retries=max_retries, default_headers=headers)


# ---------------------------------------------------------------------------
# LangChain-message -> Anthropic-request translation
# ---------------------------------------------------------------------------

def split_messages(messages) -> tuple:
    """Return ``(system_text, anthropic_turns)`` from a list of LangChain messages."""
    system_parts, turns = [], []
    for m in messages:
        role = getattr(m, "type", "") or m.__class__.__name__.lower()
        content = m.content if isinstance(m.content, str) else str(m.content)
        if role in ("system", "systemmessage"):
            system_parts.append(content)
        else:
            turns.append({
                "role": "assistant" if role in ("ai", "aimessage", "assistant") else "user",
                "content": content,
            })
    if not turns:
        turns = [{"role": "user", "content": "Proceed."}]
    return "\n\n".join(p for p in system_parts if p), turns


def request_params(messages, model: str, max_tokens: int, thinking: bool = False,
                   effort: Optional[str] = None, output_schema: Optional[dict] = None) -> dict:
    """Build a Messages API request from LangChain-style messages.

    ``thinking`` turns on adaptive thinking; ``effort`` (low..max) sets depth/spend;
    ``output_schema`` constrains the response via ``output_config.format`` (guaranteed
    valid JSON, enum-checked fields). Prompt caching is not used — the robust prompt
    embeds per-batch findings/code, so there is no stable cacheable prefix.
    """
    system_text, turns = split_messages(messages)
    params = {"model": model, "max_tokens": max_tokens, "messages": turns}
    if system_text:
        params["system"] = system_text
    if thinking:
        params["thinking"] = {"type": "adaptive"}
    output_config = {}
    if effort:
        output_config["effort"] = effort
    if output_schema is not None:
        output_config["format"] = {"type": "json_schema", "schema": output_schema}
    if output_config:
        params["output_config"] = output_config
    return params


# Structured-output schema for the robust analysis. The API rejects array minItems>1,
# so the "exactly N objects" constraint stays in the prompt + the count-mismatch retry;
# this guarantees valid JSON and enum-constrained verdicts, and forces the evidence field.
_VERDICTS = ["True Positive", "False Positive", "Inconclusive"]
_LEVELS = ["high", "medium", "low"]

ANALYSIS_ITEM_SCHEMA = {
    "type": "object",
    "properties": {
        "exploitability_evidence": {"type": "string"},
        "verdict": {"type": "string", "enum": _VERDICTS},
        "confidence": {"type": "string", "enum": _LEVELS},
        "severity_assessment": {"type": "string", "enum": ["high", "medium", "low", "info"]},
        "root_cause": {"type": "string"},
        "impact": {"type": "string"},
        "remediation": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["exploitability_evidence", "verdict", "confidence"],
    "additionalProperties": False,
}

ANALYSIS_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {"findings": {"type": "array", "items": ANALYSIS_ITEM_SCHEMA}},
    "required": ["findings"],
    "additionalProperties": False,
}


def _reply_text(response) -> str:
    if getattr(response, "stop_reason", None) == "refusal":
        return ""
    return "".join(
        getattr(block, "text", "") for block in getattr(response, "content", [])
        if getattr(block, "type", None) == "text"
    )


class _Reply:
    """Minimal stand-in for a LangChain response object (`.content` is the text)."""

    def __init__(self, content: str):
        self.content = content


@dataclass
class TokenUsage:
    input: int = 0
    output: int = 0
    cache_write: int = 0
    cache_read: int = 0
    calls: int = 0

    def add(self, u) -> None:
        self.input += getattr(u, "input_tokens", 0) or 0
        self.output += getattr(u, "output_tokens", 0) or 0
        self.cache_write += getattr(u, "cache_creation_input_tokens", 0) or 0
        self.cache_read += getattr(u, "cache_read_input_tokens", 0) or 0
        self.calls += 1

    def cost_usd(self, model: str, batch_api: bool = False) -> float:
        in_price, out_price = MODEL_PRICING.get(model, (1.0, 5.0))
        if batch_api:
            in_price, out_price = in_price / 2, out_price / 2
        return round(
            (self.input * in_price
             + self.cache_write * in_price * 1.25
             + self.cache_read * in_price * 0.1
             + self.output * out_price) / 1e6, 4)

    def to_dict(self, model: str = "", batch_api: bool = False) -> dict:
        d = {"calls": self.calls, "input_tokens": self.input, "output_tokens": self.output,
             "cache_write_tokens": self.cache_write, "cache_read_tokens": self.cache_read}
        if model:
            d["cost_usd"] = self.cost_usd(model, batch_api)
        return d


class AnthropicChatAdapter:
    """Drop-in replacement for ``ChatOllama`` as far as ``_invoke_batch`` is concerned.

    Exposes ``.invoke(messages) -> obj with .content``. The SDK client handles retries
    for 429/5xx/timeouts internally; a policy refusal comes back as empty text, which the
    caller treats like any other empty response (retry, then mark the batch failed).
    Token usage across all calls accumulates on ``.usage`` (thread-safe).
    """

    def __init__(self, model: str, max_tokens: int, timeout: float = 600.0, client=None,
                 workspace_id: Optional[str] = None, thinking: bool = False,
                 effort: Optional[str] = None, output_schema: Optional[dict] = None):
        self.model = model
        self.max_tokens = max_tokens
        self.thinking = thinking
        self.effort = effort
        self.output_schema = output_schema
        self._client = client or make_client(timeout, workspace_id)
        self.usage = TokenUsage()
        self._lock = threading.Lock()

    def invoke(self, messages):
        params = request_params(messages, self.model, self.max_tokens, thinking=self.thinking,
                                effort=self.effort, output_schema=self.output_schema)
        response = self._client.messages.create(**params)
        u = getattr(response, "usage", None)
        if u is not None:
            with self._lock:
                self.usage.add(u)
        return _Reply(_reply_text(response))


# ---------------------------------------------------------------------------
# Cost estimate
# ---------------------------------------------------------------------------

@dataclass
class CostEstimate:
    model: str
    findings: int
    input_tokens: int
    output_tokens: int
    usd_low: float
    usd_high: float
    batch_api: bool

    def render(self) -> str:
        mode = "Batch API (50% off, async)" if self.batch_api else "concurrent sync"
        return (
            f"~{self.findings} findings via {self.model} ({mode})\n"
            f"  est. input  ~{self.input_tokens:,} tok\n"
            f"  est. output ~{self.output_tokens:,} tok\n"
            f"  est. cost   ${self.usd_low:.2f}–${self.usd_high:.2f} "
            f"(±50% on the estimate; actual usage is logged per batch)"
        )


def estimate_cost(model: str, findings: int, batch_api: bool = False) -> CostEstimate:
    in_tok = findings * _EST_INPUT_TOKENS_PER_FINDING
    out_tok = findings * _EST_OUTPUT_TOKENS_PER_FINDING
    in_price, out_price = MODEL_PRICING.get(model, (1.0, 5.0))
    if batch_api:
        in_price, out_price = in_price / 2, out_price / 2
    mid = in_tok / 1e6 * in_price + out_tok / 1e6 * out_price
    return CostEstimate(model, findings, in_tok, out_tok, mid * 0.6, mid * 1.5, batch_api)


# ---------------------------------------------------------------------------
# Concurrent synchronous execution
# ---------------------------------------------------------------------------

def run_concurrent(process_batch: Callable, batches: list, max_workers: int,
                   on_result: Callable, log=print) -> None:
    """Run ``process_batch(index, dbatch)`` over ``batches`` with a thread pool.

    ``on_result(index, dbatch, outcome)`` is called on the main thread as each finishes,
    so progress writes stay single-threaded and ordered by completion.
    """
    if not batches:
        return
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(process_batch, i, db): (i, db)
                   for i, db in enumerate(batches, 1)}
        for future in as_completed(futures):
            index, dbatch = futures[future]
            try:
                outcome = future.result()
            except Exception as exc:  # noqa: BLE001 - report and continue
                log(f"  batch {index}: worker crashed: {exc}")
                outcome = None
            on_result(index, dbatch, outcome)


# ---------------------------------------------------------------------------
# Message Batches API execution
# ---------------------------------------------------------------------------

@dataclass
class BatchApiResult:
    custom_id: str
    text: str
    status: str          # "succeeded" | "errored" | "canceled" | "expired"
    error: Optional[str] = None


def submit_and_collect(requests: list, model: str, max_tokens: int,
                       poll_interval: float = 15.0, client=None, workspace_id=None,
                       thinking: bool = False, effort=None, output_schema=None, log=print) -> dict:
    """Submit ``[(custom_id, [messages]), ...]`` as one batch and wait for results.

    Returns ``{custom_id: BatchApiResult}``.
    """
    _require_sdk()
    from anthropic.types.messages.batch_create_params import Request
    from anthropic.types.message_create_params import MessageCreateParamsNonStreaming

    client = client or make_client(workspace_id=workspace_id)
    payload = [
        Request(custom_id=cid,
                params=MessageCreateParamsNonStreaming(
                    **request_params(msgs, model, max_tokens, thinking=thinking,
                                     effort=effort, output_schema=output_schema)))
        for cid, msgs in requests
    ]
    batch = client.messages.batches.create(requests=payload)
    log(f"  submitted batch {batch.id} ({len(payload)} requests)")

    while True:
        batch = client.messages.batches.retrieve(batch.id)
        counts = batch.request_counts
        if batch.processing_status == "ended":
            break
        log(f"  {batch.processing_status}: "
            f"{counts.succeeded} ok / {counts.errored} err / {counts.processing} left")
        time.sleep(poll_interval)

    results = {}
    for entry in client.messages.batches.results(batch.id):
        rtype = entry.result.type
        if rtype == "succeeded":
            results[entry.custom_id] = BatchApiResult(
                entry.custom_id, _reply_text(entry.result.message), "succeeded")
        else:
            err = getattr(getattr(entry.result, "error", None), "type", rtype)
            results[entry.custom_id] = BatchApiResult(entry.custom_id, "", rtype, str(err))
    return results


# Lock shared by callers that write progress from run_concurrent's callback.
progress_lock = threading.Lock()
