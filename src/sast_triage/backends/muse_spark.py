"""Muse Spark 1.3 backend (Meta Model API) for the robust analysis stage.

An OpenAI-compatible ``/chat/completions`` endpoint, called with the stdlib-adjacent
``requests`` library (no vendor SDK). Confirmed empirically against the real endpoint
before this was written:

    POST https://api.meta.ai/v1/chat/completions
    Authorization: Bearer <MUSE_SPARK_API_KEY>
    {"model": "muse-spark-1.3", "messages": [...], "max_tokens": N}
    -> {"choices": [{"message": {"content": ...}, "finish_reason": ...}],
        "usage": {"prompt_tokens", "completion_tokens", "total_tokens",
                  "completion_tokens_details": {"reasoning_tokens"}}}

Muse Spark reasons by default (o1/o3-style): reasoning tokens are drawn from the same
budget as ``max_tokens`` and are not returned in ``content``. A too-small ``max_tokens``
produces ``finish_reason: "length"`` with ``content: null`` and zero visible output —
exactly the runaway-generation failure mode the Ollama backend had, just budget-capped
instead of unbounded. The default here is deliberately generous.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

BASE_URL = "https://api.meta.ai/v1/chat/completions"

# USD per 1M tokens. Meta Model API, standard vs. contributor (data-sharing) tier.
# Reasoning tokens are billed as output tokens (they're part of completion_tokens).
MODEL_PRICING = {
    "muse-spark-1.3": (1.25, 4.25),
    "muse-spark-1.3-contributor": (0.10, 0.20),
}

FATAL_ERROR_MARKERS = (
    "authentication", "invalid api key", "invalid_api_key", "unauthorized",
    "permission", "not_found", "insufficient_quota", "billing", "credit",
)


def is_fatal_error(message: str) -> bool:
    low = (message or "").lower()
    return any(marker in low for marker in FATAL_ERROR_MARKERS)


def _require_requests():
    try:
        import requests  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "The 'requests' package is required for --backend muse-spark. "
            "Install it with:  python -m pip install requests"
        ) from exc
    return requests


@dataclass
class TokenUsage:
    input: int = 0
    output: int = 0            # includes reasoning_tokens - Meta bills them as output
    reasoning: int = 0         # informational subset of `output`
    calls: int = 0

    def add(self, usage: dict) -> None:
        self.input += usage.get("prompt_tokens", 0) or 0
        self.output += usage.get("completion_tokens", 0) or 0
        self.reasoning += (usage.get("completion_tokens_details") or {}).get("reasoning_tokens", 0) or 0
        self.calls += 1

    def cost_usd(self, model: str) -> float:
        in_price, out_price = MODEL_PRICING.get(model, (1.25, 4.25))
        return round((self.input * in_price + self.output * out_price) / 1e6, 4)

    def to_dict(self, model: str = "", _batch_api_unused: bool = False) -> dict:
        d = {"calls": self.calls, "input_tokens": self.input, "output_tokens": self.output,
             "reasoning_tokens": self.reasoning}
        if model:
            d["cost_usd"] = self.cost_usd(model)
        return d


class _Reply:
    def __init__(self, content: str):
        self.content = content


def _messages_to_openai(messages) -> list:
    out = []
    for m in messages:
        role = getattr(m, "type", "") or m.__class__.__name__.lower()
        content = m.content if isinstance(m.content, str) else str(m.content)
        if role in ("system", "systemmessage"):
            out.append({"role": "system", "content": content})
        elif role in ("ai", "aimessage", "assistant"):
            out.append({"role": "assistant", "content": content})
        else:
            out.append({"role": "user", "content": content})
    return out or [{"role": "user", "content": "Proceed."}]


class MuseSparkChatAdapter:
    """Drop-in replacement for ``ChatOllama``/``AnthropicChatAdapter``: exposes
    ``.invoke(messages) -> obj with .content``. Fails closed: any HTTP error, a
    non-2xx response, or a reasoning-truncated (empty) reply all surface as an empty
    string or a raised exception the caller already knows how to retry/report."""

    def __init__(self, api_key: str, model: str = "muse-spark-1.3", max_tokens: int = 8192,
                reasoning_effort: Optional[str] = None, timeout: float = 600.0):
        self.requests = _require_requests()
        self.api_key = api_key
        self.model = model
        self.max_tokens = max_tokens
        self.reasoning_effort = reasoning_effort
        self.timeout = timeout
        self.usage = TokenUsage()

    def invoke(self, messages):
        body = {"model": self.model, "messages": _messages_to_openai(messages),
                "max_tokens": self.max_tokens}
        if self.reasoning_effort:
            body["reasoning_effort"] = self.reasoning_effort

        resp = self.requests.post(
            BASE_URL, headers={"Authorization": f"Bearer {self.api_key}",
                               "Content-Type": "application/json"},
            json=body, timeout=self.timeout)
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:500]}")

        data = resp.json()
        usage = data.get("usage") or {}
        if usage:
            self.usage.add(usage)

        choices = data.get("choices") or []
        if not choices:
            return _Reply("")
        message = choices[0].get("message") or {}
        content = message.get("content")
        return _Reply(content or "")
