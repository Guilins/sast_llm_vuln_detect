"""DeepSeek V4.1 Flash backend for the robust analysis stage.

An OpenAI-compatible ``/chat/completions`` endpoint, confirmed against DeepSeek's own
docs (https://api-docs.deepseek.com/):

    POST https://api.deepseek.com/chat/completions
    Authorization: Bearer <DEEPSEEK_API_KEY>
    {"model": "deepseek-flash", "messages": [...], "max_tokens": N}
    -> standard OpenAI-shaped chat completion, "usage": {"prompt_tokens",
       "completion_tokens", "total_tokens", "prompt_cache_hit_tokens",
       "prompt_cache_miss_tokens", "completion_tokens_details": {"reasoning_tokens"}}

Pricing is peak/off-peak (DeepSeek's own scheme, not something this project invented):
peak = 01:00-04:00 and 06:00-10:00 UTC, Monday-Friday; off-peak is half price and covers
the rest of the week. ``current_price_tier()`` picks the right one from wall-clock time
so a cost estimate printed at call time is actually correct.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

BASE_URL = "https://api.deepseek.com/chat/completions"
DEFAULT_MODEL = "deepseek-flash"

# USD per 1M tokens: (cache_miss_input, output, cache_hit_input)
PRICING = {
    "off_peak": (0.15, 0.60, 0.003),
    "peak": (0.30, 1.20, 0.006),
}

FATAL_ERROR_MARKERS = (
    "authentication", "invalid api key", "invalid_api_key", "unauthorized",
    "permission", "not_found", "insufficient_quota", "insufficient balance", "billing",
)


def is_fatal_error(message: str) -> bool:
    low = (message or "").lower()
    return any(marker in low for marker in FATAL_ERROR_MARKERS)


def current_price_tier(now: Optional[datetime] = None) -> str:
    """'peak' 01:00-04:00 and 06:00-10:00 UTC Mon-Fri, else 'off_peak'."""
    now = now or datetime.now(timezone.utc)
    if now.isoweekday() > 5:  # Sat/Sun
        return "off_peak"
    hour = now.hour
    if (1 <= hour < 4) or (6 <= hour < 10):
        return "peak"
    return "off_peak"


def _require_requests():
    try:
        import requests  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "The 'requests' package is required for --backend deepseek. "
            "Install it with:  python -m pip install requests"
        ) from exc
    return requests


@dataclass
class TokenUsage:
    input: int = 0              # cache-miss input tokens
    cache_hit_input: int = 0
    output: int = 0             # includes reasoning_tokens, billed as output
    reasoning: int = 0          # informational subset of `output`
    calls: int = 0

    def add(self, usage: dict) -> None:
        miss = usage.get("prompt_cache_miss_tokens")
        hit = usage.get("prompt_cache_hit_tokens", 0) or 0
        if miss is None:
            # Field absent: treat the whole prompt as a cache miss.
            miss = (usage.get("prompt_tokens", 0) or 0) - hit
        self.input += miss or 0
        self.cache_hit_input += hit
        self.output += usage.get("completion_tokens", 0) or 0
        self.reasoning += (usage.get("completion_tokens_details") or {}).get("reasoning_tokens", 0) or 0
        self.calls += 1

    def cost_usd(self, tier: Optional[str] = None) -> float:
        in_price, out_price, hit_price = PRICING[tier or current_price_tier()]
        return round((self.input * in_price + self.cache_hit_input * hit_price
                     + self.output * out_price) / 1e6, 4)

    def to_dict(self, model: str = "", _unused: bool = False) -> dict:
        tier = current_price_tier()
        return {"calls": self.calls, "input_tokens": self.input,
                "cache_hit_input_tokens": self.cache_hit_input, "output_tokens": self.output,
                "reasoning_tokens": self.reasoning, "price_tier": tier,
                "cost_usd": self.cost_usd(tier)}


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


class DeepSeekChatAdapter:
    """Drop-in replacement for the other backend adapters: ``.invoke(messages) -> obj
    with .content``. Fails closed: HTTP errors raise (caller retries/reports); an empty
    choices list or missing content surfaces as an empty string, same as the others."""

    def __init__(self, api_key: str, model: str = DEFAULT_MODEL, max_tokens: int = 8192,
                timeout: float = 600.0):
        self.requests = _require_requests()
        self.api_key = api_key
        self.model = model
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.usage = TokenUsage()

    def invoke(self, messages):
        body = {"model": self.model, "messages": _messages_to_openai(messages),
                "max_tokens": self.max_tokens, "stream": False}

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
