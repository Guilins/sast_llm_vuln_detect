"""OpenRouter backend for the robust analysis stage.

OpenRouter is a multi-model gateway (not a single model provider): one OpenAI-compatible
endpoint that proxies to whichever model ID you pass it, confirmed against OpenRouter's
own docs (https://openrouter.ai/docs/api-reference/chat-completion):

    POST https://openrouter.ai/api/v1/chat/completions
    Authorization: Bearer <OPENROUTER_API_KEY>
    {"model": "<vendor>/<model>[:free]", "messages": [...], "max_tokens": N}
    -> standard OpenAI-shaped chat completion, "usage": {"prompt_tokens",
       "completion_tokens", "total_tokens"}

The model ID is a CLI flag (``--openrouter-model``), not hard-coded, since the whole
point of this gateway is picking any of the models it hosts (a ``:free`` suffix picks a
zero-cost, typically rate-limited variant, when the model in question has one). Cost is
read directly from OpenRouter's own ``usage.cost`` field (its credits are 1:1 with USD),
requested via ``usage: {"include": true}`` on every call, rather than maintaining a
per-model price table here that would silently go stale.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

BASE_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "z-ai/glm-5.3-flash"

FATAL_ERROR_MARKERS = (
    "authentication", "invalid api key", "invalid_api_key", "unauthorized",
    "permission", "not_found", "insufficient_quota", "insufficient balance", "billing",
    "no credit",
)


def is_fatal_error(message: str) -> bool:
    low = (message or "").lower()
    return any(marker in low for marker in FATAL_ERROR_MARKERS)


def _require_requests():
    try:
        import requests  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "The 'requests' package is required for --backend openrouter. "
            "Install it with:  python -m pip install requests"
        ) from exc
    return requests


@dataclass
class TokenUsage:
    input: int = 0
    output: int = 0
    calls: int = 0
    cost_usd: float = 0.0

    def add(self, usage: dict) -> None:
        self.input += usage.get("prompt_tokens", 0) or 0
        self.output += usage.get("completion_tokens", 0) or 0
        self.cost_usd += usage.get("cost", 0) or 0
        self.calls += 1

    def to_dict(self, model: str = "", _unused: bool = False) -> dict:
        return {"calls": self.calls, "input_tokens": self.input,
                "output_tokens": self.output, "cost_usd": round(self.cost_usd, 4)}


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


class OpenRouterChatAdapter:
    """Drop-in replacement for the other backend adapters: ``.invoke(messages) -> obj
    with .content``. Fails closed: HTTP errors raise (caller retries/reports); an empty
    choices list or missing content surfaces as an empty string, same as the others."""

    def __init__(self, api_key: str, model: str = DEFAULT_MODEL, max_tokens: int = 8192,
                timeout: float = 600.0, site_url: Optional[str] = None,
                site_title: Optional[str] = None):
        self.requests = _require_requests()
        self.api_key = api_key
        self.model = model
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.site_url = site_url
        self.site_title = site_title
        self.usage = TokenUsage()

    def invoke(self, messages):
        body = {"model": self.model, "messages": _messages_to_openai(messages),
                "max_tokens": self.max_tokens, "stream": False,
                "usage": {"include": True}}

        headers = {"Authorization": f"Bearer {self.api_key}",
                   "Content-Type": "application/json"}
        if self.site_url:
            headers["HTTP-Referer"] = self.site_url
        if self.site_title:
            headers["X-OpenRouter-Title"] = self.site_title

        resp = self.requests.post(BASE_URL, headers=headers, json=body, timeout=self.timeout)
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
