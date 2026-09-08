"""Borderline screening with a small local model.

Everything in this stage fails closed: an exception, timeout, empty reply, malformed
JSON, or an unexpected ``decision`` value all resolve to ``escalate`` so that the robust
model still sees the finding. Only an explicit, well-formed ``"dismiss"`` can defer.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, asdict
from typing import Callable, Iterable, Optional

from .prompts import SMALL_MODEL_TRIAGE_PROMPT
from .json_repair import repair_and_parse_json, _normalize_llm_content
from .triage import NormalizedFinding, TriageDecision

DECISION_ESCALATE = "escalate"
DECISION_DISMISS = "dismiss"
DECISION_UNCERTAIN = "uncertain"
VALID_DECISIONS = (DECISION_ESCALATE, DECISION_DISMISS, DECISION_UNCERTAIN)

MAX_REASON_CHARS = 240
MAX_FOCAL_CODE_CHARS = 4000


@dataclass
class SmallModelVerdict:
    key: str
    decision: str                   # always one of VALID_DECISIONS
    reason: Optional[str]
    error: Optional[str]            # set when the model output was unusable (fail-closed)
    elapsed_seconds: float
    raw: str = ""

    @property
    def failed_closed(self) -> bool:
        return self.error is not None

    def to_dict(self) -> dict:
        data = asdict(self)
        data.pop("raw", None)
        data["elapsed_seconds"] = round(self.elapsed_seconds, 3)
        return data


def parse_small_model_response(raw) -> tuple:
    """Strictly parse the screener's reply.

    Returns ``(decision, reason, error)``. ``error`` is ``None`` only when the reply was a
    JSON object with a valid ``decision``; otherwise ``decision`` is ``escalate``.
    """
    text = _normalize_llm_content(raw).strip()
    if not text:
        return DECISION_ESCALATE, None, "empty response"

    parsed, err = repair_and_parse_json(text)
    if parsed is None:
        return DECISION_ESCALATE, None, f"unparseable response: {err}"
    if isinstance(parsed, list):
        parsed = next((item for item in parsed if isinstance(item, dict)), None)
    if not isinstance(parsed, dict):
        return DECISION_ESCALATE, None, "response is not a JSON object"

    decision = parsed.get("decision")
    if not isinstance(decision, str) or decision.strip().lower() not in VALID_DECISIONS:
        return DECISION_ESCALATE, None, f"invalid decision value: {decision!r}"

    reason = parsed.get("reason")
    reason = str(reason).strip()[:MAX_REASON_CHARS] if reason is not None else None
    return decision.strip().lower(), reason, None


def slim_for_small_model(nf: NormalizedFinding) -> dict:
    return {
        "rule": nf.check_id,
        "path": nf.path,
        "line": nf.start_line,
        "severity": nf.severity,
        "confidence": nf.confidence,
        "cwe": nf.cwe_ids,
        "class": nf.vulnerability_class,
        "message": nf.message[:400],
    }


def build_small_model_prompt(nf: NormalizedFinding, decision: TriageDecision) -> str:
    code = decision.screen_code or decision.focal_code or "<code context unavailable>"
    if len(code) > MAX_FOCAL_CODE_CHARS:
        code = code[:MAX_FOCAL_CODE_CHARS] + "\n... [truncated]"
    return SMALL_MODEL_TRIAGE_PROMPT.format(
        finding=json.dumps(slim_for_small_model(nf), separators=(",", ":")),
        evidence=decision.evidence_summary(),
        code=code,
    )


def _invoke_text(llm, prompt: str) -> str:
    """Call a LangChain chat model with a single human message and return plain text."""
    from langchain_core.messages import HumanMessage  # local import keeps tests light
    response = llm.invoke([HumanMessage(content=prompt)])
    return _normalize_llm_content(getattr(response, "content", response))


def screen_one(llm, nf: NormalizedFinding, decision: TriageDecision,
               invoke: Optional[Callable[[object, str], str]] = None) -> SmallModelVerdict:
    """Screen a single finding. Never raises; every failure becomes ``escalate``."""
    invoke = invoke or _invoke_text
    prompt = build_small_model_prompt(nf, decision)
    t0 = time.time()
    raw = ""
    try:
        raw = invoke(llm, prompt) or ""
    except Exception as exc:  # noqa: BLE001 - fail closed on anything
        kind = "timeout" if "time" in str(exc).lower() and "out" in str(exc).lower() else "exception"
        return SmallModelVerdict(nf.key, DECISION_ESCALATE, None, f"{kind}: {exc}",
                                 time.time() - t0, raw)

    verdict, reason, error = parse_small_model_response(raw)
    return SmallModelVerdict(nf.key, verdict, reason, error, time.time() - t0, raw)


def screen_borderline(llm, items: Iterable[tuple], invoke=None,
                      progress_cb: Optional[Callable[[int, int, SmallModelVerdict], None]] = None,
                      max_workers: int = 1) -> dict:
    """Screen ``(normalized_finding, decision)`` pairs; returns ``{key: SmallModelVerdict}``.

    ``max_workers > 1`` screens findings concurrently (for an API-backed screener) while
    still reporting progress in completion order.
    """
    items = list(items)
    verdicts = {}
    if max_workers <= 1 or len(items) <= 1:
        for n, (nf, decision) in enumerate(items, 1):
            verdict = screen_one(llm, nf, decision, invoke=invoke)
            verdicts[nf.key] = verdict
            if progress_cb:
                progress_cb(n, len(items), verdict)
        return verdicts

    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(screen_one, llm, nf, d, invoke): nf for nf, d in items}
        for n, future in enumerate(as_completed(futures), 1):
            verdict = future.result()
            verdicts[verdict.key] = verdict
            if progress_cb:
                progress_cb(n, len(items), verdict)
    return verdicts


def apply_verdict(decision: TriageDecision, verdict: SmallModelVerdict, allow_dismiss: bool) -> None:
    """Fold the screener's verdict into the Layer-1 decision in place.

    ``dismiss`` defers only when ``allow_dismiss`` is set (the deferral policy switch);
    ``escalate``/``uncertain``/errors always escalate.
    """
    from .triage import ACTION_DEFER, ACTION_ESCALATE

    decision.small_model = verdict.to_dict()
    if verdict.decision == DECISION_DISMISS and not verdict.failed_closed:
        if allow_dismiss:
            decision.action = ACTION_DEFER
            decision.reasons.append("small_model_dismissed")
        else:
            decision.action = ACTION_ESCALATE
            decision.reasons.append("small_model_dismissed_but_deferral_disabled")
    else:
        decision.action = ACTION_ESCALATE
        if verdict.failed_closed:
            decision.reasons.append("small_model_failed_closed")
        else:
            decision.reasons.append(f"small_model_{verdict.decision}")
