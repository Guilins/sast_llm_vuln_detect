"""Model client factories: build the robust / small model client for the
configured backend (local Ollama or the Anthropic API)."""

from __future__ import annotations

from ..config import PipelineConfig


def _default_num_predict(batch_size: int) -> int:
    """A generous but *finite* output cap: ~900 tokens/finding, bounded to [1024, 8192].

    Without this, a local model that falls into a degenerate/repetitive generation can
    run for hours — Ollama streams its response, so a client-side read timeout never
    fires as long as *some* token keeps trickling out, no matter how long the total
    generation takes. ``num_predict`` is the only thing that actually bounds it.
    """
    return max(1024, min(8192, batch_size * 900))


def make_ollama_model(model, num_ctx, timeout, think=False, num_predict=None):
    from langchain_ollama import ChatOllama

    return ChatOllama(temperature=0, model=model, num_ctx=num_ctx, reasoning=think,
                      num_predict=num_predict, client_kwargs={"timeout": timeout})


def make_robust_model(config: PipelineConfig):
    """Robust-stage client for the configured backend."""
    if config.backend == "anthropic":
        from .anthropic import ANALYSIS_RESPONSE_SCHEMA, AnthropicChatAdapter

        return AnthropicChatAdapter(
            config.anthropic_model, config.anthropic_max_tokens,
            timeout=config.timeout, workspace_id=config.anthropic_workspace_id,
            thinking=config.anthropic_thinking, effort=config.anthropic_effort,
            output_schema=ANALYSIS_RESPONSE_SCHEMA if config.anthropic_structured else None)
    if config.backend == "muse-spark":
        from .muse_spark import MuseSparkChatAdapter

        if not config.muse_spark_api_key:
            raise RuntimeError("--backend muse-spark needs MUSE_SPARK_API_KEY in the environment.")
        return MuseSparkChatAdapter(
            config.muse_spark_api_key, model=config.muse_spark_model,
            max_tokens=config.muse_spark_max_tokens,
            reasoning_effort=config.muse_spark_reasoning_effort, timeout=config.timeout)
    if config.backend == "deepseek":
        from .deepseek import DeepSeekChatAdapter

        if not config.deepseek_api_key:
            raise RuntimeError("--backend deepseek needs DEEPSEEK_API_KEY in the environment.")
        return DeepSeekChatAdapter(config.deepseek_api_key, model=config.deepseek_model,
                                   max_tokens=config.deepseek_max_tokens, timeout=config.timeout)
    return make_ollama_model(config.robust_model, config.num_ctx, config.timeout,
                             think=config.ollama_think,
                             num_predict=config.ollama_num_predict or _default_num_predict(config.batch_size))


def make_small_model(config: PipelineConfig):
    """Borderline-screen client for the configured small backend."""
    if config.small_backend == "anthropic":
        from .anthropic import AnthropicChatAdapter

        return AnthropicChatAdapter(config.small_anthropic_model, config.small_model_max_tokens,
                                    timeout=config.small_model_timeout,
                                    workspace_id=config.anthropic_workspace_id)
    return make_ollama_model(config.small_model, config.small_model_num_ctx,
                             config.small_model_timeout,
                             num_predict=config.ollama_num_predict or 512)
