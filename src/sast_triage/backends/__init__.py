"""Model client factories: build the robust / small model client for the
configured backend (local Ollama or the Anthropic API)."""

from __future__ import annotations

from ..config import PipelineConfig


def make_ollama_model(model, num_ctx, timeout):
    from langchain_ollama import ChatOllama

    return ChatOllama(temperature=0, model=model, num_ctx=num_ctx, reasoning=False,
                      client_kwargs={"timeout": timeout})


def make_robust_model(config: PipelineConfig):
    """Robust-stage client for the configured backend."""
    if config.backend == "anthropic":
        from .anthropic import ANALYSIS_RESPONSE_SCHEMA, AnthropicChatAdapter

        return AnthropicChatAdapter(
            config.anthropic_model, config.anthropic_max_tokens,
            timeout=config.timeout, workspace_id=config.anthropic_workspace_id,
            thinking=config.anthropic_thinking, effort=config.anthropic_effort,
            output_schema=ANALYSIS_RESPONSE_SCHEMA if config.anthropic_structured else None)
    return make_ollama_model(config.robust_model, config.num_ctx, config.timeout)


def make_small_model(config: PipelineConfig):
    """Borderline-screen client for the configured small backend."""
    if config.small_backend == "anthropic":
        from .anthropic import AnthropicChatAdapter

        return AnthropicChatAdapter(config.small_anthropic_model, config.small_model_max_tokens,
                                    timeout=config.small_model_timeout,
                                    workspace_id=config.anthropic_workspace_id)
    return make_ollama_model(config.small_model, config.small_model_num_ctx,
                             config.small_model_timeout)
