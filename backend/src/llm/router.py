"""LLM router — calls first available provider with fallback chain."""

import logging

from src.llm.adapters import get_available_adapters
from src.llm.errors import LLMAllProvidersFailedError, LLMProviderUnavailableError

logger = logging.getLogger(__name__)


def is_llm_available() -> bool:
    """Return True if at least one LLM provider is configured."""
    return len(get_available_adapters()) > 0


async def call_llm(
    prompt: str,
    *,
    system_prompt: str | None = None,
    model: str | None = None,
) -> str:
    """
    Call first available LLM provider. Routes to OpenAI, DeepSeek, OpenRouter, etc.
    based on env vars. Raises LLMProviderUnavailableError if no provider configured,
    LLMAllProvidersFailedError if all providers fail.
    """
    adapters = get_available_adapters()
    if not adapters:
        raise LLMProviderUnavailableError(
            "No LLM provider configured. Set one of: OPENAI_API_KEY, DEEPSEEK_API_KEY, "
            "OPENROUTER_API_KEY, GOOGLE_API_KEY, KIMI_API_KEY, PERPLEXITY_API_KEY"
        )

    last_error: Exception | None = None
    for adapter in adapters:
        try:
            result = await adapter.call(
                prompt, system_prompt=system_prompt, model=model
            )
            return result
        except Exception as e:
            last_error = e
            logger.warning(
                "LLM adapter failed",
                extra={"error_type": type(e).__name__},
            )
            continue

    raise LLMAllProvidersFailedError(
        f"All LLM providers failed. Last error type: {type(last_error).__name__}"
    ) if last_error else LLMAllProvidersFailedError(
        "No LLM provider returned a response"
    )
