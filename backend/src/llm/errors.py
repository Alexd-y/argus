"""LLM-specific errors for graceful degradation."""


class LLMProviderUnavailableError(RuntimeError):
    """Raised when no LLM provider is configured (no API keys in env)."""

    pass


class LLMAllProvidersFailedError(RuntimeError):
    """Raised when all configured LLM providers failed (timeout, rate limit, etc.)."""

    pass
