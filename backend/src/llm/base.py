"""LLM provider protocol and base types."""

from typing import Protocol


class LLMAdapter(Protocol):
    """Protocol for LLM provider adapters."""

    def is_available(self) -> bool:
        """Return True if provider is configured (env key present)."""
        ...

    async def call(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        model: str | None = None,
    ) -> str:
        """Call LLM and return response text. Raises on failure."""
        ...
