"""LLM adapter layer — unified interface for multiple providers."""

from src.llm.errors import LLMAllProvidersFailedError, LLMProviderUnavailableError
from src.llm.router import call_llm, is_llm_available

__all__ = [
    "call_llm",
    "is_llm_available",
    "LLMProviderUnavailableError",
    "LLMAllProvidersFailedError",
]
