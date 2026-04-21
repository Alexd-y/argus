"""LLM adapter layer — unified interface for multiple providers."""

from src.llm.cost_tracker import (
    ScanBudgetExceededError,
    ScanCostTracker,
    calc_cost,
    get_tracker,
    pop_tracker,
)
from src.llm.errors import LLMAllProvidersFailedError, LLMProviderUnavailableError
from src.llm.router import call_llm, is_llm_available
from src.llm.task_router import LLMTask, LLMTaskResponse, call_llm_for_task

__all__ = [
    "call_llm",
    "is_llm_available",
    "LLMProviderUnavailableError",
    "LLMAllProvidersFailedError",
    "LLMTask",
    "LLMTaskResponse",
    "call_llm_for_task",
    "ScanCostTracker",
    "ScanBudgetExceededError",
    "calc_cost",
    "get_tracker",
    "pop_tracker",
]
