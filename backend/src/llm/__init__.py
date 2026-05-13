"""LLM adapter layer — unified interface for multiple providers.

WhiteRabbitNeo V3 7B is the primary pentest AI (local, $0).
Cloud providers serve only as report supplements.
"""

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
from src.llm.whiterabbitneo_adapter import (
    WhiteRabbitNeoAdapter,
    get_whiterabbitneo_adapter,
    reset_whiterabbitneo_adapter,
)

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
    "WhiteRabbitNeoAdapter",
    "get_whiterabbitneo_adapter",
    "reset_whiterabbitneo_adapter",
]
