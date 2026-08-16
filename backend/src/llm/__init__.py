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
from src.llm.gateway import (
    UnifiedLlmGateway,
    get_unified_llm_gateway,
    reset_unified_llm_gateway,
)
from src.llm.registry import get_unified_registry, reset_unified_registry
from src.llm.router import call_llm, is_llm_available
from src.llm.schemas import (
    ContentClass,
    ExecutionMode,
    LlmRequest,
    LlmResponseEnvelope,
    LlmResponseStatus,
)
from src.llm.task_router import LLMTask, LLMTaskResponse, call_llm_for_task
from src.llm.whiterabbitneo_adapter import (
    WhiteRabbitNeoAdapter,
    get_whiterabbitneo_adapter,
    reset_whiterabbitneo_adapter,
)

__all__ = [
    "ContentClass",
    "ExecutionMode",
    "LLMAllProvidersFailedError",
    "LLMProviderUnavailableError",
    "LLMTask",
    "LLMTaskResponse",
    "LlmRequest",
    "LlmResponseEnvelope",
    "LlmResponseStatus",
    "ScanBudgetExceededError",
    "ScanCostTracker",
    "UnifiedLlmGateway",
    "WhiteRabbitNeoAdapter",
    "calc_cost",
    "call_llm",
    "call_llm_for_task",
    "get_tracker",
    "get_unified_llm_gateway",
    "get_unified_registry",
    "get_whiterabbitneo_adapter",
    "is_llm_available",
    "pop_tracker",
    "reset_unified_llm_gateway",
    "reset_unified_registry",
    "reset_whiterabbitneo_adapter",
]
