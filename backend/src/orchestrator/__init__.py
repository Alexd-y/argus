"""ARGUS AI Orchestrator package — planner / critic / verifier / reporter / fixer.

Re-exports the public API so callers can write ``from src.orchestrator import
Orchestrator, ValidationPlanV1`` without reaching into submodules.

Layered structure (low-level → high-level):

* :mod:`src.orchestrator.schemas.loader` — strict JSON-schema + Pydantic
  contract for ``ValidationPlanV1`` (ARG-001).
* :mod:`src.orchestrator.llm_provider` — provider abstraction + Echo /
  OpenAI implementations.
* :mod:`src.orchestrator.prompt_registry` — signed prompt YAML loader.
* :mod:`src.orchestrator.cost_tracker` — per-tenant / per-scan token +
  USD bookkeeping.
* :mod:`src.orchestrator.agents` — five role-specific agents
  (Planner, Critic, Verifier, Reporter, Fixer).
* :mod:`src.orchestrator.retry_loop` — Fixer-driven retry with budget caps.
* :mod:`src.orchestrator.orchestrator` — :class:`Orchestrator` facade.
"""

from src.orchestrator.agents import (
    AgentConfigError,
    AgentContext,
    AgentError,
    AgentParseError,
    BaseAgent,
    CriticAgent,
    CriticVerdict,
    FixerAgent,
    PlannerAgent,
    ReporterAgent,
    ReportNarrative,
    VerifierAgent,
)
from src.orchestrator.cost_tracker import CostRecord, CostSummary, CostTracker
from src.orchestrator.llm_provider import (
    EchoLLMProvider,
    LLMProvider,
    LLMProviderError,
    LLMProviderUnavailableError,
    LLMRequest,
    LLMResponse,
    OpenAILLMProvider,
    ResponseFormat,
)
from src.orchestrator.orchestrator import (
    Orchestrator,
    OrchestratorBudgetExceeded,
    OrchestratorError,
    OrchestratorParseFailure,
    OrchestratorPlanRejected,
    OrchestratorProviderFailure,
)
from src.orchestrator.prompt_registry import (
    AgentRole,
    PromptDefinition,
    PromptNotFoundError,
    PromptRegistry,
    PromptRegistryError,
    PromptRegistrySummary,
    PromptSignatureError,
)
from src.orchestrator.retry_loop import (
    AttemptErrorKind,
    AttemptLog,
    AttemptRecord,
    RetryAbortReason,
    RetryConfig,
    RetryLoop,
)
from src.orchestrator.schemas.loader import (
    MutationClass,
    PayloadStrategyV1,
    RiskRating,
    SCHEMA_ID,
    ValidationPlanError,
    ValidationPlanV1,
    ValidatorSpecV1,
    ValidatorTool,
    load_validation_plan_v1_schema,
    validate_validation_plan,
)

__all__ = [
    "SCHEMA_ID",
    "AgentConfigError",
    "AgentContext",
    "AgentError",
    "AgentParseError",
    "AgentRole",
    "AttemptErrorKind",
    "AttemptLog",
    "AttemptRecord",
    "BaseAgent",
    "CostRecord",
    "CostSummary",
    "CostTracker",
    "CriticAgent",
    "CriticVerdict",
    "EchoLLMProvider",
    "FixerAgent",
    "LLMProvider",
    "LLMProviderError",
    "LLMProviderUnavailableError",
    "LLMRequest",
    "LLMResponse",
    "MutationClass",
    "OpenAILLMProvider",
    "Orchestrator",
    "OrchestratorBudgetExceeded",
    "OrchestratorError",
    "OrchestratorParseFailure",
    "OrchestratorPlanRejected",
    "OrchestratorProviderFailure",
    "PayloadStrategyV1",
    "PlannerAgent",
    "PromptDefinition",
    "PromptNotFoundError",
    "PromptRegistry",
    "PromptRegistryError",
    "PromptRegistrySummary",
    "PromptSignatureError",
    "ReportNarrative",
    "ReporterAgent",
    "ResponseFormat",
    "RetryAbortReason",
    "RetryConfig",
    "RetryLoop",
    "RiskRating",
    "ValidationPlanError",
    "ValidationPlanV1",
    "ValidatorSpecV1",
    "ValidatorTool",
    "VerifierAgent",
    "load_validation_plan_v1_schema",
    "validate_validation_plan",
]
