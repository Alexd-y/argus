"""Retry / Fixer loop for the ARGUS AI orchestrator (Backlog/dev1_md §6, §14).

Wraps a single agent call so that:

1. The first attempt executes the agent's normal ``run`` path.
2. On :class:`~src.orchestrator.agents.AgentParseError`, the loop invokes
   :class:`~src.orchestrator.agents.FixerAgent` with the malformed
   content + sanitised error description. The Fixer's corrected JSON is
   re-fed into the original agent's :meth:`_parse_response`.
3. Up to :attr:`RetryConfig.max_retries` Fixer attempts are made.
4. The cumulative cost (USD + total tokens) is tracked across attempts;
   the loop aborts with :class:`RetryAbortReason.BUDGET_EXHAUSTED` when
   either cap would be exceeded.

Outputs
-------
:meth:`RetryLoop.run` returns ``(typed_result_or_None, AttemptLog)``.
The :class:`AttemptLog` records every attempt's outcome (success / error
type / sanitised reason / cost) without leaking input values. Callers use
:attr:`AttemptLog.abort_reason` to discriminate the terminal state.

Why a separate module?
----------------------
The retry loop is the single point at which we couple cost tracking,
provider error handling, and Fixer routing. Keeping it apart from
:mod:`src.orchestrator.agents` keeps the agents single-purpose (one
prompt → one DTO) and makes the loop unit-testable without spinning up
a real agent stack.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field, StrictFloat, StrictInt, StrictStr

from src.orchestrator.agents import (
    AgentContext,
    AgentParseError,
    BaseAgent,
    FixerAgent,
)
from src.orchestrator.cost_tracker import CostRecord, CostTracker
from src.orchestrator.llm_provider import (
    LLMProviderError,
    LLMProviderUnavailableError,
    LLMResponse,
    ResponseFormat,
)

_logger = logging.getLogger(__name__)


_DEFAULT_MAX_RETRIES: Final[int] = 2
_DEFAULT_BACKOFF_INITIAL_S: Final[float] = 0.1
_DEFAULT_BACKOFF_FACTOR: Final[float] = 2.0
_DEFAULT_BUDGET_USD: Final[float] = 0.50
_DEFAULT_BUDGET_TOKENS: Final[int] = 16_384
_MAX_BACKOFF_S: Final[float] = 5.0


# ---------------------------------------------------------------------------
# Configuration & terminal taxonomy
# ---------------------------------------------------------------------------


class RetryAbortReason(StrEnum):
    """Closed taxonomy of terminal :class:`RetryLoop` states."""

    VALIDATED_OK = "validated_ok"
    BUDGET_EXHAUSTED = "budget_exhausted"
    MAX_RETRIES_EXHAUSTED = "max_retries_exhausted"
    PROVIDER_ERROR = "provider_error"
    UNRECOVERABLE_SCHEMA_ERROR = "unrecoverable_schema_error"


class RetryConfig(BaseModel):
    """Per-call retry / budget configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_retries: StrictInt = Field(default=_DEFAULT_MAX_RETRIES, ge=0, le=8)
    backoff_initial_s: StrictFloat = Field(
        default=_DEFAULT_BACKOFF_INITIAL_S, ge=0.0, le=_MAX_BACKOFF_S
    )
    backoff_factor: StrictFloat = Field(default=_DEFAULT_BACKOFF_FACTOR, ge=1.0, le=8.0)
    total_budget_usd: StrictFloat = Field(default=_DEFAULT_BUDGET_USD, gt=0.0)
    total_budget_tokens: StrictInt = Field(default=_DEFAULT_BUDGET_TOKENS, gt=0)


# ---------------------------------------------------------------------------
# Per-attempt log
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class AttemptErrorKind(StrEnum):
    """Closed taxonomy of per-attempt error kinds (Backlog/dev1_md §13)."""

    SCHEMA_ERROR = "schema_error"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    PROVIDER_ERROR = "provider_error"


class AttemptRecord(BaseModel):
    """One entry of an :class:`AttemptLog` (frozen)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    attempt: StrictInt = Field(ge=1, le=16)
    agent_role: StrictStr
    prompt_id: StrictStr
    success: bool
    error_kind: AttemptErrorKind | None = Field(default=None)
    sanitized_error: StrictStr | None = Field(default=None, max_length=2000)
    prompt_tokens: StrictInt = Field(default=0, ge=0)
    completion_tokens: StrictInt = Field(default=0, ge=0)
    usd_cost: StrictFloat = Field(default=0.0, ge=0.0)
    latency_ms: StrictInt = Field(default=0, ge=0)
    occurred_at: datetime = Field(default_factory=_utcnow)


class AttemptLog(BaseModel):
    """Immutable trace of every attempt for a single :meth:`RetryLoop.run`."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    abort_reason: RetryAbortReason
    attempts: list[AttemptRecord] = Field(default_factory=list)
    total_prompt_tokens: StrictInt = Field(ge=0)
    total_completion_tokens: StrictInt = Field(ge=0)
    total_usd_cost: StrictFloat = Field(ge=0.0)


# ---------------------------------------------------------------------------
# Retry loop
# ---------------------------------------------------------------------------


class RetryLoop:
    """Orchestrate a single agent call with automatic Fixer-based retry."""

    def __init__(
        self,
        *,
        cost_tracker: CostTracker,
        fixer_agent: FixerAgent,
        config: RetryConfig | None = None,
    ) -> None:
        self._cost = cost_tracker
        self._fixer = fixer_agent
        self._config = config or RetryConfig()

    @property
    def config(self) -> RetryConfig:
        return self._config

    async def run(
        self,
        agent: BaseAgent,
        context: AgentContext,
        **kwargs: Any,
    ) -> tuple[Any, AttemptLog]:
        """Execute ``agent.run`` with retry / fixer / cost tracking.

        Returns a ``(result, AttemptLog)`` tuple where ``result`` is the
        typed DTO when :attr:`AttemptLog.abort_reason` is ``VALIDATED_OK``
        and ``None`` otherwise. The caller MUST check the abort reason
        before consuming ``result``.
        """
        state = _RunState(config=self._config)

        # ----- Attempt 1: original agent --------------------------------
        first_outcome = await self._first_attempt(agent, context, state, kwargs)
        if first_outcome is not _NEED_RETRY:
            return first_outcome, state.build_log()

        # ----- Subsequent attempts: Fixer-driven ------------------------
        for retry_index in range(1, self._config.max_retries + 1):
            if not state.budget_allows():
                state.abort_reason = RetryAbortReason.BUDGET_EXHAUSTED
                return None, state.build_log()

            await _maybe_sleep(self._config, retry_index)

            assert state.last_error is not None  # noqa: S101 — invariant
            outcome = await self._fixer_attempt(agent, context, state)
            if outcome is _NEED_RETRY:
                continue
            return outcome, state.build_log()

        state.abort_reason = RetryAbortReason.MAX_RETRIES_EXHAUSTED
        return None, state.build_log()

    # -- internal attempt helpers -------------------------------------------

    async def _first_attempt(
        self,
        agent: BaseAgent,
        context: AgentContext,
        state: _RunState,
        kwargs: dict[str, Any],
    ) -> Any:
        try:
            response = await agent.call_raw(context, **kwargs)
        except (LLMProviderUnavailableError, LLMProviderError) as exc:
            state.attempts.append(
                _provider_error_attempt(state.next_attempt(), agent, exc)
            )
            state.abort_reason = RetryAbortReason.PROVIDER_ERROR
            return None
        attempt_no = state.next_attempt()
        state.add_response(response)
        self._record_cost(agent, context, response, attempt=attempt_no)
        try:
            result = agent._parse_response(response)  # noqa: SLF001
        except AgentParseError as parse_err:
            state.attempts.append(
                _failed_attempt(attempt_no, agent, response, parse_err)
            )
            state.last_error = parse_err
            return _NEED_RETRY
        state.attempts.append(_success_attempt(attempt_no, agent, response))
        state.abort_reason = RetryAbortReason.VALIDATED_OK
        return result

    async def _fixer_attempt(
        self,
        agent: BaseAgent,
        context: AgentContext,
        state: _RunState,
    ) -> Any:
        assert state.last_error is not None  # noqa: S101 — invariant
        last_error = state.last_error
        attempt_no = state.next_attempt()
        try:
            fixed_response = await self._fixer.call_raw(
                context,
                response_format=ResponseFormat.JSON_OBJECT,
                original_content=last_error.raw_content,
                schema_errors=last_error.reason,
                schema_ref=agent.prompt.expected_schema_ref or "unknown",
            )
        except (LLMProviderUnavailableError, LLMProviderError) as exc:
            state.attempts.append(_provider_error_attempt(attempt_no, self._fixer, exc))
            state.abort_reason = RetryAbortReason.PROVIDER_ERROR
            return None

        state.add_response(fixed_response)
        self._record_cost(self._fixer, context, fixed_response, attempt=attempt_no)

        if fixed_response.parsed_json is None:
            err = AgentParseError(
                field_path="<root>",
                reason="fixer response is not valid JSON",
                raw_content=fixed_response.content,
            )
            state.attempts.append(
                _failed_attempt(attempt_no, self._fixer, fixed_response, err)
            )
            state.last_error = err
            return _NEED_RETRY

        try:
            result = agent._parse_response(fixed_response)  # noqa: SLF001
        except AgentParseError as parse_err:
            state.attempts.append(
                _failed_attempt(attempt_no, self._fixer, fixed_response, parse_err)
            )
            state.last_error = parse_err
            return _NEED_RETRY

        state.attempts.append(_success_attempt(attempt_no, self._fixer, fixed_response))
        state.abort_reason = RetryAbortReason.VALIDATED_OK
        return result

    def _record_cost(
        self,
        agent: BaseAgent,
        context: AgentContext,
        response: LLMResponse,
        *,
        attempt: int,
    ) -> CostRecord:
        return self._cost.record(
            correlation_id=context.correlation_id,
            tenant_id=context.tenant_id,
            scan_id=context.scan_id,
            agent_role=agent.role,
            prompt_id=agent.prompt_id,
            model_id=response.model_id,
            prompt_tokens=response.prompt_tokens,
            completion_tokens=response.completion_tokens,
            usd_cost=response.usd_cost,
            latency_ms=response.latency_ms,
            attempt=attempt,
        )


# ---------------------------------------------------------------------------
# Run state (private; mutable scratch space for one RetryLoop.run call)
# ---------------------------------------------------------------------------


class _RunState:
    """Mutable scratch space tied to a single :meth:`RetryLoop.run` call."""

    __slots__ = (
        "_attempt_counter",
        "abort_reason",
        "attempts",
        "config",
        "last_error",
        "total_completion_tokens",
        "total_prompt_tokens",
        "total_usd",
    )

    def __init__(self, *, config: RetryConfig) -> None:
        self.config = config
        self.attempts: list[AttemptRecord] = []
        self.total_prompt_tokens: int = 0
        self.total_completion_tokens: int = 0
        self.total_usd: float = 0.0
        self.last_error: AgentParseError | None = None
        self.abort_reason: RetryAbortReason = (
            RetryAbortReason.UNRECOVERABLE_SCHEMA_ERROR
        )
        self._attempt_counter: int = 0

    def next_attempt(self) -> int:
        self._attempt_counter += 1
        return self._attempt_counter

    def add_response(self, response: LLMResponse) -> None:
        self.total_prompt_tokens += response.prompt_tokens
        self.total_completion_tokens += response.completion_tokens
        self.total_usd += response.usd_cost

    def budget_allows(self) -> bool:
        if self.total_usd >= self.config.total_budget_usd:
            return False
        total_tokens = self.total_prompt_tokens + self.total_completion_tokens
        if total_tokens >= self.config.total_budget_tokens:
            return False
        return True

    def build_log(self) -> AttemptLog:
        return AttemptLog(
            abort_reason=self.abort_reason,
            attempts=list(self.attempts),
            total_prompt_tokens=self.total_prompt_tokens,
            total_completion_tokens=self.total_completion_tokens,
            total_usd_cost=round(self.total_usd, 6),
        )


# Sentinel returned by attempt helpers to signal "advance to the next retry".
_NEED_RETRY: Final[object] = object()


# ---------------------------------------------------------------------------
# Attempt builders
# ---------------------------------------------------------------------------


def _success_attempt(
    attempt_no: int, agent: BaseAgent, response: LLMResponse
) -> AttemptRecord:
    return AttemptRecord(
        attempt=attempt_no,
        agent_role=agent.role.value,
        prompt_id=agent.prompt_id,
        success=True,
        prompt_tokens=response.prompt_tokens,
        completion_tokens=response.completion_tokens,
        usd_cost=response.usd_cost,
        latency_ms=response.latency_ms,
    )


def _failed_attempt(
    attempt_no: int,
    agent: BaseAgent,
    response: LLMResponse,
    error: AgentParseError,
) -> AttemptRecord:
    sanitized = f"{error.field_path}: {error.reason}"[:2000]
    return AttemptRecord(
        attempt=attempt_no,
        agent_role=agent.role.value,
        prompt_id=agent.prompt_id,
        success=False,
        error_kind=AttemptErrorKind.SCHEMA_ERROR,
        sanitized_error=sanitized,
        prompt_tokens=response.prompt_tokens,
        completion_tokens=response.completion_tokens,
        usd_cost=response.usd_cost,
        latency_ms=response.latency_ms,
    )


def _provider_error_attempt(
    attempt_no: int,
    agent: BaseAgent,
    error: Exception,
) -> AttemptRecord:
    if isinstance(error, LLMProviderUnavailableError):
        kind = AttemptErrorKind.PROVIDER_UNAVAILABLE
        reason = f"{error.provider}: {error.reason}"
    else:
        kind = AttemptErrorKind.PROVIDER_ERROR
        reason = type(error).__name__
    return AttemptRecord(
        attempt=attempt_no,
        agent_role=agent.role.value,
        prompt_id=agent.prompt_id,
        success=False,
        error_kind=kind,
        sanitized_error=reason[:2000],
    )


async def _maybe_sleep(config: RetryConfig, retry_index: int) -> None:
    """Sleep for the backoff window (capped at :data:`_MAX_BACKOFF_S`)."""
    backoff = min(
        config.backoff_initial_s * (config.backoff_factor ** (retry_index - 1)),
        _MAX_BACKOFF_S,
    )
    if backoff > 0:
        await asyncio.sleep(backoff)


__all__ = [
    "AttemptLog",
    "AttemptRecord",
    "RetryAbortReason",
    "RetryConfig",
    "RetryLoop",
]
