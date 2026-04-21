"""Unit tests for :mod:`src.orchestrator.retry_loop` (ARG-008)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any
from unittest.mock import patch

import pytest

from src.orchestrator.agents import (
    AgentContext,
    FixerAgent,
    PlannerAgent,
)
from src.orchestrator.cost_tracker import CostTracker
from src.orchestrator.llm_provider import (
    EchoLLMProvider,
    LLMProviderError,
)
from src.orchestrator.prompt_registry import PromptRegistry
from src.orchestrator.retry_loop import (
    AttemptErrorKind,
    AttemptLog,
    RetryAbortReason,
    RetryConfig,
    RetryLoop,
)


def _make_planner(
    registry: PromptRegistry,
    provider: EchoLLMProvider,
) -> PlannerAgent:
    return PlannerAgent(provider, registry, prompt_id="planner_v1")


def _make_fixer(
    registry: PromptRegistry,
    provider: EchoLLMProvider,
) -> FixerAgent:
    return FixerAgent(provider, registry, prompt_id="fixer_v1")


@pytest.fixture()
def fast_retry_config() -> RetryConfig:
    """Disable real backoff sleeps for fast tests."""
    return RetryConfig(
        max_retries=2,
        backoff_initial_s=0.0,
        backoff_factor=1.0,
        total_budget_usd=0.50,
        total_budget_tokens=16_384,
    )


# ---------------------------------------------------------------------------
# RetryConfig
# ---------------------------------------------------------------------------


class TestRetryConfig:
    def test_defaults(self) -> None:
        cfg = RetryConfig()
        assert cfg.max_retries == 2
        assert cfg.total_budget_usd > 0
        assert cfg.total_budget_tokens > 0

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValueError):
            RetryConfig(bogus=1)  # type: ignore[call-arg]

    def test_max_retries_upper_bound(self) -> None:
        with pytest.raises(ValueError):
            RetryConfig(max_retries=99)


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


class TestRetryLoopHappyPath:
    @pytest.mark.asyncio
    async def test_first_attempt_succeeds(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        cost_tracker: CostTracker,
        canned_validation_plan: Callable[[], dict[str, Any]],
        fast_retry_config: RetryConfig,
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory({"planner_v1": canned_validation_plan()})
        planner = _make_planner(registry, provider)
        fixer = _make_fixer(registry, provider)

        loop = RetryLoop(
            cost_tracker=cost_tracker,
            fixer_agent=fixer,
            config=fast_retry_config,
        )
        result, log = await loop.run(planner, agent_context)
        assert log.abort_reason is RetryAbortReason.VALIDATED_OK
        assert result is not None
        assert len(log.attempts) == 1
        assert log.attempts[0].success is True
        assert log.total_usd_cost > 0

    @pytest.mark.asyncio
    async def test_fixer_recovery_on_second_attempt(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        cost_tracker: CostTracker,
        canned_validation_plan: Callable[[], dict[str, Any]],
        fast_retry_config: RetryConfig,
    ) -> None:
        registry, _, _ = full_signed_registry
        bad = canned_validation_plan()
        bad.pop("hypothesis")
        good = canned_validation_plan()
        provider = echo_provider_factory({"planner_v1": bad, "fixer_v1": good})
        planner = _make_planner(registry, provider)
        fixer = _make_fixer(registry, provider)

        loop = RetryLoop(
            cost_tracker=cost_tracker,
            fixer_agent=fixer,
            config=fast_retry_config,
        )
        result, log = await loop.run(planner, agent_context)
        assert log.abort_reason is RetryAbortReason.VALIDATED_OK
        assert result is not None
        assert len(log.attempts) == 2
        assert log.attempts[0].success is False
        assert log.attempts[1].success is True


# ---------------------------------------------------------------------------
# Failure paths
# ---------------------------------------------------------------------------


class TestRetryLoopFailures:
    @pytest.mark.asyncio
    async def test_max_retries_exhausted(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        cost_tracker: CostTracker,
        canned_validation_plan: Callable[[], dict[str, Any]],
        fast_retry_config: RetryConfig,
    ) -> None:
        registry, _, _ = full_signed_registry
        bad = canned_validation_plan()
        bad.pop("hypothesis")
        provider = echo_provider_factory({"planner_v1": bad, "fixer_v1": bad})
        planner = _make_planner(registry, provider)
        fixer = _make_fixer(registry, provider)

        loop = RetryLoop(
            cost_tracker=cost_tracker,
            fixer_agent=fixer,
            config=fast_retry_config,
        )
        result, log = await loop.run(planner, agent_context)
        assert result is None
        assert log.abort_reason is RetryAbortReason.MAX_RETRIES_EXHAUSTED
        # 1 original + 2 fixer retries = 3 attempts.
        assert len(log.attempts) == 3
        for attempt in log.attempts:
            assert attempt.success is False
            assert attempt.sanitized_error is not None
            assert "input_value" not in attempt.sanitized_error

    @pytest.mark.asyncio
    async def test_fixer_returns_invalid_json(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        cost_tracker: CostTracker,
        canned_validation_plan: Callable[[], dict[str, Any]],
        fast_retry_config: RetryConfig,
    ) -> None:
        registry, _, _ = full_signed_registry
        bad = canned_validation_plan()
        bad.pop("hypothesis")
        provider = echo_provider_factory({"planner_v1": bad, "fixer_v1": "not json"})
        planner = _make_planner(registry, provider)
        fixer = _make_fixer(registry, provider)
        loop = RetryLoop(
            cost_tracker=cost_tracker,
            fixer_agent=fixer,
            config=fast_retry_config,
        )
        result, log = await loop.run(planner, agent_context)
        assert result is None
        assert log.abort_reason is RetryAbortReason.MAX_RETRIES_EXHAUSTED
        # All fixer attempts produced "fixer response is not valid JSON".
        fixer_attempts = [a for a in log.attempts[1:] if a.agent_role == "fixer"]
        assert all(
            "not valid JSON" in (a.sanitized_error or "") for a in fixer_attempts
        )

    @pytest.mark.asyncio
    async def test_provider_error_first_attempt(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        cost_tracker: CostTracker,
        fast_retry_config: RetryConfig,
    ) -> None:
        registry, _, _ = full_signed_registry
        # No canned planner_v1 → provider raises LLMProviderUnavailableError.
        provider = echo_provider_factory()
        planner = _make_planner(registry, provider)
        fixer = _make_fixer(registry, provider)
        loop = RetryLoop(
            cost_tracker=cost_tracker,
            fixer_agent=fixer,
            config=fast_retry_config,
        )
        result, log = await loop.run(planner, agent_context)
        assert result is None
        assert log.abort_reason is RetryAbortReason.PROVIDER_ERROR
        assert log.attempts[-1].error_kind is AttemptErrorKind.PROVIDER_UNAVAILABLE

    @pytest.mark.asyncio
    async def test_provider_error_during_fixer(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        cost_tracker: CostTracker,
        canned_validation_plan: Callable[[], dict[str, Any]],
        fast_retry_config: RetryConfig,
    ) -> None:
        registry, _, _ = full_signed_registry
        bad = canned_validation_plan()
        bad.pop("hypothesis")
        provider = echo_provider_factory({"planner_v1": bad})  # no fixer canned
        planner = _make_planner(registry, provider)
        fixer = _make_fixer(registry, provider)
        loop = RetryLoop(
            cost_tracker=cost_tracker,
            fixer_agent=fixer,
            config=fast_retry_config,
        )
        result, log = await loop.run(planner, agent_context)
        assert result is None
        assert log.abort_reason is RetryAbortReason.PROVIDER_ERROR
        assert log.attempts[-1].agent_role == "fixer"

    @pytest.mark.asyncio
    async def test_budget_exhausted_blocks_retries(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        cost_tracker: CostTracker,
        canned_validation_plan: Callable[[], dict[str, Any]],
    ) -> None:
        registry, _, _ = full_signed_registry
        bad = canned_validation_plan()
        bad.pop("hypothesis")
        provider = echo_provider_factory({"planner_v1": bad, "fixer_v1": bad})
        planner = _make_planner(registry, provider)
        fixer = _make_fixer(registry, provider)
        # Tiny budget -> first attempt already exhausts it.
        config = RetryConfig(
            max_retries=2,
            backoff_initial_s=0.0,
            backoff_factor=1.0,
            total_budget_usd=1e-9,
            total_budget_tokens=1,
        )
        loop = RetryLoop(cost_tracker=cost_tracker, fixer_agent=fixer, config=config)
        result, log = await loop.run(planner, agent_context)
        assert result is None
        assert log.abort_reason is RetryAbortReason.BUDGET_EXHAUSTED
        # First attempt (parse error) recorded, then loop refused to spend more.
        assert log.attempts[0].success is False


class TestRetryLoopGenericProviderError:
    @pytest.mark.asyncio
    async def test_generic_provider_error_first_attempt(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        cost_tracker: CostTracker,
        canned_validation_plan: Callable[[], dict[str, Any]],
        fast_retry_config: RetryConfig,
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory({"planner_v1": canned_validation_plan()})
        planner = _make_planner(registry, provider)
        fixer = _make_fixer(registry, provider)

        async def boom(*_args: object, **_kwargs: object) -> None:
            raise LLMProviderError("transient HTTP 500")

        with patch.object(planner, "call_raw", new=boom):
            loop = RetryLoop(
                cost_tracker=cost_tracker,
                fixer_agent=fixer,
                config=fast_retry_config,
            )
            result, log = await loop.run(planner, agent_context)
        assert result is None
        assert log.abort_reason is RetryAbortReason.PROVIDER_ERROR
        assert log.attempts[-1].error_kind is AttemptErrorKind.PROVIDER_ERROR


# ---------------------------------------------------------------------------
# AttemptLog/AttemptRecord invariants
# ---------------------------------------------------------------------------


class TestAttemptLog:
    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValueError):
            AttemptLog(
                abort_reason=RetryAbortReason.VALIDATED_OK,
                total_prompt_tokens=0,
                total_completion_tokens=0,
                total_usd_cost=0.0,
                bogus=1,  # type: ignore[call-arg]
            )

    def test_totals_non_negative(self) -> None:
        with pytest.raises(ValueError):
            AttemptLog(
                abort_reason=RetryAbortReason.VALIDATED_OK,
                total_prompt_tokens=-1,
                total_completion_tokens=0,
                total_usd_cost=0.0,
            )


# ---------------------------------------------------------------------------
# Backoff sleep
# ---------------------------------------------------------------------------


class TestRetryLoopBackoff:
    @pytest.mark.asyncio
    async def test_sleep_invoked_between_retries(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        cost_tracker: CostTracker,
        canned_validation_plan: Callable[[], dict[str, Any]],
    ) -> None:
        registry, _, _ = full_signed_registry
        bad = canned_validation_plan()
        bad.pop("hypothesis")
        provider = echo_provider_factory(
            {"planner_v1": bad, "fixer_v1": canned_validation_plan()}
        )
        planner = _make_planner(registry, provider)
        fixer = _make_fixer(registry, provider)
        config = RetryConfig(
            max_retries=2,
            backoff_initial_s=0.01,
            backoff_factor=1.0,
            total_budget_usd=0.5,
            total_budget_tokens=16_384,
        )
        sleep_calls: list[float] = []

        async def fake_sleep(seconds: float) -> None:
            sleep_calls.append(seconds)

        loop = RetryLoop(cost_tracker=cost_tracker, fixer_agent=fixer, config=config)
        with patch.object(asyncio, "sleep", new=fake_sleep):
            _, log = await loop.run(planner, agent_context)
        assert log.abort_reason is RetryAbortReason.VALIDATED_OK
        assert sleep_calls and sleep_calls[0] > 0
