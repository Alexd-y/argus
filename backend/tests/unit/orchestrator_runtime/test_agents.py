"""Unit tests for the role-specific agents in :mod:`src.orchestrator.agents`."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

from src.orchestrator.agents import (
    AgentConfigError,
    AgentContext,
    AgentParseError,
    CriticAgent,
    CriticVerdict,
    FixerAgent,
    PlannerAgent,
    ReporterAgent,
    ReportNarrative,
    VerifierAgent,
)
from src.orchestrator.llm_provider import EchoLLMProvider, ResponseFormat
from src.orchestrator.prompt_registry import PromptRegistry
from src.orchestrator.schemas.loader import ValidationPlanV1
from src.pipeline.contracts.finding_dto import FindingDTO
from tests.unit.orchestrator_runtime.conftest import canned_finding

# ---------------------------------------------------------------------------
# DTO-level invariants
# ---------------------------------------------------------------------------


class TestCriticVerdict:
    def test_default_reasons_empty_list(self) -> None:
        v = CriticVerdict(approved=True)
        assert v.reasons == []
        assert v.suggested_modifications is None
        assert v.approved is True

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            CriticVerdict(approved=True, bonus="x")  # type: ignore[call-arg]

    def test_max_reasons_enforced(self) -> None:
        with pytest.raises(ValidationError):
            CriticVerdict(approved=False, reasons=["r"] * 17)


class TestReportNarrative:
    def test_min_length_executive_summary(self) -> None:
        with pytest.raises(ValidationError):
            ReportNarrative(
                executive_summary="",
                technical_summary="ok",
                recommendations=[],
            )

    def test_max_recommendations(self) -> None:
        with pytest.raises(ValidationError):
            ReportNarrative(
                executive_summary="ok",
                technical_summary="ok",
                recommendations=[f"r{i}" for i in range(17)],
            )


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------


class TestPlannerAgent:
    @pytest.mark.asyncio
    async def test_returns_validated_plan(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        canned_validation_plan: Callable[[], dict[str, Any]],
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory({"planner_v1": canned_validation_plan()})
        agent = PlannerAgent(provider, registry, prompt_id="planner_v1")
        result = await agent.run(agent_context)
        assert isinstance(result, ValidationPlanV1)
        assert result.payload_strategy.raw_payloads_allowed is False

    @pytest.mark.asyncio
    async def test_invalid_plan_raises_parse_error(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        canned_validation_plan: Callable[[], dict[str, Any]],
    ) -> None:
        registry, _, _ = full_signed_registry
        bad = canned_validation_plan()
        bad.pop("hypothesis")  # required field gone
        provider = echo_provider_factory({"planner_v1": bad})
        agent = PlannerAgent(provider, registry, prompt_id="planner_v1")
        with pytest.raises(AgentParseError) as exc_info:
            await agent.run(agent_context)
        assert exc_info.value.reason  # sanitised reason populated
        assert "input_value" not in exc_info.value.reason

    @pytest.mark.asyncio
    async def test_non_json_response_raises_parse_error(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory({"planner_v1": "not json"})
        agent = PlannerAgent(provider, registry, prompt_id="planner_v1")
        with pytest.raises(AgentParseError) as exc_info:
            await agent.run(agent_context)
        assert exc_info.value.field_path == "<root>"

    def test_role_mismatch_at_construction(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
    ) -> None:
        registry, _, _ = full_signed_registry
        with pytest.raises(AgentConfigError):
            PlannerAgent(echo_provider_factory(), registry, prompt_id="critic_v1")


# ---------------------------------------------------------------------------
# Critic
# ---------------------------------------------------------------------------


class TestCriticAgent:
    @pytest.mark.asyncio
    async def test_approval_verdict(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        canned_critic_verdict: Callable[..., dict[str, Any]],
        canned_validation_plan: Callable[[], dict[str, Any]],
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory(
            {"critic_v1": canned_critic_verdict(approved=True)}
        )
        agent = CriticAgent(provider, registry, prompt_id="critic_v1")
        plan = ValidationPlanV1.model_validate(canned_validation_plan())
        verdict = await agent.run(agent_context, plan_json=plan, policy={"k": "v"})
        assert verdict.approved is True
        assert verdict.reasons == []

    @pytest.mark.asyncio
    async def test_rejection_verdict(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        canned_critic_verdict: Callable[..., dict[str, Any]],
        canned_validation_plan: Callable[[], dict[str, Any]],
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory(
            {"critic_v1": canned_critic_verdict(approved=False)}
        )
        agent = CriticAgent(provider, registry, prompt_id="critic_v1")
        verdict = await agent.run(
            agent_context,
            plan_json=canned_validation_plan(),
            policy={},
        )
        assert verdict.approved is False
        assert "registry_family" in verdict.reasons[0]

    @pytest.mark.asyncio
    async def test_missing_plan_json_raises_config_error(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory({"critic_v1": {"approved": True}})
        agent = CriticAgent(provider, registry, prompt_id="critic_v1")
        with pytest.raises(AgentConfigError):
            await agent.run(agent_context)

    @pytest.mark.asyncio
    async def test_invalid_plan_json_type_raises_config_error(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory({"critic_v1": {"approved": True}})
        agent = CriticAgent(provider, registry, prompt_id="critic_v1")
        with pytest.raises(AgentConfigError):
            await agent.run(agent_context, plan_json=42, policy={})

    @pytest.mark.asyncio
    async def test_plan_json_str_passes(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        canned_critic_verdict: Callable[..., dict[str, Any]],
        canned_validation_plan: Callable[[], dict[str, Any]],
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory(
            {"critic_v1": canned_critic_verdict(approved=True)}
        )
        agent = CriticAgent(provider, registry, prompt_id="critic_v1")
        verdict = await agent.run(
            agent_context,
            plan_json=json.dumps(canned_validation_plan()),
            policy={},
        )
        assert verdict.approved is True

    @pytest.mark.asyncio
    async def test_malformed_verdict_raises_parse_error(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        canned_validation_plan: Callable[[], dict[str, Any]],
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory(
            {"critic_v1": {"approved": "yes"}}
        )  # str instead of bool
        agent = CriticAgent(provider, registry, prompt_id="critic_v1")
        with pytest.raises(AgentParseError) as exc_info:
            await agent.run(agent_context, plan_json=canned_validation_plan())
        assert "input_value" not in exc_info.value.reason


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------


class TestVerifierAgent:
    @pytest.mark.asyncio
    async def test_returns_findings(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        canned_findings_payload: Callable[..., dict[str, Any]],
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory(
            {
                "verifier_v1": canned_findings_payload(
                    agent_context.scan_id, agent_context.tenant_id, count=2
                )
            }
        )
        agent = VerifierAgent(provider, registry, prompt_id="verifier_v1")
        findings = await agent.run(
            agent_context,
            tool_output={"raw": "stuff"},
            oast_evidence=[],
        )
        assert len(findings) == 2
        assert all(isinstance(f, FindingDTO) for f in findings)

    @pytest.mark.asyncio
    async def test_missing_tool_output_raises_config_error(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory({"verifier_v1": {"findings": []}})
        agent = VerifierAgent(provider, registry, prompt_id="verifier_v1")
        with pytest.raises(AgentConfigError):
            await agent.run(agent_context)

    @pytest.mark.asyncio
    async def test_oast_evidence_must_be_list(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory({"verifier_v1": {"findings": []}})
        agent = VerifierAgent(provider, registry, prompt_id="verifier_v1")
        with pytest.raises(AgentConfigError):
            await agent.run(agent_context, tool_output={"x": 1}, oast_evidence={"k": 1})

    @pytest.mark.asyncio
    async def test_findings_not_a_list_raises_parse_error(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory({"verifier_v1": {"findings": "nope"}})
        agent = VerifierAgent(provider, registry, prompt_id="verifier_v1")
        with pytest.raises(AgentParseError) as exc_info:
            await agent.run(agent_context, tool_output={"x": 1})
        assert exc_info.value.field_path == "findings"

    @pytest.mark.asyncio
    async def test_too_many_findings_raises_parse_error(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
    ) -> None:
        registry, _, _ = full_signed_registry
        many = [
            canned_finding(agent_context.scan_id, agent_context.tenant_id)
            for _ in range(33)
        ]
        provider = echo_provider_factory({"verifier_v1": {"findings": many}})
        agent = VerifierAgent(provider, registry, prompt_id="verifier_v1")
        with pytest.raises(AgentParseError) as exc_info:
            await agent.run(agent_context, tool_output={"x": 1})
        assert "max" in exc_info.value.reason

    @pytest.mark.asyncio
    async def test_finding_not_object_raises_parse_error(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory(
            {"verifier_v1": {"findings": ["not an object"]}}
        )
        agent = VerifierAgent(provider, registry, prompt_id="verifier_v1")
        with pytest.raises(AgentParseError) as exc_info:
            await agent.run(agent_context, tool_output={"x": 1})
        assert "findings[0]" == exc_info.value.field_path

    @pytest.mark.asyncio
    async def test_invalid_finding_field_raises_parse_error(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
    ) -> None:
        registry, _, _ = full_signed_registry
        bad = canned_finding(agent_context.scan_id, agent_context.tenant_id)
        bad["cvss_v3_score"] = 99.0  # out of range
        provider = echo_provider_factory({"verifier_v1": {"findings": [bad]}})
        agent = VerifierAgent(provider, registry, prompt_id="verifier_v1")
        with pytest.raises(AgentParseError) as exc_info:
            await agent.run(agent_context, tool_output={"x": 1})
        assert exc_info.value.field_path.startswith("findings[0].")
        assert "input_value" not in exc_info.value.reason


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------


class TestReporterAgent:
    @pytest.mark.asyncio
    async def test_returns_narrative(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        canned_report_narrative: Callable[[], dict[str, Any]],
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory({"reporter_v1": canned_report_narrative()})
        agent = ReporterAgent(provider, registry, prompt_id="reporter_v1")
        narrative = await agent.run(agent_context, findings=[])
        assert isinstance(narrative, ReportNarrative)
        assert "/search" in narrative.executive_summary

    @pytest.mark.asyncio
    async def test_findings_must_be_list(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory({"reporter_v1": {}})
        agent = ReporterAgent(provider, registry, prompt_id="reporter_v1")
        with pytest.raises(AgentConfigError):
            await agent.run(agent_context, findings={"k": "v"})

    @pytest.mark.asyncio
    async def test_findings_must_be_finding_dto_or_dict(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory({"reporter_v1": {}})
        agent = ReporterAgent(provider, registry, prompt_id="reporter_v1")
        with pytest.raises(AgentConfigError):
            await agent.run(agent_context, findings=[42])

    @pytest.mark.asyncio
    async def test_dict_findings_accepted(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        canned_report_narrative: Callable[[], dict[str, Any]],
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory({"reporter_v1": canned_report_narrative()})
        agent = ReporterAgent(provider, registry, prompt_id="reporter_v1")
        narrative = await agent.run(
            agent_context,
            findings=[canned_finding(agent_context.scan_id, agent_context.tenant_id)],
        )
        assert narrative.recommendations

    @pytest.mark.asyncio
    async def test_invalid_narrative_raises_parse_error(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory({"reporter_v1": {"executive_summary": ""}})
        agent = ReporterAgent(provider, registry, prompt_id="reporter_v1")
        with pytest.raises(AgentParseError) as exc_info:
            await agent.run(agent_context, findings=[])
        assert "input_value" not in exc_info.value.reason


# ---------------------------------------------------------------------------
# Fixer
# ---------------------------------------------------------------------------


class TestFixerAgent:
    @pytest.mark.asyncio
    async def test_returns_corrected_dict(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory({"fixer_v1": {"fixed": True}})
        agent = FixerAgent(provider, registry, prompt_id="fixer_v1")
        result = await agent.run(
            agent_context,
            original_content='{"broken":}',
            schema_errors="<root>: malformed JSON",
            schema_ref="validation_plan_v1",
        )
        assert result == {"fixed": True}

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "missing", ["original_content", "schema_errors", "schema_ref"]
    )
    async def test_missing_required_kwarg_raises_config_error(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
        missing: str,
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory({"fixer_v1": {"fixed": True}})
        agent = FixerAgent(provider, registry, prompt_id="fixer_v1")
        kwargs: dict[str, str] = {
            "original_content": "{}",
            "schema_errors": "x",
            "schema_ref": "y",
        }
        kwargs.pop(missing)
        with pytest.raises(AgentConfigError) as exc_info:
            await agent.run(agent_context, **kwargs)
        assert missing in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_invalid_json_raises_parse_error(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory({"fixer_v1": "still broken"})
        agent = FixerAgent(provider, registry, prompt_id="fixer_v1")
        with pytest.raises(AgentParseError):
            await agent.run(
                agent_context,
                original_content="{}",
                schema_errors="x",
                schema_ref="y",
            )


# ---------------------------------------------------------------------------
# AgentContext model
# ---------------------------------------------------------------------------


class TestAgentContext:
    def test_defaults(self, agent_context: AgentContext) -> None:
        assert agent_context.previous_findings == []
        assert isinstance(agent_context.target_summary, dict)

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AgentContext(
                tenant_id=uuid4(),
                scan_id=uuid4(),
                phase="vuln_analysis",  # type: ignore[arg-type]
                correlation_id=uuid4(),
                bonus="x",  # type: ignore[call-arg]
            )


# ---------------------------------------------------------------------------
# BaseAgent helper coverage
# ---------------------------------------------------------------------------


class TestBaseAgentTemplateRendering:
    @pytest.mark.asyncio
    async def test_missing_placeholder_raises_config_error(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
        agent_context: AgentContext,
    ) -> None:
        # The verifier prompt requires `phase`, `tool_output`, `oast_evidence`.
        # Calling without supplying tool_output/oast_evidence kwargs goes
        # through VerifierAgent.run defaults; we simulate by hitting BaseAgent
        # directly via call_raw with an unrelated kwarg set.
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory({"verifier_v1": {"findings": []}})
        agent = VerifierAgent(provider, registry, prompt_id="verifier_v1")
        with pytest.raises(AgentConfigError):
            await agent.call_raw(agent_context)


class TestBaseAgentResponseFormat:
    def test_default_response_format_is_json_object(
        self,
        full_signed_registry: tuple[PromptRegistry, Any, Any],
        echo_provider_factory: Callable[..., EchoLLMProvider],
    ) -> None:
        registry, _, _ = full_signed_registry
        provider = echo_provider_factory()
        agent = PlannerAgent(provider, registry, prompt_id="planner_v1")
        assert agent._expected_response_format() is ResponseFormat.JSON_OBJECT
