"""Unit tests for :mod:`src.llm.task_router`."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from src.llm.errors import LLMAllProvidersFailedError
from src.llm.task_router import (
    LLMRoute,
    LLMTask,
    ROUTING_TABLE,
    _GLOBAL_LLM_FALLBACK_CHAIN,
    _TASK_TO_ROLE,
    _call_route,
    _merge_route_with_global_chain,
    call_llm_for_task,
)
from src.orchestration.ai_prompts import _PHASE_TO_TASK

VALID_ROLES = {"planner", "code", "osint", "report"}

# Expected semantic role mappings
EXPECTED_ROLE_MAP: dict[LLMTask, str] = {
    LLMTask.ORCHESTRATION: "planner",
    LLMTask.THREAT_MODELING: "planner",
    LLMTask.VULN_ANALYSIS: "planner",
    LLMTask.VALIDATION_ONESHOT: "planner",
    LLMTask.DEDUP_ANALYSIS: "planner",
    LLMTask.ZERO_DAY_ANALYSIS: "planner",
    LLMTask.POC_GENERATION: "code",
    LLMTask.EXPLOIT_GENERATION: "code",
    LLMTask.PERPLEXITY_OSINT: "osint",
    LLMTask.REPORT_SECTION: "report",
    LLMTask.EXECUTIVE_SUMMARY: "report",
    LLMTask.REMEDIATION_PLAN: "report",
    LLMTask.COST_SUMMARY: "report",
    LLMTask.QUICK_PLANNER: "planner",
    LLMTask.QUICK_FINGERPRINT: "planner",
    LLMTask.QUICK_TRIAGE: "planner",
    LLMTask.QUICK_CRITIC: "planner",
    LLMTask.QUICK_REPORTER: "report",
}

EXPECTED_PHASE_MAP: dict[str, LLMTask] = {
    "recon": LLMTask.ORCHESTRATION,
    "threat_modeling": LLMTask.THREAT_MODELING,
    "vuln_analysis": LLMTask.ZERO_DAY_ANALYSIS,
    "exploitation": LLMTask.EXPLOIT_GENERATION,
    "post_exploitation": LLMTask.REMEDIATION_PLAN,
    "reporting": LLMTask.REPORT_SECTION,
}


class TestLLMTaskEnum:
    def test_all_tasks_enum_values_exist_and_correct(self):
        assert LLMTask.EXECUTIVE_SUMMARY.value == "executive_summary"
        assert LLMTask.THREAT_MODELING.value == "threat_modeling"
        assert LLMTask.EXPLOIT_GENERATION.value == "exploit_generation"
        assert LLMTask.VALIDATION_ONESHOT.value == "validation_oneshot"
        assert LLMTask.REMEDIATION_PLAN.value == "remediation_plan"
        assert LLMTask.ZERO_DAY_ANALYSIS.value == "zero_day_analysis"
        assert LLMTask.DEDUP_ANALYSIS.value == "dedup_analysis"
        assert LLMTask.PERPLEXITY_OSINT.value == "perplexity_osint"
        assert LLMTask.REPORT_SECTION.value == "report_section"
        assert LLMTask.ORCHESTRATION.value == "orchestration"
        assert LLMTask.POC_GENERATION.value == "poc_generation"
        assert LLMTask.COST_SUMMARY.value == "cost_summary"
        assert LLMTask.VULN_ANALYSIS.value == "vuln_analysis"
        assert LLMTask.QUICK_PLANNER.value == "quick_planner"
        assert LLMTask.QUICK_FINGERPRINT.value == "quick_fingerprint"
        assert LLMTask.QUICK_TRIAGE.value == "quick_triage"
        assert LLMTask.QUICK_CRITIC.value == "quick_critic"
        assert LLMTask.QUICK_REPORTER.value == "quick_reporter"

    def test_task_count_is_18(self):
        tasks = list(LLMTask)
        assert len(tasks) == 18


class TestTaskToRoleMapping:
    def test_mapping_is_complete_every_task_has_role(self):
        all_tasks = set(LLMTask)
        mapped_tasks = set(_TASK_TO_ROLE.keys())
        assert mapped_tasks == all_tasks, (
            f"Unmapped tasks: {all_tasks - mapped_tasks}"
        )

    def test_all_roles_are_valid(self):
        roles = set(_TASK_TO_ROLE.values())
        assert roles <= VALID_ROLES, f"Invalid roles: {roles - VALID_ROLES}"

    def test_task_to_role_mapping_semantically_correct(self):
        for task, expected_role in EXPECTED_ROLE_MAP.items():
            actual = _TASK_TO_ROLE.get(task)
            assert actual == expected_role, (
                f"{task.name} → expected '{expected_role}', got '{actual}'"
            )

    def test_planner_tasks_are_all_analytical(self):
        planner_tasks = [
            LLMTask.ORCHESTRATION,
            LLMTask.THREAT_MODELING,
            LLMTask.VALIDATION_ONESHOT,
            LLMTask.DEDUP_ANALYSIS,
            LLMTask.ZERO_DAY_ANALYSIS,
        ]
        for task in planner_tasks:
            assert _TASK_TO_ROLE[task] == "planner"

    def test_code_tasks_are_generation_based(self):
        code_tasks = [LLMTask.POC_GENERATION, LLMTask.EXPLOIT_GENERATION]
        for task in code_tasks:
            assert _TASK_TO_ROLE[task] == "code"

    def test_report_tasks_are_documentation_focused(self):
        report_tasks = [
            LLMTask.REPORT_SECTION,
            LLMTask.EXECUTIVE_SUMMARY,
            LLMTask.REMEDIATION_PLAN,
            LLMTask.COST_SUMMARY,
        ]
        for task in report_tasks:
            assert _TASK_TO_ROLE[task] == "report"

    def test_osint_task_is_standalone(self):
        assert _TASK_TO_ROLE[LLMTask.PERPLEXITY_OSINT] == "osint"


class TestRoutingTable:
    def test_routing_table_covers_all_tasks(self):
        all_tasks = set(LLMTask)
        routed_tasks = set(ROUTING_TABLE.keys())
        assert routed_tasks == all_tasks, (
            f"Missing routes: {all_tasks - routed_tasks}"
        )

    def test_all_routes_are_llm_route_instances(self):
        for task, route in ROUTING_TABLE.items():
            assert isinstance(route, LLMRoute), (
                f"{task.name} route is not an LLMRoute"
            )

    def test_executive_summary_route(self):
        route = ROUTING_TABLE[LLMTask.EXECUTIVE_SUMMARY]
        assert route.provider_env_key == "OPENROUTER_API_KEY"
        assert route.model == "anthropic/claude-3.5-sonnet"
        assert route.fallback_env_key == "OPENAI_API_KEY"
        assert route.fallback_model == "gpt-4o"
        assert route.max_tokens == 1500
        assert route.temperature == 0.1  # Block 5: lowered for deterministic reporting

    def test_threat_modeling_route(self):
        route = ROUTING_TABLE[LLMTask.THREAT_MODELING]
        assert route.provider_env_key == "DEEPSEEK_API_KEY"
        assert route.model == "deepseek-reasoner"
        assert route.max_tokens == 2000
        assert route.temperature == 0.4

    def test_exploit_generation_route(self):
        route = ROUTING_TABLE[LLMTask.EXPLOIT_GENERATION]
        assert route.provider_env_key == "DEEPSEEK_API_KEY"
        assert route.model == "deepseek-chat"
        assert route.temperature == 0.1

    def test_dedup_analysis_route_zero_temp(self):
        route = ROUTING_TABLE[LLMTask.DEDUP_ANALYSIS]
        assert route.temperature == 0.0
        assert route.max_tokens == 500

    def test_perplexity_osint_route_same_provider_fallback(self):
        route = ROUTING_TABLE[LLMTask.PERPLEXITY_OSINT]
        assert route.provider_env_key == "PERPLEXITY_API_KEY"
        assert route.fallback_env_key == "PERPLEXITY_API_KEY"
        assert route.model == "sonar-pro"
        assert route.fallback_model == "sonar"


class TestGlobalFallbackChain:
    def test_global_fallback_chain_has_correct_order(self):
        chain = list(_GLOBAL_LLM_FALLBACK_CHAIN)
        keys = [entry[0] for entry in chain]
        expected = [
            "OPENROUTER_API_KEY",
            "KIMI_API_KEY",
            "PERPLEXITY_API_KEY",
            "OPENAI_API_KEY",
            "DEEPSEEK_API_KEY",
            "GOOGLE_API_KEY",
        ]
        assert keys == expected, f"Fallback chain order mismatch"

    def test_global_fallback_chain_all_entries_have_three_elements(self):
        for entry in _GLOBAL_LLM_FALLBACK_CHAIN:
            assert len(entry) == 3

    def test_merge_with_global_chain_returns_non_empty(self):
        attempts = [("DEEPSEEK_API_KEY", "https://api.deepseek.com", "deepseek-chat")]
        merged = _merge_route_with_global_chain(attempts)
        assert len(merged) > 0

    def test_merge_with_global_chain_deduplicates_keys(self):
        attempts = [("OPENROUTER_API_KEY", "https://openrouter.ai/api", "openai/gpt-4o-mini")]
        merged = _merge_route_with_global_chain(attempts)
        key_counts = {}
        for env_key, _, _ in merged:
            key_counts[env_key] = key_counts.get(env_key, 0) + 1
        for key, count in key_counts.items():
            assert count == 1, f"Key '{key}' appears {count} times"

    def test_merge_with_global_chain_preserves_route_duplicates(self):
        route_key = "PERPLEXITY_API_KEY"
        attempts = [
            (route_key, "https://api.perplexity.ai", "sonar-pro"),
            (route_key, "https://api.perplexity.ai", "sonar"),
        ]
        merged = _merge_route_with_global_chain(attempts)
        route_entries = [(u, m) for k, u, m in merged if k == route_key]
        assert len(route_entries) == 2
        assert route_entries[0][1] == "sonar-pro"
        assert route_entries[1][1] == "sonar"


class TestPhaseToTaskMapping:
    def test_phase_to_task_covers_all_6_phases(self):
        expected_phases = {
            "recon",
            "threat_modeling",
            "vuln_analysis",
            "exploitation",
            "post_exploitation",
            "reporting",
        }
        assert set(_PHASE_TO_TASK.keys()) == expected_phases

    def test_phase_to_task_maps_to_correct_tasks(self):
        for phase, expected_task in EXPECTED_PHASE_MAP.items():
            actual = _PHASE_TO_TASK.get(phase)
            assert actual == expected_task, (
                f"Phase '{phase}' → expected {expected_task.name}, got {actual}"
            )

    def test_recon_phase_maps_to_orchestration(self):
        assert _PHASE_TO_TASK["recon"] == LLMTask.ORCHESTRATION

    def test_phase_to_task_uses_only_valid_task_enum_values(self):
        for task in _PHASE_TO_TASK.values():
            assert isinstance(task, LLMTask)
            assert task in LLMTask


class TestCallLlmForTaskFallback:
    @pytest.mark.asyncio
    async def test_call_llm_for_task_gracefully_handles_missing_route_config(self):
        from src.llm import task_router as tr

        modified_table = dict(ROUTING_TABLE)
        del modified_table[LLMTask.EXECUTIVE_SUMMARY]

        with patch.object(tr, "ROUTING_TABLE", modified_table):
            with patch.object(tr, "_get_key", return_value=None):
                with pytest.raises(LLMAllProvidersFailedError) as exc_info:
                    await call_llm_for_task(LLMTask.EXECUTIVE_SUMMARY, "test")
                assert "executive_summary" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_call_llm_for_task_raises_all_providers_failed_error(self):
        from src.llm import task_router as tr

        with patch.object(tr, "_get_key", return_value="fake-key"):
            with patch.object(
                tr, "_call_route", side_effect=RuntimeError("simulated failure")
            ):
                with pytest.raises(LLMAllProvidersFailedError) as exc_info:
                    await call_llm_for_task(LLMTask.COST_SUMMARY, "test prompt")
                assert "COST_SUMMARY" in str(exc_info.value) or "cost_summary" in str(exc_info.value)


class TestCallRoute:
    @pytest.mark.asyncio
    async def test_call_route_raises_on_missing_api_key(self):
        from src.llm import task_router as tr

        with patch.object(tr, "_get_key", return_value=None):
            with pytest.raises(RuntimeError, match="Provider not configured"):
                await _call_route(
                    route_env_key="NONEXISTENT_KEY",
                    route_base_url="https://example.com",
                    model="fake-model",
                    prompt="test",
                    system_prompt=None,
                    max_tokens=100,
                    temperature=0.3,
                )
