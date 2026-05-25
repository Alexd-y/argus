"""Tests for Shannon integration wiring (4.1–4.10).

Verifies that all modules are importable and properly wired into
the orchestration pipeline.
"""

import pytest


class TestSourceAnalysisIntegration:
    """4.1: Source analysis is wired into state machine."""

    def test_source_analysis_phase_exists(self):
        from src.orchestration.phases import ScanPhase, PHASE_ORDER
        assert ScanPhase.SOURCE_ANALYSIS in PHASE_ORDER
        assert PHASE_ORDER[0] == ScanPhase.SOURCE_ANALYSIS

    def test_source_analyzer_importable(self):
        from src.orchestration.source_analysis.analyzer import SourceAnalyzer
        assert SourceAnalyzer is not None

    def test_source_analysis_models_importable(self):
        from src.orchestration.phases import SourceAnalysisInput, SourceAnalysisOutput
        sa_in = SourceAnalysisInput(target="https://example.com")
        assert sa_in.target == "https://example.com"
        assert sa_in.repo_path is None
        sa_out = SourceAnalysisOutput(skipped=True, summary="test")
        assert sa_out.skipped is True

    def test_source_analysis_skips_without_repo(self):
        from src.orchestration.source_analysis.analyzer import SourceAnalyzer
        from src.orchestration.phases import SourceAnalysisInput
        sa_in = SourceAnalysisInput(target="https://example.com")
        analyzer = SourceAnalyzer(sa_in)
        result = analyzer.analyze()
        assert result.skipped is True

    def test_state_machine_imports_source_analysis(self):
        from src.orchestration.phases import SourceAnalysisInput, SourceAnalysisOutput
        assert SourceAnalysisInput is not None
        assert SourceAnalysisOutput is not None


class TestExploitationQueueIntegration:
    """4.2: ExploitationQueue wired into pipeline."""

    def test_exploitation_queue_importable(self):
        from src.orchestration.exploitation_queue import ExploitationQueue, ExploitHypothesis, VulnClass
        assert ExploitationQueue is not None

    def test_from_vuln_analysis_output(self):
        from src.orchestration.exploitation_queue import ExploitationQueue
        findings = [
            {"title": "SQL Injection", "cwe": "89", "severity": "critical", "confidence": 0.9},
        ]
        queue = ExploitationQueue.from_vuln_analysis_output(
            target="https://example.com", findings=findings
        )
        assert isinstance(queue, ExploitationQueue)

    def test_exploitation_queue_in_phases(self):
        from src.orchestration.phases import VulnAnalysisOutput
        assert hasattr(VulnAnalysisOutput, "model_fields")
        assert "exploitation_queues" in VulnAnalysisOutput.model_fields


class TestPlaywrightIntegration:
    """4.3: Playwright adapter wiring."""

    def test_playwright_adapter_importable(self):
        from src.sandbox.playwright_adapter import PlaywrightAdapter, BrowserRequest, BrowserResponse
        assert PlaywrightAdapter is not None

    def test_browser_request_model(self):
        from src.sandbox.playwright_adapter import BrowserRequest
        req = BrowserRequest(action="navigate", url="https://example.com")
        assert req.url == "https://example.com"

    def test_browser_response_model(self):
        from src.sandbox.playwright_adapter import BrowserResponse
        resp = BrowserResponse(success=True, url="https://example.com")
        assert resp.success is True

    def test_mcp_browser_tools_registered(self):
        import importlib.util
        import os
        base = os.path.dirname(os.path.abspath(__file__))
        mcp_path = os.path.normpath(os.path.join(base, "..", "..", "mcp-server", "tools", "kali_registry.py"))
        if os.path.exists(mcp_path):
            with open(mcp_path, encoding="utf-8") as f:
                content = f.read()
            browser_count = content.lower().count("browser_")
            assert browser_count >= 5, f"Expected 5+ browser tool registrations, found {browser_count}"
        else:
            from src.sandbox.playwright_adapter import PlaywrightAdapter
            assert PlaywrightAdapter is not None


class TestAuthConfigIntegration:
    """4.4: AuthConfig wired into pipeline."""

    def test_auth_config_importable(self):
        from src.orchestration.auth_config import AuthConfig, TargetConfig, LoginType
        assert AuthConfig is not None

    def test_target_config_from_scan_options(self):
        from src.orchestration.auth_config import TargetConfig
        options = {"auth_config": {"description": "Test target"}}
        tc = TargetConfig.from_scan_options(options)
        assert tc is not None
        assert tc.description == "Test target"

    def test_target_config_from_scan_options_none(self):
        from src.orchestration.auth_config import TargetConfig
        tc = TargetConfig.from_scan_options({})
        assert tc is None

    def test_target_config_from_scan_options_yaml(self):
        from src.orchestration.auth_config import TargetConfig
        options = {"auth_config": "description: YAML target\nexploit: true"}
        tc = TargetConfig.from_scan_options(options)
        assert tc is not None


class TestVulnAgentsIntegration:
    """4.5: CWE-specialized agents wiring."""

    def test_vuln_agents_importable(self):
        from src.orchestration.vuln_agents import VULN_AGENT_SPECS, AgentDomain
        assert len(VULN_AGENT_SPECS) == 5

    def test_all_domains_covered(self):
        from src.orchestration.vuln_agents import AgentDomain
        assert AgentDomain.INJECTION
        assert AgentDomain.XSS
        assert AgentDomain.AUTH
        assert AgentDomain.AUTHZ
        assert AgentDomain.SSRF

    def test_filter_findings_by_domain(self):
        from src.orchestration.vuln_agents import filter_findings_by_domain, AgentDomain
        findings = [
            {"cwe": [89], "title": "SQL Injection"},
            {"cwe": [79], "title": "XSS"},
            {"cwe": [287], "title": "Broken Auth"},
        ]
        injection = filter_findings_by_domain(findings, AgentDomain.INJECTION)
        xss = filter_findings_by_domain(findings, AgentDomain.XSS)
        assert len(injection) >= 1
        assert len(xss) >= 1

    def test_agent_tool_allowlists(self):
        from src.orchestration.vuln_agents import VULN_AGENT_SPECS, AgentDomain
        for domain in AgentDomain:
            spec = VULN_AGENT_SPECS[domain]
            assert len(spec.tool_allowlist) > 0
            assert len(spec.cwe_focus) > 0


class TestEvidenceTierIntegration:
    """4.6: Evidence tiers (already integrated, verify)."""

    def test_evidence_tier_enum(self):
        from src.orchestration.evidence_tier import EvidenceTier
        assert EvidenceTier.EXPLOITED == 4
        assert EvidenceTier.CONFIRMED == 3
        assert EvidenceTier.SUSPECTED == 2
        assert EvidenceTier.INFORMATIONAL == 1

    def test_classify_finding(self):
        from src.orchestration.evidence_tier import classify_finding, EvidenceTier, ConfidenceLevel
        exploited = classify_finding(ConfidenceLevel.EXPLOITABLE, has_payload=True, has_evidence=True)
        assert exploited == EvidenceTier.EXPLOITED
        confirmed = classify_finding(ConfidenceLevel.CONFIRMED)
        assert confirmed == EvidenceTier.CONFIRMED

    def test_evidence_tier_in_finding_dto(self):
        from src.pipeline.contracts.finding_dto import FindingDTO
        flds = FindingDTO.model_fields
        assert "evidence_tier" in flds

    def test_sort_by_evidence_tier(self):
        from src.orchestration.evidence_tier import EvidenceTier
        from src.reports.finding_quality_filter import sort_findings_by_evidence_tier
        findings = [
            {"title": "Low", "evidence_tier": EvidenceTier.INFORMATIONAL},
            {"title": "High", "evidence_tier": EvidenceTier.EXPLOITED},
        ]
        sorted_f = sort_findings_by_evidence_tier(findings)
        assert sorted_f[0]["evidence_tier"] == EvidenceTier.EXPLOITED


class TestModelTieringIntegration:
    """4.7: Model tiering routing."""

    def test_llm_tier_enum(self):
        from src.llm.task_router import LLMTier
        assert LLMTier.SMALL
        assert LLMTier.MEDIUM
        assert LLMTier.LARGE

    def test_task_tiers_populated(self):
        from src.llm.task_router import TASK_TIERS, LLMTask
        assert len(TASK_TIERS) > 0
        assert LLMTask.ORCHESTRATION in TASK_TIERS

    def test_get_tier_for_task(self):
        from src.llm.task_router import get_tier_for_task, LLMTask, LLMTier
        tier_info = get_tier_for_task(LLMTask.ORCHESTRATION)
        assert "tier" in tier_info
        assert tier_info["tier"] in (LLMTier.SMALL, LLMTier.MEDIUM, LLMTier.LARGE)

    def test_get_model_for_tier(self):
        from src.llm.task_router import get_model_for_tier, LLMTier
        models = get_model_for_tier(LLMTier.SMALL)
        assert isinstance(models, dict)


class TestScopeIntegration:
    """4.8: Scope integration wiring."""

    def test_scope_integration_importable(self):
        from src.orchestration.scope_integration import (
            target_config_to_scope_rules,
            rules_of_engagement_to_prompt_context,
        )
        assert target_config_to_scope_rules is not None

    def test_target_config_to_scope_rules(self):
        from src.orchestration.scope_integration import target_config_to_scope_rules
        from src.orchestration.auth_config import TargetConfig
        tc = TargetConfig(
            rules={
                "focus": [{"description": "API", "type": "url_path", "value": "https://example.com/api"}],
                "avoid": [{"description": "Logout", "type": "url_path", "value": "https://example.com/logout"}],
            }
        )
        allow, deny = target_config_to_scope_rules(tc)
        assert len(allow) >= 1
        assert len(deny) >= 1

    def test_rules_of_engagement_to_prompt_context(self):
        from src.orchestration.scope_integration import rules_of_engagement_to_prompt_context
        from src.orchestration.auth_config import TargetConfig
        tc = TargetConfig(description="Test target", exploit=True)
        ctx = rules_of_engagement_to_prompt_context(tc)
        assert "Test target" in ctx
        assert "enabled" in ctx


class TestPhaseResumeIntegration:
    """4.9: Phase-level resume wiring."""

    def test_phase_resume_importable(self):
        from src.orchestration.phase_resume import (
            ResumeDecision,
            compute_resume_plan,
            get_completed_phases,
            format_resume_summary,
        )
        assert ResumeDecision.SKIP
        assert ResumeDecision.RUN_FRESH

    def test_compute_resume_plan(self):
        from src.orchestration.phase_resume import compute_resume_plan, ResumeDecision
        from src.orchestration.phases import ScanPhase
        completed = {ScanPhase.RECON, ScanPhase.THREAT_MODELING}
        plan = compute_resume_plan(completed)
        assert plan[ScanPhase.RECON] == ResumeDecision.SKIP
        assert plan[ScanPhase.VULN_ANALYSIS] == ResumeDecision.RUN_FRESH

    def test_format_resume_summary(self):
        from src.orchestration.phase_resume import format_resume_summary, ResumeDecision
        from src.orchestration.phases import ScanPhase
        plan = {ScanPhase.RECON: ResumeDecision.SKIP, ScanPhase.VULN_ANALYSIS: ResumeDecision.RUN_FRESH}
        summary = format_resume_summary(plan)
        assert "SKIP" in summary
        assert "RUN" in summary


class TestPromptLoaderIntegration:
    """4.10: Jinja2 prompt template loading."""

    def test_prompt_loader_importable(self):
        from src.orchestration.prompt_loader import PromptLoader, get_loader
        assert PromptLoader is not None

    def test_get_loader_returns_loader(self):
        from src.orchestration.prompt_loader import get_loader
        loader = get_loader()
        assert loader is not None

    def test_jinja2_available(self):
        from src.orchestration.prompt_loader import get_loader
        loader = get_loader()
        assert loader.available is True

    def test_render_phase_prompts(self):
        from src.orchestration.prompt_loader import render_phase_prompts
        system, user = render_phase_prompts("recon", target="https://example.com", options="{}")
        assert "ARGUS" in system
        assert "example.com" in user

    def test_templates_exist(self):
        from src.orchestration.prompt_loader import get_loader
        loader = get_loader()
        templates = loader.list_templates()
        j2_templates = [t for t in templates if t.endswith(".j2")]
        assert len(j2_templates) >= 30

    def test_ai_prompts_uses_jinja2(self):
        from src.orchestration.ai_prompts import _get_phase_prompt
        system, user = _get_phase_prompt("recon", target="https://test.com", options="{}")
        assert len(system) > 0
        assert len(user) > 0


class TestEphemeralWorkerIntegration:
    """4.11: Ephemeral worker pool."""

    def test_ephemeral_worker_importable(self):
        from src.orchestration.ephemeral_worker import EphemeralWorkerPool, ContainerSpec, ContainerResult
        assert EphemeralWorkerPool is not None

    def test_pool_instantiation(self):
        from src.orchestration.ephemeral_worker import EphemeralWorkerPool
        pool = EphemeralWorkerPool(max_containers=3)
        assert pool.active_count == 0