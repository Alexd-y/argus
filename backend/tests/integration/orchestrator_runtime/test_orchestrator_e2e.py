"""End-to-end integration test for the AI Orchestrator (ARG-008).

Loads the **real** signed ``backend/config/prompts/`` catalog and runs
the orchestrator with a deterministic :class:`EchoLLMProvider` through
the full pipeline:

    plan() → verify() → report()

Asserts the typed return values, the cost-tracking aggregation per
scan, and the audit-event emission.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from src.oast.correlator import InteractionKind, OASTInteraction
from src.orchestrator.agents import AgentContext, ReportNarrative
from src.orchestrator.cost_tracker import CostTracker
from src.orchestrator.llm_provider import EchoLLMProvider
from src.orchestrator.orchestrator import Orchestrator
from src.orchestrator.prompt_registry import PromptRegistry
from src.orchestrator.retry_loop import RetryConfig
from src.orchestrator.schemas.loader import ValidationPlanV1
from src.pipeline.contracts.finding_dto import FindingDTO
from src.pipeline.contracts.phase_io import ScanPhase
from src.policy.audit import AuditEventType, AuditLogger, InMemoryAuditSink


def _backend_root() -> Path:
    return Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def real_prompts_dir() -> Path:
    return _backend_root() / "config" / "prompts"


@pytest.fixture(scope="module")
def real_registry(real_prompts_dir: Path) -> PromptRegistry:
    if not real_prompts_dir.is_dir():
        pytest.skip(f"prompts dir not present: {real_prompts_dir}")
    registry = PromptRegistry(prompts_dir=real_prompts_dir)
    registry.load()
    return registry


def _validation_plan_payload() -> dict[str, Any]:
    return {
        "hypothesis": (
            "Boolean-blind SQLi suspected on the /api/search?q parameter "
            "based on response-length divergence in stage 2."
        ),
        "risk": "high",
        "payload_strategy": {
            "registry_family": "sqli.boolean.diff.v3",
            "mutation_classes": ["canonicalization", "case_normalization"],
            "raw_payloads_allowed": False,
        },
        "validator": {
            "tool": "safe_validator",
            "inputs": {"endpoint": "/api/search", "param": "q"},
            "success_signals": ["response_diff > threshold"],
            "stop_conditions": ["http_500", "rate_limited"],
        },
        "approval_required": True,
        "evidence_to_collect": ["raw_output", "diff"],
        "remediation_focus": ["use parameterised queries"],
    }


def _critic_verdict_payload(approved: bool = True) -> dict[str, Any]:
    return {
        "approved": approved,
        "reasons": [] if approved else ["registry_family banned by policy"],
        "suggested_modifications": None,
    }


def _finding_payload(scan_id: str, tenant_id: str) -> dict[str, Any]:
    return {
        "id": str(uuid4()),
        "tenant_id": tenant_id,
        "scan_id": scan_id,
        "asset_id": str(uuid4()),
        "tool_run_id": str(uuid4()),
        "category": "sqli",
        "cwe": [89],
        "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_v3_score": 9.8,
        "ssvc_decision": "Act",
        "owasp_wstg": ["WSTG-INPV-05"],
        "mitre_attack": ["T1190"],
        "confidence": "confirmed",
        "status": "new",
        "evidence_ids": [],
        "first_seen": datetime.now(tz=timezone.utc).isoformat(),
        "last_seen": datetime.now(tz=timezone.utc).isoformat(),
    }


def _findings_payload(scan_id: str, tenant_id: str) -> dict[str, Any]:
    return {"findings": [_finding_payload(scan_id, tenant_id)]}


def _narrative_payload() -> dict[str, Any]:
    return {
        "executive_summary": "One critical SQLi observed on /api/search.",
        "technical_summary": (
            "Boolean-blind SQLi confirmed via deterministic response-length "
            "divergence; CVSS 9.8."
        ),
        "recommendations": [
            "Switch /api/search to parameterised queries.",
            "Add WAF SQLi rule set in blocking mode.",
        ],
    }


@pytest.mark.asyncio
async def test_full_plan_verify_report_pipeline(
    real_registry: PromptRegistry,
) -> None:
    tenant_id = uuid4()
    scan_id = uuid4()
    correlation_id = uuid4()
    context = AgentContext(
        tenant_id=tenant_id,
        scan_id=scan_id,
        phase=ScanPhase.VULN_ANALYSIS,
        correlation_id=correlation_id,
        previous_findings=[],
        target_summary={"asset": "https://example.test"},
    )

    provider = EchoLLMProvider()
    provider.register_canned("planner_v1", _validation_plan_payload())
    provider.register_canned("critic_v1", _critic_verdict_payload(approved=True))
    provider.register_canned(
        "verifier_v1",
        _findings_payload(str(scan_id), str(tenant_id)),
    )
    provider.register_canned("reporter_v1", _narrative_payload())

    cost_tracker = CostTracker()
    audit_logger = AuditLogger(InMemoryAuditSink())
    orchestrator = Orchestrator(
        provider=provider,
        registry=real_registry,
        cost_tracker=cost_tracker,
        audit_logger=audit_logger,
        retry_config=RetryConfig(
            max_retries=2,
            backoff_initial_s=0.0,
            backoff_factor=1.0,
            total_budget_usd=0.5,
            total_budget_tokens=16_384,
        ),
    )

    plan = await orchestrator.plan(context, policy={"tenant": str(tenant_id)})
    assert isinstance(plan, ValidationPlanV1)
    assert plan.payload_strategy.registry_family == "sqli.boolean.diff.v3"
    assert plan.payload_strategy.raw_payloads_allowed is False

    findings = await orchestrator.verify(
        context,
        tool_output={
            "command": "validator-call",
            "result_summary": "diff_observed",
        },
        oast_evidence=[],
    )
    assert len(findings) == 1
    assert isinstance(findings[0], FindingDTO)
    assert findings[0].category == "sqli"

    narrative = await orchestrator.report(context, findings=findings)
    assert isinstance(narrative, ReportNarrative)
    assert "/api/search" in narrative.executive_summary
    assert narrative.recommendations

    summary = orchestrator.cost_summary_for_scan(scan_id)
    assert summary.record_count == 4
    assert "planner" in summary.by_role
    assert "critic" in summary.by_role
    assert "verifier" in summary.by_role
    assert "reporter" in summary.by_role
    assert summary.total_usd > 0.0
    assert summary.total_prompt_tokens > 0
    assert summary.total_completion_tokens > 0

    events = list(audit_logger.sink.iter_events(tenant_id=tenant_id))
    assert len(events) >= 1
    assert all(e.event_type is AuditEventType.POLICY_DECISION for e in events)
    assert all(e.decision_allowed for e in events)
    audit_logger.verify_chain(tenant_id=tenant_id)


@pytest.mark.asyncio
async def test_oast_evidence_propagated_to_verifier(
    real_registry: PromptRegistry,
) -> None:
    tenant_id = uuid4()
    scan_id = uuid4()
    context = AgentContext(
        tenant_id=tenant_id,
        scan_id=scan_id,
        phase=ScanPhase.VULN_ANALYSIS,
        correlation_id=uuid4(),
    )
    provider = EchoLLMProvider()
    provider.register_canned(
        "verifier_v1",
        _findings_payload(str(scan_id), str(tenant_id)),
    )
    cost_tracker = CostTracker()
    orchestrator = Orchestrator(
        provider=provider,
        registry=real_registry,
        cost_tracker=cost_tracker,
        audit_logger=AuditLogger(InMemoryAuditSink()),
    )
    interaction = OASTInteraction(
        id=uuid4(),
        token_id=uuid4(),
        kind=InteractionKind.DNS_A,
        received_at=datetime.now(tz=timezone.utc),
        source_ip="203.0.113.7",
        metadata={"host": "callback.example"},
        raw_request_hash=hashlib.sha256(b"oob signal").hexdigest(),
    )
    findings = await orchestrator.verify(
        context,
        tool_output={"raw": "oob signal observed"},
        oast_evidence=[interaction],
    )
    assert len(findings) == 1
