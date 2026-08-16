"""CONT-007 — production vs LAB mode traces (DoD §22), fast unit-level, no Docker.

Production trace shape (§22):
  phase_input
  → policy_content_classification
  → tenant_filtered_rag
  → typed_analysis
  → deterministic_candidate_set
  → production_policy_approval (high-risk may require approval)
  → sandbox_execution_stub
  → evidence_finding_coverage_report

LAB unrestricted trace shape (§22):
  lab_scope_manifest
  → boundary_verification
  → unrestricted_lease (requires_approval=False)
  → tenant_filtered_rag
  → complete_requested_plan
  → arbitrary_tool_selection (approval_steps=0, rate_caps=None)
  → sandbox_lab_exec_stub
  → full_evidence_oast_session_trace
  → findings_diff_retest_coverage_report
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from src.execution_mode import (
    ExecutionMode,
    LabBoundaryVerifier,
    LabLeaseService,
    LabScopeManifest,
    evaluate_with_execution_mode,
)
from src.orchestration.execution_mode_context import resolve_tool_policy
from src.rag import RagIngestionPipeline, RagQuery, RagRetriever
from src.rag.hybrid_search import HybridSearchEngine
from src.rag.schemas import CollectionName

pytestmark = pytest.mark.mode_trace


@dataclass
class TraceEvent:
    stage: str
    detail: dict[str, Any] = field(default_factory=dict)


class ModeTraceSimulator:
    """Deterministic in-memory pipeline trace with real policy/RAG gates."""

    def __init__(self) -> None:
        self.events: list[TraceEvent] = []

    def _emit(self, stage: str, **detail: Any) -> None:
        self.events.append(TraceEvent(stage=stage, detail=detail))

    @property
    def stages(self) -> list[str]:
        return [event.stage for event in self.events]

    def run_production(
        self,
        *,
        tenant_id: str = "tenant-trace-prod",
        engagement_id: str = "eng-trace-001",
    ) -> list[str]:
        self._emit("phase_input", phase="vuln_analysis", mode="production")
        self._emit("policy_content_classification", content_class="internal")

        retriever = RagRetriever()
        pipeline = RagIngestionPipeline(chunk_size=400)
        other_tenant = "tenant-trace-other"
        ingest = pipeline.ingest(
            tenant_id=other_tenant,
            engagement_id=engagement_id,
            collection=CollectionName.FINDING_HISTORY,
            uri="memory://trace/other-secret",
            title="other-tenant-secret",
            content="Other tenant confidential exploit notes.",
        )
        retriever.store.add_ingestion(ingest.chunks, ingest.embeddings)

        pack = retriever.retrieve(
            RagQuery(text="confidential exploit", max_results=5),
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            mode=ExecutionMode.PRODUCTION,
            collections=[CollectionName.FINDING_HISTORY],
        )
        leaked = [chunk for chunk in pack.chunks if chunk.tenant_id == other_tenant]
        assert not leaked
        search = HybridSearchEngine(retriever.store)
        assert search.cross_tenant_denied(
            "confidential exploit",
            tenant_id=tenant_id,
            other_tenant_id=other_tenant,
            engagement_id=engagement_id,
            mode=ExecutionMode.PRODUCTION,
            collections=[CollectionName.FINDING_HISTORY],
        )
        self._emit(
            "tenant_filtered_rag",
            tenant_id=tenant_id,
            hits=len(pack.chunks),
            cross_tenant_denied=True,
        )

        self._emit("typed_analysis", alias="security_reasoner")
        self._emit("deterministic_candidate_set", count=3)

        sqlmap_policy = resolve_tool_policy(
            "sqlmap",
            mode=ExecutionMode.PRODUCTION,
            target="https://prod.example/",
            tenant_id=tenant_id,
            engagement_id=engagement_id,
        )
        assert sqlmap_policy.requires_approval is True
        assert sqlmap_policy.allowed is False
        self._emit(
            "production_policy_approval",
            tool="sqlmap",
            requires_approval=True,
            allowed=False,
            reason=sqlmap_policy.reason,
        )

        nuclei_policy = resolve_tool_policy(
            "nuclei",
            mode=ExecutionMode.PRODUCTION,
            target="https://prod.example/",
            tenant_id=tenant_id,
            engagement_id=engagement_id,
        )
        assert nuclei_policy.allowed is True
        assert nuclei_policy.requires_approval is False
        self._emit(
            "production_policy_approval",
            tool="nuclei",
            requires_approval=False,
            allowed=True,
            lab_allow_all=False,
        )

        self._emit("sandbox_execution_stub", tool="nuclei")
        self._emit("evidence_finding_coverage_report", findings=1)
        return self.stages

    def run_lab_unrestricted(
        self,
        *,
        tenant_id: str = "tenant-trace-lab",
        engagement_id: str = "eng-trace-lab",
    ) -> list[str]:
        manifest = LabScopeManifest(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            cidrs=("10.90.0.0/16",),
            dns_suffixes=("lab.argus",),
            k8s_namespace="argus-lab-42",
            vm_network_ids=("labnet-42",),
            capture_full=True,
            expires_at=datetime.now(tz=UTC) + timedelta(hours=2),
            created_by="mode-trace",
        )
        self._emit("lab_scope_manifest", manifest_id=manifest.manifest_id)

        target = "10.90.3.3"
        verdict = LabBoundaryVerifier().verify(
            target,
            manifest,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            k8s_namespace="argus-lab-42",
            vm_network_id="labnet-42",
        )
        assert verdict.allowed is True
        self._emit("boundary_verification", allowed=verdict.allowed, proof=verdict.proof)

        lease = LabLeaseService().issue(manifest, boundary_proof=verdict.proof or "trace-proof")
        bridge = evaluate_with_execution_mode(
            mode=ExecutionMode.LAB_UNRESTRICTED,
            target=target,
            lease=lease,
            manifest=manifest,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            k8s_namespace="argus-lab-42",
            vm_network_id="labnet-42",
        )
        assert bridge.requires_approval is False
        assert getattr(bridge, "allowed", False) is True
        self._emit(
            "unrestricted_lease",
            lease_id=lease.lease_id,
            requires_approval=False,
        )

        retriever = RagRetriever()
        pipeline = RagIngestionPipeline(chunk_size=400)
        ingest = pipeline.ingest(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            collection=CollectionName.LAB_RESEARCH,
            uri="memory://trace/lab-note",
            title="lab-research-note",
            content="Lab-only research corpus for unrestricted mode.",
        )
        retriever.store.add_ingestion(ingest.chunks, ingest.embeddings)
        pack = retriever.retrieve(
            RagQuery(text="lab research", max_results=5),
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            mode=ExecutionMode.LAB_UNRESTRICTED,
            collections=[CollectionName.LAB_RESEARCH],
        )
        self._emit(
            "tenant_filtered_rag",
            tenant_id=tenant_id,
            collections=["lab_research"],
            hits=len(pack.chunks),
        )

        plan_tools = ["nuclei", "custom_script", "sqlmap"]
        self._emit("complete_requested_plan", steps=plan_tools)

        for tool in plan_tools:
            decision = resolve_tool_policy(
                tool,
                mode=ExecutionMode.LAB_UNRESTRICTED,
                lease=lease,
                manifest=manifest,
                target=f"https://app.lab.argus/{tool}",
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                k8s_namespace="argus-lab-42",
                vm_network_id="labnet-42",
            )
            assert decision.allowed is True
            assert decision.requires_approval is False

        self._emit(
            "arbitrary_tool_selection",
            tools=plan_tools,
            approval_steps=0,
            rate_caps=None,
        )
        self._emit("sandbox_lab_exec_stub", tool="nuclei")
        self._emit("full_evidence_oast_session_trace", capture_full=True)
        self._emit("findings_diff_retest_coverage_report")
        return self.stages


def test_production_mode_trace_order() -> None:
    sim = ModeTraceSimulator()
    stages = sim.run_production()

    assert stages[0] == "phase_input"
    assert "policy_content_classification" in stages
    assert "tenant_filtered_rag" in stages
    assert "typed_analysis" in stages
    assert "deterministic_candidate_set" in stages
    assert "production_policy_approval" in stages
    assert "sandbox_execution_stub" in stages
    assert "evidence_finding_coverage_report" in stages

    rag = next(event for event in sim.events if event.stage == "tenant_filtered_rag")
    assert rag.detail.get("cross_tenant_denied") is True

    first_gate = next(
        event
        for event in sim.events
        if event.stage == "production_policy_approval"
        and event.detail.get("requires_approval") is True
        and event.detail.get("tool") == "sqlmap"
    )
    assert first_gate.detail.get("allowed") is False

    allowed_gate = next(
        event
        for event in sim.events
        if event.stage == "production_policy_approval"
        and event.detail.get("requires_approval") is False
        and event.detail.get("tool") == "nuclei"
    )
    assert allowed_gate.detail.get("allowed") is True
    assert allowed_gate.detail.get("lab_allow_all") is False

    idx_policy = stages.index("production_policy_approval")
    idx_sandbox = stages.index("sandbox_execution_stub")
    assert idx_policy < idx_sandbox


def test_lab_unrestricted_mode_trace_order() -> None:
    sim = ModeTraceSimulator()
    stages = sim.run_lab_unrestricted()

    assert stages[0] == "lab_scope_manifest"
    assert "boundary_verification" in stages
    assert "unrestricted_lease" in stages
    assert "complete_requested_plan" in stages
    assert "arbitrary_tool_selection" in stages
    assert "sandbox_lab_exec_stub" in stages
    assert "full_evidence_oast_session_trace" in stages
    assert "findings_diff_retest_coverage_report" in stages

    lease_ev = next(event for event in sim.events if event.stage == "unrestricted_lease")
    assert lease_ev.detail["requires_approval"] is False

    arb = next(event for event in sim.events if event.stage == "arbitrary_tool_selection")
    assert arb.detail["approval_steps"] == 0
    assert arb.detail["rate_caps"] is None

    idx_lease = stages.index("unrestricted_lease")
    idx_exec = stages.index("sandbox_lab_exec_stub")
    assert idx_lease < idx_exec
