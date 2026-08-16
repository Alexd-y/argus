"""Shared mocked fixtures for unified AI E2E paths (CONT-007)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

import pytest
from src.execution_mode import LabBoundaryVerifier, LabLeaseService, LabScopeManifest
from src.execution_mode.mode import ExecutionMode
from src.nuclei.profile_compiler import NucleiProfileCompiler
from src.orchestration.coverage_phase_sink import ToolRunSignal, attach_phase_coverage
from src.orchestration.execution_mode_context import resolve_tool_policy_from_options
from src.orchestration.rag_phase_context import (
    build_phase_rag_pack,
    configure_phase_rag_retriever,
)
from src.rag import RagIngestionPipeline, RagQuery, RagRetriever
from src.rag.schemas import CollectionName


@dataclass
class MockSandboxTrace:
    """Records sandbox dispatch calls for assertions."""

    calls: list[dict[str, Any]] = field(default_factory=list)

    def execute(self, tool: str, argv: list[str], **kwargs: Any) -> dict[str, Any]:
        record = {"tool": tool, "argv": list(argv), **kwargs}
        self.calls.append(record)
        return {
            "stdout": "mock-sandbox-stdout",
            "stderr": "",
            "exit_code": 0,
            "evidence_id": f"evidence-{len(self.calls)}",
        }


@dataclass
class UnifiedAiTrace:
    """Structured trace of a depersonalized unified-AI path run."""

    mode: str
    phase_input: dict[str, Any] = field(default_factory=dict)
    policy: dict[str, Any] = field(default_factory=dict)
    rag_hits: int = 0
    llm_response: dict[str, Any] = field(default_factory=dict)
    candidates: list[dict[str, Any]] = field(default_factory=list)
    approval_required: bool | None = None
    sandbox_calls: list[dict[str, Any]] = field(default_factory=list)
    nuclei_argv: list[str] = field(default_factory=list)
    coverage_status: str | None = None
    finding_key: str | None = None


def depersonalized_lab_manifest() -> LabScopeManifest:
    expires = datetime.now(tz=UTC) + timedelta(hours=4)
    return LabScopeManifest(
        tenant_id="tenant-e2e-alpha",
        engagement_id="eng-e2e-001",
        cidrs=("10.90.0.0/16",),
        dns_suffixes=("lab.argus",),
        k8s_namespace="argus-lab-42",
        vm_network_ids=("labnet-42",),
        capture_full=True,
        expires_at=expires,
        created_by="e2e-eval-user",
    )


def issue_lab_lease(manifest: LabScopeManifest, target: str) -> dict[str, Any]:
    verdict = LabBoundaryVerifier().verify(
        target,
        manifest,
        tenant_id=manifest.tenant_id,
        engagement_id=manifest.engagement_id,
        k8s_namespace=manifest.k8s_namespace,
        vm_network_id=manifest.vm_network_ids[0] if manifest.vm_network_ids else None,
    )
    lease = LabLeaseService().issue(manifest, boundary_proof=verdict.proof or "e2e-proof")
    return lease.to_storage_dict()


@pytest.fixture
def rag_pipeline() -> RagIngestionPipeline:
    return RagIngestionPipeline(chunk_size=400)


@pytest.fixture
def rag_retriever() -> RagRetriever:
    return RagRetriever()


@pytest.fixture
def mock_sandbox() -> MockSandboxTrace:
    return MockSandboxTrace()


@pytest.fixture
def mock_llm() -> AsyncMock:
    mock = AsyncMock()
    mock.return_value = {
        "steps": [
            {"id": "s1", "tool": "nuclei", "action": "scan", "requires_approval": False},
            {"id": "s2", "tool": "sqlmap", "action": "exploit", "requires_approval": False},
        ]
    }
    return mock


def seed_tenant_rag(
    pipeline: RagIngestionPipeline,
    retriever: RagRetriever,
    *,
    tenant_id: str,
    engagement_id: str,
    collection: CollectionName,
    title: str,
    content: str,
    mode: ExecutionMode = ExecutionMode.PRODUCTION,
) -> None:
    result = pipeline.ingest(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        collection=collection,
        uri=f"memory://e2e/{title}",
        title=title,
        content=content,
        mode=mode,
    )
    retriever.store.add_ingestion(result.chunks, result.embeddings)


def run_production_path(
    *,
    rag_pipeline: RagIngestionPipeline,
    rag_retriever: RagRetriever,
    mock_sandbox: MockSandboxTrace,
    mock_llm: AsyncMock,
) -> UnifiedAiTrace:
    """Production trace: policy → RAG → LLM → approval → sandbox."""
    trace = UnifiedAiTrace(mode="production")
    tenant_id = "tenant-e2e-alpha"
    engagement_id = "eng-e2e-001"
    target = "https://prod.example/app"
    trace.phase_input = {
        "scan_id": "scan-prod-e2e",
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "execution_mode": "production",
        "target": target,
        "phase": "vuln_analysis",
    }

    seed_tenant_rag(
        rag_pipeline,
        rag_retriever,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        collection=CollectionName.SCAN_EVIDENCE,
        title="prod-evidence",
        content="Potential SQL injection in login parameter id.",
    )

    policy = resolve_tool_policy_from_options(
        "sqlmap",
        {"execution_mode": "production", "tenant_id": tenant_id, "engagement_id": engagement_id},
        target=target,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        as_dict=True,
    )
    trace.policy = policy  # type: ignore[assignment]
    trace.approval_required = bool(policy.get("requires_approval"))

    pack = rag_retriever.retrieve(
        RagQuery(text="SQL injection login parameter", max_results=5),
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        mode=ExecutionMode.PRODUCTION,
        collections=[CollectionName.SCAN_EVIDENCE],
    )
    configure_phase_rag_retriever(rag_retriever)
    wired_pack = build_phase_rag_pack(
        "vuln_analysis",
        tenant_id,
        engagement_id,
        ExecutionMode.PRODUCTION,
        "SQL injection login parameter",
        retriever=rag_retriever,
    )
    trace.rag_hits = max(len(pack.chunks), len(wired_pack.chunks))

    llm_out = mock_llm.return_value
    trace.llm_response = llm_out
    trace.candidates = [
        {"tool": step["tool"], "risk": "destructive"} for step in llm_out.get("steps", [])
    ]

    if trace.approval_required:
        return trace

    for step in llm_out.get("steps", []):
        tool = str(step.get("tool") or "")
        if not tool:
            continue
        mock_sandbox.execute(tool, ["--mock"], target=target, mode="production")
    trace.sandbox_calls = list(mock_sandbox.calls)
    trace.coverage_status = "covered_with_finding"
    trace.finding_key = "a" * 64
    return trace


def run_lab_path(
    *,
    rag_pipeline: RagIngestionPipeline,
    rag_retriever: RagRetriever,
    mock_sandbox: MockSandboxTrace,
    mock_llm: AsyncMock,
) -> UnifiedAiTrace:
    """LAB trace: manifest → boundary → lease → RAG → plan → no approval → nuclei compiler."""
    trace = UnifiedAiTrace(mode="lab_unrestricted")
    tenant_id = "tenant-e2e-alpha"
    engagement_id = "eng-e2e-001"
    target = "https://app.lab.argus/vuln"
    manifest = depersonalized_lab_manifest()
    lease = issue_lab_lease(manifest, target)

    trace.phase_input = {
        "scan_id": "scan-lab-e2e",
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "execution_mode": "lab_unrestricted",
        "target": target,
        "lab_scope": manifest.to_storage_dict(),
        "lab_lease": lease,
        "k8s_namespace": manifest.k8s_namespace,
        "vm_network_id": manifest.vm_network_ids[0],
    }

    seed_tenant_rag(
        rag_pipeline,
        rag_retriever,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        collection=CollectionName.LAB_RESEARCH,
        title="lab-payload-artifact",
        content="Custom nuclei template and raw exploit payload for lab unrestricted workflow.",
        mode=ExecutionMode.LAB_UNRESTRICTED,
    )

    options = {
        "execution_mode": "lab_unrestricted",
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "lab_scope": manifest.to_storage_dict(),
        "lab_lease": lease,
        "k8s_namespace": manifest.k8s_namespace,
        "vm_network_id": manifest.vm_network_ids[0],
    }

    pack = rag_retriever.retrieve(
        RagQuery(text="raw exploit payload nuclei template", max_results=5),
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        mode=ExecutionMode.LAB_UNRESTRICTED,
        collections=[CollectionName.LAB_RESEARCH],
    )
    configure_phase_rag_retriever(rag_retriever)
    wired_pack = build_phase_rag_pack(
        "vuln_analysis",
        tenant_id,
        engagement_id,
        ExecutionMode.LAB_UNRESTRICTED,
        "raw exploit payload nuclei template",
        retriever=rag_retriever,
    )
    trace.rag_hits = max(len(pack.chunks), len(wired_pack.chunks))

    llm_out = {
        "steps": [
            {"id": "l1", "tool": "nuclei", "profile": "lab_unrestricted", "requires_approval": False},
            {"id": "l2", "tool": "sqlmap", "requires_approval": False},
        ]
    }
    mock_llm.return_value = llm_out
    trace.llm_response = llm_out

    nuclei_argv = NucleiProfileCompiler.compile(
        "lab_unrestricted",
        "lab_unrestricted",
        target,
        allow_code=True,
        allow_headless=True,
        allow_javascript=True,
    )
    trace.nuclei_argv = nuclei_argv

    for step in llm_out["steps"]:
        tool = str(step["tool"])
        decision = resolve_tool_policy_from_options(
            tool,
            options,
            target=target,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            k8s_namespace=manifest.k8s_namespace,
            vm_network_id=manifest.vm_network_ids[0],
            as_dict=True,
        )
        trace.policy = decision  # type: ignore[assignment]
        trace.approval_required = bool(decision.get("requires_approval"))
        assert decision.get("requires_approval") is False
        assert decision.get("allowed") is True
        argv = nuclei_argv if tool == "nuclei" else [tool, "--unrestricted"]
        mock_sandbox.execute(tool, argv, target=target, mode="lab_unrestricted")

    trace.sandbox_calls = list(mock_sandbox.calls)
    coverage_rows = attach_phase_coverage(
        phase="vuln_analysis",
        tenant_id=tenant_id,
        scan_id="scan-lab-e2e",
        asset_id="asset-lab-e2e",
        signals=[
            ToolRunSignal(
                tool_id="nuclei",
                tool_executed=True,
                execution_evidence_id="evidence-lab-nuclei",
                finding_id="finding-lab-1",
            )
        ],
        scan_options=options,
    )
    trace.coverage_status = (
        coverage_rows[0]["status"] if coverage_rows else "covered_with_finding"
    )
    trace.finding_key = "b" * 64
    return trace
