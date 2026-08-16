"""CONT-007 — depersonalized production E2E path (mocked, no Docker/LLM)."""

from __future__ import annotations

from tests.integration.unified_ai.conftest import run_production_path


def test_production_path_policy_gate_blocks_high_risk_without_approval(
    rag_pipeline,
    rag_retriever,
    mock_sandbox,
    mock_llm,
) -> None:
    trace = run_production_path(
        rag_pipeline=rag_pipeline,
        rag_retriever=rag_retriever,
        mock_sandbox=mock_sandbox,
        mock_llm=mock_llm,
    )

    assert trace.mode == "production"
    assert trace.rag_hits >= 1
    assert trace.approval_required is True
    assert trace.policy.get("requires_approval") is True  # type: ignore[union-attr]
    assert trace.policy.get("allowed") is False  # type: ignore[union-attr]
    assert trace.sandbox_calls == []
    assert trace.candidates


def test_production_path_rag_is_tenant_scoped(
    rag_pipeline,
    rag_retriever,
    mock_sandbox,
    mock_llm,
) -> None:
    from src.execution_mode.mode import ExecutionMode
    from src.rag import RagQuery
    from src.rag.schemas import CollectionName

    from tests.integration.unified_ai.conftest import seed_tenant_rag

    seed_tenant_rag(
        rag_pipeline,
        rag_retriever,
        tenant_id="tenant-e2e-beta",
        engagement_id="eng-e2e-001",
        collection=CollectionName.SCAN_EVIDENCE,
        title="other-tenant",
        content="Secret beta tenant SQL injection evidence.",
    )

    trace = run_production_path(
        rag_pipeline=rag_pipeline,
        rag_retriever=rag_retriever,
        mock_sandbox=mock_sandbox,
        mock_llm=mock_llm,
    )

    pack = rag_retriever.retrieve(
        RagQuery(text="SQL injection login", max_results=5),
        tenant_id="tenant-e2e-alpha",
        engagement_id="eng-e2e-001",
        mode=ExecutionMode.PRODUCTION,
        collections=[CollectionName.SCAN_EVIDENCE],
    )
    assert all(c.tenant_id == "tenant-e2e-alpha" for c in pack.chunks)
    assert trace.approval_required is True
