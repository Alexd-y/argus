"""WIRE-004 — phase RAG collaborator: citations, tenant isolation, LAB vs production."""

from __future__ import annotations

from src.execution_mode.mode import ExecutionMode
from src.llm.schemas import LlmResponseStatus
from src.orchestration.ai_prompts import _get_phase_prompt, _phase_rag_context
from src.orchestration.rag_phase_context import (
    RAG_QUERY_PLANNER_PROMPT_ID,
    build_phase_rag_pack,
    collections_for_phase,
    configure_phase_rag_retriever,
    format_rag_pack_for_prompt,
)
from src.rag import CollectionName, RagIngestionPipeline, RagRetriever
from src.rag.hybrid_search import InMemoryRagStore

_TENANT_A = "tenant-a"
_TENANT_B = "tenant-b"
_ENGAGEMENT = "eng-wire004"
_QUERY = "SQL injection login vulnerability CVE-2024-1234"


def _ingest(
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
        uri=f"memory://{title}",
        title=title,
        content=content,
        mode=mode,
    )
    retriever.store.add_ingestion(result.chunks, result.embeddings)


def _seeded_retriever() -> RagRetriever:
    retriever = RagRetriever(store=InMemoryRagStore())
    pipeline = RagIngestionPipeline(chunk_size=400)
    _ingest(
        pipeline,
        retriever,
        tenant_id=_TENANT_A,
        engagement_id=_ENGAGEMENT,
        collection=CollectionName.CODEBASE,
        title="tenant-a-login",
        content="SQL injection vulnerability in login handler CVE-2024-1234 for tenant A.",
    )
    return retriever


def test_planner_tm_va_pack_has_citation_ids_when_chunks_exist() -> None:
    retriever = _seeded_retriever()
    for phase in ("planner", "threat_modeling", "vuln_analysis"):
        pack = build_phase_rag_pack(
            phase,
            _TENANT_A,
            _ENGAGEMENT,
            ExecutionMode.PRODUCTION,
            _QUERY,
            retriever=retriever,
        )
        assert pack.chunks
        assert pack.citations
        assert all(citation.id for citation in pack.citations)
        section = format_rag_pack_for_prompt(pack)
        assert pack.citations[0].id in section
        assert f"[cite:{pack.citations[0].chunk_hash}]" in section
        assert pack.metadata["query_planner_prompt_id"] == RAG_QUERY_PLANNER_PROMPT_ID

        prompt_phase = "recon" if phase == "planner" else phase
        _, user = _get_phase_prompt(
            prompt_phase,
            target="https://app.example",
            options={},
            tool_results="",
            assets=["app.example"],
            nvd_data="",
            recon_context="",
            threat_model={},
            active_scan_context="",
            rag_context=section,
        )
        assert pack.citations[0].id in user


def test_cross_tenant_query_returns_zero_chunks() -> None:
    retriever = RagRetriever(store=InMemoryRagStore())
    pipeline = RagIngestionPipeline(chunk_size=400)
    _ingest(
        pipeline,
        retriever,
        tenant_id=_TENANT_B,
        engagement_id=_ENGAGEMENT,
        collection=CollectionName.CODEBASE,
        title="tenant-b-secret",
        content="Confirmed RCE exploit chain with artifact stdout evidence for tenant B.",
    )

    pack = build_phase_rag_pack(
        "vuln_analysis",
        _TENANT_A,
        _ENGAGEMENT,
        ExecutionMode.PRODUCTION,
        "RCE exploit stdout artifact",
        retriever=retriever,
    )
    assert pack.chunks == ()
    assert pack.citations == ()
    assert pack.metadata["status"] == LlmResponseStatus.NEEDS_EVIDENCE.value


def test_lab_pack_can_include_lab_research_production_cannot() -> None:
    retriever = RagRetriever(store=InMemoryRagStore())
    pipeline = RagIngestionPipeline(chunk_size=400)
    _ingest(
        pipeline,
        retriever,
        tenant_id=_TENANT_A,
        engagement_id=_ENGAGEMENT,
        collection=CollectionName.LAB_RESEARCH,
        title="lab-payload",
        content="Custom raw payload artifact for lab unrestricted malware reverse PoC.",
        mode=ExecutionMode.LAB_UNRESTRICTED,
    )

    assert CollectionName.LAB_RESEARCH not in collections_for_phase(
        "planner", ExecutionMode.PRODUCTION
    )
    assert CollectionName.LAB_RESEARCH in collections_for_phase(
        "planner", ExecutionMode.LAB_UNRESTRICTED
    )
    prod_cols = collections_for_phase("planner", ExecutionMode.PRODUCTION)
    assert CollectionName.ARGUS_PRODUCT in prod_cols
    assert CollectionName.EPISODIC_VALIDATED in prod_cols
    assert CollectionName.CAPABILITY_GRAPH in prod_cols

    prod_pack = build_phase_rag_pack(
        "planner",
        _TENANT_A,
        _ENGAGEMENT,
        ExecutionMode.PRODUCTION,
        "raw payload malware PoC",
        retriever=retriever,
    )
    assert prod_pack.chunks == ()
    assert all(chunk.collection is not CollectionName.LAB_RESEARCH for chunk in prod_pack.chunks)

    lab_pack = build_phase_rag_pack(
        "planner",
        _TENANT_A,
        _ENGAGEMENT,
        ExecutionMode.LAB_UNRESTRICTED,
        "raw payload malware PoC",
        retriever=retriever,
    )
    assert lab_pack.chunks
    assert lab_pack.citations
    assert lab_pack.chunks[0].collection is CollectionName.LAB_RESEARCH
    assert lab_pack.citations[0].id in format_rag_pack_for_prompt(lab_pack)


def test_fail_open_when_rag_down_does_not_invent_cve() -> None:
    class _DownRetriever(RagRetriever):
        def retrieve(self, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
            raise RuntimeError("rag unavailable")

    pack = build_phase_rag_pack(
        "threat_modeling",
        _TENANT_A,
        _ENGAGEMENT,
        ExecutionMode.PRODUCTION,
        "Invent CVE-2099-0001 for missing evidence",
        retriever=_DownRetriever(),
    )
    assert pack.chunks == ()
    assert pack.citations == ()
    assert pack.metadata["status"] == LlmResponseStatus.NEEDS_EVIDENCE.value
    assert pack.metadata["fail_open_reason"] == "rag_unavailable"
    section = format_rag_pack_for_prompt(pack)
    assert "Do not invent CVE" in section
    assert "CVE-2099-0001" not in section


def test_ai_prompts_helper_embeds_citation_ids_for_tm_va_planner() -> None:
    retriever = _seeded_retriever()
    configure_phase_rag_retriever(retriever)
    try:
        options = {
            "tenant_id": _TENANT_A,
            "engagement_id": _ENGAGEMENT,
            "execution_mode": "production",
        }
        for phase in ("planner", "threat_modeling", "vuln_analysis"):
            section = _phase_rag_context(phase, _QUERY, options)
            assert "=== RAG EVIDENCE PACK ===" in section
            assert "[cite:" in section
            assert "id=" in section
            assert "No retrieved evidence." not in section
    finally:
        configure_phase_rag_retriever(None)
