"""Unit tests for hybrid RAG retrieval and tenant isolation."""

from __future__ import annotations

import pytest
from src.execution_mode.mode import ExecutionMode
from src.rag import (
    CitationGate,
    CollectionName,
    RagIngestionPipeline,
    RagQuery,
    RagRetriever,
)
from src.rag.hybrid_search import HybridSearchEngine


def _ingest(
    pipeline: RagIngestionPipeline,
    *,
    tenant_id: str,
    engagement_id: str,
    collection: CollectionName,
    title: str,
    content: str,
    mode: ExecutionMode = ExecutionMode.PRODUCTION,
) -> tuple[list, list]:
    result = pipeline.ingest(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        collection=collection,
        uri=f"memory://{title}",
        title=title,
        content=content,
        mode=mode,
    )
    return result.chunks, result.embeddings


@pytest.fixture
def pipeline() -> RagIngestionPipeline:
    return RagIngestionPipeline(chunk_size=400)


@pytest.fixture
def retriever() -> RagRetriever:
    return RagRetriever()


def test_hybrid_retrieval_returns_tenant_scoped_only(pipeline, retriever):
    tenant_a = "tenant-a"
    tenant_b = "tenant-b"
    engagement = "eng-1"

    chunks_a, embeds_a = _ingest(
        pipeline,
        tenant_id=tenant_a,
        engagement_id=engagement,
        collection=CollectionName.CODEBASE,
        title="tenant-a-code",
        content="SQL injection vulnerability in login handler for tenant A.",
    )
    chunks_b, embeds_b = _ingest(
        pipeline,
        tenant_id=tenant_b,
        engagement_id=engagement,
        collection=CollectionName.CODEBASE,
        title="tenant-b-code",
        content="Cross-site scripting issue in tenant B dashboard widget.",
    )
    retriever.store.add_ingestion(chunks_a, embeds_a)
    retriever.store.add_ingestion(chunks_b, embeds_b)

    pack = retriever.retrieve(
        RagQuery(text="SQL injection login vulnerability", max_results=5),
        tenant_id=tenant_a,
        engagement_id=engagement,
        mode=ExecutionMode.PRODUCTION,
        collections=[CollectionName.CODEBASE],
    )

    assert pack.chunks
    assert all(chunk.tenant_id == tenant_a for chunk in pack.chunks)
    assert all("tenant A" in chunk.content or "SQL injection" in chunk.content for chunk in pack.chunks)
    assert not any(chunk.tenant_id == tenant_b for chunk in pack.chunks)


def test_cross_tenant_denial(pipeline, retriever):
    tenant_a = "tenant-a"
    tenant_b = "tenant-b"
    engagement = "eng-2"

    chunks_b, embeds_b = _ingest(
        pipeline,
        tenant_id=tenant_b,
        engagement_id=engagement,
        collection=CollectionName.FINDING_HISTORY,
        title="tenant-b-findings",
        content="Confirmed RCE exploit chain with artifact stdout evidence.",
    )
    retriever.store.add_ingestion(chunks_b, embeds_b)

    pack = retriever.retrieve(
        RagQuery(text="RCE exploit stdout artifact", max_results=5),
        tenant_id=tenant_a,
        engagement_id=engagement,
        mode=ExecutionMode.PRODUCTION,
        collections=[CollectionName.FINDING_HISTORY],
    )

    assert pack.chunks == ()
    assert pack.citations == ()
    search = HybridSearchEngine(retriever.store)
    assert search.cross_tenant_denied(
        "RCE exploit stdout artifact",
        tenant_id=tenant_a,
        other_tenant_id=tenant_b,
        engagement_id=engagement,
        mode=ExecutionMode.PRODUCTION,
        collections=[CollectionName.FINDING_HISTORY],
    )


def test_lab_can_query_lab_research_collection(pipeline, retriever):
    tenant = "tenant-lab"
    engagement = "eng-lab"

    chunks, embeds = _ingest(
        pipeline,
        tenant_id=tenant,
        engagement_id=engagement,
        collection=CollectionName.LAB_RESEARCH,
        title="lab-payload",
        content="Custom raw payload artifact for lab unrestricted malware reverse PoC.",
        mode=ExecutionMode.LAB_UNRESTRICTED,
    )
    retriever.store.add_ingestion(chunks, embeds)

    prod_pack = retriever.retrieve(
        RagQuery(text="raw payload malware PoC", max_results=5),
        tenant_id=tenant,
        engagement_id=engagement,
        mode=ExecutionMode.PRODUCTION,
        collections=[CollectionName.LAB_RESEARCH],
    )
    assert prod_pack.chunks == ()

    lab_pack = retriever.retrieve(
        RagQuery(text="raw payload malware PoC", max_results=5),
        tenant_id=tenant,
        engagement_id=engagement,
        mode=ExecutionMode.LAB_UNRESTRICTED,
        collections=[CollectionName.LAB_RESEARCH],
    )
    assert lab_pack.chunks
    assert lab_pack.chunks[0].collection is CollectionName.LAB_RESEARCH


def test_citations_resolve_to_chunk_hash(pipeline, retriever):
    tenant = "tenant-cite"
    engagement = "eng-cite"

    chunks, embeds = _ingest(
        pipeline,
        tenant_id=tenant,
        engagement_id=engagement,
        collection=CollectionName.SCAN_EVIDENCE,
        title="nuclei-output",
        content="Nuclei template CVE-2024-1234 matched with verified response evidence.",
    )
    retriever.store.add_ingestion(chunks, embeds)
    expected_hash = chunks[0].content_hash

    pack = retriever.retrieve(
        RagQuery(text="CVE-2024-1234 nuclei verified", max_results=3),
        tenant_id=tenant,
        engagement_id=engagement,
        mode=ExecutionMode.PRODUCTION,
        collections=[CollectionName.SCAN_EVIDENCE],
    )

    assert pack.citations
    gate = CitationGate()
    for citation in pack.citations:
        resolved = gate.resolve_citation_hash(citation.chunk_hash, pack.citations)
        assert resolved is not None
        assert resolved.chunk_hash == expected_hash
        assert resolved.chunk_id == chunks[0].id

    uncited = gate.gate(
        "CVE-2024-1234 is applicable without citation.",
        pack.citations,
    )
    assert uncited.inferred_claims
    assert "[INFERENCE]" in uncited.text
