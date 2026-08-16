"""QUICK-006 — Quick execution mode never reads LAB_RESEARCH."""

from __future__ import annotations

from src.execution_mode.mode import ExecutionMode
from src.orchestration.rag_phase_context import collections_for_phase
from src.quick.rag_profile import QUICK_COLLECTIONS, QuickRagProfile, deny_lab_research
from src.rag import CollectionName, RagIngestionPipeline, RagQuery, RagRetriever
from src.rag.hybrid_search import HybridSearchEngine, resolve_allowed_collections
from src.rag.schemas import LAB_ONLY_COLLECTIONS

_TENANT = "tenant-quick"
_ENGAGEMENT = "eng-quick"
_QUERY = "raw payload malware reverse PoC artifact"


def _ingest(
    pipeline: RagIngestionPipeline,
    retriever: RagRetriever,
    *,
    collection: CollectionName,
    title: str,
    content: str,
    mode: ExecutionMode,
) -> None:
    result = pipeline.ingest(
        tenant_id=_TENANT,
        engagement_id=_ENGAGEMENT,
        collection=collection,
        uri=f"memory://{title}",
        title=title,
        content=content,
        mode=mode,
    )
    retriever.store.add_ingestion(result.chunks, result.embeddings)


def _seeded_retriever() -> RagRetriever:
    retriever = RagRetriever()
    pipeline = RagIngestionPipeline(chunk_size=400)
    _ingest(
        pipeline,
        retriever,
        collection=CollectionName.PUBLIC_INTEL,
        title="public-cve",
        content="Public CVE-2024-1234 nginx fingerprint for authorized assessment.",
        mode=ExecutionMode.PRODUCTION,
    )
    _ingest(
        pipeline,
        retriever,
        collection=CollectionName.LAB_RESEARCH,
        title="lab-payload",
        content="Custom raw payload artifact for lab unrestricted malware reverse PoC.",
        mode=ExecutionMode.LAB_UNRESTRICTED,
    )
    return retriever


def test_quick_mode_retrieve_excludes_lab_research_chunks() -> None:
    retriever = _seeded_retriever()
    pack = retriever.retrieve(
        RagQuery(text=_QUERY, max_results=10),
        tenant_id=_TENANT,
        engagement_id=_ENGAGEMENT,
        mode=ExecutionMode.QUICK,
        collections=[CollectionName.PUBLIC_INTEL, CollectionName.LAB_RESEARCH],
    )
    assert all(chunk.collection is not CollectionName.LAB_RESEARCH for chunk in pack.chunks)
    assert CollectionName.LAB_RESEARCH not in {
        CollectionName(item) for item in pack.metadata.get("collections", [])
    }
    assert pack.metadata.get("lab_research_denied") is True
    assert pack.mode == ExecutionMode.QUICK.value


def test_quick_profile_flag_denies_lab_even_in_production_mode() -> None:
    retriever = _seeded_retriever()
    pack = retriever.retrieve(
        RagQuery(text=_QUERY, max_results=10),
        tenant_id=_TENANT,
        engagement_id=_ENGAGEMENT,
        mode=ExecutionMode.PRODUCTION,
        collections=[CollectionName.LAB_RESEARCH],
        profile="quick",
    )
    assert pack.chunks == ()
    assert pack.citations == ()


def test_lab_mode_still_can_read_lab_research() -> None:
    retriever = _seeded_retriever()
    pack = retriever.retrieve(
        RagQuery(text=_QUERY, max_results=10),
        tenant_id=_TENANT,
        engagement_id=_ENGAGEMENT,
        mode=ExecutionMode.LAB_UNRESTRICTED,
        collections=[CollectionName.LAB_RESEARCH],
    )
    assert pack.chunks
    assert pack.chunks[0].collection is CollectionName.LAB_RESEARCH


def test_hybrid_search_quick_mode_drops_lab_collection() -> None:
    allowed = resolve_allowed_collections(
        ExecutionMode.QUICK,
        (CollectionName.PUBLIC_INTEL, CollectionName.LAB_RESEARCH),
    )
    assert CollectionName.LAB_RESEARCH not in allowed
    assert CollectionName.PUBLIC_INTEL in allowed

    retriever = _seeded_retriever()
    engine = HybridSearchEngine(retriever.store)
    hits = engine.search(
        _QUERY,
        tenant_id=_TENANT,
        engagement_id=_ENGAGEMENT,
        mode=ExecutionMode.QUICK,
        collections=[CollectionName.LAB_RESEARCH],
        max_results=10,
    )
    assert hits == []


def test_quick_phase_collections_never_include_lab_research() -> None:
    for phase in (
        "quick_planner",
        "quick_fingerprint",
        "quick_triage",
        "quick_critic",
        "quick_reporter",
    ):
        names = collections_for_phase(phase, ExecutionMode.QUICK)
        assert CollectionName.LAB_RESEARCH not in names
        assert not (set(names) & LAB_ONLY_COLLECTIONS)


def test_quick_rag_profile_retrieve_skips_lab_store() -> None:
    retriever = _seeded_retriever()
    profile = QuickRagProfile(retriever=retriever)
    pack = profile.retrieve(
        _QUERY,
        tenant_id=_TENANT,
        engagement_id=_ENGAGEMENT,
        purpose="planning",
        collections=(*QUICK_COLLECTIONS, CollectionName.LAB_RESEARCH),
    )
    assert CollectionName.LAB_RESEARCH not in deny_lab_research(pack.query.collections)
    assert all(chunk.collection is not CollectionName.LAB_RESEARCH for chunk in pack.chunks)
