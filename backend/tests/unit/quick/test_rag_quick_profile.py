"""QUICK-006 — Quick RAG profile: small top_k, cache, FTS fallback, no LAB_RESEARCH."""

from __future__ import annotations

import json
from typing import Any

from src.execution_mode.mode import ExecutionMode
from src.quick.rag_profile import (
    DEFAULT_TOP_K,
    PLANNING_TOP_K,
    QUICK_COLLECTIONS,
    QUICK_RAG_PROFILE_ID,
    REPORTING_TOP_K,
    TRIAGE_TOP_K,
    QuickRagProfile,
    deny_lab_research,
    format_quick_rag_for_prompt,
)
from src.rag.schemas import (
    LAB_ONLY_COLLECTIONS,
    CollectionName,
    RagChunk,
    RagCitation,
    RagEvidencePack,
    RagQuery,
)

_TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_ENGAGEMENT = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
_CHUNK_ID = "11111111-2222-3333-4444-555555555555"
_DOC_ID = "22222222-3333-4444-5555-666666666666"
_SRC_ID = "33333333-4444-5555-6666-777777777777"
_CITE_ID = "44444444-5555-6666-7777-888888888888"
_HASH = "a" * 64


def _chunk(*, collection: CollectionName = CollectionName.PUBLIC_INTEL) -> RagChunk:
    return RagChunk(
        id=_CHUNK_ID,
        tenant_id=_TENANT,
        engagement_id=_ENGAGEMENT,
        document_id=_DOC_ID,
        source_id=_SRC_ID,
        collection=collection,
        chunk_index=0,
        content="Nuclei template CVE-2024-1234 matched nginx 1.25.",
        content_hash=_HASH,
    )


def _citation(*, collection: CollectionName = CollectionName.PUBLIC_INTEL) -> RagCitation:
    return RagCitation(
        id=_CITE_ID,
        chunk_id=_CHUNK_ID,
        chunk_hash=_HASH,
        document_id=_DOC_ID,
        source_id=_SRC_ID,
        collection=collection,
        rank=1,
        score=0.9,
        snippet="Nuclei template CVE-2024-1234 matched nginx 1.25.",
    )


def _pack(
    *,
    chunks: tuple[RagChunk, ...] = (),
    citations: tuple[RagCitation, ...] = (),
    metadata: dict[str, Any] | None = None,
    collections: tuple[CollectionName, ...] = (CollectionName.PUBLIC_INTEL,),
) -> RagEvidencePack:
    return RagEvidencePack(
        query=RagQuery(text="nginx cve nuclei", collections=collections, max_results=5),
        tenant_id=_TENANT,
        engagement_id=_ENGAGEMENT,
        mode=ExecutionMode.QUICK.value,
        chunks=chunks,
        citations=citations,
        metadata=metadata or {},
    )


class _RecordingRetriever:
    def __init__(self, packs: list[RagEvidencePack] | None = None, *, error: Exception | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self._packs = list(packs or [])
        self._error = error

    def retrieve(self, query: RagQuery, *args: Any, **kwargs: Any) -> RagEvidencePack:
        self.calls.append({"query": query, "args": args, "kwargs": kwargs})
        if self._error is not None:
            raise self._error
        if self._packs:
            return self._packs.pop(0)
        return _pack()


def test_deny_lab_research_strips_lab_collection() -> None:
    mixed = (*QUICK_COLLECTIONS, CollectionName.LAB_RESEARCH)
    denied = deny_lab_research(mixed)
    assert CollectionName.LAB_RESEARCH not in denied
    assert CollectionName.LAB_RESEARCH in LAB_ONLY_COLLECTIONS
    assert CollectionName.PUBLIC_INTEL in denied


def test_quick_profile_post_init_drops_lab_research() -> None:
    profile = QuickRagProfile(
        collections=(*QUICK_COLLECTIONS, CollectionName.LAB_RESEARCH),
        retriever=_RecordingRetriever(),  # type: ignore[arg-type]
    )
    assert CollectionName.LAB_RESEARCH not in profile.collections
    assert profile.top_k == DEFAULT_TOP_K


def test_top_k_for_purpose_is_bounded() -> None:
    profile = QuickRagProfile()
    assert profile.top_k_for("planning") == PLANNING_TOP_K
    assert profile.top_k_for("triage") == TRIAGE_TOP_K
    assert profile.top_k_for("reporting") == REPORTING_TOP_K
    assert profile.top_k_for("unknown") == DEFAULT_TOP_K
    wide = QuickRagProfile(top_k=99)
    assert wide.top_k == 12


def test_retrieve_never_requests_lab_research() -> None:
    retriever = _RecordingRetriever(packs=[_pack(chunks=(_chunk(),), citations=(_citation(),))])
    profile = QuickRagProfile(retriever=retriever)  # type: ignore[arg-type]
    pack = profile.retrieve(
        "nginx cve",
        tenant_id=_TENANT,
        engagement_id=_ENGAGEMENT,
        purpose="planning",
        collections=(CollectionName.PUBLIC_INTEL, CollectionName.LAB_RESEARCH),
    )
    query = retriever.calls[0]["query"]
    assert CollectionName.LAB_RESEARCH not in query.collections
    assert query.max_results == PLANNING_TOP_K
    assert retriever.calls[0]["kwargs"]["profile"] == QUICK_RAG_PROFILE_ID
    assert pack.chunks


def test_retrieve_strips_lab_chunks_if_retriever_leaks_them() -> None:
    leaked = _pack(
        chunks=(_chunk(collection=CollectionName.LAB_RESEARCH),),
        citations=(_citation(collection=CollectionName.LAB_RESEARCH),),
        collections=(CollectionName.LAB_RESEARCH,),
    )
    retriever = _RecordingRetriever(packs=[leaked])
    profile = QuickRagProfile(retriever=retriever)  # type: ignore[arg-type]
    pack = profile.retrieve(
        "raw payload",
        tenant_id=_TENANT,
        engagement_id=_ENGAGEMENT,
        purpose="triage",
    )
    assert pack.chunks == ()
    assert pack.citations == ()
    assert pack.metadata.get("lab_research_denied") is True


def test_vector_failure_falls_back_to_fts() -> None:
    class _VectorThenFts:
        def __init__(self) -> None:
            self.calls: list[bool] = []

        def retrieve(self, query: RagQuery, *args: Any, **kwargs: Any) -> RagEvidencePack:
            vector_enabled = bool(kwargs.get("vector_enabled", True))
            self.calls.append(vector_enabled)
            if vector_enabled:
                raise RuntimeError("vector index down")
            return _pack(
                chunks=(_chunk(),),
                citations=(_citation(),),
                metadata={"degraded": False},
            )

    retriever = _VectorThenFts()
    profile = QuickRagProfile(retriever=retriever)  # type: ignore[arg-type]
    pack = profile.retrieve("nginx", tenant_id=_TENANT, engagement_id=_ENGAGEMENT)
    assert retriever.calls == [True, False]
    assert pack.metadata.get("fts_fallback") is True
    assert pack.metadata.get("degraded") is True
    assert pack.chunks


def test_total_rag_failure_returns_degraded_empty_pack() -> None:
    retriever = _RecordingRetriever(error=RuntimeError("rag down"))
    profile = QuickRagProfile(retriever=retriever)  # type: ignore[arg-type]
    pack = profile.retrieve("nginx", tenant_id=_TENANT, engagement_id=_ENGAGEMENT)
    assert pack.chunks == ()
    assert pack.citations == ()
    assert pack.metadata.get("rag_unavailable") is True
    assert pack.metadata.get("degraded") is True
    assert pack.mode == ExecutionMode.QUICK.value


def test_fingerprint_cache_avoids_second_retrieve() -> None:
    retriever = _RecordingRetriever(packs=[_pack(chunks=(_chunk(),), citations=(_citation(),))])
    profile = QuickRagProfile(retriever=retriever, cache_ttl_seconds=60.0)  # type: ignore[arg-type]
    first = profile.retrieve("  Nginx   CVE  ", tenant_id=_TENANT, engagement_id=_ENGAGEMENT)
    second = profile.retrieve("nginx cve", tenant_id=_TENANT, engagement_id=_ENGAGEMENT)
    assert len(retriever.calls) == 1
    assert first is second


def test_format_quick_rag_for_prompt_degrades_when_empty() -> None:
    empty = format_quick_rag_for_prompt(_pack(metadata={"rag_unavailable": True}))
    payload = json.loads(empty)
    assert payload["degraded"] is True
    assert payload["citations"] == []

    cited = format_quick_rag_for_prompt(_pack(chunks=(_chunk(),), citations=(_citation(),)))
    cited_payload = json.loads(cited)
    assert cited_payload["degraded"] is False
    assert cited_payload["citations"][0]["citation_id"] == _CITE_ID
    assert cited_payload["citations"][0]["collection"] == CollectionName.PUBLIC_INTEL.value
