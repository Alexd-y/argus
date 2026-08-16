"""RAG retrieval — evidence packs with citations."""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from typing import Any

from src.core.unified_ai_metrics import record_rag_query, record_rag_retrieval_latency
from src.db.models import gen_uuid
from src.execution_mode.mode import ExecutionMode, parse_execution_mode
from src.rag.citations import CitationGate
from src.rag.hybrid_search import HybridSearchEngine, InMemoryRagStore
from src.rag.schemas import (
    LAB_ONLY_COLLECTIONS,
    CollectionName,
    RagChunk,
    RagCitation,
    RagEvidencePack,
    RagQuery,
)

_QUICK_DEFAULT_TOP_K = 5


class RagRetriever:
    """Tenant-scoped retriever producing cited evidence packs."""

    def __init__(
        self,
        store: InMemoryRagStore | None = None,
        *,
        citation_gate: CitationGate | None = None,
    ) -> None:
        self._store = store or InMemoryRagStore()
        self._search = HybridSearchEngine(self._store)
        self._citation_gate = citation_gate or CitationGate()

    @property
    def store(self) -> InMemoryRagStore:
        return self._store

    def retrieve(
        self,
        query: RagQuery,
        tenant_id: str,
        engagement_id: str | None,
        mode: ExecutionMode | str,
        collections: Sequence[CollectionName] | None = None,
        *,
        gate_text: str | None = None,
        profile: str | None = None,
        metadata_prefilter: Mapping[str, Any] | None = None,
        vector_enabled: bool = True,
    ) -> RagEvidencePack:
        resolved_mode = parse_execution_mode(mode)
        mode_value = resolved_mode.value
        requested_collections = collections or query.collections or tuple(CollectionName)
        is_quick = resolved_mode is ExecutionMode.QUICK or profile == "quick"
        if is_quick:
            requested_collections = tuple(
                item for item in requested_collections if item not in LAB_ONLY_COLLECTIONS
            )
            max_results = min(query.max_results, _QUICK_DEFAULT_TOP_K)
        else:
            max_results = query.max_results

        started = time.perf_counter()
        used_fts_fallback = not vector_enabled
        if is_quick and not requested_collections:
            hits = []
        else:
            try:
                hits = self._search.search(
                    query.text,
                    tenant_id=tenant_id,
                    engagement_id=engagement_id,
                    mode=resolved_mode,
                    collections=requested_collections,
                    max_results=max_results,
                    metadata_prefilter=metadata_prefilter,
                    vector_enabled=vector_enabled,
                )
            except Exception:
                if is_quick and vector_enabled:
                    try:
                        hits = self._search.search(
                            query.text,
                            tenant_id=tenant_id,
                            engagement_id=engagement_id,
                            mode=resolved_mode,
                            collections=requested_collections,
                            max_results=max_results,
                            metadata_prefilter=metadata_prefilter,
                            vector_enabled=False,
                        )
                        used_fts_fallback = True
                    except Exception:  # noqa: BLE001 — Quick continues without RAG hits
                        hits = []
                        used_fts_fallback = True
                elif is_quick:
                    hits = []
                else:
                    raise
        latency_ms = (time.perf_counter() - started) * 1000.0
        trace_id = gen_uuid()

        chunks: list[RagChunk] = []
        citations: list[RagCitation] = []

        for hit in hits:
            stored = self._store.get(hit.chunk_id)
            if stored is None:
                continue
            chunk = stored.chunk
            if is_quick and chunk.collection in LAB_ONLY_COLLECTIONS:
                continue
            chunks.append(chunk)
            snippet = chunk.content[:512]
            citations.append(
                RagCitation(
                    id=gen_uuid(),
                    chunk_id=chunk.id,
                    chunk_hash=chunk.content_hash,
                    document_id=chunk.document_id,
                    source_id=chunk.source_id,
                    collection=chunk.collection,
                    rank=hit.rank,
                    score=hit.score,
                    snippet=snippet,
                    metadata={
                        "fts_rank": hit.fts_rank,
                        "vector_rank": hit.vector_rank,
                        "trace_id": trace_id,
                    },
                )
            )

        inferred_claims: tuple[str, ...] = ()
        metadata: dict[str, Any] = {
            "latency_ms": latency_ms,
            "hit_count": len(hits),
            "collections": [c.value for c in requested_collections],
        }
        if is_quick:
            metadata["profile"] = "quick"
            metadata["lab_research_denied"] = True
            if used_fts_fallback:
                metadata["fts_fallback"] = True

        if gate_text:
            gated = self._citation_gate.gate(gate_text, citations)
            inferred_claims = tuple(gated.inferred_claims)
            metadata["gated_text"] = gated.text

        record_rag_query(mode=mode_value)
        record_rag_retrieval_latency(mode=mode_value, latency_ms=latency_ms)

        return RagEvidencePack(
            query=query,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            mode=mode_value,
            citations=tuple(citations),
            chunks=tuple(chunks),
            inferred_claims=inferred_claims,
            trace_id=trace_id,
            metadata=metadata,
        )
