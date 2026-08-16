"""Quick RAG retrieval profile (QUICK-006).

Small top_k, metadata prefilter before vector search, fingerprint cache,
PostgreSQL-style FTS fallback when vectors fail, and a hard deny of
``LAB_RESEARCH``. Cross-tenant chunks never leave HybridSearchEngine.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from src.execution_mode.mode import ExecutionMode
from src.quick.metrics import record_rag_latency
from src.rag.hybrid_search import HybridSearchEngine, InMemoryRagStore
from src.rag.retrieval import RagRetriever
from src.rag.schemas import (
    LAB_ONLY_COLLECTIONS,
    CollectionName,
    RagEvidencePack,
    RagQuery,
)

logger = logging.getLogger(__name__)

QUICK_RAG_PROFILE_ID: Final[str] = "quick"

DEFAULT_TOP_K: Final[int] = 5
PLANNING_TOP_K: Final[int] = 4
TRIAGE_TOP_K: Final[int] = 6
REPORTING_TOP_K: Final[int] = 8
CACHE_TTL_SECONDS: Final[float] = 300.0
_CACHE_MAX_ENTRIES: Final[int] = 256

QUICK_COLLECTIONS: Final[tuple[CollectionName, ...]] = (
    CollectionName.ARGUS_PRODUCT,
    CollectionName.SECURITY_STANDARDS,
    CollectionName.TOOL_CATALOG,
    CollectionName.DETECTION_TEMPLATES,
    CollectionName.CAPABILITY_GRAPH,
    CollectionName.PUBLIC_INTEL,
    CollectionName.FINDING_HISTORY,
    CollectionName.SCAN_EVIDENCE,
)

_PURPOSE_TOP_K: Final[dict[str, int]] = {
    "planning": PLANNING_TOP_K,
    "planner": PLANNING_TOP_K,
    "fingerprint": DEFAULT_TOP_K,
    "triage": TRIAGE_TOP_K,
    "critic": TRIAGE_TOP_K,
    "reporting": REPORTING_TOP_K,
    "reporter": REPORTING_TOP_K,
}


def deny_lab_research(
    collections: Sequence[CollectionName] | None,
) -> tuple[CollectionName, ...]:
    """Drop LAB_RESEARCH from any Quick collection list."""
    source = tuple(collections) if collections else QUICK_COLLECTIONS
    return tuple(item for item in source if item not in LAB_ONLY_COLLECTIONS)


def _cache_key(
    *,
    tenant_id: str,
    query_text: str,
    collections: Sequence[CollectionName],
    top_k: int,
    metadata_prefilter: Mapping[str, Any] | None,
) -> str:
    payload = {
        "tenant_id": tenant_id,
        "query": " ".join(query_text.lower().split()),
        "collections": [item.value for item in collections],
        "top_k": top_k,
        "prefilter": dict(metadata_prefilter or {}),
    }
    blob = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class _CacheEntry:
    pack: RagEvidencePack
    expires_at: float


@dataclass
class QuickRagProfile:
    """Bounded retrieval profile used by Quick planner / triage / reporter."""

    top_k: int = DEFAULT_TOP_K
    collections: tuple[CollectionName, ...] = QUICK_COLLECTIONS
    cache_ttl_seconds: float = CACHE_TTL_SECONDS
    retriever: RagRetriever | None = None
    _cache: dict[str, _CacheEntry] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.collections = deny_lab_research(self.collections)
        self.top_k = max(1, min(int(self.top_k), 12))

    def top_k_for(self, purpose: str) -> int:
        return _PURPOSE_TOP_K.get((purpose or "").strip().lower(), self.top_k)

    def retrieve(
        self,
        query_text: str,
        *,
        tenant_id: str,
        engagement_id: str | None,
        purpose: str = "planning",
        metadata_prefilter: Mapping[str, Any] | None = None,
        collections: Sequence[CollectionName] | None = None,
    ) -> RagEvidencePack:
        """Tenant-scoped retrieve. Vector failure → FTS. Total RAG failure → empty degraded pack."""
        allowed = deny_lab_research(collections or self.collections)
        top_k = self.top_k_for(purpose)
        normalized = " ".join((query_text or "").split()) or f"quick {purpose} evidence"
        key = _cache_key(
            tenant_id=tenant_id,
            query_text=normalized,
            collections=allowed,
            top_k=top_k,
            metadata_prefilter=metadata_prefilter,
        )
        cached = self._cache.get(key)
        now = time.monotonic()
        if cached is not None and cached.expires_at > now:
            record_rag_latency(0.0)
            return cached.pack

        started = time.monotonic()
        query = RagQuery(text=normalized[:8192], collections=allowed, max_results=top_k)
        pack = self._retrieve_with_fallback(
            query,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            metadata_prefilter=metadata_prefilter,
        )
        record_rag_latency(time.monotonic() - started)
        self._remember(key, pack)
        return pack

    def _retrieve_with_fallback(
        self,
        query: RagQuery,
        *,
        tenant_id: str,
        engagement_id: str | None,
        metadata_prefilter: Mapping[str, Any] | None,
    ) -> RagEvidencePack:
        active = self.retriever or RagRetriever()
        try:
            pack = active.retrieve(
                query,
                tenant_id,
                engagement_id,
                ExecutionMode.QUICK,
                query.collections,
                profile=QUICK_RAG_PROFILE_ID,
                metadata_prefilter=metadata_prefilter,
                vector_enabled=True,
            )
            if CollectionName.LAB_RESEARCH in {chunk.collection for chunk in pack.chunks}:
                logger.warning(
                    "quick_rag_lab_research_stripped",
                    extra={"event": "quick_rag_lab_research_stripped", "tenant_id": tenant_id},
                )
                pack = _strip_lab_research(pack)
            return pack
        except Exception:  # noqa: BLE001 — vector failure falls back to FTS
            logger.warning(
                "quick_rag_vector_failed_fts_fallback",
                extra={"event": "quick_rag_vector_failed_fts_fallback", "tenant_id": tenant_id},
            )
        try:
            pack = active.retrieve(
                query,
                tenant_id,
                engagement_id,
                ExecutionMode.QUICK,
                query.collections,
                profile=QUICK_RAG_PROFILE_ID,
                metadata_prefilter=metadata_prefilter,
                vector_enabled=False,
            )
            metadata = dict(pack.metadata)
            metadata["fts_fallback"] = True
            metadata["degraded"] = True
            return pack.model_copy(update={"metadata": metadata})
        except Exception:  # noqa: BLE001 — RAG down continues the scan degraded
            logger.warning(
                "quick_rag_unavailable_continue_degraded",
                extra={"event": "quick_rag_unavailable_continue_degraded", "tenant_id": tenant_id},
            )
            return RagEvidencePack(
                query=query,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                mode=ExecutionMode.QUICK.value,
                citations=(),
                chunks=(),
                inferred_claims=(),
                metadata={
                    "degraded": True,
                    "rag_unavailable": True,
                    "collections": [item.value for item in query.collections],
                },
            )

    def _remember(self, key: str, pack: RagEvidencePack) -> None:
        if len(self._cache) >= _CACHE_MAX_ENTRIES:
            oldest = next(iter(self._cache))
            self._cache.pop(oldest, None)
        self._cache[key] = _CacheEntry(
            pack=pack,
            expires_at=time.monotonic() + self.cache_ttl_seconds,
        )


def _strip_lab_research(pack: RagEvidencePack) -> RagEvidencePack:
    kept_chunks = tuple(
        chunk for chunk in pack.chunks if chunk.collection not in LAB_ONLY_COLLECTIONS
    )
    kept_ids = {chunk.id for chunk in kept_chunks}
    kept_citations = tuple(item for item in pack.citations if item.chunk_id in kept_ids)
    metadata = dict(pack.metadata)
    metadata["lab_research_denied"] = True
    return pack.model_copy(
        update={"chunks": kept_chunks, "citations": kept_citations, "metadata": metadata}
    )


def format_quick_rag_for_prompt(pack: RagEvidencePack) -> str:
    """Bounded citation pack for Quick prompts. Empty pack is an explicit degrade."""
    if pack.metadata.get("rag_unavailable") or not pack.citations:
        return json.dumps(
            {"citations": [], "degraded": True, "reason": "rag_unavailable_or_empty"},
            ensure_ascii=False,
        )
    items = []
    for citation in pack.citations[:DEFAULT_TOP_K]:
        items.append(
            {
                "citation_id": citation.id,
                "chunk_hash": citation.chunk_hash,
                "collection": citation.collection.value,
                "snippet": citation.snippet[:512],
            }
        )
    return json.dumps({"citations": items, "degraded": False}, ensure_ascii=False)


def default_quick_rag_store() -> InMemoryRagStore:
    return InMemoryRagStore()


def default_quick_search_engine(store: InMemoryRagStore | None = None) -> HybridSearchEngine:
    return HybridSearchEngine(store or default_quick_rag_store())
