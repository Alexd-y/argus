"""Hybrid FTS + vector retrieval with tenant-scoped reciprocal rank fusion."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from math import sqrt
from typing import Any

from src.core.unified_ai_metrics import record_rag_cross_tenant_denial
from src.execution_mode.mode import ExecutionMode, parse_execution_mode
from src.rag.ingestion import deterministic_embed
from src.rag.schemas import (
    GLOBAL_COLLECTIONS,
    LAB_ONLY_COLLECTIONS,
    CollectionName,
    RagChunk,
)

RRF_K: int = 60


@dataclass
class StoredChunk:
    """In-memory chunk record for unit tests and offline retrieval."""

    chunk: RagChunk
    embedding: list[float]
    fts_text: str


@dataclass
class SearchHit:
    """Single fused retrieval hit."""

    chunk_id: str
    score: float
    rank: int
    fts_rank: int | None = None
    vector_rank: int | None = None


class InMemoryRagStore:
    """Tenant-scoped in-memory chunk store for tests."""

    def __init__(self) -> None:
        self._chunks: dict[str, StoredChunk] = {}

    def clear(self) -> None:
        self._chunks.clear()

    def add(
        self,
        chunk: RagChunk,
        embedding: list[float],
        fts_text: str | None = None,
    ) -> None:
        text = fts_text or chunk.metadata.get("fts_text") or chunk.content
        self._chunks[chunk.id] = StoredChunk(
            chunk=chunk,
            embedding=list(embedding),
            fts_text=str(text),
        )

    def add_ingestion(
        self,
        chunks: Sequence[RagChunk],
        embeddings: Sequence[list[float]],
    ) -> None:
        for chunk, embedding in zip(chunks, embeddings, strict=True):
            self.add(chunk, embedding)

    def get(self, chunk_id: str) -> StoredChunk | None:
        return self._chunks.get(chunk_id)

    def all_chunks(self) -> list[StoredChunk]:
        return list(self._chunks.values())


def _cosine_similarity(left: list[float], right: list[float]) -> float:
    if not left or not right:
        return 0.0
    length = min(len(left), len(right))
    dot = sum(left[i] * right[i] for i in range(length))
    left_norm = sqrt(sum(left[i] * left[i] for i in range(length)))
    right_norm = sqrt(sum(right[i] * right[i] for i in range(length)))
    if left_norm <= 0.0 or right_norm <= 0.0:
        return 0.0
    return dot / (left_norm * right_norm)


def _tokenize(text: str) -> list[str]:
    return [token for token in re.findall(r"[a-z0-9_]+", text.lower()) if len(token) > 1]


def _fts_score(query: str, document: str) -> float:
    query_tokens = _tokenize(query)
    if not query_tokens:
        return 0.0
    doc_lower = document.lower()
    hits = sum(1 for token in query_tokens if token in doc_lower)
    return hits / len(query_tokens)


def _metadata_matches(metadata: Mapping[str, Any], prefilter: Mapping[str, Any]) -> bool:
    """Require every prefilter key to match chunk metadata (exact equality)."""
    for key, expected in prefilter.items():
        if metadata.get(key) != expected:
            return False
    return True


def resolve_allowed_collections(
    mode: ExecutionMode | str,
    requested: Sequence[CollectionName] | None = None,
) -> frozenset[CollectionName]:
    """Return collections permitted for the execution mode."""
    resolved_mode = parse_execution_mode(mode)
    if requested is not None:
        candidates = frozenset(requested)
    else:
        candidates = frozenset(CollectionName)

    if resolved_mode is ExecutionMode.LAB_UNRESTRICTED:
        return candidates

    # production and quick: never read LAB_RESEARCH
    return frozenset(c for c in candidates if c not in LAB_ONLY_COLLECTIONS)


def tenant_scope_matches(
    chunk: RagChunk,
    tenant_id: str,
    engagement_id: str | None,
) -> bool:
    """Enforce tenant isolation with global catalog read-through."""
    collection = chunk.collection
    if collection in GLOBAL_COLLECTIONS:
        return chunk.tenant_id is None or chunk.tenant_id == tenant_id

    if chunk.tenant_id != tenant_id:
        return False
    if engagement_id is not None and chunk.engagement_id is not None:
        return chunk.engagement_id == engagement_id
    return True


class HybridSearchEngine:
    """FTS + vector candidate fusion with mandatory tenant filters."""

    def __init__(self, store: InMemoryRagStore | None = None) -> None:
        self._store = store or InMemoryRagStore()

    @property
    def store(self) -> InMemoryRagStore:
        return self._store

    def search(
        self,
        query: str,
        *,
        tenant_id: str,
        engagement_id: str | None = None,
        mode: ExecutionMode | str = ExecutionMode.PRODUCTION,
        collections: Sequence[CollectionName] | None = None,
        max_results: int = 10,
        metadata_prefilter: Mapping[str, Any] | None = None,
        vector_enabled: bool = True,
    ) -> list[SearchHit]:
        allowed_collections = resolve_allowed_collections(mode, collections)
        if not allowed_collections:
            return []

        query_embedding = deterministic_embed(query) if vector_enabled else []
        candidates: list[StoredChunk] = []

        for stored in self._store.all_chunks():
            chunk = stored.chunk
            if chunk.collection not in allowed_collections:
                continue
            if not tenant_scope_matches(chunk, tenant_id, engagement_id):
                if chunk.tenant_id is not None and chunk.tenant_id != tenant_id:
                    record_rag_cross_tenant_denial()
                continue
            if metadata_prefilter and not _metadata_matches(chunk.metadata, metadata_prefilter):
                continue
            candidates.append(stored)

        if not candidates:
            return []

        fts_ranked = sorted(
            candidates,
            key=lambda item: _fts_score(query, item.fts_text),
            reverse=True,
        )
        fused_scores: dict[str, float] = {}
        fts_ranks: dict[str, int] = {}
        vector_ranks: dict[str, int] = {}

        for rank, item in enumerate(fts_ranked, start=1):
            chunk_id = item.chunk.id
            fused_scores[chunk_id] = fused_scores.get(chunk_id, 0.0) + 1.0 / (RRF_K + rank)
            fts_ranks[chunk_id] = rank

        if vector_enabled:
            vector_ranked = sorted(
                candidates,
                key=lambda item: _cosine_similarity(query_embedding, item.embedding),
                reverse=True,
            )
            for rank, item in enumerate(vector_ranked, start=1):
                chunk_id = item.chunk.id
                fused_scores[chunk_id] = fused_scores.get(chunk_id, 0.0) + 1.0 / (RRF_K + rank)
                vector_ranks[chunk_id] = rank

        ordered = sorted(fused_scores.items(), key=lambda pair: pair[1], reverse=True)
        hits: list[SearchHit] = []
        for fusion_rank, (chunk_id, score) in enumerate(ordered[:max_results], start=1):
            hits.append(
                SearchHit(
                    chunk_id=chunk_id,
                    score=score,
                    rank=fusion_rank,
                    fts_rank=fts_ranks.get(chunk_id),
                    vector_rank=vector_ranks.get(chunk_id),
                )
            )
        return hits

    def get_chunk(self, chunk_id: str) -> RagChunk | None:
        stored = self._store.get(chunk_id)
        return stored.chunk if stored else None

    def cross_tenant_denied(
        self,
        query: str,
        *,
        tenant_id: str,
        other_tenant_id: str,
        engagement_id: str | None = None,
        mode: ExecutionMode | str = ExecutionMode.PRODUCTION,
        collections: Sequence[CollectionName] | None = None,
    ) -> bool:
        """Return True when other tenant chunks are excluded from results."""
        hits = self.search(
            query,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            mode=mode,
            collections=collections,
        )
        for hit in hits:
            chunk = self.get_chunk(hit.chunk_id)
            if chunk is None:
                continue
            if chunk.tenant_id == other_tenant_id:
                return False
        return True
