"""Tenant-scoped hybrid RAG foundation."""

from __future__ import annotations

from src.rag.citations import CitationGate, apply_citation_gate
from src.rag.hybrid_search import HybridSearchEngine, InMemoryRagStore
from src.rag.ingestion import (
    RagIngestionPipeline,
    content_hash,
    deterministic_embed,
    redact_secrets,
)
from src.rag.retrieval import RagRetriever
from src.rag.schemas import (
    GLOBAL_COLLECTIONS,
    LAB_ONLY_COLLECTIONS,
    CollectionName,
    RagChunk,
    RagCitation,
    RagDocument,
    RagEvidencePack,
    RagQuery,
    RagSource,
)

__all__ = [
    "GLOBAL_COLLECTIONS",
    "LAB_ONLY_COLLECTIONS",
    "CitationGate",
    "CollectionName",
    "HybridSearchEngine",
    "InMemoryRagStore",
    "RagChunk",
    "RagCitation",
    "RagDocument",
    "RagEvidencePack",
    "RagIngestionPipeline",
    "RagQuery",
    "RagRetriever",
    "RagSource",
    "apply_citation_gate",
    "content_hash",
    "deterministic_embed",
    "redact_secrets",
]
