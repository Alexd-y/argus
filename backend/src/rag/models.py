"""SQLAlchemy models for tenant-scoped hybrid RAG storage."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from src.db.models import Base, gen_uuid


class RagSource(Base):
    """Registered ingest source (global or tenant-owned)."""

    __tablename__ = "rag_sources"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True
    )
    engagement_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=True
    )
    collection: Mapped[str] = mapped_column(String(64), nullable=False)
    uri: Mapped[str] = mapped_column(String(2048), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    trust_level: Mapped[str] = mapped_column(String(32), nullable=False, default="signed")
    content_class: Mapped[str] = mapped_column(String(64), nullable=False, default="metadata")
    version: Mapped[str] = mapped_column(String(64), nullable=False, default="1")
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        Index("ix_rag_sources_tenant_collection", "tenant_id", "collection"),
        Index("ix_rag_sources_engagement", "tenant_id", "engagement_id"),
    )


class RagDocument(Base):
    """Parsed document bound to a source."""

    __tablename__ = "rag_documents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True
    )
    engagement_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=True
    )
    source_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("rag_sources.id", ondelete="CASCADE"), nullable=False
    )
    content_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(128), nullable=False, default="text/plain")
    artifact_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, nullable=False, default=dict)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_rag_documents_source", "source_id"),
        Index("ix_rag_documents_tenant_engagement", "tenant_id", "engagement_id"),
        Index("ix_rag_documents_content_hash", "content_hash"),
    )


class RagChunk(Base):
    """Semantic chunk with FTS and taxonomy metadata."""

    __tablename__ = "rag_chunks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True
    )
    engagement_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=True
    )
    document_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("rag_documents.id", ondelete="CASCADE"), nullable=False
    )
    source_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("rag_sources.id", ondelete="CASCADE"), nullable=False
    )
    collection: Mapped[str] = mapped_column(String(64), nullable=False)
    chunk_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    trust_level: Mapped[str] = mapped_column(String(32), nullable=False, default="signed")
    content_class: Mapped[str] = mapped_column(String(64), nullable=False, default="text")
    taxonomy_ids: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    fts_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_rag_chunks_document", "document_id"),
        Index("ix_rag_chunks_tenant_collection", "tenant_id", "collection"),
        Index("ix_rag_chunks_content_hash", "content_hash"),
        Index("ix_rag_chunks_engagement", "tenant_id", "engagement_id"),
    )


class RagEmbedding(Base):
    """Vector embedding for a chunk."""

    __tablename__ = "rag_embeddings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    chunk_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("rag_chunks.id", ondelete="CASCADE"), nullable=False
    )
    tenant_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True
    )
    model_id: Mapped[str] = mapped_column(String(128), nullable=False, default="deterministic-hash-v1")
    dimensions: Mapped[int] = mapped_column(Integer, nullable=False, default=384)
    embedding_json: Mapped[list[Any] | None] = mapped_column(JSONB, nullable=True)
    embedding_bytes: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_rag_embeddings_chunk", "chunk_id", unique=True),
        Index("ix_rag_embeddings_tenant", "tenant_id"),
    )


class RagIngestionJob(Base):
    """Ingestion job lifecycle."""

    __tablename__ = "rag_ingestion_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    engagement_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=True
    )
    source_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("rag_sources.id", ondelete="SET NULL"), nullable=True
    )
    collection: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="production")
    redact_applied: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default=text("true"))
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, nullable=False, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_rag_ingestion_jobs_tenant_status", "tenant_id", "status"),
        Index("ix_rag_ingestion_jobs_engagement", "tenant_id", "engagement_id"),
    )


class RagQueryTrace(Base):
    """Retrieval query audit trace."""

    __tablename__ = "rag_query_traces"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    engagement_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("engagements.id", ondelete="CASCADE"), nullable=True
    )
    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="production")
    query_text: Mapped[str] = mapped_column(Text, nullable=False)
    collections: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    result_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_rag_query_traces_tenant", "tenant_id", "created_at"),
        Index("ix_rag_query_traces_engagement", "tenant_id", "engagement_id"),
    )


class RagCitation(Base):
    """Persisted citation from a retrieval trace."""

    __tablename__ = "rag_citations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    query_trace_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("rag_query_traces.id", ondelete="CASCADE"), nullable=True
    )
    chunk_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("rag_chunks.id", ondelete="CASCADE"), nullable=False
    )
    chunk_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    document_id: Mapped[str] = mapped_column(String(36), nullable=False)
    source_id: Mapped[str] = mapped_column(String(36), nullable=False)
    rank: Mapped[int] = mapped_column(Integer, nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        Index("ix_rag_citations_trace", "query_trace_id"),
        Index("ix_rag_citations_chunk_hash", "chunk_hash"),
        Index("ix_rag_citations_tenant", "tenant_id"),
    )
