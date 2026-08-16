"""055 — RAG foundation: sources, chunks, embeddings, traces (+ RLS).

Revision ID: 055
Revises: 054
Create Date: 2026-08-15

Stage C foundation for tenant-scoped hybrid RAG (PostgreSQL FTS + pgvector).
``lab_unrestricted`` never disables RLS or tenant filters.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "055"
down_revision: str | None = "054"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SOURCES = "rag_sources"
_DOCUMENTS = "rag_documents"
_CHUNKS = "rag_chunks"
_EMBEDDINGS = "rag_embeddings"
_INGESTION_JOBS = "rag_ingestion_jobs"
_QUERY_TRACES = "rag_query_traces"
_CITATIONS = "rag_citations"

_GLOBAL_RLS_TABLES: tuple[str, ...] = (
    _SOURCES,
    _DOCUMENTS,
    _CHUNKS,
    _EMBEDDINGS,
)

_STRICT_TENANT_RLS_TABLES: tuple[str, ...] = (
    _INGESTION_JOBS,
    _QUERY_TRACES,
    _CITATIONS,
)


def _json_type(is_postgres: bool) -> sa.types.TypeEngine:
    if is_postgres:
        return postgresql.JSONB()
    return sa.JSON()


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"
    json_type = _json_type(is_postgres)

    if is_postgres:
        op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    op.create_table(
        _SOURCES,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "engagement_id",
            sa.String(36),
            sa.ForeignKey("engagements.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("collection", sa.String(64), nullable=False),
        sa.Column("uri", sa.String(2048), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("trust_level", sa.String(32), nullable=False, server_default="signed"),
        sa.Column("content_class", sa.String(64), nullable=False, server_default="metadata"),
        sa.Column("version", sa.String(64), nullable=False, server_default="1"),
        sa.Column("metadata", json_type, nullable=False, server_default=sa.text("'{}'")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )
    op.create_index("ix_rag_sources_tenant_collection", _SOURCES, ["tenant_id", "collection"])
    op.create_index("ix_rag_sources_engagement", _SOURCES, ["tenant_id", "engagement_id"])

    op.create_table(
        _DOCUMENTS,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "engagement_id",
            sa.String(36),
            sa.ForeignKey("engagements.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "source_id",
            sa.String(36),
            sa.ForeignKey("rag_sources.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("content_hash", sa.String(128), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("mime_type", sa.String(128), nullable=False, server_default="text/plain"),
        sa.Column("artifact_ref", sa.String(512), nullable=True),
        sa.Column("metadata", json_type, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )
    op.create_index("ix_rag_documents_source", _DOCUMENTS, ["source_id"])
    op.create_index("ix_rag_documents_tenant_engagement", _DOCUMENTS, ["tenant_id", "engagement_id"])
    op.create_index("ix_rag_documents_content_hash", _DOCUMENTS, ["content_hash"])

    chunk_columns: list[sa.Column] = [
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "engagement_id",
            sa.String(36),
            sa.ForeignKey("engagements.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "document_id",
            sa.String(36),
            sa.ForeignKey("rag_documents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "source_id",
            sa.String(36),
            sa.ForeignKey("rag_sources.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("collection", sa.String(64), nullable=False),
        sa.Column("chunk_index", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.String(128), nullable=False),
        sa.Column("trust_level", sa.String(32), nullable=False, server_default="signed"),
        sa.Column("content_class", sa.String(64), nullable=False, server_default="text"),
        sa.Column("taxonomy_ids", json_type, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("fts_text", sa.Text(), nullable=True),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata", json_type, nullable=False, server_default=sa.text("'{}'")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    ]

    if is_postgres:
        chunk_columns.append(
            sa.Column(
                "fts_vector",
                postgresql.TSVECTOR(),
                nullable=True,
            )
        )

    op.create_table(_CHUNKS, *chunk_columns)
    op.create_index("ix_rag_chunks_document", _CHUNKS, ["document_id"])
    op.create_index("ix_rag_chunks_tenant_collection", _CHUNKS, ["tenant_id", "collection"])
    op.create_index("ix_rag_chunks_content_hash", _CHUNKS, ["content_hash"])
    op.create_index("ix_rag_chunks_engagement", _CHUNKS, ["tenant_id", "engagement_id"])

    if is_postgres:
        op.execute(
            f"""
            CREATE INDEX ix_rag_chunks_fts_vector ON {_CHUNKS}
            USING gin (fts_vector)
            """
        )
        op.execute(
            """
            CREATE OR REPLACE FUNCTION rag_chunks_fts_trigger() RETURNS trigger AS $$
            BEGIN
                NEW.fts_vector := to_tsvector('english', coalesce(NEW.fts_text, NEW.content));
                RETURN NEW;
            END
            $$ LANGUAGE plpgsql;
            """
        )
        op.execute(
            f"""
            CREATE TRIGGER rag_chunks_fts_update
            BEFORE INSERT OR UPDATE OF fts_text, content ON {_CHUNKS}
            FOR EACH ROW EXECUTE FUNCTION rag_chunks_fts_trigger();
            """
        )

    embedding_columns: list[sa.Column] = [
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "chunk_id",
            sa.String(36),
            sa.ForeignKey("rag_chunks.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("model_id", sa.String(128), nullable=False, server_default="deterministic-hash-v1"),
        sa.Column("dimensions", sa.Integer(), nullable=False, server_default="384"),
        sa.Column("embedding_json", json_type, nullable=True),
        sa.Column("embedding_bytes", sa.LargeBinary(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    ]

    op.create_table(_EMBEDDINGS, *embedding_columns)
    if is_postgres:
        op.execute("ALTER TABLE rag_embeddings ADD COLUMN embedding vector(384)")
    op.create_index("ix_rag_embeddings_chunk", _EMBEDDINGS, ["chunk_id"], unique=True)
    op.create_index("ix_rag_embeddings_tenant", _EMBEDDINGS, ["tenant_id"])

    op.create_table(
        _INGESTION_JOBS,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "engagement_id",
            sa.String(36),
            sa.ForeignKey("engagements.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "source_id",
            sa.String(36),
            sa.ForeignKey("rag_sources.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("collection", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("mode", sa.String(32), nullable=False, server_default="production"),
        sa.Column("redact_applied", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("metadata", json_type, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )
    op.create_index("ix_rag_ingestion_jobs_tenant_status", _INGESTION_JOBS, ["tenant_id", "status"])
    op.create_index("ix_rag_ingestion_jobs_engagement", _INGESTION_JOBS, ["tenant_id", "engagement_id"])

    op.create_table(
        _QUERY_TRACES,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "engagement_id",
            sa.String(36),
            sa.ForeignKey("engagements.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("mode", sa.String(32), nullable=False, server_default="production"),
        sa.Column("query_text", sa.Text(), nullable=False),
        sa.Column("collections", json_type, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("result_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("latency_ms", sa.Float(), nullable=True),
        sa.Column("metadata", json_type, nullable=False, server_default=sa.text("'{}'")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )
    op.create_index("ix_rag_query_traces_tenant", _QUERY_TRACES, ["tenant_id", "created_at"])
    op.create_index("ix_rag_query_traces_engagement", _QUERY_TRACES, ["tenant_id", "engagement_id"])

    op.create_table(
        _CITATIONS,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "query_trace_id",
            sa.String(36),
            sa.ForeignKey("rag_query_traces.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column(
            "chunk_id",
            sa.String(36),
            sa.ForeignKey("rag_chunks.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("chunk_hash", sa.String(128), nullable=False),
        sa.Column("document_id", sa.String(36), nullable=False),
        sa.Column("source_id", sa.String(36), nullable=False),
        sa.Column("rank", sa.Integer(), nullable=False),
        sa.Column("score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("metadata", json_type, nullable=False, server_default=sa.text("'{}'")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )
    op.create_index("ix_rag_citations_trace", _CITATIONS, ["query_trace_id"])
    op.create_index("ix_rag_citations_chunk_hash", _CITATIONS, ["chunk_hash"])
    op.create_index("ix_rag_citations_tenant", _CITATIONS, ["tenant_id"])

    if is_postgres:
        for table in _GLOBAL_RLS_TABLES:
            op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
            op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
            op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
            op.execute(
                f"""
                CREATE POLICY tenant_isolation ON "{table}"
                USING (
                    tenant_id IS NULL
                    OR tenant_id = current_setting('app.current_tenant_id', true)
                )
                WITH CHECK (
                    tenant_id IS NULL
                    OR tenant_id = current_setting('app.current_tenant_id', true)
                )
                """
            )

        for table in _STRICT_TENANT_RLS_TABLES:
            op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
            op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
            op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
            op.execute(
                f"""
                CREATE POLICY tenant_isolation ON "{table}"
                USING (tenant_id = current_setting('app.current_tenant_id', true))
                WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true))
                """
            )


def downgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    if is_postgres:
        for table in _STRICT_TENANT_RLS_TABLES:
            op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
            op.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
            op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')

        for table in _GLOBAL_RLS_TABLES:
            op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
            op.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
            op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')

        op.execute("DROP TRIGGER IF EXISTS rag_chunks_fts_update ON rag_chunks")
        op.execute("DROP FUNCTION IF EXISTS rag_chunks_fts_trigger()")

    op.drop_table(_CITATIONS)
    op.drop_table(_QUERY_TRACES)
    op.drop_table(_INGESTION_JOBS)
    op.drop_table(_EMBEDDINGS)
    op.drop_table(_CHUNKS)
    op.drop_table(_DOCUMENTS)
    op.drop_table(_SOURCES)
