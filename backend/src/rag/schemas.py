"""Pydantic contracts for tenant-scoped hybrid RAG."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr


class CollectionName(StrEnum):
    """RAG collection identifiers (§7.1)."""

    ARGUS_PRODUCT = "argus_product"
    SECURITY_STANDARDS = "security_standards"
    TOOL_CATALOG = "tool_catalog"
    PAYLOAD_CATALOG = "payload_catalog"
    DETECTION_TEMPLATES = "detection_templates"
    CAPABILITY_GRAPH = "capability_graph"
    CODEBASE = "codebase"
    API_SURFACE = "api_surface"
    SCAN_EVIDENCE = "scan_evidence"
    FINDING_HISTORY = "finding_history"
    EPISODIC_VALIDATED = "episodic_validated"
    PUBLIC_INTEL = "public_intel"
    LAB_RESEARCH = "lab_research"


GLOBAL_COLLECTIONS: frozenset[CollectionName] = frozenset(
    {
        CollectionName.ARGUS_PRODUCT,
        CollectionName.SECURITY_STANDARDS,
        CollectionName.TOOL_CATALOG,
        CollectionName.PAYLOAD_CATALOG,
        CollectionName.DETECTION_TEMPLATES,
        CollectionName.CAPABILITY_GRAPH,
        CollectionName.PUBLIC_INTEL,
    }
)

LAB_ONLY_COLLECTIONS: frozenset[CollectionName] = frozenset({CollectionName.LAB_RESEARCH})

ALL_COLLECTIONS: frozenset[CollectionName] = frozenset(CollectionName)


class RagSource(BaseModel):
    """Registered ingest source within a collection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr = Field(min_length=1, max_length=36)
    tenant_id: StrictStr | None = Field(default=None, max_length=36)
    engagement_id: StrictStr | None = Field(default=None, max_length=36)
    collection: CollectionName
    uri: StrictStr = Field(min_length=1, max_length=2048)
    title: StrictStr = Field(min_length=1, max_length=512)
    trust_level: StrictStr = Field(default="signed", max_length=32)
    content_class: StrictStr = Field(default="metadata", max_length=64)
    version: StrictStr = Field(default="1", max_length=64)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None


class RagDocument(BaseModel):
    """Parsed document bound to a source."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr = Field(min_length=1, max_length=36)
    tenant_id: StrictStr | None = Field(default=None, max_length=36)
    engagement_id: StrictStr | None = Field(default=None, max_length=36)
    source_id: StrictStr = Field(min_length=1, max_length=36)
    content_hash: StrictStr = Field(min_length=8, max_length=128)
    title: StrictStr = Field(min_length=1, max_length=512)
    mime_type: StrictStr = Field(default="text/plain", max_length=128)
    artifact_ref: StrictStr | None = Field(default=None, max_length=512)
    metadata: dict[str, Any] = Field(default_factory=dict)
    published_at: datetime | None = None
    created_at: datetime | None = None


class RagChunk(BaseModel):
    """Semantic chunk with provenance and taxonomy hooks."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr = Field(min_length=1, max_length=36)
    tenant_id: StrictStr | None = Field(default=None, max_length=36)
    engagement_id: StrictStr | None = Field(default=None, max_length=36)
    document_id: StrictStr = Field(min_length=1, max_length=36)
    source_id: StrictStr = Field(min_length=1, max_length=36)
    collection: CollectionName
    chunk_index: int = Field(ge=0)
    content: StrictStr
    content_hash: StrictStr = Field(min_length=8, max_length=128)
    trust_level: StrictStr = Field(default="signed", max_length=32)
    content_class: StrictStr = Field(default="text", max_length=64)
    taxonomy_ids: list[StrictStr] = Field(default_factory=list)
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime | None = None


class RagCitation(BaseModel):
    """Resolved citation to a chunk in an evidence pack."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr = Field(min_length=1, max_length=36)
    chunk_id: StrictStr = Field(min_length=1, max_length=36)
    chunk_hash: StrictStr = Field(min_length=8, max_length=128)
    document_id: StrictStr = Field(min_length=1, max_length=36)
    source_id: StrictStr = Field(min_length=1, max_length=36)
    collection: CollectionName
    rank: int = Field(ge=1)
    score: float = Field(ge=0.0)
    snippet: StrictStr = Field(default="", max_length=4096)
    metadata: dict[str, Any] = Field(default_factory=dict)


class RagQuery(BaseModel):
    """Retrieval query with tenant/mode scope."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    text: StrictStr = Field(min_length=1, max_length=8192)
    collections: tuple[CollectionName, ...] = Field(default_factory=tuple)
    max_results: int = Field(default=10, ge=1, le=100)
    token_budget: int = Field(default=4096, ge=256, le=32768)


class RagEvidencePack(BaseModel):
    """Evidence pack returned by retrieval with citations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    query: RagQuery
    tenant_id: StrictStr = Field(min_length=1, max_length=36)
    engagement_id: StrictStr | None = Field(default=None, max_length=36)
    mode: Literal["production", "lab_unrestricted", "quick"]
    citations: tuple[RagCitation, ...] = Field(default_factory=tuple)
    chunks: tuple[RagChunk, ...] = Field(default_factory=tuple)
    inferred_claims: tuple[StrictStr, ...] = Field(default_factory=tuple)
    trace_id: StrictStr | None = Field(default=None, max_length=36)
    metadata: dict[str, Any] = Field(default_factory=dict)
