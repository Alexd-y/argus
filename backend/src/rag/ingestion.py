"""RAG ingestion pipeline — hash, chunk, embed, FTS prep, publish."""

from __future__ import annotations

import hashlib
import math
import re
import struct
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from src.db.models import gen_uuid
from src.execution_mode.mode import ExecutionMode, parse_execution_mode
from src.rag.schemas import (
    CollectionName,
    RagChunk,
    RagDocument,
    RagSource,
)

EMBEDDING_DIMS: int = 384
EMBEDDING_MODEL_ID: str = "deterministic-hash-v1"
DEFAULT_CHUNK_SIZE: int = 800

_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"(?i)(api[_-]?key|secret|password|token|passwd)\s*[=:]\s*\S+",
        r"(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*",
        r"(?i)Authorization:\s*\S+",
        r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*[A-Za-z0-9/+=]{16,}",
        r"(?i)private[_-]?key\s*-----BEGIN",
    )
)


def content_hash(text: str) -> str:
    """SHA-256 hex digest for immutable content identity."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def deterministic_embed(text: str, dims: int = EMBEDDING_DIMS) -> list[float]:
    """Deterministic normalized embedding for tests without external models."""
    vec: list[float] = []
    counter = 0
    while len(vec) < dims:
        digest = hashlib.sha256(f"{text}:{counter}".encode()).digest()
        for offset in range(0, len(digest) - 3, 4):
            if len(vec) >= dims:
                break
            raw = struct.unpack(">f", digest[offset:offset + 4])[0]
            if math.isnan(raw):
                raw = 0.0
            vec.append(raw)
        counter += 1
    norm = math.sqrt(sum(value * value for value in vec))
    if norm <= 0.0:
        return [0.0] * dims
    return [value / norm for value in vec]


def redact_secrets(text: str) -> str:
    """Redact common secret patterns for production ingestion."""
    redacted = text
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def prepare_fts_text(text: str) -> str:
    """Normalize text for FTS indexing."""
    collapsed = re.sub(r"\s+", " ", text.strip())
    return collapsed[:16384]


def semantic_chunk(text: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> list[str]:
    """Split text into fixed-size semantic chunks preserving paragraph boundaries."""
    if not text:
        return []
    paragraphs = [part.strip() for part in re.split(r"\n{2,}", text) if part.strip()]
    chunks: list[str] = []
    buffer = ""
    for paragraph in paragraphs:
        candidate = f"{buffer}\n\n{paragraph}".strip() if buffer else paragraph
        if len(candidate) <= chunk_size:
            buffer = candidate
            continue
        if buffer:
            chunks.append(buffer)
            buffer = ""
        if len(paragraph) <= chunk_size:
            buffer = paragraph
            continue
        start = 0
        while start < len(paragraph):
            end = min(start + chunk_size, len(paragraph))
            chunks.append(paragraph[start:end])
            start = end
    if buffer:
        chunks.append(buffer)
    return chunks


@dataclass
class IngestionResult:
    """Published ingestion artifacts."""

    source: RagSource
    document: RagDocument
    chunks: list[RagChunk] = field(default_factory=list)
    embeddings: list[list[float]] = field(default_factory=list)
    job_id: str = ""
    redact_applied: bool = False


class RagIngestionPipeline:
    """Mode-aware ingestion: hash → meta → chunk → embed → FTS → publish."""

    def __init__(self, *, chunk_size: int = DEFAULT_CHUNK_SIZE) -> None:
        self._chunk_size = chunk_size

    def ingest(
        self,
        *,
        tenant_id: str | None,
        engagement_id: str | None,
        collection: CollectionName,
        uri: str,
        title: str,
        content: str,
        mode: ExecutionMode | str = ExecutionMode.PRODUCTION,
        redact: bool | None = None,
        trust_level: str = "signed",
        content_class: str = "text",
        taxonomy_ids: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> IngestionResult:
        resolved_mode = parse_execution_mode(mode)
        apply_redact = redact if redact is not None else resolved_mode is ExecutionMode.PRODUCTION
        working_text = redact_secrets(content) if apply_redact else content
        digest = content_hash(working_text)
        now = datetime.now(tz=UTC)

        source_id = gen_uuid()
        document_id = gen_uuid()
        job_id = gen_uuid()

        source = RagSource(
            id=source_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            collection=collection,
            uri=uri,
            title=title,
            trust_level=trust_level,
            content_class=content_class,
            version=digest[:16],
            metadata=dict(metadata or {}),
            created_at=now,
        )
        document = RagDocument(
            id=document_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            source_id=source_id,
            content_hash=digest,
            title=title,
            mime_type="text/plain",
            artifact_ref=None,
            metadata={"uri": uri, "job_id": job_id},
            published_at=now,
            created_at=now,
        )

        raw_chunks = semantic_chunk(working_text, self._chunk_size)
        chunks: list[RagChunk] = []
        embeddings: list[list[float]] = []
        taxonomy = list(taxonomy_ids or [])

        for index, chunk_text in enumerate(raw_chunks):
            chunk_hash = content_hash(chunk_text)
            fts_text = prepare_fts_text(chunk_text)
            chunk = RagChunk(
                id=gen_uuid(),
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                document_id=document_id,
                source_id=source_id,
                collection=collection,
                chunk_index=index,
                content=chunk_text,
                content_hash=chunk_hash,
                trust_level=trust_level,
                content_class=content_class,
                taxonomy_ids=taxonomy,
                metadata={"fts_text": fts_text, "job_id": job_id},
                created_at=now,
            )
            chunks.append(chunk)
            embeddings.append(deterministic_embed(chunk_text))

        return IngestionResult(
            source=source,
            document=document,
            chunks=chunks,
            embeddings=embeddings,
            job_id=job_id,
            redact_applied=apply_redact,
        )
