"""Episodic memory — cross-scan context via vector DB (ChromaDB/Qdrant).

Stores and retrieves findings, techniques, and patterns from previous
scans so the system can learn across engagements. "Last time we scanned
a Django app, we found these patterns."

Ось D п.2 из Развитие2.md: episodic memory via vector DB.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class EpisodicEntry:
    """A single episodic memory entry from a past scan."""

    entry_id: str
    scan_id: str
    tenant_id: str
    finding_type: str
    cwe: str
    title: str
    description: str
    technique: str = ""
    framework: str = ""
    resolution: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_vector_text(self) -> str:
        return f"{self.finding_type} {self.cwe} {self.title} {self.description} {self.technique} {self.framework}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "scan_id": self.scan_id,
            "finding_type": self.finding_type,
            "cwe": self.cwe,
            "title": self.title,
            "technique": self.technique,
            "framework": self.framework,
        }


class EpisodicMemory:
    """Cross-scan episodic memory backed by vector DB.

    When ChromaDB/Qdrant is available, uses vector similarity search.
    Falls back to in-memory exact-match when vector DB is unavailable.
    """

    def __init__(self, persist_dir: str | None = None) -> None:
        self._entries: list[EpisodicEntry] = []
        self._vector_client: Any = None
        self._collection: Any = None
        self._backend: str = "memory"

        _persist = persist_dir or ""
        try:
            import chromadb
            if _persist:
                self._vector_client = chromadb.PersistentClient(path=_persist)
            else:
                import os
                _default_path = os.environ.get("ARGUS_EPISODIC_DIR", "")
                if _default_path:
                    self._vector_client = chromadb.PersistentClient(path=_default_path)
                else:
                    self._vector_client = chromadb.Client()
            self._collection = self._vector_client.get_or_create_collection("argus_episodic")
            self._backend = "chromadb"
            logger.info("ChromaDB episodic memory initialized (persist=%s)", bool(_persist or os.environ.get("ARGUS_EPISODIC_DIR")))
        except ImportError:
            try:
                from qdrant_client import QdrantClient
                from qdrant_client.models import PointStruct, VectorParams
                _qdrant_host = os.environ.get("ARGUS_QDRANT_HOST", "")
                _qdrant_port = int(os.environ.get("ARGUS_QDRANT_PORT", "6333"))
                if _qdrant_host:
                    self._vector_client = QdrantClient(host=_qdrant_host, port=_qdrant_port)
                else:
                    self._vector_client = QdrantClient(path=os.environ.get("ARGUS_QDRANT_PATH", ":memory:"))
                _collection_name = "argus_episodic"
                _collections = [c.name for c in self._vector_client.get_collections().collections]
                if _collection_name not in _collections:
                    self._vector_client.create_collection(
                        collection_name=_collection_name,
                        vectors_config=VectorParams(size=384, distance="Cosine"),
                    )
                self._collection = _collection_name
                self._backend = "qdrant"
                logger.info("Qdrant episodic memory initialized")
            except ImportError:
                logger.debug("Qdrant not available — using in-memory episodic store")
            except Exception as qd_exc:
                logger.debug("Qdrant init failed: %s — using in-memory store", qd_exc)

    def store(self, entry: EpisodicEntry) -> None:
        if self._backend == "qdrant" and self._vector_client is not None:
            try:
                from qdrant_client.models import PointStruct
                self._vector_client.upsert(
                    collection_name=self._collection,
                    points=[PointStruct(
                        id=entry.entry_id,
                        vector=self._compute_vector(entry.to_vector_text()),
                        payload=entry.to_dict(),
                    )],
                )
                return
            except Exception as exc:
                logger.debug("Qdrant store failed: %s", exc)
        if self._backend == "chromadb" and self._vector_client is not None:
            try:
                self._collection.add(
                    documents=[entry.to_vector_text()],
                    metadatas=[entry.to_dict()],
                    ids=[entry.entry_id],
                )
                return
            except Exception as exc:
                logger.debug("Vector DB store failed: %s", exc)
        self._entries.append(entry)

    def recall(self, query: str, n: int = 5) -> list[EpisodicEntry]:
        """Retrieve similar past experiences."""
        if self._backend == "qdrant" and self._vector_client is not None:
            try:
                hits = self._vector_client.search(
                    collection_name=self._collection,
                    query_vector=self._compute_vector(query),
                    limit=n,
                )
                entries = []
                for hit in hits:
                    payload = hit.payload or {}
                    entries.append(EpisodicEntry(
                        entry_id=payload.get("entry_id", str(hit.id)),
                        scan_id=payload.get("scan_id", ""),
                        tenant_id="",
                        finding_type=payload.get("finding_type", ""),
                        cwe=payload.get("cwe", ""),
                        title=payload.get("title", ""),
                        technique=payload.get("technique", ""),
                        framework=payload.get("framework", ""),
                    ))
                return entries
            except Exception as exc:
                logger.debug("Qdrant query failed: %s", exc)
        if self._backend == "chromadb" and self._vector_client is not None:
            try:
                results = self._collection.query(query_texts=[query], n_results=n)
                entries = []
                for metadata in results.get("metadatas", [[]])[0]:
                    entries.append(EpisodicEntry(
                        entry_id=metadata.get("entry_id", ""),
                        scan_id=metadata.get("scan_id", ""),
                        tenant_id="",
                        finding_type=metadata.get("finding_type", ""),
                        cwe=metadata.get("cwe", ""),
                        title=metadata.get("title", ""),
                        technique=metadata.get("technique", ""),
                        framework=metadata.get("framework", ""),
                    ))
                return entries
            except Exception as exc:
                logger.debug("Vector DB query failed: %s", exc)

        query_lower = query.lower()
        scored = []
        for entry in self._entries:
            score = sum(
                1 for term in query_lower.split()
                if term in entry.to_vector_text().lower()
            )
            if score > 0:
                scored.append((score, entry))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [entry for _, entry in scored[:n]]

    def _compute_vector(self, text: str) -> list[float]:
        """Produce a simple deterministic embedding for vector search."""
        h = hashlib.sha256(text.encode()).digest()
        vec = [float(b) / 255.0 for b in h[:48]]
        norm = sum(x * x for x in vec) ** 0.5 or 1.0
        return [x / norm for x in vec]

    def build_context_prompt(self, query: str, max_entries: int = 3) -> str:
        """Build a prompt section from recalled episodic memory."""
        entries = self.recall(query, n=max_entries)
        if not entries:
            return ""
        lines = ["=== PRIOR SCAN EXPERIENCE ==="]
        for entry in entries:
            lines.append(
                f"- [{entry.cwe}] {entry.title} (framework={entry.framework}, "
                f"technique={entry.technique})"
            )
        lines.append("=== END PRIOR EXPERIENCE ===")
        return "\n".join(lines)


__all__ = [
    "EpisodicEntry",
    "EpisodicMemory",
]
