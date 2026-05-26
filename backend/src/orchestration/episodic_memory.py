"""Episodic memory — cross-scan context via vector DB (ChromaDB/Qdrant).

Stores and retrieves findings, techniques, and patterns from previous
scans so the system can learn across engagements. "Last time we scanned
a Django app, we found these patterns."

Ось D п.2 из Развитие2.md: episodic memory via vector DB.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
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
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

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
            logger.info("ChromaDB episodic memory initialized (persist=%s)", bool(_persist or os.environ.get("ARGUS_EPISODIC_DIR")))
        except ImportError:
            try:
                pass
            except Exception:
                pass
            logger.debug("ChromaDB not available — using in-memory episodic store")

    def store(self, entry: EpisodicEntry) -> None:
        if self._vector_client is not None:
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
        if self._vector_client is not None:
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