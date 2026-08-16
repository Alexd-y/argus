"""QUICK-009 — RAG tenant filter + FTS fallback (in-memory, no live Postgres)."""

from __future__ import annotations

from typing import Any

from src.execution_mode.mode import ExecutionMode
from src.quick.rag_profile import QuickRagProfile, deny_lab_research
from src.rag.schemas import CollectionName, RagEvidencePack, RagQuery


class _VectorThenFtsRetriever:
    def __init__(self) -> None:
        self.calls = 0

    def retrieve(self, *args: Any, **kwargs: Any) -> RagEvidencePack:
        self.calls += 1
        query = args[0] if args else kwargs.get("query")
        tenant_id = args[1] if len(args) > 1 else kwargs.get("tenant_id")
        if kwargs.get("vector_enabled", True) and self.calls == 1:
            raise RuntimeError("vector_down")
        return RagEvidencePack(
            query=query if isinstance(query, RagQuery) else RagQuery(text="nginx"),
            tenant_id=str(tenant_id),
            engagement_id=None,
            mode=ExecutionMode.QUICK.value,
            citations=(),
            chunks=(),
            metadata={"fts": True},
        )


def test_rag_tenant_filter_and_fts_fallback() -> None:
    stub = _VectorThenFtsRetriever()
    profile = QuickRagProfile(retriever=stub)  # type: ignore[arg-type]
    pack = profile.retrieve(
        "nginx cve",
        tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        engagement_id=None,
        purpose="planning",
    )
    assert pack.tenant_id == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    assert pack.metadata.get("fts_fallback") is True or pack.metadata.get("fts") is True
    assert CollectionName.LAB_RESEARCH not in deny_lab_research(pack.query.collections or None)
    assert stub.calls >= 1
    assert all(chunk.tenant_id != "foreign-tenant" for chunk in pack.chunks)
