"""Read-only knowledge helpers backed by ScanKnowledgeBase."""

from __future__ import annotations

from fastapi import APIRouter, Query

from src.cache.scan_knowledge_base import get_knowledge_base

router = APIRouter(prefix="/knowledge", tags=["knowledge"])


@router.get("/strategy")
async def get_knowledge_strategy(
    owasp_ids: list[str] = Query(default_factory=list),  # noqa: B008
    cwe_ids: list[str] = Query(default_factory=list),  # noqa: B008
) -> dict[str, object]:
    """Merge OWASP/CWE inputs into skills, tools, and priority (same as KB planner)."""
    kb = get_knowledge_base()
    return kb.get_scan_strategy(owasp_ids=owasp_ids, cwe_ids=cwe_ids)
