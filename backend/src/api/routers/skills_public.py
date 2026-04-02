"""Public skills inventory for MCP / clients (read-only)."""

from __future__ import annotations

from fastapi import APIRouter

from src.skills import get_available_skills

router = APIRouter(prefix="/skills", tags=["skills"])


@router.get("")
async def list_available_skills() -> dict[str, object]:
    """Return categorized skill ids from packaged markdown skills."""
    return {"success": True, "skills": get_available_skills()}
