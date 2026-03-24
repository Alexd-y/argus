"""Internal API — enqueue VA sandbox scanner Celery tasks (MCP / automation)."""

from __future__ import annotations

import logging
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from src.api.routers.admin import require_admin
from src.celery_app import app as celery_app

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/internal", tags=["internal"])

VaToolName = Literal["dalfox", "xsstrike", "ffuf", "sqlmap", "nuclei"]

_CELERY_NAME_BY_VA_TOOL: dict[str, str] = {
    "dalfox": "argus.va.run_dalfox",
    "xsstrike": "argus.va.run_xsstrike",
    "ffuf": "argus.va.run_ffuf",
    "sqlmap": "argus.va.run_sqlmap",
    "nuclei": "argus.va.run_nuclei",
}


class VaToolEnqueueRequest(BaseModel):
    tenant_id: str = Field(..., min_length=1, max_length=256)
    scan_id: str = Field(..., min_length=1, max_length=256)
    target: str = Field(..., min_length=1, max_length=2048)
    tool: VaToolName
    args: list[str] | None = None


class VaToolEnqueueResponse(BaseModel):
    task_id: str
    tool: str
    celery_task: str


@router.post(
    "/va-tools/enqueue",
    response_model=VaToolEnqueueResponse,
    dependencies=[Depends(require_admin)],
)
async def enqueue_va_tool_task(body: VaToolEnqueueRequest) -> dict[str, Any]:
    """Queue a VA sandbox tool run (policy + mcp_runner inside the worker). Requires X-Admin-Key when set."""
    celery_name = _CELERY_NAME_BY_VA_TOOL.get(body.tool)
    if not celery_name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown tool")
    try:
        async_result = celery_app.send_task(
            celery_name,
            args=[body.tenant_id, body.scan_id, body.target, body.args],
        )
    except Exception:
        logger.exception(
            "va_tool_enqueue_failed",
            extra={"event": "va_tool_enqueue_failed", "tool": body.tool},
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Enqueue failed",
        ) from None
    return {
        "task_id": async_result.id,
        "tool": body.tool,
        "celery_task": celery_name,
    }
