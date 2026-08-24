"""CVSS override endpoint — manually override auto-scored CVSS vectors on findings."""

from __future__ import annotations

import logging
import re
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import String, cast, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.tenant import get_current_tenant_id
from src.db.models import Finding
from src.db.session import async_session_factory, set_session_tenant
from src.findings.cvss import severity_label
from src.findings.cvss_auto_score import CVSSVectorSpec

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/findings", tags=["findings"])

_CVSS_VECTOR_RE = re.compile(r"^CVSS:3\.[01]/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]$")

CVSS_OVERRIDE_ALLOWED = frozenset({"critical", "high", "medium", "low", "info", "informational", "none"})


class CVSSOverrideRequest(BaseModel):
    cvss_vector: str = Field(
        ...,
        description="CVSS v3.1 vector string (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)",
    )
    reason: str | None = Field(default=None, description="Optional justification for the override")


class CVSSOverrideResponse(BaseModel):
    finding_id: str
    cvss_vector: str
    cvss_score: float
    severity: str
    cvss_overridden: bool = True
    reason: str | None = None


async def _get_session():
    session = async_session_factory()
    try:
        yield session
    finally:
        await session.close()


@router.patch(
    "/{finding_id}/cvss",
    response_model=CVSSOverrideResponse,
    responses={404: {"description": "Finding not found"}, 422: {"description": "Invalid CVSS vector"}},
)
async def override_finding_cvss(
    finding_id: UUID,
    override: CVSSOverrideRequest,
    tenant_id: str = Depends(get_current_tenant_id),
    session: AsyncSession = Depends(_get_session),
) -> CVSSOverrideResponse:
    await set_session_tenant(session, tenant_id)

    if not _CVSS_VECTOR_RE.match(override.cvss_vector):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid CVSS vector format: {override.cvss_vector}. "
            "Expected format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        )

    result = await session.execute(
        select(Finding).where(
            cast(Finding.id, String) == str(finding_id),
            cast(Finding.tenant_id, String) == tenant_id,
        )
    )
    finding = result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")

    try:
        parts = {}
        for segment in override.cvss_vector.split("/")[1:]:
            key, val = segment.split(":", 1)
            parts[key.lower()] = val
        spec = CVSSVectorSpec(
            av=parts.get("av", "N"),
            ac=parts.get("ac", "L"),
            pr=parts.get("pr", "N"),
            ui=parts.get("ui", "N"),
            s=parts.get("s", "U"),
            c=parts.get("c", "N"),
            i=parts.get("i", "N"),
            a=parts.get("a", "N"),
        )
        score = spec.compute_score()
        sev = severity_label(score).lower()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to compute CVSS score from vector: {exc}",
        )

    finding.cvss_vector = override.cvss_vector
    finding.cvss = score
    finding.severity = sev if sev in CVSS_OVERRIDE_ALLOWED else finding.severity

    await session.commit()
    await session.refresh(finding)

    logger.info(
        "cvss_overridden",
        extra={
            "event": "cvss_overridden",
            "finding_id": str(finding_id),
            "cvss_vector": override.cvss_vector,
            "score": score,
            "severity": sev,
            "tenant_id": tenant_id,
        },
    )

    return CVSSOverrideResponse(
        finding_id=str(finding.id),
        cvss_vector=override.cvss_vector,
        cvss_score=score,
        severity=sev,
        cvss_overridden=True,
        reason=override.reason,
    )
