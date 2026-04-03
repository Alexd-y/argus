"""Findings router — HexStrike v4 paths under /findings."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy import String, cast, select

from src.api.schemas import (
    FindingDetailResponse,
    FindingPocBodyResponse,
    FindingValidationApiResponse,
)
from src.core.tenant import get_current_tenant_id
from src.db.models import Finding as FindingModel
from src.db.models import Scan
from src.db.session import async_session_factory, set_session_tenant
from src.exploit.generator import generate_poc
from src.owasp_top10_2025 import parse_owasp_category
from src.validation.exploitability import validate_finding

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/findings", tags=["findings"])


def _refs_list(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(x) for x in raw]
    return []


def _row_to_detail(f: FindingModel) -> FindingDetailResponse:
    return FindingDetailResponse(
        id=f.id,
        scan_id=f.scan_id,
        report_id=f.report_id,
        severity=f.severity,
        title=f.title,
        description=f.description or "",
        cwe=f.cwe,
        cvss=f.cvss,
        owasp_category=parse_owasp_category(f.owasp_category),
        proof_of_concept=f.proof_of_concept if isinstance(f.proof_of_concept, dict) else None,
        confidence=f.confidence or "likely",  # type: ignore[arg-type]
        evidence_type=f.evidence_type,  # type: ignore[arg-type]
        evidence_refs=_refs_list(f.evidence_refs),
        reproducible_steps=f.reproducible_steps,
        applicability_notes=f.applicability_notes,
        adversarial_score=f.adversarial_score,
        dedup_status=f.dedup_status,
        created_at=f.created_at.isoformat() if f.created_at else None,
    )


async def _load_finding_for_tenant(
    finding_id: str, tenant_id: str
) -> tuple[FindingModel, str] | None:
    """Return (finding, target_url) if tenant owns the finding's scan."""
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        fr = await session.execute(
            select(FindingModel).where(cast(FindingModel.id, String) == finding_id)
        )
        finding = fr.scalar_one_or_none()
        if not finding:
            return None
        if str(finding.tenant_id) != str(tenant_id):
            return None
        sr = await session.execute(
            select(Scan).where(
                cast(Scan.id, String) == str(finding.scan_id),
                cast(Scan.tenant_id, String) == tenant_id,
            )
        )
        scan = sr.scalar_one_or_none()
        if not scan:
            return None
        return finding, scan.target_url or ""


def _finding_dict_for_pipeline(f: FindingModel, target_url: str) -> dict[str, Any]:
    return {
        "finding_id": f.id,
        "id": f.id,
        "title": f.title,
        "description": f.description or "",
        "cwe": f.cwe,
        "owasp": f.owasp_category,
        "cvss": f.cvss,
        "severity": f.severity,
        "confidence": f.confidence,
        "validation_status": f.confidence,
        "affected_url": target_url,
        "evidence": f.proof_of_concept if isinstance(f.proof_of_concept, dict) else {},
        "tool_evidence": "",
        "adversarial_score": f.adversarial_score,
        "shodan_confirmed": False,
    }


@router.get("/{finding_id}", response_model=FindingDetailResponse)
async def get_finding_detail(
    finding_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
) -> FindingDetailResponse:
    loaded = await _load_finding_for_tenant(finding_id, tenant_id)
    if not loaded:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding, _ = loaded
    return _row_to_detail(finding)


@router.get("/{finding_id}/poc", response_model=FindingPocBodyResponse)
async def get_finding_poc(
    finding_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
) -> FindingPocBodyResponse:
    loaded = await _load_finding_for_tenant(finding_id, tenant_id)
    if not loaded:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding, _ = loaded
    poc = finding.proof_of_concept if isinstance(finding.proof_of_concept, dict) else None
    if not poc:
        conf = (finding.confidence or "").lower()
        can_gen = conf in ("confirmed", "high")
        return FindingPocBodyResponse(
            finding_id=finding_id,
            poc=None,
            can_generate=can_gen,
            hint=f"No PoC stored; use POST /findings/{finding_id}/poc/generate when eligible and LLM is configured.",
        )
    return FindingPocBodyResponse(finding_id=finding_id, poc=poc, can_generate=True)


@router.post("/{finding_id}/validate", response_model=None)
async def post_validate_finding(
    finding_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
) -> FindingValidationApiResponse:
    loaded = await _load_finding_for_tenant(finding_id, tenant_id)
    if not loaded:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding, target_url = loaded
    payload = _finding_dict_for_pipeline(finding, target_url)
    try:
        result = await validate_finding(payload)
    except Exception:
        logger.exception(
            "finding_validate_failed",
            extra={"event": "argus.finding_validate_failed", "finding_id": finding_id},
        )
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "error": "llm_unavailable",
                "message": "Validation pipeline unavailable.",
                "finding_id": finding_id,
            },
        )
    return FindingValidationApiResponse(
        finding_id=result.finding_id,
        status=result.status,
        confidence=result.confidence,
        reasoning=result.reasoning,
        poc_command=result.poc_command,
        actual_impact=result.actual_impact,
        preconditions=result.preconditions,
        reject_reason=result.reject_reason,
        exploit_public=result.exploit_public,
        exploit_sources=result.exploit_sources,
        stages_passed=result.stages_passed,
    )


@router.post("/{finding_id}/poc/generate", response_model=None)
async def post_generate_poc(
    finding_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
) -> FindingPocBodyResponse:
    loaded = await _load_finding_for_tenant(finding_id, tenant_id)
    if not loaded:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding, target_url = loaded
    payload = _finding_dict_for_pipeline(finding, target_url)
    try:
        poc_res = await generate_poc(payload, target=target_url)
    except Exception:
        logger.exception(
            "finding_poc_generate_failed",
            extra={"event": "argus.finding_poc_generate_failed", "finding_id": finding_id},
        )
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "error": "llm_unavailable",
                "message": "PoC generation pipeline unavailable.",
                "finding_id": finding_id,
            },
        )
    if poc_res is None:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "error": "poc_not_eligible",
                "message": "PoC generation is disabled or this finding is not eligible (e.g. confidence).",
                "finding_id": finding_id,
            },
        )
    return FindingPocBodyResponse(
        finding_id=finding_id,
        poc_code=poc_res.poc_code,
        playwright_script=poc_res.playwright_script,
        generator_model=poc_res.generator_model or None,
        can_generate=True,
    )
