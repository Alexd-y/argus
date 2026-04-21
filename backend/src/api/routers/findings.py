"""Findings router — ARGUS v4 paths under /findings."""

from __future__ import annotations

import logging
import re
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse
from sqlalchemy import String, cast, select, update

from src.api.schemas import (
    FindingDetailResponse,
    FindingFalsePositiveRequest,
    FindingFalsePositiveResponse,
    FindingPocBodyResponse,
    FindingRemediationResponse,
    FindingRemediationSection,
    FindingValidationApiResponse,
)
from src.cache.scan_knowledge_base import get_knowledge_base
from src.core.tenant import get_current_tenant_id
from src.db.models import Finding as FindingModel
from src.db.models import Scan
from src.db.session import async_session_factory, set_session_tenant
from src.exploit.generator import generate_poc
from src.llm import call_llm, is_llm_available
from src.llm.errors import LLMAllProvidersFailedError, LLMProviderUnavailableError
from src.owasp_top10_2025 import parse_owasp_category
from src.skills import load_skill
from src.validation.exploitability import validate_finding

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/findings", tags=["findings"])

_MAX_REMEDIATION_BODY_CHARS = 6000
_MAX_LLM_SUMMARY_CHARS = 4000
_REMEDIATION_HEADING_HINT = re.compile(
    r"(?i)remediat|mitigat|\bfix\b|prevention|hardening|recommend|secure\s+coding|countermeasure"
)
_HEADING_LINE_RE = re.compile(r"^(#{2,3})\s+(.+)$")


def _markdown_sections(md: str) -> list[tuple[str, str]]:
    """Split markdown into (heading, body) using ## / ### boundaries."""
    lines = (md or "").splitlines()
    out: list[tuple[str, str]] = []
    title = ""
    body_lines: list[str] = []
    for line in lines:
        m = _HEADING_LINE_RE.match(line)
        if m:
            if title or body_lines:
                out.append((title, "\n".join(body_lines).strip()))
            title = m.group(2).strip()
            body_lines = []
        else:
            body_lines.append(line)
    if title or body_lines:
        out.append((title, "\n".join(body_lines).strip()))
    return out


def _remediation_sections_from_skill(skill_id: str, md: str) -> list[FindingRemediationSection]:
    found: list[FindingRemediationSection] = []
    for heading, body in _markdown_sections(md):
        if not body or not heading:
            continue
        if not _REMEDIATION_HEADING_HINT.search(heading):
            continue
        clipped = (
            body
            if len(body) <= _MAX_REMEDIATION_BODY_CHARS
            else body[:_MAX_REMEDIATION_BODY_CHARS] + "\n[truncated]"
        )
        found.append(FindingRemediationSection(skill_id=skill_id, heading=heading, body=clipped))
    return found


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


@router.post(
    "/{finding_id}/false-positive",
    response_model=FindingFalsePositiveResponse,
    status_code=status.HTTP_200_OK,
)
async def mark_finding_false_positive(
    finding_id: str,
    req: FindingFalsePositiveRequest,
    tenant_id: str = Depends(get_current_tenant_id),
) -> FindingFalsePositiveResponse:
    loaded = await _load_finding_for_tenant(finding_id, tenant_id)
    if not loaded:
        raise HTTPException(status_code=404, detail="Finding not found")
    reason = req.reason.strip()
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        await session.execute(
            update(FindingModel)
            .where(
                cast(FindingModel.id, String) == finding_id,
                cast(FindingModel.tenant_id, String) == tenant_id,
            )
            .values(
                false_positive=True,
                false_positive_reason=reason,
                dedup_status="false_positive",
            )
        )
        await session.commit()
    return FindingFalsePositiveResponse(
        finding_id=finding_id,
        false_positive=True,
        false_positive_reason=reason,
        dedup_status="false_positive",
    )


@router.get("/{finding_id}/remediation", response_model=FindingRemediationResponse)
async def get_finding_remediation(
    finding_id: str,
    use_llm: bool = Query(False, description="When true, append a short LLM summary if configured"),
    tenant_id: str = Depends(get_current_tenant_id),
) -> FindingRemediationResponse:
    loaded = await _load_finding_for_tenant(finding_id, tenant_id)
    if not loaded:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding, _target_url = loaded

    owasp_ids: list[str] = []
    if finding.owasp_category:
        owasp_ids.append(str(finding.owasp_category).strip())
    cwe_ids: list[str] = []
    if finding.cwe:
        cwe_ids.append(str(finding.cwe).strip())

    kb = get_knowledge_base()
    strategy = kb.get_scan_strategy(owasp_ids=owasp_ids, cwe_ids=cwe_ids)
    raw_skills = strategy.get("skills") if isinstance(strategy, dict) else []
    skill_names = [str(s) for s in raw_skills] if isinstance(raw_skills, list) else []

    sections: list[FindingRemediationSection] = []
    seen: set[tuple[str, str]] = set()
    for sid in skill_names:
        md = load_skill(sid)
        if not md:
            continue
        for block in _remediation_sections_from_skill(sid, md):
            key = (block.skill_id, block.heading)
            if key in seen:
                continue
            seen.add(key)
            sections.append(block)

    source: Literal["skills", "skills+llm"] = "skills"
    llm_summary: str | None = None
    if use_llm:
        excerpt = "\n\n".join(f"## {s.heading}\n{s.body}" for s in sections[:12])
        if not excerpt.strip():
            excerpt = (finding.description or finding.title or "")[:8000]
        if is_llm_available() and excerpt.strip():
            prompt = (
                f"Title: {finding.title}\n"
                f"Severity: {finding.severity}\n"
                f"CWE: {finding.cwe or 'n/a'}\n"
                f"OWASP: {finding.owasp_category or 'n/a'}\n\n"
                f"Reference material:\n{excerpt[:12000]}\n\n"
                "Produce a short prioritized remediation checklist (max 8 bullets, no prose introduction)."
            )
            try:
                raw = await call_llm(
                    prompt,
                    system_prompt="You are a senior application security engineer. Output only bullet lines.",
                )
                llm_summary = (raw or "").strip()[:_MAX_LLM_SUMMARY_CHARS]
                if llm_summary:
                    source = "skills+llm"
            except (LLMProviderUnavailableError, LLMAllProvidersFailedError):
                logger.info(
                    "finding_remediation_llm_skipped",
                    extra={"event": "argus.finding_remediation_llm_skipped", "finding_id": finding_id},
                )
            except Exception:
                logger.exception(
                    "finding_remediation_llm_failed",
                    extra={"event": "argus.finding_remediation_llm_failed", "finding_id": finding_id},
                )

    return FindingRemediationResponse(
        finding_id=finding_id,
        skills_considered=skill_names,
        sections=sections,
        source=source,
        llm_summary=llm_summary,
    )
