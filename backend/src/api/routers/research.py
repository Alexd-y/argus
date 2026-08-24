"""Research API — analyst workbench tools.

POST /api/v1/research/advisory      — summarise CVE advisory
POST /api/v1/research/runbook       — generate defensive runbook
POST /api/v1/research/tabletop      — generate tabletop scenario
POST /api/v1/research/explain       — explain exploit class
POST /api/v1/research/compare       — compare models
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from src.auth.admin_dependencies import require_admin_mfa_passed
from src.auth.admin_sessions import SessionPrincipal

router = APIRouter(prefix="/research", tags=["research"])


class AdvisoryRequest(BaseModel):
    cve_id: str
    description: str = ""


class RunbookRequest(BaseModel):
    finding_type: str
    environment: str = "kubernetes"


class TabletopRequest(BaseModel):
    scenario_type: str = "ransomware"
    organisation_size: str = "medium"


class ExplainRequest(BaseModel):
    vuln_type: str


class CompareRequest(BaseModel):
    models: list[str]
    benchmark_results: dict[str, dict[str, Any]]


@router.post("/advisory")
async def summarise_advisory(req: AdvisoryRequest, _principal: Annotated[SessionPrincipal, Depends(require_admin_mfa_passed)] = None) -> dict[str, Any]:
    from src.workers.research.assistant import summarise_advisory

    result = await summarise_advisory(req.cve_id, req.description)
    return {
        "cve_id": result.cve_id, "title": result.title,
        "severity": result.severity, "summary": result.summary,
        "affected_versions": result.affected_versions,
        "patches": result.patches,
        "exploit_available": result.exploit_available,
        "recommendations": result.recommendations,
    }


@router.post("/runbook")
async def generate_runbook(req: RunbookRequest, _principal: Annotated[SessionPrincipal, Depends(require_admin_mfa_passed)] = None) -> dict[str, Any]:
    from src.workers.research.assistant import generate_defensive_runbook

    result = await generate_defensive_runbook(req.finding_type, req.environment)
    return {
        "title": result.title, "steps": result.steps,
        "rollback_plan": result.rollback_plan,
        "verification": result.verification,
    }


@router.post("/tabletop")
async def generate_tabletop(req: TabletopRequest, _principal: Annotated[SessionPrincipal, Depends(require_admin_mfa_passed)] = None) -> dict[str, Any]:
    from src.workers.research.assistant import generate_tabletop_scenario

    result = await generate_tabletop_scenario(req.scenario_type, req.organisation_size)
    return {
        "title": result.title, "scenario_type": result.scenario_type,
        "description": result.description, "objectives": result.objectives,
        "injects": result.injects, "duration_minutes": result.duration_minutes,
        "participants": result.participants,
    }


@router.post("/explain")
async def explain_class(req: ExplainRequest, _principal: Annotated[SessionPrincipal, Depends(require_admin_mfa_passed)] = None) -> dict[str, str]:
    from src.workers.research.assistant import explain_exploit_class

    explanation = await explain_exploit_class(req.vuln_type)
    return {"vuln_type": req.vuln_type, "explanation": explanation}


@router.post("/compare")
async def compare(req: CompareRequest, _principal: Annotated[SessionPrincipal, Depends(require_admin_mfa_passed)] = None) -> dict[str, Any]:
    from src.workers.research.assistant import compare_models

    return compare_models(req.models, req.benchmark_results)
