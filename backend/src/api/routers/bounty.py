"""Bug Bounty Planner API — scope ingestion, surface classification, test plan generation."""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import String, cast, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.bounty.scope_ingester import ingest_scope
from src.bounty.surface_classifier import classify_surfaces
from src.bounty.vuln_prioritizer import prioritize_vulns
from src.bounty.test_planner import generate_test_plan
from src.bounty.schemas import BountyScope, BountyTestPlan, ScopeIngestRequest
from src.core.tenant import get_current_tenant_id
from src.db.session import async_session_factory, set_session_tenant

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/bounty", tags=["bounty"])


class BountyProgramCreate(BaseModel):
    name: str = Field(..., description="Program name")
    platform: str = Field(default="private", description="hackerone | bugcrowd | intigriti | private")
    scope_config: dict[str, Any] = Field(default_factory=dict)
    reward_range: str | None = None


class BountyProgramResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    platform: str
    status: str
    scope_config: dict[str, Any] = {}
    reward_range: str | None = None


class BountyPlanResponse(BaseModel):
    plan: BountyTestPlan
    program_id: str | None = None


class BountyLaunchRequest(BaseModel):
    phase_index: int = Field(default=0, description="Index of the plan phase to launch")
    scan_options: dict[str, Any] = Field(default_factory=dict)


class BountyLaunchResponse(BaseModel):
    message: str
    phase_name: str
    scan_options: dict[str, Any] = {}
    surfaces: list[str] = []


async def _get_session():
    session = async_session_factory()
    try:
        yield session
    finally:
        await session.close()


@router.post("/ingest", response_model=BountyScope)
async def ingest_bounty_scope(
    request: ScopeIngestRequest,
    tenant_id: str = Depends(get_current_tenant_id),
) -> BountyScope:
    """Parse bug bounty scope from JSON, raw text, or platform slug."""
    return ingest_scope(request)


@router.post("/plan", response_model=BountyPlanResponse)
async def generate_bounty_plan(
    request: ScopeIngestRequest,
    tenant_id: str = Depends(get_current_tenant_id),
) -> BountyPlanResponse:
    """Generate a phased test plan from bug bounty scope."""
    scope = ingest_scope(request)
    surfaces = classify_surfaces(scope)
    prioritized = prioritize_vulns(scope)
    plan = generate_test_plan(scope, surfaces, prioritized)

    try:
        from src.bounty.bounty_insights import generate_bounty_insights
        plan.llm_insights = await generate_bounty_insights(scope, surfaces, prioritized)
    except Exception as exc:
        logger.warning("bounty_insights_generation_failed: %s", exc)
        plan.llm_insights = None

    return BountyPlanResponse(plan=plan)


@router.get("/programs", response_model=list[BountyProgramResponse])
async def list_bounty_programs(
    tenant_id: str = Depends(get_current_tenant_id),
    session: AsyncSession = Depends(_get_session),
) -> list[BountyProgramResponse]:
    """List saved bounty programs for the tenant."""
    set_session_tenant(session, tenant_id)

    try:
        from src.db.models import BountyProgram
        result = await session.execute(
            select(BountyProgram).where(
                cast(BountyProgram.tenant_id, String) == tenant_id,
            )
        )
        programs = result.scalars().all()
    except Exception:
        programs = []

    return [
        BountyProgramResponse(
            id=str(p.id),
            tenant_id=str(p.tenant_id),
            name=p.name,
            platform=p.platform,
            status=getattr(p, "status", "draft"),
            scope_config=getattr(p, "scope_config", {}) or {},
            reward_range=getattr(p, "reward_range", None),
        )
        for p in programs
    ]


@router.post("/programs", response_model=BountyProgramResponse, status_code=status.HTTP_201_CREATED)
async def create_bounty_program(
    request: BountyProgramCreate,
    tenant_id: str = Depends(get_current_tenant_id),
    session: AsyncSession = Depends(_get_session),
) -> BountyProgramResponse:
    """Create a new bounty program."""
    set_session_tenant(session, tenant_id)

    try:
        from src.db.models import BountyProgram
        from src.core.database import gen_uuid

        program = BountyProgram(
            id=gen_uuid(),
            tenant_id=tenant_id,
            name=request.name,
            platform=request.platform,
            scope_config=request.scope_config,
            reward_range=request.reward_range,
            status="draft",
        )
        session.add(program)
        await session.commit()
        await session.refresh(program)

        return BountyProgramResponse(
            id=str(program.id),
            tenant_id=str(program.tenant_id),
            name=program.name,
            platform=program.platform,
            status=program.status,
            scope_config=program.scope_config or {},
            reward_range=program.reward_range,
        )
    except Exception as exc:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create bounty program: {exc}",
        )


@router.post("/programs/{program_id}/launch", response_model=BountyLaunchResponse)
async def launch_bounty_scan(
    program_id: UUID,
    request: BountyLaunchRequest,
    tenant_id: str = Depends(get_current_tenant_id),
    session: AsyncSession = Depends(_get_session),
) -> BountyLaunchResponse:
    """Launch a scan from a specific phase of the bounty test plan."""
    set_session_tenant(session, tenant_id)

    try:
        from src.db.models import BountyProgram
        result = await session.execute(
            select(BountyProgram).where(
                cast(BountyProgram.id, String) == str(program_id),
                cast(BountyProgram.tenant_id, String) == tenant_id,
            )
        )
        program = result.scalar_one_or_none()
    except Exception:
        program = None

    if program is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Bounty program {program_id} not found",
        )

    scope = BountyScope(
        program_name=program.name,
        platform=program.platform,
        reward_range=getattr(program, "reward_range", "") or "",
    )
    scope_config = getattr(program, "scope_config", {}) or {}
    if scope_config:
        scope.in_scope = scope_config.get("in_scope", [])
        scope.out_of_scope = scope_config.get("out_of_scope", [])

    surfaces = classify_surfaces(scope)
    prioritized = prioritize_vulns(scope)
    plan = generate_test_plan(scope, surfaces, prioritized)

    if not plan.phases:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No test phases generated for this program scope",
        )

    phase_idx = min(request.phase_index, len(plan.phases) - 1)
    phase = plan.phases[phase_idx]

    return BountyLaunchResponse(
        message=f"Phase '{phase.name}' ready for scan launch",
        phase_name=phase.name,
        scan_options={**phase.recommended_scan_options, **request.scan_options},
        surfaces=phase.surfaces,
    )