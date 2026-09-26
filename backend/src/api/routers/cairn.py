"""Cairn REST API — Fact-Intent blackboard (Phase 3).

Thin router over :mod:`src.cairn.graph_service`; all validation lives in the service.
Tenant is taken from the authenticated principal (never the body); every request
runs ``set_session_tenant`` so Postgres RLS also enforces isolation.

Path parameters accept either the ARGUS UUID or the human ref (``proj_001`` /
``i001``) within the caller's tenant scope. Response ``id`` fields for graph nodes
carry the ref so ``from`` / ``to`` edges line up with upstream Cairn clients.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.cairn import graph_service as gs
from src.cairn.errors import CairnError, CairnNotFoundError
from src.cairn.export import export_timeline, export_yaml
from src.cairn.models import CairnIntent, CairnProject
from src.cairn.schemas import (
    CompleteRequest,
    ConcludeRequest,
    ConcludeResponse,
    CreateFactRequest,
    CreateHintRequest,
    CreateIntentRequest,
    CreateProjectRequest,
    Fact,
    HeartbeatRequest,
    Hint,
    Intent,
    ProjectDetail,
    ProjectMeta,
    ProjectReason,
    ProjectSummary,
    ReasonClaimRequest,
    ReopenRequest,
    ReopenResponse,
    Settings,
    UpdateProjectStatusRequest,
    UpdateProjectTitleRequest,
)
from src.core.tenant import get_current_tenant_id
from src.db.models import AuditLog
from src.db.session import async_session_factory, set_session_tenant

router = APIRouter(tags=["cairn"])


async def cairn_error_handler(_: Request, exc: CairnError) -> JSONResponse:
    """Translate domain errors into the upstream HTTP status codes."""
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


# --- resolution helpers (accept UUID or ref) ---------------------------------


async def _resolve_project_id(session: AsyncSession, tenant_id: str, id_or_ref: str) -> str:
    stmt = select(CairnProject.id).where(
        CairnProject.tenant_id == tenant_id,
        (CairnProject.id == id_or_ref) | (CairnProject.ref == id_or_ref),
    )
    pid = (await session.execute(stmt)).scalar_one_or_none()
    if pid is None:
        raise CairnNotFoundError("Project not found")
    return pid


async def _resolve_intent_id(
    session: AsyncSession, tenant_id: str, project_id: str, id_or_ref: str
) -> str:
    stmt = select(CairnIntent.id).where(
        CairnIntent.tenant_id == tenant_id,
        CairnIntent.project_id == project_id,
        (CairnIntent.id == id_or_ref) | (CairnIntent.ref == id_or_ref),
    )
    iid = (await session.execute(stmt)).scalar_one_or_none()
    if iid is None:
        raise CairnNotFoundError("Intent not found")
    return iid


async def _audit(
    session: AsyncSession,
    tenant_id: str,
    action: str,
    resource_id: str | None,
    details: dict[str, Any] | None = None,
) -> None:
    session.add(
        AuditLog(
            tenant_id=tenant_id,
            action=action,
            resource_type="cairn_project",
            resource_id=resource_id,
            details=details,
        )
    )


# --- mappers -----------------------------------------------------------------


def _fact_schema(fact) -> Fact:
    return Fact(
        id=fact.ref,
        description=fact.description,
        uuid=fact.id,
        evidence_refs=fact.evidence_refs,
        evidence_tier=fact.evidence_tier,
        finding_id=fact.finding_id,
    )


def _hint_schema(hint) -> Hint:
    return Hint(
        id=hint.ref,
        content=hint.content,
        creator=hint.creator,
        created_at=hint.created_at,
        uuid=hint.id,
    )


def _reason_schema(project: CairnProject) -> ProjectReason | None:
    if project.reason_worker is None:
        return None
    return ProjectReason(
        worker=project.reason_worker,
        trigger=project.reason_trigger,
        started_at=project.reason_started_at,
        last_heartbeat_at=project.reason_last_heartbeat_at,
    )


def _project_meta(project: CairnProject) -> ProjectMeta:
    return ProjectMeta(
        id=project.id,
        ref=project.ref,
        title=project.title,
        status=project.status,  # type: ignore[arg-type]
        bootstrap_enabled=project.bootstrap_enabled,
        created_at=project.created_at,
        reason=_reason_schema(project),
        scan_id=project.scan_id,
        execution_mode=project.execution_mode,
    )


def _intent_schema(intent: CairnIntent, from_refs: list[str], to_ref: str | None) -> Intent:
    return Intent.model_validate(
        {
            "id": intent.ref,
            "from": from_refs,
            "to": to_ref,
            "description": intent.description,
            "creator": intent.creator,
            "worker": intent.worker,
            "last_heartbeat_at": intent.last_heartbeat_at,
            "created_at": intent.created_at,
            "concluded_at": intent.concluded_at,
            "uuid": intent.id,
        }
    )


def _detail_schema(detail: gs.ProjectDetailResult) -> ProjectDetail:
    ref_by_uuid = {fact.id: fact.ref for fact in detail.facts}
    intents = []
    for intent in detail.intents:
        to_ref = ref_by_uuid.get(intent.to_fact_id) if intent.to_fact_id else None
        if intent.is_completion and to_ref is None:
            to_ref = "goal"
        intents.append(_intent_schema(intent, detail.intent_sources.get(intent.ref, []), to_ref))
    return ProjectDetail(
        project=_project_meta(detail.project),
        facts=[_fact_schema(f) for f in detail.facts],
        intents=intents,
        hints=[_hint_schema(h) for h in detail.hints],
    )


# --- projects ----------------------------------------------------------------


@router.get("/projects", response_model=list[ProjectSummary])
async def list_projects(
    tenant_id: str = Depends(get_current_tenant_id),
    status: str | None = Query(default=None),
) -> list[ProjectSummary]:
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        summaries = await gs.list_projects(session, tenant_id, status=status)
        await session.commit()
        return [
            ProjectSummary(
                **_project_meta(s.project).model_dump(),
                fact_count=s.counts.fact_count,
                intent_count=s.counts.intent_count,
                working_intent_count=s.counts.working_intent_count,
                unclaimed_intent_count=s.counts.unclaimed_intent_count,
                hint_count=s.counts.hint_count,
            )
            for s in summaries
        ]


@router.post("/projects", response_model=ProjectDetail, status_code=201)
async def create_project(
    body: CreateProjectRequest,
    tenant_id: str = Depends(get_current_tenant_id),
) -> ProjectDetail:
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        detail = await gs.create_project(
            session,
            tenant_id,
            title=body.title,
            origin=body.origin,
            goal=body.goal,
            bootstrap_enabled=body.bootstrap_enabled,
            hints=[(h.content, h.creator) for h in (body.hints or [])],
            scan_id=body.scan_id,
            execution_mode=body.execution_mode,
            options=body.options,
        )
        await _audit(session, tenant_id, "cairn.project.create", detail.project.id)
        await session.commit()
        return _detail_schema(detail)


@router.get("/projects/{project_id}", response_model=ProjectDetail)
async def get_project(
    project_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
) -> ProjectDetail:
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        pid = await _resolve_project_id(session, tenant_id, project_id)
        detail = await gs.get_project(session, tenant_id, pid)
        await session.commit()
        return _detail_schema(detail)


@router.delete("/projects/{project_id}", status_code=204)
async def delete_project(
    project_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
) -> Response:
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        pid = await _resolve_project_id(session, tenant_id, project_id)
        await gs.delete_project(session, tenant_id, pid)
        await _audit(session, tenant_id, "cairn.project.delete", pid)
        await session.commit()
        return Response(status_code=204)


@router.put("/projects/{project_id}/title", response_model=ProjectMeta)
async def update_title(
    project_id: str,
    body: UpdateProjectTitleRequest,
    tenant_id: str = Depends(get_current_tenant_id),
) -> ProjectMeta:
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        pid = await _resolve_project_id(session, tenant_id, project_id)
        project = await gs.update_project_title(session, tenant_id, pid, body.title)
        await session.commit()
        return _project_meta(project)


@router.put("/projects/{project_id}/status", response_model=ProjectMeta)
async def update_status(
    project_id: str,
    body: UpdateProjectStatusRequest,
    tenant_id: str = Depends(get_current_tenant_id),
) -> ProjectMeta:
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        pid = await _resolve_project_id(session, tenant_id, project_id)
        project = await gs.update_project_status(session, tenant_id, pid, body.status)
        await _audit(session, tenant_id, "cairn.project.status", pid, {"status": body.status})
        await session.commit()
        return _project_meta(project)


# --- reason lease ------------------------------------------------------------


@router.post("/projects/{project_id}/reason/claim", response_model=ProjectMeta)
async def claim_reason(
    project_id: str,
    body: ReasonClaimRequest,
    tenant_id: str = Depends(get_current_tenant_id),
) -> ProjectMeta:
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        pid = await _resolve_project_id(session, tenant_id, project_id)
        project = await gs.claim_reason(session, tenant_id, pid, body.worker, body.trigger)
        await session.commit()
        return _project_meta(project)


@router.post("/projects/{project_id}/reason/heartbeat", response_model=ProjectMeta)
async def heartbeat_reason(
    project_id: str,
    body: HeartbeatRequest,
    tenant_id: str = Depends(get_current_tenant_id),
) -> ProjectMeta:
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        pid = await _resolve_project_id(session, tenant_id, project_id)
        project = await gs.heartbeat_reason(session, tenant_id, pid, body.worker)
        await session.commit()
        return _project_meta(project)


@router.post("/projects/{project_id}/reason/release", response_model=ProjectMeta)
async def release_reason(
    project_id: str,
    body: HeartbeatRequest,
    tenant_id: str = Depends(get_current_tenant_id),
) -> ProjectMeta:
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        pid = await _resolve_project_id(session, tenant_id, project_id)
        project = await gs.release_reason(session, tenant_id, pid, body.worker)
        await session.commit()
        return _project_meta(project)


# --- complete / reopen -------------------------------------------------------


@router.post("/projects/{project_id}/complete", response_model=Intent)
async def complete_project(
    project_id: str,
    body: CompleteRequest,
    tenant_id: str = Depends(get_current_tenant_id),
) -> Intent:
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        pid = await _resolve_project_id(session, tenant_id, project_id)
        intent = await gs.complete_project(
            session,
            tenant_id,
            pid,
            from_refs=body.from_,
            description=body.description,
            worker=body.worker,
        )
        from_refs = await gs.intent_source_refs(session, intent.id)
        await _audit(session, tenant_id, "cairn.project.complete", pid)
        await session.commit()
        return _intent_schema(intent, from_refs, "goal")


@router.post("/projects/{project_id}/reopen", response_model=ReopenResponse)
async def reopen_project(
    project_id: str,
    body: ReopenRequest,
    tenant_id: str = Depends(get_current_tenant_id),
) -> ReopenResponse:
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        pid = await _resolve_project_id(session, tenant_id, project_id)
        result = await gs.reopen_project(
            session, tenant_id, pid, description=body.description, creator=body.creator
        )
        from_refs = await gs.intent_source_refs(session, result.intent.id)
        await _audit(session, tenant_id, "cairn.project.reopen", pid)
        await session.commit()
        return ReopenResponse(
            project=_project_meta(result.project),
            fact=_fact_schema(result.fact),
            intent=_intent_schema(result.intent, from_refs, result.fact.ref),
        )


# --- intents -----------------------------------------------------------------


@router.post("/projects/{project_id}/intents", response_model=Intent, status_code=201)
async def create_intent(
    project_id: str,
    body: CreateIntentRequest,
    tenant_id: str = Depends(get_current_tenant_id),
) -> Intent:
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        pid = await _resolve_project_id(session, tenant_id, project_id)
        intent = await gs.create_intent(
            session,
            tenant_id,
            pid,
            from_refs=body.from_,
            description=body.description,
            creator=body.creator,
            worker=body.worker,
        )
        await session.commit()
        return _intent_schema(intent, body.from_, None)


@router.post("/projects/{project_id}/intents/{intent_id}/heartbeat", response_model=Intent)
async def claim_intent(
    project_id: str,
    intent_id: str,
    body: HeartbeatRequest,
    tenant_id: str = Depends(get_current_tenant_id),
) -> Intent:
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        pid = await _resolve_project_id(session, tenant_id, project_id)
        iid = await _resolve_intent_id(session, tenant_id, pid, intent_id)
        intent = await gs.claim_intent(session, tenant_id, pid, iid, body.worker)
        from_refs = await gs.intent_source_refs(session, iid)
        await session.commit()
        return _intent_schema(intent, from_refs, None)


@router.post("/projects/{project_id}/intents/{intent_id}/release", response_model=Intent)
async def release_intent(
    project_id: str,
    intent_id: str,
    body: HeartbeatRequest,
    tenant_id: str = Depends(get_current_tenant_id),
) -> Intent:
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        pid = await _resolve_project_id(session, tenant_id, project_id)
        iid = await _resolve_intent_id(session, tenant_id, pid, intent_id)
        intent = await gs.release_intent(session, tenant_id, pid, iid, body.worker)
        from_refs = await gs.intent_source_refs(session, iid)
        await session.commit()
        return _intent_schema(intent, from_refs, None)


@router.post("/projects/{project_id}/intents/{intent_id}/conclude", response_model=ConcludeResponse)
async def conclude_intent(
    project_id: str,
    intent_id: str,
    body: ConcludeRequest,
    tenant_id: str = Depends(get_current_tenant_id),
) -> ConcludeResponse:
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        pid = await _resolve_project_id(session, tenant_id, project_id)
        iid = await _resolve_intent_id(session, tenant_id, pid, intent_id)
        result = await gs.conclude_intent(
            session,
            tenant_id,
            pid,
            iid,
            body.worker,
            body.description,
            evidence_refs=body.evidence_refs,
            evidence_tier=body.evidence_tier,
        )
        from_refs = await gs.intent_source_refs(session, iid)
        await session.commit()
        return ConcludeResponse(
            fact=_fact_schema(result.fact),
            intent=_intent_schema(result.intent, from_refs, result.fact.ref),
        )


# --- hints / facts -----------------------------------------------------------


@router.post("/projects/{project_id}/hints", response_model=Hint, status_code=201)
async def create_hint(
    project_id: str,
    body: CreateHintRequest,
    tenant_id: str = Depends(get_current_tenant_id),
) -> Hint:
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        pid = await _resolve_project_id(session, tenant_id, project_id)
        hint = await gs.create_hint(
            session,
            tenant_id,
            pid,
            content=body.content,
            creator=body.creator,
            author_user_id=body.author_user_id,
        )
        await _audit(session, tenant_id, "cairn.hint.create", pid)
        await session.commit()
        return _hint_schema(hint)


@router.post("/projects/{project_id}/facts", response_model=Fact, status_code=201)
async def create_fact(
    project_id: str,
    body: CreateFactRequest,
    tenant_id: str = Depends(get_current_tenant_id),
) -> Fact:
    """Human adds an external-feedback fact directly (ARGUS §5.2)."""
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        pid = await _resolve_project_id(session, tenant_id, project_id)
        # Reuse reopen semantics is not desired here; add a standalone fact.
        from src.cairn.ids import next_fact_ref
        from src.cairn.models import CairnFact

        ref = await next_fact_ref(session, tenant_id, pid)
        fact = CairnFact(
            ref=ref,
            tenant_id=tenant_id,
            project_id=pid,
            description=body.description,
            created_by="human",
            source_task_type="external",
            evidence_refs=body.evidence_refs or [],
        )
        session.add(fact)
        await _audit(session, tenant_id, "cairn.fact.create", pid)
        await session.commit()
        return _fact_schema(fact)


# --- settings ----------------------------------------------------------------


class _WorkerCreate(BaseModel):
    name: str
    type: str = "wrb"
    task_types: list[str] = Field(default_factory=lambda: ["reason", "explore"])
    max_running: int = 1
    priority: int = 100
    enabled: bool = True


class _WorkerPatch(BaseModel):
    task_types: list[str] | None = None
    max_running: int | None = None
    priority: int | None = None
    enabled: bool | None = None


def _worker_dict(w) -> dict[str, Any]:
    return {
        "id": w.id,
        "name": w.name,
        "type": w.type,
        "task_types": w.task_types,
        "max_running": w.max_running,
        "priority": w.priority,
        "enabled": w.enabled,
    }


@router.get("/workers")
async def list_workers(tenant_id: str = Depends(get_current_tenant_id)) -> list[dict[str, Any]]:
    from src.cairn.workers.models import CairnWorker

    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        rows = (
            (
                await session.execute(
                    select(CairnWorker)
                    .where(CairnWorker.tenant_id == tenant_id)
                    .order_by(CairnWorker.priority)
                )
            )
            .scalars()
            .all()
        )
        await session.commit()
        return [_worker_dict(w) for w in rows]


@router.post("/workers", status_code=201)
async def create_worker(
    body: _WorkerCreate, tenant_id: str = Depends(get_current_tenant_id)
) -> dict[str, Any]:
    from src.cairn.workers.models import WORKER_TYPES, CairnWorker

    if body.type not in WORKER_TYPES:
        raise HTTPException(status_code=422, detail=f"type must be one of {WORKER_TYPES}")
    if not body.task_types:
        raise HTTPException(status_code=422, detail="task_types must not be empty")
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        worker = CairnWorker(
            tenant_id=tenant_id,
            name=body.name,
            type=body.type,
            task_types=body.task_types,
            max_running=body.max_running,
            priority=body.priority,
            enabled=body.enabled,
        )
        session.add(worker)
        await _audit(session, tenant_id, "cairn.worker.create", worker.id, {"name": body.name})
        await session.commit()
        return _worker_dict(worker)


@router.patch("/workers/{worker_id}")
async def update_worker(
    worker_id: str, body: _WorkerPatch, tenant_id: str = Depends(get_current_tenant_id)
) -> dict[str, Any]:
    from src.cairn.workers.models import CairnWorker

    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        worker = (
            await session.execute(
                select(CairnWorker).where(
                    CairnWorker.tenant_id == tenant_id, CairnWorker.id == worker_id
                )
            )
        ).scalar_one_or_none()
        if worker is None:
            raise HTTPException(status_code=404, detail="Worker not found")
        if body.task_types is not None:
            if not body.task_types:
                raise HTTPException(status_code=422, detail="task_types must not be empty")
            worker.task_types = body.task_types
        if body.max_running is not None:
            worker.max_running = body.max_running
        if body.priority is not None:
            worker.priority = body.priority
        if body.enabled is not None:
            worker.enabled = body.enabled
        await session.commit()
        return _worker_dict(worker)


@router.delete("/workers/{worker_id}", status_code=204)
async def delete_worker(
    worker_id: str, tenant_id: str = Depends(get_current_tenant_id)
) -> Response:
    from src.cairn.workers.models import CairnWorker

    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        worker = (
            await session.execute(
                select(CairnWorker).where(
                    CairnWorker.tenant_id == tenant_id, CairnWorker.id == worker_id
                )
            )
        ).scalar_one_or_none()
        if worker is None:
            raise HTTPException(status_code=404, detail="Worker not found")
        await session.delete(worker)
        await _audit(session, tenant_id, "cairn.worker.delete", worker_id)
        await session.commit()
        return Response(status_code=204)


@router.get("/settings", response_model=Settings)
async def get_settings(
    tenant_id: str = Depends(get_current_tenant_id),
) -> Settings:
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        row = await gs.get_settings(session, tenant_id)
        await session.commit()
        return Settings(
            intent_timeout=row.intent_timeout,
            reason_timeout=row.reason_timeout,
            max_intents=row.max_intents,
            max_workers=row.max_workers,
            max_running_projects=row.max_running_projects,
            max_project_workers=row.max_project_workers,
            tick_interval_sec=row.tick_interval_sec,
        )


@router.put("/settings", response_model=Settings)
async def update_settings(
    body: Settings,
    tenant_id: str = Depends(get_current_tenant_id),
) -> Settings:
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        row = await gs.update_settings(
            session,
            tenant_id,
            intent_timeout=body.intent_timeout,
            reason_timeout=body.reason_timeout,
            max_intents=body.max_intents,
            max_workers=body.max_workers,
            max_running_projects=body.max_running_projects,
            max_project_workers=body.max_project_workers,
            tick_interval_sec=body.tick_interval_sec,
        )
        await session.commit()
        return Settings(
            intent_timeout=row.intent_timeout,
            reason_timeout=row.reason_timeout,
            max_intents=row.max_intents,
            max_workers=row.max_workers,
            max_running_projects=row.max_running_projects,
            max_project_workers=row.max_project_workers,
            tick_interval_sec=row.tick_interval_sec,
        )


# --- export ------------------------------------------------------------------


@router.get("/projects/{project_id}/directives")
async def list_directives(
    project_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
) -> list[dict[str, Any]]:
    from src.cairn.directives.models import CairnDirective

    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        pid = await _resolve_project_id(session, tenant_id, project_id)
        rows = (
            (
                await session.execute(
                    select(CairnDirective)
                    .where(CairnDirective.project_id == pid)
                    .order_by(CairnDirective.priority_score.desc())
                )
            )
            .scalars()
            .all()
        )
        await session.commit()
        return [
            {
                "id": d.id,
                "ref": d.ref,
                "kind": d.kind,
                "title": d.title,
                "directive_text": d.directive_text,
                "focus": d.focus,
                "success_criterion": d.success_criterion,
                "proof_requirement": d.proof_requirement,
                "intrusiveness": d.intrusiveness,
                "priority_score": d.priority_score,
                "status": d.status,
                "intent_id": d.intent_id,
            }
            for d in rows
        ]


async def _get_directive_or_404(session: AsyncSession, tenant_id: str, project_id: str, did: str):
    from src.cairn.directives.models import CairnDirective

    row = (
        await session.execute(
            select(CairnDirective).where(
                CairnDirective.tenant_id == tenant_id,
                CairnDirective.project_id == project_id,
                (CairnDirective.id == did) | (CairnDirective.ref == did),
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise CairnNotFoundError("Directive not found")
    return row


@router.post("/projects/{project_id}/directives/{directive_id}/accept", response_model=Intent)
async def accept_directive(
    project_id: str,
    directive_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
) -> Intent:
    """Accept a directive → create a Cairn intent from it (§18.8)."""
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        pid = await _resolve_project_id(session, tenant_id, project_id)
        directive = await _get_directive_or_404(session, tenant_id, pid, directive_id)
        from_refs = list((directive.basis or {}).get("fact_refs") or []) or ["origin"]
        intent = await gs.create_intent(
            session,
            tenant_id,
            pid,
            from_refs=from_refs,
            description=directive.directive_text,
            creator="directive",
        )
        directive.status = "accepted"
        directive.intent_id = intent.id
        source_refs = await gs.intent_source_refs(session, intent.id)
        await _audit(
            session, tenant_id, "cairn.directive.accept", pid, {"directive": directive.ref}
        )
        await session.commit()
        return _intent_schema(intent, source_refs, None)


@router.post("/projects/{project_id}/directives/{directive_id}/reject", status_code=204)
async def reject_directive(
    project_id: str,
    directive_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
) -> Response:
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        pid = await _resolve_project_id(session, tenant_id, project_id)
        directive = await _get_directive_or_404(session, tenant_id, pid, directive_id)
        directive.status = "rejected"
        await _audit(
            session, tenant_id, "cairn.directive.reject", pid, {"directive": directive.ref}
        )
        await session.commit()
        return Response(status_code=204)


@router.get("/projects/{project_id}/directives/{directive_id}/export")
async def export_directive(
    project_id: str,
    directive_id: str,
    format: str = Query(default="text"),
    tenant_id: str = Depends(get_current_tenant_id),
) -> Response:
    """Return the raw directive text, ready to paste into an external agent (§18.8)."""
    if format != "text":
        raise HTTPException(status_code=400, detail="Supported format: text")
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        pid = await _resolve_project_id(session, tenant_id, project_id)
        directive = await _get_directive_or_404(session, tenant_id, pid, directive_id)
        await session.commit()
        return Response(content=directive.directive_text, media_type="text/plain")


@router.get("/projects/{project_id}/export")
async def export_project(
    project_id: str,
    format: str = Query(default="yaml"),
    tenant_id: str = Depends(get_current_tenant_id),
) -> Response:
    if format not in ("yaml", "timeline"):
        raise HTTPException(status_code=400, detail="Supported formats: yaml, timeline")
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        pid = await _resolve_project_id(session, tenant_id, project_id)
        detail = await gs.get_project(session, tenant_id, pid)
        await session.commit()
    text = export_timeline(detail) if format == "timeline" else export_yaml(detail)
    return Response(content=text, media_type="text/plain")
