"""Async graph service — the Cairn protocol invariants ported onto Postgres.

Ports ``_external/Cairn/cairn/src/cairn/server/{services,routers/*}.py`` (AGPL-3.0)
into a single async service layer. All validation lives here; the Phase 3 router is
thin. Two deliberate deviations from upstream (documented in
``docs/cairn_port_deviations.md``):

  * **Tenancy** — every query is tenant-scoped; callers must have run
    ``set_session_tenant`` so Postgres RLS also enforces isolation.
  * **Concurrency** — upstream relies on a single-writer dispatcher. Here mutating
    operations take ``SELECT ... FOR UPDATE`` on the project row (reason / complete /
    reopen / status) or the intent row (claim / conclude), and every successful claim
    bumps a ``fence_token`` so a stale worker's ``conclude`` is rejected (409).

Facts and intents are addressed in graph semantics by their human ref
(``origin`` / ``goal`` / ``f001`` / ``i001``); rows are keyed by UUID. ``from`` edges
are given as refs. The upstream ``to_fact_id == 'goal'`` completion sentinel becomes
the ``CairnIntent.is_completion`` boolean.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.cairn.errors import (
    CairnConflictError,
    CairnForbiddenError,
    CairnNotFoundError,
    CairnValidationError,
)
from src.cairn.ids import (
    next_fact_ref,
    next_hint_ref,
    next_intent_ref,
    next_project_ref,
)
from src.cairn.models import (
    CairnFact,
    CairnHint,
    CairnIntent,
    CairnIntentSource,
    CairnProject,
    CairnSettings,
)
from src.cairn.schemas import (
    BOOTSTRAP_CREATOR,
    GOAL_REF,
    ORIGIN_REF,
)


def _utcnow() -> datetime:
    return datetime.now(UTC)


# --- composite result containers (Phase 3 maps these to Pydantic) -------------


@dataclass(slots=True)
class ProjectReasonInfo:
    worker: str
    trigger: str | None
    started_at: datetime | None
    last_heartbeat_at: datetime | None


@dataclass(slots=True)
class ProjectCounts:
    fact_count: int = 0
    intent_count: int = 0
    working_intent_count: int = 0
    unclaimed_intent_count: int = 0
    hint_count: int = 0


@dataclass(slots=True)
class ProjectSummaryResult:
    project: CairnProject
    counts: ProjectCounts


@dataclass(slots=True)
class ProjectDetailResult:
    project: CairnProject
    facts: list[CairnFact] = field(default_factory=list)
    intents: list[CairnIntent] = field(default_factory=list)
    hints: list[CairnHint] = field(default_factory=list)
    # ref -> ordered list of source refs, so the router can render ``from`` edges.
    intent_sources: dict[str, list[str]] = field(default_factory=dict)


@dataclass(slots=True)
class ConcludeResult:
    fact: CairnFact
    intent: CairnIntent


@dataclass(slots=True)
class ReopenResult:
    project: CairnProject
    fact: CairnFact
    intent: CairnIntent


# --- settings ----------------------------------------------------------------


async def get_settings(session: AsyncSession, tenant_id: str) -> CairnSettings:
    """Return the tenant's Cairn settings, creating the default row if absent.

    Race-safe: many concurrent workers may hit this at once (each ``claim`` calls
    ``expire_workers`` which needs settings), so the default row is created with
    ``INSERT ... ON CONFLICT DO NOTHING`` rather than a plain insert.
    """
    row = await session.get(CairnSettings, tenant_id)
    if row is not None:
        return row
    await session.execute(
        text(
            "INSERT INTO cairn_settings (tenant_id) VALUES (:tid) "
            "ON CONFLICT (tenant_id) DO NOTHING"
        ),
        {"tid": tenant_id},
    )
    await session.flush()
    row = await session.get(CairnSettings, tenant_id)
    if row is None:  # pragma: no cover - defensive, row was just upserted
        raise CairnConflictError("Failed to initialise Cairn settings")
    return row


async def update_settings(session: AsyncSession, tenant_id: str, **fields: int) -> CairnSettings:
    row = await get_settings(session, tenant_id)
    for key, value in fields.items():
        if value is None:
            continue
        if key in ("intent_timeout", "reason_timeout") and value < 5:
            raise CairnValidationError(f"{key} must be >= 5")
        setattr(row, key, value)
    await session.flush()
    return row


# --- lookups -----------------------------------------------------------------


async def _get_project_or_404(
    session: AsyncSession, tenant_id: str, project_id: str, *, for_update: bool = False
) -> CairnProject:
    stmt = select(CairnProject).where(
        CairnProject.id == project_id, CairnProject.tenant_id == tenant_id
    )
    if for_update:
        stmt = stmt.with_for_update()
    row = (await session.execute(stmt)).scalar_one_or_none()
    if row is None:
        raise CairnNotFoundError("Project not found")
    return row


async def _fact_by_ref(
    session: AsyncSession, tenant_id: str, project_id: str, ref: str
) -> CairnFact | None:
    stmt = select(CairnFact).where(
        CairnFact.project_id == project_id,
        CairnFact.tenant_id == tenant_id,
        CairnFact.ref == ref,
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def _resolve_from_facts(
    session: AsyncSession, tenant_id: str, project_id: str, from_refs: list[str]
) -> list[CairnFact]:
    """Validate that every ``from`` ref exists; return facts in given order.

    Mirrors ``validate_facts_exist`` (404) + ``validate_goal_not_in_sources`` (400).
    """
    if GOAL_REF in from_refs:
        raise CairnValidationError("goal cannot be used in from")
    facts: list[CairnFact] = []
    for ref in from_refs:
        fact = await _fact_by_ref(session, tenant_id, project_id, ref)
        if fact is None:
            raise CairnNotFoundError(f"Fact {ref} not found")
        facts.append(fact)
    return facts


async def _intent_for_update(
    session: AsyncSession, tenant_id: str, project_id: str, intent_id: str
) -> CairnIntent:
    stmt = (
        select(CairnIntent)
        .where(
            CairnIntent.id == intent_id,
            CairnIntent.project_id == project_id,
            CairnIntent.tenant_id == tenant_id,
        )
        .with_for_update()
    )
    row = (await session.execute(stmt)).scalar_one_or_none()
    if row is None:
        raise CairnNotFoundError("Intent not found")
    return row


async def intent_source_refs(session: AsyncSession, intent_id: str) -> list[str]:
    """Public accessor for an intent's ordered ``from`` source refs."""
    return await _source_refs(session, intent_id)


async def _source_refs(session: AsyncSession, intent_id: str) -> list[str]:
    stmt = (
        select(CairnFact.ref)
        .join(CairnIntentSource, CairnIntentSource.fact_id == CairnFact.id)
        .where(CairnIntentSource.intent_id == intent_id)
        .order_by(CairnIntentSource.position)
    )
    return [r for (r,) in (await session.execute(stmt)).all()]


# --- expiration (called before sensitive ops, upstream S-23) -----------------


async def expire_workers(
    session: AsyncSession, tenant_id: str, project_id: str | None = None
) -> int:
    """Release claims on open intents whose heartbeat is older than intent_timeout."""
    settings = await get_settings(session, tenant_id)
    cutoff = _utcnow() - timedelta(seconds=settings.intent_timeout)
    stmt = (
        update(CairnIntent)
        .where(
            CairnIntent.tenant_id == tenant_id,
            CairnIntent.to_fact_id.is_(None),
            CairnIntent.worker.is_not(None),
            CairnIntent.last_heartbeat_at.is_not(None),
            CairnIntent.last_heartbeat_at < cutoff,
        )
        .values(worker=None)
    )
    if project_id is not None:
        stmt = stmt.where(CairnIntent.project_id == project_id)
    result = await session.execute(stmt)
    return int(result.rowcount or 0)


async def expire_reason_leases(
    session: AsyncSession, tenant_id: str, project_id: str | None = None
) -> int:
    """Clear reason-leases whose heartbeat is older than reason_timeout."""
    settings = await get_settings(session, tenant_id)
    cutoff = _utcnow() - timedelta(seconds=settings.reason_timeout)
    stmt = (
        update(CairnProject)
        .where(
            CairnProject.tenant_id == tenant_id,
            CairnProject.reason_worker.is_not(None),
            CairnProject.reason_last_heartbeat_at.is_not(None),
            CairnProject.reason_last_heartbeat_at < cutoff,
        )
        .values(
            reason_worker=None,
            reason_trigger=None,
            reason_started_at=None,
            reason_last_heartbeat_at=None,
        )
    )
    if project_id is not None:
        stmt = stmt.where(CairnProject.id == project_id)
    result = await session.execute(stmt)
    return int(result.rowcount or 0)


def _clear_reason(project: CairnProject) -> None:
    project.reason_worker = None
    project.reason_trigger = None
    project.reason_started_at = None
    project.reason_last_heartbeat_at = None


# --- projects ----------------------------------------------------------------


async def create_project(
    session: AsyncSession,
    tenant_id: str,
    *,
    title: str,
    origin: str,
    goal: str,
    bootstrap_enabled: bool = True,
    hints: list[tuple[str, str]] | None = None,
    scan_id: str | None = None,
    execution_mode: str = "production",
    options: dict | None = None,
) -> ProjectDetailResult:
    """Create a project with its ``origin`` and ``goal`` facts and any inline hints.

    ``hints`` is a list of ``(content, creator)`` pairs.
    """
    ref = await next_project_ref(session, tenant_id)
    project = CairnProject(
        ref=ref,
        tenant_id=tenant_id,
        title=title,
        status="active",
        bootstrap_enabled=bootstrap_enabled,
        execution_mode=execution_mode,
        scan_id=scan_id,
        options=options or {},
    )
    session.add(project)
    await session.flush()

    origin_fact = CairnFact(
        ref=ORIGIN_REF,
        tenant_id=tenant_id,
        project_id=project.id,
        description=origin,
        created_by="system",
        source_task_type="external",
    )
    goal_fact = CairnFact(
        ref=GOAL_REF,
        tenant_id=tenant_id,
        project_id=project.id,
        description=goal,
        created_by="system",
        source_task_type="external",
    )
    session.add_all([origin_fact, goal_fact])
    await session.flush()
    project.origin_fact_id = origin_fact.id
    project.goal_fact_id = goal_fact.id

    created_hints: list[CairnHint] = []
    for content, creator in hints or []:
        hint_ref = await next_hint_ref(session, tenant_id, project.id)
        hint = CairnHint(
            ref=hint_ref,
            tenant_id=tenant_id,
            project_id=project.id,
            content=content,
            creator=creator,
        )
        session.add(hint)
        created_hints.append(hint)
    await session.flush()

    return ProjectDetailResult(
        project=project,
        facts=[origin_fact, goal_fact],
        intents=[],
        hints=created_hints,
        intent_sources={},
    )


async def list_projects(
    session: AsyncSession, tenant_id: str, *, status: str | None = None
) -> list[ProjectSummaryResult]:
    await expire_workers(session, tenant_id)
    await expire_reason_leases(session, tenant_id)
    stmt = select(CairnProject).where(CairnProject.tenant_id == tenant_id)
    if status is not None:
        stmt = stmt.where(CairnProject.status == status)
    stmt = stmt.order_by(CairnProject.created_at)
    projects = list((await session.execute(stmt)).scalars().all())

    results: list[ProjectSummaryResult] = []
    for project in projects:
        counts = await _project_counts(session, project.id)
        results.append(ProjectSummaryResult(project=project, counts=counts))
    return results


async def _project_counts(session: AsyncSession, project_id: str) -> ProjectCounts:
    fact_count = (
        await session.execute(
            select(func.count()).select_from(CairnFact).where(CairnFact.project_id == project_id)
        )
    ).scalar_one()
    intent_count = (
        await session.execute(
            select(func.count())
            .select_from(CairnIntent)
            .where(CairnIntent.project_id == project_id)
        )
    ).scalar_one()
    working = (
        await session.execute(
            select(func.count())
            .select_from(CairnIntent)
            .where(
                CairnIntent.project_id == project_id,
                CairnIntent.concluded_at.is_(None),
                CairnIntent.worker.is_not(None),
            )
        )
    ).scalar_one()
    unclaimed = (
        await session.execute(
            select(func.count())
            .select_from(CairnIntent)
            .where(
                CairnIntent.project_id == project_id,
                CairnIntent.concluded_at.is_(None),
                CairnIntent.worker.is_(None),
            )
        )
    ).scalar_one()
    hint_count = (
        await session.execute(
            select(func.count()).select_from(CairnHint).where(CairnHint.project_id == project_id)
        )
    ).scalar_one()
    return ProjectCounts(
        fact_count=int(fact_count),
        intent_count=int(intent_count),
        working_intent_count=int(working),
        unclaimed_intent_count=int(unclaimed),
        hint_count=int(hint_count),
    )


async def get_project(
    session: AsyncSession, tenant_id: str, project_id: str
) -> ProjectDetailResult:
    await expire_workers(session, tenant_id, project_id)
    await expire_reason_leases(session, tenant_id, project_id)
    project = await _get_project_or_404(session, tenant_id, project_id)

    facts = list(
        (await session.execute(select(CairnFact).where(CairnFact.project_id == project_id)))
        .scalars()
        .all()
    )
    intents = list(
        (
            await session.execute(
                select(CairnIntent)
                .where(CairnIntent.project_id == project_id)
                .order_by(CairnIntent.created_at)
            )
        )
        .scalars()
        .all()
    )
    hints = list(
        (
            await session.execute(
                select(CairnHint)
                .where(CairnHint.project_id == project_id)
                .order_by(CairnHint.created_at)
            )
        )
        .scalars()
        .all()
    )
    sources = {intent.ref: await _source_refs(session, intent.id) for intent in intents}
    return ProjectDetailResult(
        project=project, facts=facts, intents=intents, hints=hints, intent_sources=sources
    )


async def delete_project(session: AsyncSession, tenant_id: str, project_id: str) -> None:
    project = await _get_project_or_404(session, tenant_id, project_id)
    await session.delete(project)
    await session.flush()


async def update_project_title(
    session: AsyncSession, tenant_id: str, project_id: str, title: str
) -> CairnProject:
    project = await _get_project_or_404(session, tenant_id, project_id)
    project.title = title
    await session.flush()
    return project


async def update_project_status(
    session: AsyncSession, tenant_id: str, project_id: str, status: str
) -> CairnProject:
    await expire_reason_leases(session, tenant_id, project_id)
    project = await _get_project_or_404(session, tenant_id, project_id, for_update=True)
    if project.status == "completed":
        raise CairnConflictError("Completed projects cannot change status")
    if project.status == status:
        return project
    if status not in ("active", "stopped", "completed"):
        raise CairnValidationError(f"invalid status {status}")
    project.status = status
    if status == "stopped":
        await session.execute(
            update(CairnIntent)
            .where(
                CairnIntent.project_id == project_id,
                CairnIntent.concluded_at.is_(None),
            )
            .values(worker=None)
        )
        _clear_reason(project)
    await session.flush()
    return project


# --- intents -----------------------------------------------------------------


async def _check_active(
    session: AsyncSession, tenant_id: str, project_id: str, *, for_update: bool = False
) -> CairnProject:
    project = await _get_project_or_404(session, tenant_id, project_id, for_update=for_update)
    if project.status != "active":
        raise CairnForbiddenError(f"Project is {project.status}")
    return project


async def _add_intent_sources(
    session: AsyncSession, tenant_id: str, intent_id: str, facts: list[CairnFact]
) -> None:
    for position, fact in enumerate(facts):
        session.add(
            CairnIntentSource(
                intent_id=intent_id,
                fact_id=fact.id,
                tenant_id=tenant_id,
                position=position,
            )
        )
    await session.flush()


async def create_intent(
    session: AsyncSession,
    tenant_id: str,
    project_id: str,
    *,
    from_refs: list[str],
    description: str,
    creator: str,
    worker: str | None = None,
) -> CairnIntent:
    await _check_active(session, tenant_id, project_id)
    facts = await _resolve_from_facts(session, tenant_id, project_id, from_refs)
    if worker is not None and worker != creator:
        raise CairnValidationError("worker must be null or equal to creator")

    now = _utcnow()
    ref = await next_intent_ref(session, tenant_id, project_id)
    intent = CairnIntent(
        ref=ref,
        tenant_id=tenant_id,
        project_id=project_id,
        to_fact_id=None,
        description=description,
        creator=creator,
        worker=worker,
        last_heartbeat_at=now if worker is not None else None,
    )
    session.add(intent)
    await session.flush()
    await _add_intent_sources(session, tenant_id, intent.id, facts)
    return intent


async def claim_intent(
    session: AsyncSession,
    tenant_id: str,
    project_id: str,
    intent_id: str,
    worker: str,
) -> CairnIntent:
    """Claim / heartbeat an open intent (upstream S-15). Bumps the fence token."""
    await _check_active(session, tenant_id, project_id)
    await expire_workers(session, tenant_id, project_id)
    intent = await _intent_for_update(session, tenant_id, project_id, intent_id)
    if intent.to_fact_id is not None:
        raise CairnConflictError("Intent already concluded")
    if intent.worker is not None and intent.worker != worker:
        raise CairnConflictError(f"Intent is currently claimed by {intent.worker}")
    intent.worker = worker
    intent.last_heartbeat_at = _utcnow()
    intent.fence_token += 1
    await session.flush()
    return intent


async def release_intent(
    session: AsyncSession,
    tenant_id: str,
    project_id: str,
    intent_id: str,
    worker: str,
) -> CairnIntent:
    """Release a claim; idempotent if already free (upstream S-16)."""
    await _check_active(session, tenant_id, project_id)
    await expire_workers(session, tenant_id, project_id)
    intent = await _intent_for_update(session, tenant_id, project_id, intent_id)
    if intent.to_fact_id is not None:
        raise CairnConflictError("Intent already concluded")
    if intent.worker is None:
        return intent
    if intent.worker != worker:
        raise CairnConflictError(f"Intent is currently claimed by {intent.worker}")
    intent.worker = None
    await session.flush()
    return intent


async def conclude_intent(
    session: AsyncSession,
    tenant_id: str,
    project_id: str,
    intent_id: str,
    worker: str,
    description: str,
    *,
    evidence_refs: list | None = None,
    evidence_tier: int | None = None,
    fence_token: int | None = None,
    source_task_type: str = "explore",
) -> ConcludeResult:
    """Conclude an open intent — creates a Fact and closes the edge (upstream S-17).

    If ``fence_token`` is provided it must match the intent's current token, else a
    stale worker is rejected (409).
    """
    await _check_active(session, tenant_id, project_id)
    intent = await _intent_for_update(session, tenant_id, project_id, intent_id)
    if intent.to_fact_id is not None:
        raise CairnConflictError("Intent already concluded")
    if intent.worker is not None and intent.worker != worker:
        raise CairnConflictError(f"Intent is currently claimed by {intent.worker}")
    if fence_token is not None and fence_token != intent.fence_token:
        raise CairnConflictError("Stale fence token")

    now = _utcnow()
    ref = await next_fact_ref(session, tenant_id, project_id)
    fact = CairnFact(
        ref=ref,
        tenant_id=tenant_id,
        project_id=project_id,
        description=description,
        created_by=worker,
        source_task_type=source_task_type,
        evidence_refs=evidence_refs or [],
        evidence_tier=evidence_tier,
    )
    session.add(fact)
    await session.flush()

    intent.to_fact_id = fact.id
    intent.worker = worker
    intent.last_heartbeat_at = now
    intent.concluded_at = now
    await session.flush()
    return ConcludeResult(fact=fact, intent=intent)


# --- reason lease ------------------------------------------------------------


async def claim_reason(
    session: AsyncSession, tenant_id: str, project_id: str, worker: str, trigger: str
) -> CairnProject:
    project = await _check_active(session, tenant_id, project_id, for_update=True)
    await expire_reason_leases(session, tenant_id, project_id)
    # re-read under lock after expiry
    project = await _check_active(session, tenant_id, project_id, for_update=True)
    if project.reason_worker is not None and project.reason_worker != worker:
        raise CairnConflictError(f"Project reason is currently claimed by {project.reason_worker}")
    if project.reason_worker == worker:
        return project
    now = _utcnow()
    project.reason_worker = worker
    project.reason_trigger = trigger
    project.reason_started_at = now
    project.reason_last_heartbeat_at = now
    project.reason_fence_token += 1
    await session.flush()
    return project


async def heartbeat_reason(
    session: AsyncSession, tenant_id: str, project_id: str, worker: str
) -> CairnProject:
    project = await _check_active(session, tenant_id, project_id, for_update=True)
    if project.reason_worker is None:
        raise CairnConflictError("Project reason is not currently claimed")
    if project.reason_worker != worker:
        raise CairnConflictError(f"Project reason is currently claimed by {project.reason_worker}")
    project.reason_last_heartbeat_at = _utcnow()
    await session.flush()
    return project


async def release_reason(
    session: AsyncSession, tenant_id: str, project_id: str, worker: str
) -> CairnProject:
    project = await _check_active(session, tenant_id, project_id, for_update=True)
    if project.reason_worker is None:
        return project
    if project.reason_worker != worker:
        raise CairnConflictError(f"Project reason is currently claimed by {project.reason_worker}")
    _clear_reason(project)
    await session.flush()
    return project


# --- complete / reopen -------------------------------------------------------


async def complete_project(
    session: AsyncSession,
    tenant_id: str,
    project_id: str,
    *,
    from_refs: list[str],
    description: str,
    worker: str,
) -> CairnIntent:
    """Create the completion intent, mark the project completed (upstream S-12)."""
    project = await _check_active(session, tenant_id, project_id, for_update=True)
    await expire_reason_leases(session, tenant_id, project_id)
    facts = await _resolve_from_facts(session, tenant_id, project_id, from_refs)

    now = _utcnow()
    ref = await next_intent_ref(session, tenant_id, project_id)
    goal_fact = await _fact_by_ref(session, tenant_id, project_id, GOAL_REF)
    intent = CairnIntent(
        ref=ref,
        tenant_id=tenant_id,
        project_id=project_id,
        to_fact_id=goal_fact.id if goal_fact else None,
        is_completion=True,
        description=description,
        creator=worker,
        worker=worker,
        last_heartbeat_at=now,
        concluded_at=now,
    )
    session.add(intent)
    await session.flush()
    await _add_intent_sources(session, tenant_id, intent.id, facts)

    project.status = "completed"
    _clear_reason(project)
    await session.flush()
    return intent


async def _completion_intent_or_409(
    session: AsyncSession, tenant_id: str, project_id: str
) -> CairnIntent:
    rows = list(
        (
            await session.execute(
                select(CairnIntent).where(
                    CairnIntent.project_id == project_id,
                    CairnIntent.tenant_id == tenant_id,
                    CairnIntent.is_completion.is_(True),
                )
            )
        )
        .scalars()
        .all()
    )
    if not rows:
        raise CairnConflictError("Completed project is missing its completion intent")
    if len(rows) != 1:
        raise CairnConflictError("Completed project has multiple completion intents")
    return rows[0]


async def reopen_project(
    session: AsyncSession,
    tenant_id: str,
    project_id: str,
    *,
    description: str,
    creator: str,
) -> ReopenResult:
    """Reopen a completed project with external feedback (upstream S-13)."""
    await expire_reason_leases(session, tenant_id, project_id)
    project = await _get_project_or_404(session, tenant_id, project_id, for_update=True)
    if project.status != "completed":
        raise CairnForbiddenError(f"Project is {project.status}")
    completion = await _completion_intent_or_409(session, tenant_id, project_id)
    source_refs = await _source_refs(session, completion.id)
    if not source_refs:
        raise CairnConflictError("Completion intent is missing its source facts")
    source_facts = await _resolve_from_facts(session, tenant_id, project_id, source_refs)

    now = _utcnow()
    await session.delete(completion)
    await session.flush()

    fact_ref = await next_fact_ref(session, tenant_id, project_id)
    fact = CairnFact(
        ref=fact_ref,
        tenant_id=tenant_id,
        project_id=project_id,
        description=description,
        created_by=creator,
        source_task_type="external",
    )
    session.add(fact)
    await session.flush()

    intent_ref = await next_intent_ref(session, tenant_id, project_id)
    intent = CairnIntent(
        ref=intent_ref,
        tenant_id=tenant_id,
        project_id=project_id,
        to_fact_id=fact.id,
        description="external_feedback",
        creator=creator,
        worker=creator,
        last_heartbeat_at=now,
        concluded_at=now,
    )
    session.add(intent)
    await session.flush()
    await _add_intent_sources(session, tenant_id, intent.id, source_facts)

    _clear_reason(project)
    project.status = "active"
    await session.flush()
    return ReopenResult(project=project, fact=fact, intent=intent)


# --- hints -------------------------------------------------------------------


async def create_hint(
    session: AsyncSession,
    tenant_id: str,
    project_id: str,
    *,
    content: str,
    creator: str,
    author_user_id: str | None = None,
) -> CairnHint:
    """Create a hint — allowed in any project status (upstream S-18)."""
    await _get_project_or_404(session, tenant_id, project_id)
    ref = await next_hint_ref(session, tenant_id, project_id)
    hint = CairnHint(
        ref=ref,
        tenant_id=tenant_id,
        project_id=project_id,
        content=content,
        creator=creator,
        author_user_id=author_user_id,
    )
    session.add(hint)
    await session.flush()
    return hint


__all__ = [
    "BOOTSTRAP_CREATOR",
    "ConcludeResult",
    "ProjectCounts",
    "ProjectDetailResult",
    "ProjectReasonInfo",
    "ProjectSummaryResult",
    "ReopenResult",
    "claim_intent",
    "claim_reason",
    "complete_project",
    "conclude_intent",
    "create_hint",
    "create_intent",
    "create_project",
    "delete_project",
    "expire_reason_leases",
    "expire_workers",
    "get_project",
    "get_settings",
    "heartbeat_reason",
    "intent_source_refs",
    "list_projects",
    "release_intent",
    "release_reason",
    "reopen_project",
    "update_project_status",
    "update_project_title",
    "update_settings",
]
