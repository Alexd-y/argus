"""Async persistence for Web Workbench projects / scope / EAP (WB-P1b).

Tenant isolation is enforced two ways, defence-in-depth:

* every method is called with a session on which
  :func:`src.db.session.set_session_tenant` has already been applied, so
  PostgreSQL RLS filters rows to the caller's tenant; and
* every query additionally filters ``tenant_id`` explicitly.

Concurrent-editable updates use optimistic locking on the ``version`` column:
an update whose ``expected_version`` does not match the persisted row raises
:class:`OptimisticLockError` (the caller reloads and retries) — never a silent
lost update.

Scope rules live in their own table (:class:`WbScopeRule`); they map 1:1 to
:class:`src.policy.scope.ScopeRule` so the API and the engine share semantics.
EAP blobs are re-verified fail-closed via :func:`evaluate_eap` before
persistence — an unsigned / invalid / expired profile is rejected.
"""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models_web_workbench import (
    WbScopeRule,
    WebWorkbenchEapRecord,
    WebWorkbenchProject,
)
from src.policy.engagement_authorization import EngagementAuthorizationService
from src.policy.scope import PortRange, ScopeKind, ScopeRule
from src.web_workbench.contracts import (
    ProjectStatus,
    WorkbenchEapView,
    WorkbenchProjectCreate,
    WorkbenchProjectDTO,
    WorkbenchProjectUpdate,
)
from src.web_workbench.projects.service import EAP_STATUS_VERIFIED, evaluate_eap


class WorkbenchRepositoryError(Exception):
    """Base class for workbench repository errors."""


class ProjectNotFoundError(WorkbenchRepositoryError):
    """Requested project does not exist for this tenant."""


class ProjectNameConflictError(WorkbenchRepositoryError):
    """A project with the same name already exists for this tenant."""


class OptimisticLockError(WorkbenchRepositoryError):
    """The update's ``expected_version`` did not match the persisted row."""


class EapRejectedError(WorkbenchRepositoryError):
    """The submitted EAP failed fail-closed verification and was not stored.

    ``reason`` is a closed-taxonomy summary (never raw signature material).
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# ---------------------------------------------------------------------------
# ORM <-> domain mapping
# ---------------------------------------------------------------------------


def _rule_to_row_kwargs(rule: ScopeRule) -> dict[str, object]:
    ports = [{"low": r.low, "high": r.high} for r in rule.ports] or None
    return {
        "kind": rule.kind.value,
        "pattern": rule.pattern,
        "deny": rule.deny,
        "ports": ports,
        "note": rule.note,
    }


def _row_to_rule(row: WbScopeRule) -> ScopeRule:
    ports = tuple(PortRange(low=int(p["low"]), high=int(p["high"])) for p in (row.ports or []))
    return ScopeRule(
        kind=ScopeKind(row.kind),
        pattern=row.pattern,
        deny=row.deny,
        ports=ports,
        note=row.note or "",
    )


def _eap_to_view(record: WebWorkbenchEapRecord | None) -> WorkbenchEapView | None:
    if record is None:
        return None
    return WorkbenchEapView(
        engagement_id=record.engagement_id,
        status=record.status,
        signer_key_id=record.signer_key_id,
        expires=record.expires,
    )


def _project_to_dto(
    project: WebWorkbenchProject,
    rules: Sequence[WbScopeRule],
    eap: WebWorkbenchEapRecord | None,
) -> WorkbenchProjectDTO:
    return WorkbenchProjectDTO(
        id=project.id,
        tenant_id=project.tenant_id,
        name=project.name,
        description=project.description,
        status=ProjectStatus(project.status),
        scope_rules=tuple(_row_to_rule(r) for r in rules),
        secrets_ref=project.secrets_ref,
        version=project.version,
        eap=_eap_to_view(eap),
        created_at=project.created_at,
        updated_at=project.updated_at,
    )


class WorkbenchProjectRepository:
    """Async CRUD for workbench projects (RLS + optimistic lock aware)."""

    async def _load_rules(
        self, session: AsyncSession, tenant_id: str, project_id: str
    ) -> list[WbScopeRule]:
        result = await session.execute(
            select(WbScopeRule)
            .where(
                WbScopeRule.tenant_id == tenant_id,
                WbScopeRule.project_id == project_id,
            )
            .order_by(WbScopeRule.created_at, WbScopeRule.id)
        )
        return list(result.scalars().all())

    async def _load_eap(
        self, session: AsyncSession, tenant_id: str, project_id: str
    ) -> WebWorkbenchEapRecord | None:
        result = await session.execute(
            select(WebWorkbenchEapRecord)
            .where(
                WebWorkbenchEapRecord.tenant_id == tenant_id,
                WebWorkbenchEapRecord.project_id == project_id,
            )
            .order_by(WebWorkbenchEapRecord.updated_at.desc())
            .limit(1)
        )
        return result.scalars().first()

    async def create(
        self,
        session: AsyncSession,
        tenant_id: str,
        data: WorkbenchProjectCreate,
        *,
        created_by_subject_hash: str | None = None,
    ) -> WorkbenchProjectDTO:
        project = WebWorkbenchProject(
            tenant_id=tenant_id,
            name=data.name,
            description=data.description,
            status=ProjectStatus.ACTIVE.value,
            secrets_ref=data.secrets_ref,
            created_by_subject_hash=created_by_subject_hash,
            version=1,
        )
        session.add(project)
        try:
            await session.flush()
        except IntegrityError as exc:
            await session.rollback()
            raise ProjectNameConflictError(data.name) from exc

        for rule in data.scope_rules:
            session.add(
                WbScopeRule(
                    tenant_id=tenant_id,
                    project_id=project.id,
                    **_rule_to_row_kwargs(rule),
                )
            )
        await session.flush()
        await session.refresh(project)
        rules = await self._load_rules(session, tenant_id, project.id)
        return _project_to_dto(project, rules, None)

    async def get(
        self, session: AsyncSession, tenant_id: str, project_id: str
    ) -> WorkbenchProjectDTO | None:
        result = await session.execute(
            select(WebWorkbenchProject).where(
                WebWorkbenchProject.tenant_id == tenant_id,
                WebWorkbenchProject.id == project_id,
            )
        )
        project = result.scalars().first()
        if project is None:
            return None
        rules = await self._load_rules(session, tenant_id, project_id)
        eap = await self._load_eap(session, tenant_id, project_id)
        return _project_to_dto(project, rules, eap)

    async def list(
        self,
        session: AsyncSession,
        tenant_id: str,
        *,
        status: ProjectStatus | None = None,
        offset: int = 0,
        limit: int = 20,
    ) -> tuple[list[WorkbenchProjectDTO], int]:
        filters = [WebWorkbenchProject.tenant_id == tenant_id]
        if status is not None:
            filters.append(WebWorkbenchProject.status == status.value)

        total_result = await session.execute(
            select(func.count()).select_from(WebWorkbenchProject).where(*filters)
        )
        total = int(total_result.scalar_one())

        result = await session.execute(
            select(WebWorkbenchProject)
            .where(*filters)
            .order_by(WebWorkbenchProject.created_at.desc(), WebWorkbenchProject.id)
            .offset(offset)
            .limit(limit)
        )
        projects = list(result.scalars().all())
        dtos: list[WorkbenchProjectDTO] = []
        for project in projects:
            rules = await self._load_rules(session, tenant_id, project.id)
            eap = await self._load_eap(session, tenant_id, project.id)
            dtos.append(_project_to_dto(project, rules, eap))
        return dtos, total

    async def update(
        self,
        session: AsyncSession,
        tenant_id: str,
        project_id: str,
        data: WorkbenchProjectUpdate,
    ) -> WorkbenchProjectDTO:
        result = await session.execute(
            select(WebWorkbenchProject).where(
                WebWorkbenchProject.tenant_id == tenant_id,
                WebWorkbenchProject.id == project_id,
            )
        )
        project = result.scalars().first()
        if project is None:
            raise ProjectNotFoundError(project_id)
        if project.version != data.expected_version:
            raise OptimisticLockError(project_id)

        if data.name is not None:
            project.name = data.name
        if data.description is not None:
            project.description = data.description
        if data.status is not None:
            project.status = data.status.value
        if data.secrets_ref is not None:
            project.secrets_ref = data.secrets_ref
        project.version = project.version + 1

        if data.scope_rules is not None:
            await session.execute(
                delete(WbScopeRule).where(
                    WbScopeRule.tenant_id == tenant_id,
                    WbScopeRule.project_id == project_id,
                )
            )
            for rule in data.scope_rules:
                session.add(
                    WbScopeRule(
                        tenant_id=tenant_id,
                        project_id=project_id,
                        **_rule_to_row_kwargs(rule),
                    )
                )
        try:
            await session.flush()
        except IntegrityError as exc:
            await session.rollback()
            raise ProjectNameConflictError(data.name or project_id) from exc

        await session.refresh(project)
        rules = await self._load_rules(session, tenant_id, project_id)
        eap = await self._load_eap(session, tenant_id, project_id)
        return _project_to_dto(project, rules, eap)

    async def attach_eap(
        self,
        session: AsyncSession,
        tenant_id: str,
        project_id: str,
        signed_profile: dict[str, object],
        *,
        eap_service: EngagementAuthorizationService,
    ) -> WorkbenchEapView:
        """Verify and persist a signed EAP for a project (fail-closed).

        Raises :class:`ProjectNotFoundError` if the project does not exist for
        this tenant, or :class:`EapRejectedError` if the profile does not
        verify (unsigned / invalid signature / expired). Only a ``verified``
        profile is persisted; a project keeps at most one EAP record.
        """
        exists = await session.execute(
            select(WebWorkbenchProject.id).where(
                WebWorkbenchProject.tenant_id == tenant_id,
                WebWorkbenchProject.id == project_id,
            )
        )
        if exists.scalars().first() is None:
            raise ProjectNotFoundError(project_id)

        evaluation = evaluate_eap(signed_profile, eap_service=eap_service)
        if evaluation.status != EAP_STATUS_VERIFIED or evaluation.profile is None:
            raise EapRejectedError(evaluation.failure_reason or evaluation.status)

        await session.execute(
            delete(WebWorkbenchEapRecord).where(
                WebWorkbenchEapRecord.tenant_id == tenant_id,
                WebWorkbenchEapRecord.project_id == project_id,
            )
        )
        record = WebWorkbenchEapRecord(
            tenant_id=tenant_id,
            project_id=project_id,
            engagement_id=evaluation.engagement_id or "",
            signed_profile=dict(signed_profile),
            signer_key_id=evaluation.signer_key_id,
            status=evaluation.status,
            expires=evaluation.expires,
        )
        session.add(record)
        await session.flush()
        await session.refresh(record)
        view = _eap_to_view(record)
        assert view is not None  # freshly persisted
        return view


__all__ = [
    "EapRejectedError",
    "OptimisticLockError",
    "ProjectNameConflictError",
    "ProjectNotFoundError",
    "WorkbenchProjectRepository",
    "WorkbenchRepositoryError",
]
