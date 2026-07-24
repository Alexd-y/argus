"""Async persistence for session macros + principals (WB-P6b).

Tenant isolation is defence-in-depth: the session has
:func:`~src.db.session.set_session_tenant` applied (PostgreSQL RLS) and every
query additionally filters ``tenant_id`` explicitly. Concurrent edits use
optimistic locking on ``version``.

Split-plane secrets (SI-3): neither table stores raw credentials/tokens. A
macro step references a secret by ``secret_ref`` placeholder; a principal stores
only a ``secrets_ref`` into the secret plane. Values are resolved in-process at
replay time by :class:`~src.web_workbench.sessions.macro_runner.MacroRunner`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models_web_workbench import (
    WbSessionMacro,
    WbSessionPrincipal,
    WebWorkbenchProject,
)

# -- principal roles ---------------------------------------------------------
ROLE_OWNER = "owner"
ROLE_ATTACKER = "attacker"
ROLE_ANONYMOUS = "anonymous"
_VALID_ROLES = frozenset({ROLE_OWNER, ROLE_ATTACKER, ROLE_ANONYMOUS})


class SessionRepositoryError(Exception):
    """Base class for session repository errors."""


class ProjectNotFoundError(SessionRepositoryError):
    """Target project does not exist for this tenant."""


class MacroNotFoundError(SessionRepositoryError):
    """Requested macro does not exist for this tenant."""


class PrincipalNotFoundError(SessionRepositoryError):
    """Requested principal does not exist for this tenant."""


class NameConflictError(SessionRepositoryError):
    """A macro/principal with the same name already exists in the project."""


class OptimisticLockError(SessionRepositoryError):
    """The update's ``expected_version`` did not match the persisted row."""


class InvalidRoleError(SessionRepositoryError):
    """The principal role is not one of owner/attacker/anonymous."""


@dataclass(frozen=True)
class SessionMacroDTO:
    id: str
    tenant_id: str
    project_id: str
    name: str
    steps: list[Any] | None
    match_rules: dict[str, Any] | None
    config: dict[str, Any] | None
    version: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True)
class SessionPrincipalDTO:
    id: str
    tenant_id: str
    project_id: str
    name: str
    role: str
    secrets_ref: str | None
    macro_id: str | None
    config: dict[str, Any] | None
    version: int
    created_at: datetime
    updated_at: datetime


def _macro_to_dto(row: WbSessionMacro) -> SessionMacroDTO:
    return SessionMacroDTO(
        id=row.id,
        tenant_id=row.tenant_id,
        project_id=row.project_id,
        name=row.name,
        steps=row.steps,
        match_rules=row.match_rules,
        config=row.config,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _principal_to_dto(row: WbSessionPrincipal) -> SessionPrincipalDTO:
    return SessionPrincipalDTO(
        id=row.id,
        tenant_id=row.tenant_id,
        project_id=row.project_id,
        name=row.name,
        role=row.role,
        secrets_ref=row.secrets_ref,
        macro_id=row.macro_id,
        config=row.config,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


class SessionRepository:
    """Async CRUD for session macros + principals (RLS + optimistic lock)."""

    async def _project_exists(self, session: AsyncSession, tenant_id: str, project_id: str) -> bool:
        result = await session.execute(
            select(WebWorkbenchProject.id).where(
                WebWorkbenchProject.tenant_id == tenant_id,
                WebWorkbenchProject.id == project_id,
            )
        )
        return result.scalars().first() is not None

    # -- macros --------------------------------------------------------------

    async def create_macro(
        self,
        session: AsyncSession,
        tenant_id: str,
        project_id: str,
        *,
        name: str,
        steps: list[Any] | None = None,
        match_rules: dict[str, Any] | None = None,
        config: dict[str, Any] | None = None,
    ) -> SessionMacroDTO:
        if not await self._project_exists(session, tenant_id, project_id):
            raise ProjectNotFoundError(project_id)
        row = WbSessionMacro(
            tenant_id=tenant_id,
            project_id=project_id,
            name=name,
            steps=steps,
            match_rules=match_rules,
            config=config,
            version=1,
        )
        session.add(row)
        try:
            await session.flush()
        except IntegrityError as exc:
            await session.rollback()
            raise NameConflictError(name) from exc
        await session.refresh(row)
        return _macro_to_dto(row)

    async def _get_macro_row(
        self, session: AsyncSession, tenant_id: str, macro_id: str
    ) -> WbSessionMacro | None:
        result = await session.execute(
            select(WbSessionMacro).where(
                WbSessionMacro.tenant_id == tenant_id,
                WbSessionMacro.id == macro_id,
            )
        )
        return result.scalars().first()

    async def get_macro(
        self, session: AsyncSession, tenant_id: str, macro_id: str
    ) -> SessionMacroDTO | None:
        row = await self._get_macro_row(session, tenant_id, macro_id)
        return _macro_to_dto(row) if row is not None else None

    async def list_macros(
        self, session: AsyncSession, tenant_id: str, project_id: str
    ) -> list[SessionMacroDTO]:
        result = await session.execute(
            select(WbSessionMacro)
            .where(
                WbSessionMacro.tenant_id == tenant_id,
                WbSessionMacro.project_id == project_id,
            )
            .order_by(WbSessionMacro.created_at, WbSessionMacro.id)
        )
        return [_macro_to_dto(r) for r in result.scalars().all()]

    async def update_macro(
        self,
        session: AsyncSession,
        tenant_id: str,
        macro_id: str,
        *,
        expected_version: int,
        name: str | None = None,
        steps: list[Any] | None = None,
        match_rules: dict[str, Any] | None = None,
        config: dict[str, Any] | None = None,
    ) -> SessionMacroDTO:
        row = await self._get_macro_row(session, tenant_id, macro_id)
        if row is None:
            raise MacroNotFoundError(macro_id)
        if row.version != expected_version:
            raise OptimisticLockError(macro_id)
        if name is not None:
            row.name = name
        if steps is not None:
            row.steps = steps
        if match_rules is not None:
            row.match_rules = match_rules
        if config is not None:
            row.config = config
        row.version = row.version + 1
        try:
            await session.flush()
        except IntegrityError as exc:
            await session.rollback()
            raise NameConflictError(name or macro_id) from exc
        await session.refresh(row)
        return _macro_to_dto(row)

    async def delete_macro(self, session: AsyncSession, tenant_id: str, macro_id: str) -> None:
        row = await self._get_macro_row(session, tenant_id, macro_id)
        if row is None:
            raise MacroNotFoundError(macro_id)
        await session.delete(row)
        await session.flush()

    # -- principals ----------------------------------------------------------

    async def create_principal(
        self,
        session: AsyncSession,
        tenant_id: str,
        project_id: str,
        *,
        name: str,
        role: str,
        secrets_ref: str | None = None,
        macro_id: str | None = None,
        config: dict[str, Any] | None = None,
    ) -> SessionPrincipalDTO:
        if role not in _VALID_ROLES:
            raise InvalidRoleError(role)
        if not await self._project_exists(session, tenant_id, project_id):
            raise ProjectNotFoundError(project_id)
        if macro_id is not None and await self._get_macro_row(session, tenant_id, macro_id) is None:
            raise MacroNotFoundError(macro_id)
        row = WbSessionPrincipal(
            tenant_id=tenant_id,
            project_id=project_id,
            name=name,
            role=role,
            secrets_ref=secrets_ref,
            macro_id=macro_id,
            config=config,
            version=1,
        )
        session.add(row)
        try:
            await session.flush()
        except IntegrityError as exc:
            await session.rollback()
            raise NameConflictError(name) from exc
        await session.refresh(row)
        return _principal_to_dto(row)

    async def _get_principal_row(
        self, session: AsyncSession, tenant_id: str, principal_id: str
    ) -> WbSessionPrincipal | None:
        result = await session.execute(
            select(WbSessionPrincipal).where(
                WbSessionPrincipal.tenant_id == tenant_id,
                WbSessionPrincipal.id == principal_id,
            )
        )
        return result.scalars().first()

    async def get_principal(
        self, session: AsyncSession, tenant_id: str, principal_id: str
    ) -> SessionPrincipalDTO | None:
        row = await self._get_principal_row(session, tenant_id, principal_id)
        return _principal_to_dto(row) if row is not None else None

    async def list_principals(
        self, session: AsyncSession, tenant_id: str, project_id: str
    ) -> list[SessionPrincipalDTO]:
        result = await session.execute(
            select(WbSessionPrincipal)
            .where(
                WbSessionPrincipal.tenant_id == tenant_id,
                WbSessionPrincipal.project_id == project_id,
            )
            .order_by(WbSessionPrincipal.role, WbSessionPrincipal.created_at, WbSessionPrincipal.id)
        )
        return [_principal_to_dto(r) for r in result.scalars().all()]

    async def update_principal(
        self,
        session: AsyncSession,
        tenant_id: str,
        principal_id: str,
        *,
        expected_version: int,
        name: str | None = None,
        role: str | None = None,
        secrets_ref: str | None = None,
        macro_id: str | None = None,
        config: dict[str, Any] | None = None,
    ) -> SessionPrincipalDTO:
        row = await self._get_principal_row(session, tenant_id, principal_id)
        if row is None:
            raise PrincipalNotFoundError(principal_id)
        if row.version != expected_version:
            raise OptimisticLockError(principal_id)
        if role is not None:
            if role not in _VALID_ROLES:
                raise InvalidRoleError(role)
            row.role = role
        if macro_id is not None and await self._get_macro_row(session, tenant_id, macro_id) is None:
            raise MacroNotFoundError(macro_id)
        if name is not None:
            row.name = name
        if secrets_ref is not None:
            row.secrets_ref = secrets_ref
        if macro_id is not None:
            row.macro_id = macro_id
        if config is not None:
            row.config = config
        row.version = row.version + 1
        try:
            await session.flush()
        except IntegrityError as exc:
            await session.rollback()
            raise NameConflictError(name or principal_id) from exc
        await session.refresh(row)
        return _principal_to_dto(row)

    async def delete_principal(
        self, session: AsyncSession, tenant_id: str, principal_id: str
    ) -> None:
        row = await self._get_principal_row(session, tenant_id, principal_id)
        if row is None:
            raise PrincipalNotFoundError(principal_id)
        await session.delete(row)
        await session.flush()


__all__ = [
    "ROLE_ANONYMOUS",
    "ROLE_ATTACKER",
    "ROLE_OWNER",
    "InvalidRoleError",
    "MacroNotFoundError",
    "NameConflictError",
    "OptimisticLockError",
    "PrincipalNotFoundError",
    "ProjectNotFoundError",
    "SessionMacroDTO",
    "SessionPrincipalDTO",
    "SessionRepository",
    "SessionRepositoryError",
]
