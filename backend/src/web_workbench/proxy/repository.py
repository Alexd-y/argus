"""Async persistence for proxy listeners + captured traffic (WB-P2a-2).

Tenant isolation is defence-in-depth (PostgreSQL RLS via ``set_session_tenant``
plus explicit ``tenant_id`` filters). Listener updates use optimistic locking on
``version``. Captured messages store bodies out-of-line via
:func:`~src.web_workbench.proxy.transport.plan_body` + a
:class:`~src.web_workbench.proxy.body_store.BodyObjectStore`: small bodies inline
in the DB, medium bodies spilled to the object store, oversized bodies dropped
(digest + size retained). Body bytes are never logged.

CA issuance / rotation (which requires sealing the CA *private* key into the
secret plane) is intentionally out of scope here and lives with the live daemon
(WB-P2b); this layer only ever reads/writes the *public* CA certificate.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models_web_workbench import (
    WbProxyListener,
    WbTrafficBodyArtifact,
    WbTrafficMessage,
    WebWorkbenchProject,
)
from src.web_workbench.contracts.proxy import (
    BodyRef,
    CaInfo,
    ProxyListenerCreate,
    ProxyListenerDTO,
    ProxyListenerStatus,
    ProxyListenerUpdate,
    TrafficMessageDTO,
)
from src.web_workbench.proxy.body_store import BodyObjectStore
from src.web_workbench.proxy.ca_lifecycle import SealedCa
from src.web_workbench.proxy.intercept_rules import InterceptRuleSet
from src.web_workbench.proxy.transport import plan_body

_DIRECTION_REQUEST = "request"
_DIRECTION_RESPONSE = "response"
_BACKEND_INLINE = "inline"
_BACKEND_S3 = "s3"
_BACKEND_NONE = "none"


class ProxyRepositoryError(Exception):
    """Base class for proxy repository errors."""


class ProjectNotFoundError(ProxyRepositoryError):
    """Parent project does not exist for this tenant."""


class ListenerNotFoundError(ProxyRepositoryError):
    """Listener does not exist for this tenant/project."""


class ListenerNameConflictError(ProxyRepositoryError):
    """A listener with the same name already exists in the project."""


class OptimisticLockError(ProxyRepositoryError):
    """The update's ``expected_version`` did not match the persisted row."""


@dataclass(frozen=True)
class CaptureInput:
    """A single captured request/response to persist.

    Headers are ordered ``(name, value)`` pairs (raw fidelity). Bodies are the
    full raw bytes (may be ``None`` when absent); they are digested + capped on
    persistence — never buffered without bound beyond the caller's own read.
    """

    method: str
    scheme: str
    host: str
    port: int
    path: str
    http_version: str
    forward_outcome: str
    in_scope: bool
    source: str = "proxy"
    listener_id: str | None = None
    query: str | None = None
    status_code: int | None = None
    request_headers: Sequence[tuple[str, str]] = field(default_factory=tuple)
    response_headers: Sequence[tuple[str, str]] | None = None
    request_body: bytes | None = None
    response_body: bytes | None = None
    request_content_type: str | None = None
    response_content_type: str | None = None
    block_reason: str | None = None
    tags: Sequence[str] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Mapping helpers
# ---------------------------------------------------------------------------


def _rules_from_row(raw: dict | None) -> InterceptRuleSet | None:
    if raw is None:
        return None
    return InterceptRuleSet.model_validate(raw)


def _ca_info(listener: WbProxyListener) -> CaInfo | None:
    if not listener.ca_cert_pem or not listener.ca_fingerprint:
        return None
    return CaInfo(
        fingerprint_sha256=listener.ca_fingerprint,
        certificate_pem=listener.ca_cert_pem,
    )


def _listener_to_dto(listener: WbProxyListener) -> ProxyListenerDTO:
    return ProxyListenerDTO(
        id=listener.id,
        tenant_id=listener.tenant_id,
        project_id=listener.project_id,
        name=listener.name,
        host=listener.host,
        port=listener.port,
        status=ProxyListenerStatus(listener.status),
        intercept_enabled=listener.intercept_enabled,
        intercept_rules=_rules_from_row(listener.intercept_rules),
        ca=_ca_info(listener),
        version=listener.version,
        created_at=listener.created_at,
        updated_at=listener.updated_at,
    )


def _body_ref(artifact: WbTrafficBodyArtifact | None) -> BodyRef | None:
    if artifact is None:
        return None
    return BodyRef(
        id=artifact.id,
        direction=artifact.direction,
        storage_backend=artifact.storage_backend,
        sha256=artifact.sha256,
        size_bytes=artifact.size_bytes,
        content_type=artifact.content_type,
        truncated=artifact.truncated,
    )


def _message_to_dto(
    message: WbTrafficMessage,
    request_body: WbTrafficBodyArtifact | None,
    response_body: WbTrafficBodyArtifact | None,
) -> TrafficMessageDTO:
    return TrafficMessageDTO(
        id=message.id,
        project_id=message.project_id,
        listener_id=message.listener_id,
        source=message.source,
        method=message.method,
        scheme=message.scheme,
        host=message.host,
        port=message.port,
        path=message.path,
        query=message.query,
        http_version=message.http_version,
        status_code=message.status_code,
        forward_outcome=message.forward_outcome,
        block_reason=message.block_reason,
        in_scope=message.in_scope,
        request_body=_body_ref(request_body),
        response_body=_body_ref(response_body),
        tags=tuple(message.tags or ()),
        created_at=message.created_at,
    )


class ProxyRepository:
    """Async CRUD for proxy listeners + captured traffic (RLS + optimistic lock)."""

    async def _assert_project(self, session: AsyncSession, tenant_id: str, project_id: str) -> None:
        result = await session.execute(
            select(WebWorkbenchProject.id).where(
                WebWorkbenchProject.tenant_id == tenant_id,
                WebWorkbenchProject.id == project_id,
            )
        )
        if result.scalars().first() is None:
            raise ProjectNotFoundError(project_id)

    # -- listeners -----------------------------------------------------------

    async def create_listener(
        self,
        session: AsyncSession,
        tenant_id: str,
        project_id: str,
        data: ProxyListenerCreate,
    ) -> ProxyListenerDTO:
        await self._assert_project(session, tenant_id, project_id)
        listener = WbProxyListener(
            tenant_id=tenant_id,
            project_id=project_id,
            name=data.name,
            host=data.host,
            port=data.port,
            status=ProxyListenerStatus.DISABLED.value,
            intercept_enabled=data.intercept_enabled,
            intercept_rules=(
                data.intercept_rules.model_dump(mode="json")
                if data.intercept_rules is not None
                else None
            ),
            version=1,
        )
        session.add(listener)
        try:
            await session.flush()
        except IntegrityError as exc:
            await session.rollback()
            raise ListenerNameConflictError(data.name) from exc
        await session.refresh(listener)
        return _listener_to_dto(listener)

    async def get_listener(
        self, session: AsyncSession, tenant_id: str, listener_id: str
    ) -> ProxyListenerDTO | None:
        result = await session.execute(
            select(WbProxyListener).where(
                WbProxyListener.tenant_id == tenant_id,
                WbProxyListener.id == listener_id,
            )
        )
        listener = result.scalars().first()
        return _listener_to_dto(listener) if listener is not None else None

    async def list_listeners(
        self, session: AsyncSession, tenant_id: str, project_id: str
    ) -> list[ProxyListenerDTO]:
        result = await session.execute(
            select(WbProxyListener)
            .where(
                WbProxyListener.tenant_id == tenant_id,
                WbProxyListener.project_id == project_id,
            )
            .order_by(WbProxyListener.created_at, WbProxyListener.id)
        )
        return [_listener_to_dto(row) for row in result.scalars().all()]

    async def update_listener(
        self,
        session: AsyncSession,
        tenant_id: str,
        listener_id: str,
        data: ProxyListenerUpdate,
    ) -> ProxyListenerDTO:
        result = await session.execute(
            select(WbProxyListener).where(
                WbProxyListener.tenant_id == tenant_id,
                WbProxyListener.id == listener_id,
            )
        )
        listener = result.scalars().first()
        if listener is None:
            raise ListenerNotFoundError(listener_id)
        if listener.version != data.expected_version:
            raise OptimisticLockError(listener_id)

        if data.name is not None:
            listener.name = data.name
        if data.host is not None:
            listener.host = data.host
        if data.port is not None:
            listener.port = data.port
        if data.status is not None:
            listener.status = data.status.value
        if data.intercept_enabled is not None:
            listener.intercept_enabled = data.intercept_enabled
        if data.intercept_rules is not None:
            listener.intercept_rules = data.intercept_rules.model_dump(mode="json")
        listener.version = listener.version + 1

        try:
            await session.flush()
        except IntegrityError as exc:
            await session.rollback()
            raise ListenerNameConflictError(data.name or listener_id) from exc
        await session.refresh(listener)
        return _listener_to_dto(listener)

    async def set_listener_ca(
        self,
        session: AsyncSession,
        tenant_id: str,
        listener_id: str,
        sealed: SealedCa,
        *,
        expected_version: int,
    ) -> ProxyListenerDTO:
        """Persist (issue/rotate) a sealed CA on a listener (optimistic lock).

        Only the public certificate + fingerprint + SEALED private key are
        written; the plaintext key never touches the DB or logs.
        """
        result = await session.execute(
            select(WbProxyListener).where(
                WbProxyListener.tenant_id == tenant_id,
                WbProxyListener.id == listener_id,
            )
        )
        listener = result.scalars().first()
        if listener is None:
            raise ListenerNotFoundError(listener_id)
        if listener.version != expected_version:
            raise OptimisticLockError(listener_id)
        listener.ca_cert_pem = sealed.certificate_pem
        listener.ca_fingerprint = sealed.fingerprint_sha256
        listener.ca_sealed_key = sealed.sealed_key
        listener.ca_secrets_ref = sealed.secrets_ref
        listener.version = listener.version + 1
        await session.flush()
        await session.refresh(listener)
        return _listener_to_dto(listener)

    # -- traffic -------------------------------------------------------------

    async def _persist_body(
        self,
        session: AsyncSession,
        tenant_id: str,
        project_id: str,
        message_id: str,
        direction: str,
        data: bytes,
        content_type: str | None,
        object_store: BodyObjectStore,
    ) -> WbTrafficBodyArtifact:
        plan = plan_body(data)
        if plan.truncated:
            backend, inline, key = _BACKEND_NONE, None, None
        elif plan.is_inline:
            backend, inline, key = _BACKEND_INLINE, plan.content, None
        else:
            key = object_store.put(
                tenant_id=tenant_id,
                project_id=project_id,
                sha256=plan.sha256,
                data=data,
                content_type=content_type,
            )
            backend, inline = _BACKEND_S3, None
        artifact = WbTrafficBodyArtifact(
            tenant_id=tenant_id,
            project_id=project_id,
            message_id=message_id,
            direction=direction,
            storage_backend=backend,
            inline_bytes=inline,
            object_key=key,
            sha256=plan.sha256,
            size_bytes=plan.size,
            content_type=content_type,
            truncated=plan.truncated,
        )
        session.add(artifact)
        return artifact

    async def persist_message(
        self,
        session: AsyncSession,
        tenant_id: str,
        project_id: str,
        capture: CaptureInput,
        *,
        object_store: BodyObjectStore,
    ) -> TrafficMessageDTO:
        """Persist a captured request/response pair and its bodies."""
        await self._assert_project(session, tenant_id, project_id)
        message = WbTrafficMessage(
            tenant_id=tenant_id,
            project_id=project_id,
            listener_id=capture.listener_id,
            source=capture.source,
            method=capture.method,
            scheme=capture.scheme,
            host=capture.host,
            port=capture.port,
            path=capture.path,
            query=capture.query,
            http_version=capture.http_version,
            status_code=capture.status_code,
            request_headers=[list(pair) for pair in capture.request_headers],
            response_headers=(
                [list(pair) for pair in capture.response_headers]
                if capture.response_headers is not None
                else None
            ),
            forward_outcome=capture.forward_outcome,
            block_reason=capture.block_reason,
            in_scope=capture.in_scope,
            tags=list(capture.tags) or None,
        )
        session.add(message)
        await session.flush()

        request_artifact: WbTrafficBodyArtifact | None = None
        response_artifact: WbTrafficBodyArtifact | None = None
        if capture.request_body is not None:
            request_artifact = await self._persist_body(
                session,
                tenant_id,
                project_id,
                message.id,
                _DIRECTION_REQUEST,
                capture.request_body,
                capture.request_content_type,
                object_store,
            )
        if capture.response_body is not None:
            response_artifact = await self._persist_body(
                session,
                tenant_id,
                project_id,
                message.id,
                _DIRECTION_RESPONSE,
                capture.response_body,
                capture.response_content_type,
                object_store,
            )
        await session.flush()
        if request_artifact is not None:
            message.request_body_id = request_artifact.id
        if response_artifact is not None:
            message.response_body_id = response_artifact.id
        await session.flush()
        await session.refresh(message)
        return _message_to_dto(message, request_artifact, response_artifact)

    async def _load_body(
        self, session: AsyncSession, tenant_id: str, body_id: str | None
    ) -> WbTrafficBodyArtifact | None:
        if body_id is None:
            return None
        result = await session.execute(
            select(WbTrafficBodyArtifact).where(
                WbTrafficBodyArtifact.tenant_id == tenant_id,
                WbTrafficBodyArtifact.id == body_id,
            )
        )
        return result.scalars().first()

    async def get_message(
        self, session: AsyncSession, tenant_id: str, message_id: str
    ) -> TrafficMessageDTO | None:
        result = await session.execute(
            select(WbTrafficMessage).where(
                WbTrafficMessage.tenant_id == tenant_id,
                WbTrafficMessage.id == message_id,
            )
        )
        message = result.scalars().first()
        if message is None:
            return None
        req = await self._load_body(session, tenant_id, message.request_body_id)
        resp = await self._load_body(session, tenant_id, message.response_body_id)
        return _message_to_dto(message, req, resp)

    async def list_history(
        self,
        session: AsyncSession,
        tenant_id: str,
        project_id: str,
        *,
        host: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[TrafficMessageDTO], int]:
        filters = [
            WbTrafficMessage.tenant_id == tenant_id,
            WbTrafficMessage.project_id == project_id,
        ]
        if host is not None:
            filters.append(WbTrafficMessage.host == host)

        total_result = await session.execute(
            select(func.count()).select_from(WbTrafficMessage).where(*filters)
        )
        total = int(total_result.scalar_one())

        result = await session.execute(
            select(WbTrafficMessage)
            .where(*filters)
            .order_by(WbTrafficMessage.created_at.desc(), WbTrafficMessage.id)
            .offset(offset)
            .limit(limit)
        )
        messages = list(result.scalars().all())
        dtos: list[TrafficMessageDTO] = []
        for message in messages:
            req = await self._load_body(session, tenant_id, message.request_body_id)
            resp = await self._load_body(session, tenant_id, message.response_body_id)
            dtos.append(_message_to_dto(message, req, resp))
        return dtos, total


__all__ = [
    "CaptureInput",
    "ListenerNameConflictError",
    "ListenerNotFoundError",
    "OptimisticLockError",
    "ProjectNotFoundError",
    "ProxyRepository",
    "ProxyRepositoryError",
]
