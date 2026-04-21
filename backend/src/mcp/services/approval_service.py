"""Approval lookup helpers consumed by MCP ``approvals.*`` tools.

The MCP server treats the approvals table as authoritative state but never
mutates it directly — instead it forwards decisions to
:class:`src.policy.approval.ApprovalService` and persists the outcome via
the application's existing approvals service (injected via
:func:`set_approval_repository`).

For test isolation this module ships with an in-memory repository that
covers happy-path / negative cases. Production deployments swap in a SQLA
implementation in the application's startup hook.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol, runtime_checkable

from src.mcp.exceptions import (
    ResourceNotFoundError,
    UpstreamServiceError,
    ValidationError,
)
from src.mcp.schemas.approval import (
    ApprovalDecideInput,
    ApprovalDecideResult,
    ApprovalDecisionAction,
    ApprovalListInput,
    ApprovalListResult,
    ApprovalSummary,
)

_logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class StoredApproval:
    """In-memory projection of an approvals row."""

    request_id: str
    tenant_id: str
    tool_id: str
    target: str
    action: str
    status: str
    created_at: datetime
    expires_at: datetime
    requires_dual_control: bool = False
    signatures: tuple[str, ...] = field(default_factory=tuple)


@runtime_checkable
class ApprovalRepository(Protocol):
    """Persistence Protocol abstracted away from SQLA."""

    def list_for_tenant(
        self,
        *,
        tenant_id: str,
        status: str | None,
        tool_id: str | None,
        limit: int,
        offset: int,
    ) -> tuple[Iterable[StoredApproval], int]: ...

    def get(self, *, tenant_id: str, request_id: str) -> StoredApproval | None: ...

    def update_status(
        self,
        *,
        tenant_id: str,
        request_id: str,
        new_status: str,
        signature_b64: str | None,
        public_key_id: str | None,
        justification: str | None,
        actor: str,
    ) -> str: ...


class InMemoryApprovalRepository:
    """Thread-safe in-memory approvals store used by tests and stdio mode."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._rows: dict[str, StoredApproval] = {}

    def add(self, approval: StoredApproval) -> None:
        with self._lock:
            self._rows[approval.request_id] = approval

    def list_for_tenant(
        self,
        *,
        tenant_id: str,
        status: str | None,
        tool_id: str | None,
        limit: int,
        offset: int,
    ) -> tuple[Iterable[StoredApproval], int]:
        with self._lock:
            filtered = [
                row
                for row in self._rows.values()
                if row.tenant_id == tenant_id
                and (status is None or row.status == status)
                and (tool_id is None or row.tool_id == tool_id)
            ]
        filtered.sort(key=lambda row: row.created_at, reverse=True)
        total = len(filtered)
        page = filtered[offset : offset + max(limit, 0)]
        return page, total

    def get(self, *, tenant_id: str, request_id: str) -> StoredApproval | None:
        with self._lock:
            row = self._rows.get(request_id)
        if row is None or row.tenant_id != tenant_id:
            return None
        return row

    def update_status(
        self,
        *,
        tenant_id: str,
        request_id: str,
        new_status: str,
        signature_b64: str | None,
        public_key_id: str | None,
        justification: str | None,
        actor: str,
    ) -> str:
        with self._lock:
            row = self._rows.get(request_id)
            if row is None or row.tenant_id != tenant_id:
                raise ResourceNotFoundError(
                    f"Approval {request_id!r} was not found in this tenant scope."
                )
            updated = StoredApproval(
                request_id=row.request_id,
                tenant_id=row.tenant_id,
                tool_id=row.tool_id,
                target=row.target,
                action=row.action,
                status=new_status,
                created_at=row.created_at,
                expires_at=row.expires_at,
                requires_dual_control=row.requires_dual_control,
                signatures=tuple(
                    [*row.signatures, signature_b64]
                    if signature_b64 is not None
                    else row.signatures
                ),
            )
            self._rows[request_id] = updated
        return new_status


_REPOSITORY_LOCK = threading.Lock()
_REPOSITORY: ApprovalRepository = InMemoryApprovalRepository()


def set_approval_repository(repo: ApprovalRepository) -> None:
    """Inject an approvals repository (test / app startup hook)."""
    global _REPOSITORY
    with _REPOSITORY_LOCK:
        _REPOSITORY = repo


def get_approval_repository() -> ApprovalRepository:
    """Return the currently bound approvals repository."""
    with _REPOSITORY_LOCK:
        return _REPOSITORY


def _row_to_summary(row: StoredApproval) -> ApprovalSummary:
    return ApprovalSummary(
        request_id=row.request_id,
        tool_id=row.tool_id,
        target=row.target,
        action=row.action,
        status=row.status,
        created_at=row.created_at,
        expires_at=row.expires_at,
        requires_dual_control=row.requires_dual_control,
        signatures_present=len(row.signatures),
    )


def list_approvals(*, tenant_id: str, payload: ApprovalListInput) -> ApprovalListResult:
    """List approvals visible to the authenticated tenant."""
    repo = get_approval_repository()
    rows, total = repo.list_for_tenant(
        tenant_id=tenant_id,
        status=payload.status,
        tool_id=payload.tool_id,
        limit=payload.pagination.limit,
        offset=payload.pagination.offset,
    )
    items = tuple(_row_to_summary(row) for row in rows)
    return ApprovalListResult(items=items, total=int(total))


def decide_approval(
    *, tenant_id: str, payload: ApprovalDecideInput, actor: str
) -> ApprovalDecideResult:
    """Record an operator decision on an approval request.

    Validation:

    * ``GRANT`` decisions require ``signature_b64`` + ``public_key_id``.
    * ``DENY`` / ``REVOKE`` decisions require a ``justification``.
    * The current row must exist in the authenticated tenant scope.
    """
    if payload.decision is ApprovalDecisionAction.GRANT:
        if not payload.signature_b64 or not payload.public_key_id:
            raise ValidationError(
                "GRANT decisions require both signature_b64 and public_key_id."
            )
    else:
        if not payload.justification or len(payload.justification.strip()) < 10:
            raise ValidationError(
                "DENY / REVOKE decisions require a justification of at least 10 characters."
            )

    repo = get_approval_repository()
    existing = repo.get(tenant_id=tenant_id, request_id=payload.request_id)
    if existing is None:
        raise ResourceNotFoundError(
            f"Approval {payload.request_id!r} was not found in this tenant scope."
        )

    target_status = _decision_to_status(payload.decision)
    try:
        new_status = repo.update_status(
            tenant_id=tenant_id,
            request_id=payload.request_id,
            new_status=target_status,
            signature_b64=payload.signature_b64,
            public_key_id=payload.public_key_id,
            justification=payload.justification,
            actor=actor,
        )
    except ResourceNotFoundError:
        raise
    except Exception as exc:  # pragma: no cover — defensive
        _logger.exception("mcp.approvals.update_failed")
        raise UpstreamServiceError(
            "Failed to record the approval decision; please retry later."
        ) from exc

    return ApprovalDecideResult(
        request_id=payload.request_id,
        new_status=new_status,
    )


def _decision_to_status(decision: ApprovalDecisionAction) -> str:
    return {
        ApprovalDecisionAction.GRANT: "granted",
        ApprovalDecisionAction.DENY: "denied",
        ApprovalDecisionAction.REVOKE: "revoked",
    }[decision]


def make_test_approval(
    *,
    tenant_id: str,
    tool_id: str = "demo_tool",
    action: str = "high",
    status: str = "pending",
    target: str = "https://example.com",
) -> StoredApproval:
    """Convenience helper for tests / stdio demos."""
    now = datetime.now(timezone.utc)
    return StoredApproval(
        request_id=f"req-{tool_id}-{int(now.timestamp())}",
        tenant_id=tenant_id,
        tool_id=tool_id,
        target=target,
        action=action,
        status=status,
        created_at=now,
        expires_at=now + timedelta(hours=24),
        requires_dual_control=action == "destructive",
    )


__all__ = [
    "ApprovalRepository",
    "InMemoryApprovalRepository",
    "StoredApproval",
    "decide_approval",
    "get_approval_repository",
    "list_approvals",
    "make_test_approval",
    "set_approval_repository",
]
