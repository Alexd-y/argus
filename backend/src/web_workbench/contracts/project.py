"""Project / scope / EAP contracts for the Web Workbench foundation.

Scope rules reuse :class:`src.policy.scope.ScopeRule` verbatim so that the
matching semantics enforced at request time are exactly what the operator
configured (no divergent parsing between the API layer and the engine).
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, StrictStr

from src.policy.scope import ScopeRule


class ProjectStatus(StrEnum):
    """Lifecycle status of a workbench project."""

    ACTIVE = "active"
    PAUSED = "paused"
    ARCHIVED = "archived"


class WorkbenchProjectCreate(BaseModel):
    """Request body to create a workbench project.

    ``scope_rules`` must contain at least one *allow* rule; a project with no
    allow rule can never authorise an active operation (default-deny). Secrets
    are never accepted here — only a ``secrets_ref`` handle into the secret
    plane.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: StrictStr = Field(min_length=1, max_length=255)
    description: StrictStr | None = Field(default=None, max_length=4000)
    scope_rules: tuple[ScopeRule, ...] = Field(min_length=1, max_length=512)
    secrets_ref: StrictStr | None = Field(default=None, max_length=256)


class WorkbenchProjectUpdate(BaseModel):
    """Partial update. Concurrent-editable fields require ``expected_version``.

    ``expected_version`` implements optimistic locking: the update is applied
    only if it matches the persisted ``version``, otherwise the caller must
    reload and retry.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    expected_version: int = Field(ge=1)
    name: StrictStr | None = Field(default=None, min_length=1, max_length=255)
    description: StrictStr | None = Field(default=None, max_length=4000)
    status: ProjectStatus | None = None
    scope_rules: tuple[ScopeRule, ...] | None = Field(default=None, max_length=512)
    secrets_ref: StrictStr | None = Field(default=None, max_length=256)


class WorkbenchEapView(BaseModel):
    """Non-sensitive projection of a persisted EAP for API responses."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    engagement_id: StrictStr = Field(max_length=128)
    status: StrictStr = Field(max_length=16)
    signer_key_id: StrictStr | None = Field(default=None, max_length=16)
    expires: datetime | None = None


class WorkbenchProjectDTO(BaseModel):
    """Full project projection returned by the API / service layer."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr = Field(max_length=36)
    tenant_id: StrictStr = Field(max_length=36)
    name: StrictStr = Field(max_length=255)
    description: StrictStr | None = Field(default=None, max_length=4000)
    status: ProjectStatus
    scope_rules: tuple[ScopeRule, ...]
    secrets_ref: StrictStr | None = Field(default=None, max_length=256)
    version: int = Field(ge=1)
    eap: WorkbenchEapView | None = None
    created_at: datetime
    updated_at: datetime


class EapAttachRequest(BaseModel):
    """Attach a signed EAP JSON blob to a project.

    The blob is the full, signed
    :class:`~src.policy.engagement_authorization.EngagementAuthorizationProfile`
    serialised as a mapping. It is re-verified fail-closed before persistence;
    an unsigned / invalid / expired profile is rejected.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    signed_profile: dict = Field(min_length=1)


class WorkbenchProjectListResponse(BaseModel):
    """Paginated list of workbench projects."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    items: tuple[WorkbenchProjectDTO, ...]
    total: int = Field(ge=0)
    offset: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
