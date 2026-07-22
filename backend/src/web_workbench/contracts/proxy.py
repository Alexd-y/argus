"""Pydantic contracts for the workbench proxy API (WB-P2a-2).

Strict (``extra="forbid"``) request/response models for proxy listeners, the
per-listener MITM CA (public material only) and captured traffic history. The
interception rule set reuses
:class:`~src.web_workbench.proxy.intercept_rules.InterceptRuleSet` verbatim so
the API and the engine cannot drift.

Security: no model ever carries CA *private* key material — only the public
certificate PEM and its fingerprint. Body DTOs carry provenance (sha256, size,
truncated) but never the body bytes.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

from src.web_workbench.proxy.intercept_rules import InterceptRuleSet


class ProxyListenerStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    KILLED = "killed"


class ProxyListenerCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: StrictStr = Field(min_length=1, max_length=255)
    host: StrictStr = Field(default="127.0.0.1", max_length=255)
    port: StrictInt = Field(default=8080, ge=1, le=65535)
    intercept_enabled: bool = False
    intercept_rules: InterceptRuleSet | None = None


class ProxyListenerUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    expected_version: StrictInt = Field(ge=1)
    name: StrictStr | None = Field(default=None, min_length=1, max_length=255)
    host: StrictStr | None = Field(default=None, max_length=255)
    port: StrictInt | None = Field(default=None, ge=1, le=65535)
    status: ProxyListenerStatus | None = None
    intercept_enabled: bool | None = None
    intercept_rules: InterceptRuleSet | None = None


class CaInfo(BaseModel):
    """Public CA material for a listener — safe to distribute to clients."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    fingerprint_sha256: StrictStr = Field(min_length=64, max_length=64)
    certificate_pem: StrictStr = Field(min_length=1)


class CaIssueRequest(BaseModel):
    """Issue (or rotate) the per-listener MITM CA. Optimistic-locked."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    expected_version: StrictInt = Field(ge=1)
    common_name: StrictStr = Field(default="ARGUS Workbench CA", max_length=64)


class ProxyListenerDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr
    tenant_id: StrictStr
    project_id: StrictStr
    name: StrictStr
    host: StrictStr
    port: StrictInt
    status: ProxyListenerStatus
    intercept_enabled: bool
    intercept_rules: InterceptRuleSet | None
    ca: CaInfo | None
    version: StrictInt
    created_at: datetime
    updated_at: datetime


class BodyRef(BaseModel):
    """Provenance for a stored body (never the body bytes)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr
    direction: StrictStr
    storage_backend: StrictStr
    sha256: StrictStr
    size_bytes: StrictInt = Field(ge=0)
    content_type: StrictStr | None = None
    truncated: bool = False


class TrafficMessageDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr
    project_id: StrictStr
    listener_id: StrictStr | None
    source: StrictStr
    method: StrictStr
    scheme: StrictStr
    host: StrictStr
    port: StrictInt
    path: StrictStr
    query: StrictStr | None
    http_version: StrictStr
    status_code: StrictInt | None
    forward_outcome: StrictStr
    block_reason: StrictStr | None
    in_scope: bool
    request_body: BodyRef | None
    response_body: BodyRef | None
    tags: tuple[StrictStr, ...] = ()
    created_at: datetime


class TrafficListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    items: tuple[TrafficMessageDTO, ...]
    total: StrictInt = Field(ge=0)
    offset: StrictInt = Field(ge=0)
    limit: StrictInt = Field(ge=1, le=200)


__all__ = [
    "BodyRef",
    "CaInfo",
    "CaIssueRequest",
    "ProxyListenerCreate",
    "ProxyListenerDTO",
    "ProxyListenerStatus",
    "ProxyListenerUpdate",
    "TrafficListResponse",
    "TrafficMessageDTO",
]
