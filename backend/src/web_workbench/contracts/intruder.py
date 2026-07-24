"""Contracts for the Intruder — attacks + per-request results (WB-P4b).

The raw request template travels as base64 (byte-exact, position markers
preserved) and is size-capped. ``payload_config`` carries *references* into the
signed ``PayloadRegistry`` (family id / pipeline / parameters) — never raw
payload bytes; the worker materialises them through :class:`PayloadBuilder`
(SI-5). Per-request result rows are metadata-only (status/length/time/sha256 +
flagged) and never echo the raw payload value.

All models are strict (``extra="forbid"``, frozen).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr

#: Max base64 length for a saved raw request template (~1 MiB raw).
_MAX_REQ_B64 = 1_400_000

#: Attack strategies (mirror ``intruder.strategies.Strategy``).
AttackType = Literal["sniper", "battering_ram", "pitchfork", "cluster_bomb"]


class IntruderPosition(BaseModel):
    """A single ``{{…}}`` injection position (byte offsets into the template)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    start: StrictInt = Field(ge=0)
    end: StrictInt = Field(ge=0)


class IntruderAttackCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: StrictStr = Field(min_length=1, max_length=255)
    attack_type: AttackType
    raw_request_template_base64: StrictStr = Field(min_length=1, max_length=_MAX_REQ_B64)
    positions: list[IntruderPosition] | None = Field(default=None, max_length=64)
    #: References into the signed payload registry (family_id/pipeline/params).
    payload_config: dict[str, Any] | None = None
    #: Optional grep/flag_statuses/max_requests knobs consumed by the runner.
    config: dict[str, Any] | None = None


class IntruderControlRequest(BaseModel):
    """Start/pause/resume/cancel body — optimistic-lock guard on ``version``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    expected_version: StrictInt = Field(ge=1)


class IntruderAttackDTO(BaseModel):
    """Projection of a persisted attack. ``raw_request_template_base64`` is
    byte-exact and never logged."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr
    tenant_id: StrictStr
    project_id: StrictStr
    name: StrictStr
    attack_type: StrictStr
    status: StrictStr
    raw_request_template_base64: StrictStr
    positions: list[IntruderPosition] | None
    payload_config: dict[str, Any] | None
    config: dict[str, Any] | None
    checkpoint: dict[str, Any] | None
    requests_total: StrictInt
    requests_completed: StrictInt
    findings_total: StrictInt
    error_reason: StrictStr | None
    version: StrictInt
    created_at: datetime
    updated_at: datetime


class IntruderRequestDTO(BaseModel):
    """Metadata-only projection of one recorded attack request (no raw bytes)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr
    tenant_id: StrictStr
    project_id: StrictStr
    attack_id: StrictStr
    request_index: StrictInt
    payload_label: StrictStr | None
    payload_index: StrictInt | None
    forward_outcome: StrictStr
    block_reason: StrictStr | None
    status_code: StrictInt | None
    response_length: StrictInt | None
    response_time_ms: StrictInt | None
    response_sha256: StrictStr | None
    flagged: StrictBool
    error_reason: StrictStr | None
    created_at: datetime


class IntruderRequestListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    items: tuple[IntruderRequestDTO, ...]
    total: StrictInt = Field(ge=0)
    offset: StrictInt = Field(ge=0)
    limit: StrictInt = Field(ge=1, le=500)


__all__ = [
    "AttackType",
    "IntruderAttackCreate",
    "IntruderAttackDTO",
    "IntruderControlRequest",
    "IntruderPosition",
    "IntruderRequestDTO",
    "IntruderRequestListResponse",
]
