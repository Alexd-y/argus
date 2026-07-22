"""Contracts for the Repeater — tabs + replay exchanges (WB-P3b-2).

Raw request/response bytes travel as base64 (byte-safe) and are size-capped.
Exchange list views omit the raw bytes; the single-exchange view returns them.
All models are strict (``extra="forbid"``).
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

#: Max base64 length for a saved/replayed raw request (~1 MiB raw).
_MAX_REQ_B64 = 1_400_000


class RepeaterTabCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: StrictStr = Field(min_length=1, max_length=255)
    raw_request_base64: StrictStr = Field(min_length=1, max_length=_MAX_REQ_B64)


class RepeaterTabUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    expected_version: StrictInt = Field(ge=1)
    name: StrictStr | None = Field(default=None, min_length=1, max_length=255)
    raw_request_base64: StrictStr | None = Field(
        default=None, min_length=1, max_length=_MAX_REQ_B64
    )


class RepeaterTabDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr
    tenant_id: StrictStr
    project_id: StrictStr
    name: StrictStr
    scheme: StrictStr | None
    host: StrictStr | None
    port: StrictInt | None
    raw_request_base64: StrictStr
    version: StrictInt
    created_at: datetime
    updated_at: datetime


class RepeaterReplayRequest(BaseModel):
    """Replay the tab's stored request, or an inline byte-exact override."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    raw_request_base64: StrictStr | None = Field(
        default=None, min_length=1, max_length=_MAX_REQ_B64
    )


class RepeaterExchangeDTO(BaseModel):
    """Recorded replay. ``raw_*_base64`` are populated only by single-exchange GET."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr
    tenant_id: StrictStr
    project_id: StrictStr
    tab_id: StrictStr
    forward_outcome: StrictStr
    block_reason: StrictStr | None
    status_code: StrictInt | None
    response_size: StrictInt
    truncated: bool
    duration_ms: StrictInt | None
    raw_request_base64: StrictStr | None
    raw_response_base64: StrictStr | None
    created_at: datetime


class RepeaterExchangeListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    items: tuple[RepeaterExchangeDTO, ...]
    total: StrictInt = Field(ge=0)
    offset: StrictInt = Field(ge=0)
    limit: StrictInt = Field(ge=1, le=200)


__all__ = [
    "RepeaterExchangeDTO",
    "RepeaterExchangeListResponse",
    "RepeaterReplayRequest",
    "RepeaterTabCreate",
    "RepeaterTabDTO",
    "RepeaterTabUpdate",
]
