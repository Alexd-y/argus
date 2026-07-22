"""Contracts for the Organizer — collections + saved items (WB-P3c).

Saved raw request/response bytes travel as standard base64 (byte-safe transport)
and are size-capped. List views omit the raw bytes; the single-item view returns
them. All models are strict (``extra="forbid"``).
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

#: Max base64 length per saved raw body (~1 MiB raw after decoding).
_MAX_RAW_B64 = 1_400_000
_MAX_TAGS = 32
_MAX_TAG_LEN = 64


class OrganizerCollectionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: StrictStr = Field(min_length=1, max_length=255)
    description: StrictStr | None = Field(default=None, max_length=4096)


class OrganizerCollectionUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    expected_version: StrictInt = Field(ge=1)
    name: StrictStr | None = Field(default=None, min_length=1, max_length=255)
    description: StrictStr | None = Field(default=None, max_length=4096)


class OrganizerCollectionDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr
    tenant_id: StrictStr
    project_id: StrictStr
    name: StrictStr
    description: StrictStr | None
    version: StrictInt
    created_at: datetime
    updated_at: datetime


class OrganizerItemCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    title: StrictStr = Field(min_length=1, max_length=512)
    method: StrictStr | None = Field(default=None, max_length=32)
    host: StrictStr | None = Field(default=None, max_length=255)
    url: StrictStr | None = Field(default=None, max_length=8192)
    notes: StrictStr | None = Field(default=None, max_length=16384)
    tags: tuple[StrictStr, ...] = Field(default=(), max_length=_MAX_TAGS)
    raw_request_base64: StrictStr | None = Field(default=None, max_length=_MAX_RAW_B64)
    raw_response_base64: StrictStr | None = Field(default=None, max_length=_MAX_RAW_B64)
    source_message_id: StrictStr | None = Field(default=None, max_length=36)

    def normalized_tags(self) -> tuple[str, ...]:
        """De-duplicated, length-capped, non-empty tags preserving first-seen order."""
        seen: dict[str, None] = {}
        for tag in self.tags:
            trimmed = tag.strip()[:_MAX_TAG_LEN]
            if trimmed:
                seen.setdefault(trimmed, None)
        return tuple(seen)


class OrganizerItemUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    expected_version: StrictInt = Field(ge=1)
    title: StrictStr | None = Field(default=None, min_length=1, max_length=512)
    notes: StrictStr | None = Field(default=None, max_length=16384)
    tags: tuple[StrictStr, ...] | None = Field(default=None, max_length=_MAX_TAGS)


class OrganizerItemDTO(BaseModel):
    """Item view. ``raw_*_base64`` are populated only by the single-item GET."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr
    tenant_id: StrictStr
    project_id: StrictStr
    collection_id: StrictStr
    title: StrictStr
    method: StrictStr | None
    host: StrictStr | None
    url: StrictStr | None
    notes: StrictStr | None
    tags: tuple[StrictStr, ...]
    has_raw_request: bool
    has_raw_response: bool
    raw_request_base64: StrictStr | None
    raw_response_base64: StrictStr | None
    source_message_id: StrictStr | None
    version: StrictInt
    created_at: datetime
    updated_at: datetime


class OrganizerItemListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    items: tuple[OrganizerItemDTO, ...]
    total: StrictInt = Field(ge=0)
    offset: StrictInt = Field(ge=0)
    limit: StrictInt = Field(ge=1, le=200)


__all__ = [
    "OrganizerCollectionCreate",
    "OrganizerCollectionDTO",
    "OrganizerCollectionUpdate",
    "OrganizerItemCreate",
    "OrganizerItemDTO",
    "OrganizerItemListResponse",
    "OrganizerItemUpdate",
]
