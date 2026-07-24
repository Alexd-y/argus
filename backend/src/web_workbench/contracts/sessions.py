"""Contracts for Sessions — macros + principals (WB-P6b).

Split-plane secrets (SI-3): no contract here carries a raw credential/token. A
macro step references a secret by ``secret_ref`` placeholder inside ``steps``; a
principal carries only ``secrets_ref`` (a handle into the secret plane). Values
are resolved in-process at replay time — never persisted or echoed by the API.

All models are strict (``extra="forbid"``, frozen).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

PrincipalRole = Literal["owner", "attacker", "anonymous"]


# -- macros ------------------------------------------------------------------


class SessionMacroCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: StrictStr = Field(min_length=1, max_length=255)
    #: Ordered login/replay steps; secret values referenced via ``secret_ref``.
    steps: list[Any] | None = Field(default=None, max_length=64)
    #: Rules deciding whether an established session is authenticated.
    match_rules: dict[str, Any] | None = None
    config: dict[str, Any] | None = None


class SessionMacroUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    expected_version: StrictInt = Field(ge=1)
    name: StrictStr | None = Field(default=None, min_length=1, max_length=255)
    steps: list[Any] | None = Field(default=None, max_length=64)
    match_rules: dict[str, Any] | None = None
    config: dict[str, Any] | None = None


class SessionMacroDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr
    tenant_id: StrictStr
    project_id: StrictStr
    name: StrictStr
    steps: list[Any] | None
    match_rules: dict[str, Any] | None
    config: dict[str, Any] | None
    version: StrictInt
    created_at: datetime
    updated_at: datetime


# -- principals --------------------------------------------------------------


class SessionPrincipalCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: StrictStr = Field(min_length=1, max_length=255)
    role: PrincipalRole
    #: Handle into the secret plane (SI-3) — never the raw secret.
    secrets_ref: StrictStr | None = Field(default=None, max_length=512)
    macro_id: StrictStr | None = Field(default=None, max_length=36)
    config: dict[str, Any] | None = None


class SessionPrincipalUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    expected_version: StrictInt = Field(ge=1)
    name: StrictStr | None = Field(default=None, min_length=1, max_length=255)
    role: PrincipalRole | None = None
    secrets_ref: StrictStr | None = Field(default=None, max_length=512)
    macro_id: StrictStr | None = Field(default=None, max_length=36)
    config: dict[str, Any] | None = None


class SessionPrincipalDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr
    tenant_id: StrictStr
    project_id: StrictStr
    name: StrictStr
    role: StrictStr
    secrets_ref: StrictStr | None
    macro_id: StrictStr | None
    config: dict[str, Any] | None
    version: StrictInt
    created_at: datetime
    updated_at: datetime


__all__ = [
    "PrincipalRole",
    "SessionMacroCreate",
    "SessionMacroDTO",
    "SessionMacroUpdate",
    "SessionPrincipalCreate",
    "SessionPrincipalDTO",
    "SessionPrincipalUpdate",
]
