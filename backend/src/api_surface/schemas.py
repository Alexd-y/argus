"""API surface DTOs for OpenAPI ingest (Stage E)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictStr


class ParameterLocation(StrEnum):
    """OpenAPI parameter location."""

    PATH = "path"
    QUERY = "query"
    HEADER = "header"
    COOKIE = "cookie"
    BODY = "body"


class AuthSchemeKind(StrEnum):
    """Normalized authentication scheme kinds."""

    API_KEY = "apiKey"
    HTTP = "http"
    OAUTH2 = "oauth2"
    OPENID_CONNECT = "openIdConnect"
    MUTUAL_TLS = "mutualTLS"
    CUSTOM = "custom"


class ParameterDTO(BaseModel):
    """Single operation parameter."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: StrictStr = Field(min_length=1, max_length=256)
    location: ParameterLocation
    required: bool = False
    schema_type: StrictStr | None = None
    schema_format: StrictStr | None = None
    example: Any | None = None
    source_ref: StrictStr | None = None


class AuthRequirementDTO(BaseModel):
    """Authentication requirement for an endpoint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scheme_name: StrictStr = Field(min_length=1, max_length=128)
    kind: AuthSchemeKind
    scopes: tuple[StrictStr, ...] = ()
    in_location: StrictStr | None = None
    param_name: StrictStr | None = None


class FuzzPointDTO(BaseModel):
    """Deterministic fuzz injection point derived from an endpoint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr = Field(min_length=8, max_length=128)
    endpoint_id: StrictStr = Field(min_length=8, max_length=128)
    parameter_name: StrictStr
    location: ParameterLocation
    content_type: StrictStr | None = None
    risk_hint: StrictStr | None = None


class EndpointDTO(BaseModel):
    """Stable endpoint identity with auth and fuzz metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr = Field(min_length=8, max_length=128)
    asset_id: StrictStr = Field(min_length=1, max_length=36)
    method: StrictStr = Field(min_length=1, max_length=16)
    normalized_path: StrictStr = Field(min_length=1, max_length=2048)
    operation_id: StrictStr | None = None
    content_types: tuple[StrictStr, ...] = ()
    parameters: tuple[ParameterDTO, ...] = ()
    auth_requirements: tuple[AuthRequirementDTO, ...] = ()
    source_ref: StrictStr | None = None
    risk_hints: tuple[StrictStr, ...] = ()
    fuzz_points: tuple[FuzzPointDTO, ...] = ()


class ApiDocumentDTO(BaseModel):
    """Parsed API document with endpoints and metadata."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr = Field(min_length=8, max_length=128)
    tenant_id: StrictStr = Field(min_length=1, max_length=36)
    asset_id: StrictStr = Field(min_length=1, max_length=36)
    title: StrictStr | None = None
    version: StrictStr | None = None
    spec_version: StrictStr
    servers: tuple[StrictStr, ...] = ()
    endpoints: tuple[EndpointDTO, ...] = ()
    parse_warnings: tuple[StrictStr, ...] = ()
    source_sha256: StrictStr = Field(min_length=64, max_length=64)
