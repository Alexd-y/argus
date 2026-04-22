"""Admin router — /api/v1/admin/* for tenants, users, providers, audit, health."""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import logging
import os
import re
from datetime import datetime
from typing import Any, Literal

from fastapi import (
    APIRouter,
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy import String, cast, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from src.auth.admin_sessions import SessionPrincipal
from src.core.config import settings
from src.core.observability import tenant_hash, user_id_hash
from src.db.models import (
    PDF_ARCHIVAL_FORMAT_VALUES,
    AuditLog,
    PdfArchivalFormat,
    Policy,
    ProviderConfig,
    Subscription,
    Target,
    Tenant,
    UsageMetering,
    User,
    gen_uuid,
)
from src.db.session import get_db
from src.pipeline.contracts.tool_job import TargetKind, TargetSpec
from src.policy.scope import ScopeEngine, ScopeRule

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])

_SENSITIVE_KEY_FRAGMENTS: tuple[str, ...] = (
    "password",
    "secret",
    "token",
    "credential",
    "api_key",
    "private_key",
    "bearer",
    "authorization",
)


def _escape_ilike_pattern(fragment: str) -> str:
    """Escape ``%``, ``_``, and ``\\`` for SQL ``ILIKE`` with ``ESCAPE '\\'``."""
    return (
        fragment.replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )


def _is_sensitive_detail_key(key: str) -> bool:
    low = key.lower()
    return any(part in low for part in _SENSITIVE_KEY_FRAGMENTS)


_CSV_FORMULA_TRIGGER_FIRST_CHARS: frozenset[str] = frozenset("=+-@\t\r")


def _sanitize_csv_text_cell(value: str) -> str:
    """Neutralize CSV/spreadsheet formula injection (leading =, +, -, @, TAB, CR).

    Prefixes a TAB (OWASP CSV injection mitigation) so the cell is treated as text
    in common spreadsheet tools. TAB is used consistently so JSON in ``details_json``
    remains valid (JSON allows leading whitespace).
    """
    if value and value[0] in _CSV_FORMULA_TRIGGER_FIRST_CHARS:
        return "\t" + value
    return value


def _csv_export_cell(value: Any) -> str:
    """Stringify a CSV export field and apply formula-injection sanitization."""
    if value is None:
        return ""
    return _sanitize_csv_text_cell(str(value))


def _redact_audit_details(details: dict[str, Any] | None) -> dict[str, Any] | None:
    """Drop/replace detail keys and values that may carry secrets or raw PII."""

    if details is None:
        return None
    if not isinstance(details, dict):
        return None

    def _walk(obj: Any) -> Any:
        if isinstance(obj, dict):
            out: dict[str, Any] = {}
            for k, v in obj.items():
                if _is_sensitive_detail_key(str(k)):
                    out[str(k)] = "[redacted]"
                else:
                    out[str(k)] = _walk(v)
            return out
        if isinstance(obj, list):
            return [_walk(x) for x in obj]
        if isinstance(obj, str):
            if "@" in obj and "." in obj.split("@", 1)[-1]:
                return user_id_hash(obj)
            return obj
        return obj

    walked = _walk(details)
    return walked if isinstance(walked, dict) else None


_LLM_GLOBAL_ENV_FLAGS: tuple[tuple[str, str], ...] = (
    ("openai", "OPENAI_API_KEY"),
    ("deepseek", "DEEPSEEK_API_KEY"),
    ("openrouter", "OPENROUTER_API_KEY"),
    ("kimi", "KIMI_API_KEY"),
    ("perplexity", "PERPLEXITY_API_KEY"),
    ("google", "GOOGLE_API_KEY"),
)

_CANONICAL_LLM_PROVIDER_KEYS: frozenset[str] = frozenset(
    label for label, _ in _LLM_GLOBAL_ENV_FLAGS
) | frozenset({"anthropic"})

_MAX_LLM_FALLBACK_ENTRIES: int = 24
_MAX_LLM_MODEL_TOKEN_LEN: int = 256

# PATCH body.config: only these keys may be merged (no arbitrary mass-assignment).
_ALLOWED_LLM_PROVIDER_PATCH_CONFIG_KEYS: frozenset[str] = frozenset(
    {"model", "base_url", "model_fallback_chain"}
)

_RE_SECRET_SK_TOKEN = re.compile(r"sk-[A-Za-z0-9_-]{10,}")
_RE_SECRET_PK_TOKEN = re.compile(r"pk-[A-Za-z0-9_-]{10,}")
_RE_BEARER_CREDENTIAL = re.compile(
    r"(?i)Bearer\s+[A-Za-z0-9_\-.~+/=]{8,}"
)


def _mask_secret_like_string_literals(s: str) -> str:
    """Mask OpenAI-style tokens and similar material embedded in non-sensitive keys."""
    if not s:
        return s
    if len(s) >= 48 and re.fullmatch(r"[A-Za-z0-9+/]+=*", s):
        return "***"
    out = _RE_BEARER_CREDENTIAL.sub("Bearer ***", s)
    out = _RE_SECRET_SK_TOKEN.sub("***", out)
    return _RE_SECRET_PK_TOKEN.sub("***", out)


def _parse_model_fallback_chain_or_raise(v: Any) -> list[str] | None:
    """Same rules as :class:`ProviderConfigUpdate` ``model_fallback_chain``."""
    if v is None:
        return None
    if not isinstance(v, list):
        raise ValueError("model_fallback_chain must be a list of strings")
    if len(v) > _MAX_LLM_FALLBACK_ENTRIES:
        raise ValueError("model_fallback_chain is too long")
    out: list[str] = []
    for item in v:
        if not isinstance(item, str):
            raise ValueError("model_fallback_chain entries must be strings")
        tok = item.strip()
        if not tok:
            raise ValueError("model_fallback_chain entries must be non-empty")
        if len(tok) > _MAX_LLM_MODEL_TOKEN_LEN:
            raise ValueError("model id is too long")
        out.append(tok)
    return out


def _global_llm_env_configured() -> dict[str, bool]:
    """Which global LLM env keys are non-empty (never values)."""
    out: dict[str, bool] = {}
    for label, env_key in _LLM_GLOBAL_ENV_FLAGS:
        raw = (os.environ.get(env_key) or "").strip()
        out[label] = bool(raw)
    return out


def _sanitize_provider_config_tree(obj: Any) -> Any:
    """Redact secret-like keys for API responses (never log raw secrets)."""
    if isinstance(obj, dict):
        cleaned: dict[str, Any] = {}
        for k, v in obj.items():
            sk = str(k)
            if _is_sensitive_detail_key(sk):
                cleaned[sk] = "***"
            else:
                cleaned[sk] = _sanitize_provider_config_tree(v)
        return cleaned
    if isinstance(obj, list):
        return [_sanitize_provider_config_tree(x) for x in obj]
    if isinstance(obj, str):
        return _mask_secret_like_string_literals(obj)
    return obj


def _coerce_provider_config_dict(raw: Any) -> dict[str, Any]:
    return dict(raw) if isinstance(raw, dict) else {}


def _extract_stored_api_key(config: dict[str, Any]) -> str | None:
    for k in ("api_key", "apiKey"):
        v = config.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _api_key_last4(value: str) -> str:
    s = value.strip()
    if len(s) <= 4:
        return "****"
    return s[-4:]


def _extract_model_fallback_chain(config: dict[str, Any]) -> list[str] | None:
    raw = config.get("model_fallback_chain")
    if raw is None:
        return None
    if not isinstance(raw, list):
        return None
    out: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            return None
        tok = item.strip()
        if not tok or len(tok) > _MAX_LLM_MODEL_TOKEN_LEN:
            return None
        out.append(tok)
    if len(out) > _MAX_LLM_FALLBACK_ENTRIES:
        return None
    return out


def _provider_config_to_out(row: ProviderConfig) -> "ProviderConfigOut":
    cfg = _coerce_provider_config_dict(row.config)
    key = _extract_stored_api_key(cfg)
    safe_cfg = _sanitize_provider_config_tree(cfg)
    safe_dict = safe_cfg if isinstance(safe_cfg, dict) else {}
    return ProviderConfigOut(
        id=row.id,
        tenant_id=row.tenant_id,
        provider_key=row.provider_key,
        enabled=row.enabled,
        config=safe_dict or None,
        api_key_last4=_api_key_last4(key) if key else None,
        api_key_set=bool(key),
        model_fallback_chain=_extract_model_fallback_chain(cfg),
        created_at=row.created_at,
    )


def _validate_audit_time_window(
    since: datetime | None, until: datetime | None
) -> None:
    if since is not None and until is not None and until < since:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="until must be greater than or equal to since",
        )


def _audit_logs_filtered_select(
    *,
    tenant_id: str | None,
    search: str | None,
    since: datetime | None,
    until: datetime | None,
    event_type: str | None,
) -> Select[Any]:
    stmt: Select[Any] = select(AuditLog).order_by(AuditLog.created_at.desc())
    if tenant_id:
        stmt = stmt.where(cast(AuditLog.tenant_id, String) == tenant_id)
    if event_type:
        stmt = stmt.where(AuditLog.action == event_type)
    if since is not None:
        stmt = stmt.where(AuditLog.created_at >= since)
    if until is not None:
        stmt = stmt.where(AuditLog.created_at <= until)
    if search:
        pattern = f"%{_escape_ilike_pattern(search.strip())}%"
        stmt = stmt.where(
            or_(
                AuditLog.action.ilike(pattern, escape="\\"),
                AuditLog.resource_type.ilike(pattern, escape="\\"),
                cast(AuditLog.details, String).ilike(pattern, escape="\\"),
            )
        )
    return stmt


def _audit_row_export_dict(row: AuditLog) -> dict[str, Any]:
    raw_details = row.details
    details = (
        _redact_audit_details(dict(raw_details))
        if isinstance(raw_details, dict)
        else None
    )
    uid = str(row.user_id) if row.user_id else None
    ip = str(row.ip_address) if row.ip_address else None
    return {
        "id": row.id,
        "tenant_hash": tenant_hash(str(row.tenant_id)),
        "user_id_hash": user_id_hash(uid),
        "event_type": row.action,
        "resource_type": row.resource_type,
        "resource_id": row.resource_id,
        "details": details,
        "ip_address_hash": user_id_hash(ip) if ip else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }

# Dual-mode admin gate (``require_admin``) and its session helpers live in
# :mod:`src.auth.admin_dependencies` (ISS-T20-003 Phase 1, refactored in
# C7-T03 to break the circular import that arose when this module needed
# to import ``require_admin_mfa_passed`` from the same dependency layer).
# Only the public symbols are re-exported here so every existing
# ``from src.api.routers.admin import require_admin`` keeps working;
# the private helpers stay internal to ``src.auth.admin_dependencies``.
from src.auth.admin_dependencies import (  # noqa: E402, F401 — re-exports for backwards compat
    admin_key_header,
    require_admin,
    require_admin_mfa_passed,
)


# --- Schemas ---

_MAX_SCOPE_BLACKLIST_ENTRIES: int = 200
_MAX_SCOPE_PATTERN_LEN: int = 512
_TENANT_RATE_LIMIT_RPM_MIN: int = 1
_TENANT_RATE_LIMIT_RPM_MAX: int = 50_000
_TENANT_RETENTION_DAYS_MIN: int = 1
_TENANT_RETENTION_DAYS_MAX: int = 3650


class TenantOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    exports_sarif_junit_enabled: bool = False
    rate_limit_rpm: int | None = None
    scope_blacklist: list[str] | None = None
    retention_days: int | None = None
    pdf_archival_format: PdfArchivalFormat = "standard"
    created_at: datetime
    updated_at: datetime


class TenantCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)


class TenantPatch(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    exports_sarif_junit_enabled: bool | None = None
    rate_limit_rpm: int | None = Field(
        None,
        ge=_TENANT_RATE_LIMIT_RPM_MIN,
        le=_TENANT_RATE_LIMIT_RPM_MAX,
    )
    scope_blacklist: list[str] | None = None
    retention_days: int | None = Field(
        None,
        ge=_TENANT_RETENTION_DAYS_MIN,
        le=_TENANT_RETENTION_DAYS_MAX,
    )
    #: Closed taxonomy mirroring ``Tenant.pdf_archival_format``
    #: (``"standard"`` | ``"pdfa-2u"``). Pydantic ``Literal`` rejects any
    #: unknown value with HTTP 422, so the CHECK constraint at the DB layer
    #: is a defence-in-depth guard, not the primary validator.
    pdf_archival_format: PdfArchivalFormat | None = None

    @field_validator("scope_blacklist", mode="before")
    @classmethod
    def _coerce_scope_blacklist(cls, v: Any) -> list[str] | None:
        if v is None:
            return None
        if not isinstance(v, list):
            raise ValueError("scope_blacklist must be a list of strings")
        if len(v) == 0:
            return None
        if len(v) > _MAX_SCOPE_BLACKLIST_ENTRIES:
            raise ValueError(
                f"scope_blacklist must have at most {_MAX_SCOPE_BLACKLIST_ENTRIES} entries"
            )
        out: list[str] = []
        seen: set[str] = set()
        for item in v:
            if not isinstance(item, str):
                raise ValueError("scope_blacklist entries must be strings")
            s = item.strip()
            if not s:
                raise ValueError("scope_blacklist entries must be non-empty")
            if len(s) > _MAX_SCOPE_PATTERN_LEN:
                raise ValueError(
                    f"scope_blacklist entry must be at most {_MAX_SCOPE_PATTERN_LEN} characters"
                )
            if s not in seen:
                seen.add(s)
                out.append(s)
        return out


class UserOut(BaseModel):
    id: str
    tenant_id: str
    email: str
    is_active: bool
    created_at: datetime


class SubscriptionOut(BaseModel):
    id: str
    tenant_id: str
    plan: str
    status: str
    valid_until: datetime | None
    created_at: datetime


class ProviderConfigOut(BaseModel):
    """Tenant LLM provider row — secrets never returned as plaintext."""

    id: str
    tenant_id: str
    provider_key: str
    enabled: bool
    config: dict[str, Any] | None
    api_key_last4: str | None = None
    api_key_set: bool = False
    model_fallback_chain: list[str] | None = None
    created_at: datetime


class ProviderConfigCreate(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=36)
    provider_key: str = Field(min_length=1, max_length=100)
    enabled: bool = True

    @field_validator("provider_key", mode="before")
    @classmethod
    def _normalize_provider_key(cls, v: Any) -> str:
        if not isinstance(v, str):
            raise ValueError("provider_key must be a string")
        s = v.strip().lower()
        if s not in _CANONICAL_LLM_PROVIDER_KEYS:
            raise ValueError("unsupported provider_key")
        return s


class ProviderConfigUpdate(BaseModel):
    enabled: bool | None = None
    config: dict[str, Any] | None = None
    api_key: str | None = Field(
        default=None,
        description="Write-only. When set, replaces the stored api_key; empty string clears it.",
    )
    model_fallback_chain: list[str] | None = Field(
        default=None,
        description="Ordered model ids for fallback; persisted in config JSON.",
    )

    @field_validator("model_fallback_chain", mode="before")
    @classmethod
    def _validate_fallback_chain(cls, v: Any) -> list[str] | None:
        return _parse_model_fallback_chain_or_raise(v)


class LlmRuntimeSummaryOut(BaseModel):
    """Whether the worker process uses global env for LLM (not per-tenant DB yet)."""

    execution_uses_global_env: bool
    global_env_providers: dict[str, bool]


class PolicyOut(BaseModel):
    id: str
    tenant_id: str
    policy_type: str
    config: dict[str, Any] | None
    enabled: bool
    created_at: datetime


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    user_id: str | None
    action: str
    resource_type: str | None
    resource_id: str | None
    details: dict[str, Any] | None
    created_at: datetime


class UsageMeteringOut(BaseModel):
    id: str
    tenant_id: str
    metric_type: str
    value: int
    recorded_at: datetime


class HealthDashboardOut(BaseModel):
    database: bool
    redis: bool
    storage: bool
    status: str


# --- Tenants ---


async def _tenants_operator_subject(
    request: Request,
    x_operator_subject: str | None = Header(None, alias="X-Operator-Subject"),
) -> str:
    """Resolve the operator subject for tenant-update audit attribution.

    Mirrors :func:`src.api.routers.admin_bulk_ops._operator_subject_dep`:

    1. Real ``SessionPrincipal`` from the new cookie-session flow takes
       precedence (set on ``request.state.admin_session`` by
       :func:`require_admin`).
    2. Best-effort ``X-Operator-Subject`` header for the legacy
       ``X-Admin-Key`` shim (informational only — header is unauthenticated).
    3. ``"admin_api"`` fallback so audit rows never store ``NULL``.

    Cap at 256 chars to stay under the ``audit_logs.user_id`` and details
    field length budget.
    """
    principal = getattr(request.state, "admin_session", None)
    if isinstance(principal, SessionPrincipal):
        return principal.subject[:256]
    if x_operator_subject and x_operator_subject.strip():
        return x_operator_subject.strip()[:256]
    return "admin_api"


def _emit_tenant_field_audit(
    db: AsyncSession,
    *,
    tenant_id: str,
    field: str,
    old: object,
    new: object,
    operator_subject: str,
) -> None:
    """Emit one ``AuditLog`` row per *changed* tenant field.

    We deliberately do **not** snapshot the full Tenant row in ``details``
    (B6-T02 constraint: "never include the tenant data itself"). Each row
    captures only ``field``/``old``/``new``, the operator hash, and a
    deterministic resource pointer back at the tenant.

    Caller MUST only invoke this when ``old != new`` to avoid noise.
    """
    audit_id = gen_uuid()
    db.add(
        AuditLog(
            id=audit_id,
            tenant_id=tenant_id,
            user_id=None,
            action="tenant_update",
            resource_type="tenant",
            resource_id=tenant_id,
            details={
                "field": field,
                "old": old,
                "new": new,
                "operator_user_id_hash": user_id_hash(operator_subject),
            },
            ip_address=None,
        )
    )


@router.get("/tenants", response_model=list[TenantOut])
async def list_tenants(
    _: None = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> list[TenantOut]:
    """List tenants with pagination."""
    result = await db.execute(
        select(Tenant).order_by(Tenant.created_at.desc()).limit(limit).offset(offset)
    )
    rows = result.scalars().all()
    return [TenantOut.model_validate(r) for r in rows]


@router.post("/tenants", response_model=TenantOut)
async def create_tenant(
    body: TenantCreate,
    _: None = Depends(require_admin_mfa_passed),
    db: AsyncSession = Depends(get_db),
) -> TenantOut:
    """Create a new tenant."""
    tenant = Tenant(name=body.name)
    db.add(tenant)
    await db.flush()
    await db.refresh(tenant)
    return TenantOut.model_validate(tenant)


@router.get("/tenants/{tenant_id}", response_model=TenantOut)
async def get_tenant(
    tenant_id: str,
    _: None = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> TenantOut:
    """Get tenant by ID."""
    result = await db.execute(
        select(Tenant).where(cast(Tenant.id, String) == tenant_id)
    )
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return TenantOut.model_validate(tenant)


@router.patch("/tenants/{tenant_id}", response_model=TenantOut)
async def patch_tenant(
    tenant_id: str,
    body: TenantPatch,
    _: None = Depends(require_admin_mfa_passed),
    operator_subject: str = Depends(_tenants_operator_subject),
    db: AsyncSession = Depends(get_db),
) -> TenantOut:
    """Update tenant metadata (limits, blacklist, retention, SARIF/JUnit opt-in,
    PDF archival format).

    Emits one ``AuditLog`` row per *changed* field via
    :func:`_emit_tenant_field_audit`. ``pdf_archival_format`` is validated by
    Pydantic ``Literal`` (HTTP 422 on bad input) and re-checked at the DB layer
    via the ``ck_tenants_pdf_archival_format`` CHECK constraint (defence in
    depth — see Alembic 029).
    """
    updates = body.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="No fields to update",
        )
    result = await db.execute(
        select(Tenant).where(cast(Tenant.id, String) == tenant_id)
    )
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    audit_changes: list[tuple[str, object, object]] = []

    if "name" in updates:
        if updates["name"] is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="name cannot be null",
            )
        if tenant.name != updates["name"]:
            audit_changes.append(("name", tenant.name, updates["name"]))
            tenant.name = updates["name"]
    if "exports_sarif_junit_enabled" in updates:
        ev = updates["exports_sarif_junit_enabled"]
        if ev is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="exports_sarif_junit_enabled cannot be null",
            )
        if tenant.exports_sarif_junit_enabled != ev:
            audit_changes.append(
                ("exports_sarif_junit_enabled", tenant.exports_sarif_junit_enabled, ev)
            )
            tenant.exports_sarif_junit_enabled = ev
    if "rate_limit_rpm" in updates:
        if tenant.rate_limit_rpm != updates["rate_limit_rpm"]:
            audit_changes.append(
                ("rate_limit_rpm", tenant.rate_limit_rpm, updates["rate_limit_rpm"])
            )
            tenant.rate_limit_rpm = updates["rate_limit_rpm"]
    if "scope_blacklist" in updates:
        if tenant.scope_blacklist != updates["scope_blacklist"]:
            audit_changes.append(
                (
                    "scope_blacklist",
                    tenant.scope_blacklist,
                    updates["scope_blacklist"],
                )
            )
            tenant.scope_blacklist = updates["scope_blacklist"]
    if "retention_days" in updates:
        if tenant.retention_days != updates["retention_days"]:
            audit_changes.append(
                ("retention_days", tenant.retention_days, updates["retention_days"])
            )
            tenant.retention_days = updates["retention_days"]
    if "pdf_archival_format" in updates:
        new_format = updates["pdf_archival_format"]
        if new_format is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="pdf_archival_format cannot be null",
            )
        if new_format not in PDF_ARCHIVAL_FORMAT_VALUES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=(
                    "pdf_archival_format must be one of "
                    f"{list(PDF_ARCHIVAL_FORMAT_VALUES)}"
                ),
            )
        if tenant.pdf_archival_format != new_format:
            audit_changes.append(
                (
                    "pdf_archival_format",
                    tenant.pdf_archival_format,
                    new_format,
                )
            )
            tenant.pdf_archival_format = new_format

    for field, old, new in audit_changes:
        _emit_tenant_field_audit(
            db,
            tenant_id=tenant_id,
            field=field,
            old=old,
            new=new,
            operator_subject=operator_subject,
        )
        logger.info(
            "admin.tenant_update",
            extra={
                "event": "argus.admin.tenant_update",
                "tenant_hash": tenant_hash(tenant_id),
                "user_id_hash": user_id_hash(operator_subject),
                "field": field,
            },
        )

    await db.flush()
    await db.refresh(tenant)
    return TenantOut.model_validate(tenant)


@router.delete("/tenants/{tenant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_tenant(
    tenant_id: str,
    _: None = Depends(require_admin_mfa_passed),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Delete a tenant and dependent rows (FK ON DELETE CASCADE)."""
    result = await db.execute(
        select(Tenant).where(cast(Tenant.id, String) == tenant_id)
    )
    tenant = result.scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    await db.delete(tenant)
    await db.flush()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Tenant targets (scope editor) ---

_MAX_SCOPE_EDITOR_RULES: int = 256
_CIDR_PREVIEW_SAMPLE_CAP: int = 64
_HOSTNAME_SAFE_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?:\.(?!-)[A-Za-z0-9-]{1,63})*$"
)


class OwnershipProofStatusOut(BaseModel):
    """Read-only: durable proof lookup is optional per deployment."""

    lookup_available: bool = False
    verified: bool | None = None
    policy_requires_proof: bool | None = None


class TargetOut(BaseModel):
    id: str
    tenant_id: str
    url: str
    scope_config: dict[str, Any] | None
    created_at: datetime
    ownership_proof: OwnershipProofStatusOut


class TargetCreate(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    scope_config: dict[str, Any] | None = None


class TargetPatch(BaseModel):
    url: str | None = Field(None, min_length=1, max_length=2048)
    scope_config: dict[str, Any] | None = None


class DnsPreviewOut(BaseModel):
    hostname: str | None = None
    addresses: list[str] = Field(default_factory=list)
    error: str | None = None


class CidrPreviewOut(BaseModel):
    network: str
    address_total: str | None = None
    sample: list[str] = Field(default_factory=list)


class PreviewScopeOut(BaseModel):
    scope_allowed: bool
    scope_failure_summary: str | None = None
    dns: DnsPreviewOut | None = None
    cidr: CidrPreviewOut | None = None


class PreviewScopeBody(BaseModel):
    probe: str = Field(..., min_length=1, max_length=2048)
    rules: list[dict[str, Any]] = Field(default_factory=list, max_length=_MAX_SCOPE_EDITOR_RULES)
    port: int | None = Field(None, ge=1, le=65535)
    dns_hostname: str | None = Field(None, max_length=253)
    cidr: str | None = Field(None, max_length=49)


def _admin_parse_probe(probe: str) -> TargetSpec:
    s = probe.strip()
    if not s:
        raise ValueError("Probe is empty")
    low = s.lower()
    if low.startswith("http://") or low.startswith("https://"):
        return TargetSpec(kind=TargetKind.URL, url=s)
    try:
        ipaddress.ip_address(s)
        return TargetSpec(kind=TargetKind.IP, ip=s)
    except ValueError:
        pass
    if "/" in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
            return TargetSpec(kind=TargetKind.CIDR, cidr=str(net))
        except ValueError as exc:
            raise ValueError("Invalid CIDR notation") from exc
    if "." in s:
        return TargetSpec(kind=TargetKind.DOMAIN, domain=s.lower())
    return TargetSpec(kind=TargetKind.HOST, host=s.lower())


def _scope_rules_from_config(data: dict[str, Any] | None) -> list[ScopeRule]:
    if not data:
        return []
    if not isinstance(data, dict):
        raise ValueError("scope_config must be a JSON object")
    raw_rules = data.get("rules")
    if raw_rules is None:
        return []
    if not isinstance(raw_rules, list):
        raise ValueError("scope_config.rules must be an array")
    if len(raw_rules) > _MAX_SCOPE_EDITOR_RULES:
        raise ValueError("Too many scope rules")
    out: list[ScopeRule] = []
    for item in raw_rules:
        if not isinstance(item, dict):
            raise ValueError("Each scope rule must be an object")
        try:
            out.append(ScopeRule.model_validate(item))
        except ValidationError:
            raise ValueError("Invalid scope rule") from None
    return out


async def _policy_require_ownership_proof(
    db: AsyncSession, tenant_id: str
) -> bool | None:
    result = await db.execute(
        select(Policy).where(cast(Policy.tenant_id, String) == tenant_id)
    )
    rows = result.scalars().all()
    for pol in rows:
        if pol.enabled is False:
            continue
        cfg = pol.config
        if isinstance(cfg, dict) and "require_ownership_proof" in cfg:
            v = cfg["require_ownership_proof"]
            if isinstance(v, bool):
                return v
    return None


def _ownership_status_for_target(
    *,
    policy_requires_proof: bool | None,
) -> OwnershipProofStatusOut:
    return OwnershipProofStatusOut(
        lookup_available=False,
        verified=None,
        policy_requires_proof=policy_requires_proof,
    )


def _target_row_to_out(
    row: Target,
    *,
    policy_requires_proof: bool | None,
) -> TargetOut:
    return TargetOut(
        id=str(row.id),
        tenant_id=str(row.tenant_id),
        url=str(row.url),
        scope_config=row.scope_config if isinstance(row.scope_config, dict) else None,
        created_at=row.created_at,
        ownership_proof=_ownership_status_for_target(
            policy_requires_proof=policy_requires_proof
        ),
    )


async def _target_to_out(
    db: AsyncSession, row: Target, tenant_id: str
) -> TargetOut:
    pol = await _policy_require_ownership_proof(db, tenant_id)
    return _target_row_to_out(row, policy_requires_proof=pol)


async def _resolve_dns_preview(hostname: str) -> DnsPreviewOut:
    h = hostname.strip().lower()
    if not h or len(h) > 253:
        return DnsPreviewOut(hostname=None, addresses=[], error="Invalid hostname")
    if not _HOSTNAME_SAFE_RE.match(h):
        return DnsPreviewOut(hostname=h, addresses=[], error="Invalid hostname format")
    try:
        import dns.asyncresolver as dns_asyncresolver  # noqa: PLC0415
        import dns.exception as dnsexception  # noqa: PLC0415
    except ImportError:
        return DnsPreviewOut(
            hostname=h, addresses=[], error="DNS preview is unavailable on this server"
        )

    addresses: list[str] = []

    async def _collect(rrtype: str) -> None:
        try:
            answer = await dns_asyncresolver.resolve(h, rrtype, lifetime=5.0)
            for r in answer:
                if rrtype == "A":
                    addresses.append(r.address)
                elif rrtype == "AAAA" and hasattr(r, "address"):
                    addresses.append(r.address)
        except (
            dnsexception.DNSException,
            TimeoutError,
            OSError,
        ):
            return

    await _collect("A")
    await _collect("AAAA")
    if not addresses:
        return DnsPreviewOut(
            hostname=h, addresses=[], error="No DNS answers for this hostname"
        )
    return DnsPreviewOut(hostname=h, addresses=addresses[:32], error=None)


def _cidr_preview(cidr: str) -> CidrPreviewOut:
    s = cidr.strip()
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        raise ValueError("Invalid CIDR") from None
    num = net.num_addresses
    total_s: str | None
    try:
        n_int = int(num)
        total_s = str(n_int) if n_int <= 2**48 else "too large to enumerate"
    except (OverflowError, ValueError):
        total_s = "too large to enumerate"
    sample: list[str] = []
    if num <= 1:
        sample = [str(net.network_address)]
    else:
        lim = _CIDR_PREVIEW_SAMPLE_CAP
        if net.version == 4:
            gen = net.hosts() if net.prefixlen < 32 else iter([net.network_address])
            for i, host in enumerate(gen):
                if i >= lim:
                    break
                sample.append(str(host))
        else:
            for i, host in enumerate(net.hosts()):
                if i >= lim:
                    break
                sample.append(str(host))
    return CidrPreviewOut(network=str(net), address_total=total_s, sample=sample)


@router.get("/tenants/{tenant_id}/targets", response_model=list[TargetOut])
async def list_targets(
    tenant_id: str,
    _: None = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> list[TargetOut]:
    """List scan targets for a tenant (scope rules live in ``scope_config``)."""
    tr = await db.execute(select(Tenant).where(cast(Tenant.id, String) == tenant_id))
    if tr.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    q = (
        select(Target)
        .where(cast(Target.tenant_id, String) == tenant_id)
        .order_by(Target.created_at.desc())
    )
    result = await db.execute(q)
    rows = result.scalars().all()
    pol = await _policy_require_ownership_proof(db, tenant_id)
    return [_target_row_to_out(r, policy_requires_proof=pol) for r in rows]


@router.post("/tenants/{tenant_id}/targets", response_model=TargetOut)
async def create_target(
    tenant_id: str,
    body: TargetCreate,
    _: None = Depends(require_admin_mfa_passed),
    db: AsyncSession = Depends(get_db),
) -> TargetOut:
    """Create a target with optional ``scope_config`` (``rules`` array)."""
    tr = await db.execute(select(Tenant).where(cast(Tenant.id, String) == tenant_id))
    if tr.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    try:
        _scope_rules_from_config(body.scope_config)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from None
    row = Target(tenant_id=tenant_id, url=body.url, scope_config=body.scope_config)
    db.add(row)
    await db.flush()
    await db.refresh(row)
    return await _target_to_out(db, row, tenant_id)


@router.patch("/tenants/{tenant_id}/targets/{target_id}", response_model=TargetOut)
async def patch_target(
    tenant_id: str,
    target_id: str,
    body: TargetPatch,
    _: None = Depends(require_admin_mfa_passed),
    db: AsyncSession = Depends(get_db),
) -> TargetOut:
    """Update target URL and/or scope configuration."""
    updates = body.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="No fields to update",
        )
    tr = await db.execute(select(Tenant).where(cast(Tenant.id, String) == tenant_id))
    if tr.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    result = await db.execute(
        select(Target).where(
            cast(Target.tenant_id, String) == tenant_id,
            cast(Target.id, String) == target_id,
        )
    )
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Target not found")
    if "url" in updates:
        row.url = updates["url"]
    if "scope_config" in updates:
        if updates["scope_config"] is None:
            row.scope_config = None
        else:
            try:
                _scope_rules_from_config(updates["scope_config"])
            except ValueError as exc:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail=str(exc),
                ) from None
            row.scope_config = updates["scope_config"]
    await db.flush()
    await db.refresh(row)
    return await _target_to_out(db, row, tenant_id)


@router.delete(
    "/tenants/{tenant_id}/targets/{target_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_target(
    tenant_id: str,
    target_id: str,
    _: None = Depends(require_admin_mfa_passed),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Delete a target row."""
    tr = await db.execute(select(Tenant).where(cast(Tenant.id, String) == tenant_id))
    if tr.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    result = await db.execute(
        select(Target).where(
            cast(Target.tenant_id, String) == tenant_id,
            cast(Target.id, String) == target_id,
        )
    )
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Target not found")
    await db.delete(row)
    await db.flush()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/tenants/{tenant_id}/preview-scope", response_model=PreviewScopeOut)
async def preview_scope(
    tenant_id: str,
    body: PreviewScopeBody,
    _: None = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> PreviewScopeOut:
    """Preview DNS / CIDR expansion and evaluate probe against submitted rules."""
    tr = await db.execute(select(Tenant).where(cast(Tenant.id, String) == tenant_id))
    if tr.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    try:
        rules = _scope_rules_from_config({"rules": body.rules})
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from None
    try:
        spec = _admin_parse_probe(body.probe)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from None
    engine = ScopeEngine(rules=tuple(rules))
    decision = engine.check(spec, port=body.port)
    dns_out: DnsPreviewOut | None = None
    if body.dns_hostname and body.dns_hostname.strip():
        dns_out = await _resolve_dns_preview(body.dns_hostname)
    cidr_out: CidrPreviewOut | None = None
    if body.cidr and body.cidr.strip():
        try:
            cidr_out = _cidr_preview(body.cidr)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from None
    return PreviewScopeOut(
        scope_allowed=decision.allowed,
        scope_failure_summary=decision.failure_summary,
        dns=dns_out,
        cidr=cidr_out,
    )


# --- Users ---


@router.get("/users", response_model=list[UserOut])
async def list_users(
    _: None = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    tenant_id: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> list[UserOut]:
    """List users, optionally filtered by tenant."""
    q = select(User).order_by(User.created_at.desc())
    if tenant_id:
        q = q.where(cast(User.tenant_id, String) == tenant_id)
    result = await db.execute(q.limit(limit).offset(offset))
    rows = result.scalars().all()
    return [UserOut.model_validate(r) for r in rows]


# --- Subscriptions ---


@router.get("/subscriptions", response_model=list[SubscriptionOut])
async def list_subscriptions(
    _: None = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    tenant_id: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> list[SubscriptionOut]:
    """List subscriptions, optionally filtered by tenant."""
    q = select(Subscription).order_by(Subscription.created_at.desc())
    if tenant_id:
        q = q.where(cast(Subscription.tenant_id, String) == tenant_id)
    result = await db.execute(q.limit(limit).offset(offset))
    rows = result.scalars().all()
    return [SubscriptionOut.model_validate(r) for r in rows]


# --- Providers / LLM ---


@router.get("/llm/runtime-summary", response_model=LlmRuntimeSummaryOut)
async def llm_runtime_summary(_: None = Depends(require_admin)) -> LlmRuntimeSummaryOut:
    """Non-secret snapshot: global env LLM keys present; orchestration still env-based."""
    return LlmRuntimeSummaryOut(
        execution_uses_global_env=True,
        global_env_providers=_global_llm_env_configured(),
    )


@router.post("/providers", response_model=ProviderConfigOut, status_code=status.HTTP_201_CREATED)
async def create_provider(
    body: ProviderConfigCreate,
    _: None = Depends(require_admin_mfa_passed),
    db: AsyncSession = Depends(get_db),
) -> ProviderConfigOut:
    """Create a tenant provider row (metadata only until api_key is PATCHed)."""
    tr = await db.execute(select(Tenant).where(cast(Tenant.id, String) == body.tenant_id))
    if tr.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    dup = await db.execute(
        select(ProviderConfig).where(
            cast(ProviderConfig.tenant_id, String) == body.tenant_id,
            ProviderConfig.provider_key == body.provider_key,
        )
    )
    if dup.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=409,
            detail="Provider already exists for this tenant",
        )
    prov = ProviderConfig(
        tenant_id=body.tenant_id,
        provider_key=body.provider_key,
        enabled=body.enabled,
        config=None,
    )
    db.add(prov)
    await db.flush()
    await db.refresh(prov)
    return _provider_config_to_out(prov)


@router.get("/providers", response_model=list[ProviderConfigOut])
async def list_providers(
    _: None = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    tenant_id: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> list[ProviderConfigOut]:
    """List provider configs (API keys masked; config JSON redacted)."""
    q = select(ProviderConfig).order_by(ProviderConfig.created_at.desc())
    if tenant_id:
        q = q.where(cast(ProviderConfig.tenant_id, String) == tenant_id)
    result = await db.execute(q.limit(limit).offset(offset))
    rows = result.scalars().all()
    return [_provider_config_to_out(r) for r in rows]


@router.patch("/providers/{provider_id}", response_model=ProviderConfigOut)
async def update_provider(
    provider_id: str,
    body: ProviderConfigUpdate,
    _: None = Depends(require_admin_mfa_passed),
    db: AsyncSession = Depends(get_db),
) -> ProviderConfigOut:
    """Update provider config; ``api_key`` is write-only and never echoed."""
    result = await db.execute(select(ProviderConfig).where(ProviderConfig.id == provider_id))
    prov = result.scalar_one_or_none()
    if not prov:
        raise HTTPException(status_code=404, detail="Provider not found")
    if body.enabled is not None:
        prov.enabled = body.enabled

    merged = _coerce_provider_config_dict(prov.config)

    if body.config is not None:
        raw_keys = [str(k) for k in body.config.keys()]
        unknown = [k for k in raw_keys if k not in _ALLOWED_LLM_PROVIDER_PATCH_CONFIG_KEYS]
        if unknown:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    "Unknown provider config keys: "
                    + ", ".join(sorted(set(unknown)))
                ),
            )
        for sk, v in body.config.items():
            sk_s = str(sk)
            if sk_s == "model_fallback_chain":
                try:
                    parsed = _parse_model_fallback_chain_or_raise(v)
                except ValueError as exc:
                    raise HTTPException(
                        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                        detail=str(exc),
                    ) from None
                if parsed is None:
                    merged.pop("model_fallback_chain", None)
                else:
                    merged["model_fallback_chain"] = parsed
            elif sk_s in ("model", "base_url"):
                merged[sk_s] = v

    fields_set = getattr(body, "model_fields_set", set())
    if "api_key" in fields_set:
        if body.api_key is not None and body.api_key.strip() == "":
            merged.pop("api_key", None)
            merged.pop("apiKey", None)
        elif body.api_key is not None:
            merged["api_key"] = body.api_key.strip()

    if body.model_fallback_chain is not None:
        merged["model_fallback_chain"] = list(body.model_fallback_chain)

    prov.config = merged or None
    await db.flush()
    await db.refresh(prov)
    return _provider_config_to_out(prov)


# --- Policies ---


@router.get("/policies", response_model=list[PolicyOut])
async def list_policies(
    _: None = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    tenant_id: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> list[PolicyOut]:
    """List policies."""
    q = select(Policy).order_by(Policy.created_at.desc())
    if tenant_id:
        q = q.where(cast(Policy.tenant_id, String) == tenant_id)
    result = await db.execute(q.limit(limit).offset(offset))
    rows = result.scalars().all()
    return [PolicyOut.model_validate(r) for r in rows]


# --- Audit logs ---


@router.get(
    "/audit-logs",
    response_model=list[AuditLogOut],
    description=(
        "Full internal admin view: returns audit rows as stored (raw ``tenant_id``, "
        "``user_id``, ``details``, etc.). Intended for operators inside the trust "
        "boundary; not redacted for external sharing."
    ),
)
async def list_audit_logs(
    _: None = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    tenant_id: str | None = Query(None),
    q: str | None = Query(None, max_length=500, description="Search action, resource_type, details (ILIKE)"),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
    event_type: str | None = Query(
        None,
        max_length=100,
        description="Exact match for the persisted action / event type",
    ),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> list[AuditLogOut]:
    """List audit logs for internal admin use (raw identifiers and details as stored).

    This endpoint exposes the same fields persisted in ``AuditLog`` (including raw
    ``tenant_id``, ``user_id``, and ``details``). For redacted/hashed exports safe to
    share outside the admin trust boundary, use ``GET /admin/audit-logs/export``.

    Pagination matches other admin list routes (offset/limit). Rows are ordered by
    ``created_at`` descending. The composite index ``ix_audit_logs_tenant_created``
    supports tenant-scoped time windows; the design target is p95 ≤ 500ms on a
    reference-sized dataset. CI does not run paired load tests, so treat that
    latency goal as unvalidated outside a dedicated performance environment.
    """
    _validate_audit_time_window(since, until)
    search = q.strip() if q and q.strip() else None
    stmt = _audit_logs_filtered_select(
        tenant_id=tenant_id,
        search=search,
        since=since,
        until=until,
        event_type=event_type,
    )
    result = await db.execute(stmt.limit(limit).offset(offset))
    rows = result.scalars().all()
    return [AuditLogOut.model_validate(r) for r in rows]


@router.get(
    "/audit-logs/export",
    description=(
        "Redacted export for external sharing: tenant/user/IP are hashed, sensitive "
        "detail keys and email-shaped strings are redacted/hashed. CSV cells are "
        "sanitized against formula injection. Same filters as the list endpoint, "
        "without raw ``tenant_id`` / ``user_id`` in the payload."
    ),
)
async def export_audit_logs(
    _: None = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    tenant_id: str | None = Query(None),
    q: str | None = Query(None, max_length=500),
    since: datetime | None = Query(None),
    until: datetime | None = Query(None),
    event_type: str | None = Query(None, max_length=100),
    limit: int = Query(500, ge=1, le=2000, description="Maximum rows returned"),
    export_format: Literal["json", "csv"] = Query(
        "json",
        alias="format",
        description="Export serialization",
    ),
) -> Response:
    """Export audit rows in JSON or CSV for sharing outside the raw admin view.

    Unlike ``GET /admin/audit-logs``, this response does not include raw
    ``tenant_id`` or ``user_id``; it uses ``tenant_hash`` / ``user_id_hash`` and
    redacts sensitive paths inside ``details``. CSV output applies formula-injection
    mitigation on all textual columns (including ``details_json``).

    Filtering parameters mirror ``GET /admin/audit-logs`` (tenant, search, time
    range, event type, limit). Sensitive JSON keys (tokens, secrets, etc.) and
    email-shaped strings are redacted or hashed consistently with
    :func:`~src.core.observability.user_id_hash` /
    :func:`~src.core.observability.tenant_hash` usage elsewhere in admin audit
    metadata (e.g. bulk operations).
    """
    _validate_audit_time_window(since, until)
    search = q.strip() if q and q.strip() else None
    stmt = _audit_logs_filtered_select(
        tenant_id=tenant_id,
        search=search,
        since=since,
        until=until,
        event_type=event_type,
    )
    result = await db.execute(stmt.limit(limit))
    rows = result.scalars().all()
    export_rows = [_audit_row_export_dict(r) for r in rows]

    if export_format == "json":
        return Response(
            content=json.dumps(export_rows, default=str),
            media_type="application/json; charset=utf-8",
            headers={
                "Content-Disposition": 'attachment; filename="audit_logs.json"'
            },
        )

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "id",
            "tenant_hash",
            "user_id_hash",
            "event_type",
            "resource_type",
            "resource_id",
            "details_json",
            "ip_address_hash",
            "created_at",
        ]
    )
    for item in export_rows:
        details_cell = (
            json.dumps(item["details"], ensure_ascii=False, default=str)
            if item["details"] is not None
            else ""
        )
        writer.writerow(
            [
                _csv_export_cell(item["id"]),
                _csv_export_cell(item["tenant_hash"]),
                _csv_export_cell(item["user_id_hash"]),
                _csv_export_cell(item["event_type"]),
                _csv_export_cell(item["resource_type"] or ""),
                _csv_export_cell(item["resource_id"] or ""),
                _csv_export_cell(details_cell),
                _csv_export_cell(item["ip_address_hash"] or ""),
                _csv_export_cell(item["created_at"] or ""),
            ]
        )
    return Response(
        content=buf.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="audit_logs.csv"'},
    )


# --- Usage metering ---


@router.get("/usage", response_model=list[UsageMeteringOut])
async def list_usage(
    _: None = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    tenant_id: str | None = Query(None),
    metric_type: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> list[UsageMeteringOut]:
    """List usage metering records."""
    q = select(UsageMetering).order_by(UsageMetering.recorded_at.desc())
    if tenant_id:
        q = q.where(cast(UsageMetering.tenant_id, String) == tenant_id)
    if metric_type:
        q = q.where(UsageMetering.metric_type == metric_type)
    result = await db.execute(q.limit(limit).offset(offset))
    rows = result.scalars().all()
    return [UsageMeteringOut.model_validate(r) for r in rows]


# --- Health dashboard ---


@router.get("/health/dashboard", response_model=HealthDashboardOut)
async def health_dashboard(
    _: None = Depends(require_admin),
) -> HealthDashboardOut:
    """Health dashboard — DB, Redis, storage, queue status."""
    from src.core.redis_client import redis_ping
    from src.db.session import engine
    from src.storage.s3 import ensure_bucket

    db_ok = False
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        pass

    redis_ok = redis_ping()
    storage_ok = ensure_bucket() and ensure_bucket(settings.minio_reports_bucket)

    status_val = "ok" if (db_ok and redis_ok and storage_ok) else "degraded"

    return HealthDashboardOut(
        database=db_ok,
        redis=redis_ok,
        storage=storage_ok,
        status=status_val,
    )
