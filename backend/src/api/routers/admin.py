"""Admin router — /api/v1/admin/* for tenants, users, providers, audit, health."""

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from sqlalchemy import cast, select, String, text
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.db.models import (
    AuditLog,
    Policy,
    ProviderConfig,
    Subscription,
    Tenant,
    UsageMetering,
    User,
)
from src.db.session import get_db

router = APIRouter(prefix="/admin", tags=["admin"])

admin_key_header = APIKeyHeader(name="X-Admin-Key", auto_error=False)


async def require_admin(
    request: Request,
    admin_key: str | None = Depends(admin_key_header),
) -> None:
    """Require admin auth: X-Admin-Key when ADMIN_API_KEY is set, else allow (dev placeholder)."""
    if settings.admin_api_key:
        if not admin_key or admin_key != settings.admin_api_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Admin access required",
            )


# --- Schemas ---


class TenantOut(BaseModel):
    id: str
    name: str
    created_at: datetime
    updated_at: datetime


class TenantCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)


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
    id: str
    tenant_id: str
    provider_key: str
    enabled: bool
    config: dict[str, Any] | None
    created_at: datetime


class ProviderConfigUpdate(BaseModel):
    enabled: bool | None = None
    config: dict[str, Any] | None = None


class PolicyOut(BaseModel):
    id: str
    tenant_id: str
    policy_type: str
    config: dict[str, Any] | None
    enabled: bool
    created_at: datetime


class AuditLogOut(BaseModel):
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
    _: None = Depends(require_admin),
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


# --- Providers ---


@router.get("/providers", response_model=list[ProviderConfigOut])
async def list_providers(
    _: None = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    tenant_id: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> list[ProviderConfigOut]:
    """List provider configs."""
    q = select(ProviderConfig).order_by(ProviderConfig.created_at.desc())
    if tenant_id:
        q = q.where(cast(ProviderConfig.tenant_id, String) == tenant_id)
    result = await db.execute(q.limit(limit).offset(offset))
    rows = result.scalars().all()
    return [ProviderConfigOut.model_validate(r) for r in rows]


@router.patch("/providers/{provider_id}", response_model=ProviderConfigOut)
async def update_provider(
    provider_id: str,
    body: ProviderConfigUpdate,
    _: None = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> ProviderConfigOut:
    """Update provider config."""
    result = await db.execute(select(ProviderConfig).where(ProviderConfig.id == provider_id))
    prov = result.scalar_one_or_none()
    if not prov:
        raise HTTPException(status_code=404, detail="Provider not found")
    if body.enabled is not None:
        prov.enabled = body.enabled
    if body.config is not None:
        prov.config = body.config
    await db.flush()
    await db.refresh(prov)
    return ProviderConfigOut.model_validate(prov)


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


@router.get("/audit-logs", response_model=list[AuditLogOut])
async def list_audit_logs(
    _: None = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
    tenant_id: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> list[AuditLogOut]:
    """List audit logs (read-only)."""
    q = select(AuditLog).order_by(AuditLog.created_at.desc())
    if tenant_id:
        q = q.where(cast(AuditLog.tenant_id, String) == tenant_id)
    result = await db.execute(q.limit(limit).offset(offset))
    rows = result.scalars().all()
    return [AuditLogOut.model_validate(r) for r in rows]


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
    storage_ok = ensure_bucket()

    status_val = "ok" if (db_ok and redis_ok and storage_ok) else "degraded"

    return HealthDashboardOut(
        database=db_ok,
        redis=redis_ok,
        storage=storage_ok,
        status=status_val,
    )
