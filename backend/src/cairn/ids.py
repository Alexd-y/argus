"""Human-readable scoped ref-id generation (``proj_001`` / ``f001`` / ``i001`` / ``h001``).

Ported from ``_external/Cairn/cairn/src/cairn/server/services.py`` (``next_*_id``).
Upstream uses SQLite ``UPDATE ... RETURNING`` under a single-writer dispatcher; here
the increment is atomic via Postgres ``INSERT ... ON CONFLICT DO UPDATE RETURNING``,
which is safe under concurrent distributed writers (each caller gets a distinct value).

Ref-ids are used **only** in prompts and exports; external APIs work by UUID but also
accept a ref within a project's scope.
"""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

_PROJECT_COUNTER_KIND = "project"

_FACT_PREFIX = "f"
_INTENT_PREFIX = "i"
_HINT_PREFIX = "h"


async def _next_scoped_value(
    session: AsyncSession, tenant_id: str, project_id: str, kind: str
) -> int:
    """Atomically increment and return the per-project counter for ``kind``."""
    result = await session.execute(
        text("""
            INSERT INTO cairn_scoped_counters (project_id, kind, tenant_id, value)
            VALUES (:pid, :kind, :tid, 1)
            ON CONFLICT (project_id, kind)
            DO UPDATE SET value = cairn_scoped_counters.value + 1
            RETURNING value
            """),
        {"pid": project_id, "kind": kind, "tid": tenant_id},
    )
    return int(result.scalar_one())


async def _next_tenant_value(session: AsyncSession, tenant_id: str, kind: str) -> int:
    """Atomically increment and return the per-tenant counter for ``kind``."""
    result = await session.execute(
        text("""
            INSERT INTO cairn_tenant_counters (tenant_id, kind, value)
            VALUES (:tid, :kind, 1)
            ON CONFLICT (tenant_id, kind)
            DO UPDATE SET value = cairn_tenant_counters.value + 1
            RETURNING value
            """),
        {"tid": tenant_id, "kind": kind},
    )
    return int(result.scalar_one())


async def next_project_ref(session: AsyncSession, tenant_id: str) -> str:
    """Return the next project ref for a tenant, e.g. ``proj_001``."""
    value = await _next_tenant_value(session, tenant_id, _PROJECT_COUNTER_KIND)
    return f"proj_{value:03d}"


async def next_fact_ref(session: AsyncSession, tenant_id: str, project_id: str) -> str:
    """Return the next fact ref for a project, e.g. ``f001``."""
    value = await _next_scoped_value(session, tenant_id, project_id, "fact")
    return f"{_FACT_PREFIX}{value:03d}"


async def next_intent_ref(session: AsyncSession, tenant_id: str, project_id: str) -> str:
    """Return the next intent ref for a project, e.g. ``i001``."""
    value = await _next_scoped_value(session, tenant_id, project_id, "intent")
    return f"{_INTENT_PREFIX}{value:03d}"


async def next_hint_ref(session: AsyncSession, tenant_id: str, project_id: str) -> str:
    """Return the next hint ref for a project, e.g. ``h001``."""
    value = await _next_scoped_value(session, tenant_id, project_id, "hint")
    return f"{_HINT_PREFIX}{value:03d}"
