"""Shared fixtures for the T39 webhook DLQ admin API test suite.

Test architecture
-----------------
The router under test (`src.api.routers.admin_webhook_dlq`) interacts with
the persistent DAO (`src.mcp.services.notifications.webhook_dlq_persistence`)
through `async_session_factory`. To exercise the real DAO + ORM round-trip
without spinning up Postgres we patch `async_session_factory` (at the
router's import site) to yield AsyncSessions bound to a per-test in-memory
SQLite engine seeded by Alembic revision 027 — mirroring the SQLite
isolation pattern from `tests/notifications/test_webhook_dlq_persistence.py`.

Cross-loop note
---------------
HTTP requests are issued via `httpx.AsyncClient` + `ASGITransport` so the
ASGI handler runs in the test's event loop. This keeps the per-test SQLite
engine (bound to that same loop) safely reachable from inside the
endpoint coroutine. `starlette.testclient.TestClient` would have routed
through a background thread loop and broken aiosqlite affinity.

Audit log mocking
-----------------
The production `AuditLog.details` column is `JSONB`, which SQLite cannot
materialise. The router calls `_emit_audit(session, ...)` so we monkey-patch
that symbol on the router module and capture call kwargs in
`audit_emitter`. This lets every replay/abandon test assert the canonical
audit-payload shape (`entry_id`, `adapter_name`, `event_id`, `success`,
`attempt_count`, `reason`, ...) without ever touching the audit table.

Notes on auto-classification
----------------------------
The repo-level `tests/conftest.py::_classify_item` auto-marks tests with
`requires_postgres` when (a) the file pulls the `client` fixture, (b) the
file lives at `tests/test_*.py`, or (c) the source body matches a Postgres
URL regex. We:

* Name our HTTP fixture `api_client` — NOT `client` — so rule (a) is bypassed.
* Place tests under `tests/api/admin/` (subdir, not root) — so rule (b) is bypassed.
* Use only `sqlite+aiosqlite:///:memory:` URLs — rule (c)'s Postgres regex
  has no match.

The combined effect: the suite runs by default in `pytest -q` without
needing a Docker stack, exactly like `tests/notifications/test_webhook_dlq_persistence.py`.
"""

from __future__ import annotations

import importlib.util
import os
import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Layer 1 — safe environment defaults (mirrors `tests/unit/conftest.py`).
# Must run BEFORE any `src.*` import lower in the file.
# ---------------------------------------------------------------------------

os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault(
    "JWT_SECRET",
    "test-secret-not-for-prod-but-required-by-settings",
)
os.environ.setdefault("ARGUS_TEST_MODE", "1")


# ---------------------------------------------------------------------------
# Layer 2 — heavy `src.*` imports (settings + ORM + Alembic helpers).
# ---------------------------------------------------------------------------

from alembic.migration import MigrationContext  # noqa: E402
from alembic.operations import Operations  # noqa: E402
from sqlalchemy import event, text  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool  # noqa: E402

from src.core.config import settings  # noqa: E402
from src.db.models import WebhookDlqEntry  # noqa: E402
from src.mcp.services.notifications import webhook_dlq_persistence as dlq_dao  # noqa: E402
from src.mcp.services.notifications.schemas import (  # noqa: E402
    NotificationEvent,
    NotificationSeverity,
)


# ---------------------------------------------------------------------------
# Constants — every magic value lives here so a future schema bump is a
# single-line edit at the top of this conftest.
# ---------------------------------------------------------------------------

_BACKEND_ROOT: Path = Path(__file__).resolve().parents[3]
_VERSIONS_DIR: Path = _BACKEND_ROOT / "alembic" / "versions"
_REVISION: str = "027"

#: Pinned admin API key — patched onto `settings.admin_api_key` per test.
ADMIN_API_KEY: str = "test-admin-key-webhook-dlq"

#: Stable tenant UUIDs (UUID v4 layout — required by `_admin_tenant_dep`).
TENANT_A: str = "11111111-1111-4111-8111-111111111111"
TENANT_B: str = "22222222-2222-4222-8222-222222222222"
TENANT_C: str = "33333333-3333-4333-8333-333333333333"

#: Operator subject used in every header set — mirrors the canonical
#: format used by `tests/unit/api/test_admin_scan_schedules_crud.py`.
OPERATOR_SUBJECT: str = "soc-team@argus.example"

#: Audit `event_type` taxonomy emitted by the router.
EVENT_DLQ_REPLAY: str = "webhook_dlq.replay"
EVENT_DLQ_ABANDON: str = "webhook_dlq.abandon"

#: Default canonical valid reason — exactly 30 chars, well above the
#: 10-char minimum + below the 500-char maximum.
DEFAULT_REASON: str = "Operator-driven manual replay"


# ---------------------------------------------------------------------------
# Header builders — mirror the X-Admin-Key / X-Admin-Role / X-Admin-Tenant /
# X-Operator-Subject envelope used by every Batch 2-4 admin test module.
# ---------------------------------------------------------------------------


def _base_headers() -> dict[str, str]:
    return {
        "X-Admin-Key": ADMIN_API_KEY,
        "X-Operator-Subject": OPERATOR_SUBJECT,
    }


def headers_super_admin(tenant: str | None = None) -> dict[str, str]:
    """Super-admin envelope; optional tenant filter pin."""
    h = _base_headers()
    h["X-Admin-Role"] = "super-admin"
    if tenant is not None:
        h["X-Admin-Tenant"] = tenant
    return h


def headers_admin(tenant: str) -> dict[str, str]:
    """Admin envelope scoped to ``tenant``."""
    h = _base_headers()
    h["X-Admin-Role"] = "admin"
    h["X-Admin-Tenant"] = tenant
    return h


def headers_admin_no_tenant() -> dict[str, str]:
    """Admin envelope WITHOUT X-Admin-Tenant (triggers 403 ``tenant_required``)."""
    h = _base_headers()
    h["X-Admin-Role"] = "admin"
    return h


def headers_operator() -> dict[str, str]:
    """Operator envelope (always 403 on this admin surface)."""
    h = _base_headers()
    h["X-Admin-Role"] = "operator"
    return h


# ---------------------------------------------------------------------------
# Schema bootstrap — apply Alembic revision 027 against in-memory SQLite.
# ---------------------------------------------------------------------------


def _load_revision_module() -> Any:
    """Import revision 027 as a standalone module (no full chain run)."""
    matches = list(_VERSIONS_DIR.glob(f"{_REVISION}_*.py"))
    assert matches, f"revision {_REVISION} not found under {_VERSIONS_DIR}"
    spec = importlib.util.spec_from_file_location(
        f"_alembic_{_REVISION}", matches[0]
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _bootstrap_schema_sync(conn: Any) -> None:
    """Create minimal ``tenants`` table + apply revision 027."""
    conn.execute(
        text(
            "CREATE TABLE tenants ("
            "id VARCHAR(36) PRIMARY KEY, "
            "name VARCHAR(255) NOT NULL"
            ")"
        )
    )
    module = _load_revision_module()
    ctx = MigrationContext.configure(conn)
    with Operations.context(ctx):
        module.upgrade()


# ---------------------------------------------------------------------------
# Fixtures — engine / session factory / session-factory patch.
# ---------------------------------------------------------------------------


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    """Per-test in-memory async SQLite engine with revision 027 applied."""
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )

    @event.listens_for(eng.sync_engine, "connect")
    def _enable_sqlite_fk(dbapi_conn: Any, _conn_record: Any) -> None:
        cursor = dbapi_conn.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    async with eng.begin() as conn:
        await conn.run_sync(_bootstrap_schema_sync)

    try:
        yield eng
    finally:
        await eng.dispose()


@pytest.fixture
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """Per-test ``AsyncSession`` for direct DAO assertions."""
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        try:
            yield s
        finally:
            await s.rollback()


@pytest.fixture
def session_factory_patch(engine: AsyncEngine):
    """Return a callable matching ``async_session_factory()`` semantics.

    The router does ``async with async_session_factory() as session:`` —
    we mimic that with a fresh ``async_sessionmaker`` bound to the per-test
    SQLite engine.
    """
    sm = async_sessionmaker(engine, expire_on_commit=False)

    @asynccontextmanager
    async def _cm() -> AsyncIterator[AsyncSession]:
        async with sm() as s:
            yield s

    def _factory() -> Any:
        return _cm()

    return _factory


@pytest.fixture(autouse=True)
def _patch_router_session(
    session_factory_patch, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Re-route the router's `async_session_factory` to the in-memory SQLite engine."""
    monkeypatch.setattr(
        "src.api.routers.admin_webhook_dlq.async_session_factory",
        session_factory_patch,
    )


# ---------------------------------------------------------------------------
# Audit emitter capture — the production AuditLog model uses JSONB which
# SQLite cannot materialise. We replace `_emit_audit` at the router with a
# capturing stub so every test can assert the canonical kwargs without
# persisting an AuditLog row.
# ---------------------------------------------------------------------------


class AuditEmitter:
    """Test double for `_emit_audit` — records every invocation."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(self, session: AsyncSession, **kwargs: Any) -> None:
        # Capture a defensive deep copy so later mutations on `details`
        # cannot rewrite assertions.
        record = dict(kwargs)
        details = kwargs.get("details")
        if isinstance(details, dict):
            record["details"] = dict(details)
        self.calls.append(record)

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def assert_not_called(self) -> None:
        assert self.calls == [], f"_emit_audit was called: {self.calls}"

    def last(self) -> dict[str, Any]:
        assert self.calls, "_emit_audit was never called"
        return self.calls[-1]


@pytest.fixture
def audit_emitter(monkeypatch: pytest.MonkeyPatch) -> AuditEmitter:
    """Replace `_emit_audit` on the router module with a capturing stub."""
    emitter = AuditEmitter()
    monkeypatch.setattr(
        "src.api.routers.admin_webhook_dlq._emit_audit",
        emitter,
    )
    return emitter


# ---------------------------------------------------------------------------
# Admin API key fixture — mirrors `_admin_api_key` from
# `tests/unit/api/test_admin_scan_schedules_crud.py`.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _admin_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin `settings.admin_api_key` so `require_admin` accepts X-Admin-Key."""
    monkeypatch.setattr(settings, "admin_api_key", ADMIN_API_KEY)


# ---------------------------------------------------------------------------
# Override the parent autouse `override_auth` fixture with a no-op.
# We do not use `get_required_auth` on this surface (admin routes are gated
# by `require_admin` + `X-Admin-Key`), so the parent fixture's heavy import
# chain is wasted work.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def override_auth() -> Iterator[None]:
    """Neutralise the parent `override_auth` fixture for this subtree."""
    yield


# ---------------------------------------------------------------------------
# HTTP client — `httpx.AsyncClient` + `ASGITransport` keeps everything in
# the test's event loop (avoids `starlette.testclient.TestClient`'s thread
# pool which would break aiosqlite engine affinity).
# ---------------------------------------------------------------------------


@pytest.fixture
async def api_client():
    """Async HTTP client wired directly to the FastAPI ASGI app."""
    from httpx import ASGITransport, AsyncClient

    from main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as ac:
        yield ac


# ---------------------------------------------------------------------------
# Domain helpers — tenants + DLQ rows.
# ---------------------------------------------------------------------------


async def seed_tenant(session: AsyncSession, *, tenant_id: str, name: str) -> None:
    """Insert one minimal `tenants` row and commit."""
    await session.execute(
        text("INSERT INTO tenants (id, name) VALUES (:id, :name)"),
        {"id": tenant_id, "name": name},
    )
    await session.commit()


def make_notification_payload(
    *,
    tenant_id: str,
    event_id: str = "evt-test-0000",
    event_type: str = "finding.created",
    severity: NotificationSeverity = NotificationSeverity.MEDIUM,
    title: str = "Test finding",
    summary: str = "Test summary for replay payload reconstruction.",
) -> dict[str, Any]:
    """Build a payload that round-trips through `NotificationEvent.model_validate`."""
    event = NotificationEvent(
        event_id=event_id,
        event_type=event_type,
        severity=severity,
        title=title,
        summary=summary,
        tenant_id=tenant_id,
    )
    return event.model_dump(mode="json")


async def enqueue_dlq_entry(
    session: AsyncSession,
    *,
    tenant_id: str,
    adapter_name: str = "slack",
    event_type: str = "finding.created",
    event_id: str = "evt-test-0000",
    target_url: str = "https://hooks.slack.example/T0/B0/secret-token",
    payload: dict[str, Any] | None = None,
    last_error_code: str = "http_5xx",
    last_status_code: int | None = 503,
    attempt_count: int = 0,
) -> WebhookDlqEntry:
    """Enqueue one DLQ row via the production DAO and commit."""
    actual_payload = (
        payload
        if payload is not None
        else make_notification_payload(
            tenant_id=tenant_id, event_id=event_id, event_type=event_type
        )
    )
    entry = await dlq_dao.enqueue(
        session,
        tenant_id=tenant_id,
        adapter_name=adapter_name,
        event_type=event_type,
        event_id=event_id,
        target_url=target_url,
        payload=actual_payload,
        last_error_code=last_error_code,
        last_status_code=last_status_code,
        attempt_count=attempt_count,
    )
    await session.commit()
    return entry


async def force_terminal_replayed(
    session: AsyncSession, *, entry_id: str, when: datetime | None = None
) -> None:
    """Force a row to terminal `replayed` state without HTTP plumbing."""
    moment = when or datetime.now(UTC)
    await session.execute(
        text(
            "UPDATE webhook_dlq_entries SET replayed_at = :ts WHERE id = :id"
        ),
        {"ts": moment.replace(tzinfo=None), "id": entry_id},
    )
    await session.commit()


async def force_terminal_abandoned(
    session: AsyncSession,
    *,
    entry_id: str,
    when: datetime | None = None,
    reason: str = "operator",
) -> None:
    """Force a row to terminal `abandoned` state without HTTP plumbing."""
    moment = when or datetime.now(UTC)
    await session.execute(
        text(
            "UPDATE webhook_dlq_entries SET abandoned_at = :ts, "
            "abandoned_reason = :reason WHERE id = :id"
        ),
        {
            "ts": moment.replace(tzinfo=None),
            "reason": reason,
            "id": entry_id,
        },
    )
    await session.commit()


def random_uuid() -> str:
    """Return a fresh random UUID4 string — useful for cross-tenant probes."""
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Re-export public surface — keeps test files import-list compact.
# ---------------------------------------------------------------------------

__all__ = [
    "ADMIN_API_KEY",
    "AuditEmitter",
    "DEFAULT_REASON",
    "EVENT_DLQ_ABANDON",
    "EVENT_DLQ_REPLAY",
    "OPERATOR_SUBJECT",
    "TENANT_A",
    "TENANT_B",
    "TENANT_C",
    "audit_emitter",
    "api_client",
    "enqueue_dlq_entry",
    "engine",
    "force_terminal_abandoned",
    "force_terminal_replayed",
    "headers_admin",
    "headers_admin_no_tenant",
    "headers_operator",
    "headers_super_admin",
    "make_notification_payload",
    "random_uuid",
    "seed_tenant",
    "session",
    "session_factory_patch",
]
