"""B6-T02 / T48 — admin tenant PATCH/GET ``pdf_archival_format`` endpoint.

Test plan (per the B6-T02 spec):

* GET ``/api/v1/admin/tenants/{id}`` returns ``pdf_archival_format`` in the
  payload (default ``'standard'``).
* PATCH ``/api/v1/admin/tenants/{id}`` with ``pdf_archival_format='pdfa-2u'``
  persists the new value and emits exactly one AuditLog row with the
  canonical ``field=pdf_archival_format old=X new=Y`` shape — and crucially
  no copy of the tenant row itself.
* PATCH with an invalid value (``'foobar'``, ``''``, integer) returns HTTP
  422 from Pydantic ``Literal`` validation, before the route body runs.
* PATCH with the same value as the current one is a no-op for the audit
  log (zero rows emitted).

Test architecture
-----------------
We use ``AsyncMock``-backed sessions (the same pattern as
``tests/unit/api/test_admin_tenant_patch_limits.py``) so the suite runs
against the in-process FastAPI ASGI app without spinning up Postgres or
applying the full Alembic chain. The webhook-DLQ autouse fixtures from
the parent ``conftest.py`` already pin ``settings.admin_api_key`` to
:data:`tests.api.admin.conftest.ADMIN_API_KEY` — we re-use that constant
verbatim to stay in sync.

Marker hygiene
--------------
The parent ``backend/tests/conftest.py::_classify_item`` heuristic adds
``requires_postgres`` to any test pulling the parent ``client`` fixture
(``pytest -q`` skips those in dev). We therefore name our local
``TestClient`` fixture ``test_client`` to bypass that rule — the test
suite stays default-discoverable while still using the synchronous
``starlette.testclient.TestClient`` for clarity.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Iterator
from unittest.mock import AsyncMock, MagicMock

import pytest
from starlette.testclient import TestClient

from main import app
from src.db.models import AuditLog
from src.db.session import get_db

from tests.api.admin.conftest import ADMIN_API_KEY

_ADMIN_HEADERS = {
    "X-Admin-Key": ADMIN_API_KEY,
    "Content-Type": "application/json",
}


@pytest.fixture
def test_client() -> Iterator[TestClient]:
    """Synchronous TestClient — renamed to dodge the parent auto-marker rule."""
    with TestClient(app) as tc:
        yield tc


def _build_session_with_tenant(
    tenant: MagicMock,
) -> tuple[AsyncMock, list[Any]]:
    """Return an ``AsyncMock`` session whose ``execute()`` yields ``tenant``.

    The companion list captures every ``session.add(...)`` argument so a
    test can assert on the AuditLog rows the patch route emits.
    """
    r_exec = MagicMock()
    r_exec.scalar_one_or_none.return_value = tenant

    session = AsyncMock()
    session.execute = AsyncMock(return_value=r_exec)
    session.flush = AsyncMock(return_value=None)
    session.refresh = AsyncMock(return_value=None)

    added: list[Any] = []
    session.add = MagicMock(side_effect=lambda obj: added.append(obj))
    return session, added


def _make_tenant(
    tenant_id: str,
    *,
    pdf_archival_format: str = "standard",
    name: str = "Acme Co",
) -> MagicMock:
    """Build a ``Tenant``-shaped MagicMock with the columns ``TenantOut`` reads."""
    tenant = MagicMock()
    tenant.id = tenant_id
    tenant.name = name
    tenant.exports_sarif_junit_enabled = False
    tenant.rate_limit_rpm = None
    tenant.scope_blacklist = None
    tenant.retention_days = None
    tenant.pdf_archival_format = pdf_archival_format
    tenant.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    tenant.updated_at = datetime(2026, 1, 2, tzinfo=timezone.utc)
    return tenant


@pytest.fixture
def _clear_db_override():
    yield
    app.dependency_overrides.pop(get_db, None)


# ---------------------------------------------------------------------------
# GET /tenants/{id} — pdf_archival_format included in the response
# ---------------------------------------------------------------------------


def test_get_tenant_returns_pdf_archival_format_default(
    test_client: TestClient,
    _clear_db_override: None,
) -> None:
    """Default tenant should report ``pdf_archival_format='standard'``."""
    tid = str(uuid.uuid4())
    tenant = _make_tenant(tid, pdf_archival_format="standard")
    session, _ = _build_session_with_tenant(tenant)

    async def _fake_get_db():
        yield session

    app.dependency_overrides[get_db] = _fake_get_db
    r = test_client.get(f"/api/v1/admin/tenants/{tid}", headers=_ADMIN_HEADERS)

    assert r.status_code == 200, r.text
    body = r.json()
    assert body["pdf_archival_format"] == "standard"


def test_get_tenant_returns_pdf_archival_format_pdfa_2u(
    test_client: TestClient,
    _clear_db_override: None,
) -> None:
    tid = str(uuid.uuid4())
    tenant = _make_tenant(tid, pdf_archival_format="pdfa-2u")
    session, _ = _build_session_with_tenant(tenant)

    async def _fake_get_db():
        yield session

    app.dependency_overrides[get_db] = _fake_get_db
    r = test_client.get(f"/api/v1/admin/tenants/{tid}", headers=_ADMIN_HEADERS)

    assert r.status_code == 200, r.text
    assert r.json()["pdf_archival_format"] == "pdfa-2u"


# ---------------------------------------------------------------------------
# PATCH /tenants/{id} — happy path + audit emission
# ---------------------------------------------------------------------------


def test_patch_tenant_pdf_archival_format_pdfa_2u_persists_and_audits(
    test_client: TestClient,
    _clear_db_override: None,
) -> None:
    """Toggling to ``pdfa-2u`` must persist + emit exactly one AuditLog row."""
    tid = str(uuid.uuid4())
    tenant = _make_tenant(tid, pdf_archival_format="standard")
    session, added = _build_session_with_tenant(tenant)

    async def _fake_get_db():
        yield session

    app.dependency_overrides[get_db] = _fake_get_db
    r = test_client.patch(
        f"/api/v1/admin/tenants/{tid}",
        headers=_ADMIN_HEADERS,
        json={"pdf_archival_format": "pdfa-2u"},
    )

    assert r.status_code == 200, r.text
    assert tenant.pdf_archival_format == "pdfa-2u"

    audit_rows = [obj for obj in added if isinstance(obj, AuditLog)]
    assert len(audit_rows) == 1, (
        f"expected exactly one AuditLog row, got {len(audit_rows)} — {added}"
    )
    audit = audit_rows[0]
    assert audit.tenant_id == tid
    assert audit.action == "tenant_update"
    assert audit.resource_type == "tenant"
    assert audit.resource_id == tid

    details = audit.details
    assert isinstance(details, dict), f"AuditLog.details must be dict, got {type(details)}"
    assert details["field"] == "pdf_archival_format"
    assert details["old"] == "standard"
    assert details["new"] == "pdfa-2u"

    forbidden_keys = {"name", "rate_limit_rpm", "scope_blacklist", "retention_days"}
    assert not (forbidden_keys & details.keys()), (
        "AuditLog details must NOT include the tenant row payload — "
        f"forbidden keys leaked: {forbidden_keys & details.keys()}"
    )


def test_patch_tenant_pdf_archival_format_standard_to_standard_is_audit_noop(
    test_client: TestClient,
    _clear_db_override: None,
) -> None:
    """Patching with the same value emits zero AuditLog rows (idempotency)."""
    tid = str(uuid.uuid4())
    tenant = _make_tenant(tid, pdf_archival_format="standard")
    session, added = _build_session_with_tenant(tenant)

    async def _fake_get_db():
        yield session

    app.dependency_overrides[get_db] = _fake_get_db
    r = test_client.patch(
        f"/api/v1/admin/tenants/{tid}",
        headers=_ADMIN_HEADERS,
        json={"pdf_archival_format": "standard"},
    )

    assert r.status_code == 200, r.text
    audit_rows = [obj for obj in added if isinstance(obj, AuditLog)]
    assert audit_rows == [], (
        f"expected zero AuditLog rows for unchanged value, got {len(audit_rows)}"
    )


# ---------------------------------------------------------------------------
# PATCH /tenants/{id} — invalid values rejected with 422
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad_value",
    [
        "foobar",
        "PDFA-2U",  # case-sensitive: spec mandates exact lowercase enum
        "pdfa-2b",
        "",
        " ",
        "standard ",
        123,
        ["pdfa-2u"],
    ],
)
def test_patch_tenant_pdf_archival_format_invalid_returns_422(
    bad_value: object,
    test_client: TestClient,
    _clear_db_override: None,
) -> None:
    """Pydantic ``Literal`` rejects every value outside the closed taxonomy."""
    tid = str(uuid.uuid4())
    tenant = _make_tenant(tid, pdf_archival_format="standard")
    session, added = _build_session_with_tenant(tenant)

    async def _fake_get_db():
        yield session

    app.dependency_overrides[get_db] = _fake_get_db
    r = test_client.patch(
        f"/api/v1/admin/tenants/{tid}",
        headers=_ADMIN_HEADERS,
        json={"pdf_archival_format": bad_value},
    )

    assert r.status_code == 422, (
        f"value {bad_value!r} should be rejected with 422, got {r.status_code}: "
        f"{r.text}"
    )
    audit_rows = [obj for obj in added if isinstance(obj, AuditLog)]
    assert audit_rows == [], (
        "no AuditLog row should be emitted on validation failure"
    )


def test_patch_tenant_pdf_archival_format_null_returns_422(
    test_client: TestClient,
    _clear_db_override: None,
) -> None:
    """Explicit ``null`` for ``pdf_archival_format`` must 422 — column is NOT NULL."""
    tid = str(uuid.uuid4())
    tenant = _make_tenant(tid, pdf_archival_format="standard")
    session, _ = _build_session_with_tenant(tenant)

    async def _fake_get_db():
        yield session

    app.dependency_overrides[get_db] = _fake_get_db
    r = test_client.patch(
        f"/api/v1/admin/tenants/{tid}",
        headers=_ADMIN_HEADERS,
        json={"pdf_archival_format": None, "name": "Acme Co"},
    )
    assert r.status_code == 422, r.text


def test_patch_tenant_pdf_archival_format_unknown_tenant_returns_404(
    test_client: TestClient,
    _clear_db_override: None,
) -> None:
    tid = str(uuid.uuid4())
    r_exec = MagicMock()
    r_exec.scalar_one_or_none.return_value = None
    session = AsyncMock()
    session.execute = AsyncMock(return_value=r_exec)
    session.flush = AsyncMock(return_value=None)
    session.refresh = AsyncMock(return_value=None)
    session.add = MagicMock()

    async def _fake_get_db():
        yield session

    app.dependency_overrides[get_db] = _fake_get_db
    r = test_client.patch(
        f"/api/v1/admin/tenants/{tid}",
        headers=_ADMIN_HEADERS,
        json={"pdf_archival_format": "pdfa-2u"},
    )
    assert r.status_code == 404, r.text
