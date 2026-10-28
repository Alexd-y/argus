"""Server-side DWM entitlement resolution — fail-closed."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from src.intel.dark_web.entitlement import tenant_has_dwm_entitlement

_TID = "11111111-1111-1111-1111-111111111111"


@pytest.fixture(autouse=True)
def _clear_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.core.config.settings.dark_web_entitled_tenants", None, raising=False)


@pytest.mark.asyncio
async def test_no_session_denies() -> None:
    assert await tenant_has_dwm_entitlement(None, _TID) is False


@pytest.mark.asyncio
async def test_empty_tenant_denies() -> None:
    assert await tenant_has_dwm_entitlement(None, "") is False


@pytest.mark.asyncio
async def test_allowlist_star_grants(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.core.config.settings.dark_web_entitled_tenants", "*", raising=False)
    assert await tenant_has_dwm_entitlement(None, _TID) is True


@pytest.mark.asyncio
async def test_allowlist_specific_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "src.core.config.settings.dark_web_entitled_tenants", f"other,{_TID}", raising=False
    )
    assert await tenant_has_dwm_entitlement(None, _TID) is True


# -- DB-backed resolution via a minimal fake session -------------------------


class _Sub:
    def __init__(self, plan: str, status: str = "active", valid_until=None) -> None:
        self.plan = plan
        self.status = status
        self.valid_until = valid_until


class _Quota:
    def __init__(self, tier: str) -> None:
        self.tier = tier


class _Scalars:
    def __init__(self, rows: list) -> None:
        self._rows = rows

    def all(self) -> list:
        return list(self._rows)

    def first(self):
        return self._rows[0] if self._rows else None


class _Result:
    def __init__(self, rows: list) -> None:
        self._rows = rows

    def scalars(self) -> _Scalars:
        return _Scalars(self._rows)


class _FakeSession:
    """Returns subscriptions on the first execute, quota on the second."""

    def __init__(self, subs: list, quotas: list) -> None:
        self._queue = [subs, quotas]

    async def execute(self, _stmt):  # noqa: ANN001
        rows = self._queue.pop(0) if self._queue else []
        return _Result(rows)


@pytest.mark.asyncio
async def test_active_paid_subscription_grants() -> None:
    session = _FakeSession([_Sub("premium", "active")], [])
    assert await tenant_has_dwm_entitlement(session, _TID) is True


@pytest.mark.asyncio
async def test_free_subscription_and_free_quota_deny() -> None:
    session = _FakeSession([_Sub("free", "active")], [_Quota("free")])
    assert await tenant_has_dwm_entitlement(session, _TID) is False


@pytest.mark.asyncio
async def test_expired_paid_subscription_denies() -> None:
    past = datetime.now(tz=UTC) - timedelta(days=1)
    session = _FakeSession([_Sub("premium", "active", valid_until=past)], [])
    assert await tenant_has_dwm_entitlement(session, _TID) is False


@pytest.mark.asyncio
async def test_paid_quota_tier_grants() -> None:
    session = _FakeSession([], [_Quota("standard")])
    assert await tenant_has_dwm_entitlement(session, _TID) is True
