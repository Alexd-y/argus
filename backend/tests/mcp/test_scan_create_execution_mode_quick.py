"""QUICK-007 — MCP ``scan.create`` execution_mode=quick vs ScanProfile.QUICK depth.

Mocks DB. Feature flag via settings. ``ScanProfile.QUICK`` is scan depth and
must not require ``ARGUS_QUICK_MODE_ENABLED``.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from mcp.server.fastmcp import FastMCP

from src.core.config import settings
from src.db.models import Scan
from src.mcp.auth import MCPAuthContext
from src.mcp.context import set_auth_override
from src.mcp.exceptions import ValidationError
from src.mcp.schemas.scan import (
    QuickMcpOptions,
    ScanCreateInput,
    ScanCreateResult,
    ScanProfile,
    ScanStatus,
)
from src.mcp.services import scan_service
from src.mcp.tools import scans as scans_tools


def _tool_fn(app: FastMCP, name: str):
    return app._tool_manager._tools[name].fn  # type: ignore[attr-defined]


def _call(app: FastMCP, name: str, payload: object) -> object:
    fn = _tool_fn(app, name)
    return asyncio.run(fn(payload=payload))


@pytest.fixture()
def app(auth_ctx: MCPAuthContext) -> FastMCP:
    set_auth_override(auth_ctx)
    instance = FastMCP(name="argus-scans-quick-007")
    scans_tools.register(instance)
    return instance


def _mock_db_session_create() -> tuple[object, AsyncMock]:
    tenant_result = MagicMock()
    tenant_result.scalar_one_or_none.return_value = None
    session = AsyncMock()
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.flush = AsyncMock()
    session.execute = AsyncMock(return_value=tenant_result)

    @asynccontextmanager
    async def _cm():
        yield session

    def factory():
        return _cm()

    return factory, session


def _added_scans(session: AsyncMock) -> list[Scan]:
    rows: list[Scan] = []
    for call in session.add.call_args_list:
        obj = call.args[0]
        if isinstance(obj, Scan):
            rows.append(obj)
    return rows


def test_scan_create_tool_passes_execution_mode_quick(
    app: FastMCP,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    async def _fake_enqueue(
        *, tenant_id: str, user_id: str, payload: ScanCreateInput
    ) -> ScanCreateResult:
        captured["execution_mode"] = payload.execution_mode
        captured["profile"] = payload.profile
        captured["quick"] = payload.quick
        return ScanCreateResult(
            scan_id="scan-quick01",
            status=ScanStatus.PENDING,
            target=payload.target,
            profile=payload.profile,
            execution_mode=payload.execution_mode,
            requires_approval=False,
        )

    monkeypatch.setattr(scans_tools, "svc_enqueue_scan", _fake_enqueue)
    result = _call(
        app,
        "scan.create",
        ScanCreateInput(
            target="https://example.com",
            profile=ScanProfile.STANDARD,
            execution_mode="quick",
            quick=QuickMcpOptions(profile="balanced"),
        ),
    )
    assert isinstance(result, ScanCreateResult)
    assert captured["execution_mode"] == "quick"
    assert captured["profile"] is ScanProfile.STANDARD
    assert result.execution_mode == "quick"


@pytest.mark.asyncio
async def test_enqueue_scan_flag_off_raises_quick_mode_disabled(
    tenant_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "quick_mode_enabled", False)
    with pytest.raises(ValidationError) as exc_info:
        await scan_service.enqueue_scan(
            tenant_id=tenant_id,
            user_id="mcp-user",
            payload=ScanCreateInput(
                target="https://example.com",
                execution_mode="quick",
            ),
        )
    assert exc_info.value.code == "quick_mode_disabled"


@pytest.mark.asyncio
async def test_enqueue_scan_flag_on_persists_quick_execution_mode(
    tenant_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "quick_mode_enabled", True)
    factory, session = _mock_db_session_create()
    with (
        patch("src.mcp.services.scan_service.async_session_factory", factory),
        patch(
            "src.mcp.services.scan_service.set_session_tenant",
            new_callable=AsyncMock,
        ),
        patch(
            "src.mcp.services.scan_service.try_pick_queued_scan",
            new_callable=AsyncMock,
        ),
    ):
        result = await scan_service.enqueue_scan(
            tenant_id=tenant_id,
            user_id="mcp-user",
            payload=ScanCreateInput(
                target="https://example.com",
                profile=ScanProfile.STANDARD,
                execution_mode="quick",
                quick=QuickMcpOptions(profile="compact"),
            ),
        )
    assert result.execution_mode == "quick"
    assert result.status is ScanStatus.PENDING
    created = _added_scans(session)
    assert len(created) == 1
    assert created[0].execution_mode == "quick"
    assert created[0].scan_mode == "quick"
    assert created[0].quick_profile == "compact"


@pytest.mark.asyncio
async def test_enqueue_scan_profile_quick_without_execution_mode_is_depth_not_mode(
    tenant_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ScanProfile.QUICK is Strix-style depth; flag-off must still enqueue."""
    monkeypatch.setattr(settings, "quick_mode_enabled", False)
    factory, session = _mock_db_session_create()
    with (
        patch("src.mcp.services.scan_service.async_session_factory", factory),
        patch(
            "src.mcp.services.scan_service.set_session_tenant",
            new_callable=AsyncMock,
        ),
        patch(
            "src.mcp.services.scan_service.try_pick_queued_scan",
            new_callable=AsyncMock,
        ),
    ):
        result = await scan_service.enqueue_scan(
            tenant_id=tenant_id,
            user_id="mcp-user",
            payload=ScanCreateInput(
                target="https://example.com",
                profile=ScanProfile.QUICK,
            ),
        )
    assert result.execution_mode == "production"
    created = _added_scans(session)
    assert len(created) == 1
    assert created[0].execution_mode == "production"
    assert created[0].scan_mode == "quick"


@pytest.mark.asyncio
async def test_enqueue_scan_lab_plus_quick_raises_conflicting_execution_mode(
    tenant_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "quick_mode_enabled", True)
    with pytest.raises(ValidationError) as exc_info:
        await scan_service.enqueue_scan(
            tenant_id=tenant_id,
            user_id="mcp-user",
            payload=ScanCreateInput(
                target="https://example.com",
                execution_mode="lab_unrestricted",
                quick=QuickMcpOptions(profile="balanced"),
            ),
        )
    assert exc_info.value.code == "conflicting_execution_mode"


@pytest.mark.asyncio
async def test_enqueue_scan_typed_vs_options_execution_mode_conflict(
    tenant_id: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "quick_mode_enabled", True)
    with pytest.raises(ValidationError) as exc_info:
        await scan_service.enqueue_scan(
            tenant_id=tenant_id,
            user_id="mcp-user",
            payload=ScanCreateInput(
                target="https://example.com",
                execution_mode="quick",
                scan_options={"execution_mode": "lab_unrestricted"},
            ),
        )
    assert exc_info.value.code == "conflicting_execution_mode"
