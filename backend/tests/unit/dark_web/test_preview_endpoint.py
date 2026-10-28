"""The /intelligence/dark-web/preview handler returns only the gate decision."""

from __future__ import annotations

import json

import pytest

from src.api.routers.intelligence import dark_web_preview
from src.api.schemas import DarkWebPreviewRequest


def _decode(resp) -> dict:  # noqa: ANN001
    return json.loads(bytes(resp.body))


@pytest.mark.asyncio
async def test_preview_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.core.config.settings.dark_web_monitoring_enabled", False, raising=False)
    body = DarkWebPreviewRequest(options={"dark_web": {"enabled": True}})
    data = _decode(await dark_web_preview(body))
    assert data["success"] is True
    assert data["prefilter_passes"] is False
    assert data["status"] == "disabled"
    # no observation data ever
    assert "observations" not in data


@pytest.mark.asyncio
async def test_preview_prefilter_passes_when_flag_and_optin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.core.config.settings.dark_web_monitoring_enabled", True, raising=False)
    body = DarkWebPreviewRequest(options={"dark_web": {"enabled": True}})
    data = _decode(await dark_web_preview(body))
    # Prefilter (global + opt-in) passes; entitlement is NOT asserted here.
    assert data["prefilter_passes"] is True
    assert data["status"] == "not_collected"
    assert data["flags"]["enabled"] is True
    assert "entitlement" in data["note"].lower()
