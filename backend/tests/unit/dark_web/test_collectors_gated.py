"""Collectors are gated: no key/flag -> skip (empty), never raise."""

from __future__ import annotations

import pytest

from src.intel.dark_web.collectors import default_breach_first_collectors
from src.intel.dark_web.contracts import DarkWebSelector, SelectorKind


@pytest.fixture(autouse=True)
def _no_dwm_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "HIBP_API_KEY",
        "DEHASHED_API_KEY",
        "DEHASHED_USERNAME",
        "LEAKCHECK_API_KEY",
        "PSBDMP_API_KEY",
        "AHMIA_BASE_URL",
        "GITHUB_TOKEN",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr("src.core.config.settings.dark_web_monitoring_enabled", False, raising=False)


def test_all_collectors_disabled_without_config() -> None:
    assert all(not c.is_enabled() for c in default_breach_first_collectors())


@pytest.mark.asyncio
async def test_safe_collect_returns_empty_when_gated() -> None:
    sel = DarkWebSelector(kind=SelectorKind.EMAIL, value="a@example.com")
    for c in default_breach_first_collectors():
        result = await c.safe_collect(sel)
        assert result == []


@pytest.mark.asyncio
async def test_safe_collect_swallows_exceptions() -> None:
    from src.intel.dark_web.collectors.base import BaseCollector
    from src.intel.dark_web.contracts import SourceNetwork

    class Boom(BaseCollector):
        name = "boom"
        network = SourceNetwork.FEED

        def is_enabled(self) -> bool:
            return True

        async def collect(self, selector: DarkWebSelector) -> list:  # type: ignore[override]
            raise RuntimeError("kaboom")

    sel = DarkWebSelector(kind=SelectorKind.KEYWORD, value="x")
    assert await Boom().safe_collect(sel) == []
