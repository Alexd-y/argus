"""Hidden-network collectors (W-8) — off by default, sandbox-only no-op."""

from __future__ import annotations

import pytest

from src.intel.dark_web.collectors import all_dark_web_collectors, hidden_network_collectors
from src.intel.dark_web.contracts import DarkWebSelector, SelectorKind


@pytest.fixture(autouse=True)
def _no_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.core.config.settings.dark_web_monitoring_enabled", False, raising=False)
    monkeypatch.setattr("src.core.config.settings.darkweb_tor_socks", None, raising=False)
    monkeypatch.setattr("src.core.config.settings.darkweb_i2p_sam", None, raising=False)
    monkeypatch.setattr("src.core.config.settings.telegram_api_id", None, raising=False)
    monkeypatch.setattr("src.core.config.settings.telegram_api_hash", None, raising=False)


def test_hidden_collectors_disabled_by_default() -> None:
    assert all(not c.is_enabled() for c in hidden_network_collectors())


def test_all_collectors_includes_hidden() -> None:
    names = {c.name for c in all_dark_web_collectors()}
    assert {"tor_crawler", "i2p_crawler", "telegram_monitor", "forum_monitor"} <= names


@pytest.mark.asyncio
async def test_tor_disabled_even_with_socks_but_global_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.core.config.settings.darkweb_tor_socks", "socks5://tor:9050", raising=False)
    # global flag still off -> disabled
    from src.intel.dark_web.collectors.hidden_networks import TorCrawlerCollector

    sel = DarkWebSelector(kind=SelectorKind.DOMAIN, value="acme.com")
    assert await TorCrawlerCollector().safe_collect(sel) == []


@pytest.mark.asyncio
async def test_hidden_collectors_are_noop_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    # Even when transport+flag are set, the in-process collect is a safe no-op
    # (the real crawl runs in the sandbox worker).
    monkeypatch.setattr("src.core.config.settings.dark_web_monitoring_enabled", True, raising=False)
    monkeypatch.setattr("src.core.config.settings.darkweb_i2p_sam", "127.0.0.1:7656", raising=False)
    from src.intel.dark_web.collectors.hidden_networks import I2pCrawlerCollector

    c = I2pCrawlerCollector()
    assert c.is_enabled() is True
    sel = DarkWebSelector(kind=SelectorKind.KEYWORD, value="acme")
    assert await c.collect(sel) == []
