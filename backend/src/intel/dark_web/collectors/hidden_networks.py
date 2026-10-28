"""Hidden-network collectors (W-8) — Tor / I2P / Telegram / forum.

These run ONLY inside the network-isolated ``argus-darkweb-collector`` sandbox
container (egress restricted to Tor SOCKS / I2P SAM), NEVER in the backend
process and NEVER with the docker socket mounted. They are OFF by default and
gated on their transport being configured.

Independent implementation — NO code is copied from AGPL-licensed references
(e.g. DarkWatch); only architectural ideas (SOCKS egress, YARA-style
classification, passive read-only) are reused. Passive read only: no login, no
posting, no joining closed channels, no purchase, no de-anonymisation.

MVP note: the in-process ``collect`` is a safe no-op that records why it did not
run; the actual crawl executes in the sandbox worker. This keeps the interface,
gating, and egress contract in place without shipping an untested live crawler.
"""

from __future__ import annotations

import logging

from src.core.config import settings
from src.intel.dark_web.catalog import load_catalog
from src.intel.dark_web.collectors.base import BaseCollector
from src.intel.dark_web.contracts import (
    DarkWebRawRecord,
    DarkWebSelector,
    SelectorKind,
    SourceNetwork,
)

logger = logging.getLogger(__name__)


class _SandboxOnlyCollector(BaseCollector):
    """Shared base: gated, sandbox-only, no-op in-process."""

    def _transport_configured(self) -> bool:  # pragma: no cover - overridden
        return False

    def is_enabled(self) -> bool:
        return (
            bool(getattr(settings, "dark_web_monitoring_enabled", False))
            and self._transport_configured()
        )

    async def collect(self, selector: DarkWebSelector) -> list[DarkWebRawRecord]:
        logger.info(
            "darkweb_hidden_network_deferred_to_sandbox",
            extra={
                "collector": self.name,
                "network": self.network.value,
                "selector_kind": selector.kind.value,
            },
        )
        return []


class TorCrawlerCollector(_SandboxOnlyCollector):
    name = "tor_crawler"
    network = SourceNetwork.TOR
    accepts = (SelectorKind.DOMAIN, SelectorKind.KEYWORD)

    def _transport_configured(self) -> bool:
        seeds = load_catalog(verify=False).onion_seeds.get("seeds") or []
        return bool(getattr(settings, "darkweb_tor_socks", None)) and bool(seeds)


class I2pCrawlerCollector(_SandboxOnlyCollector):
    name = "i2p_crawler"
    network = SourceNetwork.I2P
    accepts = (SelectorKind.DOMAIN, SelectorKind.KEYWORD)

    def _transport_configured(self) -> bool:
        return bool(getattr(settings, "darkweb_i2p_sam", None))


class TelegramMonitorCollector(_SandboxOnlyCollector):
    name = "telegram_monitor"
    network = SourceNetwork.TELEGRAM
    accepts = (SelectorKind.DOMAIN, SelectorKind.KEYWORD)

    def _transport_configured(self) -> bool:
        channels = load_catalog(verify=False).telegram_channels.get("channels") or []
        return (
            bool(getattr(settings, "telegram_api_id", None))
            and bool(getattr(settings, "telegram_api_hash", None))
            and bool(channels)
        )


class ForumMonitorCollector(_SandboxOnlyCollector):
    name = "forum_monitor"
    network = SourceNetwork.FORUM
    accepts = (SelectorKind.DOMAIN, SelectorKind.KEYWORD)

    def _transport_configured(self) -> bool:
        # Forums are read via the same SOCKS egress as Tor; require a whitelist.
        return bool(getattr(settings, "darkweb_tor_socks", None))


def hidden_network_collectors() -> list[BaseCollector]:
    """The W-8 sandbox-only collector set (off unless transports are configured)."""

    return [
        TorCrawlerCollector(),
        I2pCrawlerCollector(),
        TelegramMonitorCollector(),
        ForumMonitorCollector(),
    ]


__all__ = [
    "ForumMonitorCollector",
    "I2pCrawlerCollector",
    "TelegramMonitorCollector",
    "TorCrawlerCollector",
    "hidden_network_collectors",
]
