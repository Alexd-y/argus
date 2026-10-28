"""Public threat-intel feed collector (ransomware.live / abuse.ch / CISA KEV).

These are keyless public feeds, so they are gated on the GLOBAL DWM switch
(``settings.dark_web_monitoring_enabled``) rather than an API key — defence in
depth so a direct call still respects off-by-default. Used mainly for T2
finding correlation (CVE / access-sale signal).
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from src.core.config import settings
from src.intel.dark_web.collectors.base import BaseCollector
from src.intel.dark_web.contracts import (
    DarkWebRawRecord,
    DarkWebSelector,
    ExposureType,
    SelectorKind,
    SourceNetwork,
)

logger = logging.getLogger(__name__)

_RANSOMWARE_LIVE = "https://api.ransomware.live/recentvictims"
_TIMEOUT = 20.0


class FeedsCollector(BaseCollector):
    name = "feeds"
    network = SourceNetwork.FEED
    accepts = (SelectorKind.DOMAIN, SelectorKind.KEYWORD, SelectorKind.FINDING, SelectorKind.INFRA)

    def is_enabled(self) -> bool:
        return bool(getattr(settings, "dark_web_monitoring_enabled", False))

    async def collect(self, selector: DarkWebSelector) -> list[DarkWebRawRecord]:
        term = selector.value.strip().lower()
        if not term:
            return []
        out: list[DarkWebRawRecord] = []
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(_RANSOMWARE_LIVE, headers={"User-Agent": "ARGUS-DWM/1.0"})
                if resp.status_code == 200:
                    out.extend(self._parse_ransomware(selector, term, resp.json()))
        except Exception:  # noqa: BLE001 - public feed best-effort
            logger.info("darkweb_feeds_fetch_failed", extra={"feed": "ransomware.live"})
        return out

    @staticmethod
    def _parse_ransomware(
        selector: DarkWebSelector, term: str, data: Any
    ) -> list[DarkWebRawRecord]:
        victims = data if isinstance(data, list) else []
        out: list[DarkWebRawRecord] = []
        for v in victims:
            if not isinstance(v, dict):
                continue
            hay = " ".join(
                str(v.get(k, "")) for k in ("victim", "domain", "post_title", "description")
            ).lower()
            if term and term in hay:
                group = str(v.get("group_name") or v.get("group") or "unknown")
                out.append(
                    DarkWebRawRecord(
                        selector_id=selector.id,
                        source_network=SourceNetwork.FEED,
                        source_ref=f"ransomware.live:{group}",
                        exposure_hint=ExposureType.ACCESS_SALE,
                        content=f"'{selector.value}' listed as a victim by ransomware group '{group}'.",
                        collector="feeds_ransomware_live@1",
                        extra={"group": group},
                    )
                )
        return out
