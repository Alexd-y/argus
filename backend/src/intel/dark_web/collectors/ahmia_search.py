"""Ahmia clearnet-index collector — keyword/domain selector -> .onion mentions.

Parses the Ahmia search result page for ``.onion`` links referencing the
authorized target. No direct Tor fetch — that is W-8 (sandbox). Gated on
``AHMIA_BASE_URL``.
"""

from __future__ import annotations

import re

from src.data_sources.ahmia_client import AhmiaClient
from src.intel.dark_web.collectors.base import BaseCollector
from src.intel.dark_web.contracts import (
    DarkWebRawRecord,
    DarkWebSelector,
    ExposureType,
    SelectorKind,
    SourceNetwork,
)

_ONION_RE = re.compile(r"\b([a-z2-7]{16,56}\.onion)\b", re.IGNORECASE)
_MAX_HITS = 25


class AhmiaSearchCollector(BaseCollector):
    name = "ahmia_search"
    network = SourceNetwork.CLEARNET_INDEX
    accepts = (SelectorKind.DOMAIN, SelectorKind.KEYWORD)

    def __init__(self, client: AhmiaClient | None = None) -> None:
        self._client = client or AhmiaClient()

    def is_enabled(self) -> bool:
        return self._client.is_available()

    async def collect(self, selector: DarkWebSelector) -> list[DarkWebRawRecord]:
        resp = await self._client.query(keyword=selector.value)
        data = resp.get("data")
        body = data.get("body") if isinstance(data, dict) else ""
        if not isinstance(body, str) or not body:
            return []
        seen: set[str] = set()
        out: list[DarkWebRawRecord] = []
        for match in _ONION_RE.finditer(body):
            onion = match.group(1).lower()
            if onion in seen:
                continue
            seen.add(onion)
            out.append(
                DarkWebRawRecord(
                    selector_id=selector.id,
                    source_network=SourceNetwork.CLEARNET_INDEX,
                    source_ref=onion,
                    exposure_hint=ExposureType.MENTION,
                    content=f"Mention of '{selector.value}' indexed on hidden service {onion}.",
                    collector="ahmia_search@1",
                    extra={"onion": onion},
                )
            )
            if len(out) >= _MAX_HITS:
                break
        return out
