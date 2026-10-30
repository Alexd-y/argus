"""Intelligence X leak/paste/darkweb index collector (free-tier friendly).

Gated by ``INTELX_API_KEY`` (use a free https://free.intelx.io/ key with the
default ``INTELX_BASE_URL``). Searches the IntelX index for an email or domain and
records only non-sensitive descriptors of each match — bucket, name, date, system
id — never plaintext credentials. Skipped when the key is unset.
"""

from __future__ import annotations

from typing import Any

from src.data_sources.intelx_client import IntelXClient
from src.intel.dark_web.collectors.base import BaseCollector
from src.intel.dark_web.contracts import (
    DarkWebRawRecord,
    DarkWebSelector,
    ExposureType,
    SelectorKind,
    SourceNetwork,
)


def _mask(value: str) -> str:
    v = (value or "").strip()
    if "@" not in v:
        return v  # domain — not sensitive
    local, _, domain = v.partition("@")
    return f"{(local[:1] or '*')}***@{domain}"


def _records(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        recs = data.get("records")
        if isinstance(recs, list):
            return [r for r in recs if isinstance(r, dict)]
    return []


class IntelxSearchCollector(BaseCollector):
    name = "intelx_search"
    network = SourceNetwork.PASTE
    accepts = (SelectorKind.EMAIL, SelectorKind.DOMAIN)

    def __init__(self, client: IntelXClient | None = None) -> None:
        self._client = client or IntelXClient()

    def is_enabled(self) -> bool:
        return self._client.is_available()

    async def collect(self, selector: DarkWebSelector) -> list[DarkWebRawRecord]:
        term = (selector.value or "").strip()
        if not term:
            return []
        resp = await self._client.query(term=term)
        out: list[DarkWebRawRecord] = []
        for item in _records(resp.get("data")):
            bucket = str(item.get("bucket") or item.get("bucketh") or "unknown")
            name = str(item.get("name") or "")
            date = str(item.get("date") or item.get("added") or "")
            sysid = str(item.get("systemid") or item.get("storageid") or "")
            out.append(
                DarkWebRawRecord(
                    selector_id=selector.id,
                    source_network=SourceNetwork.PASTE,
                    source_ref=f"intelx:{bucket}" if bucket else "intelx",
                    exposure_hint=ExposureType.MENTION,
                    content=(
                        f"IntelX index match for {_mask(term)} in bucket '{bucket}'"
                        + (f": {name}" if name else "")
                        + (f" ({date})" if date else "")
                        + "."
                    ),
                    collector="intelx_search@1",
                    extra={"bucket": bucket, "name": name, "date": date, "systemid": sysid},
                )
            )
        return out
