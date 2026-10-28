"""HIBP breach/paste collector — email selector -> breach + paste observations.

Wraps :class:`src.data_sources.hibp_client.HIBPClient` (does not duplicate it).
HIBP never returns plaintext passwords; we record breach names + paste sources
only. Gated on ``HIBP_API_KEY``.
"""

from __future__ import annotations

from typing import Any

from src.data_sources.hibp_client import HIBPClient
from src.intel.dark_web.collectors.base import BaseCollector
from src.intel.dark_web.contracts import (
    DarkWebRawRecord,
    DarkWebSelector,
    ExposureType,
    SelectorKind,
    SourceNetwork,
)

_COLLECTOR = "breach_hibp@1"


class HibpBreachCollector(BaseCollector):
    name = "breach_hibp"
    network = SourceNetwork.BREACH_DB
    accepts = (SelectorKind.EMAIL,)

    def __init__(self, client: HIBPClient | None = None) -> None:
        self._client = client or HIBPClient()

    def is_enabled(self) -> bool:
        return self._client.is_available()

    async def collect(self, selector: DarkWebSelector) -> list[DarkWebRawRecord]:
        email = selector.value.strip()
        out: list[DarkWebRawRecord] = []

        breaches = await self._client.query(query_type="breachedaccount", account=email)
        for item in _as_list(breaches.get("data")):
            name = _breach_name(item)
            out.append(
                DarkWebRawRecord(
                    selector_id=selector.id,
                    source_network=SourceNetwork.BREACH_DB,
                    source_ref=f"hibp:breach:{name}",
                    exposure_hint=ExposureType.CREDENTIAL,
                    content=f"Account {_mask(email)} present in breach '{name}'.",
                    collector=_COLLECTOR,
                    extra={"breach": name},
                )
            )

        pastes = await self._client.query(query_type="pasteaccount", account=email)
        for item in _as_list(pastes.get("data")):
            src = str(item.get("Source", "")) if isinstance(item, dict) else ""
            pid = str(item.get("Id", "")) if isinstance(item, dict) else ""
            out.append(
                DarkWebRawRecord(
                    selector_id=selector.id,
                    source_network=SourceNetwork.PASTE,
                    source_ref=f"hibp:paste:{src}:{pid}",
                    exposure_hint=ExposureType.PII,
                    content=f"Account {_mask(email)} appears in a paste ({src}).",
                    collector=_COLLECTOR,
                    extra={"paste_source": src},
                )
            )
        return out


def _as_list(data: Any) -> list[Any]:
    return data if isinstance(data, list) else []


def _breach_name(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("Name") or item.get("name") or "unknown")
    return str(item)


def _mask(email: str) -> str:
    email = (email or "").strip()
    if "@" not in email:
        return "***"
    local, _, domain = email.partition("@")
    return f"{(local[:1] or '*')}***@{domain}"
