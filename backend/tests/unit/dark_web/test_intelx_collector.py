"""IntelX (free-tier) DWM collector: gating, record mapping, registration."""

from __future__ import annotations

import asyncio

from src.intel.dark_web.collectors import default_breach_first_collectors
from src.intel.dark_web.collectors.intelx_search import IntelxSearchCollector
from src.intel.dark_web.contracts import DarkWebSelector, ExposureType, SelectorKind, SourceNetwork


class _FakeClient:
    def __init__(self, available: bool, records: list[dict] | None = None) -> None:
        self._available = available
        self._records = records or []

    def is_available(self) -> bool:
        return self._available

    async def query(self, **_: object) -> dict:
        return {"available": True, "data": {"records": self._records}}


def _sel() -> DarkWebSelector:
    return DarkWebSelector(id="s1", kind=SelectorKind.EMAIL, value="info@svalbard.ca")


def test_registered_in_default_collector_set() -> None:
    assert any(
        isinstance(c, IntelxSearchCollector) for c in default_breach_first_collectors()
    )


def test_disabled_without_key() -> None:
    assert IntelxSearchCollector(client=_FakeClient(available=False)).is_enabled() is False


def test_maps_records_with_masked_email_and_no_plaintext() -> None:
    rec = {"bucket": "leaks", "name": "dump_2023.txt", "date": "2023-01-02", "systemid": "abc"}
    c = IntelxSearchCollector(client=_FakeClient(available=True, records=[rec]))
    out = asyncio.run(c.collect(_sel()))
    assert len(out) == 1
    r = out[0]
    assert r.source_network == SourceNetwork.PASTE
    assert r.exposure_hint == ExposureType.MENTION
    assert "i***@svalbard.ca" in r.content  # masked
    assert "info@svalbard.ca" not in r.content  # never plaintext
    assert r.extra["bucket"] == "leaks"


def test_empty_records_yield_nothing() -> None:
    c = IntelxSearchCollector(client=_FakeClient(available=True, records=[]))
    assert asyncio.run(c.collect(_sel())) == []
