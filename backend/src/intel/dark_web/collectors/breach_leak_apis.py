"""Commercial breach-API collectors (DeHashed, LeakCheck) — gated, email-only.

Plaintext passwords are NEVER stored: we record only a presence flag + the
breach/source label. Both are skipped unless their API key is configured.
"""

from __future__ import annotations

from typing import Any

from src.data_sources.dehashed_client import DehashedClient
from src.data_sources.leakcheck_client import LeakCheckClient
from src.intel.dark_web.collectors.base import BaseCollector
from src.intel.dark_web.contracts import (
    DarkWebRawRecord,
    DarkWebSelector,
    ExposureType,
    SelectorKind,
    SourceNetwork,
)


def _mask(email: str) -> str:
    email = (email or "").strip()
    if "@" not in email:
        return "***"
    local, _, domain = email.partition("@")
    return f"{(local[:1] or '*')}***@{domain}"


def _as_list(data: Any) -> list[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("entries", "result", "results", "data", "sources"):
            v = data.get(key)
            if isinstance(v, list):
                return v
    return []


class DehashedCollector(BaseCollector):
    name = "breach_dehashed"
    network = SourceNetwork.BREACH_DB
    accepts = (SelectorKind.EMAIL,)

    def __init__(self, client: DehashedClient | None = None) -> None:
        self._client = client or DehashedClient()

    def is_enabled(self) -> bool:
        return self._client.is_available()

    async def collect(self, selector: DarkWebSelector) -> list[DarkWebRawRecord]:
        email = selector.value.strip()
        resp = await self._client.query(email=email)
        out: list[DarkWebRawRecord] = []
        for item in _as_list(resp.get("data")):
            db = ""
            has_password = False
            if isinstance(item, dict):
                db = str(item.get("database_name") or item.get("obtained_from") or "")
                has_password = bool(item.get("password") or item.get("hashed_password"))
            out.append(
                DarkWebRawRecord(
                    selector_id=selector.id,
                    source_network=SourceNetwork.BREACH_DB,
                    source_ref=f"dehashed:{db}" if db else "dehashed",
                    exposure_hint=ExposureType.CREDENTIAL,
                    content=f"Account {_mask(email)} in breach '{db or 'unknown'}' "
                    f"(password {'present (hashed/omitted)' if has_password else 'absent'}).",
                    collector="breach_dehashed@1",
                    extra={"database": db, "password_present": has_password},
                )
            )
        return out


class LeakCheckCollector(BaseCollector):
    name = "breach_leakcheck"
    network = SourceNetwork.BREACH_DB
    accepts = (SelectorKind.EMAIL,)

    def __init__(self, client: LeakCheckClient | None = None) -> None:
        self._client = client or LeakCheckClient()

    def is_enabled(self) -> bool:
        return self._client.is_available()

    async def collect(self, selector: DarkWebSelector) -> list[DarkWebRawRecord]:
        email = selector.value.strip()
        resp = await self._client.query(email=email)
        out: list[DarkWebRawRecord] = []
        for item in _as_list(resp.get("data")):
            src = ""
            if isinstance(item, dict):
                src = str(
                    item.get("source", {}).get("name")
                    if isinstance(item.get("source"), dict)
                    else item.get("source") or ""
                )
            out.append(
                DarkWebRawRecord(
                    selector_id=selector.id,
                    source_network=SourceNetwork.BREACH_DB,
                    source_ref=f"leakcheck:{src}" if src else "leakcheck",
                    exposure_hint=ExposureType.CREDENTIAL,
                    content=f"Account {_mask(email)} found in leak source '{src or 'unknown'}'.",
                    collector="breach_leakcheck@1",
                    extra={"source_name": src},
                )
            )
        return out
