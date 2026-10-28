"""Collector protocol + a safe base class.

Invariants enforced here:
* A collector NEVER raises out of ``safe_collect`` — a source failure/timeout
  degrades to ``[]`` with a structured log (prompt §7: "gated: no key/channel
  off -> skip со structured-log (не падать)").
* A collector is only queried for selectors it ``supports`` (e.g. a breach
  collector only runs on EMAIL selectors).
"""

from __future__ import annotations

import logging
from typing import Protocol, runtime_checkable

from src.intel.dark_web.contracts import (
    DarkWebRawRecord,
    DarkWebSelector,
    SelectorKind,
    SourceNetwork,
)

logger = logging.getLogger(__name__)


@runtime_checkable
class DarkWebCollector(Protocol):
    name: str
    network: SourceNetwork

    def is_enabled(self) -> bool: ...

    def supports(self, selector: DarkWebSelector) -> bool: ...

    async def collect(self, selector: DarkWebSelector) -> list[DarkWebRawRecord]: ...


class BaseCollector:
    """Common behaviour: enable gating, selector filtering, fail-safe wrapper."""

    name: str = "base"
    network: SourceNetwork = SourceNetwork.FEED
    #: Selector kinds this collector can act on; empty = all.
    accepts: tuple[SelectorKind, ...] = ()

    def is_enabled(self) -> bool:  # pragma: no cover - overridden
        return False

    def supports(self, selector: DarkWebSelector) -> bool:
        if not self.accepts:
            return True
        return selector.kind in self.accepts

    async def collect(
        self, selector: DarkWebSelector
    ) -> list[DarkWebRawRecord]:  # pragma: no cover
        raise NotImplementedError

    async def safe_collect(self, selector: DarkWebSelector) -> list[DarkWebRawRecord]:
        """Run ``collect`` but never raise and never run when gated/unsupported."""

        if not self.is_enabled():
            logger.info(
                "darkweb_collector_skipped",
                extra={"collector": self.name, "reason": "disabled_or_unconfigured"},
            )
            return []
        if not self.supports(selector):
            return []
        try:
            return await self.collect(selector)
        except Exception:  # noqa: BLE001 - degrade to empty, never break the sweep
            logger.exception("darkweb_collector_failed", extra={"collector": self.name})
            return []
