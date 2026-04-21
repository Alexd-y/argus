"""Notification dispatcher (ARG-035).

Single fan-out facade in front of the three webhook adapters. The MCP
server only ever talks to :class:`NotificationDispatcher` — it never
imports the concrete Slack / Linear / Jira modules — so we can:

* swap implementations without touching the call sites,
* feature-flag the whole subsystem with one boolean,
* gate per-adapter at runtime via per-tenant config,
* emit a single structured audit row per dispatch, regardless of how
  many adapters fired.

The dispatcher is *fire-and-forget* friendly: callers can either
``await dispatch()`` (used by tests) or schedule it with
:func:`asyncio.create_task` from inside :mod:`src.mcp.server`.
Failures inside any single adapter are absorbed and surfaced via the
returned :class:`AdapterResult` list, never re-raised.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterable, Mapping
from typing import Final, Protocol, runtime_checkable

from src.mcp.audit_logger import MCPAuditLogger
from src.mcp.services.notifications._base import NotifierBase
from src.mcp.services.notifications.schemas import (
    NOTIFICATION_EVENT_TYPES,
    AdapterResult,
    NotificationEvent,
)

_logger = logging.getLogger(__name__)

ENABLE_ENV: Final[str] = "MCP_NOTIFICATIONS_ENABLED"


@runtime_checkable
class NotifierProtocol(Protocol):
    """Wire contract every webhook adapter satisfies."""

    name: str

    async def send_with_retry(
        self, event: NotificationEvent, *, tenant_id: str
    ) -> AdapterResult: ...

    async def aclose(self) -> None: ...


class NotificationDispatcher:
    """Fan-out events to all configured webhook adapters.

    Parameters
    ----------
    adapters:
        Concrete adapter instances. The dispatcher iterates them in the
        order given. Per-adapter enablement is tracked via
        :meth:`set_adapter_enabled`.
    enabled:
        Master kill-switch. ``False`` skips every adapter and returns an
        empty result list — used by the default ``MCP_NOTIFICATIONS_ENABLED=false``
        feature flag.
    audit_logger:
        Optional :class:`MCPAuditLogger`. When provided the dispatcher
        emits one structured ``mcp.notifications.dispatched`` row per
        dispatch summarising which adapters fired, how many attempts each
        took, and the redacted target hash.
    per_tenant_disabled_adapters:
        Mapping ``tenant_id -> {adapter_name, ...}``. Adapters in the set
        are skipped for the matching tenant (used by the per-tenant
        opt-out documented in ``server.yaml``).
    """

    def __init__(
        self,
        *,
        adapters: Iterable[NotifierBase | NotifierProtocol],
        enabled: bool,
        audit_logger: MCPAuditLogger | None = None,
        per_tenant_disabled_adapters: Mapping[str, frozenset[str]] | None = None,
    ) -> None:
        self._adapters: tuple[NotifierProtocol, ...] = tuple(adapters)
        self._adapter_index: dict[str, NotifierProtocol] = {
            a.name: a for a in self._adapters
        }
        self._enabled = bool(enabled)
        self._audit_logger = audit_logger
        self._per_adapter_enabled: dict[str, bool] = {
            a.name: False for a in self._adapters
        }
        self._per_tenant_disabled: dict[str, frozenset[str]] = {
            k: frozenset(v) for k, v in (per_tenant_disabled_adapters or {}).items()
        }

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def adapter_names(self) -> tuple[str, ...]:
        return tuple(self._per_adapter_enabled.keys())

    def set_enabled(self, enabled: bool) -> None:
        self._enabled = bool(enabled)

    def set_adapter_enabled(self, name: str, enabled: bool) -> None:
        if name not in self._per_adapter_enabled:
            raise KeyError(f"unknown adapter: {name}")
        self._per_adapter_enabled[name] = bool(enabled)

    def set_tenant_disabled_adapters(
        self, tenant_id: str, adapters: Iterable[str]
    ) -> None:
        self._per_tenant_disabled[tenant_id] = frozenset(adapters)

    async def aclose(self) -> None:
        for adapter in self._adapters:
            await adapter.aclose()

    async def dispatch(self, event: NotificationEvent) -> list[AdapterResult]:
        """Fan-out ``event`` to every enabled adapter.

        Returns a list of :class:`AdapterResult` (one per adapter), even
        when the dispatcher is globally disabled (in which case the list
        is empty). Never raises into the caller.
        """
        if not self._enabled:
            return []
        if not event.is_known_event_type():
            _logger.warning(
                "mcp.notifications.unknown_event_type",
                extra={
                    "event_id": event.event_id,
                    "event_type": event.event_type,
                    "known_event_types": sorted(NOTIFICATION_EVENT_TYPES),
                },
            )
            return []

        tenant_id = event.tenant_id
        tenant_disabled = self._per_tenant_disabled.get(tenant_id, frozenset())

        coros = []
        slots: list[NotifierProtocol] = []
        for adapter in self._adapters:
            if not self._per_adapter_enabled.get(adapter.name, False):
                continue
            if adapter.name in tenant_disabled:
                continue
            coros.append(adapter.send_with_retry(event, tenant_id=tenant_id))
            slots.append(adapter)

        if not coros:
            self._audit_dispatch(event=event, results=[])
            return []

        gathered = await asyncio.gather(*coros, return_exceptions=True)

        results: list[AdapterResult] = []
        for adapter, outcome in zip(slots, gathered):
            if isinstance(outcome, AdapterResult):
                results.append(outcome)
                continue
            _logger.warning(
                "mcp.notifications.adapter_unhandled_error",
                extra={
                    "adapter_name": adapter.name,
                    "tenant_id": tenant_id,
                    "event_id": event.event_id,
                    "exception_type": type(outcome).__name__,
                },
            )
            results.append(
                AdapterResult(
                    adapter_name=adapter.name,
                    event_id=event.event_id,
                    delivered=False,
                    attempts=1,
                    target_redacted="unknown" + "-" * 5,
                    error_code="unhandled_exception",
                )
            )

        self._audit_dispatch(event=event, results=results)
        return results

    def schedule(self, event: NotificationEvent) -> asyncio.Task[list[AdapterResult]]:
        """Fire-and-forget convenience: schedule :meth:`dispatch` as a Task."""
        return asyncio.create_task(self.dispatch(event))

    def _audit_dispatch(
        self, *, event: NotificationEvent, results: list[AdapterResult]
    ) -> None:
        if self._audit_logger is None:
            return
        summary: list[dict[str, object]] = []
        for r in results:
            row: dict[str, object] = {
                "adapter_name": r.adapter_name,
                "delivered": r.delivered,
                "attempts": r.attempts,
                "target_redacted": r.target_redacted,
            }
            if r.status_code is not None:
                row["status_code"] = r.status_code
            if r.error_code is not None:
                row["error_code"] = r.error_code
            if r.skipped_reason is not None:
                row["skipped_reason"] = r.skipped_reason
            summary.append(row)
        _logger.info(
            "mcp.notifications.dispatched",
            extra={
                "event_id": event.event_id,
                "event_type": event.event_type,
                "tenant_id": event.tenant_id,
                "severity": event.severity.value,
                "adapters": summary,
            },
        )


def is_globally_enabled_via_env() -> bool:
    """Return ``True`` iff the ``MCP_NOTIFICATIONS_ENABLED`` flag is set true."""
    import os

    raw = os.environ.get(ENABLE_ENV, "false").strip().lower()
    return raw in {"1", "true", "yes", "on"}


__all__ = [
    "ENABLE_ENV",
    "NotificationDispatcher",
    "NotifierProtocol",
    "is_globally_enabled_via_env",
]
