"""Discord incoming-webhook adapter.

Implements :class:`DiscordNotifier`:

* POST to the Discord webhook URL for finding and scan-completion events.
* Rich embed format with severity-coloured sidebar, finding details, and
  evidence links.
* Only routes events at or above the configured minimum severity (default
  MEDIUM). CRITICAL and HIGH events always go through; INFO is always skipped.
* All retry / circuit / dedup / target-hash logic is inherited from
  :class:`NotifierBase`.

Secrets:
    The webhook URL is read from the ``DISCORD_WEBHOOK_URL`` environment
    variable. The constructor accepts an explicit override for tests but
    defaults to the env var and raises a typed soft-disable when the URL is
    missing.
"""

from __future__ import annotations

import os
from typing import Any, Final

import httpx

from src.mcp.services.notifications._base import (
    NotifierBase,
    _AdapterDisabled,
    hash_target,
)
from src.mcp.services.notifications.schemas import (
    NotificationEvent,
    NotificationSeverity,
)

DISCORD_WEBHOOK_URL_ENV: Final[str] = "DISCORD_WEBHOOK_URL"
DISCORD_MIN_SEVERITY_ENV: Final[str] = "DISCORD_MIN_SEVERITY"

_SEVERITY_RANK: Final[dict[NotificationSeverity, int]] = {
    NotificationSeverity.CRITICAL: 0,
    NotificationSeverity.HIGH: 1,
    NotificationSeverity.MEDIUM: 2,
    NotificationSeverity.LOW: 3,
    NotificationSeverity.INFO: 4,
}

_SEVERITY_DISCORD_COLOR: Final[dict[NotificationSeverity, int]] = {
    NotificationSeverity.CRITICAL: 0xEF4444,
    NotificationSeverity.HIGH: 0xF97316,
    NotificationSeverity.MEDIUM: 0xEAB308,
    NotificationSeverity.LOW: 0x3B82F6,
    NotificationSeverity.INFO: 0x6B7280,
}

_SEVERITY_EMOJI: Final[dict[NotificationSeverity, str]] = {
    NotificationSeverity.CRITICAL: "\U0001f534",
    NotificationSeverity.HIGH: "\U0001f7e0",
    NotificationSeverity.MEDIUM: "\U0001f7e1",
    NotificationSeverity.LOW: "\U0001f535",
    NotificationSeverity.INFO: "\u26aa",
}


class DiscordNotifier(NotifierBase):
    """Discord incoming-webhook adapter."""

    name = "discord"

    def __init__(
        self,
        *,
        webhook_url: str | None = None,
        min_severity: NotificationSeverity | None = None,
        client: httpx.AsyncClient | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(client=client, **kwargs)
        self._explicit_url = webhook_url
        if min_severity is not None:
            self._min_severity = min_severity
        else:
            env_sev = os.environ.get(DISCORD_MIN_SEVERITY_ENV, "medium").strip().lower()
            self._min_severity = _parse_severity(env_sev)

    def _resolve_url(self) -> str:
        if self._explicit_url is not None:
            return self._explicit_url
        env_value = os.environ.get(DISCORD_WEBHOOK_URL_ENV, "").strip()
        return env_value

    def _describe_target(self, *, event: NotificationEvent, tenant_id: str) -> str:
        url = self._resolve_url()
        if not url:
            raise _AdapterDisabled(
                reason="missing_secret", target_redacted=hash_target("")
            )
        return url

    async def _attempt_send(
        self,
        *,
        event: NotificationEvent,
        tenant_id: str,
        target: str,
    ) -> httpx.Response:
        if not self._should_send(event):
            raise _AdapterDisabled(
                reason="skipped_below_min_severity",
                target_redacted=hash_target(""),
            )
        body = build_discord_payload(event)
        return await self._client.post(target, json=body)

    def _should_send(self, event: NotificationEvent) -> bool:
        event_rank = _SEVERITY_RANK.get(event.severity, 4)
        min_rank = _SEVERITY_RANK.get(self._min_severity, 2)
        return event_rank <= min_rank


def _parse_severity(raw: str) -> NotificationSeverity:
    mapping = {
        "critical": NotificationSeverity.CRITICAL,
        "high": NotificationSeverity.HIGH,
        "medium": NotificationSeverity.MEDIUM,
        "low": NotificationSeverity.LOW,
        "info": NotificationSeverity.INFO,
    }
    return mapping.get(raw, NotificationSeverity.MEDIUM)


def build_discord_payload(event: NotificationEvent) -> dict[str, Any]:
    """Render a Discord embed body for ``event``."""
    emoji = _SEVERITY_EMOJI.get(event.severity, "\u26aa")
    color = _SEVERITY_DISCORD_COLOR.get(event.severity, 0x6B7280)

    fields: list[dict[str, Any]] = [
        {
            "name": "OWASP / Category",
            "value": event.event_type,
            "inline": True,
        },
        {
            "name": "Severity",
            "value": f"{emoji} {event.severity.value}",
            "inline": True,
        },
        {
            "name": "Tenant",
            "value": f"`{event.tenant_id}`",
            "inline": True,
        },
    ]

    if event.scan_id:
        fields.append(
            {"name": "Scan", "value": f"`{event.scan_id}`", "inline": True}
        )
    if event.finding_id:
        fields.append(
            {"name": "Finding", "value": f"`{event.finding_id}`", "inline": True}
        )

    embed: dict[str, Any] = {
        "title": f"{emoji} {event.severity.value.upper()} \u2014 {event.title}"[:256],
        "color": color,
        "fields": fields,
        "description": event.summary[:4_096],
        "footer": {"text": "ARGUS Security Platform"},
        "timestamp": (event.occurred_at or __import__("datetime").datetime.now(__import__("datetime").timezone.utc)).isoformat(),
    }

    if event.evidence_url:
        embed["url"] = event.evidence_url

    return {"embeds": [embed]}


__all__ = ["DISCORD_WEBHOOK_URL_ENV", "DISCORD_MIN_SEVERITY_ENV", "DiscordNotifier", "build_discord_payload"]
