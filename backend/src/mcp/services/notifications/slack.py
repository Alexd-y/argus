"""Slack incoming-webhook adapter (ARG-035).

Implements :class:`SlackNotifier`:

* POST to the Slack incoming-webhook URL on the three event types from
  :data:`schemas.NOTIFICATION_EVENT_TYPES`.
* Block-Kit JSON body with interactive Approve / Deny buttons for
  ``approval.pending`` events. (The Slack message-action callback is the
  responsibility of a separate inbound webhook receiver — out of scope
  for ARG-035; we only deliver the outbound message here.)
* All retry / circuit / dedup / target-hash logic is inherited from
  :class:`NotifierBase`.

Secrets:
    The webhook URL is read EXCLUSIVELY from the ``SLACK_WEBHOOK_URL``
    environment variable. The constructor accepts an explicit override
    for tests but defaults to the env var and raises a typed soft-disable
    when the URL is missing — never a hard failure that could crash the
    server.
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

SLACK_WEBHOOK_URL_ENV: Final[str] = "SLACK_WEBHOOK_URL"

_SEVERITY_EMOJI: Final[dict[NotificationSeverity, str]] = {
    NotificationSeverity.CRITICAL: ":rotating_light:",
    NotificationSeverity.HIGH: ":warning:",
    NotificationSeverity.MEDIUM: ":mag:",
    NotificationSeverity.LOW: ":information_source:",
    NotificationSeverity.INFO: ":speech_balloon:",
}


class SlackNotifier(NotifierBase):
    """Slack incoming-webhook adapter."""

    name = "slack"

    def __init__(
        self,
        *,
        webhook_url: str | None = None,
        client: httpx.AsyncClient | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(client=client, **kwargs)
        self._explicit_url = webhook_url

    def _resolve_url(self) -> str:
        if self._explicit_url is not None:
            return self._explicit_url
        env_value = os.environ.get(SLACK_WEBHOOK_URL_ENV, "").strip()
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
        body = build_slack_payload(event)
        return await self._client.post(target, json=body)


def build_slack_payload(event: NotificationEvent) -> dict[str, object]:
    """Render a Slack Block-Kit body for ``event``.

    Notes
    -----
    * The header / context / section blocks are stable across event types so
      operators get a predictable shape.
    * For ``approval.pending`` we add an ``actions`` block with Approve /
      Deny buttons; ``action_id`` carries ``approval_id`` so the inbound
      action handler (separate concern) can resolve the decision.
    """
    emoji = _SEVERITY_EMOJI.get(event.severity, ":speech_balloon:")
    blocks: list[dict[str, object]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} {event.title}"[:150],
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": event.summary[:2_900],
            },
        },
    ]

    context_elements: list[dict[str, object]] = [
        {"type": "mrkdwn", "text": f"*Tenant:* `{event.tenant_id}`"},
        {"type": "mrkdwn", "text": f"*Severity:* `{event.severity.value}`"},
        {"type": "mrkdwn", "text": f"*Event:* `{event.event_type}`"},
    ]
    if event.scan_id:
        context_elements.append(
            {"type": "mrkdwn", "text": f"*Scan:* `{event.scan_id}`"}
        )
    if event.finding_id:
        context_elements.append(
            {"type": "mrkdwn", "text": f"*Finding:* `{event.finding_id}`"}
        )
    blocks.append({"type": "context", "elements": context_elements})

    if event.evidence_url:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"<{event.evidence_url}|View evidence>",
                },
            }
        )

    if event.event_type == "approval.pending" and event.approval_id:
        blocks.append(
            {
                "type": "actions",
                "block_id": f"approval::{event.approval_id}",
                "elements": [
                    {
                        "type": "button",
                        "style": "primary",
                        "action_id": f"approve::{event.approval_id}",
                        "text": {
                            "type": "plain_text",
                            "text": "Approve",
                            "emoji": True,
                        },
                        "value": event.approval_id,
                    },
                    {
                        "type": "button",
                        "style": "danger",
                        "action_id": f"deny::{event.approval_id}",
                        "text": {"type": "plain_text", "text": "Deny", "emoji": True},
                        "value": event.approval_id,
                    },
                ],
            }
        )

    return {
        "text": f"{emoji} {event.title}"[:1_000],
        "blocks": blocks,
    }


__all__ = ["SLACK_WEBHOOK_URL_ENV", "SlackNotifier", "build_slack_payload"]
