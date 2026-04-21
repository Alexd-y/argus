"""Linear GraphQL adapter (ARG-035).

Implements :class:`LinearAdapter`:

* Creates a Linear issue via the ``issueCreate`` mutation for critical /
  high severity findings (lower severities are skipped — the dispatcher
  is responsible for routing decisions, but the adapter still defends
  itself).
* Maps :data:`NotificationSeverity` to Linear priority (1 = Urgent,
  4 = Low) and the tenant identifier to a Linear team via the
  ``LINEAR_TEAM_MAP`` JSON env var or per-call override.
* Idempotency uses ``finding.root_cause_hash`` (or the event_id when the
  hash is absent) as the GraphQL ``externalId`` field, plus the in-memory
  dedup set inherited from :class:`NotifierBase`.

Secrets:
    The API key is read from ``LINEAR_API_KEY``. The endpoint defaults to
    ``https://api.linear.app/graphql`` and can be overridden via
    ``LINEAR_API_URL`` for tests / staging.
"""

from __future__ import annotations

import json
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

LINEAR_API_KEY_ENV: Final[str] = "LINEAR_API_KEY"
LINEAR_API_URL_ENV: Final[str] = "LINEAR_API_URL"
LINEAR_TEAM_MAP_ENV: Final[str] = "LINEAR_TEAM_MAP"
LINEAR_DEFAULT_TEAM_ENV: Final[str] = "LINEAR_DEFAULT_TEAM_ID"

DEFAULT_LINEAR_API_URL: Final[str] = "https://api.linear.app/graphql"

_NOTIFY_SEVERITIES: Final[frozenset[NotificationSeverity]] = frozenset(
    {NotificationSeverity.CRITICAL, NotificationSeverity.HIGH}
)

_PRIORITY_BY_SEVERITY: Final[dict[NotificationSeverity, int]] = {
    NotificationSeverity.CRITICAL: 1,
    NotificationSeverity.HIGH: 2,
    NotificationSeverity.MEDIUM: 3,
    NotificationSeverity.LOW: 4,
    NotificationSeverity.INFO: 4,
}

_LABEL_BY_SEVERITY: Final[dict[NotificationSeverity, str]] = {
    NotificationSeverity.CRITICAL: "Urgent",
    NotificationSeverity.HIGH: "High",
    NotificationSeverity.MEDIUM: "Normal",
    NotificationSeverity.LOW: "Low",
    NotificationSeverity.INFO: "Low",
}

_ISSUE_CREATE_MUTATION: Final[str] = (
    "mutation IssueCreate($input: IssueCreateInput!) {"
    "  issueCreate(input: $input) {"
    "    success"
    "    issue { id identifier url }"
    "  }"
    "}"
)


class LinearAdapter(NotifierBase):
    """Linear GraphQL adapter."""

    name = "linear"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        api_url: str | None = None,
        team_map: dict[str, str] | None = None,
        default_team_id: str | None = None,
        client: httpx.AsyncClient | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(client=client, **kwargs)
        self._explicit_api_key = api_key
        self._explicit_api_url = api_url
        self._explicit_team_map = team_map
        self._explicit_default_team_id = default_team_id

    def _resolve_api_url(self) -> str:
        if self._explicit_api_url:
            return self._explicit_api_url
        env_value = os.environ.get(LINEAR_API_URL_ENV, "").strip()
        return env_value or DEFAULT_LINEAR_API_URL

    def _resolve_api_key(self) -> str:
        if self._explicit_api_key is not None:
            return self._explicit_api_key
        return os.environ.get(LINEAR_API_KEY_ENV, "").strip()

    def _resolve_team_map(self) -> dict[str, str]:
        if self._explicit_team_map is not None:
            return self._explicit_team_map
        raw = os.environ.get(LINEAR_TEAM_MAP_ENV, "").strip()
        if not raw:
            return {}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {}
        if not isinstance(data, dict):
            return {}
        return {str(k): str(v) for k, v in data.items() if isinstance(v, str)}

    def _resolve_default_team_id(self) -> str:
        if self._explicit_default_team_id is not None:
            return self._explicit_default_team_id
        return os.environ.get(LINEAR_DEFAULT_TEAM_ENV, "").strip()

    def resolve_team_id(self, tenant_id: str) -> str:
        team_id = self._resolve_team_map().get(tenant_id)
        if team_id:
            return team_id
        return self._resolve_default_team_id()

    def _describe_target(self, *, event: NotificationEvent, tenant_id: str) -> str:
        if event.severity not in _NOTIFY_SEVERITIES:
            raise _AdapterDisabled(
                reason="severity_not_routed",
                target_redacted=hash_target(self._resolve_api_url()),
            )
        api_key = self._resolve_api_key()
        if not api_key:
            raise _AdapterDisabled(
                reason="missing_secret",
                target_redacted=hash_target(self._resolve_api_url()),
            )
        if not self.resolve_team_id(tenant_id):
            raise _AdapterDisabled(
                reason="missing_team_mapping",
                target_redacted=hash_target(self._resolve_api_url()),
            )
        return self._resolve_api_url()

    async def _attempt_send(
        self,
        *,
        event: NotificationEvent,
        tenant_id: str,
        target: str,
    ) -> httpx.Response:
        team_id = self.resolve_team_id(tenant_id)
        body = build_linear_payload(event, team_id=team_id)
        headers = {
            "Authorization": self._resolve_api_key(),
            "Content-Type": "application/json",
            "User-Agent": "argus-mcp-linear/1.0",
        }
        return await self._client.post(target, json=body, headers=headers)


def build_linear_payload(
    event: NotificationEvent, *, team_id: str
) -> dict[str, object]:
    """Render the GraphQL ``issueCreate`` body."""
    external_id = event.root_cause_hash or event.event_id
    description_parts = [event.summary]
    if event.evidence_url:
        description_parts.append(f"\n\n[View evidence]({event.evidence_url})")
    if event.scan_id:
        description_parts.append(f"\n\n**Scan:** `{event.scan_id}`")
    if event.finding_id:
        description_parts.append(f"\n**Finding:** `{event.finding_id}`")
    description_parts.append(f"\n**Tenant:** `{event.tenant_id}`")
    description_parts.append(
        f"\n**Severity:** `{event.severity.value}` "
        f"({_LABEL_BY_SEVERITY[event.severity]})"
    )
    description = "".join(description_parts)
    issue_input: dict[str, object] = {
        "teamId": team_id,
        "title": event.title[:255],
        "description": description[:65_000],
        "priority": _PRIORITY_BY_SEVERITY[event.severity],
        "externalId": external_id,
    }
    if event.extra_tags:
        issue_input["labels"] = list(event.extra_tags)
    return {
        "query": _ISSUE_CREATE_MUTATION,
        "variables": {"input": issue_input},
        "operationName": "IssueCreate",
    }


__all__ = [
    "DEFAULT_LINEAR_API_URL",
    "LINEAR_API_KEY_ENV",
    "LINEAR_API_URL_ENV",
    "LINEAR_DEFAULT_TEAM_ENV",
    "LINEAR_TEAM_MAP_ENV",
    "LinearAdapter",
    "build_linear_payload",
]
