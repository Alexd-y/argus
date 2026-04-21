"""Jira REST API v3 adapter (ARG-035).

Implements :class:`JiraAdapter`:

* Creates a Jira issue via ``POST /rest/api/3/issue``.
* Stores the originating finding hash in a custom field ``argus_finding_id``
  for traceability + acts as the de-duplication key (see notes below).
* Maps :data:`NotificationSeverity` to a project priority name; the mapping
  is configurable via env (``JIRA_PRIORITY_MAP`` JSON), but defaults to
  the standard Atlassian set: Highest / High / Medium / Low / Lowest.

Idempotency notes:
    Jira REST does not natively expose a ``getOrCreate(externalId)`` flow,
    so duplicate prevention is enforced in two layers:

    1. The base :class:`NotifierBase` dedup-set short-circuits resends of
       the same ``event_id`` within the same process.
    2. The custom field ``argus_finding_id`` is populated with
       ``event.root_cause_hash`` (or ``event_id``) so an operator can
       JQL-filter duplicates and a follow-up reconciliation job can mark
       them with ``Duplicate`` link type. Long-term dedup must therefore
       still be enforced by the dispatcher / pipeline, but the data is
       there to support it.

Secrets:
    Authentication is HTTP Basic with email + API token (Atlassian Cloud
    standard). Both come from env: ``JIRA_USER_EMAIL`` and
    ``JIRA_API_TOKEN``. Site URL from ``JIRA_SITE_URL``, project key from
    ``JIRA_PROJECT_KEY``. The custom field id is configurable via
    ``JIRA_FINDING_FIELD_ID`` (typical: ``customfield_10042``).
"""

from __future__ import annotations

import base64
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

JIRA_USER_EMAIL_ENV: Final[str] = "JIRA_USER_EMAIL"
JIRA_API_TOKEN_ENV: Final[str] = "JIRA_API_TOKEN"
JIRA_SITE_URL_ENV: Final[str] = "JIRA_SITE_URL"
JIRA_PROJECT_KEY_ENV: Final[str] = "JIRA_PROJECT_KEY"
JIRA_FINDING_FIELD_ENV: Final[str] = "JIRA_FINDING_FIELD_ID"
JIRA_ISSUE_TYPE_ENV: Final[str] = "JIRA_ISSUE_TYPE_NAME"
JIRA_PRIORITY_MAP_ENV: Final[str] = "JIRA_PRIORITY_MAP"

DEFAULT_FINDING_FIELD_ID: Final[str] = "customfield_10042"
DEFAULT_ISSUE_TYPE_NAME: Final[str] = "Bug"
ISSUE_CREATE_PATH: Final[str] = "/rest/api/3/issue"

_NOTIFY_SEVERITIES: Final[frozenset[NotificationSeverity]] = frozenset(
    {NotificationSeverity.CRITICAL, NotificationSeverity.HIGH}
)

_DEFAULT_PRIORITY_MAP: Final[dict[NotificationSeverity, str]] = {
    NotificationSeverity.CRITICAL: "Highest",
    NotificationSeverity.HIGH: "High",
    NotificationSeverity.MEDIUM: "Medium",
    NotificationSeverity.LOW: "Low",
    NotificationSeverity.INFO: "Lowest",
}


class JiraAdapter(NotifierBase):
    """Jira REST API v3 adapter."""

    name = "jira"

    def __init__(
        self,
        *,
        site_url: str | None = None,
        user_email: str | None = None,
        api_token: str | None = None,
        project_key: str | None = None,
        finding_field_id: str | None = None,
        issue_type_name: str | None = None,
        priority_map: dict[NotificationSeverity, str] | None = None,
        client: httpx.AsyncClient | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(client=client, **kwargs)
        self._explicit_site_url = site_url
        self._explicit_user_email = user_email
        self._explicit_api_token = api_token
        self._explicit_project_key = project_key
        self._explicit_finding_field_id = finding_field_id
        self._explicit_issue_type_name = issue_type_name
        self._explicit_priority_map = priority_map

    def _resolve_site_url(self) -> str:
        if self._explicit_site_url is not None:
            return self._explicit_site_url.rstrip("/")
        return os.environ.get(JIRA_SITE_URL_ENV, "").strip().rstrip("/")

    def _resolve_user_email(self) -> str:
        if self._explicit_user_email is not None:
            return self._explicit_user_email
        return os.environ.get(JIRA_USER_EMAIL_ENV, "").strip()

    def _resolve_api_token(self) -> str:
        if self._explicit_api_token is not None:
            return self._explicit_api_token
        return os.environ.get(JIRA_API_TOKEN_ENV, "").strip()

    def _resolve_project_key(self) -> str:
        if self._explicit_project_key is not None:
            return self._explicit_project_key
        return os.environ.get(JIRA_PROJECT_KEY_ENV, "").strip()

    def _resolve_finding_field_id(self) -> str:
        if self._explicit_finding_field_id is not None:
            return self._explicit_finding_field_id
        env_value = os.environ.get(JIRA_FINDING_FIELD_ENV, "").strip()
        return env_value or DEFAULT_FINDING_FIELD_ID

    def _resolve_issue_type_name(self) -> str:
        if self._explicit_issue_type_name is not None:
            return self._explicit_issue_type_name
        env_value = os.environ.get(JIRA_ISSUE_TYPE_ENV, "").strip()
        return env_value or DEFAULT_ISSUE_TYPE_NAME

    def _resolve_priority_map(self) -> dict[NotificationSeverity, str]:
        if self._explicit_priority_map is not None:
            return self._explicit_priority_map
        raw = os.environ.get(JIRA_PRIORITY_MAP_ENV, "").strip()
        if not raw:
            return dict(_DEFAULT_PRIORITY_MAP)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return dict(_DEFAULT_PRIORITY_MAP)
        if not isinstance(data, dict):
            return dict(_DEFAULT_PRIORITY_MAP)
        merged = dict(_DEFAULT_PRIORITY_MAP)
        for key, value in data.items():
            try:
                severity = NotificationSeverity(key)
            except ValueError:
                continue
            if isinstance(value, str) and value:
                merged[severity] = value
        return merged

    def _describe_target(self, *, event: NotificationEvent, tenant_id: str) -> str:
        site_url = self._resolve_site_url()
        if event.severity not in _NOTIFY_SEVERITIES:
            raise _AdapterDisabled(
                reason="severity_not_routed",
                target_redacted=hash_target(site_url + ISSUE_CREATE_PATH),
            )
        if not site_url:
            raise _AdapterDisabled(
                reason="missing_site_url",
                target_redacted=hash_target(""),
            )
        if not (
            self._resolve_api_token()
            and self._resolve_user_email()
            and self._resolve_project_key()
        ):
            raise _AdapterDisabled(
                reason="missing_secret",
                target_redacted=hash_target(site_url + ISSUE_CREATE_PATH),
            )
        return site_url + ISSUE_CREATE_PATH

    async def _attempt_send(
        self,
        *,
        event: NotificationEvent,
        tenant_id: str,
        target: str,
    ) -> httpx.Response:
        priority_map = self._resolve_priority_map()
        body = build_jira_payload(
            event,
            project_key=self._resolve_project_key(),
            finding_field_id=self._resolve_finding_field_id(),
            issue_type_name=self._resolve_issue_type_name(),
            priority_name=priority_map[event.severity],
        )
        headers = {
            "Authorization": _basic_auth_header(
                email=self._resolve_user_email(),
                api_token=self._resolve_api_token(),
            ),
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "argus-mcp-jira/1.0",
        }
        return await self._client.post(target, json=body, headers=headers)


def _basic_auth_header(*, email: str, api_token: str) -> str:
    """Return the ``Basic <b64>`` Authorization header value."""
    raw = f"{email}:{api_token}".encode("utf-8")
    encoded = base64.b64encode(raw).decode("ascii")
    return f"Basic {encoded}"


def build_jira_payload(
    event: NotificationEvent,
    *,
    project_key: str,
    finding_field_id: str,
    issue_type_name: str,
    priority_name: str,
) -> dict[str, object]:
    """Render the Jira REST v3 issue-create body (ADF description)."""
    external_id = event.root_cause_hash or event.event_id
    description_paragraphs = [
        _paragraph(event.summary[:30_000]),
    ]
    if event.evidence_url:
        description_paragraphs.append(
            _paragraph_with_link("View evidence", event.evidence_url)
        )
    metadata_lines: list[str] = [
        f"Tenant: {event.tenant_id}",
        f"Severity: {event.severity.value}",
    ]
    if event.scan_id:
        metadata_lines.append(f"Scan: {event.scan_id}")
    if event.finding_id:
        metadata_lines.append(f"Finding: {event.finding_id}")
    description_paragraphs.append(_paragraph("\n".join(metadata_lines)))

    fields: dict[str, object] = {
        "project": {"key": project_key},
        "summary": event.title[:250],
        "issuetype": {"name": issue_type_name},
        "priority": {"name": priority_name},
        "description": {
            "type": "doc",
            "version": 1,
            "content": description_paragraphs,
        },
        finding_field_id: external_id,
    }
    if event.extra_tags:
        fields["labels"] = list(event.extra_tags)
    return {"fields": fields}


def _paragraph(text: str) -> dict[str, object]:
    return {
        "type": "paragraph",
        "content": [{"type": "text", "text": text}],
    }


def _paragraph_with_link(text: str, href: str) -> dict[str, object]:
    return {
        "type": "paragraph",
        "content": [
            {
                "type": "text",
                "text": text,
                "marks": [{"type": "link", "attrs": {"href": href}}],
            }
        ],
    }


__all__ = [
    "DEFAULT_FINDING_FIELD_ID",
    "DEFAULT_ISSUE_TYPE_NAME",
    "ISSUE_CREATE_PATH",
    "JIRA_API_TOKEN_ENV",
    "JIRA_FINDING_FIELD_ENV",
    "JIRA_ISSUE_TYPE_ENV",
    "JIRA_PRIORITY_MAP_ENV",
    "JIRA_PROJECT_KEY_ENV",
    "JIRA_SITE_URL_ENV",
    "JIRA_USER_EMAIL_ENV",
    "JiraAdapter",
    "build_jira_payload",
]
