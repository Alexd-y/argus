"""GitHub Issues adapter for ARGUS notifications.

Implements :class:`GitHubIssuesNotifier`:

* Creates a GitHub Issue via ``POST /repos/{owner}/{repo}/issues``.
* Only routes CRITICAL and HIGH severity events by default (configurable via
  ``GITHUB_ISSUES_MIN_SEVERITY`` env var).
* Stores ``root_cause_hash`` (or ``event_id``) as a label for dedup.
* Labels include severity + ``argus`` for easy filtering.

Secrets:
    ``GITHUB_TOKEN`` — Personal Access Token with ``repo`` scope.
    ``GITHUB_REPOSITORY`` — Repository in ``owner/repo-name`` format.

Idempotency notes:
    GitHub Issues API does not natively support ``getOrCreate(externalId)``,
    so duplicate prevention is enforced via the base :class:`NotifierBase`
    dedup-set. The ``argus-`` prefixed label carries the event hash for
    manual dedup queries.
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

GITHUB_TOKEN_ENV: Final[str] = "GITHUB_TOKEN"
GITHUB_REPOSITORY_ENV: Final[str] = "GITHUB_REPOSITORY"
GITHUB_ISSUES_MIN_SEVERITY_ENV: Final[str] = "GITHUB_ISSUES_MIN_SEVERITY"
GITHUB_API_BASE: Final[str] = "https://api.github.com"

_SEVERITY_RANK: Final[dict[NotificationSeverity, int]] = {
    NotificationSeverity.CRITICAL: 0,
    NotificationSeverity.HIGH: 1,
    NotificationSeverity.MEDIUM: 2,
    NotificationSeverity.LOW: 3,
    NotificationSeverity.INFO: 4,
}

_SEVERITY_LABELS: Final[dict[NotificationSeverity, list[str]]] = {
    NotificationSeverity.CRITICAL: ["security", "critical", "argus"],
    NotificationSeverity.HIGH: ["security", "high-priority", "argus"],
    NotificationSeverity.MEDIUM: ["security", "argus"],
    NotificationSeverity.LOW: ["security", "argus"],
    NotificationSeverity.INFO: ["security", "argus"],
}

_SEVERITY_EMOJI: Final[dict[NotificationSeverity, str]] = {
    NotificationSeverity.CRITICAL: "\U0001f534",
    NotificationSeverity.HIGH: "\U0001f7e0",
    NotificationSeverity.MEDIUM: "\U0001f7e1",
    NotificationSeverity.LOW: "\U0001f535",
    NotificationSeverity.INFO: "\u26aa",
}


class GitHubIssuesNotifier(NotifierBase):
    """GitHub Issues creation adapter."""

    name = "github_issues"

    def __init__(
        self,
        *,
        github_token: str | None = None,
        github_repository: str | None = None,
        min_severity: NotificationSeverity | None = None,
        client: httpx.AsyncClient | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(client=client, **kwargs)
        self._explicit_token = github_token
        self._explicit_repo = github_repository
        if min_severity is not None:
            self._min_severity = min_severity
        else:
            env_sev = os.environ.get(
                GITHUB_ISSUES_MIN_SEVERITY_ENV, "high"
            ).strip().lower()
            self._min_severity = _parse_severity(env_sev)

    def _resolve_token(self) -> str:
        if self._explicit_token is not None:
            return self._explicit_token
        return os.environ.get(GITHUB_TOKEN_ENV, "").strip()

    def _resolve_repo(self) -> str:
        if self._explicit_repo is not None:
            return self._explicit_repo
        return os.environ.get(GITHUB_REPOSITORY_ENV, "").strip()

    def _describe_target(self, *, event: NotificationEvent, tenant_id: str) -> str:
        repo = self._resolve_repo()
        if not repo:
            raise _AdapterDisabled(
                reason="missing_secret", target_redacted=hash_target("")
            )
        return f"{GITHUB_API_BASE}/repos/{repo}/issues"

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

        token = self._resolve_token()
        repo = self._resolve_repo()
        if not token or not repo:
            raise _AdapterDisabled(
                reason="missing_secret", target_redacted=hash_target("")
            )

        body = build_github_issue_payload(event)
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "ARGUS-Security-Platform/1.0",
        }
        url = f"{GITHUB_API_BASE}/repos/{repo}/issues"
        return await self._client.post(url, json=body, headers=headers)

    def _should_send(self, event: NotificationEvent) -> bool:
        event_rank = _SEVERITY_RANK.get(event.severity, 4)
        min_rank = _SEVERITY_RANK.get(self._min_severity, 1)
        return event_rank <= min_rank


def _parse_severity(raw: str) -> NotificationSeverity:
    mapping = {
        "critical": NotificationSeverity.CRITICAL,
        "high": NotificationSeverity.HIGH,
        "medium": NotificationSeverity.MEDIUM,
        "low": NotificationSeverity.LOW,
        "info": NotificationSeverity.INFO,
    }
    return mapping.get(raw, NotificationSeverity.HIGH)


def build_github_issue_payload(event: NotificationEvent) -> dict[str, Any]:
    """Render a GitHub Issue creation body for ``event``."""
    emoji = _SEVERITY_EMOJI.get(event.severity, "\u26aa")
    sev = event.severity.value.upper()
    labels = list(_SEVERITY_LABELS.get(event.severity, ["argus"]))

    if event.root_cause_hash:
        labels.append(f"argus-hash:{event.root_cause_hash[:12]}")

    title = f"{emoji} [{sev}] {event.title}"[:256]

    body_parts: list[str] = [
        f"## {emoji} {sev} \u2014 {event.event_type}",
        "",
        f"**Tenant:** `{event.tenant_id}`",
    ]
    if event.scan_id:
        body_parts.append(f"**Scan:** `{event.scan_id}`")
    if event.finding_id:
        body_parts.append(f"**Finding:** `{event.finding_id}`")
    body_parts.append("")
    body_parts.append(event.summary[:4_000])
    if event.evidence_url:
        body_parts.append(f"\n[View evidence]({event.evidence_url})")
    body_parts.append("")
    body_parts.append("---")
    body_parts.append("*Created by [ARGUS](https://github.com/argus-security)*")

    return {
        "title": title,
        "body": "\n".join(body_parts)[:65_536],
        "labels": labels,
    }


__all__ = [
    "GITHUB_TOKEN_ENV",
    "GITHUB_REPOSITORY_ENV",
    "GITHUB_ISSUES_MIN_SEVERITY_ENV",
    "GitHubIssuesNotifier",
    "build_github_issue_payload",
]