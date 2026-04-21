"""Unit tests for :class:`JiraAdapter` (ARG-035)."""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from src.mcp.services.notifications import (
    AdapterResult,
    DEFAULT_FINDING_FIELD_ID,
    JIRA_API_TOKEN_ENV,
    JIRA_FINDING_FIELD_ENV,
    JIRA_PROJECT_KEY_ENV,
    JIRA_SITE_URL_ENV,
    JIRA_USER_EMAIL_ENV,
    JiraAdapter,
    NotificationSeverity,
    build_jira_payload,
)
from tests.unit.mcp.services.notifications.conftest import (
    collect_responses,
    make_event,
)


def _jira(
    *,
    handler: Callable[[httpx.Request], httpx.Response],
    site_url: str | None = "https://argus.atlassian.example",
    user_email: str | None = "robot@argus.example",
    api_token: str | None = "ATATT3xFfGF0_secret_token_xx",
    project_key: str | None = "SEC",
    finding_field_id: str | None = "customfield_10042",
    issue_type_name: str | None = "Bug",
    max_attempts: int = 3,
) -> JiraAdapter:
    return JiraAdapter(
        site_url=site_url,
        user_email=user_email,
        api_token=api_token,
        project_key=project_key,
        finding_field_id=finding_field_id,
        issue_type_name=issue_type_name,
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            timeout=5.0,
        ),
        max_attempts=max_attempts,
        backoff_base_seconds=0.0,
        backoff_factor=1.0,
        sleep=_NoopSleep(),
        rng=lambda: 1.0,
    )


class _NoopSleep:
    async def __call__(self, _: float) -> None:
        return None


class TestJiraPayload:
    def test_summary_truncated_to_jira_limit(self) -> None:
        ev = make_event(title="X" * 290)
        body = build_jira_payload(
            ev,
            project_key="SEC",
            finding_field_id="customfield_10042",
            issue_type_name="Bug",
            priority_name="Highest",
        )
        assert len(body["fields"]["summary"]) <= 250

    def test_priority_in_fields(self) -> None:
        ev = make_event()
        body = build_jira_payload(
            ev,
            project_key="SEC",
            finding_field_id="customfield_10042",
            issue_type_name="Bug",
            priority_name="High",
        )
        assert body["fields"]["priority"] == {"name": "High"}

    def test_project_key_passed_through(self) -> None:
        ev = make_event()
        body = build_jira_payload(
            ev,
            project_key="ARG",
            finding_field_id="customfield_10042",
            issue_type_name="Bug",
            priority_name="Highest",
        )
        assert body["fields"]["project"] == {"key": "ARG"}

    def test_finding_field_holds_root_cause_hash(self) -> None:
        ev = make_event(root_cause_hash="rch-zzz")
        body = build_jira_payload(
            ev,
            project_key="SEC",
            finding_field_id="customfield_10999",
            issue_type_name="Bug",
            priority_name="Highest",
        )
        assert body["fields"]["customfield_10999"] == "rch-zzz"

    def test_finding_field_falls_back_to_event_id(self) -> None:
        ev = make_event(root_cause_hash=None, event_id="evt-no-hash")
        body = build_jira_payload(
            ev,
            project_key="SEC",
            finding_field_id="customfield_10042",
            issue_type_name="Bug",
            priority_name="Highest",
        )
        assert body["fields"]["customfield_10042"] == "evt-no-hash"

    def test_evidence_url_renders_link_paragraph(self) -> None:
        ev = make_event(evidence_url="https://argus.example/evidence/x")
        body = build_jira_payload(
            ev,
            project_key="SEC",
            finding_field_id="customfield_10042",
            issue_type_name="Bug",
            priority_name="Highest",
        )
        description = body["fields"]["description"]
        link_marks = [
            mark
            for paragraph in description["content"]
            for elem in paragraph.get("content", [])
            for mark in elem.get("marks", [])
            if mark.get("type") == "link"
        ]
        assert any(
            m["attrs"]["href"] == "https://argus.example/evidence/x" for m in link_marks
        )

    def test_extra_tags_become_labels(self) -> None:
        ev = make_event()
        body = build_jira_payload(
            ev,
            project_key="SEC",
            finding_field_id="customfield_10042",
            issue_type_name="Bug",
            priority_name="Highest",
        )
        assert body["fields"]["labels"] == list(ev.extra_tags)

    def test_issue_type_passed_through(self) -> None:
        ev = make_event()
        body = build_jira_payload(
            ev,
            project_key="SEC",
            finding_field_id="customfield_10042",
            issue_type_name="Security Bug",
            priority_name="Highest",
        )
        assert body["fields"]["issuetype"] == {"name": "Security Bug"}


class TestJiraHappyPath:
    def test_critical_event_delivered(self) -> None:
        adapter = _jira(
            handler=collect_responses((201, {"key": "SEC-1", "id": "10001"}))
        )
        ev = make_event(severity=NotificationSeverity.CRITICAL)
        result = asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert isinstance(result, AdapterResult)
        assert result.delivered is True
        assert result.adapter_name == "jira"
        assert result.status_code == 201

    def test_basic_auth_header_uses_email_and_token(self) -> None:
        captured: dict[str, Any] = {}

        def _handler(req: httpx.Request) -> httpx.Response:
            captured["headers"] = dict(req.headers)
            return httpx.Response(201, json={"key": "SEC-2"})

        adapter = _jira(handler=_handler)
        ev = make_event(severity=NotificationSeverity.HIGH)
        asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        auth = captured["headers"]["authorization"]
        assert auth.startswith("Basic ")
        decoded = base64.b64decode(auth.removeprefix("Basic ")).decode()
        assert decoded == "robot@argus.example:ATATT3xFfGF0_secret_token_xx"

    def test_post_targets_issue_endpoint(self) -> None:
        captured: dict[str, Any] = {}

        def _handler(req: httpx.Request) -> httpx.Response:
            captured["url"] = str(req.url)
            captured["method"] = req.method
            return httpx.Response(201, json={"key": "SEC-3"})

        adapter = _jira(handler=_handler)
        ev = make_event(severity=NotificationSeverity.HIGH)
        asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert captured["url"].endswith("/rest/api/3/issue")
        assert captured["method"] == "POST"

    def test_request_body_carries_finding_field(self) -> None:
        captured: dict[str, Any] = {}

        def _handler(req: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(req.content)
            return httpx.Response(201, json={"key": "SEC-4"})

        adapter = _jira(handler=_handler)
        ev = make_event(severity=NotificationSeverity.HIGH, root_cause_hash="rch-42")
        asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert captured["body"]["fields"]["customfield_10042"] == "rch-42"


class TestJiraSeverityRouting:
    def test_medium_skipped_with_reason(self) -> None:
        adapter = _jira(handler=collect_responses((201, None)))
        ev = make_event(severity=NotificationSeverity.MEDIUM)
        result = asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert result.delivered is False
        assert result.skipped_reason == "severity_not_routed"

    def test_low_skipped_with_reason(self) -> None:
        adapter = _jira(handler=collect_responses((201, None)))
        ev = make_event(severity=NotificationSeverity.LOW)
        result = asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert result.skipped_reason == "severity_not_routed"


class TestJiraMissingConfig:
    def test_missing_site_url_disables(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(JIRA_SITE_URL_ENV, raising=False)
        adapter = JiraAdapter(
            site_url=None,
            user_email="r@e",
            api_token="tok",
            project_key="SEC",
        )
        ev = make_event(severity=NotificationSeverity.HIGH)
        result = asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert result.delivered is False
        assert result.skipped_reason == "missing_site_url"
        asyncio.run(adapter.aclose())

    def test_missing_token_disables(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(JIRA_API_TOKEN_ENV, raising=False)
        adapter = JiraAdapter(
            site_url="https://x.atlassian.example",
            user_email="r@e",
            api_token=None,
            project_key="SEC",
        )
        ev = make_event(severity=NotificationSeverity.HIGH)
        result = asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert result.skipped_reason == "missing_secret"
        asyncio.run(adapter.aclose())

    def test_missing_email_disables(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(JIRA_USER_EMAIL_ENV, raising=False)
        adapter = JiraAdapter(
            site_url="https://x.atlassian.example",
            user_email=None,
            api_token="tok",
            project_key="SEC",
        )
        ev = make_event(severity=NotificationSeverity.HIGH)
        result = asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert result.skipped_reason == "missing_secret"
        asyncio.run(adapter.aclose())

    def test_missing_project_disables(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(JIRA_PROJECT_KEY_ENV, raising=False)
        adapter = JiraAdapter(
            site_url="https://x.atlassian.example",
            user_email="r@e",
            api_token="tok",
            project_key=None,
        )
        ev = make_event(severity=NotificationSeverity.HIGH)
        result = asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert result.skipped_reason == "missing_secret"
        asyncio.run(adapter.aclose())

    def test_default_finding_field_used(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(JIRA_FINDING_FIELD_ENV, raising=False)
        adapter = JiraAdapter(
            site_url="https://x.atlassian.example",
            user_email="r@e",
            api_token="t",
            project_key="SEC",
        )
        assert adapter._resolve_finding_field_id() == DEFAULT_FINDING_FIELD_ID
        asyncio.run(adapter.aclose())


class TestJiraRetry:
    def test_retry_on_5xx(self) -> None:
        adapter = _jira(
            handler=collect_responses(
                (500, None),
                (502, None),
                (201, {"key": "SEC-5"}),
            )
        )
        ev = make_event(severity=NotificationSeverity.HIGH)
        result = asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert result.delivered is True
        assert result.attempts == 3

    def test_no_retry_on_400(self) -> None:
        adapter = _jira(handler=collect_responses((400, None)))
        ev = make_event(severity=NotificationSeverity.HIGH)
        result = asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert result.attempts == 1


class TestJiraSecretHygiene:
    def test_token_never_appears_in_result(self) -> None:
        adapter = _jira(handler=collect_responses((201, {"key": "SEC-6"})))
        ev = make_event(severity=NotificationSeverity.HIGH)
        result = asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        for value in result.model_dump().values():
            assert "ATATT3xFfGF0_secret_token_xx" not in str(value)

    def test_url_never_appears_in_result(self) -> None:
        adapter = _jira(handler=collect_responses((201, {"key": "SEC-7"})))
        ev = make_event(severity=NotificationSeverity.HIGH)
        result = asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        for value in result.model_dump().values():
            text = str(value)
            assert "argus.atlassian.example" not in text


class TestJiraIdempotency:
    def test_repeated_event_id_is_short_circuited(self) -> None:
        adapter = _jira(handler=collect_responses((201, {"key": "SEC-8"})))
        ev = make_event(severity=NotificationSeverity.HIGH)
        first = asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        second = asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert first.delivered is True
        assert second.delivered is False
        assert second.skipped_reason == "idempotent_duplicate"
