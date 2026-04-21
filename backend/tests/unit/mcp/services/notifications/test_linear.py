"""Unit tests for :class:`LinearAdapter` (ARG-035)."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from src.mcp.services.notifications import (
    AdapterResult,
    LINEAR_API_KEY_ENV,
    LINEAR_API_URL_ENV,
    LINEAR_DEFAULT_TEAM_ENV,
    LINEAR_TEAM_MAP_ENV,
    LinearAdapter,
    NotificationSeverity,
    build_linear_payload,
)
from tests.unit.mcp.services.notifications.conftest import (
    collect_responses,
    make_event,
)


def _linear(
    *,
    handler: Callable[[httpx.Request], httpx.Response],
    api_key: str | None = "lin_api_test_secret",
    api_url: str | None = "https://api.linear.example/graphql",
    team_map: dict[str, str] | None = None,
    default_team_id: str | None = "team-default",
    max_attempts: int = 3,
) -> LinearAdapter:
    return LinearAdapter(
        api_key=api_key,
        api_url=api_url,
        team_map=team_map if team_map is not None else {"tenant-alpha": "team-alpha"},
        default_team_id=default_team_id,
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


class TestLinearPayload:
    def test_priority_mapping_critical_is_one(self) -> None:
        ev = make_event(severity=NotificationSeverity.CRITICAL)
        body = build_linear_payload(ev, team_id="team-x")
        assert body["variables"]["input"]["priority"] == 1

    def test_priority_mapping_high_is_two(self) -> None:
        ev = make_event(severity=NotificationSeverity.HIGH)
        body = build_linear_payload(ev, team_id="team-x")
        assert body["variables"]["input"]["priority"] == 2

    def test_uses_root_cause_hash_as_external_id(self) -> None:
        ev = make_event(root_cause_hash="rch-abc")
        body = build_linear_payload(ev, team_id="team-x")
        assert body["variables"]["input"]["externalId"] == "rch-abc"

    def test_falls_back_to_event_id_when_no_hash(self) -> None:
        ev = make_event(root_cause_hash=None, event_id="evt-fallback")
        body = build_linear_payload(ev, team_id="team-x")
        assert body["variables"]["input"]["externalId"] == "evt-fallback"

    def test_evidence_url_in_description(self) -> None:
        ev = make_event(evidence_url="https://argus.example/e/1")
        body = build_linear_payload(ev, team_id="team-x")
        desc = body["variables"]["input"]["description"]
        assert "https://argus.example/e/1" in desc

    def test_extra_tags_become_labels(self) -> None:
        ev = make_event()
        body = build_linear_payload(ev, team_id="team-x")
        assert body["variables"]["input"]["labels"] == list(ev.extra_tags)

    def test_team_id_propagated_to_input(self) -> None:
        ev = make_event()
        body = build_linear_payload(ev, team_id="team-Q")
        assert body["variables"]["input"]["teamId"] == "team-Q"

    def test_operation_name_is_issue_create(self) -> None:
        ev = make_event()
        body = build_linear_payload(ev, team_id="team-Q")
        assert body["operationName"] == "IssueCreate"

    def test_query_targets_issue_create_mutation(self) -> None:
        ev = make_event()
        body = build_linear_payload(ev, team_id="team-Q")
        assert "issueCreate" in body["query"]


class TestLinearTeamResolution:
    def test_team_map_takes_priority_over_default(self) -> None:
        adapter = _linear(
            handler=collect_responses(
                (200, {"data": {"issueCreate": {"success": True}}})
            )
        )
        assert adapter.resolve_team_id("tenant-alpha") == "team-alpha"

    def test_default_team_used_when_unmapped(self) -> None:
        adapter = _linear(
            handler=collect_responses(
                (200, {"data": {"issueCreate": {"success": True}}})
            ),
            team_map={"tenant-other": "team-other"},
        )
        assert adapter.resolve_team_id("tenant-alpha") == "team-default"

    def test_env_team_map_loaded_when_no_explicit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(LINEAR_TEAM_MAP_ENV, json.dumps({"tenant-x": "tx"}))
        adapter = LinearAdapter(api_key="k", api_url="https://x", default_team_id="td")
        assert adapter.resolve_team_id("tenant-x") == "tx"
        assert adapter.resolve_team_id("tenant-other") == "td"
        asyncio.run(adapter.aclose())

    def test_env_default_team_loaded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(LINEAR_DEFAULT_TEAM_ENV, "td-env")
        adapter = LinearAdapter(api_key="k", api_url="https://x")
        assert adapter.resolve_team_id("tenant-x") == "td-env"
        asyncio.run(adapter.aclose())

    def test_invalid_team_map_json_falls_back_silently(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(LINEAR_TEAM_MAP_ENV, "not-json")
        adapter = LinearAdapter(api_key="k", api_url="https://x", default_team_id="td")
        assert adapter.resolve_team_id("tenant-x") == "td"
        asyncio.run(adapter.aclose())


class TestLinearHappyPath:
    def test_critical_event_delivered(self) -> None:
        adapter = _linear(
            handler=collect_responses(
                (200, {"data": {"issueCreate": {"success": True}}})
            )
        )
        ev = make_event(severity=NotificationSeverity.CRITICAL)
        result = asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert isinstance(result, AdapterResult)
        assert result.delivered is True
        assert result.attempts == 1
        assert result.adapter_name == "linear"

    def test_high_severity_also_delivered(self) -> None:
        adapter = _linear(
            handler=collect_responses(
                (200, {"data": {"issueCreate": {"success": True}}})
            )
        )
        ev = make_event(severity=NotificationSeverity.HIGH)
        result = asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert result.delivered is True

    def test_authorization_header_uses_raw_api_key(self) -> None:
        captured: dict[str, Any] = {}

        def _handler(req: httpx.Request) -> httpx.Response:
            captured["headers"] = dict(req.headers)
            return httpx.Response(
                200, json={"data": {"issueCreate": {"success": True}}}
            )

        adapter = _linear(handler=_handler)
        ev = make_event(severity=NotificationSeverity.HIGH)
        asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert captured["headers"]["authorization"] == "lin_api_test_secret"

    def test_request_body_is_json_graphql(self) -> None:
        captured: dict[str, Any] = {}

        def _handler(req: httpx.Request) -> httpx.Response:
            captured["body"] = json.loads(req.content)
            return httpx.Response(
                200, json={"data": {"issueCreate": {"success": True}}}
            )

        adapter = _linear(handler=_handler)
        ev = make_event(severity=NotificationSeverity.HIGH)
        asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert "query" in captured["body"]
        assert "variables" in captured["body"]
        assert captured["body"]["variables"]["input"]["teamId"] == "team-alpha"


class TestLinearSeverityRouting:
    def test_medium_event_skipped_with_reason(self) -> None:
        adapter = _linear(handler=collect_responses((200, None)))
        ev = make_event(severity=NotificationSeverity.MEDIUM)
        result = asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert result.delivered is False
        assert result.skipped_reason == "severity_not_routed"
        assert result.attempts == 0

    def test_low_event_skipped_with_reason(self) -> None:
        adapter = _linear(handler=collect_responses((200, None)))
        ev = make_event(severity=NotificationSeverity.LOW)
        result = asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert result.skipped_reason == "severity_not_routed"

    def test_info_event_skipped(self) -> None:
        adapter = _linear(handler=collect_responses((200, None)))
        ev = make_event(severity=NotificationSeverity.INFO)
        result = asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert result.skipped_reason == "severity_not_routed"


class TestLinearMissingConfig:
    def test_missing_api_key_disables(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(LINEAR_API_KEY_ENV, raising=False)
        adapter = LinearAdapter(
            api_key=None,
            api_url="https://api.linear.example/graphql",
            team_map={"tenant-alpha": "team-alpha"},
        )
        ev = make_event(severity=NotificationSeverity.HIGH)
        result = asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert result.delivered is False
        assert result.skipped_reason == "missing_secret"
        asyncio.run(adapter.aclose())

    def test_missing_team_mapping_disables(self) -> None:
        adapter = LinearAdapter(
            api_key="k",
            api_url="https://api.linear.example/graphql",
            team_map={},
            default_team_id="",
        )
        ev = make_event(severity=NotificationSeverity.HIGH)
        result = asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert result.delivered is False
        assert result.skipped_reason == "missing_team_mapping"
        asyncio.run(adapter.aclose())

    def test_default_url_used_when_env_unset(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(LINEAR_API_URL_ENV, raising=False)
        adapter = LinearAdapter(api_key="k", default_team_id="t")
        assert adapter._resolve_api_url() == "https://api.linear.app/graphql"
        asyncio.run(adapter.aclose())


class TestLinearRetry:
    def test_5xx_retried_and_succeeds(self) -> None:
        adapter = _linear(
            handler=collect_responses(
                (502, None),
                (502, None),
                (200, {"data": {"issueCreate": {"success": True}}}),
            )
        )
        ev = make_event(severity=NotificationSeverity.HIGH)
        result = asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert result.delivered is True
        assert result.attempts == 3

    def test_4xx_not_retried(self) -> None:
        adapter = _linear(handler=collect_responses((400, None)))
        ev = make_event(severity=NotificationSeverity.HIGH)
        result = asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert result.attempts == 1
        assert result.error_code == "http_4xx"


class TestLinearSecretHygiene:
    def test_target_redacted_does_not_leak_url(self) -> None:
        adapter = _linear(
            handler=collect_responses(
                (200, {"data": {"issueCreate": {"success": True}}})
            )
        )
        ev = make_event(severity=NotificationSeverity.HIGH)
        result = asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        for value in result.model_dump().values():
            assert "lin_api_test_secret" not in str(value)
            assert "graphql" not in str(value).lower() or value == result.adapter_name


class TestLinearIdempotency:
    def test_repeated_event_id_is_short_circuited(self) -> None:
        adapter = _linear(
            handler=collect_responses(
                (200, {"data": {"issueCreate": {"success": True}}})
            )
        )
        ev = make_event(severity=NotificationSeverity.HIGH)
        first = asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        second = asyncio.run(adapter.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert first.delivered is True
        assert second.delivered is False
        assert second.skipped_reason == "idempotent_duplicate"
