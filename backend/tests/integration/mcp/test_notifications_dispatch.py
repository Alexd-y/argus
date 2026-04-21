"""Integration tests for the MCP notifications subsystem (ARG-035).

These are *integration* tests in the ARGUS taxonomy: they exercise the
:class:`NotificationDispatcher` together with the three real concrete
adapters (Slack / Linear / Jira) wired against an in-process
:class:`httpx.MockTransport`. No real network egress occurs.

The goal is to catch wiring regressions that the per-adapter unit tests
cannot — e.g. the dispatcher passing the wrong tenant id, the order in
which adapters fire, or an exception in one adapter taking the others
down.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime, timezone

import httpx
import pytest

from src.mcp.services.notifications import (
    JiraAdapter,
    LinearAdapter,
    NotificationDispatcher,
    NotificationEvent,
    NotificationSeverity,
    SlackNotifier,
)

pytestmark = [pytest.mark.asyncio, pytest.mark.integration]


def _make_event(
    *,
    event_id: str,
    severity: NotificationSeverity = NotificationSeverity.HIGH,
    tenant_id: str = "tenant-alpha",
    event_type: str = "critical.finding.detected",
) -> NotificationEvent:
    return NotificationEvent(
        event_id=event_id,
        event_type=event_type,
        severity=severity,
        tenant_id=tenant_id,
        title="High-severity SSRF in /admin/import",
        summary="Authenticated SSRF lets users hit metadata endpoint.",
        scan_id="scan-int-001",
        finding_id="finding-int-001",
        approval_id=None,
        root_cause_hash="rch-int-001",
        evidence_url="https://argus.example/evidence/int-001",
        occurred_at=datetime(2026, 4, 19, 12, 0, tzinfo=timezone.utc),
        extra_tags=("cwe-918",),
    )


def _wire_adapters(
    *,
    slack_handler: Callable[[httpx.Request], httpx.Response],
    linear_handler: Callable[[httpx.Request], httpx.Response],
    jira_handler: Callable[[httpx.Request], httpx.Response],
) -> tuple[SlackNotifier, LinearAdapter, JiraAdapter]:
    slack = SlackNotifier(
        webhook_url="https://hooks.slack.example/T0/B0/itest",
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(slack_handler), timeout=5.0
        ),
        backoff_base_seconds=0.0,
        backoff_factor=1.0,
        rng=lambda: 1.0,
    )
    linear = LinearAdapter(
        api_key="lin_int_key",
        api_url="https://api.linear.example/graphql",
        team_map={"tenant-alpha": "team-int"},
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(linear_handler), timeout=5.0
        ),
        backoff_base_seconds=0.0,
        backoff_factor=1.0,
        rng=lambda: 1.0,
    )
    jira = JiraAdapter(
        site_url="https://argus.atlassian.example",
        user_email="bot@argus.example",
        api_token="jira_int_token",
        project_key="SEC",
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(jira_handler), timeout=5.0
        ),
        backoff_base_seconds=0.0,
        backoff_factor=1.0,
        rng=lambda: 1.0,
    )
    return slack, linear, jira


def _disp(
    *, slack: SlackNotifier, linear: LinearAdapter, jira: JiraAdapter
) -> NotificationDispatcher:
    d = NotificationDispatcher(adapters=[slack, linear, jira], enabled=True)
    for name in ("slack", "linear", "jira"):
        d.set_adapter_enabled(name, True)
    return d


class TestEndToEndDispatch:
    async def test_all_three_adapters_deliver_in_parallel(self) -> None:
        calls = {"slack": 0, "linear": 0, "jira": 0}

        def _slack(req: httpx.Request) -> httpx.Response:
            calls["slack"] += 1
            return httpx.Response(200, json={"ok": True})

        def _linear(req: httpx.Request) -> httpx.Response:
            calls["linear"] += 1
            return httpx.Response(
                200, json={"data": {"issueCreate": {"success": True}}}
            )

        def _jira(req: httpx.Request) -> httpx.Response:
            calls["jira"] += 1
            return httpx.Response(201, json={"key": "SEC-99"})

        slack, linear, jira = _wire_adapters(
            slack_handler=_slack,
            linear_handler=_linear,
            jira_handler=_jira,
        )
        disp = _disp(slack=slack, linear=linear, jira=jira)
        try:
            results = await disp.dispatch(_make_event(event_id="evt-int-100"))
        finally:
            await disp.aclose()

        assert calls == {"slack": 1, "linear": 1, "jira": 1}
        assert all(r.delivered for r in results)
        assert {r.adapter_name for r in results} == {"slack", "linear", "jira"}

    async def test_slack_only_for_medium_severity(self) -> None:
        slack_calls: list[bytes] = []

        def _slack(req: httpx.Request) -> httpx.Response:
            slack_calls.append(req.content)
            return httpx.Response(200)

        def _linear(_: httpx.Request) -> httpx.Response:
            return httpx.Response(500)  # would fail if invoked

        def _jira(_: httpx.Request) -> httpx.Response:
            return httpx.Response(500)  # would fail if invoked

        slack, linear, jira = _wire_adapters(
            slack_handler=_slack,
            linear_handler=_linear,
            jira_handler=_jira,
        )
        disp = _disp(slack=slack, linear=linear, jira=jira)
        try:
            results = await disp.dispatch(
                _make_event(
                    event_id="evt-int-101", severity=NotificationSeverity.MEDIUM
                )
            )
        finally:
            await disp.aclose()

        delivered_by = {r.adapter_name: r.delivered for r in results}
        assert delivered_by["slack"] is True
        assert delivered_by["linear"] is False
        assert delivered_by["jira"] is False
        skipped = {r.adapter_name: r.skipped_reason for r in results if not r.delivered}
        assert skipped["linear"] == "severity_not_routed"
        assert skipped["jira"] == "severity_not_routed"
        assert len(slack_calls) == 1


class TestPartialFailure:
    async def test_one_adapter_5xx_does_not_block_others(self) -> None:
        slack, linear, jira = _wire_adapters(
            slack_handler=lambda _: httpx.Response(503),
            linear_handler=lambda _: httpx.Response(
                200, json={"data": {"issueCreate": {"success": True}}}
            ),
            jira_handler=lambda _: httpx.Response(201, json={"key": "SEC-1"}),
        )
        slack._retryer = type(slack._retryer)(  # type: ignore[attr-defined]
            max_attempts=1,
            base_seconds=0.0,
            factor=1.0,
            sleep=lambda *_: asyncio.sleep(0),
            rng=lambda: 1.0,
        )
        disp = _disp(slack=slack, linear=linear, jira=jira)
        try:
            results = await disp.dispatch(_make_event(event_id="evt-int-200"))
        finally:
            await disp.aclose()

        slack_result = next(r for r in results if r.adapter_name == "slack")
        linear_result = next(r for r in results if r.adapter_name == "linear")
        jira_result = next(r for r in results if r.adapter_name == "jira")
        assert slack_result.delivered is False
        assert slack_result.error_code == "http_5xx"
        assert linear_result.delivered is True
        assert jira_result.delivered is True

    async def test_unhandled_exception_in_one_adapter(self) -> None:
        def _slack_explodes(_: httpx.Request) -> httpx.Response:
            raise RuntimeError("intentional explosion")

        slack, linear, jira = _wire_adapters(
            slack_handler=_slack_explodes,
            linear_handler=lambda _: httpx.Response(
                200, json={"data": {"issueCreate": {"success": True}}}
            ),
            jira_handler=lambda _: httpx.Response(201, json={"key": "SEC-2"}),
        )
        slack._retryer = type(slack._retryer)(  # type: ignore[attr-defined]
            max_attempts=1,
            base_seconds=0.0,
            factor=1.0,
            sleep=lambda *_: asyncio.sleep(0),
            rng=lambda: 1.0,
        )
        disp = _disp(slack=slack, linear=linear, jira=jira)
        try:
            results = await disp.dispatch(_make_event(event_id="evt-int-201"))
        finally:
            await disp.aclose()

        slack_result = next(r for r in results if r.adapter_name == "slack")
        assert slack_result.delivered is False
        # The base class catches httpx.HTTPError; RuntimeError surfaces via
        # the dispatcher's gather() guard.  Either way: not delivered.
        assert slack_result.error_code in {
            "network_error",
            "unhandled_exception",
            "unknown_error",
        }
        assert next(r for r in results if r.adapter_name == "linear").delivered is True
        assert next(r for r in results if r.adapter_name == "jira").delivered is True


class TestDeduplicationAcrossAdapters:
    async def test_repeat_event_does_not_re_post(self) -> None:
        counts = {"slack": 0, "linear": 0, "jira": 0}

        slack, linear, jira = _wire_adapters(
            slack_handler=_count_handler(counts, "slack", lambda: httpx.Response(200)),
            linear_handler=_count_handler(
                counts,
                "linear",
                lambda: httpx.Response(
                    200, json={"data": {"issueCreate": {"success": True}}}
                ),
            ),
            jira_handler=_count_handler(
                counts, "jira", lambda: httpx.Response(201, json={"key": "SEC-3"})
            ),
        )
        disp = _disp(slack=slack, linear=linear, jira=jira)
        try:
            ev = _make_event(event_id="evt-int-300")
            await disp.dispatch(ev)
            await disp.dispatch(ev)
        finally:
            await disp.aclose()

        assert counts == {"slack": 1, "linear": 1, "jira": 1}


class TestPerTenantOptOut:
    async def test_disabled_adapter_for_tenant_skipped(self) -> None:
        counts = {"slack": 0, "linear": 0, "jira": 0}
        slack, linear, jira = _wire_adapters(
            slack_handler=_count_handler(counts, "slack", lambda: httpx.Response(200)),
            linear_handler=_count_handler(
                counts,
                "linear",
                lambda: httpx.Response(
                    200, json={"data": {"issueCreate": {"success": True}}}
                ),
            ),
            jira_handler=_count_handler(
                counts, "jira", lambda: httpx.Response(201, json={"key": "SEC-4"})
            ),
        )
        disp = NotificationDispatcher(
            adapters=[slack, linear, jira],
            enabled=True,
            per_tenant_disabled_adapters={
                "tenant-alpha": frozenset({"jira", "linear"})
            },
        )
        for name in ("slack", "linear", "jira"):
            disp.set_adapter_enabled(name, True)
        try:
            await disp.dispatch(_make_event(event_id="evt-int-400"))
        finally:
            await disp.aclose()
        assert counts == {"slack": 1, "linear": 0, "jira": 0}


class TestRetryAcrossAdapters:
    async def test_each_adapter_retries_independently(self) -> None:
        counts = {"slack": 0, "linear": 0, "jira": 0}

        def _slack(req: httpx.Request) -> httpx.Response:
            counts["slack"] += 1
            return httpx.Response(200) if counts["slack"] >= 2 else httpx.Response(503)

        def _linear(req: httpx.Request) -> httpx.Response:
            counts["linear"] += 1
            return (
                httpx.Response(200, json={"data": {"issueCreate": {"success": True}}})
                if counts["linear"] >= 3
                else httpx.Response(503)
            )

        def _jira(req: httpx.Request) -> httpx.Response:
            counts["jira"] += 1
            return httpx.Response(201, json={"key": "SEC-5"})

        slack, linear, jira = _wire_adapters(
            slack_handler=_slack,
            linear_handler=_linear,
            jira_handler=_jira,
        )
        disp = _disp(slack=slack, linear=linear, jira=jira)
        try:
            results = await disp.dispatch(_make_event(event_id="evt-int-500"))
        finally:
            await disp.aclose()

        slack_result = next(r for r in results if r.adapter_name == "slack")
        linear_result = next(r for r in results if r.adapter_name == "linear")
        jira_result = next(r for r in results if r.adapter_name == "jira")
        assert slack_result.attempts == 2 and slack_result.delivered
        assert linear_result.attempts == 3 and linear_result.delivered
        assert jira_result.attempts == 1 and jira_result.delivered


def _count_handler(
    counts: dict[str, int],
    name: str,
    response_factory: Callable[[], httpx.Response],
) -> Callable[[httpx.Request], httpx.Response]:
    def _handler(_req: httpx.Request) -> httpx.Response:
        counts[name] += 1
        return response_factory()

    return _handler
