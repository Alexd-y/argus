"""Unit tests for :class:`SlackNotifier` (ARG-035)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from src.mcp.services.notifications import (
    AdapterResult,
    NotificationSeverity,
    SLACK_WEBHOOK_URL_ENV,
    SlackNotifier,
    build_slack_payload,
)
from src.mcp.services.notifications._base import (
    DEFAULT_BACKOFF_BASE_SECONDS,
    CircuitBreaker,
)
from tests.unit.mcp.services.notifications.conftest import (
    collect_responses,
    make_event,
)


def _slack(
    *,
    handler: Callable[[httpx.Request], httpx.Response],
    webhook_url: str = "https://hooks.slack.example/T0/B0/secret",
    breaker: CircuitBreaker | None = None,
    max_attempts: int = 3,
) -> SlackNotifier:
    transport = httpx.MockTransport(handler)
    return SlackNotifier(
        webhook_url=webhook_url,
        client=httpx.AsyncClient(transport=transport, timeout=5.0),
        circuit_breaker=breaker,
        max_attempts=max_attempts,
        backoff_base_seconds=0.0,
        backoff_factor=1.0,
        sleep=_NoopSleep(),
        rng=lambda: 1.0,
    )


class _NoopSleep:
    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.calls.append(delay)


class TestSlackPayload:
    def test_header_uses_severity_emoji(self) -> None:
        ev = make_event(severity=NotificationSeverity.CRITICAL)
        body = build_slack_payload(ev)
        assert body["blocks"][0]["text"]["text"].startswith(":rotating_light:")

    def test_summary_block_present(self) -> None:
        ev = make_event(summary="Detailed summary text")
        body = build_slack_payload(ev)
        assert any(
            blk.get("type") == "section"
            and blk.get("text", {}).get("text") == "Detailed summary text"
            for blk in body["blocks"]
        )

    def test_context_carries_tenant_and_severity(self) -> None:
        ev = make_event()
        body = build_slack_payload(ev)
        ctx = next(blk for blk in body["blocks"] if blk["type"] == "context")
        assert any("Tenant:" in el["text"] for el in ctx["elements"])
        assert any("Severity:" in el["text"] for el in ctx["elements"])
        assert any("Event:" in el["text"] for el in ctx["elements"])

    def test_evidence_link_added_when_present(self) -> None:
        ev = make_event(evidence_url="https://example.com/evidence/1")
        body = build_slack_payload(ev)
        assert any(
            "View evidence" in str(blk.get("text", {}).get("text", ""))
            for blk in body["blocks"]
        )

    def test_evidence_link_omitted_when_absent(self) -> None:
        ev = make_event(evidence_url=None)
        body = build_slack_payload(ev)
        assert not any(
            "View evidence" in str(blk.get("text", {}).get("text", ""))
            for blk in body["blocks"]
        )

    def test_approval_event_includes_action_buttons(self) -> None:
        ev = make_event(event_type="approval.pending", approval_id="ap-1")
        body = build_slack_payload(ev)
        actions = next(blk for blk in body["blocks"] if blk["type"] == "actions")
        action_ids = [el["action_id"] for el in actions["elements"]]
        assert "approve::ap-1" in action_ids
        assert "deny::ap-1" in action_ids

    def test_non_approval_has_no_action_buttons(self) -> None:
        ev = make_event(
            event_type="scan.completed",
            approval_id=None,
            severity=NotificationSeverity.MEDIUM,
        )
        body = build_slack_payload(ev)
        assert not any(blk["type"] == "actions" for blk in body["blocks"])

    def test_text_fallback_within_slack_limit(self) -> None:
        ev = make_event(title="A" * 290)
        body = build_slack_payload(ev)
        assert len(body["text"]) <= 1_000

    def test_summary_truncated_to_block_limit(self) -> None:
        ev = make_event(summary="B" * 2_000)
        body = build_slack_payload(ev)
        section = next(
            blk
            for blk in body["blocks"]
            if blk.get("type") == "section" and "text" in blk
        )
        assert len(section["text"]["text"]) <= 2_900


class TestSlackHappyPath:
    def test_delivered_returns_true_with_status_2xx(self) -> None:
        slack = _slack(handler=collect_responses((200, {"ok": True})))
        ev = make_event()
        result = asyncio.run(slack.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert isinstance(result, AdapterResult)
        assert result.delivered is True
        assert result.status_code == 200
        assert result.attempts == 1
        assert result.adapter_name == "slack"
        assert len(result.target_redacted) == 12

    def test_target_redacted_is_hash(self) -> None:
        slack = _slack(handler=collect_responses((200, None)))
        ev = make_event()
        result = asyncio.run(slack.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert all(c in "0123456789abcdef" for c in result.target_redacted)


class TestSlackRetry:
    def test_retries_on_5xx_then_succeeds(self) -> None:
        responses = collect_responses(
            (500, None),
            (502, None),
            (200, {"ok": True}),
        )
        slack = _slack(handler=responses)
        ev = make_event()
        result = asyncio.run(slack.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert result.delivered is True
        assert result.attempts == 3

    def test_retries_exhausted_returns_5xx_failure(self) -> None:
        slack = _slack(handler=collect_responses((503, None)))
        ev = make_event()
        result = asyncio.run(slack.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert result.delivered is False
        assert result.attempts == 3
        assert result.error_code == "http_5xx"
        assert result.status_code == 503

    def test_4xx_does_not_retry(self) -> None:
        slack = _slack(handler=collect_responses((400, None)))
        ev = make_event()
        result = asyncio.run(slack.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert result.attempts == 1
        assert result.error_code == "http_4xx"
        assert result.delivered is False

    def test_429_is_retried(self) -> None:
        slack = _slack(
            handler=collect_responses(
                (429, None),
                (429, None),
                (200, None),
            )
        )
        ev = make_event()
        result = asyncio.run(slack.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert result.delivered is True
        assert result.attempts == 3

    def test_network_error_is_retried(self) -> None:
        attempts = {"n": 0}

        def _handler(_req: httpx.Request) -> httpx.Response:
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise httpx.ConnectError("network down")
            return httpx.Response(200)

        slack = _slack(handler=_handler)
        ev = make_event()
        result = asyncio.run(slack.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert result.delivered is True
        assert result.attempts == 3

    def test_timeout_classified_as_timeout(self) -> None:
        def _handler(_req: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout("timeout")

        slack = _slack(handler=_handler)
        ev = make_event()
        result = asyncio.run(slack.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert result.error_code == "timeout"
        assert result.delivered is False


class TestSlackCircuitBreaker:
    def test_opens_after_threshold_failures(self) -> None:
        breaker = CircuitBreaker(failure_threshold=2, cooldown_seconds=60)
        slack = _slack(
            handler=collect_responses((500, None)),
            breaker=breaker,
            max_attempts=1,
        )
        ev = make_event()
        for _ in range(2):
            asyncio.run(slack.send_with_retry(ev, tenant_id=ev.tenant_id))
        snap = breaker.snapshot(adapter_name="slack", tenant_id=ev.tenant_id)
        assert snap is not None
        assert snap.failure_count >= 2
        assert snap.opened_at is not None

    def test_open_breaker_short_circuits_with_skipped_reason(self) -> None:
        breaker = CircuitBreaker(failure_threshold=1, cooldown_seconds=60)
        slack = _slack(
            handler=collect_responses((500, None)),
            breaker=breaker,
            max_attempts=1,
        )
        ev = make_event()
        asyncio.run(slack.send_with_retry(ev, tenant_id=ev.tenant_id))
        result = asyncio.run(slack.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert result.delivered is False
        assert result.skipped_reason == "circuit_open"
        assert result.error_code == "circuit_open"

    def test_success_resets_breaker(self) -> None:
        breaker = CircuitBreaker(failure_threshold=2, cooldown_seconds=60)
        responses = collect_responses(
            (500, None),
            (200, None),
        )
        slack = _slack(
            handler=responses,
            breaker=breaker,
            max_attempts=1,
        )
        ev = make_event()
        asyncio.run(slack.send_with_retry(ev, tenant_id=ev.tenant_id))
        ev2 = make_event(event_id="evt-00000002")
        result = asyncio.run(slack.send_with_retry(ev2, tenant_id=ev.tenant_id))
        assert result.delivered is True
        snap = breaker.snapshot(adapter_name="slack", tenant_id=ev.tenant_id)
        assert snap is None


class TestSlackIdempotency:
    def test_same_event_id_short_circuits(self) -> None:
        slack = _slack(handler=collect_responses((200, None)))
        ev = make_event()
        first = asyncio.run(slack.send_with_retry(ev, tenant_id=ev.tenant_id))
        second = asyncio.run(slack.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert first.delivered is True
        assert second.delivered is False
        assert second.skipped_reason == "idempotent_duplicate"
        assert second.duplicate_of == ev.event_id


class TestSlackDisabled:
    def test_missing_url_skips_with_reason(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(SLACK_WEBHOOK_URL_ENV, raising=False)
        slack = SlackNotifier(
            webhook_url=None,
            backoff_base_seconds=0.0,
            sleep=_NoopSleep(),
            rng=lambda: 1.0,
        )
        ev = make_event()
        result = asyncio.run(slack.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert result.delivered is False
        assert result.skipped_reason == "missing_secret"
        assert result.attempts == 0


class TestSlackSecretHygiene:
    def test_target_redacted_does_not_contain_url(self) -> None:
        slack = _slack(handler=collect_responses((200, None)))
        ev = make_event()
        result = asyncio.run(slack.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert "secret" not in result.target_redacted
        assert "hooks.slack" not in result.target_redacted
        for value in result.model_dump().values():
            assert "secret" not in str(value).lower() or value == result.skipped_reason

    def test_payload_does_not_carry_authorization_header(self) -> None:
        captured: dict[str, Any] = {}

        def _handler(req: httpx.Request) -> httpx.Response:
            captured["headers"] = dict(req.headers)
            return httpx.Response(200)

        slack = _slack(handler=_handler)
        ev = make_event()
        asyncio.run(slack.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert "authorization" not in {k.lower() for k in captured["headers"].keys()}


class TestSlackBackoffSchedule:
    def test_sleeps_between_retries(self) -> None:
        sleep = _NoopSleep()
        slack = SlackNotifier(
            webhook_url="https://hooks.slack.example/T0/B0/secret",
            client=httpx.AsyncClient(
                transport=httpx.MockTransport(collect_responses((500, None))),
                timeout=5.0,
            ),
            backoff_base_seconds=DEFAULT_BACKOFF_BASE_SECONDS,
            backoff_factor=4.0,
            sleep=sleep,
            rng=lambda: 1.0,
            max_attempts=3,
        )
        ev = make_event()
        asyncio.run(slack.send_with_retry(ev, tenant_id=ev.tenant_id))
        assert sleep.calls == [pytest.approx(1.0), pytest.approx(4.0)]
