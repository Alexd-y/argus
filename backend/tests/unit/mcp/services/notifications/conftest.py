"""Shared fixtures for the notification adapter unit tests."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import datetime, timezone

import httpx
import pytest

from src.mcp.services.notifications.schemas import (
    NotificationEvent,
    NotificationSeverity,
)


def make_event(
    *,
    event_id: str = "evt-00000001",
    event_type: str = "approval.pending",
    severity: NotificationSeverity = NotificationSeverity.HIGH,
    tenant_id: str = "tenant-alpha",
    title: str = "Pending approval for sqlmap",
    summary: str = "An operator must decide on the queued sqlmap run.",
    scan_id: str | None = "scan-1234",
    finding_id: str | None = "finding-5678",
    approval_id: str | None = "approval-9012",
    root_cause_hash: str | None = "rch-deadbeef-0001",
    evidence_url: str | None = "https://argus.example/evidence/abc",
) -> NotificationEvent:
    return NotificationEvent(
        event_id=event_id,
        event_type=event_type,
        severity=severity,
        tenant_id=tenant_id,
        title=title,
        summary=summary,
        scan_id=scan_id,
        finding_id=finding_id,
        approval_id=approval_id,
        root_cause_hash=root_cause_hash,
        evidence_url=evidence_url,
        occurred_at=datetime(2026, 4, 19, 10, 0, tzinfo=timezone.utc),
        extra_tags=("cwe-89", "owasp-a03"),
    )


@pytest.fixture()
def event() -> NotificationEvent:
    return make_event()


@pytest.fixture()
def critical_event() -> NotificationEvent:
    return make_event(
        event_type="critical.finding.detected",
        severity=NotificationSeverity.CRITICAL,
        title="Critical RCE in /admin",
        summary="Authenticated RCE via deserialization in /admin/import.",
    )


@pytest.fixture()
def medium_event() -> NotificationEvent:
    return make_event(
        event_type="scan.completed",
        severity=NotificationSeverity.MEDIUM,
    )


@pytest.fixture()
def make_event_factory() -> Callable[..., NotificationEvent]:
    return make_event


def build_mock_client(
    handler: Callable[[httpx.Request], httpx.Response],
) -> httpx.AsyncClient:
    """Return an :class:`httpx.AsyncClient` whose transport is the given handler."""
    transport = httpx.MockTransport(handler)
    return httpx.AsyncClient(transport=transport, timeout=5.0)


@pytest.fixture()
def make_mock_client() -> Iterator[
    Callable[[Callable[[httpx.Request], httpx.Response]], httpx.AsyncClient]
]:
    """Yield a factory that builds httpx.AsyncClient on demand for tests."""
    clients: list[httpx.AsyncClient] = []

    def _factory(
        handler: Callable[[httpx.Request], httpx.Response],
    ) -> httpx.AsyncClient:
        client = build_mock_client(handler)
        clients.append(client)
        return client

    yield _factory

    import asyncio

    for client in clients:
        try:
            asyncio.get_event_loop().run_until_complete(client.aclose())
        except Exception:
            pass


def collect_responses(
    *responses: tuple[int, dict[str, object] | str | None],
) -> Callable[[httpx.Request], httpx.Response]:
    """Return a handler that yields ``responses`` in order, repeating the last."""
    sequence = list(responses)

    def _handler(_request: httpx.Request) -> httpx.Response:
        if len(sequence) > 1:
            status, body = sequence.pop(0)
        else:
            status, body = sequence[0]
        if body is None:
            return httpx.Response(status)
        if isinstance(body, str):
            return httpx.Response(status, text=body)
        return httpx.Response(status, json=body)

    return _handler
