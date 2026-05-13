"""Integration tests for the message queue abstraction layer.

Requires live NATS or RabbitMQ instances. Skipped by default.
"""

import pytest

from src.integrations.message_queue import (
    VALID_TOPICS,
    RabbitMQBackend,
    NatsJetStreamBackend,
    _NoopBackend,
    get_message_queue,
)


class FakeSettings:
    message_queue_enabled = False
    message_queue_backend = "none"
    nats_url = "nats://localhost:4222"
    rabbitmq_url = "amqp://guest:guest@localhost:5672/"


def test_factory_returns_noop_when_disabled() -> None:
    backend = get_message_queue(FakeSettings())
    assert isinstance(backend, _NoopBackend)


def test_factory_returns_noop_when_backend_none() -> None:
    enabled = FakeSettings()
    enabled.message_queue_enabled = True
    enabled.message_queue_backend = "none"
    backend = get_message_queue(enabled)
    assert isinstance(backend, _NoopBackend)


def test_factory_returns_noop_for_invalid_backend() -> None:
    enabled = FakeSettings()
    enabled.message_queue_enabled = True
    enabled.message_queue_backend = "kafka"
    backend = get_message_queue(enabled)
    assert isinstance(backend, _NoopBackend)


def test_factory_returns_nats_backend_when_enabled() -> None:
    enabled = FakeSettings()
    enabled.message_queue_enabled = True
    enabled.message_queue_backend = "nats"
    enabled.nats_url = "nats://localhost:4222"
    backend = get_message_queue(enabled)
    assert isinstance(backend, NatsJetStreamBackend)


def test_factory_returns_rabbitmq_backend_when_enabled() -> None:
    enabled = FakeSettings()
    enabled.message_queue_enabled = True
    enabled.message_queue_backend = "rabbitmq"
    enabled.rabbitmq_url = "amqp://guest:guest@localhost:5672/"
    backend = get_message_queue(enabled)
    assert isinstance(backend, RabbitMQBackend)


def test_valid_topics_include_scan_events() -> None:
    assert "scan.events" in VALID_TOPICS


def test_valid_topics_include_finding_alerts() -> None:
    assert "finding.alerts" in VALID_TOPICS


def test_valid_topics_include_report_generated() -> None:
    assert "report.generated" in VALID_TOPICS


def test_valid_topics_count_is_three() -> None:
    assert len(VALID_TOPICS) == 3


@pytest.mark.skip(reason="requires live NATS/RabbitMQ")
def test_nats_connect_disconnect(nats_backend: NatsJetStreamBackend) -> None:
    """Smoke test: connect to live NATS and disconnect cleanly."""
    import asyncio

    async def _run() -> None:
        await nats_backend.connect()
        assert nats_backend._nc is not None
        await nats_backend.disconnect()

    asyncio.run(_run())


@pytest.mark.skip(reason="requires live NATS/RabbitMQ")
def test_rabbitmq_connect_disconnect(rabbitmq_backend: RabbitMQBackend) -> None:
    """Smoke test: connect to live RabbitMQ and disconnect cleanly."""
    import asyncio

    async def _run() -> None:
        await rabbitmq_backend.connect()
        assert rabbitmq_backend._connection is not None
        await rabbitmq_backend.disconnect()

    asyncio.run(_run())


@pytest.mark.skip(reason="requires live NATS/RabbitMQ")
def test_nats_publish_subscribe(nats_backend: NatsJetStreamBackend) -> None:
    """Round-trip: publish to NATS and verify a subscriber receives it."""
    import asyncio

    received: list[dict[str, object]] = []

    async def _handler(msg: object) -> None:
        import json

        received.append(json.loads(msg.data.decode()))  # type: ignore[union-attr]

    async def _run() -> None:
        await nats_backend.connect()
        await nats_backend.subscribe("scan.events", _handler)
        await nats_backend.publish("scan.events", {"event": "scan.started"})
        await asyncio.sleep(0.5)
        assert len(received) == 1
        assert received[0]["event"] == "scan.started"
        await nats_backend.disconnect()

    asyncio.run(_run())


@pytest.mark.skip(reason="requires live NATS/RabbitMQ")
def test_rabbitmq_publish_subscribe(rabbitmq_backend: RabbitMQBackend) -> None:
    """Round-trip: publish to RabbitMQ and verify a subscriber receives it."""
    import asyncio

    received: list[dict[str, object]] = []

    async def _handler(body: bytes) -> None:
        import json

        received.append(json.loads(body.decode()))

    async def _run() -> None:
        await rabbitmq_backend.connect()
        await rabbitmq_backend.subscribe("finding.alerts", _handler)
        await rabbitmq_backend.publish("finding.alerts", {"severity": "critical"})
        await asyncio.sleep(1.0)
        assert len(received) == 1
        assert received[0]["severity"] == "critical"
        await rabbitmq_backend.disconnect()

    asyncio.run(_run())
