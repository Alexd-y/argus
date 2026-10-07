"""P1 — message-queue backends: topic validation + offline publish/subscribe.

The repo's existing MQ tests require a live NATS/RabbitMQ broker and are skipped in
CI, so the NATS/RabbitMQ client logic was unexercised. These tests drive it fully
offline with injected fake ``nats`` / ``aio_pika`` modules, and assert the new
closed-topic validation.
"""

from __future__ import annotations

import sys
import types
from types import SimpleNamespace

import pytest
from src.integrations.message_queue import (
    NatsJetStreamBackend,
    RabbitMQBackend,
    _NoopBackend,
    get_message_queue,
)


# --------------------------------------------------------------------------- #
# Topic validation (closed set)
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_publish_rejects_unknown_topic() -> None:
    with pytest.raises(ValueError, match="unknown message-queue topic"):
        await NatsJetStreamBackend(url="nats://x").publish("evil.subject", {"a": 1})
    with pytest.raises(ValueError, match="unknown message-queue topic"):
        await RabbitMQBackend(url="amqp://x").subscribe("evil.subject", lambda _m: None)


# --------------------------------------------------------------------------- #
# Factory
# --------------------------------------------------------------------------- #
def test_factory_disabled_returns_noop() -> None:
    assert isinstance(get_message_queue(SimpleNamespace(message_queue_enabled=False)), _NoopBackend)


def test_factory_backend_selection() -> None:
    nats_be = get_message_queue(
        SimpleNamespace(message_queue_enabled=True, message_queue_backend="nats", nats_url="nats://h")
    )
    assert isinstance(nats_be, NatsJetStreamBackend)
    rmq = get_message_queue(
        SimpleNamespace(
            message_queue_enabled=True, message_queue_backend="rabbitmq", rabbitmq_url="amqp://h"
        )
    )
    assert isinstance(rmq, RabbitMQBackend)
    assert isinstance(
        get_message_queue(SimpleNamespace(message_queue_enabled=True, message_queue_backend="bogus")),
        _NoopBackend,
    )


# --------------------------------------------------------------------------- #
# NATS client logic (fake nats module)
# --------------------------------------------------------------------------- #
class _FakeJS:
    def __init__(self) -> None:
        self.published: list = []
        self.subs: list = []

    async def publish(self, subject, data) -> None:
        self.published.append((subject, data))

    async def subscribe(self, subject, cb=None):
        self.subs.append(subject)
        return object()


class _FakeNC:
    def __init__(self, js) -> None:
        self._js = js
        self.drained = False

    def jetstream(self):
        return self._js

    async def drain(self) -> None:
        self.drained = True


@pytest.mark.asyncio
async def test_nats_connect_publish_subscribe(monkeypatch) -> None:
    js = _FakeJS()
    nc = _FakeNC(js)
    fake = types.ModuleType("nats")

    async def _connect(url, **_kw):  # noqa: ARG001
        return nc

    fake.connect = _connect  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "nats", fake)

    be = NatsJetStreamBackend(url="nats://x")
    await be.connect()
    await be.publish("scan.events", {"a": 1})
    await be.subscribe("finding.alerts", lambda _m: None)
    await be.disconnect()

    assert js.published and js.published[0][0] == "scan.events"
    assert b'"a": 1' in js.published[0][1]
    assert "finding.alerts" in js.subs
    assert nc.drained is True


# --------------------------------------------------------------------------- #
# RabbitMQ client logic (fake aio_pika module)
# --------------------------------------------------------------------------- #
class _FakeExchange:
    def __init__(self) -> None:
        self.published: list = []

    async def publish(self, message, routing_key=None) -> None:
        self.published.append((routing_key, message.body))


class _FakeQueue:
    def __init__(self) -> None:
        self.bound = None
        self.consumer = None

    async def bind(self, _ex, routing_key=None) -> None:
        self.bound = routing_key

    async def consume(self, cb) -> None:
        self.consumer = cb


class _FakeChannel:
    def __init__(self, ex) -> None:
        self._ex = ex
        self.queue = _FakeQueue()

    async def declare_exchange(self, _name, _type, durable=True):  # noqa: ARG002
        return self._ex

    async def declare_queue(self, name="", exclusive=True, auto_delete=True):  # noqa: ARG002
        return self.queue


class _FakeConn:
    def __init__(self, ch) -> None:
        self._ch = ch
        self.closed = False

    async def channel(self):
        return self._ch

    async def close(self) -> None:
        self.closed = True


def _fake_aio_pika(conn) -> types.ModuleType:
    mod = types.ModuleType("aio_pika")

    async def _connect_robust(_url):
        return conn

    class _Msg:
        def __init__(self, body, content_type=None, delivery_mode=None) -> None:
            self.body = body
            self.content_type = content_type
            self.delivery_mode = delivery_mode

    mod.connect_robust = _connect_robust  # type: ignore[attr-defined]
    mod.Message = _Msg  # type: ignore[attr-defined]
    mod.ExchangeType = SimpleNamespace(TOPIC="topic")  # type: ignore[attr-defined]
    mod.DeliveryMode = SimpleNamespace(PERSISTENT=2)  # type: ignore[attr-defined]
    return mod


@pytest.mark.asyncio
async def test_rabbitmq_connect_publish_subscribe(monkeypatch) -> None:
    ex = _FakeExchange()
    ch = _FakeChannel(ex)
    conn = _FakeConn(ch)
    monkeypatch.setitem(sys.modules, "aio_pika", _fake_aio_pika(conn))

    be = RabbitMQBackend(url="amqp://x")
    await be.connect()
    await be.publish("report.generated", {"id": "r1"})
    await be.subscribe("scan.events", lambda _b: None)
    await be.disconnect()

    assert ex.published and ex.published[0][0] == "report.generated"
    assert b'"id": "r1"' in ex.published[0][1]
    assert ch.queue.bound == "scan.events"
    assert ch.queue.consumer is not None
    assert conn.closed is True
