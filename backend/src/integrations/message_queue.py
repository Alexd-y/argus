"""ARGUS — optional message queue integration (NATS JetStream / RabbitMQ).

Feature flag: ``MESSAGE_QUEUE_ENABLED`` (default False).
Backend selection: ``MESSAGE_QUEUE_BACKEND`` (nats|rabbitmq|none, default none).

Topics:
  - ``scan.events``       — scan lifecycle events (started, completed, failed)
  - ``finding.alerts``    — new / updated findings
  - ``report.generated``  — report ready for download
"""

import json
import logging
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger("src.integrations.message_queue")


class MessageQueueBackend(ABC):
    """Async publish/subscribe abstraction for message queues."""

    @abstractmethod
    async def connect(self) -> None: ...

    @abstractmethod
    async def disconnect(self) -> None: ...

    @abstractmethod
    async def publish(self, topic: str, payload: dict[str, Any]) -> None: ...

    @abstractmethod
    async def subscribe(
        self, topic: str, handler: Any
    ) -> None: ...


class _NoopBackend(MessageQueueBackend):
    """No-op stub returned when MESSAGE_QUEUE_ENABLED=False or backend=none."""

    async def connect(self) -> None:
        pass

    async def disconnect(self) -> None:
        pass

    async def publish(self, topic: str, payload: dict[str, Any]) -> None:
        pass

    async def subscribe(self, topic: str, handler: Any) -> None:
        pass


class NatsJetStreamBackend(MessageQueueBackend):
    """NATS JetStream backend via nats-py."""

    def __init__(self, url: str, creds: str | None = None) -> None:
        self._url = url
        self._creds = creds
        self._nc: Any = None
        self._js: Any = None
        self._subscriptions: list[Any] = []

    async def connect(self) -> None:
        try:
            import nats  # type: ignore[import-untyped]

            opts: dict[str, Any] = {}
            if self._creds:
                opts["user_credentials"] = self._creds

            self._nc = await nats.connect(self._url, **opts)
            self._js = self._nc.jetstream()
            logger.info(
                "nats_connected", extra={"url": self._url}
            )
        except ImportError:
            logger.error("nats_py_not_installed — pip install nats-py")
            raise
        except Exception:
            logger.exception("nats_connect_failed", extra={"url": self._url})
            raise

    async def disconnect(self) -> None:
        if self._nc is not None:
            await self._nc.drain()
            logger.info("nats_disconnected")

    async def publish(self, topic: str, payload: dict[str, Any]) -> None:
        if self._js is None:
            raise RuntimeError("Not connected — call connect() first")
        data = json.dumps(payload, default=str).encode()
        await self._js.publish(topic, data)
        logger.debug("nats_published", extra={"topic": topic})

    async def subscribe(self, topic: str, handler: Any) -> None:
        if self._js is None:
            raise RuntimeError("Not connected — call connect() first")
        sub = await self._js.subscribe(topic, cb=handler)
        self._subscriptions.append(sub)
        logger.info("nats_subscribed", extra={"topic": topic})


class RabbitMQBackend(MessageQueueBackend):
    """RabbitMQ backend via aio-pika."""

    def __init__(self, url: str) -> None:
        self._url = url
        self._connection: Any = None
        self._channel: Any = None
        self._exchange: Any = None

    async def connect(self) -> None:
        try:
            import aio_pika  # type: ignore[import-untyped]

            self._connection = await aio_pika.connect_robust(self._url)
            self._channel = await self._connection.channel()
            self._exchange = await self._channel.declare_exchange(
                "argus", aio_pika.ExchangeType.TOPIC, durable=True
            )
            logger.info(
                "rabbitmq_connected", extra={"url": self._url}
            )
        except ImportError:
            logger.error("aio_pika_not_installed — pip install aio-pika")
            raise
        except Exception:
            logger.exception(
                "rabbitmq_connect_failed", extra={"url": self._url}
            )
            raise

    async def disconnect(self) -> None:
        if self._connection is not None:
            await self._connection.close()
            logger.info("rabbitmq_disconnected")

    async def publish(self, topic: str, payload: dict[str, Any]) -> None:
        if self._exchange is None:
            raise RuntimeError("Not connected — call connect() first")
        import aio_pika  # type: ignore[import-untyped]

        body = json.dumps(payload, default=str).encode()
        message = aio_pika.Message(
            body,
            content_type="application/json",
            delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
        )
        await self._exchange.publish(message, routing_key=topic)
        logger.debug("rabbitmq_published", extra={"topic": topic})

    async def subscribe(self, topic: str, handler: Any) -> None:
        if self._channel is None:
            raise RuntimeError("Not connected — call connect() first")
        queue = await self._channel.declare_queue(
            name="", exclusive=True, auto_delete=True
        )
        await queue.bind(self._exchange, routing_key=topic)

        async def _wrap(message: Any) -> None:
            async with message.process():
                await handler(message.body)

        await queue.consume(_wrap)
        logger.info("rabbitmq_subscribed", extra={"topic": topic})


VALID_TOPICS = frozenset({"scan.events", "finding.alerts", "report.generated"})
VALID_MESSAGE_QUEUE_BACKENDS = frozenset({"nats", "rabbitmq", "none"})


def get_message_queue(settings: Any) -> MessageQueueBackend:
    """Factory: return the configured message queue backend or a no-op stub."""
    if not getattr(settings, "message_queue_enabled", False):
        return _NoopBackend()

    backend: str = str(getattr(settings, "message_queue_backend", "none") or "none").strip().lower()
    if backend not in VALID_MESSAGE_QUEUE_BACKENDS:
        logger.warning(
            "message_queue_backend_invalid",
            extra={"backend": backend, "valid": sorted(VALID_MESSAGE_QUEUE_BACKENDS)},
        )
        return _NoopBackend()

    if backend == "none":
        return _NoopBackend()

    if backend == "nats":
        nats_url = str(getattr(settings, "nats_url", "") or "nats://localhost:4222")
        nats_creds = getattr(settings, "nats_creds", None) or None
        return NatsJetStreamBackend(url=nats_url, creds=nats_creds)

    if backend == "rabbitmq":
        rabbitmq_url = str(getattr(settings, "rabbitmq_url", "") or "amqp://guest:guest@localhost:5672/")
        return RabbitMQBackend(url=rabbitmq_url)

    return _NoopBackend()
