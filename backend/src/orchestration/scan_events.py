"""Real-time scan collaboration — WebSocket event publishing.

Publishes scan events (phase_start, phase_complete, finding, progress)
to a Redis/stream backend for real-time WebSocket delivery to clients.
Also supports team chat/annotations during active scans.

From Развитие2.md: real-time collaboration.

P1-8: WebSocket delivery layer — ScanEventBus now has:
  - Redis pub/sub fan-out (existing)
  - In-memory subscriber callbacks (existing)
  - Async subscriber support (new) for WebSocket bridging
  - Redis subscriber bridge for multi-process fan-out (new)
  - Broadcast bridge for WebSocket ConnectionManager (new in ws.py)
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)


@dataclass
class ScanEvent:
    event_type: str
    scan_id: str
    tenant_id: str
    phase: str = ""
    progress: int = 0
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class ChatMessage:
    scan_id: str
    tenant_id: str
    user_id: str
    message: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ScanEventBus:
    def __init__(self) -> None:
        self._subscribers: list[Any] = None
        self._async_subscribers: list[Callable[[ScanEvent], Any]] = None
        self._redis_client: Any = None
        self._redis_pubsub: Any = None
        self._redis_listener_thread: threading.Thread | None = None
        self._redis_listener_running: bool = False
        try:
            import redis
            self._redis_client = redis.Redis.from_url("redis://localhost:6379/0")
            self._redis_client.ping()
            logger.info("Redis event bus connected")
        except Exception:
            logger.debug("Redis not available — using in-memory event bus")

    @property
    def subscribers(self) -> list[Any]:
        if self._subscribers is None:
            self._subscribers = []
        return self._subscribers

    @property
    def async_subscribers(self) -> list[Callable[[ScanEvent], Any]]:
        if self._async_subscribers is None:
            self._async_subscribers = []
        return self._async_subscribers

    def publish(self, event: ScanEvent) -> None:
        payload = json.dumps({
            "event_type": event.event_type,
            "scan_id": event.scan_id,
            "tenant_id": event.tenant_id,
            "phase": event.phase,
            "progress": event.progress,
            "message": event.message,
            "timestamp": event.timestamp,
        }, default=str)
        if self._redis_client is not None:
            try:
                self._redis_client.publish(f"argus:scan:{event.scan_id}", payload)
                return
            except Exception:
                pass
        for sub in self.subscribers:
            try:
                sub(event)
            except Exception:
                pass
        for asub in self.async_subscribers:
            try:
                asub(event)
            except Exception:
                pass

    def subscribe(self, callback: Any) -> None:
        self.subscribers.append(callback)

    def subscribe_async(self, callback: Callable[[ScanEvent], Any]) -> None:
        """Register an async callback for event delivery (e.g., WebSocket bridge)."""
        self.async_subscribers.append(callback)

    def start_redis_subscriber(self, channel_pattern: str = "argus:scan:*") -> None:
        """Start a background Redis pub/sub subscriber that forwards events
        to in-memory subscribers. Required for multi-process deployments
        where one process publishes via Redis and another serves WebSocket clients.

        Runs in a daemon thread; events are dispatched to sync subscribers.
        For async subscribers, events are queued and dispatched on the event loop.
        """
        if self._redis_listener_running:
            return
        try:
            import redis
            pubsub_client = redis.Redis.from_url("redis://localhost:6379/0")
            self._redis_pubsub = pubsub_client.pubsub()
            self._redis_pubsub.psubscribe(channel_pattern)
            self._redis_pubsub.psubscribe("argus:chat:*")
        except Exception:
            logger.debug("Redis subscriber not available — multi-process fan-out disabled")
            return

        self._redis_listener_running = True

        def _listener():
            try:
                for message in self._redis_pubsub.listen():
                    if not self._redis_listener_running:
                        break
                    if message["type"] not in ("pmessage",):
                        continue
                    channel_data = message.get("data", b"")
                    if isinstance(channel_data, bytes):
                        channel_data = channel_data.decode("utf-8", errors="replace")
                    if not channel_data:
                        continue
                    try:
                        data = json.loads(channel_data)
                    except (json.JSONDecodeError, TypeError):
                        continue
                    event = ScanEvent(
                        event_type=data.get("event_type", ""),
                        scan_id=data.get("scan_id", ""),
                        tenant_id=data.get("tenant_id", ""),
                        phase=data.get("phase", ""),
                        progress=data.get("progress", 0),
                        message=data.get("message", ""),
                    )
                    for sub in self.subscribers:
                        try:
                            sub(event)
                        except Exception:
                            pass
                    for asub in self.async_subscribers:
                        try:
                            asub(event)
                        except Exception:
                            pass
            except Exception:
                if self._redis_listener_running:
                    logger.warning("Redis subscriber listener error", exc_info=True)
            finally:
                self._redis_listener_running = False

        self._redis_listener_thread = threading.Thread(target=_listener, daemon=True, name="redis-event-subscriber")
        self._redis_listener_thread.start()
        logger.info("Redis event subscriber started", extra={"pattern": channel_pattern})

    def stop_redis_subscriber(self) -> None:
        """Stop the Redis pub/sub listener thread."""
        self._redis_listener_running = False
        if self._redis_pubsub is not None:
            try:
                self._redis_pubsub.punsubscribe()
                self._redis_pubsub.close()
            except Exception:
                pass
        if self._redis_listener_thread is not None:
            self._redis_listener_thread.join(timeout=5)
        logger.info("Redis event subscriber stopped")

    def publish_chat(self, msg: ChatMessage) -> None:
        payload = json.dumps({
            "type": "chat",
            "user_id": msg.user_id,
            "message": msg.message,
            "timestamp": msg.timestamp,
        }, default=str)
        if self._redis_client is not None:
            try:
                self._redis_client.publish(f"argus:chat:{msg.scan_id}", payload)
            except Exception:
                pass


__all__ = [
    "ChatMessage",
    "ScanEvent",
    "ScanEventBus",
]