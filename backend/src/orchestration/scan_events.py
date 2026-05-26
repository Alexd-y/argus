"""Real-time scan collaboration — WebSocket event publishing.

Publishes scan events (phase_start, phase_complete, finding, progress)
to a Redis/stream backend for real-time WebSocket delivery to clients.
Also supports team chat/annotations during active scans.

From Развитие2.md: real-time collaboration.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

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
        self._subscribers: list[Any] = []
        self._redis_client: Any = None
        try:
            import redis
            self._redis_client = redis.Redis.from_url("redis://localhost:6379/0")
            self._redis_client.ping()
            logger.info("Redis event bus connected")
        except Exception:
            logger.debug("Redis not available — using in-memory event bus")

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
        for sub in self._subscribers:
            try:
                sub(event)
            except Exception:
                pass

    def subscribe(self, callback: Any) -> None:
        self._subscribers.append(callback)

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