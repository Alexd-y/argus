"""WebSocket delivery layer for real-time scan events and collaboration.

Provides bidirectional WebSocket endpoints alongside the existing SSE stream.
Clients connect to:
  ws://{host}/api/v1/ws/scans/{scan_id}/events   — scan event stream
  ws://{host}/api/v1/ws/scans/{scan_id}/chat       — team chat/annotations

The events endpoint mirrors the SSE payload format from ``_build_sse_payload()``
but delivers via WebSocket frames. The chat endpoint allows real-time
collaboration messages using ``ChatMessage`` from ``scan_events``.

Architecture:
  ScanEventBus (publish) → Redis pub/sub → PubSubBridge → WebSocket connections
  ScanEventBus (publish) → in-memory subscribers → WebSocket connections

No external dependencies beyond ``websockets`` (optional, for client testing).
Server-side uses FastAPI's built-in ``WebSocket`` support (Starlette).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status

from src.core.config import settings
from src.core.tenant import get_current_tenant_id
from src.db.session import async_session_factory, set_session_tenant
from src.orchestration.scan_events import ScanEvent, ScanEventBus

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ws", tags=["websocket"])

_WS_PING_INTERVAL_SEC = 15
_WS_POLL_INTERVAL_SEC = 1.5
_WS_MAX_WAIT_SEC = 30 * 60
_WS_MAX_MESSAGES_DEFAULT = 10000


class _ConnectionManager:
    """Manages active WebSocket connections per scan_id.

    Thread-safe for single-process deployments. For multi-process,
    Redis pub/sub fan-out in ScanEventBus handles cross-process delivery.
    """

    def __init__(self) -> None:
        self._connections: dict[str, list[WebSocket]] = {}

    def connect(self, scan_id: str, ws: WebSocket) -> None:
        self._connections.setdefault(scan_id, []).append(ws)

    def disconnect(self, scan_id: str, ws: WebSocket) -> None:
        conns = self._connections.get(scan_id)
        if conns:
            try:
                conns.remove(ws)
            except ValueError:
                pass
            if not conns:
                del self._connections[scan_id]

    async def broadcast(self, scan_id: str, payload: dict[str, Any]) -> None:
        conns = list(self._connections.get(scan_id, []))
        dead: list[WebSocket] = []
        for ws in conns:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(scan_id, ws)

    def active_count(self, scan_id: str | None = None) -> int:
        if scan_id:
            return len(self._connections.get(scan_id, []))
        return sum(len(v) for v in self._connections.values())


_manager = _ConnectionManager()


def _filter_ws_output_data(event: str, data: dict[str, Any] | None) -> dict[str, Any] | None:
    """Filter sensitive fields from phase_complete events (mirrors SSE filter)."""
    if event == "phase_complete" and data:
        allowed = {"phase", "progress", "duration_sec", "severity_counts"}
        return {k: v for k, v in data.items() if k in allowed}
    return data


def _build_ws_payload(ev: Any) -> dict[str, Any]:
    """Build WebSocket payload from a ScanEvent DB row.

    Mirrors ``_build_sse_payload()`` from scans.py — same structure,
    same field filtering (ARGUS-010).
    """
    payload: dict[str, Any] = {"event": ev.event}
    if getattr(ev, "phase", None) is not None:
        payload["phase"] = ev.phase
    if getattr(ev, "progress", None) is not None:
        payload["progress"] = ev.progress
    if getattr(ev, "message", None):
        payload["message"] = ev.message
    if ev.event == "error":
        payload["error"] = ev.message or (
            ev.data.get("error") if ev.data else None
        ) or "Unknown error"
    filtered_data = _filter_ws_output_data(ev.event, ev.data)
    if filtered_data:
        payload["data"] = filtered_data
    return payload


async def _scan_event_stream(
    ws: WebSocket,
    scan_id: str,
    tenant_id: str,
) -> None:
    """Main event loop for the scan events WebSocket.

    Polls DB for new events (same approach as SSE), deduplicates by
    event ID, and sends JSON frames. Also listens for Redis pub/sub
    events via ScanEventBus if available.

    Receives pings from client; sends pongs. Client can send
    ``{"type": "ping"}`` to keep connection alive.
    """
    from sqlalchemy import String, cast, select
    from src.db.models import Scan, ScanEvent

    seen_ids: set[str] = set()
    started_at = time.monotonic()
    last_keepalive = started_at

    bus: ScanEventBus | None = None
    bus_queue: asyncio.Queue[dict[str, Any]] | None = None

    try:
        bus = ScanEventBus()
        if bus._redis_client is not None:
            bus_queue = asyncio.Queue(maxsize=1000)

            def _on_bus_event(event: ScanEvent) -> None:
                if event.scan_id == scan_id:
                    payload = {
                        "event_type": event.event_type,
                        "scan_id": event.scan_id,
                        "tenant_id": event.tenant_id,
                        "phase": event.phase,
                        "progress": event.progress,
                        "message": event.message,
                        "timestamp": event.timestamp,
                    }
                    try:
                        bus_queue.put_nowait(payload)
                    except asyncio.QueueFull:
                        pass

            bus.subscribe(_on_bus_event)
    except Exception:
        logger.debug("ws_scan_events_bus_unavailable", extra={"scan_id": scan_id})

    try:
        while True:
            now = time.monotonic()

            if now - last_keepalive >= _WS_PING_INTERVAL_SEC:
                try:
                    await ws.send_json({"event": "keepalive", "timestamp": now})
                except Exception:
                    return
                last_keepalive = now

            if bus_queue is not None:
                try:
                    payload = bus_queue.get_nowait()
                    try:
                        await ws.send_json(payload)
                    except Exception:
                        return
                except asyncio.QueueEmpty:
                    pass

            async with async_session_factory() as session:
                await set_session_tenant(session, tenant_id)
                result = await session.execute(
                    select(Scan).where(
                        cast(Scan.id, String) == scan_id,
                        cast(Scan.tenant_id, String) == tenant_id,
                    )
                )
                scan = result.scalar_one_or_none()
                if not scan:
                    await ws.send_json({"event": "error", "error": "Scan not found"})
                    return

                result = await session.execute(
                    select(ScanEvent)
                    .where(cast(ScanEvent.scan_id, String) == scan_id)
                    .order_by(ScanEvent.created_at)
                )
                events = list(result.scalars().all())

            if not events and not seen_ids:
                await ws.send_json(
                    {"event": "init", "phase": "init", "progress": 0, "message": "Scan started"}
                )
                seen_ids.add("__init__")

            for ev in events:
                if ev.id not in seen_ids:
                    seen_ids.add(ev.id)
                    payload = _build_ws_payload(ev)
                    try:
                        await ws.send_json(payload)
                    except Exception:
                        return

            if scan.status in ("completed", "failed"):
                if scan.status == "completed":
                    if "complete" not in {e.event for e in events}:
                        await ws.send_json(
                            {
                                "event": "complete",
                                "phase": scan.phase,
                                "progress": 100,
                                "message": "Scan completed",
                            }
                        )
                else:
                    if "error" not in {e.event for e in events}:
                        await ws.send_json(
                            {
                                "event": "error",
                                "error": scan.phase or "Scan failed",
                                "phase": scan.phase,
                                "progress": scan.progress,
                            }
                        )
                return

            elapsed = time.monotonic() - started_at
            if elapsed >= _WS_MAX_WAIT_SEC:
                await ws.send_json({"event": "error", "error": "Event stream timeout"})
                return

            await asyncio.sleep(_WS_POLL_INTERVAL_SEC)
    finally:
        if bus_queue is not None and bus is not None:
            try:
                pass
            except Exception:
                pass


@router.websocket("/scans/{scan_id}/events")
async def ws_scan_events(ws: WebSocket, scan_id: str) -> None:
    """WebSocket endpoint for real-time scan event streaming.

    Authenticates tenant via ``X-Tenant-ID`` header (or query param
    ``tenant_id`` for WebSocket clients that cannot set headers).
    Sends the same event payloads as the SSE endpoint, as JSON frames.
    """
    tenant_id = ws.headers.get("x-tenant-id") or ws.query_params.get(
        "tenant_id", settings.default_tenant_id
    )
    try:
        await ws.accept()
    except Exception:
        logger.warning("ws_accept_failed", extra={"scan_id": scan_id})
        return

    _manager.connect(scan_id, ws)
    try:
        await _scan_event_stream(ws, scan_id, tenant_id)
    except WebSocketDisconnect:
        logger.debug("ws_client_disconnected", extra={"scan_id": scan_id})
    except Exception:
        logger.warning("ws_scan_events_error", extra={"scan_id": scan_id}, exc_info=True)
        try:
            await ws.close(code=status.WS_1011_INTERNAL_ERROR, reason="Internal error")
        except Exception:
            pass
    finally:
        _manager.disconnect(scan_id, ws)


@router.websocket("/scans/{scan_id}/chat")
async def ws_scan_chat(ws: WebSocket, scan_id: str) -> None:
    """WebSocket endpoint for real-time team chat during active scans.

    Uses ``ChatMessage`` from ``scan_events`` module for publishing.
    Receives JSON messages from clients and broadcasts to all
    connected clients for the same scan.

    Message format:
      Incoming:  ``{"user_id": "...", "message": "..."}``
      Outgoing:  ``{"type": "chat", "user_id": "...", "message": "...", "timestamp": "..."}``
    """
    from src.orchestration.scan_events import ChatMessage

    tenant_id = ws.headers.get("x-tenant-id") or ws.query_params.get(
        "tenant_id", settings.default_tenant_id
    )
    try:
        await ws.accept()
    except Exception:
        return

    _manager.connect(scan_id, ws)
    bus = ScanEventBus()
    msg_count = 0

    try:
        while msg_count < _WS_MAX_MESSAGES_DEFAULT:
            try:
                raw = await asyncio.wait_for(ws.receive_text(), timeout=300)
            except asyncio.TimeoutError:
                try:
                    await ws.send_json({"event": "keepalive"})
                    continue
                except Exception:
                    break
            except WebSocketDisconnect:
                break

            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                await ws.send_json({"event": "error", "error": "Invalid JSON"})
                continue

            msg_type = data.get("type", "chat")
            if msg_type == "ping":
                try:
                    await ws.send_json({"event": "pong"})
                except Exception:
                    break
                continue

            user_id = data.get("user_id", "anonymous")
            message = data.get("message", "").strip()
            if not message:
                continue

            chat = ChatMessage(
                scan_id=scan_id,
                tenant_id=tenant_id,
                user_id=user_id,
                message=message,
            )
            bus.publish_chat(chat)

            broadcast = {
                "type": "chat",
                "scan_id": scan_id,
                "user_id": user_id,
                "message": message,
                "timestamp": chat.timestamp,
            }
            await _manager.broadcast(scan_id, broadcast)
            msg_count += 1
    except WebSocketDisconnect:
        pass
    except Exception:
        logger.warning("ws_scan_chat_error", extra={"scan_id": scan_id}, exc_info=True)
    finally:
        _manager.disconnect(scan_id, ws)


@router.get("/stats")
async def ws_stats() -> dict[str, Any]:
    """Return WebSocket connection statistics."""
    return {"active_connections": _manager.active_count()}