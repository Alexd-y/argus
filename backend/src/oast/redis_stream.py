"""OAST correlator durability via Redis Streams (ARG-061 / T01).

Producer: ``XADD`` after a successful in-memory ingest (correlation id = token_id).
Consumer: one consumer group + ``XREADGROUP``; ``XACK`` after idempotent
:meth:`~src.oast.correlator.OASTCorrelator.ingest`.

When Redis is unavailable, publish is skipped and a structured warning is
logged (degraded mode — in-process correlation still works; multi-instance
fan-out requires Redis).
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
from typing import Any

from redis.exceptions import ResponseError

from src.core.config import Settings
from src.oast.correlator import OASTCorrelator, OASTInteraction

_logger = logging.getLogger(__name__)


class OASTRedisStreamBridge:
    """Sync XADD producer + async consumer loop for :class:`OASTCorrelator`."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    @property
    def enabled(self) -> bool:
        return bool(self._settings.oast_redis_streams_enabled)

    def publish_after_store(self, interaction: OASTInteraction) -> None:
        """Append interaction to the Redis stream (best-effort)."""
        if not self.enabled:
            return
        try:
            from src.core.redis_client import get_redis

            client = get_redis()
        except Exception as exc:  # pragma: no cover — import guard
            _logger.warning(
                "oast.redis_stream.redis_unavailable",
                extra={
                    "event": "oast.redis_stream.redis_unavailable",
                    "error_type": type(exc).__name__,
                },
            )
            return
        if client is None:
            _logger.warning(
                "oast.redis_stream.redis_unavailable",
                extra={"event": "oast.redis_stream.redis_unavailable"},
            )
            return

        payload = interaction.model_dump_json()
        stream_key = self._settings.oast_stream_key
        maxlen = self._settings.oast_stream_maxlen
        try:
            client.xadd(
                stream_key,
                {"payload": payload},
                maxlen=maxlen,
                approximate=True,
            )
        except Exception as exc:
            _logger.warning(
                "oast.redis_stream.xadd_failed",
                extra={
                    "event": "oast.redis_stream.xadd_failed",
                    "error_type": type(exc).__name__,
                },
            )

    def _consumer_name(self) -> str:
        raw = (self._settings.oast_stream_consumer_name or "").strip()
        if raw:
            return raw
        host = socket.gethostname()
        return f"{host}-{os.getpid()}"

    async def ensure_consumer_group(self, redis: Any) -> None:
        """Create stream + consumer group if missing (idempotent)."""
        stream_key = self._settings.oast_stream_key
        group = self._settings.oast_stream_group
        try:
            await redis.xgroup_create(stream_key, group, id="0", mkstream=True)
        except ResponseError as exc:
            if "BUSYGROUP" in str(exc):
                return
            raise

    async def run_consumer(self, correlator: OASTCorrelator) -> None:
        """Blocking loop: read stream, re-ingest (idempotent), ACK.

        Cancel the task to stop. Intended for ``asyncio.create_task`` from
        application lifespan once a correlator singleton exists.
        """
        if not self.enabled:
            return
        try:
            import redis.asyncio as redis_asyncio
        except ImportError:  # pragma: no cover
            _logger.warning(
                "oast.redis_stream.async_redis_missing",
                extra={"event": "oast.redis_stream.async_redis_missing"},
            )
            return

        redis = redis_asyncio.from_url(
            self._settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
        )
        stream_key = self._settings.oast_stream_key
        group = self._settings.oast_stream_group
        consumer = self._consumer_name()
        block_ms = self._settings.oast_stream_block_ms

        try:
            await self.ensure_consumer_group(redis)
        except Exception as exc:
            _logger.warning(
                "oast.redis_stream.group_init_failed",
                extra={
                    "event": "oast.redis_stream.group_init_failed",
                    "error_type": type(exc).__name__,
                },
            )
            await redis.close()
            return

        try:
            while True:
                try:
                    streams = await redis.xreadgroup(
                        groupname=group,
                        consumername=consumer,
                        streams={stream_key: ">"},
                        count=32,
                        block=block_ms,
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    _logger.warning(
                        "oast.redis_stream.xreadgroup_failed",
                        extra={
                            "event": "oast.redis_stream.xreadgroup_failed",
                            "error_type": type(exc).__name__,
                        },
                    )
                    await asyncio.sleep(min(block_ms / 1000.0, 5.0))
                    continue

                if not streams:
                    continue
                for _sname, messages in streams:
                    for msg_id, fields in messages:
                        await self._process_one(
                            redis,
                            stream_key,
                            group,
                            msg_id,
                            fields,
                            correlator,
                        )
        finally:
            await redis.close()

    async def _process_one(
        self,
        redis: Any,
        stream_key: str,
        group: str,
        msg_id: str,
        fields: dict[str, str],
        correlator: OASTCorrelator,
    ) -> None:
        payload = fields.get("payload")
        if not payload:
            await redis.xack(stream_key, group, msg_id)
            return
        try:
            interaction = OASTInteraction.model_validate_json(payload)
        except Exception as exc:
            _logger.warning(
                "oast.redis_stream.invalid_payload",
                extra={
                    "event": "oast.redis_stream.invalid_payload",
                    "error_type": type(exc).__name__,
                },
            )
            await redis.xack(stream_key, group, msg_id)
            return
        try:
            correlator.ingest(interaction)
        except Exception as exc:
            _logger.warning(
                "oast.redis_stream.ingest_failed",
                extra={
                    "event": "oast.redis_stream.ingest_failed",
                    "error_type": type(exc).__name__,
                },
            )
            # Do not ACK: leave the message pending so XREADGROUP can retry
            # after a transient failure (at-least-once semantics).
            return
        try:
            await redis.xack(stream_key, group, msg_id)
        except Exception as exc:
            _logger.warning(
                "oast.redis_stream.xack_failed",
                extra={
                    "event": "oast.redis_stream.xack_failed",
                    "error_type": type(exc).__name__,
                },
            )


__all__ = ["OASTRedisStreamBridge"]
