"""Unit tests for OAST Redis Streams bridge (T01)."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, Mock, patch
from uuid import uuid4

import pytest
from redis.exceptions import ResponseError

from src.core.config import Settings
from src.oast.correlator import InteractionKind, OASTCorrelator, OASTInteraction
from src.oast.provisioner import InternalOASTProvisioner
from src.oast.redis_stream import OASTRedisStreamBridge


@pytest.fixture
def internal_provisioner() -> InternalOASTProvisioner:
    return InternalOASTProvisioner(base_domain="oast.test.example")


def _interaction(token_id) -> OASTInteraction:
    return OASTInteraction.build(
        id=uuid4(),
        token_id=token_id,
        kind=InteractionKind.DNS_A,
        source_ip="203.0.113.1",
        raw_request_bytes=b"q",
        metadata={"qname": "x.example.com"},
    )


def test_publish_skipped_when_disabled(internal_provisioner: InternalOASTProvisioner) -> None:
    settings = Settings(oast_redis_streams_enabled=False)
    bridge = OASTRedisStreamBridge(settings)
    token = internal_provisioner.issue(
        tenant_id=uuid4(),
        scan_id=uuid4(),
        validation_job_id=None,
        family="test",
    )
    inter = _interaction(token.id)
    with patch("src.core.redis_client.get_redis") as gr:
        bridge.publish_after_store(inter)
        gr.assert_not_called()


def test_publish_calls_xadd_when_enabled(
    internal_provisioner: InternalOASTProvisioner,
) -> None:
    settings = Settings(
        oast_redis_streams_enabled=True,
        oast_stream_key="test:oast:stream",
    )
    bridge = OASTRedisStreamBridge(settings)
    token = internal_provisioner.issue(
        tenant_id=uuid4(),
        scan_id=uuid4(),
        validation_job_id=None,
        family="test",
    )
    inter = _interaction(token.id)
    fake = MagicMock()
    with patch("src.core.redis_client.get_redis", return_value=fake):
        bridge.publish_after_store(inter)
    fake.xadd.assert_called_once()
    args, kwargs = fake.xadd.call_args
    assert args[0] == "test:oast:stream"
    assert "payload" in args[1]
    assert kwargs.get("maxlen") == settings.oast_stream_maxlen
    assert kwargs.get("approximate") is True


def test_correlator_invokes_callback_on_store(
    internal_provisioner: InternalOASTProvisioner,
) -> None:
    called: list[OASTInteraction] = []

    def cb(i: OASTInteraction) -> None:
        called.append(i)

    correlator = OASTCorrelator(internal_provisioner, on_interaction_stored=cb)
    token = internal_provisioner.issue(
        tenant_id=uuid4(),
        scan_id=uuid4(),
        validation_job_id=None,
        family="test",
    )
    inter = _interaction(token.id)
    assert correlator.ingest(inter) is True
    assert len(called) == 1
    assert called[0].id == inter.id


@pytest.mark.asyncio
async def test_consumer_processes_message(
    internal_provisioner: InternalOASTProvisioner,
) -> None:
    settings = Settings(
        oast_redis_streams_enabled=True,
        oast_stream_key="s",
        oast_stream_group="g",
    )
    bridge = OASTRedisStreamBridge(settings)
    correlator = OASTCorrelator(internal_provisioner)
    token = internal_provisioner.issue(
        tenant_id=uuid4(),
        scan_id=uuid4(),
        validation_job_id=None,
        family="test",
    )
    inter = _interaction(token.id)
    payload = inter.model_dump_json()

    redis = AsyncMock()
    redis.xack = AsyncMock()
    await bridge._process_one(redis, "s", "g", "1-0", {"payload": payload}, correlator)
    assert len(correlator.list_interactions(token.id)) == 1
    redis.xack.assert_awaited_once()


def test_oast_settings_defaults() -> None:
    s = Settings()
    assert s.oast_redis_streams_enabled is False
    assert s.oast_stream_key == "argus:oast:interactions"
    assert s.oast_stream_group == "argus-oast-correlators"
    assert s.oast_stream_consumer_name == ""
    assert s.oast_stream_maxlen == 100_000
    assert s.oast_stream_block_ms == 5000


def test_publish_skips_when_get_redis_raises(
    internal_provisioner: InternalOASTProvisioner,
) -> None:
    settings = Settings(oast_redis_streams_enabled=True, oast_stream_key="k")
    bridge = OASTRedisStreamBridge(settings)
    token = internal_provisioner.issue(
        tenant_id=uuid4(),
        scan_id=uuid4(),
        validation_job_id=None,
        family="test",
    )
    inter = _interaction(token.id)
    with patch("src.core.redis_client.get_redis", side_effect=RuntimeError("no redis")):
        bridge.publish_after_store(inter)


def test_publish_skips_when_redis_client_none(
    internal_provisioner: InternalOASTProvisioner,
) -> None:
    settings = Settings(oast_redis_streams_enabled=True, oast_stream_key="k")
    bridge = OASTRedisStreamBridge(settings)
    token = internal_provisioner.issue(
        tenant_id=uuid4(),
        scan_id=uuid4(),
        validation_job_id=None,
        family="test",
    )
    inter = _interaction(token.id)
    with patch("src.core.redis_client.get_redis", return_value=None) as gr:
        bridge.publish_after_store(inter)
        gr.assert_called_once()


def test_publish_swallows_xadd_failure(
    internal_provisioner: InternalOASTProvisioner,
) -> None:
    settings = Settings(oast_redis_streams_enabled=True, oast_stream_key="k")
    bridge = OASTRedisStreamBridge(settings)
    token = internal_provisioner.issue(
        tenant_id=uuid4(),
        scan_id=uuid4(),
        validation_job_id=None,
        family="test",
    )
    inter = _interaction(token.id)
    fake = MagicMock()
    fake.xadd.side_effect = OSError("write failed")
    with patch("src.core.redis_client.get_redis", return_value=fake):
        bridge.publish_after_store(inter)


@pytest.mark.asyncio
async def test_ensure_consumer_group_ignores_busygroup() -> None:
    settings = Settings(oast_stream_key="sk", oast_stream_group="grp")
    bridge = OASTRedisStreamBridge(settings)
    redis = AsyncMock()
    redis.xgroup_create = AsyncMock(
        side_effect=ResponseError("BUSYGROUP Consumer Group name already exists")
    )
    await bridge.ensure_consumer_group(redis)
    redis.xgroup_create.assert_awaited_once()


@pytest.mark.asyncio
async def test_ensure_consumer_group_raises_other_response_error() -> None:
    settings = Settings(oast_stream_key="sk", oast_stream_group="grp")
    bridge = OASTRedisStreamBridge(settings)
    redis = AsyncMock()
    redis.xgroup_create = AsyncMock(side_effect=ResponseError("NOGROUP no such key"))
    with pytest.raises(ResponseError):
        await bridge.ensure_consumer_group(redis)


@pytest.mark.asyncio
async def test_run_consumer_noop_when_disabled(
    internal_provisioner: InternalOASTProvisioner,
) -> None:
    settings = Settings(oast_redis_streams_enabled=False)
    bridge = OASTRedisStreamBridge(settings)
    correlator = OASTCorrelator(internal_provisioner)
    with patch("redis.asyncio.from_url") as from_url:
        await bridge.run_consumer(correlator)
        from_url.assert_not_called()


@pytest.mark.asyncio
async def test_run_consumer_xreadgroup_ingests_and_xacks(
    internal_provisioner: InternalOASTProvisioner,
) -> None:
    settings = Settings(
        oast_redis_streams_enabled=True,
        oast_stream_key="s",
        oast_stream_group="g",
        redis_url="redis://127.0.0.1:16379/9",
        oast_stream_block_ms=100,
    )
    bridge = OASTRedisStreamBridge(settings)
    correlator = OASTCorrelator(internal_provisioner)
    token = internal_provisioner.issue(
        tenant_id=uuid4(),
        scan_id=uuid4(),
        validation_job_id=None,
        family="test",
    )
    inter = _interaction(token.id)
    payload = inter.model_dump_json()

    redis = AsyncMock()
    redis.close = AsyncMock()
    redis.xack = AsyncMock()

    calls: list[int] = []

    async def xread_side_effect(*_a: object, **_kw: object) -> object:
        calls.append(1)
        if len(calls) == 1:
            return [[("s", [("1-0", {"payload": payload})])]]
        ev = asyncio.Event()
        await ev.wait()

    redis.xreadgroup = AsyncMock(side_effect=xread_side_effect)

    with (
        patch("redis.asyncio.from_url", return_value=redis),
        patch.object(bridge, "ensure_consumer_group", new_callable=AsyncMock),
    ):
        task = asyncio.create_task(bridge.run_consumer(correlator))
        try:
            loop = asyncio.get_running_loop()
            deadline = loop.time() + 2.0
            while loop.time() < deadline:
                if correlator.list_interactions(token.id):
                    break
                await asyncio.sleep(0.01)
            else:
                pytest.fail("correlator did not ingest stream message in time")
            assert len(correlator.list_interactions(token.id)) == 1
            redis.xack.assert_awaited()
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    redis.close.assert_awaited()


@pytest.mark.asyncio
async def test_process_one_ingest_failure_does_not_xack(
    internal_provisioner: InternalOASTProvisioner,
) -> None:
    """Transient ingest errors must not ACK so the message stays pending."""
    settings = Settings(oast_redis_streams_enabled=True, oast_stream_key="s", oast_stream_group="g")
    bridge = OASTRedisStreamBridge(settings)
    token = internal_provisioner.issue(
        tenant_id=uuid4(),
        scan_id=uuid4(),
        validation_job_id=None,
        family="test",
    )
    inter = _interaction(token.id)
    payload = inter.model_dump_json()

    redis = AsyncMock()
    redis.xack = AsyncMock()
    correlator = Mock(spec=OASTCorrelator)
    correlator.ingest = Mock(side_effect=RuntimeError("transient"))

    await bridge._process_one(redis, "s", "g", "1-0", {"payload": payload}, correlator)
    redis.xack.assert_not_awaited()
