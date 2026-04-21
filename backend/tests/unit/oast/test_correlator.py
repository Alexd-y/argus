"""Unit tests for :mod:`src.oast.correlator` (ARG-007).

Coverage focus:

* Metadata sanitisation strips control characters and enforces value
  length / key shape limits.
* Ingestion rejects unknown tokens, deduplicates by interaction id, and
  caps per-token storage at the configured ``max_per_token``.
* :meth:`OASTCorrelator.wait_for_interaction` is non-blocking
  (`asyncio.Event`-driven), respects the configurable window, and
  returns existing data immediately when available.
* Filtering by :class:`InteractionKind` works for both immediate and
  awaited fetches.
* The wait loop never busy-spins on a spurious wake (regression for the
  filtered-ingest race fixed in the post-ARG-007 review).
* :meth:`OASTCorrelator.purge_expired` evicts expired tokens AND
  per-interaction stale entries while keeping warm data intact.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import cast
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from src.oast.correlator import (
    InteractionKind,
    OASTCorrelator,
    OASTInteraction,
)
from src.oast.provisioner import (
    InternalOASTProvisioner,
)


_TENANT = UUID("11111111-1111-1111-1111-111111111111")
_SCAN = UUID("22222222-2222-2222-2222-222222222222")


def _build_interaction(
    *,
    token_id: UUID,
    kind: InteractionKind = InteractionKind.HTTP_REQUEST,
    metadata: dict[str, str] | None = None,
    raw: bytes = b"GET /p/abcdef HTTP/1.1",
    source_ip: str = "203.0.113.5",
    received_at: datetime | None = None,
) -> OASTInteraction:
    return OASTInteraction.build(
        id=uuid4(),
        token_id=token_id,
        kind=kind,
        source_ip=source_ip,
        raw_request_bytes=raw,
        metadata=metadata,
        received_at=received_at,
    )


# ---------------------------------------------------------------------------
# OASTInteraction model
# ---------------------------------------------------------------------------


class TestOASTInteraction:
    def test_build_hashes_raw_bytes(self) -> None:
        interaction = _build_interaction(token_id=uuid4(), raw=b"hello world")
        assert (
            interaction.raw_request_hash == hashlib.sha256(b"hello world").hexdigest()
        )

    def test_metadata_strips_control_characters(self) -> None:
        interaction = _build_interaction(
            token_id=uuid4(),
            metadata={"qname": "evil\x00.example.com\x07"},
        )
        assert interaction.metadata["qname"] == "evil.example.com"

    def test_metadata_truncates_long_values(self) -> None:
        long_value = "x" * 1000
        interaction = _build_interaction(
            token_id=uuid4(),
            metadata={"qname": long_value},
        )
        assert len(interaction.metadata["qname"]) == 256

    def test_metadata_rejects_too_many_keys(self) -> None:
        too_many = {f"key_{i:02d}": "v" for i in range(20)}
        with pytest.raises(ValidationError):
            _build_interaction(token_id=uuid4(), metadata=too_many)

    def test_metadata_rejects_bad_key(self) -> None:
        with pytest.raises(ValidationError):
            _build_interaction(token_id=uuid4(), metadata={"BadKey": "v"})

    def test_metadata_rejects_non_string_value(self) -> None:
        # Forge through Pydantic by passing a dict with int value via cast.
        bad: dict[str, str] = cast(dict[str, str], {"key": 123})
        with pytest.raises(ValidationError):
            _build_interaction(token_id=uuid4(), metadata=bad)

    def test_invalid_hash_rejected(self) -> None:
        with pytest.raises(ValidationError):
            OASTInteraction(
                id=uuid4(),
                token_id=uuid4(),
                kind=InteractionKind.DNS_A,
                source_ip="1.2.3.4",
                raw_request_hash="not-a-real-hash",
            )

    def test_source_ip_rejects_only_control_chars(self) -> None:
        with pytest.raises(ValidationError):
            OASTInteraction(
                id=uuid4(),
                token_id=uuid4(),
                kind=InteractionKind.DNS_A,
                source_ip="\x00\x01",
                raw_request_hash="0" * 64,
            )


# ---------------------------------------------------------------------------
# OASTCorrelator
# ---------------------------------------------------------------------------


class TestOASTCorrelator:
    def test_constructor_validates_window_bounds(
        self, internal_provisioner: InternalOASTProvisioner
    ) -> None:
        with pytest.raises(ValueError):
            OASTCorrelator(internal_provisioner, default_window_s=0)
        with pytest.raises(ValueError):
            OASTCorrelator(internal_provisioner, max_window_s=0)
        with pytest.raises(ValueError):
            OASTCorrelator(
                internal_provisioner,
                default_window_s=10,
                max_window_s=5,
            )
        with pytest.raises(ValueError):
            OASTCorrelator(internal_provisioner, max_per_token=0)

    def test_ingest_rejects_unknown_token(self, correlator: OASTCorrelator) -> None:
        accepted = correlator.ingest(_build_interaction(token_id=uuid4()))
        assert accepted is False

    def test_ingest_records_known_token_interaction(
        self,
        correlator: OASTCorrelator,
        internal_provisioner: InternalOASTProvisioner,
    ) -> None:
        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)
        accepted = correlator.ingest(_build_interaction(token_id=token.id))
        assert accepted is True
        assert len(correlator.list_interactions(token.id)) == 1

    def test_ingest_deduplicates_by_interaction_id(
        self,
        correlator: OASTCorrelator,
        internal_provisioner: InternalOASTProvisioner,
    ) -> None:
        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)
        interaction = _build_interaction(token_id=token.id)
        assert correlator.ingest(interaction) is True
        assert correlator.ingest(interaction) is False
        assert len(correlator.list_interactions(token.id)) == 1

    def test_ingest_caps_per_token_storage(
        self,
        internal_provisioner: InternalOASTProvisioner,
    ) -> None:
        correlator = OASTCorrelator(
            internal_provisioner,
            default_window_s=1,
            max_window_s=2,
            max_per_token=2,
        )
        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)
        for _ in range(3):
            correlator.ingest(_build_interaction(token_id=token.id))
        assert len(correlator.list_interactions(token.id)) == 2

    def test_list_interactions_filters_by_kind(
        self,
        correlator: OASTCorrelator,
        internal_provisioner: InternalOASTProvisioner,
    ) -> None:
        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)
        correlator.ingest(
            _build_interaction(token_id=token.id, kind=InteractionKind.DNS_A)
        )
        correlator.ingest(
            _build_interaction(token_id=token.id, kind=InteractionKind.HTTP_REQUEST)
        )
        dns_only = correlator.list_interactions(token.id, kinds=[InteractionKind.DNS_A])
        assert len(dns_only) == 1
        assert dns_only[0].kind is InteractionKind.DNS_A

    def test_clear_drops_state(
        self,
        correlator: OASTCorrelator,
        internal_provisioner: InternalOASTProvisioner,
    ) -> None:
        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)
        correlator.ingest(_build_interaction(token_id=token.id))
        correlator.clear()
        assert correlator.list_interactions(token.id) == []
        assert list(correlator.known_tokens()) == []


# ---------------------------------------------------------------------------
# wait_for_interaction (asyncio path)
# ---------------------------------------------------------------------------


class TestWaitForInteraction:
    @pytest.mark.asyncio()
    async def test_returns_existing_immediately(
        self,
        correlator: OASTCorrelator,
        internal_provisioner: InternalOASTProvisioner,
    ) -> None:
        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)
        correlator.ingest(_build_interaction(token_id=token.id))

        result = await correlator.wait_for_interaction(token.id, timeout_s=5)
        assert len(result) == 1

    @pytest.mark.asyncio()
    async def test_zero_timeout_returns_snapshot(
        self,
        correlator: OASTCorrelator,
        internal_provisioner: InternalOASTProvisioner,
    ) -> None:
        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)
        result = await correlator.wait_for_interaction(token.id, timeout_s=0)
        assert result == []

    @pytest.mark.asyncio()
    async def test_negative_timeout_rejected(
        self,
        correlator: OASTCorrelator,
        internal_provisioner: InternalOASTProvisioner,
    ) -> None:
        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)
        with pytest.raises(ValueError):
            await correlator.wait_for_interaction(token.id, timeout_s=-1)

    @pytest.mark.asyncio()
    async def test_timeout_returns_empty_when_no_interaction_arrives(
        self,
        correlator: OASTCorrelator,
        internal_provisioner: InternalOASTProvisioner,
    ) -> None:
        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)
        result = await correlator.wait_for_interaction(token.id, timeout_s=1)
        assert result == []

    @pytest.mark.asyncio()
    async def test_unblocks_on_concurrent_ingest(
        self,
        correlator: OASTCorrelator,
        internal_provisioner: InternalOASTProvisioner,
    ) -> None:
        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)

        async def _ingest_after_delay() -> None:
            await asyncio.sleep(0.05)
            correlator.ingest(_build_interaction(token_id=token.id))

        ingest_task = asyncio.create_task(_ingest_after_delay())
        result = await correlator.wait_for_interaction(token.id, timeout_s=2)
        await ingest_task

        assert len(result) == 1

    @pytest.mark.asyncio()
    async def test_timeout_clamped_to_max_window(
        self,
        correlator: OASTCorrelator,
        internal_provisioner: InternalOASTProvisioner,
    ) -> None:
        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)
        # Default fixture has max_window_s=2; passing 9999 should clamp.
        # We simply verify the call completes within ~max_window_s + overhead.
        loop = asyncio.get_event_loop()
        start = loop.time()
        await correlator.wait_for_interaction(token.id, timeout_s=9999)
        elapsed = loop.time() - start
        assert elapsed < correlator.max_window_s + 1.0

    @pytest.mark.asyncio()
    async def test_filters_by_kind(
        self,
        correlator: OASTCorrelator,
        internal_provisioner: InternalOASTProvisioner,
    ) -> None:
        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)
        # Dispatch a DNS interaction; the wait filters for HTTP only.
        correlator.ingest(
            _build_interaction(token_id=token.id, kind=InteractionKind.DNS_A)
        )
        result = await correlator.wait_for_interaction(
            token.id,
            timeout_s=1,
            kinds=[InteractionKind.HTTP_REQUEST],
        )
        assert result == []

        # Now ingest matching kind and re-wait.
        correlator.ingest(
            _build_interaction(token_id=token.id, kind=InteractionKind.HTTP_REQUEST)
        )
        result = await correlator.wait_for_interaction(
            token.id,
            timeout_s=1,
            kinds=[InteractionKind.HTTP_REQUEST],
        )
        assert len(result) == 1
        assert result[0].kind is InteractionKind.HTTP_REQUEST


# ---------------------------------------------------------------------------
# wait_for_interaction — busy-loop / multi-waiter regressions (post-ARG-007)
# ---------------------------------------------------------------------------


class TestWaitForInteractionRegressions:
    """Guards the wait loop against the spurious-wake busy spin and the
    multi-waiter signal loss the original implementation suffered from."""

    @pytest.mark.asyncio()
    async def test_wait_for_interaction_does_not_busy_loop_on_filtered_wake(
        self,
        correlator: OASTCorrelator,
        internal_provisioner: InternalOASTProvisioner,
    ) -> None:
        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)

        # Sentinel: count how many snapshot probes the wait loop performs.
        # With the bug the loop spun thousands of times per second; with
        # the fix it should probe once per real wake.
        snapshot_count = 0
        original_snapshot = correlator._snapshot_matching

        def counting_snapshot(
            token_id: UUID,
            kinds: frozenset[InteractionKind] | None,
        ) -> list[OASTInteraction]:
            nonlocal snapshot_count
            snapshot_count += 1
            return original_snapshot(token_id, kinds)

        correlator._snapshot_matching = counting_snapshot  # type: ignore[method-assign]

        matching_ingest_time: list[float] = []

        async def _ingest_sequence() -> None:
            # Non-matching kind first — must NOT resolve the DNS_A waiter
            # nor make it spin on a stale "set" flag.
            await asyncio.sleep(0.05)
            correlator.ingest(
                _build_interaction(
                    token_id=token.id,
                    kind=InteractionKind.HTTP_REQUEST,
                )
            )
            # Then a matching ingest — the waiter must resolve promptly.
            await asyncio.sleep(0.05)
            matching_ingest_time.append(asyncio.get_running_loop().time())
            correlator.ingest(
                _build_interaction(
                    token_id=token.id,
                    kind=InteractionKind.DNS_A,
                )
            )

        ingest_task = asyncio.create_task(_ingest_sequence())
        try:
            result = await correlator.wait_for_interaction(
                token.id,
                timeout_s=1,
                kinds=[InteractionKind.DNS_A],
            )
        finally:
            await ingest_task

        assert len(result) == 1
        assert result[0].kind is InteractionKind.DNS_A

        # Three legitimate snapshot probes:
        #   1. initial fast-path before parking on the event;
        #   2. after the spurious HTTP_REQUEST wake;
        #   3. after the matching DNS_A wake.
        # A small head-room of ``<= 5`` absorbs scheduling jitter without
        # losing the busy-loop signal (which used to be in the thousands).
        assert snapshot_count <= 5, f"busy loop detected: {snapshot_count} snapshots"

        # Late match must surface within the 200 ms budget called out in
        # the ARG-007 review.
        assert matching_ingest_time, "matching ingest never ran"
        elapsed_after_match = (
            asyncio.get_running_loop().time() - matching_ingest_time[0]
        )
        assert elapsed_after_match < 0.2, (
            f"slow resolution: {elapsed_after_match * 1000:.1f} ms"
        )

    @pytest.mark.asyncio()
    async def test_wait_for_interaction_multiple_waiters_one_wakes_all_filter_correctly(
        self,
        correlator: OASTCorrelator,
        internal_provisioner: InternalOASTProvisioner,
    ) -> None:
        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)

        waiter_dns = asyncio.create_task(
            correlator.wait_for_interaction(
                token.id,
                timeout_s=2,
                kinds=[InteractionKind.DNS_A],
            )
        )
        waiter_http = asyncio.create_task(
            correlator.wait_for_interaction(
                token.id,
                timeout_s=2,
                kinds=[InteractionKind.HTTP_REQUEST],
            )
        )

        # Yield once so both tasks reach ``await event.wait()`` before we
        # ingest. Without this the ingests could fire on the fast-path
        # before the waiters even register their event.
        await asyncio.sleep(0.01)

        correlator.ingest(
            _build_interaction(token_id=token.id, kind=InteractionKind.DNS_A)
        )
        correlator.ingest(
            _build_interaction(token_id=token.id, kind=InteractionKind.HTTP_REQUEST)
        )

        dns_result, http_result = await asyncio.gather(waiter_dns, waiter_http)

        assert len(dns_result) == 1
        assert dns_result[0].kind is InteractionKind.DNS_A

        assert len(http_result) == 1
        assert http_result[0].kind is InteractionKind.HTTP_REQUEST


# ---------------------------------------------------------------------------
# purge_expired — eviction policy
# ---------------------------------------------------------------------------


class TestCorrelatorPurgeExpired:
    """The correlator must evict aged interactions and orphaned events
    so long-running scans cannot grow ``_interactions`` / ``_events``
    without bound."""

    def _correlator_with_short_retention(
        self,
        provisioner: InternalOASTProvisioner,
        max_retention: timedelta,
    ) -> OASTCorrelator:
        return OASTCorrelator(
            provisioner,
            default_window_s=1,
            max_window_s=2,
            max_retention=max_retention,
        )

    def test_purge_drops_interactions_older_than_max_retention(
        self,
        internal_provisioner: InternalOASTProvisioner,
    ) -> None:
        correlator = self._correlator_with_short_retention(
            internal_provisioner, timedelta(hours=1)
        )
        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)

        now = datetime(2026, 4, 17, 12, 0, 0, tzinfo=timezone.utc)
        old = now - timedelta(hours=2)
        recent = now - timedelta(minutes=10)

        correlator.ingest(_build_interaction(token_id=token.id, received_at=old))
        correlator.ingest(_build_interaction(token_id=token.id, received_at=recent))

        evicted = correlator.purge_expired(before=now)
        assert evicted == 1

        remaining = correlator.list_interactions(token.id)
        assert len(remaining) == 1
        assert remaining[0].received_at == recent

    def test_purge_drops_buckets_for_unknown_tokens(
        self,
        deterministic_uuid_factory: Callable[[], UUID],
        deterministic_token_factory: Callable[[int], str],
    ) -> None:
        # Use a moving clock so we can freeze "now" for the provisioner
        # during the issue() call, then advance it for purge_expired().
        moments: list[datetime] = []

        def clock() -> datetime:
            return moments[-1]

        moments.append(datetime(2026, 4, 17, 12, 0, 0, tzinfo=timezone.utc))
        provisioner = InternalOASTProvisioner(
            base_domain="oast.argus.local",
            clock=clock,
            id_factory=deterministic_uuid_factory,
            token_factory=deterministic_token_factory,
        )
        correlator = OASTCorrelator(
            provisioner,
            default_window_s=1,
            max_window_s=2,
            max_retention=timedelta(hours=1),
        )
        token = provisioner.issue(
            tenant_id=_TENANT,
            scan_id=_SCAN,
            ttl=timedelta(seconds=60),
        )
        correlator.ingest(_build_interaction(token_id=token.id))

        # Fast-forward 30 minutes — token expired by 29 minutes,
        # exceeding the 5 minute default grace.
        future = moments[0] + timedelta(minutes=30)
        moments.append(future)
        provisioner.purge_expired(before=future)

        assert provisioner.get(token.id) is None

        evicted = correlator.purge_expired(before=future)
        assert evicted == 1
        assert correlator.list_interactions(token.id) == []

    def test_purge_respects_grace_window(
        self,
        deterministic_uuid_factory: Callable[[], UUID],
        deterministic_token_factory: Callable[[int], str],
    ) -> None:
        moments: list[datetime] = [datetime(2026, 4, 17, 12, 0, 0, tzinfo=timezone.utc)]

        def clock() -> datetime:
            return moments[-1]

        provisioner = InternalOASTProvisioner(
            base_domain="oast.argus.local",
            clock=clock,
            id_factory=deterministic_uuid_factory,
            token_factory=deterministic_token_factory,
        )
        correlator = OASTCorrelator(
            provisioner,
            default_window_s=1,
            max_window_s=2,
            max_retention=timedelta(hours=1),
        )
        token = provisioner.issue(
            tenant_id=_TENANT,
            scan_id=_SCAN,
            ttl=timedelta(seconds=60),
        )
        correlator.ingest(_build_interaction(token_id=token.id, received_at=moments[0]))

        # 30 seconds past expiry but still within the 5 minute grace.
        # The token AND interaction must both survive.
        slight_future = moments[0] + timedelta(seconds=90)
        evicted = correlator.purge_expired(before=slight_future)
        assert evicted == 0
        assert len(correlator.list_interactions(token.id)) == 1

    def test_purge_negative_grace_rejected(
        self,
        correlator: OASTCorrelator,
    ) -> None:
        with pytest.raises(ValueError):
            correlator.purge_expired(grace=timedelta(seconds=-1))

    def test_purge_naive_before_rejected(
        self,
        correlator: OASTCorrelator,
    ) -> None:
        with pytest.raises(ValueError):
            correlator.purge_expired(before=datetime(2026, 4, 17, 12, 0, 0))

    @pytest.mark.asyncio()
    async def test_purge_unblocks_waiter_when_token_evicted(
        self,
        deterministic_uuid_factory: Callable[[], UUID],
        deterministic_token_factory: Callable[[int], str],
    ) -> None:
        """A waiter parked on an event whose token gets purged must be
        unblocked promptly so it returns its (empty) snapshot rather than
        hanging until its own deadline."""
        moments: list[datetime] = [datetime(2026, 4, 17, 12, 0, 0, tzinfo=timezone.utc)]

        def clock() -> datetime:
            return moments[-1]

        provisioner = InternalOASTProvisioner(
            base_domain="oast.argus.local",
            clock=clock,
            id_factory=deterministic_uuid_factory,
            token_factory=deterministic_token_factory,
        )
        correlator = OASTCorrelator(
            provisioner,
            default_window_s=1,
            max_window_s=2,
            max_retention=timedelta(hours=1),
        )
        token = provisioner.issue(
            tenant_id=_TENANT,
            scan_id=_SCAN,
            ttl=timedelta(seconds=60),
        )

        async def _purge_after_yield() -> None:
            # Yield twice so the waiter parks on its event before we
            # advance the clock past the grace window and purge.
            await asyncio.sleep(0.01)
            await asyncio.sleep(0.01)
            future = moments[0] + timedelta(minutes=30)
            moments.append(future)
            provisioner.purge_expired(before=future)
            correlator.purge_expired(before=future)

        purge_task = asyncio.create_task(_purge_after_yield())
        loop = asyncio.get_running_loop()
        start = loop.time()
        result = await correlator.wait_for_interaction(token.id, timeout_s=2)
        elapsed = loop.time() - start
        await purge_task

        assert result == []
        # The 2-second wait should be cut short well under 1 second once
        # the token is evicted; if the wake never fires we hit the full
        # window.
        assert elapsed < 1.0, f"waiter did not wake on purge: {elapsed:.2f}s"
