"""Shared fixtures for the :mod:`src.oast` unit-test suite (ARG-007).

The OAST plane is fully in-process: every fixture here is deterministic
(fake clocks, deterministic ID factories, in-memory listeners) so the
suite can run in any environment without touching real DNS/HTTP/SMTP
sockets.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone
from itertools import count
from uuid import UUID

import pytest

from src.oast.canary import CanaryGenerator
from src.oast.correlator import OASTCorrelator
from src.oast.listener_protocol import FakeOASTListener
from src.oast.provisioner import (
    DisabledOASTProvisioner,
    InternalOASTProvisioner,
)


_BASE_DOMAIN = "oast.argus.local"


@pytest.fixture()
def fixed_clock() -> Callable[[], datetime]:
    """Return a clock that is stable for the lifetime of a single test."""
    moment = datetime(2026, 4, 17, 12, 0, 0, tzinfo=timezone.utc)
    return lambda: moment


@pytest.fixture()
def advancing_clock() -> Callable[[timedelta], Callable[[], datetime]]:
    """Return a factory that produces clocks advancing by a fixed step."""

    def _factory(step: timedelta) -> Callable[[], datetime]:
        start = datetime(2026, 4, 17, 12, 0, 0, tzinfo=timezone.utc)
        ticks: Iterator[int] = count()

        def _clock() -> datetime:
            return start + step * next(ticks)

        return _clock

    return _factory


@pytest.fixture()
def deterministic_uuid_factory() -> Callable[[], UUID]:
    """Return a UUID factory yielding 0000…0001, 0000…0002, ..."""
    counter = count(start=1)

    def _factory() -> UUID:
        return UUID(int=next(counter))

    return _factory


@pytest.fixture()
def deterministic_token_factory() -> Callable[[int], str]:
    """Return a token factory producing ``aabb…`` patterns of the right length."""
    counter = count(start=1)

    def _factory(nbytes: int) -> str:
        # Each token is ``<index>`` left-padded with ``a`` to 2*nbytes hex chars.
        index = next(counter)
        marker = format(index, "x")
        if len(marker) > nbytes * 2:
            raise AssertionError(
                "deterministic_token_factory exhausted; raise the upper bound"
            )
        return marker.rjust(nbytes * 2, "a")

    return _factory


@pytest.fixture()
def internal_provisioner(
    fixed_clock: Callable[[], datetime],
    deterministic_uuid_factory: Callable[[], UUID],
    deterministic_token_factory: Callable[[int], str],
) -> InternalOASTProvisioner:
    """Return a fully deterministic :class:`InternalOASTProvisioner`."""
    return InternalOASTProvisioner(
        base_domain=_BASE_DOMAIN,
        clock=fixed_clock,
        id_factory=deterministic_uuid_factory,
        token_factory=deterministic_token_factory,
    )


@pytest.fixture()
def disabled_provisioner() -> DisabledOASTProvisioner:
    return DisabledOASTProvisioner()


@pytest.fixture()
def correlator(internal_provisioner: InternalOASTProvisioner) -> OASTCorrelator:
    """Return a correlator wired to the deterministic in-memory provisioner."""
    return OASTCorrelator(
        internal_provisioner,
        default_window_s=1,
        max_window_s=2,
    )


@pytest.fixture()
def listener(
    correlator: OASTCorrelator,
    deterministic_uuid_factory: Callable[[], UUID],
) -> FakeOASTListener:
    """Return an in-memory fake listener wired to ``correlator``."""
    return FakeOASTListener(correlator, id_factory=deterministic_uuid_factory)


@pytest.fixture()
def canary_generator(
    deterministic_uuid_factory: Callable[[], UUID],
    deterministic_token_factory: Callable[[int], str],
    fixed_clock: Callable[[], datetime],
) -> CanaryGenerator:
    """Return a deterministic canary generator (delays + tokens are stable)."""
    delays = count(start=1)

    def _delay_factory() -> int:
        # Use a deterministic but plausible delay (>=250ms <=30s) for tests.
        return 1500 + (next(delays) * 100)

    return CanaryGenerator(
        id_factory=deterministic_uuid_factory,
        token_factory=deterministic_token_factory,
        delay_ms_factory=_delay_factory,
        clock=fixed_clock,
    )
