"""Intruder attack strategies — assignment generation (WB-P4a).

Given a template's position count + base values and one or more payload sets,
each strategy yields a sequence of *assignments* (one payload value per
position). The four classic strategies:

* **Sniper** — one payload set; fuzz a single position at a time while the other
  positions keep their base value. Total = ``positions * len(set)``.
* **Battering ram** — one payload set; place the same payload in *every* position
  at once. Total = ``len(set)``.
* **Pitchfork** — one payload set per position; iterate in lockstep. Total =
  ``min(len(set_i))``.
* **Cluster bomb** — one payload set per position; cartesian product across all
  positions. Total = ``prod(len(set_i))``.

Only the injected payload passes through the caller's ``process`` callable
(processor chain); base values are emitted untouched, preserving byte-fidelity.
Payload sets are supplied by the caller (sourced from the signed PayloadRegistry,
SI-5) — this module never fetches payloads itself.
"""

from __future__ import annotations

import itertools
import math
from collections.abc import Callable, Iterator, Sequence
from enum import StrEnum

from src.web_workbench.intruder.positions import IntruderError


def _identity(payload: bytes) -> bytes:
    """Default transform when no processor chain is supplied."""
    return payload


#: Hard cap on total generated requests (guard against accidental blow-up).
MAX_TOTAL_REQUESTS: int = 5_000_000

PayloadSet = Sequence[bytes]


class Strategy(StrEnum):
    """The four attack strategies."""

    SNIPER = "sniper"
    BATTERING_RAM = "battering_ram"
    PITCHFORK = "pitchfork"
    CLUSTER_BOMB = "cluster_bomb"


def _single_set(payload_sets: Sequence[PayloadSet]) -> PayloadSet:
    if len(payload_sets) != 1:
        raise IntruderError("this strategy requires exactly one payload set")
    if not payload_sets[0]:
        raise IntruderError("payload set must not be empty")
    return payload_sets[0]


def _per_position_sets(
    payload_sets: Sequence[PayloadSet], position_count: int
) -> Sequence[PayloadSet]:
    if len(payload_sets) != position_count:
        raise IntruderError(
            f"this strategy requires one payload set per position "
            f"({position_count}); got {len(payload_sets)}"
        )
    for payload_set in payload_sets:
        if not payload_set:
            raise IntruderError("payload set must not be empty")
    return payload_sets


def total_requests(
    strategy: Strategy, position_count: int, payload_sets: Sequence[PayloadSet]
) -> int:
    """Compute the total request count for ``strategy`` without generating them."""
    if position_count <= 0:
        raise IntruderError("template has no insertion points")
    match strategy:
        case Strategy.SNIPER:
            return position_count * len(_single_set(payload_sets))
        case Strategy.BATTERING_RAM:
            return len(_single_set(payload_sets))
        case Strategy.PITCHFORK:
            sets = _per_position_sets(payload_sets, position_count)
            return min(len(s) for s in sets)
        case Strategy.CLUSTER_BOMB:
            sets = _per_position_sets(payload_sets, position_count)
            return math.prod(len(s) for s in sets)
    raise IntruderError(f"unhandled strategy {strategy!r}")  # pragma: no cover


def iter_assignments(
    strategy: Strategy,
    position_count: int,
    base_values: Sequence[bytes],
    payload_sets: Sequence[PayloadSet],
    *,
    process: Callable[[bytes], bytes] = _identity,
) -> Iterator[tuple[bytes, ...]]:
    """Yield the per-position value tuple for each request of the attack.

    ``process`` is applied to injected payloads only (never to base values).
    Raises :class:`IntruderError` if the generated total exceeds
    :data:`MAX_TOTAL_REQUESTS`.
    """
    if position_count <= 0:
        raise IntruderError("template has no insertion points")
    if len(base_values) != position_count:
        raise IntruderError("base_values length must equal position_count")

    total = total_requests(strategy, position_count, payload_sets)
    if total > MAX_TOTAL_REQUESTS:
        raise IntruderError(f"attack would generate {total} requests (max {MAX_TOTAL_REQUESTS})")

    match strategy:
        case Strategy.SNIPER:
            yield from _iter_sniper(position_count, base_values, _single_set(payload_sets), process)
        case Strategy.BATTERING_RAM:
            yield from _iter_battering_ram(position_count, _single_set(payload_sets), process)
        case Strategy.PITCHFORK:
            yield from _iter_pitchfork(_per_position_sets(payload_sets, position_count), process)
        case Strategy.CLUSTER_BOMB:
            yield from _iter_cluster_bomb(_per_position_sets(payload_sets, position_count), process)
        case _:  # pragma: no cover - exhaustive over StrEnum
            raise IntruderError(f"unhandled strategy {strategy!r}")


def _iter_sniper(
    position_count: int,
    base_values: Sequence[bytes],
    payload_set: PayloadSet,
    process: Callable[[bytes], bytes],
) -> Iterator[tuple[bytes, ...]]:
    for position in range(position_count):
        for payload in payload_set:
            assignment = list(base_values)
            assignment[position] = process(payload)
            yield tuple(assignment)


def _iter_battering_ram(
    position_count: int, payload_set: PayloadSet, process: Callable[[bytes], bytes]
) -> Iterator[tuple[bytes, ...]]:
    for payload in payload_set:
        processed = process(payload)
        yield tuple(processed for _ in range(position_count))


def _iter_pitchfork(
    sets: Sequence[PayloadSet], process: Callable[[bytes], bytes]
) -> Iterator[tuple[bytes, ...]]:
    length = min(len(s) for s in sets)
    for index in range(length):
        yield tuple(process(s[index]) for s in sets)


def _iter_cluster_bomb(
    sets: Sequence[PayloadSet], process: Callable[[bytes], bytes]
) -> Iterator[tuple[bytes, ...]]:
    for combo in itertools.product(*sets):
        yield tuple(process(payload) for payload in combo)


__all__ = [
    "MAX_TOTAL_REQUESTS",
    "PayloadSet",
    "Strategy",
    "iter_assignments",
    "total_requests",
]
