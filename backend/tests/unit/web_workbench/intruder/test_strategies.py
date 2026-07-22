"""Unit tests for the four Intruder attack strategies."""

from __future__ import annotations

import pytest

from src.web_workbench.intruder.positions import IntruderError
from src.web_workbench.intruder.strategies import (
    Strategy,
    iter_assignments,
    total_requests,
)

_BASE2 = (b"A", b"B")


def _assignments(strategy: Strategy, base, sets, **kw):
    return list(iter_assignments(strategy, len(base), base, sets, **kw))


def test_sniper_one_position_at_a_time() -> None:
    payloads = [b"p1", b"p2"]
    result = _assignments(Strategy.SNIPER, _BASE2, [payloads])
    # 2 positions * 2 payloads = 4; each request fuzzes exactly one position.
    assert result == [
        (b"p1", b"B"),
        (b"p2", b"B"),
        (b"A", b"p1"),
        (b"A", b"p2"),
    ]
    assert total_requests(Strategy.SNIPER, 2, [payloads]) == 4


def test_battering_ram_same_payload_everywhere() -> None:
    result = _assignments(Strategy.BATTERING_RAM, _BASE2, [[b"x", b"y"]])
    assert result == [(b"x", b"x"), (b"y", b"y")]
    assert total_requests(Strategy.BATTERING_RAM, 2, [[b"x", b"y"]]) == 2


def test_pitchfork_lockstep_min_length() -> None:
    result = _assignments(Strategy.PITCHFORK, _BASE2, [[b"u1", b"u2", b"u3"], [b"p1", b"p2"]])
    # min(3, 2) == 2 lockstep rows.
    assert result == [(b"u1", b"p1"), (b"u2", b"p2")]
    assert total_requests(Strategy.PITCHFORK, 2, [[b"u1", b"u2", b"u3"], [b"p1", b"p2"]]) == 2


def test_cluster_bomb_cartesian_product() -> None:
    result = _assignments(Strategy.CLUSTER_BOMB, _BASE2, [[b"a", b"b"], [b"1", b"2"]])
    assert result == [
        (b"a", b"1"),
        (b"a", b"2"),
        (b"b", b"1"),
        (b"b", b"2"),
    ]
    assert total_requests(Strategy.CLUSTER_BOMB, 2, [[b"a", b"b"], [b"1", b"2"]]) == 4


def test_processor_applied_to_payloads_not_base() -> None:
    # Sniper: only the injected payload is processed; the base value is untouched.
    result = _assignments(Strategy.SNIPER, _BASE2, [[b"p"]], process=lambda b: b"[" + b + b"]")
    assert result == [(b"[p]", b"B"), (b"A", b"[p]")]


def test_sniper_requires_single_set() -> None:
    with pytest.raises(IntruderError, match="exactly one payload set"):
        _assignments(Strategy.SNIPER, _BASE2, [[b"a"], [b"b"]])


def test_pitchfork_requires_set_per_position() -> None:
    with pytest.raises(IntruderError, match="one payload set per position"):
        _assignments(Strategy.PITCHFORK, _BASE2, [[b"a"]])


def test_empty_payload_set_rejected() -> None:
    with pytest.raises(IntruderError, match="must not be empty"):
        _assignments(Strategy.BATTERING_RAM, _BASE2, [[]])


def test_no_positions_rejected() -> None:
    with pytest.raises(IntruderError, match="no insertion points"):
        list(iter_assignments(Strategy.SNIPER, 0, (), [[b"a"]]))
