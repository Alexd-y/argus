"""WP C — multi-LLM rotation (ARTEX A,B,A,B with failover + excluded-skip).

Pure/offline. The rotation advances through an ordered profile list independently
of completion (A,B,A,B), skips excluded providers without rebalancing, and
round-trips its cursor so the order/position can be persisted in the DB.
"""

from __future__ import annotations

from src.llm.rotation import LLMRotation


def test_empty_rotation_yields_none() -> None:
    rot = LLMRotation([])
    assert rot.advance() is None


def test_abab_sequence_independent_of_completion() -> None:
    rot = LLMRotation(["A", "B"])
    assert [rot.advance() for _ in range(4)] == ["A", "B", "A", "B"]


def test_single_profile_repeats() -> None:
    rot = LLMRotation(["A"])
    assert [rot.advance() for _ in range(3)] == ["A", "A", "A"]


def test_excluded_profile_is_skipped_without_rebalance() -> None:
    rot = LLMRotation(["A", "B", "C"])
    rot.exclude("B")
    assert [rot.advance() for _ in range(4)] == ["A", "C", "A", "C"]


def test_all_excluded_yields_none() -> None:
    rot = LLMRotation(["A", "B"])
    rot.exclude("A")
    rot.exclude("B")
    assert rot.advance() is None


def test_state_roundtrip_preserves_cursor_and_exclusions() -> None:
    rot = LLMRotation(["A", "B", "C"])
    rot.exclude("C")
    assert rot.advance() == "A"  # cursor now at 1
    restored = LLMRotation.from_state(rot.state())
    # Continues exactly where the persisted cursor left off, same exclusions/order.
    assert restored.advance() == "B"
    assert restored.advance() == "A"


def test_order_is_preserved_in_state() -> None:
    rot = LLMRotation(["x", "y", "z"])
    assert rot.state()["profile_ids"] == ["x", "y", "z"]
