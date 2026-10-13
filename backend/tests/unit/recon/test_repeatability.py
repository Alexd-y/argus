"""Wave 3 / etap 5 — repeatability runner feeds the arbiter gate."""

from __future__ import annotations

from src.recon.vulnerability_analysis.repeatability import confirm_repeatability


async def test_stable_observation_confirms() -> None:
    async def observe() -> str:
        return "alert-fired"

    outcome, results = await confirm_repeatability(observe, runs=2)
    assert len(results) == 2
    assert outcome.attempts == 2 and outcome.matched == 2
    assert outcome.confirmed is True
    assert outcome.diverged is False


async def test_flaky_observation_diverges_not_discarded() -> None:
    seq = iter(["fired", "not-fired", "fired"])

    async def observe() -> str:
        return next(seq)

    outcome, results = await confirm_repeatability(observe, runs=3)
    assert len(results) == 3
    # 2 of 3 matched the first → reflected, not thrown away.
    assert outcome.matched == 2 and outcome.attempts == 3
    assert outcome.confirmed is False
    assert outcome.diverged is True


async def test_repeat_disabled_is_not_a_free_pass() -> None:
    async def observe() -> str:
        return "fired"

    outcome, _ = await confirm_repeatability(observe, runs=1)
    assert outcome.attempts == 1
    # One run cannot confirm repeatability (required default 2) → arbiter caps.
    assert outcome.confirmed is False


async def test_custom_matcher() -> None:
    seq = iter([{"status": 500, "note": "a"}, {"status": 500, "note": "b"}])

    async def observe() -> dict:
        return next(seq)

    # Compare only on status → the two runs match despite the differing note.
    outcome, _ = await confirm_repeatability(
        observe, runs=2, matches=lambda a, b: a["status"] == b["status"]
    )
    assert outcome.confirmed is True
