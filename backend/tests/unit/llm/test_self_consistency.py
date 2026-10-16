"""Wave 5 / R-9.13 — self-consistency voting for high-stakes decisions."""

from __future__ import annotations

import asyncio

from src.llm.self_consistency import run_self_consistent


def _runner(results):
    """Build an async sample_fn that returns results[i] (raises if it's an Exception)."""

    async def _fn(i):
        r = results[i]
        if isinstance(r, Exception):
            raise r
        return r

    return _fn


def test_majority_reaches_consensus():
    res = asyncio.run(run_self_consistent(_runner(["yes", "yes", "no"]), n=3, min_agree=2))
    assert res.reached is True
    assert res.value == "yes"
    assert res.agreement == 2
    assert res.total == 3


def test_no_majority_does_not_reach():
    res = asyncio.run(run_self_consistent(_runner(["a", "b", "c"]), n=3, min_agree=2))
    assert res.reached is False
    assert res.value is None
    assert res.agreement == 1


def test_failed_samples_do_not_vote():
    res = asyncio.run(
        run_self_consistent(_runner([RuntimeError("x"), "yes", "yes"]), n=3, min_agree=2)
    )
    assert res.reached is True
    assert res.value == "yes"
    assert res.samples[0] is None  # the failed attempt is recorded as None


def test_key_extractor_tallies_on_field():
    samples = [
        {"tier": 3, "note": "a"},
        {"tier": 3, "note": "b"},
        {"tier": 2, "note": "c"},
    ]
    res = asyncio.run(
        run_self_consistent(_runner(samples), n=3, min_agree=2, key=lambda s: s["tier"])
    )
    assert res.reached is True
    assert res.value["tier"] == 3  # representative sample for the winning key


def test_all_failed_returns_no_consensus():
    res = asyncio.run(
        run_self_consistent(_runner([RuntimeError(), RuntimeError()]), n=2, min_agree=1)
    )
    assert res.reached is False
    assert res.value is None
    assert res.agreement == 0
