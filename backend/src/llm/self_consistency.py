"""Self-consistency voting for high-stakes LLM decisions (Wave 5, R-9.13).

For the small number of decisions that move a finding's evidence tier, one LLM
sample is not enough: run the decision several times — each with a different
seed so the samples are genuinely independent — and accept the answer only when a
majority agrees. Deliberately expensive, so callers apply it to a few responsible
decisions, never to every call.

Generic and dependency-light: the caller supplies an async ``sample_fn(i)`` (it
is responsible for varying the seed/temperature by ``i``) and a ``key`` that maps
a sample to the value votes are tallied on. Pure orchestration — fully testable
offline with a stub ``sample_fn``.
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Awaitable, Callable, Hashable
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ConsensusResult:
    """Outcome of a self-consistency vote."""

    value: Any | None  # a representative sample for the winning key, or None
    agreement: int  # votes for the winning key
    total: int  # samples attempted
    reached: bool  # agreement >= min_agree
    samples: tuple[Any, ...]  # all samples (None for a failed attempt)


async def run_self_consistent(
    sample_fn: Callable[[int], Awaitable[Any]],
    *,
    n: int = 3,
    min_agree: int = 2,
    key: Callable[[Any], Hashable] = lambda x: x,
) -> ConsensusResult:
    """Run ``sample_fn`` ``n`` times and return the majority decision.

    A sample that raises (or returns ``None``) does not vote. ``value`` is a
    representative sample for the winning key when consensus is reached, else
    ``None``. ``n`` and ``min_agree`` are clamped to sane minimums.
    """
    n = max(1, int(n))
    min_agree = max(1, int(min_agree))

    samples: list[Any] = []
    for i in range(n):
        try:
            samples.append(await sample_fn(i))
        except Exception:
            logger.debug("self_consistency sample %d failed", i, exc_info=True)
            samples.append(None)

    counts: Counter[Hashable] = Counter()
    for s in samples:
        if s is not None:
            try:
                counts[key(s)] += 1
            except Exception:
                logger.debug("self_consistency key() failed", exc_info=True)

    if not counts:
        return ConsensusResult(None, 0, n, False, tuple(samples))

    top_key, agreement = counts.most_common(1)[0]
    reached = agreement >= min_agree
    representative = next(
        (s for s in samples if s is not None and _safe_key(key, s) == top_key),
        None,
    )
    return ConsensusResult(
        value=representative if reached else None,
        agreement=agreement,
        total=n,
        reached=reached,
        samples=tuple(samples),
    )


def _safe_key(key: Callable[[Any], Hashable], value: Any) -> Hashable | None:
    try:
        return key(value)
    except Exception:
        return None


__all__ = ["ConsensusResult", "run_self_consistent"]
