"""Cairn engine (Mode-B) — wait for the blackboard project to reach a terminal state.

The Cairn search is driven asynchronously by the beat tick (``argus.cairn.tick``) +
worker tasks. When a scan runs with ``engine=cairn`` the state machine creates the
project and then waits here, mapping graph progress onto ``Scan.progress`` (§11.2)
until the project is ``completed``/``stopped``, a deadline elapses, or the scan is
cancelled. All collaborators are injected so the loop is unit-testable without a
database, Celery, or real time.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable

# (status, total_intents, concluded_intents)
StateProvider = Callable[[], Awaitable[tuple[str, int, int]]]
ProgressSink = Callable[[int], Awaitable[None]]
CancelCheck = Callable[[], Awaitable[bool]]

_TERMINAL_STATES = frozenset({"completed", "stopped"})


def compute_scan_progress(concluded_intents: int, total_intents: int) -> int:
    """Map graph state onto a 5..95 scan-progress band (§11.2).

    ``progress = min(95, 5 + 90 * concluded / max(1, total))``. Reporting takes it to
    100 afterwards; 5 is the floor so a just-created project shows movement.
    """
    ratio = concluded_intents / max(1, total_intents)
    return min(95, 5 + int(round(90 * ratio)))


async def await_cairn_project(
    *,
    get_state: StateProvider,
    on_progress: ProgressSink,
    is_cancelled: CancelCheck | None = None,
    poll_interval: float = 10.0,
    max_wait_seconds: float = 3600.0,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> str:
    """Poll until the project is terminal / cancelled / past deadline.

    Returns the terminal reason: ``"completed"``, ``"stopped"``, ``"cancelled"`` or
    ``"timeout"``. Emits mapped progress on every poll (monotonic — never regresses).
    """
    start = clock()
    last_progress = 0
    while True:
        if is_cancelled is not None and await is_cancelled():
            return "cancelled"

        status, total, concluded = await get_state()
        progress = compute_scan_progress(concluded, total)
        if progress > last_progress:
            last_progress = progress
            await on_progress(progress)

        if status in _TERMINAL_STATES:
            return status

        if (clock() - start) >= max_wait_seconds:
            return "timeout"

        await sleep(poll_interval)


__all__ = ["await_cairn_project", "compute_scan_progress"]
