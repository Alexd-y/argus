"""Phase 9 Mode-B — Cairn engine progress mapping + terminal-wait loop (no DB/time)."""

from __future__ import annotations

from src.orchestration.cairn_engine import await_cairn_project, compute_scan_progress


def test_progress_floor_and_ceiling() -> None:
    assert compute_scan_progress(0, 0) == 5
    assert compute_scan_progress(0, 4) == 5
    assert compute_scan_progress(2, 4) == 50
    assert compute_scan_progress(4, 4) == 95
    assert compute_scan_progress(10, 4) == 95  # capped


class _Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


async def _noop_sleep(_seconds: float) -> None:
    return None


async def test_await_returns_completed_and_emits_progress() -> None:
    states = [("active", 4, 0), ("active", 4, 2), ("completed", 4, 4)]
    seq = iter(states)
    emitted: list[int] = []

    async def get_state():
        return next(seq)

    async def on_progress(p: int) -> None:
        emitted.append(p)

    reason = await await_cairn_project(
        get_state=get_state,
        on_progress=on_progress,
        poll_interval=0,
        sleep=_noop_sleep,
        clock=_Clock(),
    )
    assert reason == "completed"
    assert emitted == sorted(emitted)  # monotonic non-decreasing
    assert emitted[-1] == 95


async def test_await_honours_cancellation() -> None:
    async def get_state():
        return ("active", 4, 1)

    async def on_progress(_p: int) -> None:
        return None

    async def cancelled():
        return True

    reason = await await_cairn_project(
        get_state=get_state,
        on_progress=on_progress,
        is_cancelled=cancelled,
        poll_interval=0,
        sleep=_noop_sleep,
        clock=_Clock(),
    )
    assert reason == "cancelled"


async def test_await_times_out() -> None:
    clock = _Clock()

    async def get_state():
        return ("active", 4, 1)

    async def on_progress(_p: int) -> None:
        return None

    async def advancing_sleep(_seconds: float) -> None:
        clock.t += 100.0

    reason = await await_cairn_project(
        get_state=get_state,
        on_progress=on_progress,
        poll_interval=1,
        max_wait_seconds=50.0,
        sleep=advancing_sleep,
        clock=clock,
    )
    assert reason == "timeout"


async def test_progress_never_regresses() -> None:
    # concluded goes down (shouldn't happen, but be safe) — progress must not drop.
    states = [("active", 4, 3), ("active", 4, 1), ("completed", 4, 4)]
    seq = iter(states)
    emitted: list[int] = []

    async def get_state():
        return next(seq)

    async def on_progress(p: int) -> None:
        emitted.append(p)

    await await_cairn_project(
        get_state=get_state,
        on_progress=on_progress,
        poll_interval=0,
        sleep=_noop_sleep,
        clock=_Clock(),
    )
    assert emitted == sorted(emitted)
