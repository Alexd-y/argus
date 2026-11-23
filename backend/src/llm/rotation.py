"""Multi-LLM rotation (WP C) — ARTEX-style A,B,A,B with failover + excluded-skip.

An ordered list of LLM *profile ids* is rotated independently of completion: each
``advance()`` returns the next profile in order and moves the cursor on (A,B,A,B,…).
A profile marked ``exclude()`` (e.g. a 402 payment-required or a provider that
errored) is skipped **without rebalancing** — the fixed order is preserved, the
cursor simply steps over it. The cursor + order + exclusions serialise via
``state()`` / ``from_state()`` so a caller can persist the rotation position in the
DB and resume it exactly.

Pure module: no DB/LLM/network. WRB-001 is unaffected — rotation is applied only to
roles where it is safe (reports / OSINT / non-sensitive members); sensitive pentest
analysis stays WRB-first and is never rotated onto a hosted cloud model.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

__all__ = ["LLMRotation"]


class LLMRotation:
    """Ordered, cursor-based rotation over LLM profile ids with excluded-skip."""

    def __init__(
        self,
        profile_ids: Iterable[str],
        *,
        cursor: int = 0,
        excluded: Iterable[str] = (),
    ) -> None:
        self._profiles: list[str] = [str(p) for p in profile_ids]
        self._cursor: int = int(cursor)
        self._excluded: set[str] = {str(e) for e in excluded}

    @property
    def cursor(self) -> int:
        return self._cursor

    def exclude(self, profile_id: str) -> None:
        """Mark a profile excluded (failover-skip); the order is never rebalanced."""
        self._excluded.add(str(profile_id))

    def advance(self) -> str | None:
        """Return the next active profile (A,B,A,B…), stepping over excluded ones.

        Advances the cursor regardless of completion. Returns ``None`` when there is
        no active profile (empty list, or every profile excluded).
        """
        n = len(self._profiles)
        if n == 0:
            return None
        if all(p in self._excluded for p in self._profiles):
            return None
        for _ in range(n):
            profile = self._profiles[self._cursor % n]
            self._cursor += 1
            if profile not in self._excluded:
                return profile
        return None

    def state(self) -> dict[str, Any]:
        """Serialisable cursor/order/exclusions for DB persistence."""
        return {
            "profile_ids": list(self._profiles),
            "cursor": self._cursor,
            "excluded": sorted(self._excluded),
        }

    @classmethod
    def from_state(cls, state: dict[str, Any]) -> LLMRotation:
        """Rebuild a rotation from a persisted :meth:`state` mapping."""
        return cls(
            state.get("profile_ids", []),
            cursor=int(state.get("cursor", 0)),
            excluded=state.get("excluded", ()),
        )
