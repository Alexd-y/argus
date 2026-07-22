"""Intruder response analysis — grep-match, grep-extract, dedup (WB-P4a).

Pure helpers a runner applies to each replay response to build the results grid:

* :func:`grep_match` — flags which of the given patterns appear in the response.
* :func:`grep_extract` — pulls the first regex capture out of the response.
* :func:`dedup` — collapses a result list to first-seen-per-key, the standard
  way to spot the "interesting" outlier response among thousands.

Regex operates on the raw response bytes decoded as latin-1 (total, lossless for
byte round-trips), so byte patterns and text patterns both work deterministically.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Generic, TypeVar

T = TypeVar("T")


class AnalysisError(Exception):
    """Raised for an invalid grep pattern."""


def grep_match(
    response: bytes, patterns: Sequence[str], *, regex: bool = False
) -> tuple[bool, ...]:
    """Return, per pattern, whether it occurs in ``response``.

    With ``regex=False`` patterns are literal substrings; with ``regex=True``
    each is a regular expression searched against the latin-1 view.
    """
    text = response.decode("latin-1")
    flags: list[bool] = []
    for pattern in patterns:
        if regex:
            try:
                compiled = re.compile(pattern)
            except re.error as exc:
                raise AnalysisError(f"invalid grep pattern {pattern!r}: {exc}") from exc
            flags.append(compiled.search(text) is not None)
        else:
            flags.append(pattern in text)
    return tuple(flags)


def grep_extract(response: bytes, pattern: str, *, group: int = 0) -> str | None:
    """Return the first regex match (or capture ``group``) in ``response``.

    Returns ``None`` when the pattern does not match. Raises
    :class:`AnalysisError` for an invalid pattern or an out-of-range group.
    """
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise AnalysisError(f"invalid extract pattern {pattern!r}: {exc}") from exc
    match = compiled.search(response.decode("latin-1"))
    if match is None:
        return None
    try:
        return match.group(group)
    except IndexError as exc:
        raise AnalysisError(f"capture group {group} out of range") from exc


@dataclass(frozen=True)
class DedupResult(Generic[T]):
    """Outcome of :func:`dedup`: the kept items and how many were dropped."""

    kept: tuple[T, ...]
    dropped: int


def dedup(items: Sequence[T], key: Callable[[T], object]) -> DedupResult[T]:
    """Keep the first item per distinct ``key(item)``; count the rest as dropped."""
    seen: set[object] = set()
    kept: list[T] = []
    dropped = 0
    for item in items:
        marker = key(item)
        if marker in seen:
            dropped += 1
            continue
        seen.add(marker)
        kept.append(item)
    return DedupResult(kept=tuple(kept), dropped=dropped)


__all__ = [
    "AnalysisError",
    "DedupResult",
    "dedup",
    "grep_extract",
    "grep_match",
]
