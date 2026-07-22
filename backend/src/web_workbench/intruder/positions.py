"""Intruder insertion-point parsing + byte-exact rendering (WB-P4a).

A *template* is a raw HTTP request with zero or more **insertion points** marked
by a delimiter pair (default ``{{`` … ``}}``). The bytes between a pair are the
position's *base value* (what the request contains when that position is not
being fuzzed). Everything outside the markers is preserved byte-exact.

Rendering interleaves the literal segments with a caller-supplied value per
position, so :meth:`ParsedTemplate.render` with the base values reproduces the
original request bytes exactly (verified by tests) — the byte-fidelity invariant
the whole workbench relies on for faithful replay.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

#: Default insertion-point delimiters (neutral Mustache-style, not tool-specific).
DEFAULT_OPEN: bytes = b"{{"
DEFAULT_CLOSE: bytes = b"}}"

#: Hard cap on insertion points per template (abuse / accidental-blowup guard).
MAX_POSITIONS: int = 256


class IntruderError(Exception):
    """Raised for malformed templates or invalid position/payload wiring."""


@dataclass(frozen=True)
class ParsedTemplate:
    """A template split into literal segments + per-position base values.

    Invariant: ``len(literals) == len(base_values) + 1`` and
    ``render(base_values) == original_raw``.
    """

    literals: tuple[bytes, ...]
    base_values: tuple[bytes, ...]

    @property
    def position_count(self) -> int:
        return len(self.base_values)

    def render(self, values: Sequence[bytes]) -> bytes:
        """Interleave the literals with ``values`` (one per position)."""
        if len(values) != self.position_count:
            raise IntruderError(f"expected {self.position_count} values, got {len(values)}")
        out = bytearray(self.literals[0])
        for value, literal in zip(values, self.literals[1:], strict=True):
            out += value
            out += literal
        return bytes(out)

    def render_base(self) -> bytes:
        """Render with the original base values (reproduces the source bytes)."""
        return self.render(self.base_values)


def parse_template(
    raw: bytes, *, open_marker: bytes = DEFAULT_OPEN, close_marker: bytes = DEFAULT_CLOSE
) -> ParsedTemplate:
    """Parse ``raw`` into literal segments + base values at each insertion point.

    Raises :class:`IntruderError` on an unbalanced/overlapping marker or when the
    template declares more than :data:`MAX_POSITIONS` positions.
    """
    if not open_marker or not close_marker:
        raise IntruderError("markers must be non-empty")

    literals: list[bytes] = []
    base_values: list[bytes] = []
    cursor = 0
    while True:
        start = raw.find(open_marker, cursor)
        if start == -1:
            literals.append(raw[cursor:])
            break
        end = raw.find(close_marker, start + len(open_marker))
        if end == -1:
            raise IntruderError("unbalanced insertion-point marker (missing close)")
        literals.append(raw[cursor:start])
        base_values.append(raw[start + len(open_marker) : end])
        cursor = end + len(close_marker)
        if len(base_values) > MAX_POSITIONS:
            raise IntruderError(f"too many insertion points (max {MAX_POSITIONS})")

    return ParsedTemplate(literals=tuple(literals), base_values=tuple(base_values))


__all__ = [
    "DEFAULT_CLOSE",
    "DEFAULT_OPEN",
    "MAX_POSITIONS",
    "IntruderError",
    "ParsedTemplate",
    "parse_template",
]
