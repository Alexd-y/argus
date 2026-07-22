"""Comparer: deterministic diffs across bytes / words / lines / JSON / DOM (WB-P3a).

The workbench analogue of Burp's Comparer. All diff modes are pure and offline
and return a structured, JSON-serialisable :class:`DiffResult` (never raw HTML)
so the frontend can render highlights without re-parsing.

Modes:

* ``byte`` — opcode diff over raw bytes (latin-1 view for spans).
* ``word`` — diff over whitespace-delimited tokens.
* ``line`` — diff over ``splitlines`` output.
* ``json`` — structural, order-insensitive diff of parsed JSON.
* ``dom`` — diff over a normalised HTML token stream (tags + sorted attrs +
  collapsed text) so cosmetic whitespace/attribute-order changes are ignored.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from difflib import SequenceMatcher
from enum import Enum
from html.parser import HTMLParser
from typing import Any


class DiffKind(str, Enum):
    BYTE = "byte"
    WORD = "word"
    LINE = "line"
    JSON = "json"
    DOM = "dom"


class ComparerError(Exception):
    """Raised on an unsupported mode or malformed structured input."""


class DiffOp(str, Enum):
    EQUAL = "equal"
    INSERT = "insert"
    DELETE = "delete"
    REPLACE = "replace"


@dataclass(frozen=True)
class DiffSegment:
    """One aligned region between the two inputs."""

    op: DiffOp
    a: str
    b: str


@dataclass(frozen=True)
class DiffResult:
    """Full diff output plus summary counts for rendering."""

    kind: DiffKind
    identical: bool
    segments: tuple[DiffSegment, ...]
    inserted: int
    deleted: int
    replaced: int


class _DomTokenizer(HTMLParser):
    """Collapse HTML into a normalised token stream for structural comparison."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tokens: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        rendered = " ".join(f"{k}={v or ''}" for k, v in sorted(attrs))
        self.tokens.append(f"<{tag} {rendered}>".rstrip())

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        self.tokens.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        text = data.strip()
        if text:
            self.tokens.append(" ".join(text.split()))


def _dom_tokens(payload: bytes) -> list[str]:
    parser = _DomTokenizer()
    parser.feed(payload.decode("utf-8", "replace"))
    parser.close()
    return parser.tokens


def _units(kind: DiffKind, left: bytes, right: bytes) -> tuple[list[str], list[str], str]:
    """Return (left_units, right_units, join_sep) for opcode-based diffs."""
    if kind is DiffKind.BYTE:
        return (
            [chr(b) for b in left],
            [chr(b) for b in right],
            "",
        )
    if kind is DiffKind.WORD:
        return (
            left.decode("utf-8", "replace").split(),
            right.decode("utf-8", "replace").split(),
            " ",
        )
    if kind is DiffKind.LINE:
        return (
            left.decode("utf-8", "replace").splitlines(),
            right.decode("utf-8", "replace").splitlines(),
            "\n",
        )
    if kind is DiffKind.DOM:
        return _dom_tokens(left), _dom_tokens(right), "\n"
    raise ComparerError(f"unsupported opcode diff kind: {kind}")


def _opcode_diff(kind: DiffKind, left: bytes, right: bytes, sep: str) -> DiffResult:
    a_units, b_units, _ = _units(kind, left, right)
    matcher = SequenceMatcher(a=a_units, b=b_units, autojunk=False)
    segments: list[DiffSegment] = []
    inserted = deleted = replaced = 0
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        a_text = sep.join(a_units[i1:i2])
        b_text = sep.join(b_units[j1:j2])
        op = DiffOp(tag)
        if op is DiffOp.INSERT:
            inserted += j2 - j1
        elif op is DiffOp.DELETE:
            deleted += i2 - i1
        elif op is DiffOp.REPLACE:
            replaced += max(i2 - i1, j2 - j1)
        segments.append(DiffSegment(op=op, a=a_text, b=b_text))
    return DiffResult(
        kind=kind,
        identical=inserted == 0 and deleted == 0 and replaced == 0,
        segments=tuple(segments),
        inserted=inserted,
        deleted=deleted,
        replaced=replaced,
    )


def _canonical_json(payload: bytes) -> str:
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ComparerError("input is not valid JSON") from exc
    return json.dumps(parsed, ensure_ascii=False, sort_keys=True, indent=2)


def _json_diff(left: bytes, right: bytes) -> DiffResult:
    """Order-insensitive JSON diff via canonicalisation, then a line opcode diff."""
    a_lines = _canonical_json(left).splitlines()
    b_lines = _canonical_json(right).splitlines()
    matcher = SequenceMatcher(a=a_lines, b=b_lines, autojunk=False)
    segments: list[DiffSegment] = []
    inserted = deleted = replaced = 0
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        op = DiffOp(tag)
        if op is DiffOp.INSERT:
            inserted += j2 - j1
        elif op is DiffOp.DELETE:
            deleted += i2 - i1
        elif op is DiffOp.REPLACE:
            replaced += max(i2 - i1, j2 - j1)
        segments.append(
            DiffSegment(op=op, a="\n".join(a_lines[i1:i2]), b="\n".join(b_lines[j1:j2]))
        )
    return DiffResult(
        kind=DiffKind.JSON,
        identical=inserted == 0 and deleted == 0 and replaced == 0,
        segments=tuple(segments),
        inserted=inserted,
        deleted=deleted,
        replaced=replaced,
    )


def compare(left: bytes, right: bytes, *, kind: DiffKind = DiffKind.LINE) -> DiffResult:
    """Diff ``left`` vs ``right`` using ``kind`` and return a structured result."""
    if kind is DiffKind.JSON:
        return _json_diff(left, right)
    _, _, sep = _units(kind, left, right)
    return _opcode_diff(kind, left, right, sep)


def result_to_dict(result: DiffResult) -> dict[str, Any]:
    """Serialise a :class:`DiffResult` into a plain JSON-safe dict."""
    return {
        "kind": result.kind.value,
        "identical": result.identical,
        "inserted": result.inserted,
        "deleted": result.deleted,
        "replaced": result.replaced,
        "segments": [{"op": seg.op.value, "a": seg.a, "b": seg.b} for seg in result.segments],
    }


__all__ = [
    "ComparerError",
    "DiffKind",
    "DiffOp",
    "DiffResult",
    "DiffSegment",
    "compare",
    "result_to_dict",
]
