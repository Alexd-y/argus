"""Shared building blocks for JSON-shape sandbox parsers (ARG-029).

Every parser in the ARG-029 batch (and several from earlier cycles)
operates on the same skeleton:

1.  Resolve the canonical artefact file under ``artifacts_dir`` if it
    exists; otherwise fall back to ``stdout``.  Tools that emit to
    ``-o /out/<name>`` always have the canonical file present in
    production; tools invoked via ``sh -c '... > /out/<name>'`` may
    occasionally race the redirect, in which case ``stdout`` is the
    only source of truth.
2.  Iterate the resolved bytes either as a JSONL stream
    (one JSON dict per line) or a single JSON document (object or
    list of objects).
3.  Hand each raw record to a tool-specific normaliser.
4.  Dedup, sort, cap, persist a sidecar, and return the FindingDTOs.

This module ships the generic primitives so the per-tool parsers stay
focused on the tool-specific shape; the shared infrastructure is
implemented once and tested against several callers, eliminating an
entire class of "I forgot to fail-soft on OSError" / "I forgot to
truncate evidence" bugs.

The helpers are intentionally pure functions: every input arrives as
arguments, every output is returned (no global state, no module-level
mutation), and ``OSError`` from filesystem reads is logged + swallowed
so a hostile file system cannot wedge the worker.

Public surface
--------------

* :func:`safe_join_artifact` — defensive ``base / name`` that refuses
  path-traversal segments.  Mirrors the ``_safe_join`` private helper
  used by the older parsers; kept centralised here so future parsers do
  not reimplement (and inevitably weaken) the guard.
* :func:`load_canonical_or_stdout_json` — resolve a top-level JSON
  document from ``artifacts_dir / canonical_name`` or fall back to
  ``stdout``.  Returns the parsed payload (any JSON type) or ``None``.
* :func:`iter_jsonl_records` — yield one JSON dict per non-empty line
  from ``artifacts_dir / canonical_name`` (preferred) or ``stdout``
  (fallback).  Wraps :func:`safe_load_jsonl`.
* :func:`persist_jsonl_sidecar` — best-effort writer for the per-tool
  sidecar JSONL evidence file.

The shared helpers do NOT make any assumption about the FindingDTO
shape; they hand back raw payloads and let the per-tool parser build
its DTOs.  This keeps the helpers reusable from the rest of the
parser registry without forcing every parser to share a single dedup
key shape.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any, Final

from src.sandbox.parsers._base import (
    MAX_STDOUT_BYTES,
    safe_load_json,
    safe_load_jsonl,
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Path / IO helpers
# ---------------------------------------------------------------------------


def safe_join_artifact(base: Path, name: str) -> Path | None:
    """Return ``base / name`` iff ``name`` has no path-traversal segments.

    Refuses ``"/"``, ``"\\"``, and ``".."`` anywhere in ``name``.  The
    canonical artefact filenames declared in ``backend/config/tools/*.yaml``
    are simple basenames (e.g. ``trufflehog.json``) so this guard is a
    pure defence-in-depth move against a malicious YAML or a catalog
    drift bug.
    """
    if "/" in name or "\\" in name or ".." in name:
        return None
    return base / name


def _read_canonical_bytes(
    artifacts_dir: Path,
    *,
    canonical_name: str,
    tool_id: str,
) -> bytes:
    """Best-effort read of ``artifacts_dir / canonical_name``.

    Returns ``b""`` for any failure mode (missing file, OSError, path
    traversal blocked).  Every failure other than "file does not exist"
    emits a structured ``WARNING`` so the operator can spot the I/O
    issue without triggering parser dispatch errors.
    """
    canonical = safe_join_artifact(artifacts_dir, canonical_name)
    if canonical is None or not canonical.is_file():
        return b""
    try:
        return canonical.read_bytes()
    except OSError as exc:
        _logger.warning(
            "parsers.jsonl_base.canonical_read_failed",
            extra={
                "event": "parsers_jsonl_base_canonical_read_failed",
                "tool_id": tool_id,
                "canonical_name": canonical_name,
                "error_type": type(exc).__name__,
            },
        )
        return b""


def load_canonical_or_stdout_json(
    *,
    stdout: bytes,
    artifacts_dir: Path,
    canonical_name: str,
    tool_id: str,
) -> Any:
    """Resolve ``canonical_name`` JSON or fall back to ``stdout``.

    Returns the parsed JSON value (which may be a dict, list, or
    scalar) or ``None`` when both sources are empty / malformed.
    """
    raw = _read_canonical_bytes(
        artifacts_dir, canonical_name=canonical_name, tool_id=tool_id
    )
    if raw.strip():
        payload = safe_load_json(raw, tool_id=tool_id)
        if payload is not None:
            return payload
    if stdout and stdout.strip():
        return safe_load_json(stdout, tool_id=tool_id)
    return None


def iter_jsonl_records(
    *,
    stdout: bytes,
    artifacts_dir: Path,
    canonical_name: str,
    tool_id: str,
    limit: int = MAX_STDOUT_BYTES,
) -> Iterator[dict[str, Any]]:
    """Yield JSON dicts from ``canonical_name`` JSONL (file then stdout).

    Both sources are mutually exclusive: when the canonical file is
    present and non-empty, ``stdout`` is ignored.  This matches the
    semantics every tool in the JSON_LINES family ships with — the
    YAML descriptor sets ``-o /out/<name>`` so the file is the source
    of truth.

    Malformed JSONL lines are logged and skipped (fail-soft, per
    :func:`safe_load_jsonl`), so a single broken record cannot drop
    the entire scan.
    """
    raw = _read_canonical_bytes(
        artifacts_dir, canonical_name=canonical_name, tool_id=tool_id
    )
    source: bytes = raw if raw.strip() else stdout
    if not source or not source.strip():
        return
    yield from safe_load_jsonl(source, tool_id=tool_id, limit=limit)


# ---------------------------------------------------------------------------
# Sidecar persistence
# ---------------------------------------------------------------------------


_DEFAULT_SIDECAR_BUDGET: Final[int] = 8 * 1024 * 1024


def persist_jsonl_sidecar(
    artifacts_dir: Path,
    *,
    sidecar_name: str,
    evidence_records: Iterable[str],
    tool_id: str,
) -> None:
    """Write ``evidence_records`` (one per line) to ``sidecar_name``.

    Best-effort: any :class:`OSError` is logged and swallowed so a
    read-only filesystem cannot fail the parser.  The caller is
    expected to pass already-redacted JSON strings — the helper does
    NOT inspect the records' contents.
    """
    try:
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        sidecar_path = artifacts_dir / sidecar_name
        with sidecar_path.open("w", encoding="utf-8") as fh:
            for blob in evidence_records:
                fh.write(blob)
                fh.write("\n")
    except OSError as exc:
        _logger.warning(
            "parsers.jsonl_base.sidecar_write_failed",
            extra={
                "event": "parsers_jsonl_base_sidecar_write_failed",
                "tool_id": tool_id,
                "sidecar_name": sidecar_name,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


__all__ = [
    "iter_jsonl_records",
    "load_canonical_or_stdout_json",
    "persist_jsonl_sidecar",
    "safe_join_artifact",
]
