"""Common building blocks for sandbox tool-output parsers.

This module is intentionally thin: it provides the dataclasses, exception
types, and pure helpers that every concrete parser under
:mod:`src.sandbox.parsers` reuses. Keeping the surface area small (and free
of any I/O / global state) lets parsers remain referentially transparent —
``parse_xxx(stdout, stderr, artifacts_dir)`` is a pure function and can be
unit-tested with byte fixtures.

Design notes
------------
* :class:`ParserContext` carries optional metadata (``tool_id``,
  ``artifacts_dir``) that the dispatch layer fills in. Tool-specific public
  parser functions accept the trio ``(stdout, stderr, artifacts_dir)`` per
  the cycle plan; the dispatch wrapper materialises the context.

* :class:`ParseError` is raised only by helpers operating in ``strict=True``
  mode — the public ``parse_*`` functions are fail-soft by contract (they
  log structured warnings and skip malformed records), so an exception
  reaching the dispatch layer is treated as a programming bug, not a data
  bug. The dispatch layer catches it and degrades to ``[]`` so a single
  pathological tool run never takes the worker down.

* :data:`SENTINEL_UUID` is the placeholder that every parser uses for
  ``tenant_id`` / ``scan_id`` / ``asset_id`` / ``tool_run_id`` / ``id`` on
  the ``FindingDTO``. The downstream :class:`src.findings.normalizer.Normalizer`
  re-derives those identifiers from the ``NormalizationContext``, so the
  values produced here are intentionally inert.

* :data:`SENTINEL_CVSS_VECTOR` / :data:`SENTINEL_CVSS_SCORE` mirror the
  ``info``-severity defaults used by the normaliser. Keeping the constants
  in one place avoids drift between the parser and normaliser layers.

* All parsers are subject to the size caps in :data:`MAX_STDOUT_BYTES` /
  :data:`MAX_STDERR_BYTES` so a 1 GB stdout cannot exhaust worker memory.
  Oversized inputs are dropped with a structured warning.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final
from uuid import UUID

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
    FindingStatus,
    SSVCDecision,
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------


# Hard caps on raw bytes a parser will look at. The sandbox layer also caps
# tool output, but a defence-in-depth ceiling here protects the worker even
# when a parser is invoked outside the standard pipeline (CLI, tests).
MAX_STDOUT_BYTES: Final[int] = 25 * 1024 * 1024
MAX_STDERR_BYTES: Final[int] = 1 * 1024 * 1024


# Sentinel UUIDs used for FindingDTO identity / context fields that the
# parser layer cannot resolve. The downstream normaliser replaces them with
# real, deterministic UUIDs derived from the scan / asset / tool_run.
SENTINEL_UUID: Final[UUID] = UUID(int=0)


# Default CVSS vector / score for ``info`` severity findings. Mirrors the
# constants in :mod:`src.findings.normalizer` so the two layers stay in
# lock-step. Any change here must also be applied there.
SENTINEL_CVSS_VECTOR: Final[str] = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
SENTINEL_CVSS_SCORE: Final[float] = 0.0


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParserContext:
    """Read-only metadata threaded through the parser dispatch layer.

    Tool-specific public parser functions stay pure ``(stdout, stderr,
    artifacts_dir) -> list[FindingDTO]`` triples. The dispatch wrapper
    constructs a :class:`ParserContext` from its arguments; helpers in this
    module accept it directly when they need the ``tool_id`` for log
    correlation or branching.
    """

    tool_id: str
    artifacts_dir: Path
    stderr_preview: str = ""
    extras: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ParseError(Exception):
    """Raised by ``strict=True`` helpers on malformed input.

    Public ``parse_*`` functions are fail-soft and never propagate this
    error — they log a structured warning and skip the offending record.
    Dispatch wrappers catch any escaped :class:`ParseError` and degrade to
    ``[]`` so a single malformed payload cannot kill a worker.
    """


# ---------------------------------------------------------------------------
# Helpers — bytes / decoding
# ---------------------------------------------------------------------------


def safe_decode(raw: bytes | bytearray | None, *, limit: int) -> str:
    """Decode ``raw`` as UTF-8 with replacement, capped at ``limit`` bytes.

    Returns an empty string for ``None`` / empty input or when ``raw``
    exceeds ``limit``. Oversized inputs emit a structured ``WARNING`` so the
    drop is visible in observability.
    """
    if not raw:
        return ""
    if len(raw) > limit:
        _logger.warning(
            "parsers.safe_decode.oversize",
            extra={
                "event": "parsers_safe_decode_oversize",
                "size": len(raw),
                "limit": limit,
            },
        )
        return ""
    return bytes(raw).decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Helpers — JSON / JSONL loaders
# ---------------------------------------------------------------------------


def safe_load_jsonl(
    raw: bytes | bytearray | None,
    *,
    tool_id: str,
    strict: bool = False,
    limit: int = MAX_STDOUT_BYTES,
) -> Iterator[dict[str, Any]]:
    """Yield one JSON object per non-empty line in ``raw``.

    * ``strict=False`` (default): malformed lines are skipped with a
      structured ``WARNING parsers.jsonl.malformed`` log entry.
    * ``strict=True``: the first malformed line raises :class:`ParseError`.

    Non-dict JSON values (lists, scalars) are skipped silently — every
    parser in this package expects per-record dicts.
    """
    text = safe_decode(raw, limit=limit)
    if not text:
        return
    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            if strict:
                raise ParseError(f"malformed JSONL line at line {line_no}") from exc
            _logger.warning(
                "parsers.jsonl.malformed",
                extra={
                    "event": "parsers_jsonl_malformed",
                    "tool_id": tool_id,
                    "line_no": line_no,
                },
            )
            continue
        if isinstance(payload, dict):
            yield payload


def safe_load_json(
    raw: bytes | bytearray | None,
    *,
    tool_id: str,
    strict: bool = False,
    limit: int = MAX_STDOUT_BYTES,
) -> Any:
    """Load ``raw`` as a single JSON document.

    Returns ``None`` on malformed input when ``strict=False``; raises
    :class:`ParseError` when ``strict=True``. Returns ``None`` for empty /
    oversized input regardless of mode.
    """
    text = safe_decode(raw, limit=limit)
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        if strict:
            raise ParseError("malformed JSON document") from exc
        _logger.warning(
            "parsers.json.malformed",
            extra={
                "event": "parsers_json_malformed",
                "tool_id": tool_id,
            },
        )
        return None


# ---------------------------------------------------------------------------
# Helpers — FindingDTO factory
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    """Return current UTC time with timezone info (test-friendly seam)."""
    return datetime.now(tz=timezone.utc)


def make_finding_dto(
    *,
    finding_id: UUID = SENTINEL_UUID,
    category: FindingCategory,
    cwe: list[int],
    cvss_v3_vector: str = SENTINEL_CVSS_VECTOR,
    cvss_v3_score: float = SENTINEL_CVSS_SCORE,
    confidence: ConfidenceLevel = ConfidenceLevel.SUSPECTED,
    status: FindingStatus = FindingStatus.NEW,
    ssvc_decision: SSVCDecision = SSVCDecision.TRACK,
    owasp_wstg: list[str] | None = None,
    mitre_attack: list[str] | None = None,
    epss_score: float | None = None,
    kev_listed: bool = False,
) -> FindingDTO:
    """Construct a :class:`FindingDTO` with sentinel identity fields.

    The downstream :class:`src.findings.normalizer.Normalizer` replaces the
    sentinel ``tenant_id`` / ``scan_id`` / ``asset_id`` / ``tool_run_id`` /
    ``id`` with real values derived from the run context. Parsers therefore
    only need to populate the *finding-specific* fields (category, cwe,
    severity, evidence, …) and stay decoupled from the persistence layer.

    ``cwe`` must contain at least one positive integer (FindingDTO contract);
    callers should pass a sensible CWE for the finding category — e.g.
    ``[200]`` (Information Exposure) for technology disclosure findings.
    """
    if not cwe:
        raise ParseError("cwe must contain at least one positive integer")
    now = _utcnow()
    return FindingDTO(
        id=finding_id,
        tenant_id=SENTINEL_UUID,
        scan_id=SENTINEL_UUID,
        asset_id=SENTINEL_UUID,
        tool_run_id=SENTINEL_UUID,
        category=category,
        cwe=list(cwe),
        cvss_v3_vector=cvss_v3_vector,
        cvss_v3_score=cvss_v3_score,
        epss_score=epss_score,
        kev_listed=kev_listed,
        ssvc_decision=ssvc_decision,
        owasp_wstg=list(owasp_wstg or []),
        mitre_attack=list(mitre_attack or []),
        confidence=confidence,
        status=status,
        first_seen=now,
        last_seen=now,
    )


# ---------------------------------------------------------------------------
# Helpers — secret redaction + deterministic hashing
# ---------------------------------------------------------------------------


# Default minimum prefix kept when redacting a secret.  Picks up token-type
# prefixes (``ghp_``, ``AKIA``, ``sk_live_``) without leaking the entropy
# bits an attacker would need to reuse the credential.
_REDACTION_PREFIX_DEFAULT: Final[int] = 4
_REDACTION_SUFFIX_DEFAULT: Final[int] = 2
_REDACTION_MIN_LEN_FOR_PARTIAL: Final[int] = 12


def redact_secret(
    match: str | None,
    *,
    prefix: int = _REDACTION_PREFIX_DEFAULT,
    suffix: int = _REDACTION_SUFFIX_DEFAULT,
) -> str | None:
    """Return a redacted preview of a secret string.

    Keeps ``prefix`` leading and ``suffix`` trailing characters and
    masks the middle with ``***REDACTED({len})***`` where ``{len}`` is
    the **original** string length.  This gives operators enough signal
    for triage while keeping the raw secret out of any sidecar / log /
    PDF that might leak downstream.

    Strings shorter than :data:`_REDACTION_MIN_LEN_FOR_PARTIAL` (default
    12 chars) collapse to ``***REDACTED({len})***`` with no leading /
    trailing reveal — short tokens have so little entropy that any
    non-trivial reveal effectively prints the secret.

    ``None`` / empty strings return ``None``.
    """
    if not match:
        return None
    length = len(match)
    if length < _REDACTION_MIN_LEN_FOR_PARTIAL:
        return f"***REDACTED({length})***"
    head = match[: max(0, prefix)]
    tail = match[-max(0, suffix) :] if suffix > 0 else ""
    return f"{head}***REDACTED({length})***{tail}"


def stable_hash_12(text: str) -> str:
    """Return a deterministic 12-char hex digest of ``text``.

    Mirrors the contract used by the per-parser ``_stable_hash``
    helpers (Nuclei, Dalfox, Trivy, Semgrep): SHA-256 truncated to 12
    hex chars so dedup keys stay byte-identical across CI workers
    regardless of ``PYTHONHASHSEED``.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


__all__ = [
    "MAX_STDERR_BYTES",
    "MAX_STDOUT_BYTES",
    "SENTINEL_CVSS_SCORE",
    "SENTINEL_CVSS_VECTOR",
    "SENTINEL_UUID",
    "ParseError",
    "ParserContext",
    "make_finding_dto",
    "redact_secret",
    "safe_decode",
    "safe_load_json",
    "safe_load_jsonl",
    "stable_hash_12",
]
