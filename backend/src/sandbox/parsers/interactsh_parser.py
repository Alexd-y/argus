"""Parser for interactsh-client / oastify-client JSONL output (ARG-017 §4.11).

interactsh / oastify emit one JSON envelope per OOB callback the OAST plane
correlated to a sandboxed payload. The shape is small and stable:

* ``protocol``        — ``dns`` / ``http`` / ``smtp`` (and the rarely-used
  ``smb`` / ``responder`` variants — the parser folds everything outside the
  three primaries onto :class:`FindingCategory.INFO`).
* ``unique-id``       — the per-token correlation handle interactsh issued
  before the scan started; identifies which sandbox payload triggered the
  callback. Optional in some early builds; we synthesise a stable hash from
  the protocol + remote_address + minute bucket when missing.
* ``full-id``         — the full OAST hostname the callback hit (e.g.
  ``c2vhx10sxxx.oast.argus.local``). Always carried verbatim into the
  evidence sidecar so the operator can pivot.
* ``raw-request``     — the exact wire bytes of the offending probe (HTTP
  request line + headers; SMTP DATA stream; DNS query name).
* ``raw-response``    — the exact wire bytes of what the OAST plane echoed
  back (often empty for DNS, the canned 200 OK for HTTP).
* ``remote-address``  — IP[:port] of the originating host. Critical for
  attribution (a callback from the target's CIDR vs the operator's egress
  IP tells two very different stories).
* ``timestamp``       — RFC-3339 string of the moment the OAST plane
  received the callback. Used in the dedup minute bucket and in the
  sidecar.
* ``q-type``          — DNS question type (``A`` / ``AAAA`` / ``ANY``);
  optional, only present for ``protocol=dns``.
* ``smtp-from``       — sender email, only present for ``protocol=smtp``;
  preserved in evidence for victim-side attribution.

Severity / confidence ladder (Backlog/dev1_md §4.11 + §10):

* HTTP / SMTP callbacks ⇒ :class:`FindingCategory.SSRF` /
  :class:`ConfidenceLevel.CONFIRMED`. The OAST plane only relays callbacks
  the *target* generated, so receiving an HTTP request on the canary URL
  proves the SSRF chain fired end-to-end.
* DNS callbacks ⇒ :class:`FindingCategory.INFO` /
  :class:`ConfidenceLevel.LIKELY`. DNS-only callbacks frequently come from
  passive resolvers (Google DNS / 1.1.1.1 / corporate caches) — the
  underlying SSRF / OAST chain is plausible but not yet exploitable on its
  own.

Parse strategy contract (mandated by :mod:`src.sandbox.parsers.__init__`):

1. ``artifacts_dir / "interactsh.jsonl"`` is the canonical path interactsh
   writes when invoked with ``-o /out/interactsh.jsonl``.
2. ``stdout`` is the fallback when the operator forgot ``-o`` (interactsh's
   ``-v`` mode mirrors records to stdout).
3. ``stderr`` is accepted for parser-dispatch signature symmetry but
   intentionally not consumed — interactsh uses stderr for its banner /
   poll status only.

Determinism:

* Records are deduped on
  ``(unique_id, protocol, remote_address, timestamp_minute_bucket)`` so
  the same callback re-mirrored to stdout and to the JSONL file does NOT
  emit two findings.
* Output is sorted by ``(severity_rank desc, protocol, remote_address,
  full_id, timestamp)`` so the sidecar bytes are reproducible across
  test runs and CI workers.
* Synthetic IDs use SHA-256 (truncated to 12 hex chars) so identifier
  determinism survives parallel processes / different ``PYTHONHASHSEED``.

Hard caps:

* :data:`_MAX_FINDINGS` defends the worker against a misconfigured
  campaign that fires tens of thousands of OAST tokens at a wildcard
  subdomain.
* :data:`_MAX_EVIDENCE_BYTES` truncates the per-finding ``raw-request`` /
  ``raw-response`` carry into the sidecar so a 200 KiB SMTP DATA stream
  cannot balloon ``interactsh_findings.jsonl`` past the worker's evidence
  budget.

Failure model (mirrors the dispatch layer):

* Malformed JSON lines are skipped with a structured warning
  (``parsers.jsonl.malformed``). One bad line never aborts the run.
* OS errors writing the sidecar are logged and swallowed — the
  FindingDTO list still flows back to the worker.
* No exception escapes the public ``parse_interactsh_jsonl`` boundary
  outside the dispatch layer's catch-all.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final, TypeAlias

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
)
from src.sandbox.parsers._base import (
    make_finding_dto,
    safe_load_jsonl,
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public constants — surfaced for tests + downstream evidence pipeline.
# ---------------------------------------------------------------------------


# Single sidecar shared between interactsh-client and oastify-client; the
# wire shape they emit is identical (oastify mirrors interactsh's JSONL
# protocol verbatim — that's the point of the project).
EVIDENCE_SIDECAR_NAME: Final[str] = "interactsh_findings.jsonl"


# Hard cap on emitted findings. A wildcard SSRF campaign against a
# poorly-isolated target can legitimately yield thousands of OAST hits in
# a few seconds; capping defends the worker even when the OAST plane
# replays its full backlog at startup.
_MAX_FINDINGS: Final[int] = 5_000


# Hard cap on raw-request / raw-response bytes kept verbatim in the
# sidecar. 4 KiB matches the §4.10 dalfox / §4.8 nuclei precedent and
# is large enough to retain the request line + header block.
_MAX_EVIDENCE_BYTES: Final[int] = 4 * 1024


# Canonical artifact path interactsh writes with ``-o /out/interactsh.jsonl``.
_CANONICAL_ARTIFACT: Final[str] = "interactsh.jsonl"


# CWE / WSTG anchors for every emitted finding (ARG-017 §4.11). CWE-918
# (SSRF) is the universal floor; the OWASP WSTG INPV-19 scenario covers
# server-side request forgery / OOB exfiltration.
_CWE_HINTS: Final[tuple[int, ...]] = (918,)
_OWASP_WSTG: Final[tuple[str, ...]] = ("WSTG-INPV-19",)


# ---------------------------------------------------------------------------
# Severity / confidence / category mapping
# ---------------------------------------------------------------------------


# Protocol → (FindingCategory, ConfidenceLevel, severity_rank) mapping.
# severity_rank drives the deterministic sort order in :func:`_emit`.
# HTTP and SMTP both indicate the *target* actually fetched the canary,
# so they CONFIRM SSRF; DNS-only callbacks frequently come from passive
# resolvers (Google DNS / corp caches) so they LIKELY indicate the
# underlying chain but do not prove exploitability on their own.
_PROTOCOL_MAP: Final[dict[str, tuple[FindingCategory, ConfidenceLevel, int]]] = {
    "http": (FindingCategory.SSRF, ConfidenceLevel.CONFIRMED, 3),
    "https": (FindingCategory.SSRF, ConfidenceLevel.CONFIRMED, 3),
    "smtp": (FindingCategory.SSRF, ConfidenceLevel.CONFIRMED, 3),
    "smtps": (FindingCategory.SSRF, ConfidenceLevel.CONFIRMED, 3),
    "dns": (FindingCategory.INFO, ConfidenceLevel.LIKELY, 1),
    # SMB / responder / FTP variants are folded onto INFO + SUSPECTED so a
    # legitimate but rare protocol does not crash the parser. The §4.11
    # backlog only mandates HTTP / DNS / SMTP support; everything else is
    # an evidence-only forward.
    "smb": (FindingCategory.INFO, ConfidenceLevel.LIKELY, 0),
    "ftp": (FindingCategory.INFO, ConfidenceLevel.LIKELY, 0),
    "responder": (FindingCategory.INFO, ConfidenceLevel.LIKELY, 0),
    "ldap": (FindingCategory.INFO, ConfidenceLevel.LIKELY, 0),
}


# Protocol → CVSS v3.1 base score map (ARG-016/017 reviewer H1).
#
# The OAST callback is end-to-end proof that a sandboxed payload reached
# the OAST plane: the per-protocol score reflects the realistic blast
# radius of that confirmation:
#
# * ``http`` / ``https`` (7.5)  — blind SSRF / RCE callback proven from
#   the target.
# * ``smb`` (7.5)               — NTLM relay / SMB exfiltration vector.
# * ``smtp`` / ``smtps`` (7.0)  — outbound mail allowed; usable for
#   exfiltration / phishing chain.
# * ``ldap`` (7.0)              — JNDI / LDAP-injection callback path.
# * ``dns`` (6.5)               — DNS exfiltration / blind probe; the
#   underlying chain is plausible but a passive resolver can deliver
#   the same callback without target-side execution, hence one notch
#   below HTTP.
# * ``ftp`` (6.0)               — outbound FTP; rarer in modern targets
#   but still proves data-exfil capability.
# * ``responder`` (6.0)         — lab-only mirror; treated as info-grade
#   confirmation.
#
# Unknown / missing protocol falls back to :data:`_INTERACTSH_DEFAULT_CVSS`
# (6.0) so any future OAST plane addition still produces a non-info
# baseline finding.
_PROTOCOL_TO_CVSS: Final[dict[str, float]] = {
    "http": 7.5,
    "https": 7.5,
    "smb": 7.5,
    "smtp": 7.0,
    "smtps": 7.0,
    "ldap": 7.0,
    "dns": 6.5,
    "ftp": 6.0,
    "responder": 6.0,
}
_INTERACTSH_DEFAULT_CVSS: Final[float] = 6.0


# Stable dedup key shape. Module-level alias keeps the signature short
# in the dedup loop.
DedupKey: TypeAlias = tuple[str, str, str, str]


# Timestamp formats interactsh / oastify can emit (RFC-3339 with or
# without nanosecond precision; with or without an explicit zone). All
# three variants are normalised to UTC by :func:`_minute_bucket`.
_TIMESTAMP_NS_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<base>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.\d+)?"
    r"(?P<tz>Z|[+\-]\d{2}:\d{2}|[+\-]\d{4})?$"
)


# ---------------------------------------------------------------------------
# Public entry point — signature mandated by the dispatch layer:
# ``(stdout, stderr, artifacts_dir, tool_id) -> list[FindingDTO]``.
# ---------------------------------------------------------------------------


def parse_interactsh_jsonl(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate interactsh / oastify JSONL output into FindingDTOs.

    Resolution order for the JSONL stream:

    1. ``artifacts_dir / "interactsh.jsonl"`` (canonical: written when
       interactsh is invoked with ``-o /out/interactsh.jsonl``).
    2. ``stdout`` fallback (some operators run interactsh without ``-o``
       so the JSONL lands on stdout instead).

    ``stderr`` is accepted for parser-dispatch signature symmetry but
    intentionally not consumed — interactsh uses stderr for its banner
    and poll-status updates only.

    Both sources can be present simultaneously (operator passed ``-o``
    AND ``-v``); when this happens the records are merged through the
    same dedup pass so the operator does not see duplicate findings.
    """
    del stderr  # intentionally unused — interactsh stderr is banner only

    raw_records = list(
        _load_records(stdout=stdout, artifacts_dir=artifacts_dir, tool_id=tool_id)
    )
    if not raw_records:
        return []

    normalised = list(_iter_normalised(raw_records, tool_id=tool_id))
    if not normalised:
        return []

    return _emit(normalised, artifacts_dir=artifacts_dir, tool_id=tool_id)


# ---------------------------------------------------------------------------
# Source resolution — canonical artifact + stdout merge
# ---------------------------------------------------------------------------


def _load_records(
    *,
    stdout: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> Iterator[dict[str, Any]]:
    """Yield raw dict records from the canonical artifact AND/OR stdout.

    Both sources may legitimately be populated (operator combined
    ``-o /out/interactsh.jsonl`` with ``-v`` to mirror records to
    stdout). The dedup pass downstream collapses the resulting
    duplicates.
    """
    canonical = _safe_join(artifacts_dir, _CANONICAL_ARTIFACT)
    if canonical is not None and canonical.is_file():
        try:
            raw = canonical.read_bytes()
        except OSError as exc:
            _logger.warning(
                "interactsh_parser.canonical_read_failed",
                extra={
                    "event": "interactsh_parser_canonical_read_failed",
                    "tool_id": tool_id,
                    "path": _CANONICAL_ARTIFACT,
                    "error_type": type(exc).__name__,
                },
            )
            raw = b""
        if raw.strip():
            yield from safe_load_jsonl(raw, tool_id=tool_id)
    if stdout and stdout.strip():
        yield from safe_load_jsonl(stdout, tool_id=tool_id)


def _safe_join(base: Path, name: str) -> Path | None:
    """Defensive ``base / name`` that refuses path-traversal segments."""
    if "/" in name or "\\" in name or ".." in name:
        return None
    return base / name


# ---------------------------------------------------------------------------
# Normalisation — interactsh JSONL → internal record dict
# ---------------------------------------------------------------------------


def _iter_normalised(
    records: Iterable[dict[str, Any]],
    *,
    tool_id: str,
) -> Iterator[dict[str, Any]]:
    """Yield internal record dicts ready for dedup + finding building."""
    for raw in records:
        try:
            normalised = _normalise_one(raw)
        except _SkipRecord as exc:
            _logger.warning(
                "interactsh_parser.record_skipped",
                extra={
                    "event": "interactsh_parser_record_skipped",
                    "tool_id": tool_id,
                    "reason": exc.reason,
                },
            )
            continue
        if normalised is None:
            continue
        yield normalised


class _SkipRecord(Exception):
    """Raised by :func:`_normalise_one` to signal a deliberate skip."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _normalise_one(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Project one raw interactsh record onto the internal schema.

    Skips records that do not carry a recognisable protocol — the
    interactsh ``poll`` keepalive frames the parser legitimately ignores
    fall through this branch.
    """
    protocol_raw = raw.get("protocol")
    if not isinstance(protocol_raw, str) or not protocol_raw.strip():
        return None
    protocol = protocol_raw.strip().lower()

    full_id_raw = raw.get("full-id") or raw.get("full_id") or ""
    full_id = str(full_id_raw).strip()

    unique_id_raw = raw.get("unique-id") or raw.get("unique_id") or ""
    unique_id = str(unique_id_raw).strip()

    remote_addr_raw = raw.get("remote-address") or raw.get("remote_address") or ""
    remote_addr = str(remote_addr_raw).strip()

    timestamp_raw = raw.get("timestamp") or ""
    timestamp = str(timestamp_raw).strip()

    raw_request = _coerce_to_text(raw.get("raw-request") or raw.get("raw_request"))
    raw_response = _coerce_to_text(raw.get("raw-response") or raw.get("raw_response"))

    q_type_raw = raw.get("q-type") or raw.get("q_type")
    q_type = str(q_type_raw).strip().upper() if isinstance(q_type_raw, str) else None

    smtp_from_raw = raw.get("smtp-from") or raw.get("smtp_from")
    smtp_from = str(smtp_from_raw).strip() if isinstance(smtp_from_raw, str) else None

    if not unique_id and not full_id and not remote_addr:
        # Defence-in-depth: a record that carries NO attribution is
        # useless for OAST correlation (it could come from any internal
        # noise). Skip with a deliberate signal so the operator notices
        # via the structured warning.
        raise _SkipRecord("record carries no unique-id / full-id / remote-address")

    return {
        "protocol": protocol,
        "full_id": full_id,
        "unique_id": unique_id,
        "remote_address": remote_addr,
        "timestamp": timestamp,
        "raw_request": raw_request,
        "raw_response": raw_response,
        "q_type": q_type,
        "smtp_from": smtp_from,
    }


def _coerce_to_text(value: Any) -> str:
    """Coerce interactsh's ``raw-request`` / ``raw-response`` into a string.

    Modern builds carry the wire bytes as a base64-decoded string (it's
    JSON-safe). Older builds emitted a list of integers (one per byte)
    that we reassemble; everything else is folded to ``str(value)`` so
    the evidence still surfaces in the sidecar even when interactsh
    changes shape under us.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list | tuple):
        try:
            return bytes(int(b) & 0xFF for b in value).decode("utf-8", errors="replace")
        except (TypeError, ValueError):
            return ""
    return str(value)


# ---------------------------------------------------------------------------
# Dedup + sort + sidecar persistence
# ---------------------------------------------------------------------------


def _emit(
    records: list[dict[str, Any]],
    *,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Common pipeline: dedup → cap → sort → build FindingDTO + sidecar."""

    seen: set[DedupKey] = set()
    keyed: list[tuple[tuple[int, str, str, str, str], DedupKey, FindingDTO, str]] = []

    for record in records:
        key = _dedup_key(record)
        if key in seen:
            continue
        seen.add(key)

        finding = _build_finding(record)
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        sort_key = _sort_key(record)
        keyed.append((sort_key, key, finding, evidence_blob))

        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "interactsh_parser.cap_reached",
                extra={
                    "event": "interactsh_parser_cap_reached",
                    "tool_id": tool_id,
                    "cap": _MAX_FINDINGS,
                },
            )
            break

    keyed.sort(key=lambda item: item[0])
    if keyed:
        _persist_evidence_sidecar(
            artifacts_dir,
            tool_id=tool_id,
            evidence_records=[blob for _, _, _, blob in keyed],
        )

    return [finding for _, _, finding, _ in keyed]


def _dedup_key(record: dict[str, Any]) -> DedupKey:
    """Stable dedup key: (unique_id_or_synth, protocol, remote_address, minute_bucket).

    When ``unique_id`` is missing the synthetic key keeps the record
    unique on the (full_id, raw_request_prefix) tuple — two callbacks
    that share remote address + minute but came from different OAST
    tokens still produce two findings.
    """
    unique_id = record.get("unique_id") or _synth_unique_id(record)
    protocol = record.get("protocol", "")
    remote_addr = record.get("remote_address", "")
    minute = _minute_bucket(record.get("timestamp", ""))
    return (str(unique_id), str(protocol), str(remote_addr), minute)


def _synth_unique_id(record: dict[str, Any]) -> str:
    """Synthesize a deterministic unique-id when interactsh did not emit one.

    Anchored on SHA-256 (12 hex chars) of the
    ``(full_id, protocol, remote_address, raw_request_prefix)`` tuple
    so the id stays stable across reruns of the same input.
    """
    full_id = str(record.get("full_id", ""))
    protocol = str(record.get("protocol", ""))
    remote = str(record.get("remote_address", ""))
    request_prefix = str(record.get("raw_request", ""))[:128]
    return _stable_hash(f"{full_id}|{protocol}|{remote}|{request_prefix}")


def _minute_bucket(timestamp: str) -> str:
    """Return a deterministic minute-bucket string for ``timestamp``.

    Two callbacks delivered within the same wall-clock minute on the
    same (unique-id, protocol, remote-address) tuple are treated as
    duplicates — interactsh re-mirrors records from disk on restart,
    and the OAST poll loop can deliver the same callback twice.
    Falls back to the literal string when the timestamp cannot be
    parsed so a malformed timestamp does not accidentally fold every
    record into one bucket.
    """
    if not timestamp:
        return ""
    parsed = _parse_timestamp(timestamp)
    if parsed is None:
        return timestamp
    rounded = parsed.replace(second=0, microsecond=0)
    return rounded.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")


def _parse_timestamp(timestamp: str) -> datetime | None:
    """Parse an interactsh timestamp into a UTC ``datetime``.

    Accepts:

    * ``2026-04-19T12:34:56Z``
    * ``2026-04-19T12:34:56.123456789Z`` — nanosecond precision; the
      sub-second part is truncated to microseconds for ``datetime``
      compatibility.
    * ``2026-04-19T12:34:56+00:00`` / ``2026-04-19T12:34:56+0000``
    """
    match = _TIMESTAMP_NS_RE.match(timestamp)
    if not match:
        return None
    base = match.group("base")
    tz = match.group("tz") or "Z"
    if tz == "Z":
        tz = "+00:00"
    elif len(tz) == 5 and (tz[0] == "+" or tz[0] == "-"):
        tz = f"{tz[:3]}:{tz[3:]}"
    try:
        return datetime.fromisoformat(f"{base}{tz}")
    except ValueError:
        return None


def _sort_key(record: dict[str, Any]) -> tuple[int, str, str, str, str]:
    """Deterministic sort key (severity_rank desc → protocol → addr → id → ts)."""
    protocol = str(record.get("protocol", ""))
    _, _, rank = _PROTOCOL_MAP.get(
        protocol, (FindingCategory.INFO, ConfidenceLevel.SUSPECTED, 0)
    )
    return (
        -rank,
        protocol,
        str(record.get("remote_address", "")),
        str(record.get("full_id", "")),
        str(record.get("timestamp", "")),
    )


def _build_finding(record: dict[str, Any]) -> FindingDTO:
    """Build a FindingDTO from a normalised interactsh record.

    Lifts ``cvss_v3_score`` from :data:`_PROTOCOL_TO_CVSS` so the
    downstream :class:`Prioritizer` can place verified OAST callbacks
    above :attr:`PriorityTier.P4_INFO` (ARG-016/017 reviewer H1).
    """
    protocol = str(record.get("protocol", ""))
    category, confidence, _ = _PROTOCOL_MAP.get(
        protocol, (FindingCategory.INFO, ConfidenceLevel.SUSPECTED, 0)
    )
    cvss_score = _PROTOCOL_TO_CVSS.get(protocol, _INTERACTSH_DEFAULT_CVSS)
    return make_finding_dto(
        category=category,
        cwe=list(_CWE_HINTS),
        cvss_v3_score=cvss_score,
        owasp_wstg=list(_OWASP_WSTG),
        confidence=confidence,
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    """Build a compact evidence JSON for downstream redaction + persistence."""
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": "oast_callback",
        "protocol": record.get("protocol"),
        "full_id": record.get("full_id"),
        "unique_id": record.get("unique_id"),
        "remote_address": record.get("remote_address"),
        "timestamp": record.get("timestamp"),
        "q_type": record.get("q_type"),
        "smtp_from": record.get("smtp_from"),
        "raw_request": _truncate_text(record.get("raw_request") or ""),
        "raw_response": _truncate_text(record.get("raw_response") or ""),
        "synthetic_id": _synth_unique_id(record),
    }
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if value is None:
            continue
        if isinstance(value, list | tuple) and not value:
            continue
        if value == "":
            continue
        cleaned[key] = value
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


def _persist_evidence_sidecar(
    artifacts_dir: Path,
    *,
    tool_id: str,
    evidence_records: list[str],
) -> None:
    """Best-effort write of the per-finding evidence sidecar JSONL."""
    try:
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        sidecar_path = artifacts_dir / EVIDENCE_SIDECAR_NAME
        with sidecar_path.open("w", encoding="utf-8") as fh:
            for blob in evidence_records:
                fh.write(blob)
                fh.write("\n")
    except OSError as exc:
        _logger.warning(
            "interactsh_parser.evidence_sidecar_write_failed",
            extra={
                "event": "interactsh_parser_evidence_sidecar_write_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


# ---------------------------------------------------------------------------
# Helpers — text truncation + stable hashing
# ---------------------------------------------------------------------------


def _truncate_text(value: str) -> str:
    """Cap a single string at :data:`_MAX_EVIDENCE_BYTES` UTF-8 bytes."""
    if not value:
        return ""
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= _MAX_EVIDENCE_BYTES:
        return value
    truncated = encoded[:_MAX_EVIDENCE_BYTES]
    return truncated.decode("utf-8", errors="replace") + "...[truncated]"


def _stable_hash(text: str) -> str:
    """Return a cross-process deterministic 12-char hex digest of ``text``.

    ``hash()`` is randomised per Python interpreter via ``PYTHONHASHSEED``,
    so the same interactsh fixture would produce different synthesized
    unique-ids between processes — breaking sidecar byte determinism in
    CI. Anchored on SHA-256 (truncated to 12 hex chars / 48 bits) the
    digest stays constant across interpreters and OSes; collisions are
    cosmetic (sidecar synthetic_id) and 2^48 wide enough for any
    realistic OAST campaign.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_interactsh_jsonl",
]
