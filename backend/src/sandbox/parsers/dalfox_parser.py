"""Parser for dalfox JSON output (Backlog/dev1_md §4.10 — ARG-016).

§4.10 ships five XSS scanners; this module covers the canonical
JSON-emitting flagship:

* **dalfox** (``dalfox url {url} -F json -o /out/dalfox.json``) —
  hahwul/dalfox parameter-aware XSS scanner with optional DOM
  mining (``--mining-dom``), payload mining
  (``--mining-dict``), and deep DOM traversal
  (``--deep-domxss``).

The remaining four §4.10 tools (``xsstrike``, ``kxss``, ``xsser``,
``playwright_xss_verify``) ship without parsers in Cycle 2 — their
YAMLs declare the appropriate ``parse_strategy`` (``json_object`` for
xsstrike / xsser / playwright; ``text_lines`` for kxss) and the
dispatch layer emits ``parsers.dispatch.unmapped_tool`` until the
Cycle 3 XSS-parser cluster lands.

Dalfox output shape
-------------------
The ``-F json`` envelope is either a top-level ``{"results": [...]}``
object (newer dalfox builds) or a bare top-level array (older builds).
Each result element carries:

.. code-block:: json

    {
      "type":             "V",                    // V=Verified, R=Reflected, S=Stored
      "url":              "https://target/?q=...",
      "method":           "GET",
      "param":            "q",
      "payload":          "><script>alert(1)</script>",
      "evidence":         "code snippet from response",
      "severity":         "high",                 // dalfox-side severity
      "poc":              "...",
      "tag":              "...",
      "cwe":              ["CWE-79"],
      "category":         "xss",
      "matched_signature":"...",
      "data":             "extra info"
    }

Translation rules
-----------------
* ``severity`` (low/medium/high/critical) →
  :class:`FindingCategory` and :class:`ConfidenceLevel`:
  - ``type=V`` (Verified) → ``CONFIRMED`` confidence,
    :class:`FindingCategory.XSS`.
  - ``type=S`` (Stored)   → ``LIKELY`` confidence,
    :class:`FindingCategory.XSS`.
  - ``type=R`` (Reflected) → ``SUSPECTED`` confidence,
    :class:`FindingCategory.INFO` (reflected payload without proven
    JS execution context).
* ``cwe`` from ``result.cwe[]`` (string ``"CWE-79"`` or numeric
  ``79`` accepted), defaults to ``[79]`` (CWE-79: Improper
  Neutralization of Input During Web Page Generation — XSS).
* ``owasp_wstg`` → ``["WSTG-INPV-01", "WSTG-INPV-02"]`` (Reflected /
  Stored XSS).

Dedup
-----
Records collapse on a stable key:

* ``(url, method, param, payload[:200])``

Sorting is deterministic on the dedup key so two runs against the
same fixture produce byte-identical sidecars.

Hard cap at :data:`_MAX_FINDINGS` defends the worker against a
runaway dalfox run with ``--mining-dict`` enabled (every payload in
the dict can technically surface as a separate result).

Sidecar
-------
Every emitted record is mirrored into
``artifacts_dir / "dalfox_findings.jsonl"`` for the downstream
evidence pipeline. Each record carries its source ``tool_id``
(``dalfox``).

Empty-result runs do not emit a sidecar (no findings → no file) so
``ls`` on the artifacts dir does not surface a confusing zero-byte
companion.

Failure model
-------------
Fail-soft by contract:

* Missing ``dalfox.json`` falls back to stdout parsing.
* Malformed JSON returns ``[]`` after a structured warning.
* OS errors writing the sidecar are logged and swallowed.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Final, TypeAlias

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
)
from src.sandbox.parsers._base import (
    make_finding_dto,
    safe_load_json,
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public constants — surfaced for tests + downstream evidence pipeline.
# ---------------------------------------------------------------------------


EVIDENCE_SIDECAR_NAME: Final[str] = "dalfox_findings.jsonl"


# Hard cap on emitted findings. A dalfox run with ``--mining-dict``
# against a parameter-rich target can legitimately surface thousands
# of payload permutations; capping defends the worker against a
# misconfigured wordlist.
_MAX_FINDINGS: Final[int] = 5_000


# Hard cap on individual evidence fields kept verbatim. Keeps the
# sidecar bounded even when dalfox echoes a 50 KiB payload chain.
_MAX_EVIDENCE_BYTES: Final[int] = 4 * 1024


# Cap on payload bytes carried into the dedup key so a multi-MB
# payload (legitimate but rare) does not balloon the dedup set.
_DEDUP_PAYLOAD_LEN: Final[int] = 200


# Stable dedup key shape: (url, method, param, payload_prefix).
DedupKey: TypeAlias = tuple[str, str, str, str]


# Severity bucket used when sorting (descending). ``critical`` sits
# above ``high`` so the most pressing findings end up at the top of
# both the FindingDTO list and the sidecar.
_SEVERITY_RANK: Final[dict[str, int]] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


# Default CWE for an XSS finding when dalfox does not surface one
# inline. Matches the §4.10 backlog hint set.
_DEFAULT_CWE: Final[tuple[int, ...]] = (79,)
_OWASP_WSTG: Final[tuple[str, ...]] = ("WSTG-INPV-01", "WSTG-INPV-02")


# Severity → CVSS v3.1 base score map (ARG-016/017 reviewer H1).
#
# Without this map every dalfox finding lands at the parser-layer sentinel
# ``cvss_v3_score=0.0``, which the downstream :class:`Prioritizer` flattens
# to :attr:`PriorityTier.P4_INFO` regardless of XSS class — a verified
# stored XSS would then rank below an info-level header banner.
#
# The numeric anchors line up with the canonical CVSS v3.1 reflected /
# stored / DOM XSS references published in Backlog/dev1_md §11 (priority
# weighting) and the dalfox upstream severity buckets:
#
# * ``critical`` (9.6) — stored XSS on an authenticated admin endpoint
#   (full account takeover).
# * ``high`` (7.5)     — verified reflected / stored XSS with a working
#   ``alert(...)`` PoC.
# * ``medium`` (6.1)   — reflected XSS without a confirmed bypass.
# * ``low`` (4.3)      — reflected payload, no impactful execution
#   context (e.g. attribute escape only).
# * ``info`` (0.0)     — sentinel, defers to the normaliser.
#
# Unknown / missing severity falls back to ``medium`` so the prioritiser
# treats them as "needs triage" rather than info-noise.
_DALFOX_SEVERITY_TO_CVSS: Final[dict[str, float]] = {
    "critical": 9.6,
    "high": 7.5,
    "medium": 6.1,
    "low": 4.3,
    "info": 0.0,
}
_DALFOX_DEFAULT_CVSS: Final[float] = 6.1


# Type → (category, confidence) mapping.
_TYPE_MAP: Final[dict[str, tuple[FindingCategory, ConfidenceLevel]]] = {
    "V": (FindingCategory.XSS, ConfidenceLevel.CONFIRMED),
    "S": (FindingCategory.XSS, ConfidenceLevel.LIKELY),
    "R": (FindingCategory.INFO, ConfidenceLevel.SUSPECTED),
}


# ---------------------------------------------------------------------------
# Public entry point — signature mandated by the dispatch layer:
# ``(stdout, stderr, artifacts_dir, tool_id) -> list[FindingDTO]``.
# ---------------------------------------------------------------------------


def parse_dalfox_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate dalfox ``-F json`` output into FindingDTOs.

    Resolution order for the JSON blob:

    1. ``artifacts_dir / "dalfox.json"`` (canonical: dalfox writes
       there when invoked with ``-o /out/dalfox.json``).
    2. ``stdout`` fallback (some operators run dalfox without
       ``-o`` so the JSON lands on stdout instead).

    ``stderr`` is accepted for parser dispatch signature symmetry
    but intentionally not consumed — dalfox uses stderr for its
    progress bar / banner only.
    """
    del stderr
    payload = _load_payload(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        tool_id=tool_id,
    )
    if payload is None:
        return []
    raw_results = list(_iter_raw_results(payload))
    if not raw_results:
        return []
    records = list(_iter_normalised(raw_results, tool_id=tool_id))
    return _emit(records, artifacts_dir=artifacts_dir, tool_id=tool_id)


# ---------------------------------------------------------------------------
# Pipeline — dedup + sort + sidecar persistence
# ---------------------------------------------------------------------------


def _emit(
    records: list[dict[str, Any]],
    *,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Common pipeline: dedup → cap → sort → build FindingDTO + sidecar."""

    seen: set[DedupKey] = set()
    keyed: list[tuple[tuple[int, str, str, str], DedupKey, FindingDTO, str]] = []

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
                "dalfox_parser.cap_reached",
                extra={
                    "event": "dalfox_parser_cap_reached",
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
    """Stable dedup key for a normalised dalfox record."""
    url = str(record.get("url", ""))
    method = str(record.get("method", "GET")).upper()
    param = str(record.get("param", ""))
    payload = str(record.get("payload", ""))[:_DEDUP_PAYLOAD_LEN]
    return (url, method, param, payload)


def _sort_key(record: dict[str, Any]) -> tuple[int, str, str, str]:
    """Deterministic sort key (severity desc → url → param → payload)."""
    severity = str(record.get("severity", "info")).lower()
    rank = _SEVERITY_RANK.get(severity, 0)
    # Negative rank so descending severity is achieved by the default
    # ascending sort.
    return (
        -rank,
        str(record.get("url", "")),
        str(record.get("param", "")),
        str(record.get("payload", ""))[:_DEDUP_PAYLOAD_LEN],
    )


def _build_finding(record: dict[str, Any]) -> FindingDTO:
    """Map a normalised dalfox record to a FindingDTO.

    Lifts ``cvss_v3_score`` from :data:`_DALFOX_SEVERITY_TO_CVSS` so the
    downstream :class:`Prioritizer` can place verified XSS findings above
    :attr:`PriorityTier.P4_INFO` (ARG-016/017 reviewer H1).
    """
    finding_type = str(record.get("type", "R")).upper()
    category, confidence = _TYPE_MAP.get(
        finding_type, (FindingCategory.INFO, ConfidenceLevel.SUSPECTED)
    )
    cwe_list = list(record.get("cwe") or _DEFAULT_CWE)
    severity = str(record.get("severity", "medium")).lower()
    cvss_score = _DALFOX_SEVERITY_TO_CVSS.get(severity, _DALFOX_DEFAULT_CVSS)
    return make_finding_dto(
        category=category,
        cwe=cwe_list,
        cvss_v3_score=cvss_score,
        owasp_wstg=list(_OWASP_WSTG),
        confidence=confidence,
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    """Build a compact evidence JSON for downstream redaction + persistence."""
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": "dalfox_xss",
        "type": record.get("type"),
        "severity": record.get("severity"),
        "url": record.get("url"),
        "method": record.get("method"),
        "param": record.get("param"),
        "payload": _truncate_text(record.get("payload") or ""),
        "evidence_snippet": _truncate_text(record.get("evidence_snippet") or ""),
        "poc": _truncate_text(record.get("poc") or ""),
        "tag": record.get("tag"),
        "category": record.get("dalfox_category"),
        "cwe": record.get("cwe"),
        "matched_signature": record.get("matched_signature"),
        "synthetic_id": _stable_hash(
            f"{record.get('url', '')}::{record.get('method', '')}::"
            f"{record.get('param', '')}::"
            f"{str(record.get('payload', ''))[:_DEDUP_PAYLOAD_LEN]}"
        ),
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
            "dalfox_parser.evidence_sidecar_write_failed",
            extra={
                "event": "dalfox_parser_evidence_sidecar_write_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


# ---------------------------------------------------------------------------
# Payload resolution
# ---------------------------------------------------------------------------


def _load_payload(
    *,
    stdout: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> Any:
    """Resolve the canonical ``dalfox.json`` blob or fall back to stdout."""
    canonical = _safe_join(artifacts_dir, "dalfox.json")
    if canonical is not None and canonical.is_file():
        try:
            raw = canonical.read_bytes()
        except OSError as exc:
            _logger.warning(
                "dalfox_parser.canonical_read_failed",
                extra={
                    "event": "dalfox_parser_canonical_read_failed",
                    "tool_id": tool_id,
                    "path": "dalfox.json",
                    "error_type": type(exc).__name__,
                },
            )
            raw = b""
        if raw.strip():
            payload = safe_load_json(raw, tool_id=tool_id)
            if payload is not None:
                return payload
    if stdout and stdout.strip():
        return safe_load_json(stdout, tool_id=tool_id)
    return None


def _safe_join(base: Path, name: str) -> Path | None:
    """Defensive ``base / name`` that refuses path-traversal segments."""
    if "/" in name or "\\" in name or ".." in name:
        return None
    return base / name


# ---------------------------------------------------------------------------
# Record normalisation
# ---------------------------------------------------------------------------


def _iter_raw_results(payload: Any) -> Iterable[dict[str, Any]]:
    """Yield the raw dalfox result dicts from either envelope shape."""
    if isinstance(payload, dict):
        results = payload.get("results")
        if isinstance(results, list):
            for item in results:
                if isinstance(item, dict):
                    yield item
        # Some dalfox versions use ``"poc"`` instead of ``"results"``.
        elif isinstance(payload.get("poc"), list):
            for item in payload["poc"]:
                if isinstance(item, dict):
                    yield item
    elif isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                yield item


def _iter_normalised(
    raw_results: list[dict[str, Any]],
    *,
    tool_id: str,
) -> Iterable[dict[str, Any]]:
    """Yield records normalised onto the parser's working schema."""
    for raw in raw_results:
        url = _string_field(raw, "url") or _string_field(raw, "data")
        if url is None:
            _logger.warning(
                "dalfox_parser.result_missing_url",
                extra={
                    "event": "dalfox_parser_result_missing_url",
                    "tool_id": tool_id,
                },
            )
            continue
        finding_type = (_string_field(raw, "type") or "R").upper()
        if finding_type not in _TYPE_MAP:
            finding_type = "R"
        method = (_string_field(raw, "method") or "GET").upper()
        param = _string_field(raw, "param") or ""
        payload = _string_field(raw, "payload") or ""
        evidence_snippet = _string_field(raw, "evidence") or ""
        severity = (_string_field(raw, "severity") or "medium").lower()
        if severity not in _SEVERITY_RANK:
            severity = "medium"
        cwe_list = _normalise_cwe(raw.get("cwe"))
        yield {
            "type": finding_type,
            "url": url,
            "method": method,
            "param": param,
            "payload": payload,
            "evidence_snippet": evidence_snippet,
            "severity": severity,
            "poc": _string_field(raw, "poc") or "",
            "tag": _string_field(raw, "tag") or "",
            "dalfox_category": _string_field(raw, "category") or "",
            "matched_signature": _string_field(raw, "matched_signature") or "",
            "cwe": cwe_list,
        }


def _normalise_cwe(raw: Any) -> list[int]:
    """Coerce the dalfox ``cwe`` field into a list of positive ints."""
    if raw is None:
        return list(_DEFAULT_CWE)
    candidates: list[Any] = []
    if isinstance(raw, list):
        candidates.extend(raw)
    else:
        candidates.append(raw)
    out: list[int] = []
    seen: set[int] = set()
    for item in candidates:
        cwe_id = _coerce_cwe_token(item)
        if cwe_id is None or cwe_id in seen:
            continue
        seen.add(cwe_id)
        out.append(cwe_id)
    return out or list(_DEFAULT_CWE)


def _coerce_cwe_token(token: Any) -> int | None:
    """Coerce ``"CWE-79"`` / ``79`` / ``"79"`` into the integer 79."""
    if isinstance(token, bool):
        return None
    if isinstance(token, int):
        return token if token > 0 else None
    if not isinstance(token, str):
        return None
    candidate = token.strip().upper()
    if candidate.startswith("CWE-"):
        candidate = candidate[4:]
    if not candidate.isdigit():
        return None
    value = int(candidate)
    return value if value > 0 else None


def _string_field(record: dict[str, Any], key: str) -> str | None:
    """Return ``record[key]`` if it is a non-empty string, else ``None``."""
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _truncate_text(text: str) -> str:
    """Cap a single string at :data:`_MAX_EVIDENCE_BYTES` UTF-8 bytes."""
    if not text:
        return ""
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= _MAX_EVIDENCE_BYTES:
        return text
    truncated = encoded[:_MAX_EVIDENCE_BYTES]
    return truncated.decode("utf-8", errors="replace") + "...[truncated]"


def _stable_hash(text: str) -> str:
    """Return a cross-process deterministic 12-char hex digest of ``text``.

    Mirrors ``nuclei_parser._stable_hash`` / ``sqlmap_parser._stable_hash``:
    ``hash()`` is randomised per-interpreter (PYTHONHASHSEED) and would
    break sidecar byte determinism across CI workers. SHA-256
    truncated to 12 hex chars (48 bits) is collision-safe at the
    realistic upper bound of dalfox findings per scan.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_dalfox_json",
]
