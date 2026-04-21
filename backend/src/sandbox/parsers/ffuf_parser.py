"""Universal parser for ffuf-family JSON output (Backlog/dev1_md §4.5).

The §4.5 content / path / parameter discovery batch ships five tools that
emit broadly compatible JSON shapes — ``ffuf``, ``feroxbuster``,
``dirsearch``, ``ffuf_vhost``, and ``ffuf_param`` (the latter two are
``ffuf`` invoked with different flags).  Two more tools (``arjun``,
``wfuzz``) emit related but slightly different shapes; their support lands
opportunistically here when their schema collapses to the common
projection (URL + status + length-ish), and as a separate parser otherwise.

Common record shape (post-normalisation)
----------------------------------------
* ``url`` — full URL of the discovered endpoint / parameter (required).
* ``status`` — HTTP status code (required, int).
* ``length`` — response content length in bytes (optional, int).
* ``words``, ``lines`` — response token / line counts (optional, int).
* ``content_type`` — server-reported ``Content-Type`` (optional, str).
* ``redirect_location`` — ``Location`` header for 3xx (optional, str).

Source variants supported by :func:`parse_ffuf_json`
----------------------------------------------------
1. **ffuf** (`-of json` / `-of all`) emits a single JSON object::

      {"results": [
          {"url": "...", "status": 200, "length": 1234, "words": 64, ...},
          ...
      ], "config": {...}, "commandline": "..."}

2. **feroxbuster** (``--json`` / ``-o file.json``) emits either:
   - one JSON object per line (JSONL stream), each ``{"type": "response",
     "url": "...", "status": 200, "content_length": 1234, ...}``; or
   - the same ``{"results": [...]}`` envelope when the user redirects
     the JSON output to a file.  Both shapes are accepted.

3. **dirsearch** (``--format json``) emits ``{"results": [...]}`` but
   with ``content-length`` (hyphenated) instead of ``length``.

Severity mapping (mirrors `Backlog/dev1_md` §4.5 risk semantics)
----------------------------------------------------------------
* HTTP **2xx** — INFO category; sentinel CVSS (0.0).  A discovered
  resource is an information-disclosure data point but not a CVSS-scoring
  vulnerability on its own.  Recorded for downstream correlation
  (auth/IDOR/SSRF chaining).
* HTTP **3xx** — INFO category; sentinel CVSS.  Redirects are catalogued
  for crawler hand-off.
* HTTP **401 / 403** — INFO category with ``ConfidenceLevel.LIKELY`` and
  the descriptive evidence preserved; the parser does NOT promote auth
  walls to MEDIUM/HIGH because the categorical risk is "auth wall is
  there, an attacker now knows where to point credential-stuffing".
* HTTP **5xx** — INFO category with ``ConfidenceLevel.LIKELY``;
  server-error-during-discovery is a useful signal (SSRF / verbose error
  / fragile path) but not a finding the parser can score.
* Any other status — INFO with sentinel score; the dedup key still
  collapses repeats.

Why everything maps to FindingCategory.INFO
-------------------------------------------
The :class:`FindingCategory` enum (see ``src.pipeline.contracts.finding_dto``)
does not include ``path_disclosure`` / ``parameter_disclosure`` as separate
categories — the closest semantic match is :attr:`FindingCategory.INFO`
with the ``[200]`` (CWE-200, Information Exposure) hint preserved on every
record.  The downstream :class:`~src.findings.normalizer.Normalizer`
re-derives the per-finding category from richer metadata (asset shape,
correlated tool runs); the parser layer just puts the raw signal on the
wire.  ``tool_id`` is recorded in the evidence sidecar so the normaliser
can branch on path-vs-parameter without re-reading the raw output.

Dedup
-----
Records are deduplicated by ``(url, status)`` — running ``ffuf`` with
``-recursion`` legitimately re-emits the same root URL multiple times, so
the canonical-on-disk JSON would otherwise inflate the FindingDTO count.

Output ordering
---------------
Sorted by ``(url, status)`` so snapshot tests stay stable across reruns
(the source tools do NOT guarantee a deterministic enumeration order).

Sidecar evidence
----------------
A compact projection of every emitted record is written to
``artifacts_dir / "ffuf_findings.jsonl"`` — best-effort, OSError-tolerant
just like ``httpx_parser``.  Includes ``tool_id`` so a downstream consumer
can reconstruct which scanner produced which row.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Final

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
)
from src.sandbox.parsers._base import (
    make_finding_dto,
    safe_decode,
    safe_load_json,
    safe_load_jsonl,
)

_logger = logging.getLogger(__name__)


# Path / parameter / vhost discovery findings are an "Information Exposure"
# class (CWE-200).  Backlog/dev1_md §4.5 maps to:
#   - WSTG-CONFIG-04 (Old, Backup and Unreferenced Files) — content discovery
#   - WSTG-CONFIG-06 (Application Platform Configuration) — path discovery
#   - WSTG-INPV-04   (HTTP Parameter Pollution / Parameter Discovery)
#   - WSTG-INFO-04   (Application Entry Points / vhost discovery)
_DEFAULT_CWE: Final[tuple[int, ...]] = (200,)


# Per-tool OWASP WSTG hints. ``arjun`` / ``paramspider`` / ``ffuf_param`` /
# ``wfuzz`` discover parameters → INPV-04. ``ffuf_vhost`` discovers vhosts
# → INFO-04. Everything else discovers paths/files → CONFIG-04 + CONFIG-06.
_TOOL_OWASP_WSTG: Final[dict[str, tuple[str, ...]]] = {
    "ffuf_dir": ("WSTG-CONFIG-04", "WSTG-CONFIG-06"),
    "ffuf_vhost": ("WSTG-INFO-04",),
    "ffuf_param": ("WSTG-INPV-04",),
    "feroxbuster": ("WSTG-CONFIG-04", "WSTG-CONFIG-06"),
    "dirsearch": ("WSTG-CONFIG-04", "WSTG-CONFIG-06"),
    "kiterunner": ("WSTG-CONFIG-04", "WSTG-CONFIG-06"),
    "arjun": ("WSTG-INPV-04",),
    "paramspider": ("WSTG-INPV-04",),
    "wfuzz": ("WSTG-INPV-04",),
}

_FALLBACK_OWASP_WSTG: Final[tuple[str, ...]] = ("WSTG-CONFIG-04",)


# Public sidecar filename so tests + downstream evidence pipeline both
# reference the same constant (mirrors the httpx_parser pattern).
EVIDENCE_SIDECAR_NAME: Final[str] = "ffuf_findings.jsonl"


# Soft cap on how many records we persist into the sidecar.  Defence
# in-depth against a runaway ``-r`` (recursion) ffuf run that might emit
# tens of thousands of duplicates after dedup; well above any realistic
# legitimate count.
_MAX_FINDINGS: Final[int] = 5_000


def parse_ffuf_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate ffuf-family output into a deduplicated list of findings.

    Side-effect: writes one compact JSON evidence record per emitted
    finding to ``artifacts_dir / EVIDENCE_SIDECAR_NAME`` (best-effort —
    OSErrors are logged and swallowed).  ``stderr`` is accepted for parser
    dispatch signature symmetry but not consumed.

    The function never raises on malformed input — both ``safe_load_json``
    and ``safe_load_jsonl`` log a structured WARNING and return an empty
    iterable on parse error.  An unrecognised payload shape is treated the
    same way (zero findings).
    """
    del stderr

    records = list(_extract_findings_list(stdout, tool_id=tool_id))
    if not records:
        return []

    DedupKey = tuple[str, int]
    seen: set[DedupKey] = set()
    keyed: list[tuple[DedupKey, FindingDTO, str]] = []

    owasp_wstg = list(_TOOL_OWASP_WSTG.get(tool_id, _FALLBACK_OWASP_WSTG))

    for raw in records:
        url = _string_field(raw, "url")
        status = _int_field(raw, "status")
        if url is None or status is None:
            _logger.warning(
                "ffuf_parser.skip_incomplete_record",
                extra={
                    "event": "ffuf_parser_skip_incomplete_record",
                    "tool_id": tool_id,
                    "has_url": url is not None,
                    "has_status": status is not None,
                },
            )
            continue

        dedup_key: DedupKey = (url, status)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        confidence = _confidence_for_status(status)
        finding = make_finding_dto(
            category=FindingCategory.INFO,
            cwe=list(_DEFAULT_CWE),
            owasp_wstg=owasp_wstg,
            confidence=confidence,
        )
        evidence_blob = _build_evidence(raw, url=url, status=status, tool_id=tool_id)
        keyed.append((dedup_key, finding, evidence_blob))

        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "ffuf_parser.cap_reached",
                extra={
                    "event": "ffuf_parser_cap_reached",
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
            evidence_records=[blob for _, _, blob in keyed],
        )

    return [finding for _, finding, _ in keyed]


# ---------------------------------------------------------------------------
# Shape adapters — translate ffuf / feroxbuster / dirsearch payloads into
# the common ``{"url", "status", "length", "words", "lines", ...}`` dict.
# ---------------------------------------------------------------------------


def _looks_like_jsonl(text: str) -> bool:
    """Return True when ``text`` is two-or-more independent JSON objects per line.

    Distinguishes the feroxbuster JSONL stream (each line is its own JSON
    object) from a single-document envelope (ffuf / dirsearch).  The cheap
    heuristic: at least two non-empty lines, AND every non-empty line
    starts with ``{``, AND the first two lines parse independently as
    dicts.  Both checks together rule out a pretty-printed single object
    (where lines start with whitespace + key) and a JSON list-of-objects
    (where the first non-whitespace char is ``[``).
    """
    non_empty_lines = [line for line in text.splitlines() if line.strip()]
    if len(non_empty_lines) < 2:
        return False
    if not all(line.lstrip().startswith("{") for line in non_empty_lines):
        return False
    for sample in non_empty_lines[:2]:
        try:
            parsed = json.loads(sample)
        except (json.JSONDecodeError, TypeError):
            return False
        if not isinstance(parsed, dict):
            return False
    return True


def _extract_findings_list(
    stdout: bytes,
    *,
    tool_id: str,
) -> Iterable[dict[str, Any]]:
    """Yield normalised per-record dicts from any supported source shape."""
    text = safe_decode(stdout, limit=25 * 1024 * 1024)  # mirror MAX_STDOUT_BYTES
    if not text:
        return

    if _looks_like_jsonl(text):
        yield from _iter_feroxbuster_jsonl(stdout, tool_id=tool_id)
        return

    payload = safe_load_json(stdout, tool_id=tool_id)
    if payload is None:
        return

    if isinstance(payload, list):
        # Some wrappers (or `--format json` alternatives) wrap the records
        # directly into a top-level list.  Treat as ffuf-shape result list.
        yield from _iter_normalised(payload, tool_id=tool_id)
        return

    if not isinstance(payload, dict):
        _logger.warning(
            "ffuf_parser.unsupported_top_level_type",
            extra={
                "event": "ffuf_parser_unsupported_top_level_type",
                "tool_id": tool_id,
                "type": type(payload).__name__,
            },
        )
        return

    # arjun emits a top-level dict keyed by URL (``{url: [param_dicts]}``)
    # which collides with neither the ``{"results": [...]}`` nor the
    # single-record envelopes below.  Try the arjun-specific projection
    # FIRST so a real arjun payload is not silently dropped through the
    # ``unrecognised_envelope`` warning at the bottom; if no records come
    # out (e.g. the synthetic ``{"results": [...]}`` envelope used by
    # integration tests), fall through to the standard envelope handlers.
    if tool_id == "arjun":
        arjun_records = list(_iter_arjun_items(payload))
        if arjun_records:
            yield from arjun_records
            return

    if isinstance(payload.get("results"), list):
        yield from _iter_normalised(payload["results"], tool_id=tool_id)
        return

    # Single-record top-level object — unusual but legitimate when a tool
    # is invoked with a single FUZZ position.  Try it as a record.
    if "url" in payload or "type" in payload:
        yield from _iter_normalised([payload], tool_id=tool_id)
        return

    _logger.warning(
        "ffuf_parser.unrecognised_envelope",
        extra={
            "event": "ffuf_parser_unrecognised_envelope",
            "tool_id": tool_id,
            "top_level_keys": sorted(payload.keys())[:10],
        },
    )


def _iter_feroxbuster_jsonl(stdout: bytes, *, tool_id: str) -> Iterable[dict[str, Any]]:
    """Yield normalised records from a feroxbuster JSONL stream."""
    for record in safe_load_jsonl(stdout, tool_id=tool_id):
        # feroxbuster mixes "configuration" / "scan-info" / "response" /
        # "statistics" record types in the same stream.  We only care about
        # responses.
        record_type = record.get("type")
        if record_type and record_type != "response":
            continue
        yield from _iter_normalised([record], tool_id=tool_id)


def _iter_normalised(
    records: list[Any],
    *,
    tool_id: str,
) -> Iterable[dict[str, Any]]:
    """Project each record into the common shape used by :func:`parse_ffuf_json`."""
    del tool_id
    for record in records:
        if not isinstance(record, dict):
            continue
        # Field name normalisation across the §4.5 family:
        #   - length  → ffuf
        #   - content_length / content-length → feroxbuster / dirsearch
        #   - chars   → wfuzz (printer-emitted ``-o json`` field)
        length = (
            _int_field(record, "length")
            or _int_field(record, "content_length")
            or _int_field_hyphen(record, "content-length")
            or _int_field(record, "chars")
        )
        words = _int_field(record, "words")
        lines = _int_field(record, "lines")
        content_type = _string_field(record, "content_type") or _string_field_hyphen(
            record, "content-type"
        )
        redirect = _string_field(record, "redirectlocation") or _string_field(
            record, "redirect_location"
        )
        # Status field aliasing:
        #   - status         → ffuf / dirsearch / feroxbuster
        #   - code           → wfuzz (printer-emitted ``-o json`` field)
        #   - status_code    → some wrapper wfuzz adapters (see
        #     ``backend/src/recon/vulnerability_analysis/active_scan/
        #     wfuzz_va_adapter.py``)
        status = (
            _int_field(record, "status")
            or _int_field(record, "code")
            or _int_field(record, "status_code")
        )
        normalised: dict[str, Any] = {
            "url": _string_field(record, "url"),
            "status": status,
        }
        if length is not None:
            normalised["length"] = length
        if words is not None:
            normalised["words"] = words
        if lines is not None:
            normalised["lines"] = lines
        if content_type is not None:
            normalised["content_type"] = content_type
        if redirect is not None:
            normalised["redirect_location"] = redirect
        yield normalised


def _iter_arjun_items(payload: dict[str, Any]) -> Iterable[dict[str, Any]]:
    """Project real arjun ``-oJ`` output into the common ``parse_ffuf_json`` shape.

    arjun ``-oJ`` writes a top-level JSON dict whose KEYS are URLs and
    whose VALUES are lists of parameter dicts::

        {"https://target/api/users": [
            {"name": "user_id", "method": "GET", "type": "Form"},
            {"name": "page",    "method": "GET", "type": "Form"}
        ]}

    Each discovered parameter is catalogued as if the URL responded 200
    (arjun only reports CONFIRMED parameters that produced a behavioural
    change in the response).  ``status=200`` is supplied so the
    ``(url, status)`` dedup key in :func:`parse_ffuf_json` stays usable;
    multiple parameters under the same URL collapse to a single finding,
    and the per-parameter detail is preserved in the evidence sidecar via
    ``parameter_name`` / ``method``.

    Hardening: the URL-key heuristic (``startswith(("http://", "https://"))``)
    skips synthetic test envelopes whose top-level keys are not URLs (e.g.
    ``{"results": [...]}`` reused for the dispatch parametrisation), so the
    arjun branch can fall through to the standard envelope handler without
    yielding bogus records keyed off literal envelope names.
    """
    for url_key, params in payload.items():
        if not isinstance(url_key, str):
            continue
        url = url_key.strip()
        if not url.startswith(("http://", "https://")):
            continue
        if not isinstance(params, list):
            continue
        for param_record in params:
            if not isinstance(param_record, dict):
                continue
            yield {
                "url": url,
                "status": 200,
                "parameter_name": _string_field(param_record, "name") or "",
                "method": _string_field(param_record, "method") or "GET",
            }


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------


def _confidence_for_status(status: int) -> ConfidenceLevel:
    """Map an HTTP status to a :class:`ConfidenceLevel`.

    The parser itself does not score severity (CVSS is sentinel for INFO);
    confidence is the only signal we can carry up the pipeline.  401/403
    and 5xx responses are higher-confidence findings (the response shape
    is unambiguous), while 2xx/3xx hits stay SUSPECTED until correlated.
    """
    if status in {401, 403}:
        return ConfidenceLevel.LIKELY
    if 500 <= status < 600:
        return ConfidenceLevel.LIKELY
    return ConfidenceLevel.SUSPECTED


# ---------------------------------------------------------------------------
# Sidecar persistence
# ---------------------------------------------------------------------------


def _persist_evidence_sidecar(
    artifacts_dir: Path,
    *,
    tool_id: str,
    evidence_records: list[str],
) -> None:
    """Best-effort write of the per-finding evidence sidecar JSONL.

    Failure is non-fatal: any :class:`OSError` is logged and swallowed so
    the parser stays pure-deterministic for in-memory test paths and so a
    transient disk error never aborts the worker run.
    """
    try:
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        sidecar_path = artifacts_dir / EVIDENCE_SIDECAR_NAME
        with sidecar_path.open("w", encoding="utf-8") as fh:
            for blob in evidence_records:
                fh.write(blob)
                fh.write("\n")
    except OSError as exc:
        _logger.warning(
            "ffuf_parser.evidence_sidecar_write_failed",
            extra={
                "event": "ffuf_parser_evidence_sidecar_write_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


def _build_evidence(
    record: dict[str, Any],
    *,
    url: str,
    status: int,
    tool_id: str,
) -> str:
    """Build a compact evidence JSON for downstream redaction + persistence.

    Keeps only the fields with probative value for a discovery finding
    (URL, status, response shape, content-type, redirect).  Unknown keys
    are intentionally dropped so a verbose ffuf run cannot leak headers /
    cookies / per-request metadata that may include sensitive payload.
    """
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "url": url,
        "status": status,
        "length": _int_field(record, "length"),
        "words": _int_field(record, "words"),
        "lines": _int_field(record, "lines"),
        "content_type": _string_field(record, "content_type"),
        "redirect_location": _string_field(record, "redirect_location"),
        "parameter_name": _string_field(record, "parameter_name"),
        "method": _string_field(record, "method"),
    }
    cleaned = {
        key: value for key, value in payload.items() if value not in (None, "", [], {})
    }
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Field accessors — duplicate of the httpx_parser helpers so the two
# parsers stay independent (no cross-module coupling on private helpers).
# ---------------------------------------------------------------------------


def _string_field(record: dict[str, Any], key: str) -> str | None:
    """Return ``record[key]`` if it is a non-empty string, else ``None``."""
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _string_field_hyphen(record: dict[str, Any], key: str) -> str | None:
    """Variant of :func:`_string_field` that tolerates hyphenated keys."""
    return _string_field(record, key)


def _int_field(record: dict[str, Any], key: str) -> int | None:
    """Return ``record[key]`` if it is an int, else ``None``."""
    value = record.get(key)
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def _int_field_hyphen(record: dict[str, Any], key: str) -> int | None:
    """Variant of :func:`_int_field` that tolerates hyphenated keys."""
    return _int_field(record, key)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_ffuf_json",
]
