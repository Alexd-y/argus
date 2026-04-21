"""Parsers for Katana / Gospider / gau crawler JSON(L) output (Backlog/dev1_md §4.6).

The §4.6 batch ships eight web crawler / endpoint extraction tools but only
three of them emit machine-parseable JSON(L) on stdout:

* **katana** (``-jsonl``)       — one JSON object per discovered request,
  with fields ``request.endpoint``, ``request.method``, ``response.*``.
* **gospider** (``--json``)     — one JSON object per discovered URL, with
  fields ``output``, ``source``, ``type``, ``stat``.
* **gau** (``--json``)          — one JSON object per archived URL, with
  fields ``url`` and (optionally) HTTP metadata.

The remaining five (``hakrawler``, ``waybackurls``, ``linkfinder``,
``subjs``, ``secretfinder``) emit plain text (one URL or secret per line)
and stay routed via :class:`ParseStrategy.TEXT_LINES` (parser to ship in
ARG-013 cycle 3 follow-up).

Every record collapses into the same :class:`FindingDTO` shape:

* ``category=FindingCategory.INFO``
* ``cwe=[200]`` (CWE-200, Information Exposure — discovered endpoints
  always leak the application surface area to a future attacker even when
  the response itself is benign).
* ``confidence=ConfidenceLevel.SUSPECTED`` (a discovered endpoint is a
  hand-off point for downstream auth / IDOR / SSRF chaining; the parser
  layer deliberately does not promote severity).
* ``cvss_v3_score=0.0`` (sentinel — INFO findings stay below the CVSS
  threshold per the normaliser contract in :mod:`src.sandbox.parsers._base`).
* ``owasp_wstg=["WSTG-INFO-06", "WSTG-INFO-07"]`` (Application Entry
  Points + Map Execution Paths Through Application).

Dedup
-----
Records collapse on ``(endpoint, method)`` — running katana with
``-rl 50`` legitimately re-discovers the same path multiple times via
different referers, and gospider often emits the same URL from both the
sitemap and the live crawl.

Ordering
--------
Findings + sidecar JSONL are sorted by ``(endpoint, method)`` so snapshot
tests stay stable across reruns regardless of the upstream tool's
emission order.

Sidecar evidence
----------------
A compact projection of every emitted record is written to
``artifacts_dir / "katana_findings.jsonl"`` (single sidecar shared across
the three tools so the downstream evidence pipeline only needs to
register one filename). Each record carries the source ``tool_id``.

Hard cap
--------
``_MAX_FINDINGS = 5_000`` defends the worker against a runaway crawl
(katana with ``-d 10`` against a wildcard CDN can emit tens of thousands
of distinct URLs in a few minutes).
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
    safe_load_jsonl,
)

_logger = logging.getLogger(__name__)


# Endpoint discovery findings are an "Information Exposure" class
# (CWE-200). Backlog/dev1_md §4.6 maps to:
#   - WSTG-INFO-06 (Identify Application Entry Points) — universal
#   - WSTG-INFO-07 (Map Execution Paths Through Application) — for the
#     three crawlers that walk the application graph (katana, gospider,
#     hakrawler); gau / waybackurls discover historical entry points only.
_DEFAULT_CWE: Final[tuple[int, ...]] = (200,)
_DEFAULT_OWASP_WSTG: Final[tuple[str, ...]] = ("WSTG-INFO-06", "WSTG-INFO-07")


# Public sidecar filename so tests + downstream evidence pipeline both
# reference the same constant (mirrors the httpx_parser / ffuf_parser
# pattern). Single sidecar shared across the three §4.6 JSON parsers.
EVIDENCE_SIDECAR_NAME: Final[str] = "katana_findings.jsonl"


# Soft cap on how many records we persist into a single parser run.
# Defence in-depth against a runaway crawl (katana with ``-d 10`` against
# a wildcard CDN can emit tens of thousands of distinct URLs).
_MAX_FINDINGS: Final[int] = 5_000


# Default HTTP method when a record does not carry one (gau / waybackurls).
_DEFAULT_METHOD: Final[str] = "GET"


# ---------------------------------------------------------------------------
# Public entry points — one per tool (signature mandated by the dispatch
# layer: ``(stdout, stderr, artifacts_dir, tool_id) -> list[FindingDTO]``).
# ---------------------------------------------------------------------------


def parse_katana_jsonl(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate katana JSONL output into a deduplicated list of findings.

    Side-effect: writes one compact JSON evidence record per emitted
    finding to ``artifacts_dir / EVIDENCE_SIDECAR_NAME`` (best-effort —
    OSErrors are logged and swallowed). ``stderr`` is accepted for parser
    dispatch signature symmetry but not consumed.
    """
    del stderr
    return _parse_jsonl_common(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        tool_id=tool_id,
        record_iter=_iter_katana_records,
    )


def parse_gospider_jsonl(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate gospider JSONL output into a deduplicated list of findings.

    Thin adapter over :func:`parse_katana_jsonl`: gospider records expose
    ``output`` (the discovered URL) instead of ``request.endpoint`` and a
    string ``stat`` instead of an int ``response.status_code``; the
    helper :func:`_iter_gospider_records` normalises the shape so the
    common pipeline stays a single code path.
    """
    del stderr
    return _parse_jsonl_common(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        tool_id=tool_id,
        record_iter=_iter_gospider_records,
    )


def parse_gau_jsonl(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate gau JSONL output into a deduplicated list of findings.

    gau ``--json`` emits one minimal record per archived URL — usually
    just ``{"url": "..."}`` — so the parser only extracts the URL and
    treats every record as a discovered endpoint with no HTTP method
    (defaulted to ``GET``) and no observed status code. Records that
    additionally carry HTTP metadata (some gau wrappers do) are folded
    into the evidence sidecar verbatim.
    """
    del stderr
    return _parse_jsonl_common(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        tool_id=tool_id,
        record_iter=_iter_gau_records,
    )


# ---------------------------------------------------------------------------
# Shared pipeline — dedup + sort + sidecar persistence
# ---------------------------------------------------------------------------


def _parse_jsonl_common(
    *,
    stdout: bytes,
    artifacts_dir: Path,
    tool_id: str,
    record_iter: Any,  # Callable[[bytes, str], Iterable[_NormalisedRecord]]
) -> list[FindingDTO]:
    """Common pipeline: iterate normalised records → dedup → sort → sidecar."""

    DedupKey = tuple[str, str]
    seen: set[DedupKey] = set()
    keyed: list[tuple[DedupKey, FindingDTO, str]] = []

    for record in record_iter(stdout, tool_id):
        endpoint = record["endpoint"]
        method = record["method"]
        # Invariant: every ``_iter_*_records`` already filters out records
        # whose endpoint is missing (``if endpoint is None: continue``).
        # Asserting here documents the contract without paying a runtime
        # branch in the hot loop and traps any future normaliser regression.
        assert endpoint, "normaliser invariant: endpoint must be non-empty"

        dedup_key: DedupKey = (endpoint, method)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        finding = make_finding_dto(
            category=FindingCategory.INFO,
            cwe=list(_DEFAULT_CWE),
            owasp_wstg=list(_DEFAULT_OWASP_WSTG),
            confidence=ConfidenceLevel.SUSPECTED,
        )
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        keyed.append((dedup_key, finding, evidence_blob))

        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "katana_parser.cap_reached",
                extra={
                    "event": "katana_parser_cap_reached",
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
# Per-tool record normalisers — yield ``{endpoint, method, status_code,
# content_length, content_type, source}`` dicts for the common pipeline.
# ---------------------------------------------------------------------------


def _iter_katana_records(stdout: bytes, tool_id: str) -> Iterable[dict[str, Any]]:
    """Yield normalised records from a katana JSONL stream.

    Katana emits one JSON object per request with the canonical shape::

        {
          "timestamp": "...",
          "request": {"endpoint": "https://target/path", "method": "GET",
                      "tag": "form|sitemap|robots|...", "source": "..."},
          "response": {"status_code": 200, "content_length": 1234,
                       "content_type": "text/html", "headers": {...}}
        }
    """
    for record in safe_load_jsonl(stdout, tool_id=tool_id):
        request = record.get("request") or {}
        response = record.get("response") or {}
        if not isinstance(request, dict) or not isinstance(response, dict):
            continue
        endpoint = _string_field(request, "endpoint")
        if endpoint is None:
            continue
        method = _string_field(request, "method") or _DEFAULT_METHOD
        yield {
            "endpoint": endpoint,
            "method": method.upper(),
            "status_code": _int_field(response, "status_code"),
            "content_length": _int_field(response, "content_length"),
            "content_type": _string_field(response, "content_type"),
            "source": _string_field(request, "tag") or _string_field(request, "source"),
        }


def _iter_gospider_records(stdout: bytes, tool_id: str) -> Iterable[dict[str, Any]]:
    """Yield normalised records from a gospider JSONL stream.

    Gospider ``--json`` emits one JSON object per discovered URL::

        {"output": "https://target/path", "url": "https://target",
         "source": "scan|sitemap|robots|...", "type": "url|js|subdomain|...",
         "stat": "200"}

    The discovered URL lives in ``output``; ``stat`` is a string status
    code (gospider quotes the field even though it's numeric). Gospider
    does not record HTTP method per record — every crawl request is GET
    by construction.
    """
    for record in safe_load_jsonl(stdout, tool_id=tool_id):
        endpoint = _string_field(record, "output") or _string_field(record, "url")
        if endpoint is None:
            continue
        # gospider stores status as a string; coerce defensively.
        status_code: int | None = _int_field(record, "stat")
        if status_code is None:
            stat_str = _string_field(record, "stat")
            if stat_str is not None and stat_str.isdigit():
                status_code = int(stat_str)
        yield {
            "endpoint": endpoint,
            "method": _DEFAULT_METHOD,
            "status_code": status_code,
            "content_length": _int_field(record, "length"),
            "content_type": _string_field(record, "content_type"),
            "source": _string_field(record, "source") or _string_field(record, "type"),
        }


def _iter_gau_records(stdout: bytes, tool_id: str) -> Iterable[dict[str, Any]]:
    """Yield normalised records from a gau JSONL stream.

    gau ``--json`` produces minimal records — usually just
    ``{"url": "https://target/path"}`` — but some wrappers add HTTP
    metadata (status, length). The parser tolerates both shapes; the
    only required field is ``url``.
    """
    for record in safe_load_jsonl(stdout, tool_id=tool_id):
        endpoint = _string_field(record, "url") or _string_field(record, "endpoint")
        if endpoint is None:
            continue
        yield {
            "endpoint": endpoint,
            "method": _DEFAULT_METHOD,
            # Use ``_first_int`` so a legitimate ``content_length=0`` (HEAD /
            # 204 / 304 responses) is preserved instead of being shadowed by
            # the ``or`` short-circuit on falsy ints.
            "status_code": _first_int(record, "status_code", "status"),
            "content_length": _first_int(record, "content_length", "length"),
            "content_type": _string_field(record, "content_type"),
            "source": _string_field(record, "source") or "wayback",
        }


# ---------------------------------------------------------------------------
# Evidence sidecar
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
            "katana_parser.evidence_sidecar_write_failed",
            extra={
                "event": "katana_parser_evidence_sidecar_write_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    """Build a compact evidence JSON for downstream redaction + persistence.

    Keeps only the fields with probative value for an endpoint-discovery
    finding (endpoint, method, response shape, source). Unknown keys are
    intentionally dropped so a verbose crawler run cannot leak headers /
    cookies / per-request metadata that may include sensitive payload.
    """
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "endpoint": record["endpoint"],
        "method": record["method"],
        "status_code": record.get("status_code"),
        "content_length": record.get("content_length"),
        "content_type": record.get("content_type"),
        "source": record.get("source"),
    }
    cleaned = {
        key: value for key, value in payload.items() if value not in (None, "", [], {})
    }
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Field accessors — duplicated from the sibling parsers so the three tool
# parsers stay independent (no cross-module coupling on private helpers).
# ---------------------------------------------------------------------------


def _string_field(record: dict[str, Any], key: str) -> str | None:
    """Return ``record[key]`` if it is a non-empty string, else ``None``."""
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _int_field(record: dict[str, Any], key: str) -> int | None:
    """Return ``record[key]`` if it is an int, else ``None``."""
    value = record.get(key)
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def _first_int(record: dict[str, Any], *keys: str) -> int | None:
    """Return the first ``record[key]`` that resolves to an int.

    Resolves "first non-``None``" rather than "first truthy" so a
    legitimate ``0`` value (HEAD / 204 / 304 ``content_length``) is
    preserved instead of being silently shadowed by the next fallback
    key (the bug LOW-3 in the ARG-013 review caught the naive
    ``A or B`` chain dropping ``content_length=0``).
    """
    for key in keys:
        value = _int_field(record, key)
        if value is not None:
            return value
    return None


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_gau_jsonl",
    "parse_gospider_jsonl",
    "parse_katana_jsonl",
]
