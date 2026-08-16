"""Parser for curl HTTP fingerprinting output (Backlog/dev1_md §4.4 — F-M03).

The curl wrapper runs ``curl -sS -i -L -o /out/curl_body.txt -D
/out/curl_headers.txt <url>`` (see ``config/tools/curl.yaml``), so the
response headers land in ``curl_headers.txt`` — one HTTP header block per
redirect hop, e.g.::

    HTTP/1.1 301 Moved Permanently
    Server: nginx/1.18.0
    Location: https://target/

    HTTP/2 200
    server: Apache/2.4.41 (Ubuntu)
    x-powered-by: PHP/7.4.3
    x-aspnet-version: 4.0.30319

This is a *passive* recon probe (``risk_level: passive``); it only reads
what the server volunteers. The parser therefore emits low-signal
:class:`FindingCategory.INFO` technology-disclosure findings for the
subset of response headers that reveal server / framework / language
version information — the classic "banner grabbing" surface an operator
uses to seed later version-specific checks.

Only disclosure headers in :data:`_DISCLOSURE_HEADERS` yield findings;
transport / caching / security headers (``Content-Type``, ``Date``,
``Cache-Control``, ``Strict-Transport-Security`` …) are ignored so the
operator inbox is not flooded with non-actionable noise.

Translation rules
-----------------

* **Category** — :class:`FindingCategory.INFO` (information disclosure).
* **Confidence** — :class:`ConfidenceLevel.CONFIRMED`: the header was
  literally observed in the response, so its presence is a fact, not a
  heuristic. (The *impact* is still only informational.)
* **CWE** — ``[200]`` (Exposure of Sensitive Information). ``curl.yaml``
  ships empty ``cwe_hints`` because the disclosure CWE is header-driven,
  not tool-driven.
* **OWASP WSTG** — ``WSTG-INFO-02`` / ``WSTG-INFO-08`` from ``curl.yaml``.

Dedup
-----

Stable key: ``(header_name_lower, value)``. A ``Server`` banner repeated
across three redirect hops collapses to a single finding; two *different*
banner values (e.g. an edge proxy then an origin server) are two
findings.

Cap
---

Hard-limited to :data:`_MAX_FINDINGS = 200`.

Sidecar
-------

Mirrored into ``artifacts_dir / "curl_findings.jsonl"``.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final, TypeAlias

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
    SSVCDecision,
)
from src.sandbox.parsers._base import make_finding_dto
from src.sandbox.parsers._text_base import (
    load_canonical_or_stdout_text,
    scrub_evidence_strings,
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------


EVIDENCE_SIDECAR_NAME: Final[str] = "curl_findings.jsonl"
# Headers land in curl_headers.txt; stdout is the test-time fallback.
_CANONICAL_FILENAMES: Final[tuple[str, ...]] = ("curl_headers.txt",)
_MAX_FINDINGS: Final[int] = 200
_MAX_EVIDENCE_BYTES: Final[int] = 2 * 1024


_CWE_INFO_DISCLOSURE: Final[tuple[int, ...]] = (200,)
_OWASP_WSTG_DEFAULT: Final[tuple[str, ...]] = ("WSTG-INFO-02", "WSTG-INFO-08")
_MITRE_ATTACK_DEFAULT: Final[tuple[str, ...]] = ("T1592", "T1595")


# Response headers that leak server / framework / language fingerprints.
# Compared case-insensitively (HTTP header names are case-insensitive).
_DISCLOSURE_HEADERS: Final[frozenset[str]] = frozenset(
    {
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "x-generator",
        "x-drupal-cache",
        "x-drupal-dynamic-cache",
        "x-runtime",
        "x-version",
        "x-backend-server",
        "x-served-by",
        "via",
        "x-varnish",
        "x-turbo-charged-by",
    }
)


_STATUS_LINE_RE: Final[re.Pattern[str]] = re.compile(
    r"^HTTP/(?:\d(?:\.\d)?|\d)\s+(?P<status>\d{3})",
    re.IGNORECASE,
)
_HEADER_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9\-]{0,64}):\s*(?P<value>.*)$",
)


DedupKey: TypeAlias = tuple[str, str]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_curl(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate curl response headers into INFO disclosure findings."""
    del stderr
    text = load_canonical_or_stdout_text(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_names=_CANONICAL_FILENAMES,
        tool_id=tool_id,
    )
    if not text:
        return []
    records = list(_iter_records(text))
    if not records:
        return []
    return _emit(records, artifacts_dir=artifacts_dir, tool_id=tool_id)


# ---------------------------------------------------------------------------
# Record extraction
# ---------------------------------------------------------------------------


def _iter_records(text: str) -> Iterator[dict[str, Any]]:
    hop = 0
    last_status = ""
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r")
        status_match = _STATUS_LINE_RE.match(line.strip())
        if status_match:
            hop += 1
            last_status = status_match.group("status")
            continue
        header_match = _HEADER_RE.match(line)
        if header_match is None:
            continue
        name = header_match.group("name").strip()
        value = header_match.group("value").strip()
        if not value:
            continue
        if name.lower() not in _DISCLOSURE_HEADERS:
            continue
        yield {
            "header": name,
            "value": value,
            "hop": hop,
            "status": last_status,
        }


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def _emit(
    records: list[dict[str, Any]],
    *,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    seen: set[DedupKey] = set()
    keyed: list[tuple[tuple[str, str], FindingDTO, str]] = []
    for record in records:
        key: DedupKey = (
            record["header"].lower(),
            record["value"],
        )
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding()
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        keyed.append((key, finding, evidence_blob))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "curl_parser.cap_reached",
                extra={
                    "event": "curl_parser_cap_reached",
                    "tool_id": tool_id,
                    "cap": _MAX_FINDINGS,
                },
            )
            break
    keyed.sort(key=lambda item: item[0])
    if keyed:
        _persist_sidecar(
            artifacts_dir,
            tool_id=tool_id,
            evidence_records=[blob for _, _, blob in keyed],
        )
    return [finding for _, finding, _ in keyed]


def _build_finding() -> FindingDTO:
    return make_finding_dto(
        category=FindingCategory.INFO,
        cwe=list(_CWE_INFO_DISCLOSURE),
        confidence=ConfidenceLevel.CONFIRMED,
        ssvc_decision=SSVCDecision.TRACK,
        owasp_wstg=list(_OWASP_WSTG_DEFAULT),
        mitre_attack=list(_MITRE_ATTACK_DEFAULT),
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": "http_tech_disclosure",
        "header": record.get("header"),
        "value": _truncate_text(record.get("value")),
        "hop": record.get("hop"),
        "status": record.get("status"),
    }
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if value in (None, "", 0) and key != "hop":
            continue
        cleaned[key] = value
    return json.dumps(
        scrub_evidence_strings(cleaned), sort_keys=True, ensure_ascii=False
    )


def _persist_sidecar(
    artifacts_dir: Path,
    *,
    tool_id: str,
    evidence_records: list[str],
) -> None:
    try:
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        sidecar_path = artifacts_dir / EVIDENCE_SIDECAR_NAME
        with sidecar_path.open("w", encoding="utf-8") as fh:
            for blob in evidence_records:
                fh.write(blob)
                fh.write("\n")
    except OSError as exc:
        _logger.warning(
            "curl_parser.evidence_sidecar_write_failed",
            extra={
                "event": "curl_parser_sidecar_write_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _truncate_text(text: str | None) -> str | None:
    if text is None or text == "":
        return None
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= _MAX_EVIDENCE_BYTES:
        return text
    truncated = encoded[:_MAX_EVIDENCE_BYTES].decode("utf-8", errors="replace")
    return truncated + "...[truncated]"


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_curl",
]
