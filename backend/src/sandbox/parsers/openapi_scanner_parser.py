"""Parser for ``openapi-scanner`` output (Backlog/dev1_md §4.14 — ARG-029).

ARGUS' internal openapi-scanner walks a Swagger/OpenAPI 3.x document
exposed at ``{url}`` and emits a JSON envelope summarising the API
surface — discovered endpoints, auth schemes, response codes, plus any
inline security findings raised against the schema (broken object-level
authorisation, missing scopes, etc.).

Canonical envelope (defensive — the parser tolerates several minor
shape variations):

.. code-block:: json

    {
      "schema_version": "openapi-3.0.1",
      "target":         "https://api.example.com",
      "auth_schemes":   ["bearer", "apiKey"],
      "endpoints": [
        {
          "method":     "POST",
          "path":       "/v1/users/{userId}/transfer",
          "operationId":"transferFunds",
          "auth":       "bearer",
          "responses":  ["200", "400", "401", "404"]
        }
      ],
      "findings": [
        {
          "id":         "OAS-BOLA-001",
          "severity":   "high",
          "title":      "Possible BOLA on /v1/users/{userId}/transfer",
          "endpoint":   "POST /v1/users/{userId}/transfer",
          "category":   "idor",
          "description":"Path parameter `userId` is not validated against authenticated subject"
        }
      ]
    }

Translation rules
-----------------

* **Findings list (preferred)** — each entry maps onto a FindingDTO
  whose category, severity and CWE are derived from the entry's
  ``category`` hint (defaulting to MISCONFIG).
* **Endpoints list (fallback)** — when ``findings[]`` is absent OR
  empty AND endpoints exist, the parser emits a single INFO finding
  per endpoint summarising the discovered API surface.  This keeps
  the dispatch contract honest (the operator sees that the tool
  *did* run and discovered N endpoints) without misclassifying
  benign discovery hits as vulnerabilities.

* **Severity → CVSS**:

  - ``critical`` → 9.5
  - ``high``     → 7.5
  - ``medium``   → 5.0
  - ``low``      → 3.0
  - else / discovery → 0.0

* **Confidence** — :class:`ConfidenceLevel.LIKELY` for
  vulnerability findings (heuristic-based), :class:`ConfidenceLevel.\
  CONFIRMED` for pure discovery records.

Sidecar
-------

Mirrored into ``artifacts_dir / "openapi_scanner_findings.jsonl"``.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any, Final, TypeAlias

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
)
from src.sandbox.parsers._base import (
    SENTINEL_CVSS_VECTOR,
    make_finding_dto,
)
from src.sandbox.parsers._jsonl_base import (
    load_canonical_or_stdout_json,
    persist_jsonl_sidecar,
)

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "openapi_scanner_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "openapi.json"
_MAX_FINDINGS: Final[int] = 5_000


_SEVERITY_TO_CVSS: Final[dict[str, float]] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
}


_SEVERITY_RANK: Final[dict[str, int]] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


_CATEGORY_HINT: Final[dict[str, FindingCategory]] = {
    "idor": FindingCategory.IDOR,
    "bola": FindingCategory.IDOR,
    "auth": FindingCategory.AUTH,
    "missing_auth": FindingCategory.AUTH,
    "broken_auth": FindingCategory.AUTH,
    "jwt": FindingCategory.JWT,
    "rate_limit": FindingCategory.DOS,
    "dos": FindingCategory.DOS,
    "ssrf": FindingCategory.SSRF,
    "injection": FindingCategory.OTHER,
    "sqli": FindingCategory.SQLI,
    "xss": FindingCategory.XSS,
    "cors": FindingCategory.CORS,
    "open_redirect": FindingCategory.OPEN_REDIRECT,
    "secret": FindingCategory.SECRET_LEAK,
    "info_leak": FindingCategory.INFO,
    "misconfig": FindingCategory.MISCONFIG,
}


_CATEGORY_DEFAULT_CWE: Final[dict[FindingCategory, tuple[int, ...]]] = {
    FindingCategory.IDOR: (639, 285),
    FindingCategory.AUTH: (287, 862),
    FindingCategory.JWT: (345, 287),
    FindingCategory.DOS: (770, 400),
    FindingCategory.SSRF: (918,),
    FindingCategory.SQLI: (89,),
    FindingCategory.XSS: (79,),
    FindingCategory.CORS: (942,),
    FindingCategory.OPEN_REDIRECT: (601,),
    FindingCategory.SECRET_LEAK: (798,),
    FindingCategory.INFO: (200,),
    FindingCategory.MISCONFIG: (16, 200),
    FindingCategory.OTHER: (20,),
}


DedupKey: TypeAlias = tuple[str, str, str]


def parse_openapi_scanner_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate openapi-scanner output into FindingDTOs."""
    del stderr
    payload = load_canonical_or_stdout_json(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=_CANONICAL_FILENAME,
        tool_id=tool_id,
    )
    if not isinstance(payload, dict):
        if payload is not None:
            _logger.warning(
                "openapi_scanner_parser.envelope_not_object",
                extra={
                    "event": "openapi_scanner_parser_envelope_not_object",
                    "tool_id": tool_id,
                    "actual_type": type(payload).__name__,
                },
            )
        return []
    records = list(_iter_records(payload, tool_id=tool_id))
    if not records:
        return []
    return _emit(records, artifacts_dir=artifacts_dir, tool_id=tool_id)


def _emit(
    records: list[dict[str, Any]],
    *,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    seen: set[DedupKey] = set()
    keyed: list[tuple[tuple[int, str, str, str], FindingDTO, str]] = []
    for record in records:
        key: DedupKey = (
            str(record.get("kind") or ""),
            str(record.get("finding_id") or record.get("endpoint") or ""),
            str(record.get("category") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding(record)
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        sort_key = (
            -_SEVERITY_RANK.get(str(record.get("severity") or "info"), 0),
            str(record.get("kind") or ""),
            str(record.get("finding_id") or ""),
            str(record.get("endpoint") or ""),
        )
        keyed.append((sort_key, finding, evidence_blob))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "openapi_scanner_parser.cap_reached",
                extra={
                    "event": "openapi_scanner_parser_cap_reached",
                    "tool_id": tool_id,
                    "cap": _MAX_FINDINGS,
                },
            )
            break
    keyed.sort(key=lambda item: item[0])
    if keyed:
        persist_jsonl_sidecar(
            artifacts_dir,
            sidecar_name=EVIDENCE_SIDECAR_NAME,
            evidence_records=[blob for _, _, blob in keyed],
            tool_id=tool_id,
        )
    return [finding for _, finding, _ in keyed]


def _build_finding(record: dict[str, Any]) -> FindingDTO:
    category = record.get("_category", FindingCategory.MISCONFIG)
    cwe = list(_CATEGORY_DEFAULT_CWE.get(category, (16,)))
    confidence = (
        ConfidenceLevel.LIKELY
        if record.get("kind") == "vulnerability"
        else ConfidenceLevel.CONFIRMED
    )
    severity = str(record.get("severity") or "info")
    return make_finding_dto(
        category=category,
        cwe=cwe,
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=_SEVERITY_TO_CVSS.get(severity, 0.0),
        confidence=confidence,
        owasp_wstg=["WSTG-CONF-04", "WSTG-INFO-08"],
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": record.get("kind"),
        "finding_id": record.get("finding_id"),
        "title": record.get("title"),
        "description": record.get("description"),
        "endpoint": record.get("endpoint"),
        "method": record.get("method"),
        "path": record.get("path"),
        "operation_id": record.get("operation_id"),
        "auth": record.get("auth"),
        "responses": record.get("responses"),
        "category": record.get("category"),
        "severity": record.get("severity"),
        "schema_version": record.get("schema_version"),
        "target": record.get("target"),
    }
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if value is None or value == "":
            continue
        if isinstance(value, list) and not value:
            continue
        cleaned[key] = value
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


def _iter_records(payload: dict[str, Any], *, tool_id: str) -> Iterable[dict[str, Any]]:
    schema_version = _string_field(payload, "schema_version")
    target = _string_field(payload, "target")
    findings = payload.get("findings") or payload.get("issues")
    emitted_findings = False
    if isinstance(findings, list):
        for raw in findings:
            if not isinstance(raw, dict):
                continue
            normalised = _normalise_finding(
                raw,
                schema_version=schema_version,
                target=target,
                tool_id=tool_id,
            )
            if normalised is None:
                continue
            emitted_findings = True
            yield normalised
    if emitted_findings:
        return
    endpoints = payload.get("endpoints")
    if isinstance(endpoints, list):
        for raw in endpoints:
            if not isinstance(raw, dict):
                continue
            normalised = _normalise_endpoint(
                raw,
                schema_version=schema_version,
                target=target,
            )
            if normalised is not None:
                yield normalised


def _normalise_finding(
    raw: dict[str, Any],
    *,
    schema_version: str | None,
    target: str | None,
    tool_id: str,
) -> dict[str, Any] | None:
    finding_id = _string_field(raw, "id") or _string_field(raw, "finding_id")
    if finding_id is None:
        _logger.warning(
            "openapi_scanner_parser.finding_missing_id",
            extra={
                "event": "openapi_scanner_parser_finding_missing_id",
                "tool_id": tool_id,
            },
        )
        return None
    severity = (_string_field(raw, "severity") or "medium").lower()
    category_hint = (_string_field(raw, "category") or "misconfig").lower()
    category = _CATEGORY_HINT.get(category_hint, FindingCategory.MISCONFIG)
    return {
        "kind": "vulnerability",
        "finding_id": finding_id,
        "title": _string_field(raw, "title"),
        "description": _string_field(raw, "description"),
        "endpoint": _string_field(raw, "endpoint"),
        "method": _string_field(raw, "method"),
        "path": _string_field(raw, "path"),
        "operation_id": _string_field(raw, "operationId")
        or _string_field(raw, "operation_id"),
        "category": category_hint,
        "severity": severity,
        "schema_version": schema_version,
        "target": target,
        "_category": category,
    }


def _normalise_endpoint(
    raw: dict[str, Any],
    *,
    schema_version: str | None,
    target: str | None,
) -> dict[str, Any] | None:
    method = _string_field(raw, "method")
    path = _string_field(raw, "path")
    if method is None or path is None:
        return None
    endpoint = f"{method.upper()} {path}"
    responses = [
        str(item)
        for item in (raw.get("responses") or [])
        if isinstance(item, str | int)
    ]
    return {
        "kind": "endpoint",
        "finding_id": endpoint,
        "title": f"Discovered API endpoint: {endpoint}",
        "endpoint": endpoint,
        "method": method.upper(),
        "path": path,
        "operation_id": _string_field(raw, "operationId")
        or _string_field(raw, "operation_id"),
        "auth": _string_field(raw, "auth") or "none",
        "responses": sorted(set(responses)),
        "category": "discovery",
        "severity": "info",
        "schema_version": schema_version,
        "target": target,
        "_category": FindingCategory.INFO,
    }


def _string_field(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_openapi_scanner_json",
]


def _typecheck_iterator() -> None:  # pragma: no cover - mypy seam
    _: Iterator[dict[str, Any]] = iter([])
    del _
