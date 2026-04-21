"""Parser for ``graphql-cop`` JSON output (Backlog §4.14 — ARG-029).

``graphql-cop`` runs ~15 GraphQL-specific safety checks against
``{url}/graphql`` and emits a top-level JSON array.  Each entry has the
shape::

    {
      "title":       "Introspection Query Enabled",
      "description": "Introspection query enabled - https://...",
      "impact":      "Information Leakage",
      "severity":    "HIGH",
      "result":      true,
      "color":       "red",
      "curl_verify": "curl -X POST -H 'Content-Type: application/json' ..."
    }

Only entries with ``result == true`` are emitted as findings (the
others are negative observations and only inflate the dispatch
contract).  Severity is normalised to lowercase, missing severities
default to ``medium``, and CWEs are mapped from the check's title via a
small keyword table:

* ``introspection`` / ``field suggestions`` / ``debug`` → 200 (info leak)
* ``alias`` / ``batch`` / ``deep query`` / ``circular``  → 770/400 (DoS)
* ``missing csrf`` / ``get`` / ``post``                  → 352 (CSRF)
* ``injection`` (rare in upstream)                       → 89

Sidecar lives at ``artifacts_dir / "graphql_cop_findings.jsonl"`` and
includes the redacted curl PoC (auth headers stripped) for triage.
"""

from __future__ import annotations

import json
import logging
import re
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


EVIDENCE_SIDECAR_NAME: Final[str] = "graphql_cop_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "graphqlcop.json"
_MAX_FINDINGS: Final[int] = 1_000


_SEVERITY_TO_CVSS: Final[dict[str, float]] = {
    "critical": 9.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "novel": 5.0,
    "info": 0.0,
}


_SEVERITY_RANK: Final[dict[str, int]] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "novel": 1,
    "info": 0,
}


_DOS_KEYWORDS: Final[tuple[str, ...]] = (
    "alias",
    "batch",
    "deep query",
    "circular",
    "field duplication",
    "directive overload",
)


_CSRF_KEYWORDS: Final[tuple[str, ...]] = (
    "csrf",
    "get-based",
    "post-based",
)


_INFO_LEAK_KEYWORDS: Final[tuple[str, ...]] = (
    "introspection",
    "field suggestions",
    "trace mode",
    "debug",
    "graphiql",
)


_INJECTION_KEYWORDS: Final[tuple[str, ...]] = (
    "injection",
    "sqli",
)


_CURL_AUTH_HEADER_RE: Final[re.Pattern[str]] = re.compile(
    r"-H\s+['\"]\s*(?:Authorization|Cookie|X-API-Key)\s*:\s*[^'\"]+['\"]",
    re.IGNORECASE,
)


DedupKey: TypeAlias = tuple[str, str]


def parse_graphql_cop_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate graphql-cop output into FindingDTOs."""
    del stderr
    payload = load_canonical_or_stdout_json(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=_CANONICAL_FILENAME,
        tool_id=tool_id,
    )
    if not isinstance(payload, list):
        if payload is not None:
            _logger.warning(
                "graphql_cop_parser.payload_not_array",
                extra={
                    "event": "graphql_cop_parser_payload_not_array",
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
    keyed: list[tuple[tuple[int, str], FindingDTO, str]] = []
    for record in records:
        key: DedupKey = (
            str(record.get("title") or ""),
            str(record.get("severity") or "medium"),
        )
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding(record)
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        sort_key = (
            -_SEVERITY_RANK.get(str(record.get("severity") or "medium"), 0),
            str(record.get("title") or ""),
        )
        keyed.append((sort_key, finding, evidence_blob))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "graphql_cop_parser.cap_reached",
                extra={
                    "event": "graphql_cop_parser_cap_reached",
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
    category: FindingCategory = record.get("_category", FindingCategory.MISCONFIG)
    cwes = record.get("_cwes") or [200]
    severity = str(record.get("severity") or "medium")
    return make_finding_dto(
        category=category,
        cwe=list(cwes),
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=_SEVERITY_TO_CVSS.get(severity, 5.0),
        confidence=ConfidenceLevel.LIKELY,
        owasp_wstg=["WSTG-INFO-08", "WSTG-CONF-04"],
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "title": record.get("title"),
        "description": record.get("description"),
        "impact": record.get("impact"),
        "severity": record.get("severity"),
        "category": record.get("category"),
        "curl_verify": record.get("curl_verify"),
    }
    cleaned: dict[str, Any] = {
        key: value
        for key, value in payload.items()
        if value is not None and value != ""
    }
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


def _iter_records(payload: list[Any], *, tool_id: str) -> Iterable[dict[str, Any]]:
    for index, raw in enumerate(payload):
        if not isinstance(raw, dict):
            _logger.debug(
                "graphql_cop_parser.entry_not_object",
                extra={
                    "event": "graphql_cop_parser_entry_not_object",
                    "tool_id": tool_id,
                    "index": index,
                },
            )
            continue
        if not _coerce_bool(raw.get("result"), default=True):
            continue
        title = _string_field(raw, "title")
        if title is None:
            _logger.debug(
                "graphql_cop_parser.entry_missing_title",
                extra={
                    "event": "graphql_cop_parser_entry_missing_title",
                    "tool_id": tool_id,
                    "index": index,
                },
            )
            continue
        category, cwes = _classify(title)
        severity = _normalise_severity(_string_field(raw, "severity"))
        yield {
            "title": title,
            "description": _string_field(raw, "description"),
            "impact": _string_field(raw, "impact"),
            "severity": severity,
            "category": category.name.lower(),
            "curl_verify": _redact_curl(_string_field(raw, "curl_verify")),
            "_category": category,
            "_cwes": cwes,
        }


def _coerce_bool(value: Any, *, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1"}:
            return True
        if lowered in {"false", "no", "0"}:
            return False
    if value is None:
        return default
    return bool(value)


def _normalise_severity(raw: str | None) -> str:
    if raw is None:
        return "medium"
    candidate = raw.strip().lower()
    if candidate in _SEVERITY_TO_CVSS:
        return candidate
    if candidate.startswith(("crit",)):
        return "critical"
    if candidate.startswith("hi"):
        return "high"
    if candidate.startswith("med"):
        return "medium"
    if candidate.startswith("lo"):
        return "low"
    return "medium"


def _classify(title: str) -> tuple[FindingCategory, tuple[int, ...]]:
    lowered = title.lower()
    if any(word in lowered for word in _INJECTION_KEYWORDS):
        return FindingCategory.OTHER, (74,)
    if any(word in lowered for word in _DOS_KEYWORDS):
        return FindingCategory.DOS, (770, 400)
    if any(word in lowered for word in _CSRF_KEYWORDS):
        return FindingCategory.CSRF, (352,)
    if any(word in lowered for word in _INFO_LEAK_KEYWORDS):
        return FindingCategory.INFO, (200,)
    return FindingCategory.MISCONFIG, (16, 200)


def _redact_curl(curl: str | None) -> str | None:
    if curl is None:
        return None
    return _CURL_AUTH_HEADER_RE.sub("-H '<REDACTED-AUTH>'", curl)


def _string_field(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_graphql_cop_json",
]


def _typecheck_iterator() -> None:  # pragma: no cover - mypy seam
    _: Iterator[dict[str, Any]] = iter([])
    del _
