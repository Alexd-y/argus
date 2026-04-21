"""Parser for Checkmarx KICS ``--report-formats json`` output (Backlog/dev1_md §4.16 — ARG-021).

KICS scans IaC bundles (Terraform / K8s / Docker / CloudFormation /
ARM / OpenAPI / gRPC / Ansible / Helm / Crossplane) and writes a
``results.json`` envelope under ``--output-path``:

.. code-block:: json

    {
      "kics_version":   "v1.7.x",
      "files_scanned":  42,
      "lines_scanned":  9876,
      "queries_total":  1234,
      "queries":  [
        {
          "query_name":     "Privileged Container",
          "query_id":       "1c5e0e6f-...",
          "query_url":      "https://docs.kics.io/...",
          "severity":       "HIGH",
          "platform":       "Kubernetes",
          "category":       "Insecure Configurations",
          "description":    "...",
          "cwe":            "250",
          "files": [
            {
              "file_name":           "deployment.yaml",
              "similarity_id":       "abc123...",
              "line":                42,
              "issue_type":          "MissingAttribute",
              "search_key":          "metadata.name=...",
              "search_line":         42,
              "search_value":        "true",
              "expected_value":      "false",
              "actual_value":        "true",
              "resource_type":       "Deployment",
              "resource_name":       "frontend"
            }
          ]
        }
      ],
      "severity_counters": {"INFO": 0, "LOW": 1, "MEDIUM": 12, "HIGH": 4}
    }

Translation rules
-----------------

* **Severity** — KICS emits ``HIGH`` / ``MEDIUM`` / ``LOW`` / ``INFO``
  / ``TRACE`` (uppercase). Mapped one-to-one. ``TRACE`` collapses to
  ``info``.

* **Confidence** — :class:`ConfidenceLevel.LIKELY` for HIGH/CRITICAL
  on a deterministic file/line match; :class:`ConfidenceLevel.SUSPECTED`
  otherwise.

* **Category** — :class:`FindingCategory.MISCONFIG` for the bulk of
  KICS rules. Findings whose ``query_name`` mentions ``secret`` /
  ``credential`` / ``password`` route to
  :class:`FindingCategory.SECRET_LEAK`.

* **CWE** — extracted from the query's ``cwe`` field (``"250"`` /
  ``250`` / ``"CWE-250"``); falls back to ``[16, 1032]``.

Dedup
-----

Stable key: ``(query_id, file_name, line)``. KICS emits one record
per (query × file × line) match, so re-runs collapse cleanly.

Sidecar
-------

``artifacts_dir / "kics_findings.jsonl"``.
"""

from __future__ import annotations

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
    SENTINEL_CVSS_VECTOR,
    make_finding_dto,
    safe_load_json,
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------


EVIDENCE_SIDECAR_NAME: Final[str] = "kics_findings.jsonl"
# KICS' ``-o {dir}`` writes ``results.json`` by default; ``kics.json``
# is supported for back-compat with custom wrappers.
_CANONICAL_FILENAMES: Final[tuple[str, ...]] = ("results.json", "kics.json")
_MAX_FINDINGS: Final[int] = 5_000
_MAX_EVIDENCE_BYTES: Final[int] = 4 * 1024


_CWE_MISCONFIG_DEFAULT: Final[tuple[int, ...]] = (16, 1032)
_CWE_SECRET_LEAK: Final[tuple[int, ...]] = (798,)
_OWASP_MISCONFIG: Final[tuple[str, ...]] = ("WSTG-CONF-04",)
_OWASP_SECRET_LEAK: Final[tuple[str, ...]] = ("WSTG-ATHN-06", "WSTG-INFO-08")


_SEVERITY_TO_CVSS: Final[dict[str, float]] = {
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "info": 0.0,
}


_SEVERITY_RANK: Final[dict[str, int]] = {
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


_SECRET_KEYWORDS: Final[tuple[str, ...]] = (
    "secret",
    "password",
    "credential",
    "api key",
    "api-key",
    "access key",
    "access-key",
    "token",
    "private key",
)


DedupKey: TypeAlias = tuple[str, str, int]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_kics_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate KICS ``--report-formats json`` output into FindingDTOs."""
    del stderr
    payload = _load_payload(stdout=stdout, artifacts_dir=artifacts_dir, tool_id=tool_id)
    if payload is None:
        return []
    if not isinstance(payload, dict):
        _logger.warning(
            "kics_parser.envelope_not_dict",
            extra={
                "event": "kics_parser_envelope_not_dict",
                "tool_id": tool_id,
            },
        )
        return []
    raw_queries = payload.get("queries")
    if not isinstance(raw_queries, list):
        return []
    records = list(_iter_normalised(raw_queries, tool_id=tool_id))
    if not records:
        return []
    return _emit(records, artifacts_dir=artifacts_dir, tool_id=tool_id)


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
    keyed: list[tuple[tuple[int, str, str, int], DedupKey, FindingDTO, str]] = []
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
                "kics_parser.cap_reached",
                extra={
                    "event": "kics_parser_cap_reached",
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
    return (
        str(record.get("query_id") or ""),
        str(record.get("file_name") or ""),
        int(record.get("line") or 0),
    )


def _sort_key(record: dict[str, Any]) -> tuple[int, str, str, int]:
    severity = str(record.get("severity") or "info")
    return (
        -_SEVERITY_RANK.get(severity, 0),
        str(record.get("query_id") or ""),
        str(record.get("file_name") or ""),
        int(record.get("line") or 0),
    )


def _build_finding(record: dict[str, Any]) -> FindingDTO:
    category: FindingCategory = record["category"]
    cwe_list = list(record.get("cwe") or ())
    if not cwe_list:
        cwe_list = list(
            _CWE_SECRET_LEAK
            if category is FindingCategory.SECRET_LEAK
            else _CWE_MISCONFIG_DEFAULT
        )
    owasp = list(
        _OWASP_SECRET_LEAK
        if category is FindingCategory.SECRET_LEAK
        else _OWASP_MISCONFIG
    )
    return make_finding_dto(
        category=category,
        cwe=cwe_list,
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=float(record.get("cvss_v3_score") or 0.0),
        confidence=record["confidence"],
        owasp_wstg=owasp,
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": "kics",
        "query_id": record.get("query_id"),
        "query_name": _truncate_text(record.get("query_name")),
        "query_url": record.get("query_url"),
        "platform": record.get("platform"),
        "kics_category": record.get("kics_category"),
        "file_name": record.get("file_name"),
        "line": record.get("line"),
        "severity": record.get("severity"),
        "kics_severity": record.get("kics_severity"),
        "issue_type": record.get("issue_type"),
        "resource_type": record.get("resource_type"),
        "resource_name": record.get("resource_name"),
        "search_key": _truncate_text(record.get("search_key")),
        "expected_value": _truncate_text(record.get("expected_value")),
        "actual_value": _truncate_text(record.get("actual_value")),
        "cwe": list(record.get("cwe") or ()),
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
    try:
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        sidecar_path = artifacts_dir / EVIDENCE_SIDECAR_NAME
        with sidecar_path.open("w", encoding="utf-8") as fh:
            for blob in evidence_records:
                fh.write(blob)
                fh.write("\n")
    except OSError as exc:
        _logger.warning(
            "kics_parser.evidence_sidecar_write_failed",
            extra={
                "event": "kics_parser_evidence_sidecar_write_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


# ---------------------------------------------------------------------------
# Payload resolution
# ---------------------------------------------------------------------------


def _load_payload(*, stdout: bytes, artifacts_dir: Path, tool_id: str) -> Any:
    for name in _CANONICAL_FILENAMES:
        canonical = _safe_join(artifacts_dir, name)
        if canonical is None or not canonical.is_file():
            continue
        try:
            raw = canonical.read_bytes()
        except OSError as exc:
            _logger.warning(
                "kics_parser.canonical_read_failed",
                extra={
                    "event": "kics_parser_canonical_read_failed",
                    "tool_id": tool_id,
                    "path": name,
                    "error_type": type(exc).__name__,
                },
            )
            continue
        if raw.strip():
            payload = safe_load_json(raw, tool_id=tool_id)
            if payload is not None:
                return payload
    if stdout and stdout.strip():
        return safe_load_json(stdout, tool_id=tool_id)
    return None


def _safe_join(base: Path, name: str) -> Path | None:
    if "/" in name or "\\" in name or ".." in name:
        return None
    return base / name


# ---------------------------------------------------------------------------
# Record normalisation
# ---------------------------------------------------------------------------


def _iter_normalised(
    raw_queries: list[Any], *, tool_id: str
) -> Iterable[dict[str, Any]]:
    for query in raw_queries:
        if not isinstance(query, dict):
            continue
        query_id = _string_field(query, "query_id")
        if query_id is None:
            _logger.warning(
                "kics_parser.query_missing_id",
                extra={
                    "event": "kics_parser_query_missing_id",
                    "tool_id": tool_id,
                },
            )
            continue
        query_name = _string_field(query, "query_name") or query_id
        kics_severity = (_string_field(query, "severity") or "MEDIUM").upper()
        severity = _map_severity(kics_severity)
        cwe_list = _extract_cwe(query.get("cwe"))
        category = _classify_category(query_name=query_name)
        confidence = (
            ConfidenceLevel.LIKELY if severity == "high" else ConfidenceLevel.SUSPECTED
        )
        platform = _string_field(query, "platform")
        kics_category = _string_field(query, "category")
        query_url = _string_field(query, "query_url")
        files = query.get("files")
        if not isinstance(files, list):
            continue
        for file_entry in files:
            if not isinstance(file_entry, dict):
                continue
            file_name = _string_field(file_entry, "file_name")
            if file_name is None:
                continue
            yield {
                "query_id": query_id,
                "query_name": query_name,
                "query_url": query_url,
                "platform": platform,
                "kics_category": kics_category,
                "file_name": file_name,
                "line": _coerce_int(file_entry.get("line")) or 0,
                "severity": severity,
                "kics_severity": kics_severity,
                "category": category,
                "confidence": confidence,
                "cwe": cwe_list,
                "issue_type": _string_field(file_entry, "issue_type"),
                "resource_type": _string_field(file_entry, "resource_type"),
                "resource_name": _string_field(file_entry, "resource_name"),
                "search_key": _string_field(file_entry, "search_key"),
                "expected_value": _string_field(file_entry, "expected_value"),
                "actual_value": _string_field(file_entry, "actual_value"),
                "cvss_v3_score": _SEVERITY_TO_CVSS.get(severity, 0.0),
            }


def _map_severity(raw: str) -> str:
    lowered = raw.strip().lower()
    if lowered == "trace":
        return "info"
    if lowered in {"high", "medium", "low", "info"}:
        return lowered
    return "info"


def _classify_category(*, query_name: str) -> FindingCategory:
    lowered = query_name.lower()
    if any(token in lowered for token in _SECRET_KEYWORDS):
        return FindingCategory.SECRET_LEAK
    return FindingCategory.MISCONFIG


def _extract_cwe(raw: Any) -> list[int]:
    if isinstance(raw, dict):
        return _extract_cwe(raw.get("id"))
    if isinstance(raw, list):
        out: list[int] = []
        for item in raw:
            for cwe_id in _extract_cwe(item):
                out.append(cwe_id)
        return sorted(set(out))
    if isinstance(raw, bool):
        return []
    if isinstance(raw, int) and raw > 0:
        return [raw]
    if isinstance(raw, str):
        token = raw.strip().upper()
        if token.startswith("CWE-"):
            token = token[4:]
        if token.isdigit():
            value = int(token)
            return [value] if value > 0 else []
    return []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _string_field(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _coerce_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        candidate = int(value.strip())
        return candidate if candidate >= 0 else None
    return None


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
    "parse_kics_json",
]
