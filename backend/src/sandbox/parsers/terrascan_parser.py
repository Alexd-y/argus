"""Parser for Tenable Terrascan ``-o json`` output (Backlog/dev1_md §4.16 — ARG-021).

Terrascan analyses Terraform modules (and other IaC) using the bundled
OPA / Rego policy library. Output:

.. code-block:: json

    {
      "results": {
        "violations": [
          {
            "rule_name":         "ensureSecurityGroupNotOpenToInternet",
            "description":       "It is recommended that no security group allows unrestricted ingress access",
            "rule_id":           "AC_AWS_0319",
            "severity":          "HIGH",
            "category":          "Network Ports Security",
            "resource_name":     "main",
            "resource_type":     "aws_security_group",
            "module_name":       "root",
            "file":              "main.tf",
            "plan_root":         "./",
            "line":              25
          }
        ],
        "skipped_violations": [],
        "scan_summary": {...}
      }
    }

Translation rules
-----------------

* **Severity** — Terrascan emits ``HIGH`` / ``MEDIUM`` / ``LOW``;
  mapped one-to-one. Anything else collapses to ``info``.

* **Confidence** — :class:`ConfidenceLevel.LIKELY` for HIGH (Rego
  policies on parsed HCL are precise); :class:`ConfidenceLevel.SUSPECTED`
  for MEDIUM/LOW.

* **Category** — :class:`FindingCategory.MISCONFIG`. Findings whose
  ``category`` mentions "Secret*" / "Credentials" route to
  :class:`FindingCategory.SECRET_LEAK`.

* **CWE** — fixed ``[16, 1032]`` (Configuration / OWASP Misconfig);
  ``[798]`` for secret leaks.

Dedup
-----

Stable key: ``(rule_id, file, line)``.

Sidecar
-------

``artifacts_dir / "terrascan_findings.jsonl"``.
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


EVIDENCE_SIDECAR_NAME: Final[str] = "terrascan_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "terrascan.json"
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
    "credential",
    "password",
    "api key",
    "api-key",
    "access key",
    "access-key",
)


DedupKey: TypeAlias = tuple[str, str, int]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_terrascan_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate Terrascan ``-o json`` output into FindingDTOs."""
    del stderr
    payload = _load_payload(stdout=stdout, artifacts_dir=artifacts_dir, tool_id=tool_id)
    if payload is None:
        return []
    if not isinstance(payload, dict):
        _logger.warning(
            "terrascan_parser.envelope_not_dict",
            extra={
                "event": "terrascan_parser_envelope_not_dict",
                "tool_id": tool_id,
            },
        )
        return []
    results = payload.get("results")
    if not isinstance(results, dict):
        return []
    raw_violations = results.get("violations")
    if not isinstance(raw_violations, list):
        return []
    records = list(_iter_normalised(raw_violations, tool_id=tool_id))
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
                "terrascan_parser.cap_reached",
                extra={
                    "event": "terrascan_parser_cap_reached",
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
        str(record.get("rule_id") or ""),
        str(record.get("file") or ""),
        int(record.get("line") or 0),
    )


def _sort_key(record: dict[str, Any]) -> tuple[int, str, str, int]:
    severity = str(record.get("severity") or "info")
    return (
        -_SEVERITY_RANK.get(severity, 0),
        str(record.get("rule_id") or ""),
        str(record.get("file") or ""),
        int(record.get("line") or 0),
    )


def _build_finding(record: dict[str, Any]) -> FindingDTO:
    category: FindingCategory = record["category"]
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
        "kind": "terrascan",
        "rule_id": record.get("rule_id"),
        "rule_name": record.get("rule_name"),
        "description": _truncate_text(record.get("description")),
        "file": record.get("file"),
        "line": record.get("line"),
        "module_name": record.get("module_name"),
        "resource_name": record.get("resource_name"),
        "resource_type": record.get("resource_type"),
        "terrascan_category": record.get("terrascan_category"),
        "severity": record.get("severity"),
        "terrascan_severity": record.get("terrascan_severity"),
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
            "terrascan_parser.evidence_sidecar_write_failed",
            extra={
                "event": "terrascan_parser_evidence_sidecar_write_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


# ---------------------------------------------------------------------------
# Payload resolution
# ---------------------------------------------------------------------------


def _load_payload(*, stdout: bytes, artifacts_dir: Path, tool_id: str) -> Any:
    canonical = _safe_join(artifacts_dir, _CANONICAL_FILENAME)
    if canonical is not None and canonical.is_file():
        try:
            raw = canonical.read_bytes()
        except OSError as exc:
            _logger.warning(
                "terrascan_parser.canonical_read_failed",
                extra={
                    "event": "terrascan_parser_canonical_read_failed",
                    "tool_id": tool_id,
                    "path": _CANONICAL_FILENAME,
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
    if "/" in name or "\\" in name or ".." in name:
        return None
    return base / name


# ---------------------------------------------------------------------------
# Record normalisation
# ---------------------------------------------------------------------------


def _iter_normalised(
    raw_violations: list[Any], *, tool_id: str
) -> Iterable[dict[str, Any]]:
    for raw in raw_violations:
        if not isinstance(raw, dict):
            continue
        rule_id = _string_field(raw, "rule_id")
        file_path = _string_field(raw, "file")
        if rule_id is None or file_path is None:
            _logger.warning(
                "terrascan_parser.violation_missing_field",
                extra={
                    "event": "terrascan_parser_violation_missing_field",
                    "tool_id": tool_id,
                    "missing": "rule_id" if rule_id is None else "file",
                },
            )
            continue
        terrascan_severity = (_string_field(raw, "severity") or "MEDIUM").upper()
        severity = _map_severity(terrascan_severity)
        terrascan_category = _string_field(raw, "category") or ""
        category = _classify_category(terrascan_category=terrascan_category)
        confidence = (
            ConfidenceLevel.LIKELY if severity == "high" else ConfidenceLevel.SUSPECTED
        )
        yield {
            "rule_id": rule_id,
            "rule_name": _string_field(raw, "rule_name"),
            "description": _string_field(raw, "description"),
            "file": file_path,
            "line": _coerce_int(raw.get("line")) or 0,
            "module_name": _string_field(raw, "module_name"),
            "resource_name": _string_field(raw, "resource_name"),
            "resource_type": _string_field(raw, "resource_type"),
            "terrascan_category": terrascan_category or None,
            "severity": severity,
            "terrascan_severity": terrascan_severity,
            "category": category,
            "confidence": confidence,
            "cvss_v3_score": _SEVERITY_TO_CVSS.get(severity, 0.0),
        }


def _map_severity(raw: str) -> str:
    lowered = raw.strip().lower()
    if lowered in {"high", "medium", "low"}:
        return lowered
    return "info"


def _classify_category(*, terrascan_category: str) -> FindingCategory:
    lowered = terrascan_category.lower()
    if any(token in lowered for token in _SECRET_KEYWORDS):
        return FindingCategory.SECRET_LEAK
    return FindingCategory.MISCONFIG


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
    "parse_terrascan_json",
]
