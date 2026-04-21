"""Parser for Aqua tfsec ``--format json`` output (Backlog/dev1_md §4.16 — ARG-021).

tfsec inspects Terraform modules and emits the following envelope:

.. code-block:: json

    {
      "results": [
        {
          "rule_id":          "AVD-AWS-0001",
          "long_id":          "aws-s3-enable-bucket-encryption",
          "rule_description": "Bucket should be encrypted",
          "rule_provider":    "aws",
          "rule_service":     "s3",
          "impact":           "Confidential data is unencrypted...",
          "resolution":       "Enable encryption...",
          "links":            ["https://aquasecurity.github.io/tfsec/..."],
          "description":      "Bucket does not have encryption enabled",
          "severity":         "HIGH",
          "warning":          false,
          "status":           1,
          "resource":         "aws_s3_bucket.example",
          "location": {
            "filename":     "/repo/main.tf",
            "start_line":   10,
            "end_line":     15
          }
        }
      ]
    }

Translation rules
-----------------

* **Severity** — tfsec emits ``CRITICAL`` / ``HIGH`` / ``MEDIUM`` /
  ``LOW`` (uppercase). Mapped one-to-one. ``CRITICAL`` falls into the
  ``critical`` bucket.

* **Confidence** — :class:`ConfidenceLevel.LIKELY` for HIGH/CRITICAL
  on a deterministic HCL match; :class:`ConfidenceLevel.SUSPECTED` for
  MEDIUM/LOW.

* **Category** — :class:`FindingCategory.MISCONFIG`. Findings whose
  ``rule_service`` indicates secrets handling (``ssm``, ``secrets-manager``,
  ``kms`` with weak config) keep MISCONFIG; pure secret leak detection
  is handled by gitleaks.

* **CWE** — fixed ``[16, 1032]``.

Dedup
-----

Stable key: ``(rule_id, location.filename, location.start_line)``.

Sidecar
-------

``artifacts_dir / "tfsec_findings.jsonl"``.
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


EVIDENCE_SIDECAR_NAME: Final[str] = "tfsec_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "tfsec.json"
_MAX_FINDINGS: Final[int] = 5_000
_MAX_EVIDENCE_BYTES: Final[int] = 4 * 1024


_CWE_MISCONFIG: Final[tuple[int, ...]] = (16, 1032)
_OWASP_WSTG_DEFAULT: Final[tuple[str, ...]] = ("WSTG-CONF-04",)


_SEVERITY_TO_CVSS: Final[dict[str, float]] = {
    "critical": 9.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "info": 0.0,
}


_SEVERITY_RANK: Final[dict[str, int]] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


DedupKey: TypeAlias = tuple[str, str, int]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_tfsec_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate tfsec ``--format json`` output into FindingDTOs."""
    del stderr
    payload = _load_payload(stdout=stdout, artifacts_dir=artifacts_dir, tool_id=tool_id)
    if payload is None:
        return []
    if not isinstance(payload, dict):
        _logger.warning(
            "tfsec_parser.envelope_not_dict",
            extra={
                "event": "tfsec_parser_envelope_not_dict",
                "tool_id": tool_id,
            },
        )
        return []
    raw_results = payload.get("results")
    if not isinstance(raw_results, list):
        return []
    records = list(_iter_normalised(raw_results, tool_id=tool_id))
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
                "tfsec_parser.cap_reached",
                extra={
                    "event": "tfsec_parser_cap_reached",
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
        str(record.get("filename") or ""),
        int(record.get("start_line") or 0),
    )


def _sort_key(record: dict[str, Any]) -> tuple[int, str, str, int]:
    severity = str(record.get("severity") or "info")
    return (
        -_SEVERITY_RANK.get(severity, 0),
        str(record.get("rule_id") or ""),
        str(record.get("filename") or ""),
        int(record.get("start_line") or 0),
    )


def _build_finding(record: dict[str, Any]) -> FindingDTO:
    return make_finding_dto(
        category=FindingCategory.MISCONFIG,
        cwe=list(_CWE_MISCONFIG),
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=float(record.get("cvss_v3_score") or 0.0),
        confidence=record["confidence"],
        owasp_wstg=list(_OWASP_WSTG_DEFAULT),
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": "tfsec",
        "rule_id": record.get("rule_id"),
        "long_id": record.get("long_id"),
        "rule_description": _truncate_text(record.get("rule_description")),
        "rule_provider": record.get("rule_provider"),
        "rule_service": record.get("rule_service"),
        "description": _truncate_text(record.get("description")),
        "filename": record.get("filename"),
        "start_line": record.get("start_line"),
        "end_line": record.get("end_line"),
        "resource": record.get("resource"),
        "severity": record.get("severity"),
        "tfsec_severity": record.get("tfsec_severity"),
        "impact": _truncate_text(record.get("impact")),
        "resolution": _truncate_text(record.get("resolution")),
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
            "tfsec_parser.evidence_sidecar_write_failed",
            extra={
                "event": "tfsec_parser_evidence_sidecar_write_failed",
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
                "tfsec_parser.canonical_read_failed",
                extra={
                    "event": "tfsec_parser_canonical_read_failed",
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
    raw_results: list[Any], *, tool_id: str
) -> Iterable[dict[str, Any]]:
    for raw in raw_results:
        if not isinstance(raw, dict):
            continue
        rule_id = _string_field(raw, "rule_id")
        location = raw.get("location")
        if rule_id is None or not isinstance(location, dict):
            _logger.warning(
                "tfsec_parser.result_missing_field",
                extra={
                    "event": "tfsec_parser_result_missing_field",
                    "tool_id": tool_id,
                    "missing": "rule_id" if rule_id is None else "location",
                },
            )
            continue
        filename = _string_field(location, "filename")
        if filename is None:
            _logger.warning(
                "tfsec_parser.result_missing_filename",
                extra={
                    "event": "tfsec_parser_result_missing_filename",
                    "tool_id": tool_id,
                    "rule_id": rule_id,
                },
            )
            continue
        tfsec_severity = (_string_field(raw, "severity") or "MEDIUM").upper()
        severity = _map_severity(tfsec_severity)
        confidence = (
            ConfidenceLevel.LIKELY
            if severity in {"high", "critical"}
            else ConfidenceLevel.SUSPECTED
        )
        yield {
            "rule_id": rule_id,
            "long_id": _string_field(raw, "long_id"),
            "rule_description": _string_field(raw, "rule_description"),
            "rule_provider": _string_field(raw, "rule_provider"),
            "rule_service": _string_field(raw, "rule_service"),
            "description": _string_field(raw, "description"),
            "filename": filename,
            "start_line": _coerce_int(location.get("start_line")) or 0,
            "end_line": _coerce_int(location.get("end_line")),
            "resource": _string_field(raw, "resource"),
            "severity": severity,
            "tfsec_severity": tfsec_severity,
            "impact": _string_field(raw, "impact"),
            "resolution": _string_field(raw, "resolution"),
            "confidence": confidence,
            "cvss_v3_score": _SEVERITY_TO_CVSS.get(severity, 0.0),
        }


def _map_severity(raw: str) -> str:
    lowered = raw.strip().lower()
    if lowered in {"critical", "high", "medium", "low"}:
        return lowered
    return "info"


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
    "parse_tfsec_json",
]
