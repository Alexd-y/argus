"""Parser for Checkov ``-o json`` output (Backlog/dev1_md §4.15 — ARG-021).

Bridgecrew Checkov is a multi-format IaC scanner; output is a JSON
envelope that may be either a single object (single-runner) or a list
of objects (multi-runner: terraform, cloudformation, kubernetes, …).

Single-runner shape:

.. code-block:: json

    {
      "check_type": "terraform",
      "results": {
        "passed_checks": [...],
        "failed_checks": [
          {
            "check_id":      "CKV_AWS_20",
            "bc_check_id":   "BC_AWS_S3_1",
            "check_name":    "S3 bucket has an ACL of public-read or public-read-write",
            "check_class":   "checkov.terraform.checks.resource.aws.S3PublicACLRead",
            "file_path":     "/main.tf",
            "file_abs_path": "/repo/main.tf",
            "file_line_range": [10, 20],
            "resource":      "aws_s3_bucket.public",
            "severity":      "HIGH",
            "guideline":     "https://docs.bridgecrew.io/...",
            "code_block":    [["10", "resource ..."], ...],
            "evaluations":   {...}
          }
        ],
        "skipped_checks": [...],
        "parsing_errors": [...]
      },
      "summary": {...}
    }

Multi-runner shape: a top-level ``list`` of single-runner objects.

Translation rules
-----------------

* **Severity** — Checkov ships ``severity`` as
  ``CRITICAL`` / ``HIGH`` / ``MEDIUM`` / ``LOW`` / ``INFO`` (uppercase).
  When absent (older policies), default to ``MEDIUM``. Mapped one-to-one
  onto ARGUS buckets.

* **Confidence** — :class:`ConfidenceLevel.LIKELY` for HIGH/CRITICAL
  (Checkov asserts on declarative IaC; reachability is high), and
  :class:`ConfidenceLevel.SUSPECTED` for everything else.

* **Category** — :class:`FindingCategory.MISCONFIG`. Findings whose
  ``check_id`` starts with ``CKV_SECRET_*`` route to
  :class:`FindingCategory.SECRET_LEAK` instead (Checkov's secrets
  ruleset is a separate namespace).

* **CWE** — sourced from per-rule mapping; falls back to ``[16, 1032]``
  (Configuration / OWASP Misconfig).

Dedup
-----

Stable key: ``(check_id, file_path, start_line)``.

Sidecar
-------

``artifacts_dir / "checkov_findings.jsonl"``.
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


EVIDENCE_SIDECAR_NAME: Final[str] = "checkov_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "checkov.json"
_MAX_FINDINGS: Final[int] = 5_000
_MAX_EVIDENCE_BYTES: Final[int] = 4 * 1024


_CWE_MISCONFIG_DEFAULT: Final[tuple[int, ...]] = (16, 1032)
_CWE_SECRET_LEAK: Final[tuple[int, ...]] = (798,)
_OWASP_MISCONFIG: Final[tuple[str, ...]] = ("WSTG-CONF-04",)
_OWASP_SECRET_LEAK: Final[tuple[str, ...]] = ("WSTG-ATHN-06", "WSTG-INFO-08")


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


def parse_checkov_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate Checkov ``-o json`` output into FindingDTOs."""
    del stderr
    payload = _load_payload(stdout=stdout, artifacts_dir=artifacts_dir, tool_id=tool_id)
    if payload is None:
        return []
    runners = _flatten_runners(payload, tool_id=tool_id)
    if not runners:
        return []
    records: list[dict[str, Any]] = []
    for runner in runners:
        results = runner.get("results")
        if not isinstance(results, dict):
            continue
        check_type = (
            runner.get("check_type")
            if isinstance(runner.get("check_type"), str)
            else None
        )
        failed = results.get("failed_checks")
        if not isinstance(failed, list):
            continue
        records.extend(_iter_normalised(failed, check_type=check_type, tool_id=tool_id))
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
                "checkov_parser.cap_reached",
                extra={
                    "event": "checkov_parser_cap_reached",
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
        str(record.get("check_id") or ""),
        str(record.get("file_path") or ""),
        int(record.get("start_line") or 0),
    )


def _sort_key(record: dict[str, Any]) -> tuple[int, str, str, int]:
    severity = str(record.get("severity") or "info")
    return (
        -_SEVERITY_RANK.get(severity, 0),
        str(record.get("check_id") or ""),
        str(record.get("file_path") or ""),
        int(record.get("start_line") or 0),
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
        "kind": "checkov",
        "check_id": record.get("check_id"),
        "bc_check_id": record.get("bc_check_id"),
        "check_name": _truncate_text(record.get("check_name")),
        "check_class": record.get("check_class"),
        "check_type": record.get("check_type"),
        "file_path": record.get("file_path"),
        "file_abs_path": record.get("file_abs_path"),
        "start_line": record.get("start_line"),
        "end_line": record.get("end_line"),
        "resource": record.get("resource"),
        "severity": record.get("severity"),
        "checkov_severity": record.get("checkov_severity"),
        "guideline": record.get("guideline"),
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
            "checkov_parser.evidence_sidecar_write_failed",
            extra={
                "event": "checkov_parser_evidence_sidecar_write_failed",
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
                "checkov_parser.canonical_read_failed",
                extra={
                    "event": "checkov_parser_canonical_read_failed",
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


def _flatten_runners(payload: Any, *, tool_id: str) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    _logger.warning(
        "checkov_parser.envelope_unexpected_type",
        extra={
            "event": "checkov_parser_envelope_unexpected_type",
            "tool_id": tool_id,
            "actual_type": type(payload).__name__,
        },
    )
    return []


# ---------------------------------------------------------------------------
# Record normalisation
# ---------------------------------------------------------------------------


def _iter_normalised(
    failed_checks: list[Any],
    *,
    check_type: str | None,
    tool_id: str,
) -> Iterable[dict[str, Any]]:
    for raw in failed_checks:
        if not isinstance(raw, dict):
            continue
        check_id = _string_field(raw, "check_id")
        file_path = _string_field(raw, "file_path")
        if check_id is None or file_path is None:
            _logger.warning(
                "checkov_parser.result_missing_field",
                extra={
                    "event": "checkov_parser_result_missing_field",
                    "tool_id": tool_id,
                    "missing": "check_id" if check_id is None else "file_path",
                },
            )
            continue
        line_range = _extract_line_range(raw.get("file_line_range"))
        start_line = line_range[0] if line_range else 0
        end_line = line_range[1] if len(line_range) >= 2 else None
        checkov_severity = (_string_field(raw, "severity") or "MEDIUM").upper()
        severity = _map_severity(checkov_severity)
        category = _classify_category(check_id=check_id)
        confidence = (
            ConfidenceLevel.LIKELY
            if severity in {"high", "critical"}
            else ConfidenceLevel.SUSPECTED
        )
        yield {
            "check_id": check_id,
            "bc_check_id": _string_field(raw, "bc_check_id"),
            "check_name": _string_field(raw, "check_name"),
            "check_class": _string_field(raw, "check_class"),
            "check_type": check_type,
            "file_path": file_path,
            "file_abs_path": _string_field(raw, "file_abs_path"),
            "start_line": start_line,
            "end_line": end_line,
            "resource": _string_field(raw, "resource"),
            "severity": severity,
            "checkov_severity": checkov_severity,
            "category": category,
            "confidence": confidence,
            "guideline": _string_field(raw, "guideline"),
            "cvss_v3_score": _SEVERITY_TO_CVSS.get(severity, 0.0),
        }


def _map_severity(raw: str) -> str:
    lowered = raw.strip().lower()
    if lowered in {"critical", "high", "medium", "low"}:
        return lowered
    return "info"


def _classify_category(*, check_id: str) -> FindingCategory:
    if check_id.upper().startswith(("CKV_SECRET_", "CKV_GIT_")):
        return FindingCategory.SECRET_LEAK
    return FindingCategory.MISCONFIG


def _extract_line_range(raw: Any) -> list[int]:
    if not isinstance(raw, list):
        return []
    out: list[int] = []
    for item in raw:
        if isinstance(item, bool):
            continue
        if isinstance(item, int) and item >= 0:
            out.append(item)
        elif isinstance(item, str) and item.strip().isdigit():
            out.append(int(item.strip()))
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _string_field(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
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
    "parse_checkov_json",
]
