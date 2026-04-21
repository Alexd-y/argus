"""Parser for Goodwith Dockle ``-f json`` output (Backlog/dev1_md §4.15 — ARG-021).

Dockle inspects container images against the CIS Docker Benchmark and
OWASP container Top-10. Output:

.. code-block:: json

    {
      "summary": {"fatal": 1, "warn": 3, "info": 2, "skip": 0, "pass": 5},
      "details": [
        {
          "code":     "CIS-DI-0001",
          "title":    "Create a user for the container",
          "level":    "FATAL",
          "alerts": [
            "Last user should not be root"
          ]
        },
        {
          "code":     "DKL-DI-0006",
          "title":    "Avoid latest tag",
          "level":    "WARN",
          "alerts":   ["Avoid 'latest' tag"]
        }
      ]
    }

Translation rules
-----------------

* **Level → severity** (Backlog §11):

  - ``FATAL`` → ``high``
  - ``WARN``  → ``medium``
  - ``INFO``  → ``info``
  - ``SKIP``  → dropped (not a finding; user opted out)
  - ``PASS``  → dropped (audit completeness only)

* **Confidence** — :class:`ConfidenceLevel.LIKELY` for FATAL,
  :class:`ConfidenceLevel.SUSPECTED` for WARN/INFO. Dockle is a
  rule-based checker; FATAL hits map to deterministic image config
  flaws (e.g., missing USER), so likelihood is high but exploitation
  still depends on the runtime context.

* **Category** — :class:`FindingCategory.MISCONFIG`.

* **CWE** — fixed ``[16, 250]`` (Configuration / Execution with
  Unnecessary Privileges).

Dedup
-----

Stable key: ``(code, alert)``. One Dockle code may emit multiple
``alerts`` per image (e.g., multiple secrets in env vars); each alert
is a separate finding.

Sidecar
-------

``artifacts_dir / "dockle_findings.jsonl"``.
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


EVIDENCE_SIDECAR_NAME: Final[str] = "dockle_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "dockle.json"
_MAX_FINDINGS: Final[int] = 1_000
_MAX_EVIDENCE_BYTES: Final[int] = 4 * 1024


_CWE_MISCONFIG: Final[tuple[int, ...]] = (16, 250)
_OWASP_WSTG_DEFAULT: Final[tuple[str, ...]] = ("WSTG-CONF-04",)


_LEVEL_TO_SEVERITY: Final[dict[str, str]] = {
    "FATAL": "high",
    "WARN": "medium",
    "INFO": "info",
}


_LEVEL_TO_CONFIDENCE: Final[dict[str, ConfidenceLevel]] = {
    "FATAL": ConfidenceLevel.LIKELY,
    "WARN": ConfidenceLevel.SUSPECTED,
    "INFO": ConfidenceLevel.SUSPECTED,
}


_SEVERITY_TO_CVSS: Final[dict[str, float]] = {
    "high": 7.0,
    "medium": 5.0,
    "info": 0.0,
}


_SEVERITY_RANK: Final[dict[str, int]] = {
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


_RELEVANT_LEVELS: Final[frozenset[str]] = frozenset({"FATAL", "WARN", "INFO"})


DedupKey: TypeAlias = tuple[str, str]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_dockle_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate Dockle ``-f json`` output into FindingDTOs."""
    del stderr
    payload = _load_payload(stdout=stdout, artifacts_dir=artifacts_dir, tool_id=tool_id)
    if payload is None:
        return []
    if not isinstance(payload, dict):
        _logger.warning(
            "dockle_parser.envelope_not_dict",
            extra={
                "event": "dockle_parser_envelope_not_dict",
                "tool_id": tool_id,
            },
        )
        return []
    raw_details = payload.get("details")
    if not isinstance(raw_details, list):
        return []
    records = list(_iter_normalised(raw_details, tool_id=tool_id))
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
    keyed: list[tuple[tuple[int, str, str], DedupKey, FindingDTO, str]] = []
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
                "dockle_parser.cap_reached",
                extra={
                    "event": "dockle_parser_cap_reached",
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
        str(record.get("code") or ""),
        str(record.get("alert") or ""),
    )


def _sort_key(record: dict[str, Any]) -> tuple[int, str, str]:
    severity = str(record.get("severity") or "info")
    return (
        -_SEVERITY_RANK.get(severity, 0),
        str(record.get("code") or ""),
        str(record.get("alert") or ""),
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
        "kind": "dockle",
        "code": record.get("code"),
        "title": _truncate_text(record.get("title")),
        "level": record.get("level"),
        "severity": record.get("severity"),
        "alert": _truncate_text(record.get("alert")),
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
            "dockle_parser.evidence_sidecar_write_failed",
            extra={
                "event": "dockle_parser_evidence_sidecar_write_failed",
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
                "dockle_parser.canonical_read_failed",
                extra={
                    "event": "dockle_parser_canonical_read_failed",
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
    raw_details: list[Any], *, tool_id: str
) -> Iterable[dict[str, Any]]:
    for raw in raw_details:
        if not isinstance(raw, dict):
            continue
        code = _string_field(raw, "code")
        level_raw = _string_field(raw, "level") or ""
        level = level_raw.upper()
        if code is None:
            _logger.warning(
                "dockle_parser.detail_missing_code",
                extra={
                    "event": "dockle_parser_detail_missing_code",
                    "tool_id": tool_id,
                    "level": level,
                },
            )
            continue
        if level not in _RELEVANT_LEVELS:
            continue
        title = _string_field(raw, "title")
        severity = _LEVEL_TO_SEVERITY.get(level, "info")
        confidence = _LEVEL_TO_CONFIDENCE.get(level, ConfidenceLevel.SUSPECTED)
        alerts = _extract_alerts(raw.get("alerts"))
        if not alerts:
            yield {
                "code": code,
                "title": title,
                "level": level,
                "severity": severity,
                "confidence": confidence,
                "alert": None,
                "cvss_v3_score": _SEVERITY_TO_CVSS.get(severity, 0.0),
            }
            continue
        for alert in alerts:
            yield {
                "code": code,
                "title": title,
                "level": level,
                "severity": severity,
                "confidence": confidence,
                "alert": alert,
                "cvss_v3_score": _SEVERITY_TO_CVSS.get(severity, 0.0),
            }


def _extract_alerts(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for item in raw:
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
        elif isinstance(item, dict):
            desc = item.get("desc") or item.get("description")
            if isinstance(desc, str) and desc.strip():
                out.append(desc.strip())
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
    "parse_dockle_json",
]
