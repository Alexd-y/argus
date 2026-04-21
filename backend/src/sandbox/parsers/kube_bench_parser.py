"""Parser for Aqua kube-bench ``--json`` output (Backlog/dev1_md §4.15 — ARG-021).

kube-bench runs the CIS Kubernetes Benchmark and emits a JSON envelope
with one or more *Controls* groups (master / node / etcd / policies /
managed-services). Each control contains a tree of tests:

.. code-block:: json

    {
      "Controls": [
        {
          "id":     "1",
          "version":"1.7",
          "text":   "Master Node Configuration Files",
          "node_type": "master",
          "tests": [
            {
              "section":     "1.1",
              "desc":        "Master Node Configuration",
              "results": [
                {
                  "test_number":  "1.1.1",
                  "test_desc":    "Ensure that the API server pod specification file permissions are set to 644",
                  "audit":        "stat -c %a /etc/kubernetes/...",
                  "remediation":  "chmod 644 /etc/kubernetes/...",
                  "test_info":    [],
                  "status":       "FAIL",
                  "scored":       true,
                  "actual_value": "660",
                  "expected_result": "permissions has permission 644"
                }
              ]
            }
          ]
        }
      ],
      "Totals": {"total_pass": 0, "total_fail": 12, "total_warn": 4, ...}
    }

Translation rules
-----------------

* **Status filter** — only ``status == "FAIL"`` and ``status == "WARN"``
  are emitted; ``PASS`` / ``INFO`` are dropped (we surface findings,
  not audit completeness). Backlog §11.

* **Severity** — ``FAIL`` for a *scored* control → ``high``, unscored
  ``FAIL`` → ``medium``; any ``WARN`` → ``medium``. Reflects the
  weighting CIS itself uses to score audited environments.

* **Confidence** — :class:`ConfidenceLevel.LIKELY`. kube-bench inspects
  live config files / kubelet args, but the rule logic does not
  exercise the cluster; treating every match as ``CONFIRMED`` would
  over-rank misconfig findings against runtime exploits.

* **Category** — :class:`FindingCategory.MISCONFIG` for everything
  this parser yields.

* **CWE** — fixed mapping ``[16, 250]`` (Configuration + Execution
  with Unnecessary Privileges) — these two CWEs cover the entire CIS
  benchmark surface.

Dedup
-----

Stable key: ``(test_number, node_type)``. The same test running on
master + node should *not* collapse — reporting a hardening gap on
both planes is action-relevant.

Cap
---

Hard-limited to :data:`_MAX_FINDINGS = 1_000`. CIS K8s benchmark
contains ≈120 controls per node-type; even a 5-cluster scan stays
well under the cap.

Sidecar
-------

Mirrored into ``artifacts_dir / "kube_bench_findings.jsonl"``.
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


EVIDENCE_SIDECAR_NAME: Final[str] = "kube_bench_findings.jsonl"
# kube-bench wrapper writes to /out/kubebench.json (no underscore) —
# canonical filename comes from backend/config/tools/kube_bench.yaml.
_CANONICAL_FILENAMES: Final[tuple[str, ...]] = ("kubebench.json", "kube_bench.json")
_MAX_FINDINGS: Final[int] = 1_000
_MAX_EVIDENCE_BYTES: Final[int] = 4 * 1024


_CWE_MISCONFIG: Final[tuple[int, ...]] = (16, 250)
_OWASP_WSTG_DEFAULT: Final[tuple[str, ...]] = ("WSTG-CONF-04",)


_SEVERITY_RANK: Final[dict[str, int]] = {
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


_SEVERITY_TO_CVSS: Final[dict[str, float]] = {
    "high": 7.0,
    "medium": 5.0,
    "low": 3.5,
    "info": 0.0,
}


_RELEVANT_STATUSES: Final[frozenset[str]] = frozenset({"FAIL", "WARN"})


DedupKey: TypeAlias = tuple[str, str]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_kube_bench_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate kube-bench ``--json`` output into FindingDTOs."""
    del stderr
    payload = _load_payload(stdout=stdout, artifacts_dir=artifacts_dir, tool_id=tool_id)
    if payload is None:
        return []
    if not isinstance(payload, dict):
        _logger.warning(
            "kube_bench_parser.envelope_not_dict",
            extra={
                "event": "kube_bench_parser_envelope_not_dict",
                "tool_id": tool_id,
            },
        )
        return []
    raw_controls = payload.get("Controls")
    if not isinstance(raw_controls, list):
        return []
    records = list(_iter_normalised(raw_controls, tool_id=tool_id))
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
                "kube_bench_parser.cap_reached",
                extra={
                    "event": "kube_bench_parser_cap_reached",
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
        str(record.get("test_number") or ""),
        str(record.get("node_type") or ""),
    )


def _sort_key(record: dict[str, Any]) -> tuple[int, str, str]:
    severity = str(record.get("severity") or "info")
    return (
        -_SEVERITY_RANK.get(severity, 0),
        str(record.get("node_type") or ""),
        str(record.get("test_number") or ""),
    )


def _build_finding(record: dict[str, Any]) -> FindingDTO:
    return make_finding_dto(
        category=FindingCategory.MISCONFIG,
        cwe=list(_CWE_MISCONFIG),
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=float(record.get("cvss_v3_score") or 0.0),
        confidence=ConfidenceLevel.LIKELY,
        owasp_wstg=list(_OWASP_WSTG_DEFAULT),
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": "kube_bench",
        "test_number": record.get("test_number"),
        "test_desc": _truncate_text(record.get("test_desc")),
        "section": record.get("section"),
        "section_desc": _truncate_text(record.get("section_desc")),
        "node_type": record.get("node_type"),
        "control_id": record.get("control_id"),
        "control_text": _truncate_text(record.get("control_text")),
        "control_version": record.get("control_version"),
        "status": record.get("status"),
        "severity": record.get("severity"),
        "scored": record.get("scored"),
        "audit": _truncate_text(record.get("audit")),
        "actual_value": _truncate_text(record.get("actual_value")),
        "expected_result": _truncate_text(record.get("expected_result")),
        "remediation": _truncate_text(record.get("remediation")),
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
            "kube_bench_parser.evidence_sidecar_write_failed",
            extra={
                "event": "kube_bench_parser_evidence_sidecar_write_failed",
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
                "kube_bench_parser.canonical_read_failed",
                extra={
                    "event": "kube_bench_parser_canonical_read_failed",
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
    raw_controls: list[Any], *, tool_id: str
) -> Iterable[dict[str, Any]]:
    for control in raw_controls:
        if not isinstance(control, dict):
            continue
        control_id = _string_field(control, "id")
        control_text = _string_field(control, "text")
        node_type = _string_field(control, "node_type") or "unknown"
        control_version = _string_field(control, "version")
        raw_tests = control.get("tests")
        if not isinstance(raw_tests, list):
            continue
        for test_section in raw_tests:
            if not isinstance(test_section, dict):
                continue
            section = _string_field(test_section, "section")
            section_desc = _string_field(test_section, "desc")
            raw_results = test_section.get("results")
            if not isinstance(raw_results, list):
                continue
            for result in raw_results:
                normalised = _normalise_result(
                    result,
                    control_id=control_id,
                    control_text=control_text,
                    control_version=control_version,
                    node_type=node_type,
                    section=section,
                    section_desc=section_desc,
                    tool_id=tool_id,
                )
                if normalised is not None:
                    yield normalised


def _normalise_result(
    result: Any,
    *,
    control_id: str | None,
    control_text: str | None,
    control_version: str | None,
    node_type: str,
    section: str | None,
    section_desc: str | None,
    tool_id: str,
) -> dict[str, Any] | None:
    if not isinstance(result, dict):
        return None
    status_raw = _string_field(result, "status") or ""
    status = status_raw.upper()
    if status not in _RELEVANT_STATUSES:
        return None
    test_number = _string_field(result, "test_number")
    if test_number is None:
        _logger.warning(
            "kube_bench_parser.result_missing_test_number",
            extra={
                "event": "kube_bench_parser_result_missing_test_number",
                "tool_id": tool_id,
                "node_type": node_type,
                "section": section,
            },
        )
        return None
    scored = bool(result.get("scored"))
    severity = _classify_severity(status=status, scored=scored)
    return {
        "control_id": control_id,
        "control_text": control_text,
        "control_version": control_version,
        "node_type": node_type,
        "section": section,
        "section_desc": section_desc,
        "test_number": test_number,
        "test_desc": _string_field(result, "test_desc"),
        "audit": _string_field(result, "audit"),
        "actual_value": _string_field(result, "actual_value"),
        "expected_result": _string_field(result, "expected_result"),
        "remediation": _string_field(result, "remediation"),
        "status": status,
        "severity": severity,
        "scored": scored,
        "cvss_v3_score": _SEVERITY_TO_CVSS.get(severity, 0.0),
    }


def _classify_severity(*, status: str, scored: bool) -> str:
    if status == "FAIL":
        return "high" if scored else "medium"
    return "medium"


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
    "parse_kube_bench_json",
]
