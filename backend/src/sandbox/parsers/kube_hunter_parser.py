"""Parser for Aqua kube-hunter ``--report json`` output (Backlog/dev1_md §4.15 — ARG-018 / F-M03).

kube-hunter probes a remote Kubernetes attack surface and, with
``--report json``, emits a single JSON envelope with three arrays —
``nodes`` (discovered hosts), ``services`` (open K8s services), and
``vulnerabilities`` (the actionable findings)::

.. code-block:: json

    {
      "nodes": [{"type": "Node/Master", "location": "10.0.0.5"}],
      "services": [
        {"service": "Kubelet API", "location": "10.0.0.5:10250",
         "description": "The read-only port on the kubelet ..."}
      ],
      "vulnerabilities": [
        {
          "location":      "10.0.0.5:10250",
          "vid":           "KHV005",
          "category":      "Information Disclosure",
          "severity":      "medium",
          "vulnerability": "Access to pod's secrets",
          "description":   "Accessing the pods secrets ...",
          "evidence":      "count: 3",
          "avd_reference": "avd.aquasec.com/...",
          "hunter":        "Kubelet Secure Ports Hunter"
        }
      ]
    }

Only the ``vulnerabilities`` array yields findings — ``nodes`` /
``services`` are attack-surface context, not issues, and are folded into
the evidence sidecar for the matching location instead of emitting noise.

Translation rules
-----------------

* **Category** — kube-hunter's own ``category`` string drives the
  :class:`FindingCategory` mapping (see :data:`_CATEGORY_MAP`). Unknown
  categories fall back to :class:`FindingCategory.MISCONFIG` — a
  Kubernetes attack-surface issue is a misconfiguration by default.

* **Severity → CVSS** — kube-hunter grades ``low`` / ``medium`` / ``high``.
  These map to representative CVSS base scores (:data:`_SEVERITY_TO_CVSS`);
  the real vector is re-derived downstream, so the sentinel vector is used.

* **Confidence** — :class:`ConfidenceLevel.LIKELY`. kube-hunter issues
  real HTTP probes against the control plane (active detection) but does
  not weaponise them, so ``CONFIRMED`` would over-rank against a genuine
  exploited finding.

* **CWE** — per-category mapping (:data:`_CATEGORY_CWE`) drawn from the
  ``cwe_hints`` declared in ``config/tools/kube_hunter.yaml``.

Dedup
-----

Stable key: ``(vid, location)``. The same ``KHV`` id on two different
kubelet endpoints is two distinct findings; the same id on the same
endpoint (kube-hunter can repeat across hunters) collapses to one.

Cap
---

Hard-limited to :data:`_MAX_FINDINGS = 1_000`.

Sidecar
-------

Mirrored into ``artifacts_dir / "kube_hunter_findings.jsonl"``.
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
    SSVCDecision,
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


EVIDENCE_SIDECAR_NAME: Final[str] = "kube_hunter_findings.jsonl"
# kube-hunter wrapper redirects to /out/kubehunter.json (no underscore) —
# canonical filename comes from backend/config/tools/kube_hunter.yaml.
_CANONICAL_FILENAMES: Final[tuple[str, ...]] = ("kubehunter.json", "kube_hunter.json")
_MAX_FINDINGS: Final[int] = 1_000
_MAX_EVIDENCE_BYTES: Final[int] = 4 * 1024


# kube-hunter's ``category`` strings → FindingDTO category.
_CATEGORY_MAP: Final[dict[str, FindingCategory]] = {
    "remote code execution": FindingCategory.RCE,
    "information disclosure": FindingCategory.INFO,
    "access risk": FindingCategory.AUTH,
    "unauthenticated access": FindingCategory.AUTH,
    "identity theft": FindingCategory.AUTH,
    "privilege escalation": FindingCategory.MISCONFIG,
    "lateral movement": FindingCategory.MISCONFIG,
    "denial of service": FindingCategory.DOS,
}


# Per-category CWE list, derived from kube_hunter.yaml ``cwe_hints``.
_CATEGORY_CWE: Final[dict[FindingCategory, tuple[int, ...]]] = {
    FindingCategory.RCE: (94, 78, 668),
    FindingCategory.INFO: (200,),
    FindingCategory.AUTH: (287, 285, 306),
    FindingCategory.MISCONFIG: (16, 285, 668),
    FindingCategory.DOS: (400,),
}
_CWE_FALLBACK: Final[tuple[int, ...]] = (16, 668)


_SEVERITY_RANK: Final[dict[str, int]] = {
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


_SEVERITY_TO_CVSS: Final[dict[str, float]] = {
    "high": 8.5,
    "medium": 5.5,
    "low": 3.5,
    "info": 0.0,
}


_SEVERITY_TO_SSVC: Final[dict[str, SSVCDecision]] = {
    "high": SSVCDecision.ACT,
    "medium": SSVCDecision.ATTEND,
    "low": SSVCDecision.TRACK,
    "info": SSVCDecision.TRACK,
}


_OWASP_WSTG_DEFAULT: Final[tuple[str, ...]] = ("WSTG-CONF-04", "WSTG-ATHN-01")
_MITRE_ATTACK_DEFAULT: Final[tuple[str, ...]] = ("T1610", "T1613")


DedupKey: TypeAlias = tuple[str, str]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_kube_hunter_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate kube-hunter ``--report json`` output into FindingDTOs."""
    del stderr
    payload = _load_payload(stdout=stdout, artifacts_dir=artifacts_dir, tool_id=tool_id)
    if payload is None:
        return []
    if not isinstance(payload, dict):
        _logger.warning(
            "kube_hunter_parser.envelope_not_dict",
            extra={
                "event": "kube_hunter_parser_envelope_not_dict",
                "tool_id": tool_id,
            },
        )
        return []
    raw_vulns = payload.get("vulnerabilities")
    if not isinstance(raw_vulns, list):
        return []
    services_by_location = _index_services(payload.get("services"))
    records = list(
        _iter_normalised(
            raw_vulns,
            services_by_location=services_by_location,
            tool_id=tool_id,
        )
    )
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
    keyed: list[tuple[tuple[int, str, str], FindingDTO, str]] = []
    for record in records:
        key = _dedup_key(record)
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding(record)
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        sort_key = _sort_key(record)
        keyed.append((sort_key, finding, evidence_blob))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "kube_hunter_parser.cap_reached",
                extra={
                    "event": "kube_hunter_parser_cap_reached",
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


def _dedup_key(record: dict[str, Any]) -> DedupKey:
    return (
        str(record.get("vid") or ""),
        str(record.get("location") or ""),
    )


def _sort_key(record: dict[str, Any]) -> tuple[int, str, str]:
    severity = str(record.get("severity") or "info")
    return (
        -_SEVERITY_RANK.get(severity, 0),
        str(record.get("location") or ""),
        str(record.get("vid") or ""),
    )


def _build_finding(record: dict[str, Any]) -> FindingDTO:
    category: FindingCategory = record["category"]
    severity = str(record.get("severity") or "info")
    return make_finding_dto(
        category=category,
        cwe=list(_CATEGORY_CWE.get(category, _CWE_FALLBACK)),
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=_SEVERITY_TO_CVSS.get(severity, 0.0),
        confidence=ConfidenceLevel.LIKELY,
        ssvc_decision=_SEVERITY_TO_SSVC.get(severity, SSVCDecision.TRACK),
        owasp_wstg=list(_OWASP_WSTG_DEFAULT),
        mitre_attack=list(_MITRE_ATTACK_DEFAULT),
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": "kube_hunter",
        "vid": record.get("vid"),
        "location": record.get("location"),
        "category": _category_value(record.get("category")),
        "category_raw": record.get("category_raw"),
        "severity": record.get("severity"),
        "vulnerability": _truncate_text(record.get("vulnerability")),
        "description": _truncate_text(record.get("description")),
        "evidence": _truncate_text(record.get("evidence")),
        "hunter": record.get("hunter"),
        "avd_reference": record.get("avd_reference"),
        "service": _truncate_text(record.get("service")),
    }
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if value is None or value == "":
            continue
        cleaned[key] = value
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


def _category_value(category: Any) -> str | None:
    if isinstance(category, FindingCategory):
        return category.value
    if isinstance(category, str) and category:
        return category
    return None


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
            "kube_hunter_parser.evidence_sidecar_write_failed",
            extra={
                "event": "kube_hunter_parser_evidence_sidecar_write_failed",
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
                "kube_hunter_parser.canonical_read_failed",
                extra={
                    "event": "kube_hunter_parser_canonical_read_failed",
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


def _index_services(raw_services: Any) -> dict[str, str]:
    """Map ``location`` → service name so a vuln can name its host service."""
    if not isinstance(raw_services, list):
        return {}
    index: dict[str, str] = {}
    for service in raw_services:
        if not isinstance(service, dict):
            continue
        location = _string_field(service, "location")
        name = _string_field(service, "service")
        if location and name and location not in index:
            index[location] = name
    return index


def _iter_normalised(
    raw_vulns: list[Any],
    *,
    services_by_location: dict[str, str],
    tool_id: str,
) -> Iterable[dict[str, Any]]:
    for vuln in raw_vulns:
        if not isinstance(vuln, dict):
            continue
        title = _string_field(vuln, "vulnerability")
        if title is None:
            _logger.warning(
                "kube_hunter_parser.vuln_missing_title",
                extra={
                    "event": "kube_hunter_parser_vuln_missing_title",
                    "tool_id": tool_id,
                    "vid": _string_field(vuln, "vid"),
                },
            )
            continue
        category_raw = (_string_field(vuln, "category") or "").lower()
        category = _CATEGORY_MAP.get(category_raw, FindingCategory.MISCONFIG)
        severity = (_string_field(vuln, "severity") or "medium").lower()
        if severity not in _SEVERITY_TO_CVSS:
            severity = "medium"
        location = _string_field(vuln, "location") or ""
        yield {
            "vid": _string_field(vuln, "vid") or "",
            "location": location,
            "category": category,
            "category_raw": _string_field(vuln, "category"),
            "severity": severity,
            "vulnerability": title,
            "description": _string_field(vuln, "description"),
            "evidence": _string_field(vuln, "evidence"),
            "hunter": _string_field(vuln, "hunter"),
            "avd_reference": _string_field(vuln, "avd_reference"),
            "service": services_by_location.get(location),
        }


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
    "parse_kube_hunter_json",
]
