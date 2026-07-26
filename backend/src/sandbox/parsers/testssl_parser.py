"""Parser for ``testssl.sh`` JSON output (ARG-048).

``testssl.sh --jsonfile /out/testssl.json --severity LOW {host}:{port}``
emits a JSON array of finding objects::

    [
      {
        "id": "cipherlist_HIGH",
        "severity": "HIGH",
        "finding": "...",
        "ip": "93.184.216.34",
        "port": "443",
        "cwe": "CWE-327",
        "cve": "CVE-..."
      }
    ]

Findings:

* One finding per array entry with non-OK severity.
* Severity mapped to FindingCategory: HIGH → MISCONFIG, MEDIUM → INFO, LOW → INFO.
* OK / INFO / DEBUG entries dropped.
"""

from __future__ import annotations

import json
import logging
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
    stable_hash_12,
)
from src.sandbox.parsers._jsonl_base import (
    load_canonical_or_stdout_json,
    persist_jsonl_sidecar,
)
from src.sandbox.parsers._text_base import scrub_evidence_strings

_logger = logging.getLogger(__name__)

EVIDENCE_SIDECAR_NAME: Final[str] = "testssl_findings.jsonl"
_CANONICAL_NAME: Final[str] = "testssl.json"
_MAX_FINDINGS: Final[int] = 1_000

_SEVERITY_MAP: Final[dict[str, tuple[FindingCategory, float]]] = {
    "HIGH": (FindingCategory.MISCONFIG, 7.5),
    "MEDIUM": (FindingCategory.MISCONFIG, 5.0),
    "LOW": (FindingCategory.INFO, 0.0),
}

_DedupKey: TypeAlias = tuple[str]


def parse_testssl(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate testssl.sh JSON output into FindingDTOs."""
    del stderr
    payload = load_canonical_or_stdout_json(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=_CANONICAL_NAME,
        tool_id=tool_id,
    )
    # testssl.sh can emit either a top-level array or a dict wrapping scanResult
    records: list[dict[str, Any]] = []
    if isinstance(payload, list):
        records = [item for item in payload if isinstance(item, dict)]
    elif isinstance(payload, dict):
        scan_result = payload.get("scanResult")
        if isinstance(scan_result, list):
            records = [item for item in scan_result if isinstance(item, dict)]

    if not records:
        return []

    seen: set[_DedupKey] = set()
    keyed: list[tuple[_DedupKey, FindingDTO, str]] = []

    for entry in records:
        finding_id = entry.get("id")
        if not isinstance(finding_id, str) or not finding_id.strip():
            continue
        severity_raw = entry.get("severity")
        if not isinstance(severity_raw, str):
            continue
        severity = severity_raw.strip().upper()
        if severity in ("OK", "INFO", "DEBUG", "WARN"):
            continue

        key: _DedupKey = (finding_id.lower(),)
        if key in seen:
            continue
        seen.add(key)

        category, cvss_score = _SEVERITY_MAP.get(severity, (FindingCategory.INFO, 0.0))
        finding_text = (
            entry.get("finding") if isinstance(entry.get("finding"), str) else ""
        )
        cve = entry.get("cve") if isinstance(entry.get("cve"), str) else ""

        finding = _build_finding(category, cvss_score)
        evidence: dict[str, object] = {
            "tool_id": tool_id,
            "id": finding_id,
            "severity": severity,
            "finding": finding_text[:500],
            "cve": cve,
            "fingerprint_hash": stable_hash_12(f"testssl|{finding_id}"),
        }
        keyed.append((key, finding, _serialise(evidence)))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "testssl.cap_reached",
                extra={
                    "event": "testssl_cap_reached",
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


def _build_finding(category: FindingCategory, cvss_score: float) -> FindingDTO:
    return make_finding_dto(
        category=category,
        cwe=[326, 327],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=cvss_score,
        confidence=ConfidenceLevel.LIKELY,
        owasp_wstg=["WSTG-CRYP-01", "WSTG-CRYP-02"],
    )


def _serialise(payload: dict[str, object]) -> str:
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_testssl",
]
