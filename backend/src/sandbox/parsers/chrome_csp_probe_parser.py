"""Parser for chrome-csp-probe output (ARG-032 batch 4a).

The catalog ``chrome_csp_probe`` tool emits ``/out/csp.json`` with the
merged ``Content-Security-Policy`` / ``Content-Security-Policy-Report-Only``
header set plus DOM-side findings (inline ``script`` handlers,
``unsafe-eval`` / ``unsafe-inline`` directives observed in practice).

Expected canonical shape::

    {
      "url":  "https://example.com/",
      "csp":  {
        "Content-Security-Policy": "default-src 'self'; ...",
        "Content-Security-Policy-Report-Only": "..."
      },
      "violations": [
        {"directive": "script-src", "value": "'unsafe-inline'", "where": "header"},
        {"directive": "default-src", "value": "*",              "where": "header"},
        {"directive": "inline-handler", "value": "onclick=...", "where": "dom"}
      ],
      "missing":   ["Content-Security-Policy"],
      "report_only": true
    }

Translation rules
-----------------

* One MISCONFIG finding per (directive, value) violation tuple
  (CWE-693 — Protection Mechanism Failure).  ``unsafe-inline`` /
  ``unsafe-eval`` / wildcard sources escalate to severity ``high``
  (CVSS 7.5); other violations stay at ``medium`` (CVSS 5.3).
* One MISCONFIG finding per missing critical CSP header
  (CWE-693).  Missing ``Content-Security-Policy`` while only
  ``Content-Security-Policy-Report-Only`` is set escalates to
  ``medium``.
* Pure passive observation; no exploit evidence; the policy bytes
  themselves are NOT secrets so they are preserved in evidence
  for triage (after :func:`scrub_evidence_strings` for defence in
  depth).
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
    make_finding_dto,
    stable_hash_12,
)
from src.sandbox.parsers._jsonl_base import (
    load_canonical_or_stdout_json,
    persist_jsonl_sidecar,
)
from src.sandbox.parsers._text_base import scrub_evidence_strings

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "chrome_csp_probe_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "csp.json"
_MAX_FINDINGS: Final[int] = 200

_HIGH_RISK_TOKENS: Final[frozenset[str]] = frozenset(
    {
        "'unsafe-inline'",
        "'unsafe-eval'",
        "'unsafe-hashes'",
        "*",
        "data:",
        "blob:",
        "filesystem:",
    }
)

_CRITICAL_HEADERS: Final[frozenset[str]] = frozenset(
    {"Content-Security-Policy", "Content-Security-Policy-Report-Only"}
)


_DedupKey: TypeAlias = tuple[str, str, str]


def parse_chrome_csp_probe(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate chrome-csp-probe JSON output into FindingDTOs."""
    del stderr
    payload = load_canonical_or_stdout_json(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=_CANONICAL_FILENAME,
        tool_id=tool_id,
    )
    if not isinstance(payload, dict):
        return []

    target_url = _string_field(payload, "url") or ""
    findings: list[FindingDTO] = []
    evidence_blobs: list[str] = []
    seen: set[_DedupKey] = set()

    for record in _iter_violations(payload):
        directive = _string_field(record, "directive") or "unknown"
        value = _string_field(record, "value") or ""
        where = _string_field(record, "where") or "header"
        key: _DedupKey = (directive, value, where)
        if key in seen:
            continue
        seen.add(key)
        is_high = _is_high_risk(value)
        finding = _build_violation_finding(is_high=is_high)
        evidence: dict[str, object] = {
            "tool_id": tool_id,
            "url_hash": stable_hash_12(target_url),
            "directive": directive,
            "value": value,
            "where": where,
            "severity": "high" if is_high else "medium",
            "kind": "csp_violation",
        }
        findings.append(finding)
        evidence_blobs.append(_serialise(evidence))
        if len(findings) >= _MAX_FINDINGS:
            _logger.warning(
                "chrome_csp_probe.cap_reached",
                extra={
                    "event": "chrome_csp_probe_cap_reached",
                    "tool_id": tool_id,
                    "cap": _MAX_FINDINGS,
                },
            )
            break

    findings.extend(
        _emit_missing_header_findings(
            payload,
            evidence_blobs=evidence_blobs,
            target_url=target_url,
            tool_id=tool_id,
        )
    )

    if evidence_blobs:
        persist_jsonl_sidecar(
            artifacts_dir,
            sidecar_name=EVIDENCE_SIDECAR_NAME,
            evidence_records=evidence_blobs,
            tool_id=tool_id,
        )
    return findings


def _iter_violations(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw = payload.get("violations")
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]


def _emit_missing_header_findings(
    payload: dict[str, Any],
    *,
    evidence_blobs: list[str],
    target_url: str,
    tool_id: str,
) -> list[FindingDTO]:
    missing = payload.get("missing")
    if not isinstance(missing, list):
        return []
    findings: list[FindingDTO] = []
    seen: set[str] = set()
    for header in missing:
        if not isinstance(header, str):
            continue
        normalised = header.strip()
        if not normalised or normalised in seen:
            continue
        seen.add(normalised)
        is_critical = normalised in _CRITICAL_HEADERS
        finding = _build_violation_finding(is_high=is_critical)
        evidence: dict[str, object] = {
            "tool_id": tool_id,
            "url_hash": stable_hash_12(target_url),
            "directive": "missing-header",
            "value": normalised,
            "where": "header",
            "severity": "high" if is_critical else "medium",
            "kind": "csp_missing",
        }
        findings.append(finding)
        evidence_blobs.append(_serialise(evidence))
    return findings


def _build_violation_finding(*, is_high: bool) -> FindingDTO:
    if is_high:
        return make_finding_dto(
            category=FindingCategory.MISCONFIG,
            cwe=[693, 1021],
            cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
            cvss_v3_score=7.5,
            confidence=ConfidenceLevel.LIKELY,
            owasp_wstg=["WSTG-CONF-12", "WSTG-CLNT-09"],
        )
    return make_finding_dto(
        category=FindingCategory.MISCONFIG,
        cwe=[693],
        cvss_v3_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        cvss_v3_score=5.3,
        confidence=ConfidenceLevel.SUSPECTED,
        owasp_wstg=["WSTG-CONF-12"],
    )


def _is_high_risk(value: str) -> bool:
    if not value:
        return False
    normalised = value.strip().lower()
    return any(token in normalised for token in _HIGH_RISK_TOKENS)


def _string_field(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _serialise(payload: dict[str, object]) -> str:
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_chrome_csp_probe",
]
