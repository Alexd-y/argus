"""Parser for ``detect-secrets scan`` baseline JSON (Backlog/dev1_md §4.16 — ARG-029).

Yelp detect-secrets emits a baseline-shape document keyed by file path,
each value a list of per-secret records:

.. code-block:: json

    {
      "version": "1.5.0",
      "plugins_used": [
        {"name": "AWSKeyDetector"},
        {"name": "PrivateKeyDetector"}
      ],
      "results": {
        "src/config/dev.env": [
          {
            "type":          "AWS Access Key",
            "filename":      "src/config/dev.env",
            "hashed_secret": "daefe0b4345a654580dcad25c7c11ff4c944a8c0",
            "is_verified":   false,
            "line_number":   12
          }
        ],
        "src/keys/dev.pem": [
          {
            "type":          "Private Key",
            "filename":      "src/keys/dev.pem",
            "hashed_secret": "0011223344556677889900aabbccddeeff112233",
            "is_verified":   false,
            "line_number":   1
          }
        ]
      },
      "generated_at": "2026-04-19T11:00:00Z"
    }

CRITICAL — secret-redaction rule (security-auditor gated)
---------------------------------------------------------

The ``hashed_secret`` field is a SHA-1 hash of (secret_value || filename
|| plugin_type) — it intentionally does NOT contain the cleartext
secret.  We therefore PRESERVE it verbatim because it is the only
mechanism by which two scans can correlate "same secret, different
line" without re-storing the cleartext.  This contrasts with
``trufflehog`` where ``Raw`` IS the cleartext and MUST be redacted.

If a future detect-secrets release ever surfaces a cleartext ``secret``
field next to ``hashed_secret``, the parser falls through
:func:`src.sandbox.parsers._base.redact_secret` so the cleartext never
lands in evidence.  The integration test verifies the absence of any
``secret`` key carrying cleartext bytes for the detect_secrets fixture.

Translation rules
-----------------

* **Severity** is plugin-derived using the same keyword ladder as
  trufflehog (CRITICAL for AWS / Private-Key / GCP detectors, HIGH
  for the popular API-token detectors, MEDIUM otherwise).  A
  ``is_verified=true`` flag escalates a MEDIUM finding to HIGH.
* **Confidence** — :class:`ConfidenceLevel.CONFIRMED` for verified
  secrets, :class:`ConfidenceLevel.LIKELY` otherwise.
* **Category** — :class:`FindingCategory.SECRET_LEAK`.
* **CWE** — pinned at ``[798, 312]`` (Hard-coded Credentials +
  Cleartext Storage).

Dedup
-----

``(plugin_type, filename, hashed_secret)`` so re-runs over the same
tree collapse to a single finding regardless of line drift.

Sidecar
-------

Mirrored into ``artifacts_dir / "detect_secrets_findings.jsonl"`` —
``hashed_secret`` is preserved (intentional, for cross-scan
correlation), ``secret`` (if ever present) is redacted.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
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
    redact_secret,
)
from src.sandbox.parsers._jsonl_base import (
    load_canonical_or_stdout_json,
    persist_jsonl_sidecar,
)

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "detect_secrets_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "detect-secrets.json"
_MAX_FINDINGS: Final[int] = 5_000


_CWE_HARDCODED_CREDS: Final[int] = 798
_CWE_CLEARTEXT_STORAGE: Final[int] = 312


_SEVERITY_TO_CVSS: Final[dict[str, float]] = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 6.0,
}


_SEVERITY_RANK: Final[dict[str, int]] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
}


_CRITICAL_PLUGINS: Final[tuple[str, ...]] = (
    "aws",
    "azurestorage",
    "gcpcredentials",
    "privatekey",
)
_HIGH_PLUGINS: Final[tuple[str, ...]] = (
    "github",
    "gitlab",
    "slack",
    "stripe",
    "twilio",
    "sendgrid",
    "discord",
    "npm",
    "mailchimp",
    "square",
)


DedupKey: TypeAlias = tuple[str, str, str]


def parse_detect_secrets_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate detect-secrets baseline output into FindingDTOs."""
    del stderr
    payload = load_canonical_or_stdout_json(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=_CANONICAL_FILENAME,
        tool_id=tool_id,
    )
    if not isinstance(payload, dict):
        if payload is not None:
            _logger.warning(
                "detect_secrets_parser.envelope_not_object",
                extra={
                    "event": "detect_secrets_parser_envelope_not_object",
                    "tool_id": tool_id,
                    "actual_type": type(payload).__name__,
                },
            )
        return []
    records = list(_iter_normalised(payload, tool_id=tool_id))
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
    keyed: list[tuple[tuple[int, str, str], FindingDTO, str]] = []
    for record in records:
        key: DedupKey = (
            str(record.get("plugin_type") or ""),
            str(record.get("filename") or ""),
            str(record.get("hashed_secret") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding(record)
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        sort_key = (
            -_SEVERITY_RANK.get(str(record.get("severity") or "medium"), 0),
            str(record.get("filename") or ""),
            str(record.get("hashed_secret") or ""),
        )
        keyed.append((sort_key, finding, evidence_blob))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "detect_secrets_parser.cap_reached",
                extra={
                    "event": "detect_secrets_parser_cap_reached",
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
    confidence = (
        ConfidenceLevel.CONFIRMED
        if record.get("is_verified")
        else ConfidenceLevel.LIKELY
    )
    return make_finding_dto(
        category=FindingCategory.SECRET_LEAK,
        cwe=[_CWE_HARDCODED_CREDS, _CWE_CLEARTEXT_STORAGE],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=float(record.get("cvss_v3_score") or 0.0),
        confidence=confidence,
        owasp_wstg=["WSTG-ATHN-06", "WSTG-INFO-08"],
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": "detect_secrets",
        "plugin_type": record.get("plugin_type"),
        "filename": record.get("filename"),
        "line_number": record.get("line_number"),
        "is_verified": record.get("is_verified"),
        "hashed_secret": record.get("hashed_secret"),
        "secret_preview": record.get("secret_preview"),
        "severity": record.get("severity"),
    }
    cleaned = {key: value for key, value in payload.items() if value not in (None, "")}
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


def _iter_normalised(
    payload: dict[str, Any], *, tool_id: str
) -> Iterator[dict[str, Any]]:
    results = payload.get("results")
    if not isinstance(results, dict):
        _logger.warning(
            "detect_secrets_parser.results_missing",
            extra={
                "event": "detect_secrets_parser_results_missing",
                "tool_id": tool_id,
            },
        )
        return
    for filename, entries in results.items():
        if not isinstance(filename, str) or not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            plugin_type = _string_field(entry, "type")
            hashed_secret = _string_field(entry, "hashed_secret")
            if plugin_type is None or hashed_secret is None:
                continue
            severity = _classify_severity(
                plugin_type=plugin_type,
                verified=bool(entry.get("is_verified")),
            )
            yield {
                "plugin_type": plugin_type,
                "filename": filename,
                "line_number": _coerce_int(entry.get("line_number")),
                "is_verified": bool(entry.get("is_verified")),
                "hashed_secret": hashed_secret,
                "secret_preview": redact_secret(_string_field(entry, "secret")),
                "severity": severity,
                "cvss_v3_score": _SEVERITY_TO_CVSS.get(severity, 0.0),
            }


def _classify_severity(*, plugin_type: str, verified: bool) -> str:
    haystack = plugin_type.lower().replace(" ", "").replace("-", "").replace("_", "")
    if any(token in haystack for token in _CRITICAL_PLUGINS):
        return "critical"
    if any(token in haystack for token in _HIGH_PLUGINS):
        return "high"
    if verified:
        return "high"
    return "medium"


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
    return None


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_detect_secrets_json",
]
