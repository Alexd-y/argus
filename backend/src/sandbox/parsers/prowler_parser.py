"""Parser for ``prowler -M json`` output (Backlog/dev1_md §4.15 — ARG-029).

Prowler is the canonical AWS posture scanner.  ``-M json`` emits a top-
level JSON array of findings (legacy native format, still supported in
v3.x) with the following shape:

.. code-block:: json

    [
      {
        "Status":         "FAIL",
        "Severity":       "high",
        "CheckID":        "iam_root_mfa_enabled",
        "CheckTitle":     "Ensure MFA is enabled for the root account",
        "ServiceName":    "iam",
        "Region":         "us-east-1",
        "AccountId":      "123456789012",
        "ResourceId":     "arn:aws:iam::123456789012:root",
        "ResourceArn":    "arn:aws:iam::123456789012:root",
        "ResourceType":   "AwsIamUser",
        "Resource":       {"Identifier": "arn:aws:iam::123456789012:root"},
        "StatusExtended": "Root account does not have MFA enabled",
        "Compliance":     {"CIS-1.5.0": ["1.5"]},
        "Remediation":    {"Recommendation": {"Text": "Enable MFA..."}},
        "Notes":          ""
      }
    ]

Translation rules
-----------------

* **Category** — :class:`FindingCategory.MISCONFIG` (default) for FAIL
  findings.  IAM / KMS / Encryption checks → :class:`FindingCategory.CRYPTO`
  when the title or check ID mentions encryption / TLS / KMS.  Public
  S3 buckets, public RDS / EBS snapshots → :class:`FindingCategory.MISCONFIG`
  with CWE-732 (Incorrect Permission Assignment).
* **Severity → CVSS**:

  - ``critical`` → 9.5
  - ``high``     → 7.5
  - ``medium``   → 5.0
  - ``low``      → 3.0
  - ``info`` / ``informational`` → 0.0

* **Status** — only ``FAIL`` records emit findings.  ``PASS`` /
  ``MUTED`` / ``MANUAL`` are dropped (they are NOT findings; the
  scan-summary report layer surfaces compliance posture separately).
* **Confidence** — :class:`ConfidenceLevel.CONFIRMED` (Prowler
  evaluates direct cloud API state; it is binary).
* **CWE** — defaults to ``[16]`` (Configuration); IAM / public-access
  checks add CWE-732 and CWE-285.

NOTE on AWS account IDs
-----------------------

The ``Resource.Identifier`` and ``ResourceArn`` fields can carry the
12-digit AWS account ID embedded in an ARN.  These are NOT secrets —
they are the customer's tenancy identifier and are returned by every
authenticated AWS API call.  The parser PRESERVES them intact: the
audit trail value of "this ARN failed compliance check X" is
proportional to operators being able to see the ARN.  Compare with
trufflehog where the secret bytes carry exploit value.

Dedup
-----

``(check_id, account_id, resource_id)`` so a check that flags the
same resource twice in different runs collapses to one finding.

Sidecar
-------

Mirrored into ``artifacts_dir / "prowler_findings.jsonl"`` with
canonical fields (check_id / status / severity / service / region /
resource / remediation summary).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Iterator
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
)
from src.sandbox.parsers._jsonl_base import (
    load_canonical_or_stdout_json,
    persist_jsonl_sidecar,
)

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "prowler_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "prowler.json"
_MAX_FINDINGS: Final[int] = 50_000


_SEVERITY_TO_CVSS: Final[dict[str, float]] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "info": 0.0,
    "informational": 0.0,
}


_SEVERITY_RANK: Final[dict[str, int]] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
    "informational": 0,
}


_SEVERITY_TO_SSVC: Final[dict[str, SSVCDecision]] = {
    "critical": SSVCDecision.ACT,
    "high": SSVCDecision.ATTEND,
    "medium": SSVCDecision.ATTEND,
    "low": SSVCDecision.TRACK,
    "info": SSVCDecision.TRACK,
    "informational": SSVCDecision.TRACK,
}


# Substrings in the check title / id that re-route the finding into a
# more specific :class:`FindingCategory`.  Walked in priority order so a
# title mentioning both "encryption" and "policy" is classified as
# CRYPTO (the more concrete signal).
_CRYPTO_KEYWORDS: Final[tuple[str, ...]] = (
    "encrypt",
    "kms",
    "tls",
    "ssl",
    "cipher",
)
_AUTH_KEYWORDS: Final[tuple[str, ...]] = (
    "mfa",
    "password_policy",
    "root_account",
    "iam_user",
    "access_key",
)
_PUBLIC_KEYWORDS: Final[tuple[str, ...]] = (
    "public",
    "world_readable",
    "world_writable",
    "open_to_internet",
    "publicly",
)


DedupKey: TypeAlias = tuple[str, str, str]


def parse_prowler_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate Prowler ``-M json`` array into MISCONFIG findings."""
    del stderr
    payload = load_canonical_or_stdout_json(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=_CANONICAL_FILENAME,
        tool_id=tool_id,
    )
    if not isinstance(payload, list):
        if payload is not None:
            _logger.warning(
                "prowler_parser.envelope_not_list",
                extra={
                    "event": "prowler_parser_envelope_not_list",
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
            str(record.get("check_id") or ""),
            str(record.get("account_id") or ""),
            str(record.get("resource_id") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding(record)
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        sort_key = (
            -_SEVERITY_RANK.get(str(record.get("severity") or "info"), 0),
            str(record.get("check_id") or ""),
            str(record.get("resource_id") or ""),
        )
        keyed.append((sort_key, finding, evidence_blob))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "prowler_parser.cap_reached",
                extra={
                    "event": "prowler_parser_cap_reached",
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
    severity = str(record.get("severity") or "info")
    category = _classify_category(record)
    cwe = list(_classify_cwe(category, record))
    return make_finding_dto(
        category=category,
        cwe=cwe,
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=_SEVERITY_TO_CVSS.get(severity, 0.0),
        confidence=ConfidenceLevel.CONFIRMED,
        ssvc_decision=_SEVERITY_TO_SSVC.get(severity, SSVCDecision.TRACK),
        owasp_wstg=["WSTG-CONF-04", "WSTG-INFO-08"],
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": "prowler",
        "check_id": record.get("check_id"),
        "check_title": record.get("check_title"),
        "service_name": record.get("service_name"),
        "severity": record.get("severity"),
        "status": record.get("status"),
        "status_extended": record.get("status_extended"),
        "account_id": record.get("account_id"),
        "region": record.get("region"),
        "resource_type": record.get("resource_type"),
        "resource_id": record.get("resource_id"),
        "resource_arn": record.get("resource_arn"),
        "compliance": record.get("compliance"),
        "remediation": record.get("remediation"),
    }
    cleaned = {key: value for key, value in payload.items() if value not in (None, "")}
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


def _iter_normalised(payload: list[Any], *, tool_id: str) -> Iterator[dict[str, Any]]:
    for raw in payload:
        if not isinstance(raw, dict):
            continue
        status = _string_field(raw, "Status")
        if status is None or status.upper() != "FAIL":
            continue
        check_id = _string_field(raw, "CheckID") or _string_field(raw, "check_id")
        if check_id is None:
            _logger.warning(
                "prowler_parser.record_missing_field",
                extra={
                    "event": "prowler_parser_record_missing_field",
                    "tool_id": tool_id,
                    "missing": "CheckID",
                },
            )
            continue
        severity = (_string_field(raw, "Severity") or "info").lower()
        yield {
            "check_id": check_id,
            "check_title": _string_field(raw, "CheckTitle"),
            "service_name": _string_field(raw, "ServiceName"),
            "status": status.upper(),
            "status_extended": _string_field(raw, "StatusExtended"),
            "severity": severity,
            "account_id": _string_field(raw, "AccountId"),
            "region": _string_field(raw, "Region"),
            "resource_type": _string_field(raw, "ResourceType"),
            "resource_id": _resolve_resource_id(raw),
            "resource_arn": _string_field(raw, "ResourceArn"),
            "compliance": _shrink_compliance(raw.get("Compliance")),
            "remediation": _shrink_remediation(raw.get("Remediation")),
        }


def _resolve_resource_id(raw: dict[str, Any]) -> str | None:
    resource = raw.get("Resource")
    if isinstance(resource, dict):
        identifier = _string_field(resource, "Identifier") or _string_field(
            resource, "Id"
        )
        if identifier is not None:
            return identifier
    return _string_field(raw, "ResourceId") or _string_field(raw, "ResourceArn")


def _shrink_compliance(raw: Any) -> dict[str, list[str]] | None:
    if not isinstance(raw, dict):
        return None
    out: dict[str, list[str]] = {}
    for key, value in raw.items():
        if not isinstance(key, str):
            continue
        if isinstance(value, list):
            controls = [str(item) for item in value if isinstance(item, str | int)]
            if controls:
                out[key] = sorted(set(controls))
        elif isinstance(value, str | int):
            out[key] = [str(value)]
    return out or None


def _shrink_remediation(raw: Any) -> str | None:
    if not isinstance(raw, dict):
        return None
    recommendation = raw.get("Recommendation")
    if isinstance(recommendation, dict):
        text = _string_field(recommendation, "Text")
        if text is not None:
            return text[:512]
    text = _string_field(raw, "Text")
    if text is not None:
        return text[:512]
    return None


def _classify_category(record: dict[str, Any]) -> FindingCategory:
    haystack = (
        f"{(record.get('check_id') or '').lower()} "
        f"{(record.get('check_title') or '').lower()}"
    )
    if any(token in haystack for token in _CRYPTO_KEYWORDS):
        return FindingCategory.CRYPTO
    if any(token in haystack for token in _AUTH_KEYWORDS):
        return FindingCategory.AUTH
    return FindingCategory.MISCONFIG


def _classify_cwe(category: FindingCategory, record: dict[str, Any]) -> Iterable[int]:
    haystack = (
        f"{(record.get('check_id') or '').lower()} "
        f"{(record.get('check_title') or '').lower()}"
    )
    if category is FindingCategory.CRYPTO:
        return (327, 326)
    if category is FindingCategory.AUTH:
        return (287, 521)
    if any(token in haystack for token in _PUBLIC_KEYWORDS):
        return (732, 200)
    return (16, 1395)


def _string_field(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_prowler_json",
]
