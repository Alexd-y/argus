"""Parser for ``cloudsploit scan --json`` output (Backlog §4.15 — ARG-029).

Aqua CloudSploit emits a JSON document that aggregates per-region
posture findings from a multi-cloud scan.  Two upstream shapes occur
in the wild:

* ``{"results": [...]}`` — newer schema where each entry has
  ``status`` ``OK | WARN | FAIL | UNKNOWN``, a ``plugin`` key and
  per-resource detail.
* Legacy nested object — ``{"cloud": "aws", "regions": {"us-east-1":
  {"plugin": [{"status": "FAIL", ...}, ...]}}}``.

The parser supports both, normalises each finding to::

    {
      "status":   "FAIL",
      "title":    "S3 Bucket All Users Acl",
      "category": "S3",
      "plugin":   "bucketAllUsersAcl",
      "region":   "us-east-1",
      "resource": "arn:aws:s3:::public-data",
      "message":  "Bucket grants public READ"
    }

Translation rules
-----------------

* Only ``FAIL`` and ``WARN`` statuses are emitted as findings;
  ``OK`` and ``UNKNOWN`` are dropped (noise / no actionable signal).
* ``WARN`` → severity ``low``, ``FAIL`` → severity ``medium``.  The
  category keyword table can promote ``high`` for IAM / encryption
  surfaces (``iam``, ``mfa``, ``key``, ``rotation``, ``encrypt``).
* CWE assignment is keyword-driven; defaults to (16, 200) for generic
  misconfigurations.
* Confidence — :class:`ConfidenceLevel.LIKELY` (cloud control-plane
  signals are reliable but operator-provided context can flip them).

Sidecar lives at ``artifacts_dir / "cloudsploit_findings.jsonl"``.  AWS
account IDs in resource ARNs are PRESERVED — they are not secrets.
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


EVIDENCE_SIDECAR_NAME: Final[str] = "cloudsploit_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "cloudsploit.json"
_MAX_FINDINGS: Final[int] = 5_000


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


_HIGH_KEYWORDS: Final[tuple[str, ...]] = (
    "root account",
    "root user",
    "mfa",
    "key rotation",
    "kms",
    "encryption disabled",
    "publicly accessible",
    "world-readable",
    "all users",
)


_CATEGORY_KEYWORDS: Final[tuple[tuple[str, FindingCategory, tuple[int, ...]], ...]] = (
    ("encryption", FindingCategory.CRYPTO, (311,)),
    ("ssl", FindingCategory.CRYPTO, (319,)),
    ("tls", FindingCategory.CRYPTO, (319,)),
    ("certificate", FindingCategory.CRYPTO, (295,)),
    ("password policy", FindingCategory.AUTH, (521,)),
    ("mfa", FindingCategory.AUTH, (308,)),
    ("authorization", FindingCategory.AUTH, (285,)),
    ("public", FindingCategory.MISCONFIG, (732,)),
    ("permission", FindingCategory.MISCONFIG, (732,)),
    ("logging", FindingCategory.MISCONFIG, (778,)),
    ("audit", FindingCategory.MISCONFIG, (778,)),
    ("backup", FindingCategory.MISCONFIG, (16,)),
)


_STATUS_TO_SEVERITY: Final[dict[str, str]] = {
    "FAIL": "medium",
    "WARN": "low",
}


DedupKey: TypeAlias = tuple[str, str, str, str]


def parse_cloudsploit_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate cloudsploit JSON into FindingDTOs."""
    del stderr
    payload = load_canonical_or_stdout_json(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=_CANONICAL_FILENAME,
        tool_id=tool_id,
    )
    if payload is None:
        return []
    records = list(_iter_records(payload, tool_id=tool_id))
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
    keyed: list[tuple[tuple[int, str, str, str, str], FindingDTO, str]] = []
    for record in records:
        key: DedupKey = (
            str(record.get("plugin") or ""),
            str(record.get("region") or ""),
            str(record.get("resource") or ""),
            str(record.get("status") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding(record)
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        sort_key = (
            -_SEVERITY_RANK.get(str(record.get("severity") or "info"), 0),
            str(record.get("plugin") or ""),
            str(record.get("region") or ""),
            str(record.get("resource") or ""),
            str(record.get("title") or ""),
        )
        keyed.append((sort_key, finding, evidence_blob))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "cloudsploit_parser.cap_reached",
                extra={
                    "event": "cloudsploit_parser_cap_reached",
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
    category: FindingCategory = record.get("_category", FindingCategory.MISCONFIG)
    cwes = list(record.get("_cwes") or [16, 200])
    severity = str(record.get("severity") or "info")
    return make_finding_dto(
        category=category,
        cwe=cwes,
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=_SEVERITY_TO_CVSS.get(severity, 0.0),
        confidence=ConfidenceLevel.LIKELY,
        owasp_wstg=["WSTG-CONF-04", "WSTG-INFO-08"],
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "status": record.get("status"),
        "title": record.get("title"),
        "plugin": record.get("plugin"),
        "category": record.get("category"),
        "cloud": record.get("cloud"),
        "region": record.get("region"),
        "resource": record.get("resource"),
        "message": record.get("message"),
        "severity": record.get("severity"),
    }
    cleaned: dict[str, Any] = {
        key: value
        for key, value in payload.items()
        if value is not None and value != ""
    }
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


def _iter_records(payload: Any, *, tool_id: str) -> Iterable[dict[str, Any]]:
    if isinstance(payload, dict):
        results = payload.get("results")
        if isinstance(results, list):
            yield from _iter_results_array(results, payload=payload, tool_id=tool_id)
            return
        yield from _iter_legacy_envelope(payload, tool_id=tool_id)
        return
    if isinstance(payload, list):
        yield from _iter_results_array(payload, payload={}, tool_id=tool_id)
        return
    _logger.warning(
        "cloudsploit_parser.unsupported_payload",
        extra={
            "event": "cloudsploit_parser_unsupported_payload",
            "tool_id": tool_id,
            "actual_type": type(payload).__name__,
        },
    )


def _iter_results_array(
    results: list[Any], *, payload: dict[str, Any], tool_id: str
) -> Iterable[dict[str, Any]]:
    cloud = _string_field(payload, "cloud")
    for index, raw in enumerate(results):
        if not isinstance(raw, dict):
            _logger.debug(
                "cloudsploit_parser.entry_not_object",
                extra={
                    "event": "cloudsploit_parser_entry_not_object",
                    "tool_id": tool_id,
                    "index": index,
                },
            )
            continue
        normalised = _normalise(
            raw,
            status=_string_field(raw, "status"),
            cloud=_string_field(raw, "cloud") or cloud,
        )
        if normalised is not None:
            yield normalised


def _iter_legacy_envelope(
    payload: dict[str, Any], *, tool_id: str
) -> Iterable[dict[str, Any]]:
    cloud = _string_field(payload, "cloud")
    regions = payload.get("regions")
    if not isinstance(regions, dict):
        return
    for region_name, region_block in regions.items():
        if not isinstance(region_block, dict):
            continue
        for plugin_name, entries in region_block.items():
            if not isinstance(entries, list):
                continue
            for raw in entries:
                if not isinstance(raw, dict):
                    continue
                augmented = dict(raw)
                augmented.setdefault("plugin", plugin_name)
                augmented.setdefault("region", region_name)
                normalised = _normalise(
                    augmented,
                    status=_string_field(augmented, "status"),
                    cloud=cloud,
                )
                if normalised is not None:
                    yield normalised


def _normalise(
    raw: dict[str, Any], *, status: str | None, cloud: str | None
) -> dict[str, Any] | None:
    status_token = (status or "").upper()
    if status_token not in _STATUS_TO_SEVERITY:
        return None
    plugin = _string_field(raw, "plugin") or _string_field(raw, "id")
    title = _string_field(raw, "title") or _string_field(raw, "description")
    if title is None:
        title = plugin or "CloudSploit finding"
    base_severity = _STATUS_TO_SEVERITY[status_token]
    severity = _maybe_promote_severity(base_severity, title=title)
    category, cwes = _classify(
        title=title, category_hint=_string_field(raw, "category")
    )
    region = _string_field(raw, "region")
    resource = _string_field(raw, "resource")
    message = _string_field(raw, "message") or _string_field(raw, "description")
    return {
        "status": status_token,
        "title": title,
        "plugin": plugin,
        "category": _string_field(raw, "category"),
        "cloud": cloud,
        "region": region,
        "resource": resource,
        "message": message,
        "severity": severity,
        "_category": category,
        "_cwes": cwes,
    }


def _maybe_promote_severity(base: str, *, title: str) -> str:
    lowered = title.lower()
    if any(keyword in lowered for keyword in _HIGH_KEYWORDS):
        return "high"
    return base


def _classify(
    *, title: str, category_hint: str | None
) -> tuple[FindingCategory, tuple[int, ...]]:
    haystack = " ".join(filter(None, (category_hint, title))).lower()
    for keyword, category, cwes in _CATEGORY_KEYWORDS:
        if keyword in haystack:
            return category, cwes
    return FindingCategory.MISCONFIG, (16, 200)


def _string_field(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_cloudsploit_json",
]


def _typecheck_iterator() -> None:  # pragma: no cover - mypy seam
    _: Iterator[dict[str, Any]] = iter([])
    del _
