"""Parser for ``dnsx`` JSON-lines output (ARG-032 batch 4c).

ProjectDiscovery's ``dnsx`` writes one record per resolved host to
``-o /out/dnsx.json``.  Canonical record shape (``-json -resp -all``)::

    {
      "host": "api.example.com",
      "a": ["10.0.0.1"],
      "aaaa": ["2001:db8::1"],
      "cname": ["api-prod.example.com"],
      "mx": ["10 mx1.example.com"],
      "ns": ["ns1.example.com"],
      "txt": ["v=spf1 -all"],
      "soa": ["ns1.example.com hostmaster.example.com 1 7200 1800 1209600 3600"],
      "ptr": ["api.example.com"],
      "wildcard": false,
      "status_code": "NOERROR",
      "resolver": ["1.1.1.1:53"]
    }

Findings:

* One INFO finding per ``(host, record_type)`` tuple.
* Wildcard / SPF-permissive records escalate to MISCONFIG (SOA + TXT).
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
    SSVCDecision,
)
from src.sandbox.parsers._base import (
    SENTINEL_CVSS_VECTOR,
    make_finding_dto,
    stable_hash_12,
)
from src.sandbox.parsers._jsonl_base import (
    iter_jsonl_records,
    persist_jsonl_sidecar,
)
from src.sandbox.parsers._subdomain_base import is_valid_hostname
from src.sandbox.parsers._text_base import scrub_evidence_strings

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "dnsx_findings.jsonl"
_CANONICAL_NAME: Final[str] = "dnsx.json"
_MAX_FINDINGS: Final[int] = 5_000

_RECORD_TYPES: Final[tuple[str, ...]] = (
    "a",
    "aaaa",
    "cname",
    "mx",
    "ns",
    "txt",
    "soa",
    "ptr",
    "srv",
    "caa",
)


_DedupKey: TypeAlias = tuple[str, str]


def parse_dnsx(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate dnsx JSONL output into INFO/MISCONFIG FindingDTOs."""
    del stderr

    seen: set[_DedupKey] = set()
    keyed: list[tuple[_DedupKey, FindingDTO, str]] = []

    for raw_record in iter_jsonl_records(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=_CANONICAL_NAME,
        tool_id=tool_id,
    ):
        for normalised in _normalise(raw_record):
            host = str(normalised["host"])
            record_type = str(normalised["record_type"])
            category_value = normalised["category"]
            if not isinstance(category_value, FindingCategory):
                continue
            key: _DedupKey = (host, record_type)
            if key in seen:
                continue
            seen.add(key)
            finding = _build_finding(category_value)
            evidence = _build_evidence(normalised, tool_id=tool_id)
            keyed.append((key, finding, evidence))
            if len(keyed) >= _MAX_FINDINGS:
                _logger.warning(
                    "dnsx.cap_reached",
                    extra={
                        "event": "dnsx_cap_reached",
                        "tool_id": tool_id,
                        "cap": _MAX_FINDINGS,
                    },
                )
                break
        if len(keyed) >= _MAX_FINDINGS:
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


def _normalise(record: dict[str, Any]) -> Iterator[dict[str, object]]:
    raw_host = record.get("host")
    if not isinstance(raw_host, str) or not is_valid_hostname(raw_host):
        return
    host = raw_host.strip().rstrip(".").lower()
    wildcard = bool(record.get("wildcard"))
    status = (
        record.get("status_code") if isinstance(record.get("status_code"), str) else ""
    )
    for record_type in _RECORD_TYPES:
        values = record.get(record_type)
        if not isinstance(values, list) or not values:
            continue
        cleaned_values = [str(v) for v in values if isinstance(v, (str, int, float))]
        if not cleaned_values:
            continue
        category = FindingCategory.INFO
        if record_type in {"soa", "txt"} and wildcard:
            category = FindingCategory.MISCONFIG
        yield {
            "host": host,
            "record_type": record_type,
            "values": cleaned_values,
            "wildcard": wildcard,
            "status": status,
            "category": category,
        }


def _build_finding(category: FindingCategory) -> FindingDTO:
    if category is FindingCategory.MISCONFIG:
        return make_finding_dto(
            category=FindingCategory.MISCONFIG,
            cwe=[16, 200],
            cvss_v3_vector=SENTINEL_CVSS_VECTOR,
            cvss_v3_score=4.3,
            confidence=ConfidenceLevel.SUSPECTED,
            ssvc_decision=SSVCDecision.TRACK,
            owasp_wstg=["WSTG-INFO-04", "WSTG-CONF-04"],
        )
    return make_finding_dto(
        category=FindingCategory.INFO,
        cwe=[200, 668],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=0.0,
        confidence=ConfidenceLevel.CONFIRMED,
        owasp_wstg=["WSTG-INFO-02", "WSTG-INFO-04"],
    )


def _build_evidence(record: dict[str, object], *, tool_id: str) -> str:
    host = str(record["host"])
    payload: dict[str, object] = {
        "tool_id": tool_id,
        "host": host,
        "record_type": record["record_type"],
        "values": record["values"],
        "wildcard": record["wildcard"],
        "status": record["status"],
        "fingerprint_hash": stable_hash_12(f"dnsx|{host}|{record['record_type']}"),
    }
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_dnsx",
]
