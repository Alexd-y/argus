"""Parser for ``dnsrecon -j`` output (ARG-032 batch 4b).

dnsrecon emits a JSON document at ``/out/dnsrecon.json`` with a
top-level array of records::

    [
      {"type": "A",  "name": "www.example.com", "address": "1.2.3.4"},
      {"type": "MX", "exchange": "mail.example.com", "preference": 10},
      {"type": "NS", "target": "ns1.example.com"},
      {"type": "AXFR", "zone_transfer": "AXFR successful", "name": "example.com"}
    ]

Translation rules
-----------------

* One INFO finding per ``(type, host)`` pair (CWE-200).  Hostname is
  pulled from ``name`` / ``exchange`` / ``target`` depending on record
  type.
* AXFR records (zone transfers) escalate to MISCONFIG MEDIUM
  (CWE-200 + CWE-668) — leaking the entire zone is a configuration
  drift.
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
from src.sandbox.parsers._subdomain_base import (
    build_subdomain_finding,
    is_valid_hostname,
)
from src.sandbox.parsers._text_base import scrub_evidence_strings

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "dnsrecon_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "dnsrecon.json"
_MAX_FINDINGS: Final[int] = 5_000


_DedupKey: TypeAlias = tuple[str, str]


def parse_dnsrecon(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate dnsrecon JSON output into FindingDTOs."""
    del stderr
    payload = load_canonical_or_stdout_json(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=_CANONICAL_FILENAME,
        tool_id=tool_id,
    )
    records = _normalise_payload(payload)
    if not records:
        return []

    seen: set[_DedupKey] = set()
    keyed: list[tuple[_DedupKey, FindingDTO, str]] = []

    for record in records:
        record_type = _string(record, "type").upper()
        host = _extract_hostname(record)
        if not host or not is_valid_hostname(host):
            continue
        host_lower = host.lower()
        key: _DedupKey = (record_type or "A", host_lower)
        if key in seen:
            continue
        seen.add(key)
        is_zone_xfer = record_type == "AXFR"
        finding = _build_axfr_finding() if is_zone_xfer else build_subdomain_finding()
        evidence: dict[str, object] = {
            "tool_id": tool_id,
            "host": host_lower,
            "type": record_type or "A",
            "address": _string(record, "address"),
            "target": _string(record, "target"),
            "exchange": _string(record, "exchange"),
            "fingerprint_hash": stable_hash_12(f"{record_type}|{host_lower}"),
        }
        if is_zone_xfer:
            evidence["zone_transfer"] = True
        keyed.append((key, finding, _serialise(evidence)))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "dnsrecon.cap_reached",
                extra={
                    "event": "dnsrecon_cap_reached",
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


def _normalise_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        records = payload.get("records") or payload.get("results")
        if isinstance(records, list):
            return [item for item in records if isinstance(item, dict)]
    return []


def _extract_hostname(record: dict[str, Any]) -> str:
    for key in ("name", "target", "exchange", "host"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _string(record: dict[str, Any], key: str) -> str:
    value = record.get(key)
    if isinstance(value, str):
        return value.strip()
    return ""


def _build_axfr_finding() -> FindingDTO:
    return make_finding_dto(
        category=FindingCategory.MISCONFIG,
        cwe=[200, 668, 16],
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cvss_v3_score=5.3,
        confidence=ConfidenceLevel.CONFIRMED,
        owasp_wstg=["WSTG-INFO-04", "WSTG-CONF-01"],
    )


def _serialise(payload: dict[str, object]) -> str:
    cleaned: dict[str, object] = {
        key: value for key, value in payload.items() if value not in ("", None)
    }
    cleaned = scrub_evidence_strings(cleaned)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_dnsrecon",
]
