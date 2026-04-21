"""Parser for ``fierce --json`` output (ARG-032 batch 4b).

fierce (Mozilla) writes a JSON envelope at ``/out/fierce.json`` with
the discovered subdomains under ``found_dns`` and any successful
zone-transfer payload under ``zone_transfer``::

    {
      "domain": "example.com",
      "found_dns": [
        {"name": "ns1.example.com", "ip": "1.2.3.4"},
        {"name": "mail.example.com", "ip": "5.6.7.8"}
      ],
      "zone_transfer": {
        "successful": true,
        "records": [{"name": "internal.example.com", ...}]
      }
    }

Translation rules
-----------------

* One INFO finding per ``found_dns`` hostname (CWE-200).
* One MISCONFIG finding per ``zone_transfer.successful=true`` event
  (CWE-200 + CWE-16) — escalated severity because zone transfer leaks
  the entire DNS namespace.
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


EVIDENCE_SIDECAR_NAME: Final[str] = "fierce_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "fierce.json"
_MAX_FINDINGS: Final[int] = 5_000


_DedupKey: TypeAlias = tuple[str, str]


def parse_fierce(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate fierce JSON output into FindingDTOs."""
    del stderr
    payload = load_canonical_or_stdout_json(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=_CANONICAL_FILENAME,
        tool_id=tool_id,
    )
    if not isinstance(payload, dict):
        return []

    seen: set[_DedupKey] = set()
    keyed: list[tuple[_DedupKey, FindingDTO, str]] = []

    for hostname in _iter_hostnames(payload):
        host = hostname.lower()
        key: _DedupKey = ("dns", host)
        if key in seen:
            continue
        seen.add(key)
        finding = build_subdomain_finding()
        evidence: dict[str, object] = {
            "tool_id": tool_id,
            "host": host,
            "kind": "subdomain",
            "fingerprint_hash": stable_hash_12(host),
        }
        keyed.append((key, finding, _serialise(evidence)))
        if len(keyed) >= _MAX_FINDINGS:
            break

    if _zone_transfer_successful(payload) and len(keyed) < _MAX_FINDINGS:
        domain = _string(payload, "domain") or "unknown"
        key = ("axfr", domain.lower())
        if key not in seen:
            seen.add(key)
            finding = _build_zone_transfer_finding()
            evidence = {
                "tool_id": tool_id,
                "domain": domain,
                "kind": "zone_transfer",
                "fingerprint_hash": stable_hash_12(f"axfr|{domain}"),
            }
            keyed.append((key, finding, _serialise(evidence)))

    if len(keyed) >= _MAX_FINDINGS:
        _logger.warning(
            "fierce.cap_reached",
            extra={
                "event": "fierce_cap_reached",
                "tool_id": tool_id,
                "cap": _MAX_FINDINGS,
            },
        )

    keyed.sort(key=lambda item: item[0])
    if keyed:
        persist_jsonl_sidecar(
            artifacts_dir,
            sidecar_name=EVIDENCE_SIDECAR_NAME,
            evidence_records=[blob for _, _, blob in keyed],
            tool_id=tool_id,
        )
    return [finding for _, finding, _ in keyed]


def _iter_hostnames(payload: dict[str, Any]) -> Iterable[str]:
    found = payload.get("found_dns")
    if isinstance(found, list):
        for item in found:
            if isinstance(item, dict):
                value = item.get("name")
            else:
                value = item
            if isinstance(value, str) and is_valid_hostname(value):
                yield value
    zone = payload.get("zone_transfer")
    if isinstance(zone, dict):
        records = zone.get("records")
        if isinstance(records, list):
            for entry in records:
                if not isinstance(entry, dict):
                    continue
                name = entry.get("name")
                if isinstance(name, str) and is_valid_hostname(name):
                    yield name


def _zone_transfer_successful(payload: dict[str, Any]) -> bool:
    zone = payload.get("zone_transfer")
    if not isinstance(zone, dict):
        return False
    if zone.get("successful") is True:
        return True
    records = zone.get("records")
    return isinstance(records, list) and len(records) > 0


def _string(record: dict[str, Any], key: str) -> str:
    value = record.get(key)
    return value.strip() if isinstance(value, str) else ""


def _build_zone_transfer_finding() -> FindingDTO:
    return make_finding_dto(
        category=FindingCategory.MISCONFIG,
        cwe=[200, 668, 16],
        cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cvss_v3_score=5.3,
        confidence=ConfidenceLevel.CONFIRMED,
        owasp_wstg=["WSTG-INFO-04", "WSTG-CONF-01"],
    )


def _serialise(payload: dict[str, object]) -> str:
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_fierce",
]
