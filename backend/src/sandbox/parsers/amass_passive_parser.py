"""Parser for ``amass enum -passive -json`` output (ARG-032 batch 4b).

OWASP Amass passive mode emits a JSONL stream (one record per line) at
``/out/amass.jsonl``::

    {"name": "api.example.com", "domain": "example.com",
     "addresses": [{"ip": "1.2.3.4", "cidr": "1.2.3.0/24"}],
     "tag": "cert", "sources": ["crt.sh"]}

Translation rules
-----------------

* One INFO finding per unique hostname (CWE-200 / CWE-668).
* Hostname strings are validated against an RFC-1035 regex so a log
  line cannot be captured as a finding.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Final, TypeAlias

from src.pipeline.contracts.finding_dto import FindingDTO
from src.sandbox.parsers._base import stable_hash_12
from src.sandbox.parsers._jsonl_base import (
    iter_jsonl_records,
    persist_jsonl_sidecar,
)
from src.sandbox.parsers._subdomain_base import (
    build_subdomain_finding,
    is_valid_hostname,
)
from src.sandbox.parsers._text_base import scrub_evidence_strings

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "amass_passive_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "amass.jsonl"
_MAX_FINDINGS: Final[int] = 5_000


_DedupKey: TypeAlias = tuple[str]


def parse_amass_passive(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate amass passive JSONL output into FindingDTOs."""
    del stderr
    seen: set[_DedupKey] = set()
    keyed: list[tuple[_DedupKey, FindingDTO, str]] = []

    for record in iter_jsonl_records(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=_CANONICAL_FILENAME,
        tool_id=tool_id,
    ):
        host = _string_field(record, "name")
        if not host or not is_valid_hostname(host):
            continue
        host_lower = host.lower()
        key: _DedupKey = (host_lower,)
        if key in seen:
            continue
        seen.add(key)
        finding = build_subdomain_finding()
        evidence: dict[str, object] = {
            "tool_id": tool_id,
            "host": host_lower,
            "domain": _string_field(record, "domain") or "",
            "tag": _string_field(record, "tag") or "",
            "sources": _normalise_sources(record.get("sources")),
            "addresses": _normalise_addresses(record.get("addresses")),
            "fingerprint_hash": stable_hash_12(host_lower),
        }
        keyed.append((key, finding, _serialise(evidence)))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "amass_passive.cap_reached",
                extra={
                    "event": "amass_passive_cap_reached",
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


def _string_field(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _normalise_sources(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
    return sorted(set(out))


def _normalise_addresses(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        ip = item.get("ip")
        if isinstance(ip, str) and ip.strip():
            out.append(ip.strip())
    return sorted(set(out))


def _serialise(payload: dict[str, object]) -> str:
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_amass_passive",
]
