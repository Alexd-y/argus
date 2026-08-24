"""Parser for ``crt.sh`` Certificate Transparency JSON output (ARG-048).

``curl 'https://crt.sh/?q=%25.{domain}&output=json'`` returns a JSON array
of certificate entries::

    [
      {
        "id": 123456789,
        "issuer_ca_id": 1111,
        "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        "common_name": "www.example.com",
        "name_value": "www.example.com\\nexample.com\\napi.example.com",
        "entry_timestamp": "2024-01-15T00:00:00.000",
        "not_before": "2024-01-01T00:00:00",
        "not_after": "2025-01-01T00:00:00"
      }
    ]

Findings:

* One INFO finding per unique domain in ``name_value`` (newline-separated).
* Deduplicated across all certificate entries.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Final, TypeAlias

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
from src.sandbox.parsers._subdomain_base import is_valid_hostname
from src.sandbox.parsers._text_base import scrub_evidence_strings

_logger = logging.getLogger(__name__)

EVIDENCE_SIDECAR_NAME: Final[str] = "crtsh_findings.jsonl"
_CANONICAL_NAME: Final[str] = "crtsh.json"
_MAX_FINDINGS: Final[int] = 10_000

_DedupKey: TypeAlias = tuple[str]


def parse_crt_sh(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate crt.sh JSON output into FindingDTOs."""
    del stderr
    payload = load_canonical_or_stdout_json(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=_CANONICAL_NAME,
        tool_id=tool_id,
    )
    if not isinstance(payload, list):
        return []

    seen: set[_DedupKey] = set()
    keyed: list[tuple[_DedupKey, FindingDTO, str]] = []

    for entry in payload:
        if not isinstance(entry, dict):
            continue
        name_value = entry.get("name_value")
        if not isinstance(name_value, str) or not name_value.strip():
            continue
        common_name = (
            entry.get("common_name") if isinstance(entry.get("common_name"), str) else ""
        )
        for raw_name in name_value.split("\n"):
            host = raw_name.strip().lstrip("*.").rstrip(".").lower()
            if not host or not is_valid_hostname(host):
                continue
            key: _DedupKey = (host,)
            if key in seen:
                continue
            seen.add(key)
            finding = _build_finding()
            evidence: dict[str, object] = {
                "tool_id": tool_id,
                "host": host,
                "common_name": common_name,
                "fingerprint_hash": stable_hash_12(f"crt_sh|{host}"),
            }
            keyed.append((key, finding, _serialise(evidence)))
            if len(keyed) >= _MAX_FINDINGS:
                _logger.warning(
                    "crtsh.cap_reached",
                    extra={
                        "event": "crtsh_cap_reached",
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


def _build_finding() -> FindingDTO:
    return make_finding_dto(
        category=FindingCategory.INFO,
        cwe=[200, 668],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=0.0,
        confidence=ConfidenceLevel.CONFIRMED,
        owasp_wstg=["WSTG-INFO-01", "WSTG-INFO-08"],
    )


def _serialise(payload: dict[str, object]) -> str:
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_crt_sh",
]
