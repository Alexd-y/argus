"""Parser for classic ``whois`` protocol output (ARG-048).

``whois {domain}`` writes semi-structured WHOIS text to ``/out/whois.txt``.
Key fields are extracted via regex::

    Registrar: Example Registrar, Inc.
    Creation Date: 2020-01-15T00:00:00Z
    Updated Date: 2024-01-15T00:00:00Z
    Registry Expiry Date: 2025-01-15T00:00:00Z
    Name Server: NS1.EXAMPLE.COM
    Name Server: NS2.EXAMPLE.COM
    Registrant Organization: Example Corp
    ...

Findings:

* One INFO finding per extracted field type (registrar, dates, nameservers).
* A single WHOIS finding aggregates key metadata (registrar + dates + org).
"""

from __future__ import annotations

import json
import logging
import re
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
    persist_jsonl_sidecar,
)
from src.sandbox.parsers._text_base import (
    load_canonical_or_stdout_text,
    scrub_evidence_strings,
)

_logger = logging.getLogger(__name__)

EVIDENCE_SIDECAR_NAME: Final[str] = "whois_findings.jsonl"
_CANONICAL_NAMES: Final[tuple[str, ...]] = ("whois.txt", "whois.log")
_MAX_FINDINGS: Final[int] = 500

# Key WhoIS fields to extract.  Each pattern returns the value in group "value".
_FIELD_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("registrar", re.compile(r"(?:registrar|registrar\s*name)\s*:\s*(?P<value>.+)", re.IGNORECASE)),
    ("registrar_url", re.compile(r"(?:registrar\s*url|whois\s*server)\s*:\s*(?P<value>.+)", re.IGNORECASE)),
    ("creation_date", re.compile(r"(?:creation\s*date|created)\s*:\s*(?P<value>.+)", re.IGNORECASE)),
    ("updated_date", re.compile(r"(?:updated\s*date|modified)\s*:\s*(?P<value>.+)", re.IGNORECASE)),
    ("expiry_date", re.compile(r"(?:registry\s*expiry\s*date|expir(?:y|ation)\s*date|expires)\s*:\s*(?P<value>.+)", re.IGNORECASE)),
    ("registrant_org", re.compile(r"(?:registrant\s*(?:organization|org|name)|org\s*name)\s*:\s*(?P<value>.+)", re.IGNORECASE)),
    ("registrant_country", re.compile(r"(?:registrant\s*country|country)\s*:\s*(?P<value>.+)", re.IGNORECASE)),
    ("admin_email", re.compile(r"(?:admin\s*email|registrar\s*abuse\s*contact\s*email)\s*:\s*(?P<value>.+)", re.IGNORECASE)),
)

# Name server lines come in several flavours:
#   Name Server: NS1.EXAMPLE.COM
#   nserver:      ns1.example.com
_NS_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:name\s*server|nserver)\s*:\s*(?P<value>[^\s]+)",
    re.IGNORECASE,
)

_DedupKey: TypeAlias = tuple[str, str]


def parse_whois(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate WHOIS text output into FindingDTOs."""
    del stderr
    text = load_canonical_or_stdout_text(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_names=_CANONICAL_NAMES,
        tool_id=tool_id,
    )
    if not text:
        return []

    seen: set[_DedupKey] = set()
    keyed: list[tuple[_DedupKey, FindingDTO, str]] = []

    # Extract structured fields
    for field_name, pattern in _FIELD_PATTERNS:
        for match in pattern.finditer(text):
            raw_value = match.group("value").strip()
            if not raw_value or len(raw_value) > 500:
                continue
            key: _DedupKey = (field_name, raw_value.lower()[:120])
            if key in seen:
                continue
            seen.add(key)
            finding = _build_finding(field_name)
            evidence: dict[str, object] = {
                "tool_id": tool_id,
                "field": field_name,
                "value": raw_value,
                "fingerprint_hash": stable_hash_12(f"whois|{field_name}|{raw_value}"),
            }
            keyed.append((key, finding, _serialise(evidence)))
            if len(keyed) >= _MAX_FINDINGS:
                break
        if len(keyed) >= _MAX_FINDINGS:
            break

    # Extract nameservers
    for match in _NS_RE.finditer(text):
        ns = match.group("value").strip().rstrip(".").lower()
        if not ns:
            continue
        key = ("nameserver", ns)
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding("nameserver")
        evidence: dict[str, object] = {
            "tool_id": tool_id,
            "field": "nameserver",
            "value": ns,
            "fingerprint_hash": stable_hash_12(f"whois|nameserver|{ns}"),
        }
        keyed.append((key, finding, _serialise(evidence)))
        if len(keyed) >= _MAX_FINDINGS:
            break

    if not keyed:
        return []

    if len(keyed) > _MAX_FINDINGS:
        keyed = keyed[:_MAX_FINDINGS]
        _logger.warning(
            "whois.cap_reached",
            extra={
                "event": "whois_cap_reached",
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


def _build_finding(field_name: str) -> FindingDTO:
    wstg = ["WSTG-INFO-01"]
    cwe = [200]
    if field_name == "nameserver":
        wstg.append("WSTG-INFO-02")
        cwe.append(668)
    return make_finding_dto(
        category=FindingCategory.INFO,
        cwe=cwe,
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=0.0,
        confidence=ConfidenceLevel.CONFIRMED,
        owasp_wstg=wstg,
    )


def _serialise(payload: dict[str, object]) -> str:
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_whois",
]
