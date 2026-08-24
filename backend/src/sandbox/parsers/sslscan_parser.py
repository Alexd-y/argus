"""Parser for ``sslscan`` XML output (ARG-048).

``sslscan --xml=/out/sslscan.xml {host}:{port}`` emits XML with
TLS/SSL cipher and protocol information::

    <document title="SSLScan Results">
      <ssltest host="93.184.216.34" port="443">
        <cipher status="accepted" sslversion="TLSv1.2" bits="256" cipher="ECDHE-RSA-AES256-GCM-SHA384" />
        <cipher status="rejected" sslversion="TLSv1.0" bits="128" cipher="RC4-MD5" />
        ...
      </ssltest>
    </document>

Findings:

* One finding per cipher entry (accepted = INFO, rejected = dropped).
* Deprecated protocol versions (TLSv1.0, TLSv1.1, SSLv3) → MISCONFIG with CVSS 5.0.
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
from src.sandbox.parsers._jsonl_base import persist_jsonl_sidecar
from src.sandbox.parsers._text_base import (
    load_canonical_or_stdout_text,
    scrub_evidence_strings,
)

_logger = logging.getLogger(__name__)

EVIDENCE_SIDECAR_NAME: Final[str] = "sslscan_findings.jsonl"
_CANONICAL_NAMES: Final[tuple[str, ...]] = ("sslscan.xml", "sslscan.txt", "sslscan.log")
_MAX_FINDINGS: Final[int] = 2_000

_DEPRECATED_PROTOCOLS: Final[frozenset[str]] = frozenset(
    {"TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"}
)
_WEAK_CIPHER_KEYWORDS: Final[frozenset[str]] = frozenset(
    {"NULL", "anon", "EXPORT", "RC4", "DES", "3DES", "MD5", "CBC"}
)

_DedupKey: TypeAlias = tuple[str, str]


def parse_sslscan(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate sslscan XML output into FindingDTOs via regex fallback.

    sslscan output is XML but parseable with regex for the key cipher elements.
    """
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

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or "cipher" not in stripped.lower():
            continue
        sslversion = _attr_value(stripped, "sslversion")
        cipher_name = _attr_value(stripped, "cipher")
        status = _attr_value(stripped, "status")
        if not cipher_name:
            continue
        if status and status.lower() == "rejected":
            continue

        key: _DedupKey = (cipher_name.lower(), sslversion.lower())
        if key in seen:
            continue
        seen.add(key)

        category = FindingCategory.INFO
        cvss_score = 0.0

        if sslversion and sslversion in _DEPRECATED_PROTOCOLS:
            category = FindingCategory.MISCONFIG
            cvss_score = 5.0
        elif cipher_name and any(
            kw in cipher_name for kw in _WEAK_CIPHER_KEYWORDS
        ):
            category = FindingCategory.MISCONFIG
            cvss_score = 4.3

        finding = _build_finding(category, cvss_score)
        evidence: dict[str, object] = {
            "tool_id": tool_id,
            "cipher": cipher_name,
            "sslversion": sslversion,
            "status": status or "accepted",
            "fingerprint_hash": stable_hash_12(f"sslscan|{cipher_name}|{sslversion}"),
        }
        keyed.append((key, finding, _serialise(evidence)))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "sslscan.cap_reached",
                extra={
                    "event": "sslscan_cap_reached",
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


def _attr_value(xml_fragment: str, attr: str) -> str:
    """Extract ``attr="value"`` from an XML element fragment."""
    import re

    pattern = re.compile(rf'{attr}=["\']([^"\']*?)["\']', re.IGNORECASE)
    match = pattern.search(xml_fragment)
    return match.group(1).strip() if match else ""


def _build_finding(category: FindingCategory, cvss_score: float) -> FindingDTO:
    return make_finding_dto(
        category=category,
        cwe=[326, 327],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=cvss_score,
        confidence=ConfidenceLevel.LIKELY if category == FindingCategory.MISCONFIG else ConfidenceLevel.CONFIRMED,
        owasp_wstg=["WSTG-CRYP-01", "WSTG-CRYP-02"],
    )


def _serialise(payload: dict[str, object]) -> str:
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_sslscan",
]
