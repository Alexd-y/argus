"""Parser for ``sslyze`` JSON output (ARG-048).

``sslyze --json_out /out/sslyze.json {host}:{port}`` emits a JSON
object with scan results per endpoint::

    {
      "server_scan_results": [
        {
          "server_location": {"hostname": "example.com", "port": 443},
          "scan_result": {
            "tls_versions": {"tls_1_2": true, "tls_1_3": true, "tls_1_1": false},
            "cipher_suites": [
              {
                "cipher_suite": {"name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
                "accepted": true
              }
            ],
            "certificate_info": {
              "subject": {"common_name": "example.com"},
              "not_valid_before": "2024-01-01T00:00:00",
              "not_valid_after": "2025-01-01T00:00:00"
            }
          }
        }
      ]
    }

Findings:

* One INFO finding per accepted cipher suite.
* One MISCONFIG finding for deprecated TLS versions (TLSv1.0, TLSv1.1).
* One INFO finding for certificate subject/validity.
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
    SENTINEL_CVSS_VECTOR,
    make_finding_dto,
    stable_hash_12,
)
from src.sandbox.parsers._jsonl_base import (
    load_canonical_or_stdout_json,
    persist_jsonl_sidecar,
)
from src.sandbox.parsers._text_base import scrub_evidence_strings

_logger = logging.getLogger(__name__)

EVIDENCE_SIDECAR_NAME: Final[str] = "sslyze_findings.jsonl"
_CANONICAL_NAME: Final[str] = "sslyze.json"
_MAX_FINDINGS: Final[int] = 2_000

_DEPRECATED_VERSIONS: Final[frozenset[str]] = frozenset(
    {"tls_1_0", "tls_1_1", "ssl_3_0", "ssl_2_0"}
)

_DedupKey: TypeAlias = tuple[str, str]


def parse_sslyze(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate sslyze JSON output into FindingDTOs."""
    del stderr
    payload = load_canonical_or_stdout_json(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=_CANONICAL_NAME,
        tool_id=tool_id,
    )
    if not isinstance(payload, dict):
        return []

    results_list = payload.get("server_scan_results")
    if not isinstance(results_list, list):
        return []

    seen: set[_DedupKey] = set()
    keyed: list[tuple[_DedupKey, FindingDTO, str]] = []

    for server_result in results_list:
        if not isinstance(server_result, dict):
            continue
        location = server_result.get("server_location")
        if not isinstance(location, dict):
            continue
        hostname = location.get("hostname")
        if not isinstance(hostname, str):
            hostname = "unknown"
        port = location.get("port")

        scan_result = server_result.get("scan_result")
        if not isinstance(scan_result, dict):
            continue

        # Parse cipher suites
        cipher_suites = scan_result.get("cipher_suites")
        if isinstance(cipher_suites, list):
            for entry in cipher_suites:
                if not isinstance(entry, dict):
                    continue
                accepted = entry.get("accepted")
                if not accepted:
                    continue
                cs = entry.get("cipher_suite")
                cipher_name = (
                    cs.get("name") if isinstance(cs, dict) else str(cs) if cs else None
                )
                if not isinstance(cipher_name, str) or not cipher_name.strip():
                    continue
                key: _DedupKey = ("cipher", cipher_name.lower())
                if key in seen:
                    continue
                seen.add(key)
                finding = _build_finding(FindingCategory.INFO, 0.0)
                evidence: dict[str, object] = {
                    "tool_id": tool_id,
                    "hostname": hostname,
                    "port": port,
                    "type": "cipher_suite",
                    "cipher": cipher_name,
                    "fingerprint_hash": stable_hash_12(f"sslyze|cipher|{cipher_name}"),
                }
                keyed.append((key, finding, _serialise(evidence)))
                if len(keyed) >= _MAX_FINDINGS:
                    break
            if len(keyed) >= _MAX_FINDINGS:
                break

        # Parse TLS versions
        tls_versions = scan_result.get("tls_versions")
        if isinstance(tls_versions, dict):
            for version_name, supported in tls_versions.items():
                if not supported:
                    continue
                key = ("tls_version", version_name.lower())
                if key in seen:
                    continue
                seen.add(key)
                category = FindingCategory.INFO
                cvss_score = 0.0
                if version_name.lower() in _DEPRECATED_VERSIONS:
                    category = FindingCategory.MISCONFIG
                    cvss_score = 5.0
                finding = _build_finding(category, cvss_score)
                evidence: dict[str, object] = {
                    "tool_id": tool_id,
                    "hostname": hostname,
                    "port": port,
                    "type": "tls_version",
                    "version": version_name,
                    "supported": True,
                    "fingerprint_hash": stable_hash_12(
                        f"sslyze|tls|{version_name}"
                    ),
                }
                keyed.append((key, finding, _serialise(evidence)))
                if len(keyed) >= _MAX_FINDINGS:
                    break
            if len(keyed) >= _MAX_FINDINGS:
                break

        # Parse certificate info
        cert_info = scan_result.get("certificate_info")
        if isinstance(cert_info, dict):
            subject = cert_info.get("subject")
            common_name: str = ""
            if isinstance(subject, dict):
                cn = subject.get("common_name")
                if isinstance(cn, str):
                    common_name = cn
            not_before = cert_info.get("not_valid_before")
            not_after = cert_info.get("not_valid_after")
            key = ("certificate", common_name.lower())
            if key not in seen:
                seen.add(key)
                finding = _build_finding(FindingCategory.INFO, 0.0)
                evidence: dict[str, object] = {
                    "tool_id": tool_id,
                    "hostname": hostname,
                    "port": port,
                    "type": "certificate_info",
                    "common_name": common_name,
                    "not_before": str(not_before) if not_before else "",
                    "not_after": str(not_after) if not_after else "",
                    "fingerprint_hash": stable_hash_12(f"sslyze|cert|{common_name}"),
                }
                keyed.append((key, finding, _serialise(evidence)))
        if len(keyed) >= _MAX_FINDINGS:
            break

    if not keyed:
        return []

    if len(keyed) > _MAX_FINDINGS:
        keyed = keyed[:_MAX_FINDINGS]
        _logger.warning(
            "sslyze.cap_reached",
            extra={
                "event": "sslyze_cap_reached",
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
    "parse_sslyze",
]
