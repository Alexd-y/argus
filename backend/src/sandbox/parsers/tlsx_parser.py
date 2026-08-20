"""Parser for ProjectDiscovery ``tlsx -json`` output (Backlog/dev1_md §4.3).

``tlsx`` performs a fast TLS handshake against ``host:port`` and emits a
per-target JSON record.  The ARGUS catalog invokes it with
``-json -o /out/tlsx.json``; depending on the target count the file is
either a single JSON object (one host) or a newline-delimited JSON
stream (several hosts).  Both shapes — plus a top-level JSON array — are
tolerated.

Record shape (the fields we consume; upstream emits more)::

    {
      "host": "example.com",
      "ip": "93.184.216.34",
      "port": "443",
      "tls_version": "tls13",
      "cipher": "TLS_AES_256_GCM_SHA384",
      "not_before": "2022-03-14T00:00:00Z",
      "not_after": "2023-03-14T23:59:59Z",
      "subject_cn": "www.example.org",
      "subject_an": ["example.com", "www.example.com"],
      "issuer_cn": "DigiCert TLS RSA SHA256 2020 CA1",
      "self_signed": false,
      "expired": false,
      "mismatched": false,
      "wildcard_cert": false,
      "jarm_hash": "27d40d40d...",
      "sni": "example.com"
    }

Translation rules (conservative — describe observed facts only)
---------------------------------------------------------------
* Every successful handshake yields one :class:`FindingCategory.INFO`
  finding (CWE-200) recording the negotiated protocol / cipher / cert
  identity.  Certificate fields are public data, so they are preserved
  verbatim in the evidence sidecar.  Confidence is ``CONFIRMED`` — the
  handshake either happened or it did not.
* Deprecated protocols (SSLv2/SSLv3/TLS 1.0/TLS 1.1), weak cipher
  keywords (RC4/3DES/DES/NULL/EXPORT/MD5/anon) and certificate defects
  (expired / self-signed / hostname-mismatch) each emit an additional
  low-severity :class:`FindingCategory.CRYPTO` finding.  No CVE is ever
  invented — the parser only reports the fact tlsx observed.

Dedup key: ``(host, port, issue)`` where ``issue`` is ``"tls_summary"``
for the base finding or the specific weakness name.  Findings are sorted
by the dedup key so snapshot tests stay stable.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Final

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
    SSVCDecision,
)
from src.sandbox.parsers._base import (
    MAX_STDOUT_BYTES,
    make_finding_dto,
    safe_decode,
    safe_load_json,
    safe_load_jsonl,
)
from src.sandbox.parsers._jsonl_base import persist_jsonl_sidecar, safe_join_artifact
from src.sandbox.parsers._text_base import scrub_evidence_strings

_logger = logging.getLogger(__name__)

EVIDENCE_SIDECAR_NAME: Final[str] = "tlsx_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "tlsx.json"
_MAX_FINDINGS: Final[int] = 5_000
_MAX_VALUE_LEN: Final[int] = 500

# tlsx protocol tokens considered deprecated / insecure.  ``tls13`` /
# ``tls12`` are omitted deliberately — they are the current baseline.
_DEPRECATED_PROTOCOLS: Final[frozenset[str]] = frozenset(
    {"ssl20", "sslv2", "ssl30", "sslv3", "tls10", "tls11"}
)

# Substrings that mark a cipher suite as cryptographically weak.  Matched
# case-insensitively against the negotiated cipher name.
_WEAK_CIPHER_MARKERS: Final[tuple[str, ...]] = (
    "RC4",
    "3DES",
    "DES-",
    "_DES_",
    "NULL",
    "EXPORT",
    "MD5",
    "ANON",
    "_RC2_",
)

DedupKey = tuple[str, str, str]


def parse_tlsx_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate tlsx JSON/JSONL output into a deduplicated finding list."""
    del stderr
    records = _load_records(stdout=stdout, artifacts_dir=artifacts_dir, tool_id=tool_id)
    if not records:
        return []

    seen: set[DedupKey] = set()
    keyed: list[tuple[DedupKey, FindingDTO, str]] = []

    for record in records:
        host = _string_field(record, "host") or _string_field(record, "ip")
        if host is None:
            continue
        port = _port_str(record.get("port"))

        for key, finding, evidence in _findings_for_record(
            record, host=host, port=port, tool_id=tool_id
        ):
            if key in seen:
                continue
            seen.add(key)
            keyed.append((key, finding, evidence))
            if len(keyed) >= _MAX_FINDINGS:
                _logger.warning(
                    "tlsx_parser.cap_reached",
                    extra={
                        "event": "tlsx_parser_cap_reached",
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


def _findings_for_record(
    record: dict[str, Any],
    *,
    host: str,
    port: str,
    tool_id: str,
) -> Iterable[tuple[DedupKey, FindingDTO, str]]:
    """Yield ``(dedup_key, finding, evidence_json)`` triples for one record."""
    tls_version = _string_field(record, "tls_version")
    cipher = _string_field(record, "cipher")

    base_evidence = {
        "tool_id": tool_id,
        "host": host,
        "ip": _string_field(record, "ip"),
        "port": port,
        "tls_version": tls_version,
        "cipher": cipher,
        "subject_cn": _string_field(record, "subject_cn"),
        "issuer_cn": _string_field(record, "issuer_cn"),
        "not_after": _string_field(record, "not_after"),
        "sni": _string_field(record, "sni"),
        "jarm_hash": _string_field(record, "jarm_hash"),
    }
    yield (
        (host, port, "tls_summary"),
        make_finding_dto(
            category=FindingCategory.INFO,
            cwe=[200],
            cvss_v3_score=0.0,
            confidence=ConfidenceLevel.CONFIRMED,
            owasp_wstg=["WSTG-CRYP-01", "WSTG-CRYP-03"],
        ),
        _serialise(base_evidence),
    )

    if tls_version and tls_version.lower() in _DEPRECATED_PROTOCOLS:
        yield (
            (host, port, "deprecated_protocol"),
            _crypto_finding(cwe=[326, 327], score=5.3, confidence=ConfidenceLevel.LIKELY),
            _serialise(
                {
                    "tool_id": tool_id,
                    "host": host,
                    "port": port,
                    "issue": "deprecated_tls_protocol",
                    "tls_version": tls_version,
                }
            ),
        )

    if cipher and _is_weak_cipher(cipher):
        yield (
            (host, port, "weak_cipher"),
            _crypto_finding(cwe=[326, 327], score=5.3, confidence=ConfidenceLevel.LIKELY),
            _serialise(
                {
                    "tool_id": tool_id,
                    "host": host,
                    "port": port,
                    "issue": "weak_cipher_suite",
                    "cipher": cipher,
                }
            ),
        )

    if _bool_field(record, "expired"):
        yield (
            (host, port, "expired_cert"),
            _crypto_finding(cwe=[295, 298], score=5.3, confidence=ConfidenceLevel.LIKELY),
            _serialise(
                {
                    "tool_id": tool_id,
                    "host": host,
                    "port": port,
                    "issue": "expired_certificate",
                    "not_after": _string_field(record, "not_after"),
                }
            ),
        )

    if _bool_field(record, "self_signed"):
        yield (
            (host, port, "self_signed_cert"),
            _crypto_finding(cwe=[295, 296], score=4.0, confidence=ConfidenceLevel.SUSPECTED),
            _serialise(
                {
                    "tool_id": tool_id,
                    "host": host,
                    "port": port,
                    "issue": "self_signed_certificate",
                    "subject_cn": _string_field(record, "subject_cn"),
                }
            ),
        )

    if _bool_field(record, "mismatched"):
        yield (
            (host, port, "mismatched_cert"),
            _crypto_finding(cwe=[295, 297], score=5.3, confidence=ConfidenceLevel.LIKELY),
            _serialise(
                {
                    "tool_id": tool_id,
                    "host": host,
                    "port": port,
                    "issue": "hostname_mismatch",
                    "subject_cn": _string_field(record, "subject_cn"),
                }
            ),
        )


def _crypto_finding(*, cwe: list[int], score: float, confidence: ConfidenceLevel) -> FindingDTO:
    return make_finding_dto(
        category=FindingCategory.CRYPTO,
        cwe=cwe,
        cvss_v3_score=score,
        confidence=confidence,
        ssvc_decision=SSVCDecision.ATTEND,
        owasp_wstg=["WSTG-CRYP-01"],
    )


# ---------------------------------------------------------------------------
# Payload loading — canonical file first, stdout fallback; JSON / JSONL / array.
# ---------------------------------------------------------------------------


def _load_records(*, stdout: bytes, artifacts_dir: Path, tool_id: str) -> list[dict[str, Any]]:
    raw = _read_canonical(artifacts_dir, tool_id=tool_id)
    if not raw.strip():
        raw = stdout or b""
    if not raw.strip():
        return []

    text = safe_decode(raw, limit=MAX_STDOUT_BYTES)
    stripped = text.lstrip()
    if not stripped:
        return []
    encoded = text.encode("utf-8")

    if stripped.startswith("["):
        decoded = safe_load_json(encoded, tool_id=tool_id)
        if isinstance(decoded, list):
            return [item for item in decoded if isinstance(item, dict)]
        return []
    if stripped.startswith("{") and "\n" not in stripped.strip():
        decoded = safe_load_json(encoded, tool_id=tool_id)
        if isinstance(decoded, dict):
            return [decoded]
        return []
    if stripped.startswith("{"):
        decoded = safe_load_json(encoded, tool_id=tool_id)
        if isinstance(decoded, dict):
            return [decoded]
    return [
        record for record in safe_load_jsonl(encoded, tool_id=tool_id) if isinstance(record, dict)
    ]


def _read_canonical(artifacts_dir: Path, *, tool_id: str) -> bytes:
    canonical = safe_join_artifact(artifacts_dir, _CANONICAL_FILENAME)
    if canonical is None or not canonical.is_file():
        return b""
    try:
        return canonical.read_bytes()
    except OSError as exc:
        _logger.warning(
            "tlsx_parser.canonical_read_failed",
            extra={
                "event": "tlsx_parser_canonical_read_failed",
                "tool_id": tool_id,
                "error_type": type(exc).__name__,
            },
        )
        return b""


# ---------------------------------------------------------------------------
# Field helpers
# ---------------------------------------------------------------------------


def _serialise(evidence: dict[str, Any]) -> str:
    cleaned = {
        key: (value[:_MAX_VALUE_LEN] if isinstance(value, str) else value)
        for key, value in evidence.items()
        if value not in (None, "", [], {})
    }
    scrubbed = scrub_evidence_strings(cleaned)
    return json.dumps(scrubbed, sort_keys=True, ensure_ascii=False)


def _is_weak_cipher(cipher: str) -> bool:
    upper = cipher.upper()
    return any(marker in upper for marker in _WEAK_CIPHER_MARKERS)


def _string_field(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _bool_field(record: dict[str, Any], key: str) -> bool:
    return record.get(key) is True


_PORT_RE: Final[re.Pattern[str]] = re.compile(r"^\d{1,5}$")


def _port_str(value: Any) -> str:
    if isinstance(value, bool):
        return "443"
    if isinstance(value, int) and 0 < value < 65_536:
        return str(value)
    if isinstance(value, str) and _PORT_RE.match(value.strip()):
        candidate = value.strip()
        if 0 < int(candidate) < 65_536:
            return candidate
    return "443"


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_tlsx_json",
]
