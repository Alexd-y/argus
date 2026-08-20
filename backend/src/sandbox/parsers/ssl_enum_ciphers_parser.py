"""Parser for the Nmap ``ssl-enum-ciphers`` NSE script (Backlog/dev1_md §4.3).

The ARGUS catalog runs ``nmap --script ssl-enum-ciphers ... -oX
/out/ssl_ciphers.xml``.  The machine contract is the XML ``<script
id="ssl-enum-ciphers" output="...">`` element whose ``output`` attribute
carries the canonical, well-documented cipher table::

    | ssl-enum-ciphers:
    |   TLSv1.0:
    |     ciphers:
    |       TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A
    |       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
    |     cipher preference: server
    |   TLSv1.2:
    |     ciphers:
    |       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (secp256r1) - A
    |_  least strength: C

Translation rules (conservative)
---------------------------------
* One :class:`FindingCategory.INFO` finding per supported protocol
  version (records the fact the endpoint negotiates it; CWE-326).
* Deprecated protocols (SSLv2/SSLv3/TLS 1.0/TLS 1.1) additionally emit a
  low-severity :class:`FindingCategory.CRYPTO` finding (CWE-326/327).
* When a protocol block contains a cipher graded ``C``/``D``/``E``/``F``
  the parser emits one CRYPTO finding for that protocol, listing the
  weak ciphers (capped) in the evidence sidecar.

XML is parsed with :mod:`defusedxml` so XXE / billion-laughs / external
DTD payloads are refused before the tree is materialised.  Malformed or
non-nmap input degrades to ``[]``.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final

from defusedxml import ElementTree as DefusedET  # type: ignore[import-untyped]
from defusedxml.common import DefusedXmlException  # type: ignore[import-untyped]

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
    SSVCDecision,
)
from src.sandbox.parsers._base import (
    MAX_STDOUT_BYTES,
    make_finding_dto,
)
from src.sandbox.parsers._jsonl_base import persist_jsonl_sidecar, safe_join_artifact

_logger = logging.getLogger(__name__)

EVIDENCE_SIDECAR_NAME: Final[str] = "ssl_enum_ciphers_findings.jsonl"
_CANONICAL_FILENAMES: Final[tuple[str, ...]] = ("ssl_ciphers.xml", "ssl_enum_ciphers.xml")
_SCRIPT_ID: Final[str] = "ssl-enum-ciphers"
_MAX_FINDINGS: Final[int] = 2_000
_MAX_CIPHERS_IN_EVIDENCE: Final[int] = 40

# Protocol block headers, e.g. ``  TLSv1.2:`` / ``  SSLv3:``.
_PROTOCOL_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|TLSv1\.2|TLSv1\.3):\s*$"
)
# Cipher line with strength grade, e.g.
# ``TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C``.
_CIPHER_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*((?:TLS|SSL)_\S+)\s*\([^)]*\)\s*-\s*([A-F])\s*$"
)
_LEAST_STRENGTH_RE: Final[re.Pattern[str]] = re.compile(r"least strength:\s*([A-F])")

_DEPRECATED_PROTOCOLS: Final[frozenset[str]] = frozenset({"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"})
_WEAK_GRADES: Final[frozenset[str]] = frozenset({"C", "D", "E", "F"})

DedupKey = tuple[str, str, str]


def parse_ssl_enum_ciphers(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate ssl-enum-ciphers XML into TLS-hygiene findings."""
    del stderr
    raw = _load_xml(stdout=stdout, artifacts_dir=artifacts_dir, tool_id=tool_id)
    if not raw.strip():
        return []

    root = _safe_parse_xml(raw, tool_id=tool_id)
    if root is None:
        return []

    seen: set[DedupKey] = set()
    keyed: list[tuple[DedupKey, FindingDTO, str]] = []

    for host_addr, protocol, ciphers in _iter_protocol_blocks(root):
        for key, finding, evidence in _findings_for_protocol(
            host_addr, protocol, ciphers, tool_id=tool_id
        ):
            if key in seen:
                continue
            seen.add(key)
            keyed.append((key, finding, evidence))
            if len(keyed) >= _MAX_FINDINGS:
                _logger.warning(
                    "ssl_enum_ciphers_parser.cap_reached",
                    extra={
                        "event": "ssl_enum_ciphers_parser_cap_reached",
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


def _findings_for_protocol(
    host_addr: str,
    protocol: str,
    ciphers: list[tuple[str, str]],
    *,
    tool_id: str,
) -> Iterator[tuple[DedupKey, FindingDTO, str]]:
    cipher_names = [name for name, _ in ciphers]
    yield (
        (host_addr, protocol, "protocol"),
        make_finding_dto(
            category=FindingCategory.INFO,
            cwe=[326],
            cvss_v3_score=0.0,
            confidence=ConfidenceLevel.CONFIRMED,
            owasp_wstg=["WSTG-CRYP-01"],
        ),
        _serialise(
            {
                "tool_id": tool_id,
                "host": host_addr,
                "protocol": protocol,
                "cipher_count": len(cipher_names),
            }
        ),
    )

    if protocol in _DEPRECATED_PROTOCOLS:
        yield (
            (host_addr, protocol, "deprecated_protocol"),
            _crypto_finding(cwe=[326, 327], score=5.3),
            _serialise(
                {
                    "tool_id": tool_id,
                    "host": host_addr,
                    "issue": "deprecated_tls_protocol",
                    "protocol": protocol,
                }
            ),
        )

    weak = [name for name, grade in ciphers if grade in _WEAK_GRADES]
    if weak:
        yield (
            (host_addr, protocol, "weak_cipher"),
            _crypto_finding(cwe=[326, 327], score=5.3),
            _serialise(
                {
                    "tool_id": tool_id,
                    "host": host_addr,
                    "issue": "weak_cipher_grade",
                    "protocol": protocol,
                    "weak_ciphers": weak[:_MAX_CIPHERS_IN_EVIDENCE],
                }
            ),
        )


def _crypto_finding(*, cwe: list[int], score: float) -> FindingDTO:
    return make_finding_dto(
        category=FindingCategory.CRYPTO,
        cwe=cwe,
        cvss_v3_score=score,
        confidence=ConfidenceLevel.LIKELY,
        ssvc_decision=SSVCDecision.ATTEND,
        owasp_wstg=["WSTG-CRYP-01"],
    )


# ---------------------------------------------------------------------------
# XML walking
# ---------------------------------------------------------------------------


def _iter_protocol_blocks(
    root: Any,
) -> Iterator[tuple[str, str, list[tuple[str, str]]]]:
    """Yield ``(host_addr, protocol, [(cipher, grade), ...])`` per protocol."""
    for host in root.iter("host"):
        host_addr = _host_address(host)
        for script in host.iter("script"):
            if script.get("id") != _SCRIPT_ID:
                continue
            output = script.get("output") or ""
            yield from (
                (host_addr, protocol, ciphers) for protocol, ciphers in _parse_script_output(output)
            )


def _host_address(host: Any) -> str:
    for address in host.iter("address"):
        addr = address.get("addr")
        if addr:
            return str(addr)
    return "unknown"


def _parse_script_output(output: str) -> Iterator[tuple[str, list[tuple[str, str]]]]:
    """Split the script ``output`` text into per-protocol cipher lists."""
    current_protocol: str | None = None
    ciphers: list[tuple[str, str]] = []
    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        proto_match = _PROTOCOL_RE.match(line)
        if proto_match:
            if current_protocol is not None:
                yield current_protocol, ciphers
            current_protocol = proto_match.group(1)
            ciphers = []
            continue
        cipher_match = _CIPHER_RE.match(line)
        if cipher_match and current_protocol is not None:
            ciphers.append((cipher_match.group(1), cipher_match.group(2)))
    if current_protocol is not None:
        yield current_protocol, ciphers


def _load_xml(*, stdout: bytes, artifacts_dir: Path, tool_id: str) -> bytes:
    for filename in _CANONICAL_FILENAMES:
        canonical = safe_join_artifact(artifacts_dir, filename)
        if canonical is None or not canonical.is_file():
            continue
        try:
            raw = canonical.read_bytes()
        except OSError as exc:
            _logger.warning(
                "ssl_enum_ciphers_parser.canonical_read_failed",
                extra={
                    "event": "ssl_enum_ciphers_parser_canonical_read_failed",
                    "tool_id": tool_id,
                    "error_type": type(exc).__name__,
                },
            )
            continue
        if raw.strip():
            return raw
    return stdout or b""


def _safe_parse_xml(raw: bytes, *, tool_id: str) -> Any | None:
    if len(raw) > MAX_STDOUT_BYTES:
        _logger.warning(
            "ssl_enum_ciphers_parser.oversize",
            extra={
                "event": "ssl_enum_ciphers_parser_oversize",
                "tool_id": tool_id,
                "size": len(raw),
            },
        )
        return None
    try:
        return DefusedET.fromstring(raw)
    except DefusedXmlException as exc:
        _logger.warning(
            "ssl_enum_ciphers_parser.xml_unsafe",
            extra={
                "event": "ssl_enum_ciphers_parser_xml_unsafe",
                "tool_id": tool_id,
                "error_type": type(exc).__name__,
            },
        )
        return None
    except DefusedET.ParseError as exc:
        _logger.warning(
            "ssl_enum_ciphers_parser.xml_malformed",
            extra={
                "event": "ssl_enum_ciphers_parser_xml_malformed",
                "tool_id": tool_id,
                "error_type": type(exc).__name__,
            },
        )
        return None


def _serialise(evidence: dict[str, Any]) -> str:
    cleaned = {key: value for key, value in evidence.items() if value not in (None, "", [], {})}
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_ssl_enum_ciphers",
]
