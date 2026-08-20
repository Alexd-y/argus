"""Unit tests for :mod:`src.sandbox.parsers.ssl_enum_ciphers_parser` (§4.3).

Pinned contracts:

* Parses the Nmap ``ssl-enum-ciphers`` ``<script output="...">`` table.
* One INFO finding per supported protocol version.
* Deprecated protocols (SSLv3 / TLS 1.0 / TLS 1.1) → extra CRYPTO finding.
* A protocol block with a weak cipher grade (C-F) → extra CRYPTO finding.
* Malformed / non-nmap XML → ``[]`` (defusedxml hardened).
* Sidecar JSONL stamped with ``tool_id``.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers.ssl_enum_ciphers_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_ssl_enum_ciphers,
)

# The script ``output`` attribute uses ``&#10;`` char-references for
# newlines exactly as nmap emits them, so XML attribute normalisation
# does not collapse the multi-line table into a single spaced line.
_SCRIPT_OUTPUT_LINES = (
    "",
    "  TLSv1.0: ",
    "    ciphers: ",
    "      TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C",
    "      TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A",
    "    cipher preference: server",
    "  TLSv1.2: ",
    "    ciphers: ",
    "      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (secp256r1) - A",
    "    cipher preference: server",
    "  least strength: C",
)


def _nmap_xml(addr: str = "93.184.216.34") -> bytes:
    output_attr = "&#10;".join(_SCRIPT_OUTPUT_LINES)
    xml = (
        '<?xml version="1.0"?>'
        "<nmaprun>"
        "<host>"
        f'<address addr="{addr}" addrtype="ipv4"/>'
        "<ports>"
        '<port protocol="tcp" portid="443">'
        f'<script id="ssl-enum-ciphers" output="{output_attr}"/>'
        "</port>"
        "</ports>"
        "</host>"
        "</nmaprun>"
    )
    return xml.encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_ssl_enum_ciphers(b"", b"", tmp_path, "ssl_enum_ciphers") == []


def test_trivial_root_returns_no_findings(tmp_path: Path) -> None:
    assert parse_ssl_enum_ciphers(b"<root/>", b"", tmp_path, "ssl_enum_ciphers") == []


def test_happy_path_protocol_and_crypto_findings(tmp_path: Path) -> None:
    findings = parse_ssl_enum_ciphers(_nmap_xml(), b"", tmp_path, "ssl_enum_ciphers")
    categories = [f.category for f in findings]
    # TLSv1.0 → INFO + deprecated_protocol + weak_cipher; TLSv1.2 → INFO.
    assert categories.count(FindingCategory.INFO) == 2
    assert categories.count(FindingCategory.CRYPTO) == 2
    assert len(findings) == 4


def test_info_finding_shape(tmp_path: Path) -> None:
    findings = parse_ssl_enum_ciphers(_nmap_xml(), b"", tmp_path, "ssl_enum_ciphers")
    info = next(f for f in findings if f.category is FindingCategory.INFO)
    assert 326 in info.cwe
    assert info.confidence is ConfidenceLevel.CONFIRMED
    assert info.cvss_v3_score == 0.0


def test_crypto_finding_carries_cwe(tmp_path: Path) -> None:
    findings = parse_ssl_enum_ciphers(_nmap_xml(), b"", tmp_path, "ssl_enum_ciphers")
    crypto = [f for f in findings if f.category is FindingCategory.CRYPTO]
    assert all(326 in f.cwe for f in crypto)
    assert all(f.confidence is ConfidenceLevel.LIKELY for f in crypto)


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "ssl_ciphers.xml"
    canonical.write_bytes(_nmap_xml(addr="10.0.0.9"))
    parse_ssl_enum_ciphers(b"<root/>", b"", tmp_path, "ssl_enum_ciphers")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "10.0.0.9" in sidecar


def test_malformed_xml_returns_no_findings(tmp_path: Path) -> None:
    assert parse_ssl_enum_ciphers(b"<nmaprun><host>", b"", tmp_path, "ssl_enum_ciphers") == []


def test_garbage_bytes_returns_no_findings(tmp_path: Path) -> None:
    assert parse_ssl_enum_ciphers(b"not xml at all", b"", tmp_path, "ssl_enum_ciphers") == []


def test_sidecar_stamped_with_tool_id(tmp_path: Path) -> None:
    parse_ssl_enum_ciphers(_nmap_xml(), b"", tmp_path, "ssl_enum_ciphers")
    lines = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()
    records = [json.loads(line) for line in lines if line.strip()]
    assert records
    assert all(rec["tool_id"] == "ssl_enum_ciphers" for rec in records)
    assert any(rec.get("protocol") == "TLSv1.0" for rec in records)
