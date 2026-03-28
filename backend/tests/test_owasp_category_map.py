"""OWASP Top 10:2025 category mapping (OWASP-002)."""

from __future__ import annotations

from src.recon.vulnerability_analysis.finding_normalizer import normalize_active_scan_intel_findings
from src.recon.vulnerability_analysis.owasp_category_map import (
    apply_owasp_category_to_intel_row,
    resolve_owasp_category,
)


def test_resolve_cwe79() -> None:
    assert resolve_owasp_category(cwe="CWE-79") == "A05"


def test_resolve_cwe352_csrf() -> None:
    assert resolve_owasp_category(cwe="CWE-352") == "A01"


def test_resolve_source_tool_sqlmap_without_cwe() -> None:
    assert resolve_owasp_category(cwe=None, finding_type_key=None, source_tool="sqlmap") == "A05"


def test_resolve_unknown_returns_none() -> None:
    assert resolve_owasp_category(cwe="UNKNOWN", finding_type_key="nope", source_tool="wfuzz") is None


def test_apply_intel_row_sets_category() -> None:
    row = {
        "finding_type": "vulnerability",
        "source_tool": "dalfox",
        "data": {"type": "XSS", "cwe": "CWE-79", "url": "https://x.test/"},
    }
    apply_owasp_category_to_intel_row(row)
    assert row["owasp_category"] == "A05"


def test_apply_intel_row_preserves_explicit_owasp_category() -> None:
    row = {
        "finding_type": "vulnerability",
        "source_tool": "web_vuln_heuristics",
        "owasp_category": "A08",
        "data": {"type": "Insecure deserialization", "cwe": "CWE-502", "url": "https://x.test/"},
    }
    apply_owasp_category_to_intel_row(row)
    assert row["owasp_category"] == "A08"


def test_normalizer_attaches_owasp() -> None:
    rows = [
        {
            "finding_type": "vulnerability",
            "source_tool": "nuclei",
            "data": {
                "type": "NUCLEI",
                "template_id": "http/exposures/configs/phpinfo-files",
                "matched_at": "https://x.test/phpinfo.php",
                "severity": "low",
            },
        },
    ]
    out = normalize_active_scan_intel_findings(rows)
    assert len(out) == 1
    assert out[0].get("owasp_category") == "A02"
