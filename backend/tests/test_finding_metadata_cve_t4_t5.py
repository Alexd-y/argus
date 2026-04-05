"""T4/T5 — finding metadata normalization and CVE platform mitigations."""

from __future__ import annotations

from src.orchestration.cve_platform_mitigations import (
    apply_platform_cve_mitigations,
    infer_hosting_platforms,
    parse_nextjs_version,
)
from src.orchestration.handlers import _postprocess_findings_cvss
from src.recon.trivy_recon_manifest_scan import raw_trivy_vuln_to_intel_row
from src.reports.finding_metadata import (
    apply_default_finding_metadata,
    extract_cve_ids_from_finding,
    format_evidence_cell,
    normalize_confidence,
    normalize_evidence_refs,
    normalize_evidence_type,
)


def test_normalize_confidence_and_evidence_type() -> None:
    assert normalize_confidence("CONFIRMED") == "confirmed"
    assert normalize_confidence("nope", default="possible") == "possible"
    assert normalize_evidence_type("CVE_CORRELATION") == "cve_correlation"
    assert normalize_evidence_type("bad") is None
    assert normalize_evidence_refs(["a", 1]) == ["a", "1"]


def test_format_evidence_cell() -> None:
    s = format_evidence_cell("observed", ["tool:dalfox"])
    assert "observed" in s
    assert "dalfox" in s


def test_extract_cve_ids_from_finding() -> None:
    f = {"title": "X", "description": "See CVE-2024-51479 for details"}
    assert "CVE-2024-51479" in extract_cve_ids_from_finding(f)


def test_apply_default_finding_metadata_active_scan_no_poc() -> None:
    """Active scan WITHOUT real PoC evidence → confidence='likely' (ARGUS-004)."""
    f: dict = {"source": "active_scan", "source_tool": "nuclei", "title": "t", "severity": "high"}
    apply_default_finding_metadata(f)
    assert f["confidence"] == "likely"
    assert f["evidence_type"] == "observed"
    assert any(x.startswith("tool:nuclei") for x in f["evidence_refs"])


def test_apply_default_finding_metadata_active_scan_with_poc() -> None:
    """Active scan WITH real PoC evidence → confidence='confirmed' (ARGUS-004)."""
    f: dict = {
        "source": "active_scan",
        "source_tool": "nuclei",
        "title": "t",
        "severity": "high",
        "proof_of_concept": {
            "request": "GET /vuln HTTP/1.1\nHost: target.com",
            "response": "HTTP/1.1 200 OK\n\n<script>alert(1)</script>",
        },
    }
    apply_default_finding_metadata(f)
    assert f["confidence"] == "confirmed"
    assert f["evidence_type"] == "observed"
    assert any(x.startswith("tool:nuclei") for x in f["evidence_refs"])


def test_apply_default_finding_metadata_threat_model() -> None:
    """Threat model source → confidence='possible' (ARGUS-004)."""
    f: dict = {"source": "threat_model", "title": "Potential IDOR", "severity": "medium"}
    apply_default_finding_metadata(f)
    assert f["confidence"] == "possible"
    assert f["evidence_type"] == "threat_model_inference"


def test_postprocess_applies_default_metadata() -> None:
    findings = [
        {
            "severity": "high",
            "title": "test",
            "description": "d",
            "cwe": "CWE-79",
            "cvss": 7.5,
            "source": "active_scan",
            "source_tool": "dalfox",
        }
    ]
    out = _postprocess_findings_cvss(findings)
    assert out[0]["confidence"] == "likely"
    assert out[0]["evidence_type"] == "observed"


def test_raw_trivy_vuln_to_intel_row_shape() -> None:
    raw = {
        "VulnerabilityID": "CVE-2021-1234",
        "PkgName": "curl",
        "Severity": "HIGH",
        "Title": "curl issue",
        "_target": "package.json",
    }
    wrapped = raw_trivy_vuln_to_intel_row(raw)
    assert wrapped["source_tool"] == "trivy"
    assert "curl" in wrapped["data"]["name"].lower()


def test_infer_hosting_platforms_vercel() -> None:
    assert "vercel" in infer_hosting_platforms("https://myapp.vercel.app/api")


def test_parse_nextjs_version() -> None:
    assert parse_nextjs_version('dependencies: {"next": "14.2.3"}') == "14.2.3"


def test_cve_2024_51479_vercel_downgrades_confirmed() -> None:
    findings = [
        {
            "severity": "high",
            "title": "Next.js CVE-2024-51479",
            "description": "RSC issue",
            "confidence": "confirmed",
            "cvss": 8.0,
            "cwe": "CWE-79",
        }
    ]
    apply_platform_cve_mitigations(
        findings,
        assets=["https://x.vercel.app"],
        target="https://x.vercel.app",
        extra_context_blob="next@14.2.0",
    )
    assert findings[0]["confidence"] == "advisory"
    assert "CVE-2024-51479" in (findings[0].get("applicability_notes") or "")
    assert "vercel" in (findings[0].get("applicability_notes") or "").lower()


def test_cve_2024_51479_self_hosted_keeps_confirmed() -> None:
    findings = [
        {
            "severity": "high",
            "title": "CVE-2024-51479 on Next",
            "description": "self-hosted",
            "confidence": "confirmed",
            "cvss": 8.0,
        }
    ]
    apply_platform_cve_mitigations(
        findings,
        assets=["https://example.com"],
        target="https://example.com",
        extra_context_blob="",
    )
    assert findings[0]["confidence"] == "confirmed"
