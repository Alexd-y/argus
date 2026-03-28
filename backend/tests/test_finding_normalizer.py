"""Intel finding dedupe / severity merge (XSS-PLAN-006)."""

from __future__ import annotations

from src.recon.schemas.base import FindingType
from src.recon.vulnerability_analysis.finding_normalizer import (
    normalize_active_scan_intel_findings,
)


def _row(url: str, param: str, sev: str, cvss: float, poc: str = "x") -> dict:
    return {
        "finding_type": FindingType.VULNERABILITY,
        "value": f"xss:{url}:{param}",
        "data": {
            "type": "XSS",
            "url": url,
            "param": param,
            "severity": sev,
            "cvss_score": cvss,
            "cwe": "CWE-79",
            "poc": poc,
        },
        "source_tool": "dalfox",
        "confidence": 0.7,
    }


def test_normalize_dedupes_same_url_param_cwe() -> None:
    u = "https://Example.COM/path/?q=1"
    rows = [
        _row(u, "q", "medium", 5.0, "a"),
        _row("https://example.com/path", "q", "high", 7.2, "longer-payload-here"),
    ]
    out = normalize_active_scan_intel_findings(rows)
    assert len(out) == 1
    d = out[0]["data"]
    assert d["severity"] == "high"
    assert float(d["cvss_score"]) >= 7.2
    assert "longer" in (d.get("poc") or "")


def test_merge_dalfox_hypothesis_with_custom_xss() -> None:
    """Same host+path+param+CWE-79: hypothesis + custom PoC → one confirmed high XSS."""
    base = "https://example.com/alert1"
    hyp = {
        "finding_type": FindingType.VULNERABILITY,
        "value": f"xss:{base}:world",
        "data": {
            "type": "Reflected XSS (hypothesis)",
            "url": base,
            "param": "world",
            "severity": "medium",
            "cvss_score": 5.0,
            "cwe": "CWE-79",
            "poc": "(reflection suspected) param=world",
            "description": "Dalfox stderr indicated reflected input (partially_confirmed)",
        },
        "source_tool": "dalfox",
        "confidence": 0.55,
    }
    custom = {
        "finding_type": FindingType.VULNERABILITY,
        "value": f"xss:{base}?world=1:world",
        "data": {
            "type": "XSS",
            "url": f"{base}?world=alert%281%29",
            "param": "world",
            "severity": "high",
            "cvss_score": 7.2,
            "cwe": "CWE-79",
            "poc": "alert(1)",
            "poc_curl": "curl -sS -G 'https://example.com/alert1?world=alert(1)'",
            "description": "Script-context reflected XSS (GET)",
        },
        "source_tool": "custom_xss_poc",
        "confidence": 0.88,
    }
    out = normalize_active_scan_intel_findings([hyp, custom])
    assert len(out) == 1
    d = out[0]["data"]
    assert d.get("type") == "XSS"
    assert (d.get("severity") or "").lower() == "high"
    assert float(d.get("cvss_score") or 0) >= 7.0
    assert "Dalfox" in (d.get("description") or "") and "custom" in (d.get("description") or "").lower()
    assert d.get("poc_curl")
    assert out[0].get("source_tool") == "custom_xss_poc"


def test_normalize_caps_long_poc() -> None:
    long_poc = "P" * 5000
    rows = [
        {
            "finding_type": FindingType.VULNERABILITY,
            "value": "x",
            "data": {
                "type": "XSS",
                "url": "https://z.test/",
                "param": "a",
                "severity": "low",
                "cwe": "CWE-79",
                "poc": long_poc,
            },
            "source_tool": "t",
            "confidence": 0.5,
        }
    ]
    out = normalize_active_scan_intel_findings(rows)
    assert len(out) == 1
    assert len((out[0]["data"] or {}).get("poc", "")) < len(long_poc)
