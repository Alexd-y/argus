"""Unit tests for the conservative severity floor (product policy).

Verifies the raise-only floor that aligns backend severity with the Frontend
curated model for a small, unambiguous set of hardening findings, and that
*present-but-weak* conditions (SPF ``~all``, DMARC without ``rua``, CAA) are
left untouched.
"""

from __future__ import annotations

from src.findings.severity_policy import (
    apply_floor_to_dict,
    apply_floor_to_findings,
    resolve_display_severity,
    severity_floor_band,
)


class TestSeverityFloorBand:
    def test_security_headers_by_cwe_raised_to_high(self):
        band = severity_floor_band(
            "medium", "CWE-693", "Security HTTP response headers missing or incomplete"
        )
        assert band is not None and band.value == "high"

    def test_security_headers_by_title_signature_raised_to_high(self):
        band = severity_floor_band("low", "CWE-16", "X-Frame-Options header missing")
        assert band is not None and band.value == "high"

    def test_dnssec_not_enabled_raised_to_high(self):
        band = severity_floor_band("low", "CWE-350", "DNSSEC not enabled — alleksy.com")
        assert band is not None and band.value == "high"

    def test_dkim_not_detected_raised_to_medium(self):
        band = severity_floor_band("low", "CWE-16", "DKIM not detected — alleksy.com")
        assert band is not None and band.value == "medium"

    def test_spf_soft_fail_untouched(self):
        assert severity_floor_band("low", "CWE-16", "SPF not enforced (~all) — alleksy.com") is None

    def test_dmarc_no_rua_untouched(self):
        assert (
            severity_floor_band(
                "low", "CWE-16", "DMARC has no aggregate reporting (rua) — alleksy.com"
            )
            is None
        )

    def test_caa_untouched(self):
        assert severity_floor_band("low", "CWE-295", "No CAA record — alleksy.com") is None

    def test_raise_only_never_lowers(self):
        # A header finding already rated critical must NOT be pulled down to high.
        assert severity_floor_band("critical", "CWE-693", "Security headers missing") is None

    def test_unrelated_finding_untouched(self):
        assert severity_floor_band("info", "CWE-200", "Technology fingerprint (WhatWeb)") is None


class TestResolveDisplaySeverity:
    def test_raises_severity_and_cvss_to_band_floor(self):
        severity, cvss = resolve_display_severity(
            "medium", "CWE-693", "Security headers missing or incomplete", 4.3
        )
        assert severity == "high"
        assert cvss == 7.5  # representative high midpoint, not the lower 4.3

    def test_does_not_lower_existing_higher_cvss(self):
        severity, cvss = resolve_display_severity("low", "CWE-350", "DNSSEC not enabled", 8.5)
        assert severity == "high"
        assert cvss == 8.5  # already above the high midpoint — keep it

    def test_none_cvss_gets_representative(self):
        severity, cvss = resolve_display_severity("low", "CWE-16", "DKIM not detected", None)
        assert severity == "medium"
        assert cvss == 5.5

    def test_no_policy_returns_inputs_unchanged(self):
        severity, cvss = resolve_display_severity("low", "CWE-16", "SPF not enforced (~all)", 3.1)
        assert severity == "low"
        assert cvss == 3.1


class TestApplyFloorToDict:
    def test_mutates_dict_in_place(self):
        finding = {
            "severity": "medium",
            "cwe": "CWE-693",
            "title": "Security HTTP response headers missing or incomplete",
            "cvss": 4.3,
        }
        apply_floor_to_dict(finding)
        assert finding["severity"] == "high"
        assert finding["cvss"] == 7.5

    def test_untouched_finding_unchanged(self):
        finding = {
            "severity": "low",
            "cwe": "CWE-16",
            "title": "SPF not enforced (~all) — alleksy.com",
            "cvss": 3.1,
        }
        apply_floor_to_dict(finding)
        assert finding["severity"] == "low"
        assert finding["cvss"] == 3.1

    def test_idempotent(self):
        finding = {
            "severity": "low",
            "cwe": "CWE-350",
            "title": "DNSSEC not enabled",
            "cvss": None,
        }
        apply_floor_to_dict(finding)
        apply_floor_to_dict(finding)
        assert finding["severity"] == "high"
        assert finding["cvss"] == 7.5

    def test_non_dict_is_noop(self):
        apply_floor_to_dict(None)  # type: ignore[arg-type]

    def test_apply_to_findings_list(self):
        findings = [
            {
                "severity": "medium",
                "cwe": "CWE-693",
                "title": "Security headers missing",
                "cvss": 4.3,
            },
            {"severity": "low", "cwe": "CWE-16", "title": "SPF not enforced (~all)", "cvss": 3.1},
        ]
        apply_floor_to_findings(findings)
        assert findings[0]["severity"] == "high"
        assert findings[1]["severity"] == "low"
