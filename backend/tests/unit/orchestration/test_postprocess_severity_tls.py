"""_postprocess_findings_cvss: TLS gate (VHL-TLS-001) + CVSS→severity (VHL-SEV-001)."""

from __future__ import annotations

from src.orchestration.handlers import _postprocess_findings_cvss


def _by_title(findings, needle):
    return next(f for f in findings if needle.lower() in f["title"].lower())


class TestTlsGateInPostprocess:
    def test_bare_tls_probe_capped_to_info(self):
        out = _postprocess_findings_cvss(
            [
                {
                    "title": "TLS_PROBE finding",
                    "type": "TLS_PROBE",
                    "source_tool": "testssl",
                    "severity": "medium",
                    "cvss": 5.3,
                    "cwe": "CWE-326",
                    "description": "HTTP 200 on :443",
                }
            ]
        )
        tls = _by_title(out, "TLS_PROBE")
        assert tls["severity"] == "info"
        assert tls["cvss"] is None

    def test_weak_tls_probe_retained(self):
        out = _postprocess_findings_cvss(
            [
                {
                    "title": "TLS_PROBE finding",
                    "type": "TLS_PROBE",
                    "source_tool": "testssl",
                    "severity": "high",
                    "cvss": 7.4,
                    "cwe": "CWE-327",
                    "description": "RC4 and SSLv3 supported",
                }
            ]
        )
        tls = _by_title(out, "TLS_PROBE")
        assert tls["severity"] == "high"


class TestSeverityFromCvss:
    def test_sqli_upgraded_to_critical(self):
        out = _postprocess_findings_cvss(
            [{"title": "SQL injection in id", "severity": "low", "description": "sqli"}]
        )
        sqli = _by_title(out, "SQL injection")
        assert sqli["severity"] == "critical"  # CVSS 9.8 → critical

    def test_xss_upgraded_to_high(self):
        out = _postprocess_findings_cvss(
            [{"title": "Reflected XSS", "severity": "info", "description": "xss"}]
        )
        xss = _by_title(out, "XSS")
        assert xss["severity"] == "high"  # CVSS 7.2 → high

    def test_low_finding_not_inflated(self):
        out = _postprocess_findings_cvss(
            [{"title": "Verbose banner", "severity": "low", "cvss": 2.0, "description": "info leak"}]
        )
        low = _by_title(out, "Verbose banner")
        assert low["severity"] == "low"  # upgrade-only: 2.0 stays low
