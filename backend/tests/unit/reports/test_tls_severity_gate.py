"""Tests for the TLS/SSL finding severity gate (VHL-TLS-001)."""

from __future__ import annotations

from src.reports.tls_severity_gate import (
    gate_tls_finding,
    is_tls_finding,
    weak_tls_signal,
)


class TestIsTlsFinding:
    def test_detects_by_source_tool(self):
        assert is_tls_finding({"source_tool": "testssl"})
        assert is_tls_finding({"source": "sslscan"})

    def test_detects_by_type(self):
        assert is_tls_finding({"type": "TLS_PROBE"})
        assert is_tls_finding({"vuln_type": "tls"})

    def test_detects_by_title(self):
        assert is_tls_finding({"title": "TLS_PROBE finding — https://x"})

    def test_non_tls_finding(self):
        assert not is_tls_finding({"source_tool": "nuclei", "title": "XSS"})


class TestWeakTlsSignal:
    def test_weak_protocol(self):
        assert weak_tls_signal({"description": "SSLv3 is offered"})
        assert weak_tls_signal({"description": "TLS 1.0 enabled"})

    def test_weak_cipher(self):
        assert weak_tls_signal({"description": "RC4 cipher supported"})
        assert weak_tls_signal({"title": "3DES / SWEET32 weakness"})

    def test_named_vuln(self):
        assert weak_tls_signal({"description": "Server vulnerable to Heartbleed"})

    def test_cert_error(self):
        assert weak_tls_signal({"description": "certificate is self-signed"})
        assert weak_tls_signal({"description": "hostname mismatch on cert"})

    def test_healthy_handshake_has_no_signal(self):
        assert not weak_tls_signal(
            {"description": "TLS 1.3 offered (OK); strong ciphers only"}
        )

    def test_empty_evidence(self):
        assert not weak_tls_signal({})


class TestGateTlsFinding:
    def test_caps_non_evidenced_tls_to_info(self):
        f = {
            "source_tool": "testssl",
            "type": "TLS_PROBE",
            "severity": "medium",
            "cvss": 5.3,
            "cwe": "CWE-326",
            "description": "HTTP 200 on :443",
        }
        assert gate_tls_finding(f) is True
        assert f["severity"] == "info"
        assert f["cvss"] is None
        assert f["cwe"] == "CWE-310"
        assert f["tls_gate_applied"] is True

    def test_keeps_evidenced_weak_tls(self):
        f = {
            "source_tool": "testssl",
            "type": "TLS_PROBE",
            "severity": "high",
            "cvss": 7.4,
            "cwe": "CWE-327",
            "description": "RC4 and SSLv3 supported",
        }
        assert gate_tls_finding(f) is False
        assert f["severity"] == "high"
        assert f["cvss"] == 7.4
        assert f["cwe"] == "CWE-327"

    def test_ignores_non_tls(self):
        f = {"source_tool": "dalfox", "severity": "high", "type": "xss"}
        assert gate_tls_finding(f) is False
        assert f["severity"] == "high"

    def test_already_info_tls_not_marked(self):
        f = {"source_tool": "testssl", "type": "TLS_PROBE", "severity": "info"}
        # No severity/cvss/cwe to downgrade → no-op.
        assert gate_tls_finding(f) is False
        assert f["severity"] == "info"
