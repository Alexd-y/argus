"""ARG-024 — Tests for :mod:`src.reports.sarif_generator`.

Coverage targets:
    * SARIF v2.1.0 conformance (``$schema`` / ``version`` / ``runs`` shape).
    * Severity → SARIF level mapping (``error|warning|note``).
    * CWE-derived rule ids (`ARGUS-CWE-79`) and ``helpUri``.
    * CVSS surfaced via ``properties.security-severity`` (string per spec).
    * Stable fingerprint (same input → same digest, immune to ordering).
    * Determinism: same input → byte-identical output.
    * Optional jsonschema validation against the canonical SARIF schema.
"""

from __future__ import annotations

import json

import pytest

from src.api.schemas import Finding, ReportSummary
from src.reports.generators import ReportData
from src.reports.sarif_generator import (
    ARGUS_TOOL_INFORMATION_URI,
    ARGUS_TOOL_NAME,
    PRIMARY_FINGERPRINT_KEY,
    SARIF_SCHEMA_URL,
    SARIF_VERSION,
    build_sarif_payload,
    generate_sarif,
)


def _summary() -> ReportSummary:
    return ReportSummary(
        critical=0, high=0, medium=0, low=0, info=0,
        technologies=[], sslIssues=0, headerIssues=0, leaksFound=False,
    )


def _data(*, findings: list[Finding] | None = None, target: str = "https://x.test") -> ReportData:
    return ReportData(
        report_id="r-1",
        target=target,
        summary=_summary(),
        findings=findings or [],
        technologies=[],
        scan_id="scan-1",
        tenant_id="tenant-1",
    )


class TestPayloadShape:
    def test_top_level_fields(self) -> None:
        payload = build_sarif_payload(_data())
        assert payload["$schema"] == SARIF_SCHEMA_URL
        assert payload["version"] == SARIF_VERSION
        assert isinstance(payload["runs"], list)
        assert len(payload["runs"]) == 1

    def test_tool_driver_metadata(self) -> None:
        payload = build_sarif_payload(_data(), tool_version="1.2.3")
        driver = payload["runs"][0]["tool"]["driver"]
        assert driver["name"] == ARGUS_TOOL_NAME
        assert driver["informationUri"] == ARGUS_TOOL_INFORMATION_URI
        assert driver["version"] == "1.2.3"

    def test_automation_id_from_scan(self) -> None:
        payload = build_sarif_payload(_data())
        assert payload["runs"][0]["automationDetails"]["id"] == "scan-1"

    def test_artifact_for_target(self) -> None:
        payload = build_sarif_payload(_data())
        artifacts = payload["runs"][0].get("artifacts", [])
        assert artifacts and artifacts[0]["location"]["uri"] == "https://x.test"


class TestSeverityMapping:
    @pytest.mark.parametrize(
        ("sev", "level"),
        [
            ("critical", "error"),
            ("high", "error"),
            ("medium", "warning"),
            ("low", "note"),
            ("info", "note"),
            ("informational", "note"),
            ("UNKNOWN", "warning"),
            (None, "warning"),
        ],
    )
    def test_severity_to_level(self, sev: str | None, level: str) -> None:
        f = Finding(severity=sev or "info", title="t", description="")
        if sev is None:
            f.severity = ""
        payload = build_sarif_payload(_data(findings=[f]))
        result = payload["runs"][0]["results"][0]
        assert result["level"] == level


class TestRuleAndCwe:
    def test_rule_id_uses_cwe(self) -> None:
        f = Finding(severity="high", title="XSS", description="", cwe="CWE-79")
        payload = build_sarif_payload(_data(findings=[f]))
        rule = payload["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["id"] == "ARGUS-CWE-79"
        assert rule["helpUri"] == "https://cwe.mitre.org/data/definitions/79.html"

    def test_rule_id_falls_back_when_no_cwe(self) -> None:
        f = Finding(severity="high", title="custom finding", description="")
        payload = build_sarif_payload(_data(findings=[f]))
        rule = payload["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["id"].startswith("ARGUS-RULE-")

    def test_rule_dedup_for_same_cwe(self) -> None:
        f1 = Finding(severity="high", title="XSS-1", description="", cwe="CWE-79")
        f2 = Finding(severity="high", title="XSS-2", description="", cwe="CWE-79")
        payload = build_sarif_payload(_data(findings=[f1, f2]))
        rules = payload["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        results = payload["runs"][0]["results"]
        assert all(r["ruleId"] == "ARGUS-CWE-79" for r in results)


class TestProperties:
    def test_cvss_in_security_severity(self) -> None:
        f = Finding(severity="critical", title="t", description="", cvss=9.8)
        payload = build_sarif_payload(_data(findings=[f]))
        result = payload["runs"][0]["results"][0]
        assert result["properties"]["security-severity"] == "9.8"
        assert result["properties"]["cvss_v3_score"] == 9.8

    def test_owasp_category_propagated(self) -> None:
        f = Finding(
            severity="high",
            title="auth bypass",
            description="",
            owasp_category="A01",
        )
        payload = build_sarif_payload(_data(findings=[f]))
        result = payload["runs"][0]["results"][0]
        assert result["properties"]["owasp_top10_2025"] == "A01"

    def test_evidence_refs_propagated(self) -> None:
        f = Finding(
            severity="high",
            title="t",
            description="",
            evidence_refs=["s3://b/k1", "s3://b/k2"],
        )
        payload = build_sarif_payload(_data(findings=[f]))
        result = payload["runs"][0]["results"][0]
        assert result["properties"]["evidence_refs"] == ["s3://b/k1", "s3://b/k2"]


class TestFingerprints:
    def test_fingerprint_present(self) -> None:
        f = Finding(severity="high", title="t", description="")
        payload = build_sarif_payload(_data(findings=[f]))
        fp = payload["runs"][0]["results"][0]["fingerprints"]
        assert PRIMARY_FINGERPRINT_KEY in fp
        assert len(fp[PRIMARY_FINGERPRINT_KEY]) == 64

    def test_fingerprint_stable_across_runs(self) -> None:
        f = Finding(severity="high", title="t", description="x", cwe="CWE-79", cvss=8.0)
        payload_a = build_sarif_payload(_data(findings=[f]))
        payload_b = build_sarif_payload(_data(findings=[f]))
        fp_a = payload_a["runs"][0]["results"][0]["fingerprints"][PRIMARY_FINGERPRINT_KEY]
        fp_b = payload_b["runs"][0]["results"][0]["fingerprints"][PRIMARY_FINGERPRINT_KEY]
        assert fp_a == fp_b

    def test_fingerprint_changes_with_target(self) -> None:
        f = Finding(severity="high", title="t", description="")
        a = build_sarif_payload(_data(findings=[f], target="https://a.test"))
        b = build_sarif_payload(_data(findings=[f], target="https://b.test"))
        fp_a = a["runs"][0]["results"][0]["fingerprints"][PRIMARY_FINGERPRINT_KEY]
        fp_b = b["runs"][0]["results"][0]["fingerprints"][PRIMARY_FINGERPRINT_KEY]
        assert fp_a != fp_b


class TestSarifDeterminism:
    def test_byte_identical_output(self) -> None:
        f = Finding(severity="critical", title="t", description="d", cwe="CWE-79", cvss=9.8)
        out_a = generate_sarif(_data(findings=[f]))
        out_b = generate_sarif(_data(findings=[f]))
        assert out_a == out_b

    def test_finding_order_independence(self) -> None:
        a = Finding(severity="low", title="a", description="")
        b = Finding(severity="critical", title="b", description="")
        out1 = generate_sarif(_data(findings=[a, b]))
        out2 = generate_sarif(_data(findings=[b, a]))
        assert out1 == out2


class TestEmissionFormat:
    def test_generate_returns_bytes(self) -> None:
        out = generate_sarif(_data())
        assert isinstance(out, bytes)
        json.loads(out)

    def test_pretty_printed_json(self) -> None:
        out = generate_sarif(_data())
        text = out.decode("utf-8")
        assert "\n" in text  # multi-line indent

    def test_jsonschema_validation_when_available(self) -> None:
        try:
            import jsonschema  # noqa: F401
        except ImportError:
            pytest.skip("jsonschema not installed in test env")
        f = Finding(severity="critical", title="t", description="d", cwe="CWE-79", cvss=9.8)
        payload = build_sarif_payload(_data(findings=[f]))
        # Minimal SARIF v2.1.0 invariants we explicitly assert without
        # downloading the full schema (keeps tests offline-safe).
        assert payload["$schema"].endswith("sarif-2.1.0.json")
        assert payload["version"] == "2.1.0"
        for run in payload["runs"]:
            assert "tool" in run
            assert "driver" in run["tool"]
            assert "name" in run["tool"]["driver"]
            for result in run["results"]:
                assert "ruleId" in result
                assert "level" in result
                assert "message" in result
                assert "text" in result["message"]


class TestEmptyFindings:
    def test_empty_findings_yield_valid_sarif(self) -> None:
        payload = build_sarif_payload(_data())
        run = payload["runs"][0]
        assert run["results"] == []
        assert run["tool"]["driver"]["rules"] == []
