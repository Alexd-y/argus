"""ARG-024 — Tests for :mod:`src.reports.junit_generator`.

Coverage targets:
    * Each finding becomes a ``<testcase>``.
    * ``critical|high|medium`` → ``<failure>``; ``low|info`` → ``<system-out>``.
    * ``tests`` / ``failures`` attributes match counts (CI gate semantics).
    * XML 1.0 control characters scrubbed (no parser rejection).
    * Determinism: same input → byte-identical output.
    * No-findings case still emits a valid testsuite (``tests=1``, summary case).

XML parsing in tests uses ``defusedxml`` — never the stdlib parser
(prevents XXE if a future test reads back attacker-controlled XML).
"""

from __future__ import annotations

import pytest
from defusedxml import ElementTree as DET

from src.api.schemas import Finding, ReportSummary
from src.reports.generators import ReportData
from src.reports.junit_generator import (
    JUNIT_HOSTNAME,
    JUNIT_TESTSUITE_NAME,
    build_junit_tree,
    generate_junit,
)


def _summary() -> ReportSummary:
    return ReportSummary(
        critical=0, high=0, medium=0, low=0, info=0,
        technologies=[], sslIssues=0, headerIssues=0, leaksFound=False,
    )


def _data(*, findings: list[Finding] | None = None) -> ReportData:
    return ReportData(
        report_id="r-1",
        target="https://x.test",
        summary=_summary(),
        findings=findings or [],
        technologies=["nginx"],
        scan_id="scan-1",
        tenant_id="tenant-1",
        created_at="2026-04-19T10:00:00Z",
    )


def _parse(xml_bytes: bytes):
    return DET.fromstring(xml_bytes)


class TestSuiteShape:
    def test_root_is_testsuites(self) -> None:
        root = _parse(generate_junit(_data()))
        assert root.tag == "testsuites"
        assert root.attrib["name"] == JUNIT_TESTSUITE_NAME

    def test_inner_testsuite_metadata(self) -> None:
        root = _parse(generate_junit(_data()))
        suite = root.find("testsuite")
        assert suite is not None
        assert suite.attrib["hostname"] == JUNIT_HOSTNAME
        assert suite.attrib["package"] == "argus.report"
        assert suite.attrib["id"] == "scan-1"
        assert suite.attrib["timestamp"] == "2026-04-19T10:00:00Z"

    def test_properties_block(self) -> None:
        root = _parse(generate_junit(_data()))
        props = root.find(".//properties")
        assert props is not None
        names = {p.attrib["name"] for p in props.findall("property")}
        assert {"target", "scan_id", "tenant_id"}.issubset(names)


class TestFailingSeverities:
    @pytest.mark.parametrize("sev", ["critical", "high", "medium"])
    def test_failing_severity_yields_failure_element(self, sev: str) -> None:
        f = Finding(severity=sev, title=f"{sev} bug", description="d", cwe="CWE-79", cvss=8.0)
        root = _parse(generate_junit(_data(findings=[f])))
        case = root.find(".//testcase")
        assert case is not None
        failure = case.find("failure")
        assert failure is not None
        assert failure.attrib["type"] == "CWE-79"
        assert sev.upper() in failure.attrib["message"]
        assert "[CVSS:8.0]" in failure.attrib["message"]

    @pytest.mark.parametrize("sev", ["low", "info", "informational"])
    def test_non_failing_severity_yields_system_out(self, sev: str) -> None:
        f = Finding(severity=sev, title=f"{sev} note", description="d")
        root = _parse(generate_junit(_data(findings=[f])))
        case = root.find(".//testcase")
        assert case is not None
        assert case.find("failure") is None
        sysout = case.find("system-out")
        assert sysout is not None
        assert (sysout.text or "").startswith(f"[{sev.upper()}]")


class TestCounts:
    def test_failures_count_matches_failing(self) -> None:
        findings = [
            Finding(severity="critical", title="c1", description=""),
            Finding(severity="high", title="h1", description=""),
            Finding(severity="medium", title="m1", description=""),
            Finding(severity="low", title="l1", description=""),
            Finding(severity="info", title="i1", description=""),
        ]
        root = _parse(generate_junit(_data(findings=findings)))
        suite = root.find("testsuite")
        assert suite is not None
        assert suite.attrib["tests"] == "5"
        assert suite.attrib["failures"] == "3"
        assert suite.attrib["errors"] == "0"

    def test_no_findings_emits_summary_case(self) -> None:
        root = _parse(generate_junit(_data()))
        suite = root.find("testsuite")
        assert suite is not None
        assert suite.attrib["tests"] == "1"
        assert suite.attrib["failures"] == "0"
        case = suite.find("testcase")
        assert case is not None
        assert case.attrib["classname"] == "argus.findings.summary"


class TestSafety:
    def test_control_characters_scrubbed(self) -> None:
        f = Finding(
            severity="high",
            title="bad\x00title\x07",
            description="body\x08with\x0Bcontrol",
        )
        out = generate_junit(_data(findings=[f]))
        # Should parse without errors (defusedxml is strict about control chars).
        root = _parse(out)
        case = root.find(".//testcase")
        assert case is not None
        # The malicious bytes are replaced with ``?`` (XML-1.0-safe).
        assert "\x00" not in (case.attrib.get("name") or "")
        assert "\x07" not in (case.attrib.get("name") or "")

    def test_truncates_oversized_title(self) -> None:
        big = "X" * 10_000
        f = Finding(severity="high", title=big, description="")
        out = generate_junit(_data(findings=[f]))
        root = _parse(out)
        case = root.find(".//testcase")
        assert case is not None
        assert len(case.attrib["name"]) < len(big)


class TestJunitDeterminism:
    def test_byte_identical_output(self) -> None:
        f1 = Finding(severity="critical", title="a", description="d", cwe="CWE-79", cvss=9.0)
        f2 = Finding(severity="high", title="b", description="d", cwe="CWE-22", cvss=7.5)
        out1 = generate_junit(_data(findings=[f1, f2]))
        out2 = generate_junit(_data(findings=[f1, f2]))
        assert out1 == out2

    def test_finding_order_independence(self) -> None:
        f1 = Finding(severity="low", title="z", description="")
        f2 = Finding(severity="critical", title="a", description="")
        out1 = generate_junit(_data(findings=[f1, f2]))
        out2 = generate_junit(_data(findings=[f2, f1]))
        assert out1 == out2


class TestBuildTreeReturnType:
    def test_returns_element_tree(self) -> None:
        tree = build_junit_tree(_data())
        assert tree.getroot().tag == "testsuites"
