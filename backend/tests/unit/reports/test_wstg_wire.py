"""Track B-wire — strict WSTG report attached to the canonical snapshot behind a flag."""

from __future__ import annotations

from typing import ClassVar
from xml.etree.ElementTree import fromstring

import pytest
from src.core.config import settings
from src.reports.renderers import render_html, render_markdown, render_xml
from src.reports.snapshot_builder import build_snapshot_from_report_data


class _Finding:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _ReportData:
    scan_id = "s1"
    tenant_id = "t1"
    target = "example.com"
    evidence: ClassVar[list] = []

    def __init__(self, findings):
        self.findings = findings


class _SRD:
    scan = None
    coverage_occurrence: ClassVar[dict] = {}

    def __init__(self, tool_names):
        self.tool_runs = [{"id": f"TR-{i}", "tool_name": n, "status": "ok"}
                          for i, n in enumerate(tool_names)]


@pytest.fixture
def _flag_on():
    prev = settings.wstg_strict_gate_enabled
    settings.wstg_strict_gate_enabled = True
    try:
        yield
    finally:
        settings.wstg_strict_gate_enabled = prev


@pytest.fixture
def _flag_off():
    prev = settings.wstg_strict_gate_enabled
    settings.wstg_strict_gate_enabled = False
    try:
        yield
    finally:
        settings.wstg_strict_gate_enabled = prev


def test_wstg_absent_when_flag_off(_flag_off):
    doc = build_snapshot_from_report_data(
        _ReportData([]), scan_meta={"scan_id": "s1"}, scan_report_data=_SRD(["nmap", "nuclei"])
    )
    assert doc.wstg is None


def test_wstg_present_when_flag_on(_flag_on):
    doc = build_snapshot_from_report_data(
        _ReportData([]), scan_meta={"scan_id": "s1"}, scan_report_data=_SRD(["nmap", "nuclei"])
    )
    assert isinstance(doc.wstg, dict)
    assert doc.wstg["wstg_version"] == "4.2"
    assert "coverage_pct" in doc.wstg
    assert "gate_passed" in doc.wstg
    assert doc.wstg["catalog_size"] > 0


def test_empty_scan_wstg_is_zero_and_gate_false(_flag_on):
    doc = build_snapshot_from_report_data(
        _ReportData([]), scan_meta={"scan_id": "s1"}, scan_report_data=_SRD([])
    )
    assert doc.wstg["coverage_pct"] == 0.0
    assert doc.wstg["gate_passed"] is False


def test_markdown_renders_wstg_section_when_present(_flag_on):
    doc = build_snapshot_from_report_data(
        _ReportData([]), scan_meta={"scan_id": "s1"}, scan_report_data=_SRD(["nmap", "nuclei"])
    )
    md = render_markdown(doc)
    assert "WSTG v4.2 Coverage (strict)" in md
    assert "gate_passed" in md


def test_markdown_omits_wstg_section_when_absent(_flag_off):
    doc = build_snapshot_from_report_data(
        _ReportData([]), scan_meta={"scan_id": "s1"}, scan_report_data=_SRD(["nmap"])
    )
    md = render_markdown(doc)
    assert "WSTG v4.2 Coverage (strict)" not in md


def test_xml_contains_wstg_element_when_present(_flag_on):
    doc = build_snapshot_from_report_data(
        _ReportData([]), scan_meta={"scan_id": "s1"}, scan_report_data=_SRD(["nmap", "nuclei"])
    )
    root = fromstring(render_xml(doc))
    we = root.find("wstg")
    assert we is not None
    assert we.get("version") == "4.2"
    assert we.get("gate_passed") is not None


def test_xml_omits_wstg_element_when_absent(_flag_off):
    doc = build_snapshot_from_report_data(
        _ReportData([]), scan_meta={"scan_id": "s1"}, scan_report_data=_SRD(["nmap"])
    )
    root = fromstring(render_xml(doc))
    assert root.find("wstg") is None


def test_html_contains_wstg_section_when_present(_flag_on):
    doc = build_snapshot_from_report_data(
        _ReportData([]), scan_meta={"scan_id": "s1"}, scan_report_data=_SRD(["nmap", "nuclei"])
    )
    html = render_html(doc)
    assert "WSTG v4.2 Coverage (strict)" in html
    assert "gate_passed" in html


def test_html_omits_wstg_section_when_absent(_flag_off):
    doc = build_snapshot_from_report_data(
        _ReportData([]), scan_meta={"scan_id": "s1"}, scan_report_data=_SRD(["nmap"])
    )
    html = render_html(doc)
    assert "WSTG v4.2 Coverage (strict)" not in html
