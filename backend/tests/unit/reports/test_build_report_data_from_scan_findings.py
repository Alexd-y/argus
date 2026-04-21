"""Unit tests for scan-scoped ReportData builder (T04 export)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from src.db.models import Finding as FindingModel
from src.db.models import Scan
from src.reports.generators import build_report_data_from_scan_findings


def test_build_report_data_from_scan_findings_maps_rows() -> None:
    tid = str(uuid.uuid4())
    sid = str(uuid.uuid4())
    scan = Scan(
        id=sid,
        tenant_id=tid,
        target_id=None,
        target_url="https://example.com/app",
        status="completed",
    )
    scan.created_at = datetime.now(UTC)
    fid = str(uuid.uuid4())
    finding = FindingModel(
        id=fid,
        tenant_id=tid,
        scan_id=sid,
        report_id=None,
        severity="high",
        title="XSS",
        description="Reflected",
        cwe="CWE-79",
        cvss=7.5,
        owasp_category="A03",
    )
    data = build_report_data_from_scan_findings(scan, [finding])
    assert data.scan_id == sid
    assert data.tenant_id == tid
    assert data.target == "https://example.com/app"
    assert len(data.findings) == 1
    assert data.findings[0].title == "XSS"
    assert data.findings[0].severity == "high"
    assert data.summary.high >= 1
