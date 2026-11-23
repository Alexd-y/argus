"""WP B — proof-strength honesty reaches the findings CSV too (6th real format).

Pure/offline: builds a minimal ReportData and runs the real ``generate_csv``.
"""

from __future__ import annotations

import csv
import io

from src.api.schemas import Finding, ReportSummary
from src.reports.generators import ReportData, generate_csv


def _finding() -> Finding:
    return Finding(
        finding_id="fid-1",
        severity="high",
        title="SQL injection in /login",
        description="Boolean-based SQLi suspected on the id parameter.",
        cwe="CWE-89",
        cvss=7.5,
        cvss_score=7.5,
        confidence="likely",
        evidence_classification="candidate",
        is_provable=True,
        evidence_refs=["minio://artifacts/scan/req-1.txt"],
        unconfirmed_reason="payload blocked by WAF; no reflection observed",
    )


def _report() -> ReportData:
    return ReportData(
        report_id="r-1",
        target="https://victim.example.com",
        summary=ReportSummary(),
        findings=[_finding()],
        technologies=["nginx"],
        scan_id="00000000-0000-0000-0000-0000000000aa",
        tenant_id="00000000-0000-0000-0000-000000000001",
        created_at="2026-04-19T12:00:00Z",
    )


def _findings_table(blob: str) -> tuple[list[str], list[str]]:
    rows = list(csv.reader(io.StringIO(blob)))
    header_idx = next(i for i, r in enumerate(rows) if r and r[0] == "report_id")
    return rows[header_idx], rows[header_idx + 1]


def test_findings_csv_exposes_proof_state_and_counterevidence() -> None:
    header, row = _findings_table(generate_csv(_report()).decode("utf-8"))
    assert "proof_state" in header
    assert "counterevidence" in header
    assert row[header.index("proof_state")] in {"present", "missing", "unavailable"}
    assert "blocked by WAF" in row[header.index("counterevidence")]


def test_findings_csv_proof_columns_have_poe_and_bound_count() -> None:
    header, row = _findings_table(generate_csv(_report()).decode("utf-8"))
    assert "proof_poe_level" in header
    assert "bound_evidence" in header
    assert row[header.index("bound_evidence")] == "1"
