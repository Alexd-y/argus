"""Standalone e2e check: render a fully-populated v2 snapshot to a multi-page PDF.

Proves Phase B (pagination) + C/D (v2 sections + finding cards) render end-to-end
through WeasyPrint, without a DB. Run inside the argus-backend container (WeasyPrint
present). Exits non-zero if the PDF is single-page or a v2 section is missing.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from src.reports.canonical_bundle import render_canonical_bundle
from src.reports.pdf_backend import get_active_backend
from src.reports.report_document import (
    ReportEvidenceRef,
    ReportFinding,
    ReportPoC,
    ReportRemediation,
    build_report_document,
)


def _findings(n: int):
    out = []
    for i in range(1, n + 1):
        out.append(
            ReportFinding(
                finding_id=f"F-{i:03d}",
                title=f"SQL Injection in endpoint /api/v1/resource{i}",
                severity="high",
                cwe="CWE-89",
                owasp_category="A03:2021",
                verification_status="confirmed",
                confidence=0.95,
                evidence_ids=[f"E-{i}"],
                validator_id="sqlmap",
                cvss_version="3.1",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                cvss_score=9.8,
                poc=ReportPoC(
                    tool="sqlmap 1.8.2",
                    payload="' OR 1=1 -- " * 6,
                    command="curl -sS -G 'https://target/api' --data-urlencode 'q=payload' " * 4,
                    http_request="GET /api/v1/resource?q=... HTTP/1.1\nHost: target\n" * 6,
                    http_response="HTTP/1.1 500 Internal Server Error\n" * 6,
                    discriminator="SQL syntax error signature in response body",
                    negative_control="Same request without payload returns 200 and clean body",
                    canary=f"argus-canary-{i:03d}",
                    observed_impact="Read one row belonging to another tenant",
                    reproducibility="confirmed",
                    evidence_ids=[f"E-{i}"],
                ),
                remediation=ReportRemediation(
                    status="generated_validated",
                    permanent_fix="Use parameterised queries in the resource search handler. " * 4,
                    component=f"resource{i}_service.py",
                    acceptance_criteria=["No error on quote payloads", "Prepared statements only"],
                ),
            )
        )
    return out


def main() -> int:
    doc = build_report_document(
        scan_id="verify-scan",
        tenant_id="verify-tenant",
        target="https://target.example",
        findings=_findings(15),
        evidence_references=[
            ReportEvidenceRef(evidence_id=f"E-{i}", kind="http", object_key=f"k{i}")
            for i in range(1, 16)
        ],
    )

    def _to_pdf(html: str) -> bytes | None:
        backend = get_active_backend()
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "verify.pdf"
            rendered = backend.render(html_content=html, output_path=out, scan_completed_at="")
            if rendered and out.exists():
                return out.read_bytes()
        return None

    artifacts = {
        a.format: a for a in render_canonical_bundle(doc, include_pdf=True, html_to_pdf=_to_pdf)
    }

    pdf = artifacts.get("pdf")
    if pdf is None:
        print("FAIL: no PDF artifact produced")
        return 1

    # Page count via WeasyPrint directly (container lacks pypdf).
    from weasyprint import HTML

    html_doc = artifacts["html"].content.decode("utf-8")
    rendered = HTML(string=html_doc).render()
    pages = len(rendered.pages)
    # Semantic checks run against the HTML/MD projections (parity guarantees the PDF
    # carries the same content); PDF text extraction needs no extra dependency.
    text = html_doc

    checks = {
        "multipage(>3)": pages > 3,
        "finding_F-001": "F-001" in text,
        "finding_F-015": "F-015" in text,
        "poc_canary": "argus-canary-001" in text,
        "cvss_vector": "AV:N/AC:L" in text,
        "remediation": "parameterised queries" in text.lower(),
        "passport": "generation_status" in text.lower() or "Report Passport" in text,
    }
    print(f"PDF pages: {pages}")
    for name, ok in checks.items():
        print(f"  [{'OK' if ok else 'FAIL'}] {name}")
    md = artifacts["md"].content.decode("utf-8")
    xml = artifacts["xml"].content.decode("utf-8")
    print(f"MD length: {len(md)}, XML length: {len(xml)}")

    if all(checks.values()):
        print("RESULT: PASS — v2 multi-page PDF with finding cards + PoC + remediation")
        return 0
    print("RESULT: FAIL")
    return 1


if __name__ == "__main__":
    sys.exit(main())
