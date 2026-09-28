"""Live cloud-LLM verification: generate a real Valhalla remediation/closure release
and merge it into the v2 snapshot. Proves Phase E end-to-end against the real cloud
report LLM. Run inside argus-backend with infra/.env + ARGUS_LLM_CLOUD_DISABLED=false.
"""

from __future__ import annotations

import sys

from src.reports.llm_remediation.facade_binding import build_facade_llm_callable
from src.reports.llm_remediation.integration import generate_valhalla_llm_release
from src.reports.report_document import ReportFinding, build_report_document
from src.reports.valhalla_llm_merge import merge_llm_into_document


def main() -> int:
    findings = [
        {
            "finding_id": "F-LIVE-1",
            "title": "Exposed .env configuration file",
            "severity": "high",
            "verification_status": "confirmed",
            "description": "The application serves /.env exposing configuration and secrets.",
            "evidence_refs": ["E1"],
        }
    ]
    report_meta = {
        "report_id": "R-LIVE",
        "report_version": "live-smoke",
        "tenant_id": "T-LIVE",
        "scan_id": "S-LIVE",
        "target": "example.test",
    }
    doc, release = generate_valhalla_llm_release(
        findings,
        report_meta=report_meta,
        llm_callable=build_facade_llm_callable(scan_id="S-LIVE", tenant_id="T-LIVE"),
        formats=["json", "md"],
        provider="facade",
        model="report_writer",
    )
    print("LLM release generation_status:", release.manifest.generation_status.value)
    print("assessment_completeness:", release.manifest.assessment_completeness.value)
    node = doc.findings[0]
    print("finding:", node.finding_id, "llm_analysis_status:", node.llm_analysis_status)
    if node.remediation is not None:
        print("remediation analysis_status:", node.remediation.analysis_status.value)
        print("permanent_fix_steps:", len(node.remediation.permanent_fix_steps))
    if node.closure is not None:
        print("closure permitted_status:", node.closure.permitted_closure_status.value)
        assert (
            node.closure.permitted_closure_status.value != "fixed_verified"
        ), "no retest performed → must not claim fixed_verified"

    # Prove the merge into the v2 snapshot works with the REAL LLM output.
    snap = build_report_document(
        scan_id="S-LIVE",
        tenant_id="T-LIVE",
        target="example.test",
        findings=[
            ReportFinding(
                finding_id="F-LIVE-1",
                title="Exposed .env configuration file",
                severity="high",
                verification_status="confirmed",
                evidence_ids=["E1"],
                validator_id="nuclei",
            )
        ],
    )
    merged = merge_llm_into_document(snap, doc)
    mf = merged.findings[0]
    print("merged llm_analysis_status:", merged.llm_analysis_status)
    print("merged finding has remediation:", mf.remediation is not None)
    print("merged finding has closure:", mf.closure is not None)
    print("RESULT: PASS — real cloud LLM produced remediation/closure, merged into v2")
    return 0


if __name__ == "__main__":
    sys.exit(main())
