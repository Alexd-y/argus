"""WSTG coverage must reflect findings that carry only a CWE / vuln_type.

Findings frequently lack an explicit ``WSTG-*`` tag, so the CWE / vuln_type →
WSTG mapping (``wstg_ids_for_finding``) is what lets a control-failure count.
These tests lock in that mapping and the evidence gate: a completed/fail test
counts only when its evidence validated (ARGUS-WSTG-COV-1).
"""

from __future__ import annotations

from src.reports.wstg_applicability import decide_applicability
from src.reports.wstg_coverage import wstg_ids_for_finding
from src.reports.wstg_execution import aggregate_executions
from src.reports.wstg_gate import compute_wstg_coverage
from src.reports.wstg_plan import build_wstg_states, catalog_ids
from src.reports.wstg_producers import findings_to_executions


def _coverage_from_findings(findings, *, evidence_validated: bool):
    execs = findings_to_executions(
        findings,
        scan_id="scan-1",
        target="https://t.example",
        wstg_ids_for_finding=wstg_ids_for_finding,
    )
    aggregated = aggregate_executions(execs)
    finding_test_ids = frozenset(
        wid for f in findings if f.get("_has_evidence") for wid in wstg_ids_for_finding(f)
    )
    decisions = decide_applicability(finding_test_ids=finding_test_ids)
    ev = {tid: evidence_validated for tid in aggregated}
    states = build_wstg_states(
        decisions=decisions, aggregated=aggregated, evidence_validated_by_test=ev
    )
    return compute_wstg_coverage(states, catalog_ids=catalog_ids())


class TestWstgIdsForFinding:
    def test_cwe_maps_to_wstg(self) -> None:
        assert "WSTG-CONF-07" in wstg_ids_for_finding({"cwe": "CWE-693"})
        assert "WSTG-CRYP-01" in wstg_ids_for_finding({"cwe_id": "CWE-319"})
        assert "WSTG-INPV-05" in wstg_ids_for_finding({"cwe": "89"})

    def test_vuln_type_maps_to_wstg(self) -> None:
        assert "WSTG-CRYP-01" in wstg_ids_for_finding({"vuln_type": "tls_probe"})
        assert "WSTG-CONF-07" in wstg_ids_for_finding({"type": "security_headers"})
        assert "WSTG-ATHN-03" in wstg_ids_for_finding({"vuln_type": "rate_limit"})

    def test_explicit_tag_still_wins(self) -> None:
        assert "WSTG-INPV-01" in wstg_ids_for_finding({"tags": ["WSTG-INPV-01"]})

    def test_overbroad_cwe_unmapped(self) -> None:
        # CWE-200 is deliberately excluded to avoid inflating coverage.
        assert wstg_ids_for_finding({"cwe": "CWE-200"}) == set()


class TestCoverageFromFindings:
    def test_finding_with_validated_evidence_counts(self) -> None:
        findings = [
            {
                "id": "tls-1",
                "title": "TLS weak",
                "cwe": "CWE-319",
                "vuln_type": "tls_probe",
                "_has_evidence": True,
            }
        ]
        report = _coverage_from_findings(findings, evidence_validated=True)
        assert report.counted >= 1
        assert report.completed_fail >= 1
        assert report.coverage_pct is not None and report.coverage_pct > 0.0

    def test_finding_without_evidence_does_not_count(self) -> None:
        findings = [{"id": "tls-1", "title": "TLS weak", "cwe": "CWE-319", "_has_evidence": False}]
        report = _coverage_from_findings(findings, evidence_validated=False)
        # Producer emits a partial (evidence_present=False) → never counts (§3.5).
        assert report.counted == 0
