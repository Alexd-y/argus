"""WSTG coverage must reflect findings that carry only a CWE / vuln_type.

Before this fix ``derive_wstg_states`` scored 0% whenever findings lacked an
explicit ``WSTG-*`` tag (the common case), because nothing mapped CWE →
WSTG. These tests lock in the CWE / vuln_type derivation and the evidence
linkage that lets a completed/fail test count toward coverage.
"""

from __future__ import annotations

from src.reports.wstg_coverage import wstg_ids_for_finding
from src.reports.wstg_gate import compute_wstg_coverage
from src.reports.wstg_plan import derive_wstg_states


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


class TestDeriveStatesCoverageFromFindings:
    def test_finding_with_evidence_counts(self) -> None:
        findings = [{"title": "TLS weak", "cwe": "CWE-319", "vuln_type": "tls_probe"}]
        evidence = {"WSTG-CRYP-01": ["FINDING:tls-1"]}
        states = derive_wstg_states([], findings, evidence_by_test=evidence)
        report = compute_wstg_coverage(states, catalog_size=len(states))
        assert report.counted >= 1
        assert report.completed_fail >= 1
        assert report.coverage_pct > 0.0

    def test_finding_without_evidence_does_not_count(self) -> None:
        findings = [{"title": "TLS weak", "cwe": "CWE-319"}]
        states = derive_wstg_states([], findings, evidence_by_test={})
        report = compute_wstg_coverage(states, catalog_size=len(states))
        # Marked completed/fail but no evidence → excluded from numerator (spec §4).
        assert report.counted == 0
        assert report.coverage_pct == 0.0
