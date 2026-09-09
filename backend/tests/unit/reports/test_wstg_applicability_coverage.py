"""ARGUS-WSTG-COV-1 — honest applicability + coverage (replaces the old
"any reduced toolset must reach >80%" regression).

The point is no longer to *guarantee* a threshold: it is to prove that coverage
reflects verified facts. An unauthenticated static scan with no evidenced
findings must NOT reach the gate, and auth/input tests must stay ``unknown``
(in the denominator), never silently excluded (spec §3.1, §3.9, §14).
"""

from __future__ import annotations

from src.reports.wstg_applicability import decide_applicability
from src.reports.wstg_coverage import wstg_ids_for_finding
from src.reports.wstg_execution import aggregate_executions
from src.reports.wstg_gate import compute_wstg_coverage
from src.reports.wstg_model import Applicability
from src.reports.wstg_plan import build_wstg_states, catalog_checksum, catalog_ids
from src.reports.wstg_producers import findings_to_executions

_FINDINGS = [
    {
        "id": "F1",
        "title": "Missing security headers",
        "vuln_type": "security_headers",
        "cwe": "CWE-693",
        "_has_evidence": True,
        "proof_of_concept": {"observed": "no HSTS"},
    },
    {
        "id": "F3",
        "title": "Subdomain takeover",
        "wstg": "WSTG-CONF-10",
        "_has_evidence": True,
        "evidence_refs": ["ev-2"],
    },
]


def _coverage(findings):
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
    ev = {tid: True for tid in aggregated}  # finding is the (upstream-validated) evidence
    states = build_wstg_states(
        decisions=decisions, aggregated=aggregated, evidence_validated_by_test=ev
    )
    return compute_wstg_coverage(
        states, catalog_ids=catalog_ids(), catalog_checksum=catalog_checksum()
    )


class TestApplicabilityHonesty:
    def test_scenario1_no_credentials_keeps_auth_tests_unknown_not_na(self):
        decisions = decide_applicability()
        d = decisions["WSTG-ATHN-02"]
        assert d.state == Applicability.UNKNOWN
        assert d.is_valid_not_applicable() is False

    def test_universal_tests_are_applicable(self):
        decisions = decide_applicability()
        assert decisions["WSTG-INFO-02"].state == Applicability.APPLICABLE
        assert decisions["WSTG-CONF-07"].state == Applicability.APPLICABLE

    def test_scenario5_finding_reconsiders_applicability(self):
        decisions = decide_applicability(finding_test_ids=frozenset({"WSTG-INPV-05"}))
        assert decisions["WSTG-INPV-05"].state == Applicability.APPLICABLE


class TestHonestCoverage:
    def test_unauth_no_findings_does_not_pass_gate(self):
        report = _coverage([])
        assert report.counted == 0
        # Denominator is the honest in-scope catalog (nothing validly excluded).
        assert report.denominator > 0
        assert report.coverage_gate_passed is False

    def test_evidenced_findings_count_as_completed_fail(self):
        report = _coverage(_FINDINGS)
        assert report.counted >= 1
        assert report.completed_fail >= 1
        # A couple of evidenced findings never fabricate >80% of a full catalog.
        assert report.coverage_pct is not None
        assert report.coverage_pct < 80.0

    def test_denominator_is_full_in_scope_catalog(self):
        report = _coverage(_FINDINGS)
        # No validated N/A (surface unknown) → denominator == in_scope_total.
        assert report.denominator == report.in_scope_total
        assert report.validated_not_applicable == 0
