"""UI findings endpoint selects findings via the SAME canonical pipeline as the
report generator (single source of truth), so the UI list matches every report
tier. Previously the endpoint used a separate ``orchestration/finding_gate``
implementation, which could show findings/severities the reports did not.
"""

from __future__ import annotations

from types import SimpleNamespace

from src.reports.canonical_findings import apply_canonical_finding_pipeline
from src.reports.data_collector import finding_rows_from_models


def _model(
    rid: str,
    title: str,
    *,
    cwe: str = "CWE-200",
    description: str = "A sufficiently long finding description for the quality gate.",
    severity: str = "medium",
    cvss: float | None = None,
    proof_of_concept: dict | None = None,
    evidence_refs: list | None = None,
) -> SimpleNamespace:
    """Minimal DB-FindingModel stand-in carrying the attributes
    ``finding_rows_from_models`` reads."""
    return SimpleNamespace(
        id=rid,
        tenant_id="t1",
        scan_id="s1",
        report_id=None,
        severity=severity,
        title=title,
        description=description,
        cwe=cwe,
        cvss=cvss,
        owasp_category=None,
        proof_of_concept=proof_of_concept,
        confidence="likely",
        evidence_type=None,
        evidence_refs=evidence_refs or [],
        reproducible_steps=None,
        applicability_notes=None,
        created_at=None,
    )


def _canonical(models: list[SimpleNamespace]):
    return apply_canonical_finding_pipeline(finding_rows_from_models(models))


def test_canonical_collapses_same_title_cwe_duplicates() -> None:
    """Near-identical rows (same CWE + title) collapse to one — the UI must not
    list the same issue several times, matching the report snapshot."""
    rows = [
        _model("r1", "Missing rate limiting on login endpoint", cwe="CWE-307", severity="low"),
        _model(
            "r2",
            "Missing or insufficient rate limiting on login endpoint",
            cwe="CWE-307",
            severity="low",
        ),
        _model("r3", "Missing rate limiting on the login endpoint", cwe="CWE-307", severity="low"),
    ]
    assert len(_canonical(rows)) == 1


def test_canonical_drops_degenerate_description() -> None:
    """A finding with a too-short description is dropped by the quality filter."""
    rows = [_model("m1", "Some finding", description="no")]
    assert _canonical(rows) == []


def test_canonical_keeps_distinct_findings() -> None:
    """Distinct issues (different CWE + unrelated titles) are all retained."""
    rows = [
        _model("a", "Reflected XSS in q parameter", cwe="CWE-79", severity="high"),
        _model("b", "SPF record missing", cwe="CWE-16", severity="medium"),
        _model("c", "No CAA record", cwe="CWE-295", severity="low"),
    ]
    assert len(_canonical(rows)) == 3


def test_canonical_tags_provability() -> None:
    """The pipeline tags ``is_provable`` in place; nothing is dropped by it."""
    rows = [_model("p1", "SPF record missing", cwe="CWE-16")]
    out = _canonical(rows)
    assert len(out) == 1
    assert hasattr(out[0], "is_provable")


def test_host_of_normalizes_scheme_and_port() -> None:
    from src.orchestration.finding_gate import _host_of

    assert _host_of("https://alleksy.com/") == "alleksy.com"
    assert _host_of("https://alleksy.com:443/login") == "alleksy.com"
    assert _host_of("alleksy.com") == "alleksy.com"
    assert _host_of("") == ""
