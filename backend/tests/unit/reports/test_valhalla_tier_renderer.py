"""ARG-031 — Unit tests for ``src.reports.valhalla_tier_renderer``.

Coverage requirements (plan §3 ARG-031):

* assembly determinism (run twice → byte-identical),
* ordering invariants (composite score desc, ties broken by tool / cwe),
* sanitizer threading (verify ``sanitize_context`` is applied to
  reproducer fields and *that the sanitised tokens are surfaced via the
  business-impact rows*),
* business-context propagation (asset business-value affects risk),
* OWASP rollup correctness (CWE-79 → A05:Injection bucket per the
  2025 mapping; CWE-918 → A10:Mishandling; unknown CWE → A00:Other),
* presigned URL embedding for evidence refs,
* executive summary template renders deterministically with empty
  findings, single finding, max findings,
* edge cases: zero findings, all findings same severity, missing CVSS,
  missing CWE.

Goal: ≥ 25 deterministic test cases that pin every public guarantee
of the module without standing up Jinja, the DB, or the network.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from src.api.schemas import Finding, ReportSummary
from src.reports.generators import (
    EvidenceEntry,
    ReportData,
    TimelineEntry,
)
from src.reports.replay_command_sanitizer import (
    REDACTED_BEARER,
    SanitizeContext,
)
from src.reports.valhalla_tier_renderer import (
    VALHALLA_EXECUTIVE_SECTION_ORDER,
    VALHALLA_TOP_ASSETS_CAP,
    VALHALLA_TOP_FINDINGS_CAP,
    AssetRiskRow,
    BusinessContext,
    BusinessImpactFindingRow,
    OwaspRollupRow,
    RemediationPhaseRow,
    ValhallaEvidenceRef,
    ValhallaSectionAssembly,
    ValhallaTimelineEntry,
    assemble_valhalla_sections,
    valhalla_assembly_to_jinja_context,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _finding(
    *,
    severity: str = "high",
    title: str = "SQLi at /api/v1/users",
    cwe: str | None = "CWE-89",
    cvss: float | None = 8.6,
    owasp: str | None = "A05",
    confidence: str = "confirmed",
    poc: dict[str, Any] | None = None,
    repro_steps: str | None = None,
    description: str | None = None,
    kev_listed: bool = False,
    kev_added_date: str | None = None,
    epss_percentile: float | None = None,
    ssvc_decision: str | None = None,
) -> Finding:
    return Finding(
        severity=severity,
        title=title,
        description=description or f"{title} - synthetic test finding.",
        cwe=cwe,
        cvss=cvss,
        owasp_category=owasp,  # type: ignore[arg-type]
        proof_of_concept=poc,
        confidence=confidence,  # type: ignore[arg-type]
        evidence_type="tool_output",
        reproducible_steps=repro_steps,
        applicability_notes=None,
        kev_listed=kev_listed,
        kev_added_date=kev_added_date,
        epss_percentile=epss_percentile,
        ssvc_decision=ssvc_decision,
    )


_SENTINEL: list[Finding] = []


def _make_data(
    *,
    findings: list[Finding] | None = _SENTINEL,  # type: ignore[assignment]
    timeline: list[TimelineEntry] | None = None,
    evidence: list[EvidenceEntry] | None = None,
    target: str = "https://acme.example.com",
    scan_id: str = "scan-001",
    tenant_id: str = "tenant-default",
    created_at: str = "2026-04-19T12:00:00Z",
) -> ReportData:
    # Sentinel pattern: the caller can pass an explicit ``findings=[]`` to mean
    # "no findings". A bare ``None`` (or omission) yields the default fixture.
    if findings is _SENTINEL:
        findings = [_finding()]
    elif findings is None:
        findings = [_finding()]
    return ReportData(
        report_id="rep-001",
        target=target,
        summary=ReportSummary(critical=0, high=1, medium=0, low=0, info=0),
        findings=findings,
        technologies=["nginx", "django"],
        created_at=created_at,
        scan_id=scan_id,
        tenant_id=tenant_id,
        timeline=timeline or [],
        evidence=evidence or [],
        screenshots=[],
    )


# ---------------------------------------------------------------------------
# Section ordering & shape (1-6)
# ---------------------------------------------------------------------------


def test_assembly_returns_pydantic_model() -> None:
    out = assemble_valhalla_sections(_make_data())
    assert isinstance(out, ValhallaSectionAssembly)


def test_section_order_constant_is_complete_and_immutable() -> None:
    expected = (
        "title_meta",
        "executive_summary",
        "executive_summary_counts",
        "risk_quantification_per_asset",
        "owasp_rollup_matrix",
        "top_findings_by_business_impact",
        "kev_listed_findings",
        "remediation_roadmap",
        "evidence_refs",
        "timeline_entries",
    )
    assert VALHALLA_EXECUTIVE_SECTION_ORDER == expected
    assert isinstance(VALHALLA_EXECUTIVE_SECTION_ORDER, tuple)


def test_assembly_serialises_to_json_round_trip() -> None:
    out = assemble_valhalla_sections(_make_data())
    blob = out.model_dump_json()
    parsed = json.loads(blob)
    for section in VALHALLA_EXECUTIVE_SECTION_ORDER:
        assert section in parsed


def test_title_meta_contains_required_keys() -> None:
    out = assemble_valhalla_sections(_make_data())
    for k in ("report_id", "target", "scan_id", "tenant_id", "tier", "created_at"):
        assert k in out.title_meta
    assert out.title_meta["tier"] == "valhalla"


def test_assembly_is_frozen() -> None:
    """ValhallaSectionAssembly must be immutable to satisfy the contract."""
    out = assemble_valhalla_sections(_make_data())
    with pytest.raises((TypeError, ValueError, AttributeError)):
        out.executive_summary = "tampered"  # type: ignore[misc]


def test_assembly_forbids_extra_fields() -> None:
    with pytest.raises(Exception):  # pydantic ValidationError
        ValhallaSectionAssembly(executive_summary="x", unexpected="boom")  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# Determinism (7-8)
# ---------------------------------------------------------------------------


def test_assembly_is_byte_deterministic_across_runs() -> None:
    data = _make_data(
        findings=[
            _finding(severity="critical", title="A", cwe="CWE-79", cvss=9.0),
            _finding(severity="high", title="B", cwe="CWE-89", cvss=8.0),
            _finding(severity="medium", title="C", cwe="CWE-22", cvss=5.0),
        ],
        timeline=[
            TimelineEntry(
                phase="recon", order_index=1, entry={"k": 1}, created_at="t1"
            ),
            TimelineEntry(phase="scan", order_index=2, entry={"k": 2}, created_at="t2"),
        ],
        evidence=[
            EvidenceEntry(finding_id="f1", object_key="k/a", description="ev1"),
            EvidenceEntry(finding_id="f2", object_key="k/b", description="ev2"),
        ],
    )
    a = assemble_valhalla_sections(data).model_dump_json()
    b = assemble_valhalla_sections(data).model_dump_json()
    assert a == b


def test_assembly_is_byte_deterministic_with_business_context() -> None:
    bctx = BusinessContext(
        asset_business_values=(("acme.example.com", 3.0),), default_business_value=1.0
    )
    data = _make_data()
    a = assemble_valhalla_sections(data, business_context=bctx).model_dump_json()
    b = assemble_valhalla_sections(data, business_context=bctx).model_dump_json()
    assert a == b


# ---------------------------------------------------------------------------
# Ordering invariants for asset risk + top findings (9-12)
# ---------------------------------------------------------------------------


def test_asset_risk_rows_sorted_by_composite_score_desc() -> None:
    f1 = _finding(
        severity="medium",
        title="m1",
        cwe="CWE-89",
        cvss=5.0,
        poc={"url": "https://api.acme.example.com/v1"},
    )
    f2 = _finding(
        severity="critical",
        title="c1",
        cwe="CWE-79",
        cvss=9.5,
        poc={"url": "https://app.acme.example.com/dashboard"},
    )
    f3 = _finding(
        severity="low",
        title="l1",
        cwe="CWE-22",
        cvss=3.0,
        poc={"url": "https://www.acme.example.com/about"},
    )
    bctx = BusinessContext(
        asset_business_values=(
            ("api.acme.example.com", 1.0),
            ("app.acme.example.com", 5.0),
            ("www.acme.example.com", 0.1),
        ),
    )
    out = assemble_valhalla_sections(
        _make_data(findings=[f1, f2, f3]),
        business_context=bctx,
    )
    assert len(out.risk_quantification_per_asset) == 3
    scores = [r.composite_score for r in out.risk_quantification_per_asset]
    assert scores == sorted(scores, reverse=True)
    assert out.risk_quantification_per_asset[0].asset == "app.acme.example.com"


def test_asset_risk_caps_to_max_assets() -> None:
    findings = [
        _finding(
            severity="medium",
            title=f"f{i}",
            cwe="CWE-89",
            cvss=5.0,
            poc={"url": f"https://h{i}.example.com/x"},
        )
        for i in range(VALHALLA_TOP_ASSETS_CAP + 5)
    ]
    out = assemble_valhalla_sections(_make_data(findings=findings))
    assert len(out.risk_quantification_per_asset) == VALHALLA_TOP_ASSETS_CAP


def test_top_findings_ranked_by_intel_aware_prioritizer() -> None:
    bctx = BusinessContext(
        asset_business_values=(("acme.example.com", 5.0),),
        default_business_value=1.0,
    )
    findings = [
        _finding(severity="low", title="A_low", cvss=3.0, owasp="A01"),
        _finding(severity="critical", title="B_crit", cvss=9.0, owasp="A05"),
        _finding(severity="high", title="C_high", cvss=8.0, owasp="A03"),
        _finding(severity="high", title="A_high", cvss=8.0, owasp="A03"),
    ]
    out = assemble_valhalla_sections(
        _make_data(findings=findings), business_context=bctx
    )
    titles = [r.title for r in out.top_findings_by_business_impact]
    assert titles[0] == "B_crit"
    # Intel-aware :class:`FindingPrioritizer` orders within bucket; not title-only.
    assert titles == ["B_crit", "C_high", "A_high", "A_low"]


def test_top_findings_capped_at_max_findings() -> None:
    findings = [_finding(severity="medium", title=f"t{i}", cvss=5.0) for i in range(40)]
    out = assemble_valhalla_sections(_make_data(findings=findings))
    assert len(out.top_findings_by_business_impact) == VALHALLA_TOP_FINDINGS_CAP


# ---------------------------------------------------------------------------
# Sanitizer threading (13-15)
# ---------------------------------------------------------------------------


def test_sanitizer_redacts_bearer_token_in_top_findings() -> None:
    f = _finding(
        poc={
            "url": "https://acme.example.com/api/v1/users",
            "replay_command": [
                "curl",
                "-H",
                "Authorization: Bearer eyJabc123def456ghi",
                "https://acme.example.com/api/v1/users",
            ],
        }
    )
    sctx = SanitizeContext(
        target="https://acme.example.com",
        endpoints=("https://acme.example.com/api/v1/users",),
    )
    out = assemble_valhalla_sections(_make_data(findings=[f]), sanitize_context=sctx)
    assert out.top_findings_by_business_impact, "top findings must be populated"
    cmd = " ".join(out.top_findings_by_business_impact[0].sanitized_command)
    assert "eyJabc123def456ghi" not in cmd
    assert REDACTED_BEARER in cmd or "[REDACTED" in cmd


def test_sanitizer_handles_string_form_reproducer() -> None:
    f = _finding(
        poc={
            "url": "https://acme.example.com",
            "reproducer": "curl https://acme.example.com/admin",
        }
    )
    sctx = SanitizeContext(target="https://acme.example.com")
    out = assemble_valhalla_sections(_make_data(findings=[f]), sanitize_context=sctx)
    assert out.top_findings_by_business_impact
    cmd = " ".join(out.top_findings_by_business_impact[0].sanitized_command)
    assert "acme.example.com" not in cmd


def test_sanitizer_no_command_for_findings_without_poc() -> None:
    out = assemble_valhalla_sections(_make_data(findings=[_finding(poc=None)]))
    assert out.top_findings_by_business_impact[0].sanitized_command == ()


# ---------------------------------------------------------------------------
# Business context propagation (16-18)
# ---------------------------------------------------------------------------


def test_business_value_inflates_composite_score() -> None:
    f = _finding(
        severity="high",
        cvss=8.0,
        confidence="confirmed",
        poc={"url": "https://payments.acme.example.com/api"},
    )
    bctx_low = BusinessContext(
        asset_business_values=(("payments.acme.example.com", 1.0),)
    )
    bctx_high = BusinessContext(
        asset_business_values=(("payments.acme.example.com", 5.0),)
    )
    low = assemble_valhalla_sections(
        _make_data(findings=[f]), business_context=bctx_low
    )
    high = assemble_valhalla_sections(
        _make_data(findings=[f]), business_context=bctx_high
    )
    assert (
        high.risk_quantification_per_asset[0].composite_score
        > low.risk_quantification_per_asset[0].composite_score
    )


def test_business_context_default_one_when_no_overrides() -> None:
    f = _finding(
        severity="high",
        cvss=8.0,
        confidence="confirmed",
        poc={"url": "https://unknown.example/x"},
    )
    out = assemble_valhalla_sections(_make_data(findings=[f]))
    row = out.risk_quantification_per_asset[0]
    assert row.business_value == 1.0
    # composite = 8.0 * 1.0 * 1.0 (confirmed)
    assert row.composite_score == pytest.approx(8.0)


def test_business_context_value_for_lookup() -> None:
    bctx = BusinessContext(
        asset_business_values=(("a.example", 2.5), ("b.example", 0.5)),
        default_business_value=1.0,
    )
    assert bctx.value_for("a.example") == 2.5
    assert bctx.value_for("b.example") == 0.5
    assert bctx.value_for("c.example") == 1.0


# ---------------------------------------------------------------------------
# OWASP rollup correctness (19-23)
# ---------------------------------------------------------------------------


def test_owasp_rollup_returns_eleven_categories_in_canonical_order() -> None:
    out = assemble_valhalla_sections(_make_data(findings=[]))
    # 10 canonical + A00 "Other"
    ids = [r.category_id for r in out.owasp_rollup_matrix]
    assert ids == [
        "A01",
        "A02",
        "A03",
        "A04",
        "A05",
        "A06",
        "A07",
        "A08",
        "A09",
        "A10",
        "A00",
    ]


def test_owasp_rollup_buckets_xss_to_a05_injection() -> None:
    out = assemble_valhalla_sections(
        _make_data(findings=[_finding(cwe="CWE-79", owasp=None, severity="high")])
    )
    a05 = next(r for r in out.owasp_rollup_matrix if r.category_id == "A05")
    assert a05.high == 1
    assert a05.total == 1


def test_owasp_rollup_buckets_ssrf_to_a10_mishandling() -> None:
    out = assemble_valhalla_sections(
        _make_data(findings=[_finding(cwe="CWE-918", owasp=None, severity="critical")])
    )
    a10 = next(r for r in out.owasp_rollup_matrix if r.category_id == "A10")
    assert a10.critical == 1
    assert a10.total == 1


def test_owasp_rollup_unmapped_cwe_falls_to_other_bucket() -> None:
    out = assemble_valhalla_sections(
        _make_data(findings=[_finding(cwe="CWE-99999", owasp=None, severity="low")])
    )
    a00 = next(r for r in out.owasp_rollup_matrix if r.category_id == "A00")
    assert a00.low == 1


def test_owasp_rollup_explicit_owasp_category_takes_precedence_over_cwe() -> None:
    # Even though CWE-79 → A05, explicit owasp_category="A06" wins.
    out = assemble_valhalla_sections(
        _make_data(findings=[_finding(cwe="CWE-79", owasp="A06", severity="high")])
    )
    a06 = next(r for r in out.owasp_rollup_matrix if r.category_id == "A06")
    assert a06.high == 1


# ---------------------------------------------------------------------------
# Remediation roadmap (24-27)
# ---------------------------------------------------------------------------


def test_remediation_roadmap_has_four_phases_in_order() -> None:
    out = assemble_valhalla_sections(_make_data())
    ids = [p.phase_id for p in out.remediation_roadmap]
    assert ids == ["P0", "P1", "P2", "P3"]


def test_remediation_roadmap_buckets_by_severity() -> None:
    findings = [
        _finding(severity="critical", title="c1"),
        _finding(severity="critical", title="c2"),
        _finding(severity="high", title="h1"),
        _finding(severity="medium", title="m1"),
        _finding(severity="low", title="l1"),
        _finding(severity="info", title="i1"),
    ]
    out = assemble_valhalla_sections(_make_data(findings=findings))
    by_id = {p.phase_id: p for p in out.remediation_roadmap}
    assert by_id["P0"].finding_count == 2
    assert by_id["P1"].finding_count == 1
    assert by_id["P2"].finding_count == 1
    assert by_id["P3"].finding_count == 2  # low + info


def test_remediation_roadmap_top_titles_capped_at_five() -> None:
    findings = [_finding(severity="critical", title=f"crit-{i:02d}") for i in range(8)]
    out = assemble_valhalla_sections(_make_data(findings=findings))
    p0 = next(p for p in out.remediation_roadmap if p.phase_id == "P0")
    assert p0.finding_count == 8
    assert len(p0.top_finding_titles) == 5


def test_remediation_roadmap_p3_sla_is_zero() -> None:
    out = assemble_valhalla_sections(_make_data())
    p3 = next(p for p in out.remediation_roadmap if p.phase_id == "P3")
    assert p3.sla_days == 0


# ---------------------------------------------------------------------------
# Evidence + presigner (28-30)
# ---------------------------------------------------------------------------


def test_evidence_invokes_presigner_and_returns_url() -> None:
    data = _make_data(
        evidence=[
            EvidenceEntry(finding_id="f1", object_key="k/a", description="ev1"),
            EvidenceEntry(finding_id="f2", object_key="k/b", description=None),
        ]
    )
    seen: list[str] = []

    def presigner(key: str) -> str | None:
        seen.append(key)
        return f"https://signed.example/{key}?sig=xyz"

    out = assemble_valhalla_sections(data, presigner=presigner)
    assert {"k/a", "k/b"} == set(seen)
    assert all(
        e.presigned_url and e.presigned_url.startswith("https://signed.example/")
        for e in out.evidence_refs
    )


def test_evidence_handles_presigner_exception_gracefully() -> None:
    data = _make_data(
        evidence=[EvidenceEntry(finding_id="f1", object_key="k/a", description=None)]
    )

    def boom(_: str) -> str | None:
        raise RuntimeError("S3 down")

    out = assemble_valhalla_sections(data, presigner=boom)
    assert out.evidence_refs[0].presigned_url is None


def test_evidence_sorted_by_finding_then_object_key() -> None:
    data = _make_data(
        evidence=[
            EvidenceEntry(finding_id="f2", object_key="k/b", description=None),
            EvidenceEntry(finding_id="f1", object_key="k/c", description=None),
            EvidenceEntry(finding_id="f1", object_key="k/a", description=None),
        ]
    )
    out = assemble_valhalla_sections(data)
    keys = [(e.finding_id, e.object_key) for e in out.evidence_refs]
    assert keys == [("f1", "k/a"), ("f1", "k/c"), ("f2", "k/b")]


# ---------------------------------------------------------------------------
# Executive summary template (31-34)
# ---------------------------------------------------------------------------


def test_executive_summary_is_non_empty() -> None:
    out = assemble_valhalla_sections(_make_data())
    assert out.executive_summary
    assert "scan-001" in out.executive_summary
    assert "tenant-default" in out.executive_summary


def test_executive_summary_zero_findings_handled() -> None:
    out = assemble_valhalla_sections(_make_data(findings=[]))
    assert out.executive_summary
    assert (
        "0 actionable" in out.executive_summary or "0 finding" in out.executive_summary
    )


def test_executive_summary_contains_top_asset_when_findings_present() -> None:
    f = _finding(
        severity="critical",
        cvss=9.5,
        poc={"url": "https://payments.acme.example.com/checkout"},
    )
    out = assemble_valhalla_sections(_make_data(findings=[f]))
    assert "payments.acme.example.com" in out.executive_summary
    assert "P0" in out.executive_summary


def test_executive_summary_counts_match_findings() -> None:
    findings = [
        _finding(severity="critical"),
        _finding(severity="critical"),
        _finding(severity="medium"),
        _finding(severity="info"),
    ]
    out = assemble_valhalla_sections(_make_data(findings=findings))
    assert out.executive_summary_counts["critical"] == 2
    assert out.executive_summary_counts["medium"] == 1
    assert out.executive_summary_counts["info"] == 1
    assert out.executive_summary_counts["high"] == 0
    assert out.executive_summary_counts["low"] == 0


# ---------------------------------------------------------------------------
# Edge cases (35-39)
# ---------------------------------------------------------------------------


def test_zero_findings_returns_empty_collections() -> None:
    out = assemble_valhalla_sections(_make_data(findings=[]))
    assert out.top_findings_by_business_impact == ()
    assert out.risk_quantification_per_asset == ()
    # Roadmap still emits four phases (with finding_count=0)
    assert len(out.remediation_roadmap) == 4
    assert sum(p.finding_count for p in out.remediation_roadmap) == 0


def test_missing_cvss_falls_back_to_severity_weight() -> None:
    f = _finding(
        severity="high",
        cvss=None,
        confidence="confirmed",
        poc={"url": "https://h.example/x"},
    )
    out = assemble_valhalla_sections(_make_data(findings=[f]))
    row = out.risk_quantification_per_asset[0]
    # severity weight for high = 7.5; bv=1; expl=1 → composite ≈ 7.5
    assert row.composite_score == pytest.approx(7.5)


def test_missing_cwe_and_owasp_buckets_to_other() -> None:
    f = _finding(cwe=None, owasp=None, severity="medium")
    out = assemble_valhalla_sections(_make_data(findings=[f]))
    a00 = next(r for r in out.owasp_rollup_matrix if r.category_id == "A00")
    assert a00.medium == 1


def test_informational_collapses_into_info_bucket() -> None:
    f = _finding(severity="informational", cvss=0.0)
    out = assemble_valhalla_sections(_make_data(findings=[f]))
    assert out.executive_summary_counts["info"] == 1


def test_does_not_mutate_input_data() -> None:
    data = _make_data()
    original_findings = list(data.findings)
    original_target = data.target
    assemble_valhalla_sections(data)
    assert data.findings == original_findings
    assert data.target == original_target


# ---------------------------------------------------------------------------
# Timeline + Jinja projector (40-43)
# ---------------------------------------------------------------------------


def test_timeline_entries_sorted_by_order_index() -> None:
    data = _make_data(
        timeline=[
            TimelineEntry(phase="b", order_index=2, entry={"k": 2}, created_at="t2"),
            TimelineEntry(phase="a", order_index=1, entry={"k": 1}, created_at="t1"),
            TimelineEntry(phase="c", order_index=3, entry=None, created_at=None),
        ]
    )
    out = assemble_valhalla_sections(data)
    ids = [t.order_index for t in out.timeline_entries]
    assert ids == [1, 2, 3]
    # Snippet is JSON-canonical for dict, empty for None
    assert out.timeline_entries[0].snippet == '{"k": 1}'
    assert out.timeline_entries[2].snippet == ""


def test_jinja_projector_includes_executive_report_slot() -> None:
    out = assemble_valhalla_sections(_make_data())
    ctx = valhalla_assembly_to_jinja_context(out)
    assert ctx["tier"] == "valhalla"
    assert "valhalla_executive_report" in ctx
    assert isinstance(ctx["valhalla_executive_report"], dict)
    assert ctx.get("valhalla_executive_section_order") == list(VALHALLA_EXECUTIVE_SECTION_ORDER)
    for k in VALHALLA_EXECUTIVE_SECTION_ORDER:
        assert k in ctx["valhalla_executive_report"]


def test_jinja_executive_report_serialises_kev_section_for_html_pdf() -> None:
    """RPT-002 — KEV rows must appear in the same blob HTML/PDF consume."""
    f = _finding(
        severity="critical",
        title="KEV-tracked vuln",
        cwe="CWE-918",
        cvss=9.0,
        owasp=None,
        poc={"url": "https://api.acme.example.com/"},
        kev_listed=True,
        kev_added_date="2024-01-15",
        epss_percentile=0.99,
        ssvc_decision="Act",
    )
    out = assemble_valhalla_sections(_make_data(findings=[f]))
    assert len(out.kev_listed_findings) == 1
    kev_row = out.kev_listed_findings[0]
    assert kev_row.rank == 1
    assert kev_row.title == "KEV-tracked vuln"
    assert kev_row.kev_added_date == "2024-01-15"
    assert kev_row.owasp_category == "A10"
    assert out.top_findings_by_business_impact[0].kev_listed is True

    ctx = valhalla_assembly_to_jinja_context(out)
    slot = ctx["valhalla_executive_report"]["kev_listed_findings"]
    assert isinstance(slot, list) and len(slot) == 1
    assert slot[0]["rank"] == 1
    assert slot[0]["asset"] == "api.acme.example.com"
    assert slot[0]["kev_added_date"] == "2024-01-15"
    assert slot[0]["owasp_category"] == "A10"
    assert slot[0]["epss_percentile"] == 0.99
    assert slot[0]["ssvc_decision"] == "Act"


def test_jinja_executive_report_owasp_matrix_matches_assembly_for_pdf() -> None:
    """RPT-002 — OWASP rollup in context must mirror assembly (PDF uses same dict)."""
    out = assemble_valhalla_sections(
        _make_data(findings=[_finding(cwe="CWE-79", owasp=None, severity="high")])
    )
    ctx = valhalla_assembly_to_jinja_context(out)
    matrix = ctx["valhalla_executive_report"]["owasp_rollup_matrix"]
    assert isinstance(matrix, list)
    assert len(matrix) == len(out.owasp_rollup_matrix)
    a05 = next(r for r in matrix if r["category_id"] == "A05")
    assert a05["high"] == 1


def test_jinja_projector_layers_on_top_of_base_context() -> None:
    out = assemble_valhalla_sections(_make_data())
    base = {"existing_key": "preserved", "tier": "midgard"}  # tier should be overridden
    ctx = valhalla_assembly_to_jinja_context(out, base_context=base)
    assert ctx["existing_key"] == "preserved"
    assert ctx["tier"] == "valhalla"


def test_pydantic_row_models_are_frozen() -> None:
    """Every section row must be immutable — assigning to a known field raises."""
    a = AssetRiskRow(
        asset="x",
        finding_count=1,
        max_cvss=1.0,
        business_value=1.0,
        exploitability_factor=1.0,
        composite_score=1.0,
        top_severity="info",
    )
    o = OwaspRollupRow(
        category_id="A01",
        title="t",
        critical=0,
        high=0,
        medium=0,
        low=0,
        info=0,
        total=0,
    )
    b = BusinessImpactFindingRow(
        rank=1,
        severity="info",
        title="x",
        description="x",
        cwe=None,
        cvss=None,
        owasp_category="A01",
        business_value=1.0,
        exploitability_factor=1.0,
        composite_score=1.0,
        asset="x",
    )
    r = RemediationPhaseRow(
        phase_id="P0",
        sla_days=7,
        severity_bucket="critical",
        finding_count=0,
        top_finding_titles=(),
    )
    e = ValhallaEvidenceRef(
        finding_id="f", object_key="k", description=None, presigned_url=None
    )
    t = ValhallaTimelineEntry(order_index=0, phase="x", snippet="", created_at=None)
    cases = [
        (a, "asset"),
        (o, "category_id"),
        (b, "rank"),
        (r, "phase_id"),
        (e, "finding_id"),
        (t, "order_index"),
    ]
    for model, attr in cases:
        with pytest.raises((TypeError, ValueError, AttributeError)):
            setattr(model, attr, "tampered")


# ---------------------------------------------------------------------------
# BusinessContext bounds (44-46)
# ---------------------------------------------------------------------------


def test_business_context_default_value_below_zero_rejected() -> None:
    with pytest.raises(Exception):  # pydantic ValidationError
        BusinessContext(default_business_value=-0.1)


def test_business_context_default_value_above_ten_rejected() -> None:
    with pytest.raises(Exception):  # pydantic ValidationError
        BusinessContext(default_business_value=10.1)


def test_business_context_extra_fields_rejected() -> None:
    with pytest.raises(Exception):  # pydantic ValidationError
        BusinessContext(default_business_value=1.0, unexpected="boom")  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# Confidence → exploitability factor (47-48)
# ---------------------------------------------------------------------------


def test_confirmed_confidence_yields_full_exploitability() -> None:
    f = _finding(
        severity="high",
        cvss=8.0,
        confidence="confirmed",
        poc={"url": "https://h.example/x"},
    )
    out = assemble_valhalla_sections(_make_data(findings=[f]))
    row = out.risk_quantification_per_asset[0]
    assert row.exploitability_factor == 1.0


def test_advisory_confidence_yields_quartered_exploitability() -> None:
    f = _finding(
        severity="high",
        cvss=8.0,
        confidence="advisory",
        poc={"url": "https://h.example/x"},
    )
    out = assemble_valhalla_sections(_make_data(findings=[f]))
    row = out.risk_quantification_per_asset[0]
    assert row.exploitability_factor == 0.25
    # composite = 8.0 * 1.0 (default bv) * 0.25 = 2.0
    assert row.composite_score == pytest.approx(2.0)
