"""ARG-025 — Unit tests for ``src.reports.asgard_tier_renderer``.

Coverage requirements (plan §3 ARG-025):

* section ordering
* presigned URLs invoked through callback
* sanitiser applied to reproducer commands
* remediation block present even with empty PoC
* deterministic ordering by severity
* graceful handling of missing data
* presigner exception → ``None`` (no crash)
* canary preservation through full assembly
* JSON-serialisable output (round-trip via ``model_dump_json``)
* OWASP rollup A01..A10 ordering preserved
"""

from __future__ import annotations

import json

from src.api.schemas import Finding, ReportSummary
from src.reports.asgard_tier_renderer import (
    ASGARD_SECTION_ORDER,
    AsgardSectionAssembly,
    asgard_assembly_to_jinja_context,
    assemble_asgard_sections,
)
from src.reports.generators import (
    EvidenceEntry,
    ReportData,
    ScreenshotEntry,
    TimelineEntry,
)
from src.reports.replay_command_sanitizer import (
    PLACEHOLDER_ASSET,
    PLACEHOLDER_ENDPOINT,
    REDACTED_BEARER,
    SanitizeContext,
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
    owasp: str = "A05",
    poc: dict[str, object] | None = None,
    repro_steps: str | None = None,
    notes: str | None = None,
) -> Finding:
    return Finding(
        severity=severity,
        title=title,
        description=f"{title} - synthetic test finding.",
        cwe=cwe,
        cvss=cvss,
        owasp_category=owasp,  # type: ignore[arg-type]
        proof_of_concept=poc,
        confidence="confirmed",
        evidence_type="tool_output",
        reproducible_steps=repro_steps,
        applicability_notes=notes,
    )


def _make_data(
    *,
    findings: list[Finding] | None = None,
    timeline: list[TimelineEntry] | None = None,
    evidence: list[EvidenceEntry] | None = None,
    screenshots: list[ScreenshotEntry] | None = None,
    target: str = "https://acme.example.com",
) -> ReportData:
    return ReportData(
        report_id="rep-001",
        target=target,
        summary=ReportSummary(critical=0, high=1, medium=0, low=0, info=0),
        findings=findings or [_finding()],
        technologies=["nginx", "django"],
        created_at="2026-04-19T12:00:00Z",
        scan_id="scan-001",
        tenant_id="tenant-default",
        timeline=timeline or [],
        evidence=evidence or [],
        screenshots=screenshots or [],
    )


# ---------------------------------------------------------------------------
# Section ordering & shape
# ---------------------------------------------------------------------------


def test_assembly_returns_pydantic_model() -> None:
    out = assemble_asgard_sections(_make_data())
    assert isinstance(out, AsgardSectionAssembly)


def test_section_order_constant_is_complete_and_immutable() -> None:
    expected = (
        "title_meta",
        "executive_summary_counts",
        "owasp_compliance",
        "findings",
        "remediation",
        "reproducer",
        "timeline",
        "evidence",
        "screenshots",
    )
    assert ASGARD_SECTION_ORDER == expected
    assert isinstance(ASGARD_SECTION_ORDER, tuple)


def test_assembly_serialises_to_json_round_trip() -> None:
    out = assemble_asgard_sections(_make_data())
    blob = out.model_dump_json()
    parsed = json.loads(blob)
    for section in ASGARD_SECTION_ORDER:
        assert section in parsed


def test_title_meta_contains_required_keys() -> None:
    out = assemble_asgard_sections(_make_data())
    for k in ("report_id", "target", "scan_id", "tenant_id", "tier", "created_at"):
        assert k in out.title_meta
    assert out.title_meta["tier"] == "asgard"


# ---------------------------------------------------------------------------
# Findings ordering by severity
# ---------------------------------------------------------------------------


def test_findings_ordered_by_severity_then_cvss() -> None:
    data = _make_data(
        findings=[
            _finding(severity="low", title="Z low", cvss=3.0, owasp="A05"),
            _finding(severity="critical", title="A crit", cvss=9.8, owasp="A01"),
            _finding(severity="high", title="B high", cvss=8.0, owasp="A03"),
            _finding(severity="high", title="A high", cvss=8.2, owasp="A03"),
        ]
    )
    out = assemble_asgard_sections(data)
    titles = [f.title for f in out.findings]
    assert titles[0] == "A crit"
    assert titles[1].startswith("A high")  # higher CVSS wins
    assert titles[2].startswith("B high")
    assert titles[-1] == "Z low"


def test_executive_counts_match_findings() -> None:
    data = _make_data(
        findings=[
            _finding(severity="critical"),
            _finding(severity="critical"),
            _finding(severity="medium"),
            _finding(severity="info"),
        ]
    )
    out = assemble_asgard_sections(data)
    assert out.executive_summary_counts["critical"] == 2
    assert out.executive_summary_counts["medium"] == 1
    assert out.executive_summary_counts["info"] == 1


# ---------------------------------------------------------------------------
# Reproducer / sanitiser integration
# ---------------------------------------------------------------------------


def test_reproducer_sanitises_bearer_token() -> None:
    data = _make_data(
        findings=[
            _finding(
                poc={
                    "replay_command": [
                        "curl",
                        "-H",
                        "Authorization: Bearer eyJabc123def456ghi",
                        "https://acme.example.com/api/v1/users",
                    ]
                }
            )
        ]
    )
    out = assemble_asgard_sections(
        data,
        sanitize_context=SanitizeContext(
            target="https://acme.example.com",
            endpoints=("https://acme.example.com/api/v1/users",),
        ),
    )
    assert out.reproducer, "reproducer section must be populated"
    cmd = " ".join(out.reproducer[0].command)
    assert "eyJabc123def456ghi" not in cmd
    assert REDACTED_BEARER in cmd or "[REDACTED" in cmd
    assert PLACEHOLDER_ENDPOINT in cmd or PLACEHOLDER_ASSET in cmd


def test_reproducer_falls_back_to_string_form() -> None:
    data = _make_data(
        findings=[
            _finding(
                poc={"reproducer": "curl https://acme.example.com/admin"},
            )
        ]
    )
    out = assemble_asgard_sections(
        data,
        sanitize_context=SanitizeContext(target="https://acme.example.com"),
    )
    assert out.reproducer
    cmd = " ".join(out.reproducer[0].command)
    assert "acme.example.com" not in cmd


def test_reproducer_falls_back_to_repro_steps() -> None:
    data = _make_data(
        findings=[_finding(poc=None, repro_steps="nikto -h https://victim.tld")]
    )
    out = assemble_asgard_sections(
        data,
        sanitize_context=SanitizeContext(target="https://victim.tld"),
    )
    assert out.reproducer
    cmd = " ".join(out.reproducer[0].command)
    assert "victim.tld" not in cmd


def test_reproducer_omits_findings_without_poc_or_steps() -> None:
    data = _make_data(findings=[_finding(poc=None, repro_steps=None)])
    out = assemble_asgard_sections(data)
    assert out.reproducer == []


# ---------------------------------------------------------------------------
# Remediation
# ---------------------------------------------------------------------------


def test_remediation_present_for_every_finding() -> None:
    data = _make_data(
        findings=[
            _finding(severity="high", notes="Apply patch v2.4.7."),
            _finding(
                severity="medium",
                notes=None,
                poc={"remediation": "Disable feature flag X."},
            ),
            _finding(severity="low", notes=None, poc=None),
        ]
    )
    out = assemble_asgard_sections(data)
    assert len(out.remediation) == 3
    guidance = [r.guidance for r in out.remediation]
    assert "Apply patch v2.4.7." in guidance
    assert "Disable feature flag X." in guidance
    assert any("vendor-provided patches" in g for g in guidance)


# ---------------------------------------------------------------------------
# Evidence + screenshots + presigner
# ---------------------------------------------------------------------------


def test_evidence_invokes_presigner_and_returns_url() -> None:
    data = _make_data(
        evidence=[
            EvidenceEntry(
                finding_id="f1", object_key="obj/key/a.png", description="screenshot"
            ),
            EvidenceEntry(
                finding_id="f2", object_key="obj/key/b.txt", description=None
            ),
        ]
    )
    seen: list[str] = []

    def presigner(key: str) -> str | None:
        seen.append(key)
        return f"https://signed.example/{key}?sig=xyz"

    out = assemble_asgard_sections(data, presigner=presigner)
    assert {"obj/key/a.png", "obj/key/b.txt"} == set(seen)
    assert all(
        e.presigned_url and e.presigned_url.startswith("https://signed.example/")
        for e in out.evidence
    )


def test_evidence_handles_presigner_exception_gracefully() -> None:
    data = _make_data(
        evidence=[
            EvidenceEntry(finding_id="f1", object_key="obj/key/a.png", description=None)
        ]
    )

    def boom(_: str) -> str | None:
        raise RuntimeError("S3 down")

    out = assemble_asgard_sections(data, presigner=boom)
    assert out.evidence[0].presigned_url is None


def test_screenshots_invoke_presigner() -> None:
    data = _make_data(
        screenshots=[
            ScreenshotEntry(
                object_key="ss/login.png", url_or_email="https://target/login"
            ),
        ]
    )

    def presigner(key: str) -> str | None:
        return f"s3://bucket/{key}?sig=ok"

    out = assemble_asgard_sections(data, presigner=presigner)
    assert out.screenshots[0].presigned_url == "s3://bucket/ss/login.png?sig=ok"


def test_evidence_no_presigner_returns_none_url() -> None:
    data = _make_data(
        evidence=[
            EvidenceEntry(finding_id="f1", object_key="obj.png", description=None)
        ]
    )
    out = assemble_asgard_sections(data)
    assert out.evidence[0].presigned_url is None


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------


def test_timeline_sorted_and_truncated() -> None:
    data = _make_data(
        timeline=[
            TimelineEntry(
                phase="exploit",
                order_index=2,
                entry={"k": "v" * 1000},
                created_at="2026-04-19T12:30:00Z",
            ),
            TimelineEntry(
                phase="recon",
                order_index=1,
                entry={"hosts": ["a", "b"]},
                created_at="2026-04-19T12:00:00Z",
            ),
        ]
    )
    out = assemble_asgard_sections(data)
    assert [t.order_index for t in out.timeline] == [1, 2]
    assert all(len(t.snippet) <= 480 for t in out.timeline)


# ---------------------------------------------------------------------------
# OWASP rollup
# ---------------------------------------------------------------------------


def test_owasp_rollup_returns_full_a01_to_a10() -> None:
    data = _make_data(
        findings=[
            _finding(severity="critical", owasp="A01"),
            _finding(severity="high", owasp="A03"),
            _finding(severity="high", owasp="A03"),
        ]
    )
    out = assemble_asgard_sections(data)
    rows = out.owasp_compliance
    assert len(rows) == 10
    assert [r["category_id"] for r in rows] == [
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
    ]
    by_id = {r["category_id"]: r for r in rows}
    assert by_id["A01"]["count"] == 1
    assert by_id["A03"]["count"] == 2
    assert by_id["A02"]["count"] == 0
    assert by_id["A03"]["has_findings"] is True
    assert by_id["A02"]["has_findings"] is False


# ---------------------------------------------------------------------------
# jinja context projection
# ---------------------------------------------------------------------------


def test_jinja_context_overlays_asgard_report_and_tier() -> None:
    out = assemble_asgard_sections(_make_data())
    ctx = asgard_assembly_to_jinja_context(out, base_context={"existing": True})
    assert ctx["existing"] is True
    assert ctx["tier"] == "asgard"
    assert "asgard_report" in ctx
    assert ctx["asgard_report"]["title_meta"]["tier"] == "asgard"


def test_jinja_context_handles_no_base_context() -> None:
    out = assemble_asgard_sections(_make_data())
    ctx = asgard_assembly_to_jinja_context(out)
    assert ctx["tier"] == "asgard"
    assert "asgard_report" in ctx


# ---------------------------------------------------------------------------
# Canary preservation through full pipeline
# ---------------------------------------------------------------------------


def test_canary_preserved_in_reproducer_section() -> None:
    data = _make_data(
        findings=[
            _finding(
                poc={
                    "replay_command": [
                        "echo",
                        "https://acme.example.com/CANARY-PROBE-42",
                    ]
                }
            )
        ]
    )
    out = assemble_asgard_sections(
        data,
        sanitize_context=SanitizeContext(
            target="https://acme.example.com",
            canaries=("CANARY-PROBE-42",),
        ),
    )
    cmd = " ".join(out.reproducer[0].command)
    assert "CANARY-PROBE-42" in cmd


# ---------------------------------------------------------------------------
# Empty data
# ---------------------------------------------------------------------------


def test_assembly_for_empty_data_does_not_crash() -> None:
    data = ReportData(
        report_id="rep-empty",
        target="",
        summary=ReportSummary(),
        findings=[],
        technologies=[],
    )
    out = assemble_asgard_sections(data)
    assert out.findings == []
    assert out.reproducer == []
    assert out.evidence == []
    assert out.screenshots == []
    assert sum(out.executive_summary_counts.values()) == 0
