"""Report-formats hardening regression suite.

Locks the invariants introduced by the MD/JSON/PDF/HTML/CSV hardening pass:

* a stable ``finding_id`` is carried into the ``Finding`` schema and surfaces in
  every export format (no ``NOT_ASSESSED`` / ``finding_without_id``);
* a single headline severity counter (provable-only for Valhalla) drives prose,
  tables and the cross-format gate;
* JSON/MD/HTML never dump raw phase bodies (no internal-address / secret leak,
  no multi-MB bloat) and the internal ``cost_summary`` billing section is dropped
  from every customer-facing format;
* the cross-format validator actually compares the numbers between formats.
"""

from __future__ import annotations

import csv
import io
import json

from src.api.schemas import Finding, ReportSummary
from src.reports.data_collector import headline_findings, headline_severity_totals
from src.reports.generators import (
    PhaseOutputEntry,
    ReportData,
    TimelineEntry,
    _verify_cross_format,
    finding_id_of,
    generate_csv,
    generate_export_validation_report,
    generate_json,
    generate_markdown,
)


def _finding(
    *,
    finding_id: str,
    severity: str = "high",
    title: str = "Reflected XSS",
    is_provable: bool = True,
    evidence_classification: str = "validated",
) -> Finding:
    return Finding(
        finding_id=finding_id,
        severity=severity,
        title=title,
        description="desc",
        cwe="CWE-79",
        cvss=6.1,
        cvss_score=6.1,
        confidence="confirmed",
        evidence_classification=evidence_classification,  # type: ignore[arg-type]
        is_provable=is_provable,
        evidence_refs=["minio://artifacts/scan/req-1.txt"],
    )


def _report(findings: list[Finding], **kw: object) -> ReportData:
    return ReportData(
        report_id="r-1",
        target="https://victim.example.com",
        summary=ReportSummary(high=len(findings)),
        findings=findings,
        technologies=["nginx"],
        scan_id="scan-1",
        tenant_id="tenant-1",
        created_at="2026-04-19T12:00:00Z",
        **kw,  # type: ignore[arg-type]
    )


# --------------------------------------------------------------------------- #
# A1 — finding_id propagation                                                  #
# --------------------------------------------------------------------------- #


class TestFindingIdHelper:
    def test_reads_dict_id(self) -> None:
        assert finding_id_of({"id": "abc"}) == "abc"
        assert finding_id_of({"finding_id": "xyz"}) == "xyz"

    def test_reads_object_attrs(self) -> None:
        assert finding_id_of(_finding(finding_id="fid-1")) == "fid-1"

    def test_empty_when_absent(self) -> None:
        assert finding_id_of({}) == ""
        assert finding_id_of(_finding(finding_id="")) == ""

    def test_schema_carries_finding_id(self) -> None:
        f = _finding(finding_id="fid-9")
        assert f.model_dump()["finding_id"] == "fid-9"


class TestCsvFindingId:
    def test_findings_csv_has_real_finding_id(self) -> None:
        blob = generate_csv(_report([_finding(finding_id="fid-42")])).decode("utf-8")
        assert "fid-42" in blob
        # The data row's finding_id column must be the real id, not the sentinel.
        rows = list(csv.reader(io.StringIO(blob)))
        header_idx = next(i for i, r in enumerate(rows) if r and r[0] == "report_id")
        data_row = rows[header_idx + 1]
        assert data_row[3] == "fid-42"


# --------------------------------------------------------------------------- #
# A2 — single headline severity counter                                        #
# --------------------------------------------------------------------------- #


class TestHeadlineCounts:
    def test_valhalla_counts_provable_only(self) -> None:
        findings = [
            _finding(finding_id="a", severity="high", is_provable=True),
            _finding(finding_id="b", severity="critical", is_provable=False),
        ]
        totals = headline_severity_totals(findings, "valhalla")
        assert totals["high"] == 1
        assert totals["critical"] == 0
        assert len(headline_findings(findings, "valhalla")) == 1

    def test_other_tiers_count_everything(self) -> None:
        findings = [
            _finding(finding_id="a", severity="high", is_provable=True),
            _finding(finding_id="b", severity="critical", is_provable=False),
        ]
        totals = headline_severity_totals(findings, "midgard")
        assert totals["high"] == 1
        assert totals["critical"] == 1


# --------------------------------------------------------------------------- #
# B — JSON projection + cost_summary                                           #
# --------------------------------------------------------------------------- #


class TestJsonProjection:
    def _payload(self) -> dict[str, object]:
        rd = _report(
            [_finding(finding_id="fid-1")],
            phase_outputs=[
                PhaseOutputEntry(
                    phase="recon",
                    output_data={
                        "phase": "recon",
                        "duration_seconds": 12.5,
                        "output": {
                            "summary": "completed recon",
                            "internal_probe": "169.254.169.254",
                            "secret": "AKIAIOSFODNN7EXAMPLE",
                            "hosts": [1, 2, 3],
                        },
                    },
                )
            ],
            timeline=[
                TimelineEntry(
                    phase="recon",
                    order_index=0,
                    entry={
                        "phase": "recon",
                        "duration_seconds": 12.5,
                        "output": {"summary": "completed recon", "hosts": [1, 2, 3]},
                    },
                    created_at="2026-04-19T12:00:00Z",
                )
            ],
        )
        return json.loads(generate_json(rd).decode("utf-8"))

    def test_phase_outputs_are_projected_not_raw(self) -> None:
        out = self._payload()
        po = out["phase_outputs"]
        assert isinstance(po, list) and po
        entry = po[0]
        assert "output_data" not in entry
        assert entry["phase"] == "recon"
        assert "output_summary" in entry

    def test_phase_projection_drops_internal_and_secret_scalars(self) -> None:
        out = self._payload()
        blob = json.dumps(out)
        assert "169.254.169.254" not in blob
        assert "AKIAIOSFODNN7EXAMPLE" not in blob
        summary = out["phase_outputs"][0]["output_summary"]
        assert summary["summary"] == "completed recon"
        assert summary["hosts_count"] == 3

    def test_timeline_is_projected(self) -> None:
        out = self._payload()
        tl = out["timeline"][0]
        assert tl["entry"]["output_summary"]["hosts_count"] == 3


class TestCostSummaryExcluded:
    """cost_summary is internal LLM billing/telemetry (tokens, USD, provider, tenant_id)
    and must never appear in any customer-facing export."""

    def test_json_export_drops_cost_summary(self) -> None:
        rd = _report([_finding(finding_id="fid-1")])
        ctx = {
            "ai_sections": {
                "cost_summary": json.dumps(
                    {"total_cost_usd": 4.2, "tenant_id": "t-secret", "by_provider": {}}
                ),
                "business_risk": "Account takeover is feasible.",
            },
        }
        blob = generate_json(rd, jinja_context=ctx)
        out = json.loads(blob.decode("utf-8"))
        assert "cost_summary" not in out.get("ai_sections", {})
        assert b"cost_summary" not in blob
        assert b"total_cost_usd" not in blob
        assert b"t-secret" not in blob


# --------------------------------------------------------------------------- #
# C — CSV sections / bloat                                                      #
# --------------------------------------------------------------------------- #


class TestCsvSections:
    def test_csv_excludes_internal_cost_summary(self) -> None:
        ctx = {
            "ai_sections": {
                "cost_summary": json.dumps(
                    {"total_cost_usd": 9.9, "tenant_id": "t-secret", "blob": "y" * 200000}
                )
            },
        }
        blob = generate_csv(_report([_finding(finding_id="fid-1")]), jinja_context=ctx)
        # Internal billing section is dropped, so it can never bloat the file.
        assert len(blob) < 50_000
        assert b"cost_summary" not in blob
        assert b"total_cost_usd" not in blob
        assert b"t-secret" not in blob


# --------------------------------------------------------------------------- #
# D — Markdown                                                                  #
# --------------------------------------------------------------------------- #


class TestMarkdown:
    def test_timeline_is_human_readable(self) -> None:
        rd = _report(
            [_finding(finding_id="fid-1")],
            timeline=[
                TimelineEntry(
                    phase="recon",
                    order_index=0,
                    entry={
                        "phase": "recon",
                        "duration_seconds": 5,
                        "output": {
                            "summary": "done",
                            "secret": "AKIAIOSFODNN7EXAMPLE",
                            "hosts": [1, 2],
                        },
                    },
                    created_at="2026-04-19T12:00:00Z",
                )
            ],
        )
        md = generate_markdown(rd).decode("utf-8")
        assert "**[recon]**" in md
        assert "(5s)" in md
        assert "hosts=2" in md
        # No raw JSON dump of the phase body, no leaked secret.
        assert "AKIAIOSFODNN7EXAMPLE" not in md
        assert '"output":' not in md

    def test_ai_cost_summary_not_in_prose(self) -> None:
        rd = _report([_finding(finding_id="fid-1")])
        ctx = {
            "ai_sections": {
                "cost_summary": json.dumps(
                    {"total_cost_usd": 1.0, "tenant_id": "t-secret"}
                ),
                "business_risk": "Account takeover is feasible via the login endpoint.",
            }
        }
        md = generate_markdown(rd, jinja_context=ctx).decode("utf-8")
        assert "Business Risk" in md
        assert "Account takeover" in md
        # cost_summary is internal billing data, never rendered anywhere.
        assert "total_cost_usd" not in md
        assert "t-secret" not in md


# --------------------------------------------------------------------------- #
# F — cross-format gate                                                         #
# --------------------------------------------------------------------------- #


class TestCrossFormatGate:
    def test_consistent_when_totals_match(self) -> None:
        findings = [_finding(finding_id="a", severity="high")]
        ok, issues = _verify_cross_format(
            findings,
            "r-1",
            "https://t",
            "scan-1",
            expected_severity_totals={"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            expected_finding_count=1,
            tier="valhalla",
        )
        assert ok, issues

    def test_flags_severity_mismatch(self) -> None:
        findings = [_finding(finding_id="a", severity="high")]
        ok, issues = _verify_cross_format(
            findings,
            "r-1",
            "https://t",
            "scan-1",
            expected_severity_totals={"critical": 5, "high": 0, "medium": 0, "low": 0, "info": 0},
            tier="valhalla",
        )
        assert not ok
        assert any("severity_totals_mismatch" in i for i in issues)

    def test_flags_missing_finding_id(self) -> None:
        ok, issues = _verify_cross_format(
            [_finding(finding_id="")], "r-1", "https://t", "scan-1"
        )
        assert not ok
        assert "finding_without_id" in issues

    def test_export_validation_report_consistent(self) -> None:
        rd = _report([_finding(finding_id="a", severity="high")])
        ctx = {
            "severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            "findings_count": 1,
        }
        report = json.loads(
            generate_export_validation_report(rd, jinja_context=ctx).decode("utf-8")
        )
        assert report["validation"]["cross_format_consistent"] is True
        assert "finding_without_id" not in report["validation"]["issues"]


# --------------------------------------------------------------------------- #
# G — timeline preview snippet leak-safety                                     #
# --------------------------------------------------------------------------- #


class TestTimelineSnippetLeakSafe:
    """Regression: ``recon_summary.timeline_preview[].snippet`` used to be the raw
    ``str(entry)`` body and leaked internal addresses/secrets into the JSON appendices."""

    def _leaky_report(self) -> ReportData:
        leaky_entry = {
            "phase": "recon",
            "duration_seconds": 12.5,
            "output": {
                "summary": "recon complete",
                "internal_probe": "169.254.169.254",
                "aws_key": "AKIAIOSFODNN7EXAMPLE",
                "hosts": [1, 2, 3],
            },
        }
        return _report(
            [_finding(finding_id="fid-1")],
            timeline=[
                TimelineEntry(
                    phase="recon",
                    order_index=0,
                    entry=leaky_entry,
                    created_at="2026-04-19T12:00:00Z",
                )
            ],
        )

    def test_safe_phase_summary_text_drops_internal_scalars(self) -> None:
        from src.reports.generators import safe_phase_summary_text

        text = safe_phase_summary_text(
            {
                "output": {
                    "summary": "recon complete",
                    "internal_probe": "169.254.169.254",
                    "aws_key": "AKIAIOSFODNN7EXAMPLE",
                    "hosts": [1, 2, 3],
                }
            }
        )
        assert "recon complete" in text
        assert "hosts=3" in text
        assert "169.254.169.254" not in text
        assert "AKIAIOSFODNN7EXAMPLE" not in text

    def test_offline_context_timeline_preview_is_leak_safe(self) -> None:
        from src.reports.jinja_minimal_context import (
            offline_minimal_jinja_context_from_report_data,
        )

        ctx = offline_minimal_jinja_context_from_report_data(
            self._leaky_report(), "valhalla"
        )
        blob = json.dumps(ctx)
        assert "169.254.169.254" not in blob
        assert "AKIAIOSFODNN7EXAMPLE" not in blob
        # cost_summary billing must not reach the Jinja ai_sections either.
        assert "cost_summary" not in ctx.get("ai_sections", {})

    def test_valhalla_json_appendices_have_no_internal_leak(self) -> None:
        from src.reports.jinja_minimal_context import (
            offline_minimal_jinja_context_from_report_data,
        )

        rd = self._leaky_report()
        ctx = offline_minimal_jinja_context_from_report_data(rd, "valhalla")
        blob = generate_json(rd, jinja_context=ctx)
        assert b"169.254.169.254" not in blob
        assert b"AKIAIOSFODNN7EXAMPLE" not in blob
        assert b"cost_summary" not in blob
