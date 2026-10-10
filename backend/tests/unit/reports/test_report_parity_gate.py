"""Phase 3 — the declarative parity gate + render-policy machinery (spec RC-13).

These assert the *mechanism* (it detects an omission, it reads the render policy, the
coverage script is wired) and are stable across phases. The exhaustive completeness
assertions live in ``test_report_field_coverage.py`` /
``test_render_parity_full_document.py``.
"""

from __future__ import annotations

from pydantic import BaseModel, Field
from src.reports.renderers import render_html, render_json, render_markdown, render_xml
from src.reports.report_content_parity import content_parity_blockers
from src.reports.report_document import (
    ReportFinding,
    build_report_document,
    field_render_policy,
)


def _canon(doc) -> dict[str, bytes]:
    return {
        "json": render_json(doc).encode(),
        "md": render_markdown(doc).encode(),
        "xml": render_xml(doc).encode(),
        "html": render_html(doc).encode(),
    }


def test_parity_gate_detects_doctored_omission():
    """A rendered value removed from one format must be reported with model.field + format."""
    doc = build_report_document(
        scan_id="s",
        tenant_id="t",
        target="https://t",
        findings=[ReportFinding(finding_id="F-1", title="x", severity="high")],
    )
    canon = _canon(doc)
    canon["md"] = canon["md"].replace(b"F-1", b"XXX")  # drop the finding id from Markdown
    blockers = content_parity_blockers(canon, doc=doc)
    assert any(
        "ReportFinding.finding_id" in b and "md" in b for b in blockers
    ), blockers


def test_parity_gate_backward_compatible_without_doc():
    """Without ``doc`` the gate runs only the structural checks (no per-field blockers)."""
    doc = build_report_document(
        scan_id="s",
        tenant_id="t",
        target="https://t",
        findings=[ReportFinding(finding_id="F-1", title="x", severity="high")],
    )
    blockers = content_parity_blockers(_canon(doc))
    assert not any(b.startswith("parity: Report") for b in blockers), blockers


def test_field_render_policy_defaults_to_all():
    assert field_render_policy(ReportFinding, "parameter") == "all"
    assert field_render_policy(ReportFinding, "finding_id") == "all"


def test_field_render_policy_reads_json_only():
    class _M(BaseModel):
        a: str = Field(default="x")
        b: str = Field(default="y", json_schema_extra={"render": "json_only"})

    assert field_render_policy(_M, "a") == "all"
    assert field_render_policy(_M, "b") == "json_only"


def test_coverage_script_is_wired():
    import importlib.util
    from pathlib import Path

    script = Path(__file__).resolve().parents[3] / "scripts" / "report_field_coverage.py"
    spec = importlib.util.spec_from_file_location("report_field_coverage", script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    rows = mod.missing_fields()
    assert isinstance(rows, list)
    assert all(isinstance(r, str) and ": NOT in " in r for r in rows)
