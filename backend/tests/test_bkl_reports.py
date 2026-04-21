"""BKL-003: Report template validation.

Tests:
- Valhalla templates contain zero Russian (Cyrillic) text
- cost_summary partial exists and renders
- sections_10_12 does NOT reference executive_summary_valhalla
- Jinja template rendering doesn't crash with empty context
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ARGUS_ROOT = Path(__file__).resolve().parent.parent.parent
VALHALLA_PARTIALS_DIR = (
    ARGUS_ROOT
    / "backend"
    / "src"
    / "reports"
    / "templates"
    / "reports"
    / "partials"
    / "valhalla"
)

CYRILLIC_RE = re.compile(r"[\u0400-\u04FF]")


@pytest.fixture(scope="module")
def valhalla_templates() -> dict[str, str]:
    """Load all Valhalla Jinja2 partials."""
    templates: dict[str, str] = {}
    for p in VALHALLA_PARTIALS_DIR.glob("*.j2"):
        templates[p.name] = p.read_text(encoding="utf-8")
    return templates


class TestValhallaTemplatesNoCyrillic:
    """BKL-003: All Valhalla templates must be English-only (no Cyrillic text)."""

    def test_partials_dir_exists(self) -> None:
        assert VALHALLA_PARTIALS_DIR.exists(), (
            f"Valhalla partials dir not found: {VALHALLA_PARTIALS_DIR}"
        )

    def test_at_least_one_template(self, valhalla_templates: dict[str, str]) -> None:
        assert len(valhalla_templates) > 0, "Must have at least one Valhalla template"

    @pytest.mark.parametrize(
        "template_name",
        [
            "sections_01_02_title_executive.html.j2",
            "sections_03_05_objectives_methodology.html.j2",
            "section_06_results_overview.html.j2",
            "sections_07_08_threat_findings.html.j2",
            "section_09_exploit_chains.html.j2",
            "sections_10_12_remediation_conclusion.html.j2",
            "appendices.html.j2",
            "section_cost_summary.html.j2",
            "finding_evidence_block.html.j2",
            "findings_table.html.j2",
            "section_data_coverage.html.j2",
            "section_status_macro.html.j2",
        ],
    )
    def test_template_no_cyrillic(
        self, valhalla_templates: dict[str, str], template_name: str,
    ) -> None:
        if template_name not in valhalla_templates:
            pytest.skip(f"Template {template_name} not found")
        content = valhalla_templates[template_name]
        matches = CYRILLIC_RE.findall(content)
        assert not matches, (
            f"Template {template_name} contains Cyrillic characters: "
            f"{''.join(matches[:20])!r}"
        )


class TestCostSummaryPartial:
    """BKL-003: section_cost_summary partial must exist and contain expected structure."""

    def test_cost_summary_exists(self) -> None:
        path = VALHALLA_PARTIALS_DIR / "section_cost_summary.html.j2"
        assert path.exists(), "section_cost_summary.html.j2 must exist"

    def test_cost_summary_contains_section_tag(self) -> None:
        path = VALHALLA_PARTIALS_DIR / "section_cost_summary.html.j2"
        content = path.read_text(encoding="utf-8")
        assert "<section" in content
        assert "cost-summary" in content

    def test_cost_summary_references_ai_sections(self) -> None:
        path = VALHALLA_PARTIALS_DIR / "section_cost_summary.html.j2"
        content = path.read_text(encoding="utf-8")
        assert "ai_sections" in content
        assert "cost_summary" in content


class TestSections1012NoExecSummaryValhalla:
    """BKL-003: sections_10_12 must NOT contain executive_summary_valhalla key reference."""

    def test_no_executive_summary_valhalla_ref(self) -> None:
        path = VALHALLA_PARTIALS_DIR / "sections_10_12_remediation_conclusion.html.j2"
        content = path.read_text(encoding="utf-8")
        assert "executive_summary_valhalla" not in content, (
            "sections_10_12 must NOT reference executive_summary_valhalla "
            "(dedup: only in sections_01_02)"
        )


class TestJinjaTemplateRenderEmptyContext:
    """BKL-003: Templates must not crash when rendered with minimal empty context."""

    def test_cost_summary_renders_empty(self) -> None:
        from jinja2 import Environment, FileSystemLoader

        env = Environment(
            loader=FileSystemLoader(str(VALHALLA_PARTIALS_DIR)),
            autoescape=True,
        )
        env.filters["md"] = lambda text: text
        template = env.get_template("section_cost_summary.html.j2")
        result = template.render(ai_sections={}, findings=[])
        assert "cost-summary" in result

    def test_sections_10_12_renders_empty(self) -> None:
        from jinja2 import Environment, FileSystemLoader

        env = Environment(
            loader=FileSystemLoader(str(VALHALLA_PARTIALS_DIR)),
            autoescape=True,
        )
        env.filters["md"] = lambda text: text
        template = env.get_template("sections_10_12_remediation_conclusion.html.j2")
        result = template.render(ai_sections={}, findings=[])
        assert "remediation-priority" in result
        assert "conclusion" in result
