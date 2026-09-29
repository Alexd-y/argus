"""Ordered section registry (Phase C) — one section order for all four formats.

A single ordered list of sections defines the content and order of the Valhalla
report for JSON / Markdown / XML / HTML. Renderers walk the registry in full: a
section with no data renders with an explicit *status and reason*, never a silent
omission (prompt §5.2). This is the structural guarantee behind four-format parity.

Pure module: it only inspects a :class:`ReportDocumentV1` and reports, per section,
whether data is present and a short status note. Renderers own the formatting.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from src.reports.report_document import ReportDocumentV1


@dataclass(frozen=True)
class SectionSpec:
    """One report section: stable id, human title, and a presence predicate."""

    section_id: str
    title: str
    present: Callable[[ReportDocumentV1], bool]
    #: Status note when the section is empty (why there is no data).
    empty_status: str = "not_assessed"


def _has(seq) -> bool:
    return bool(seq)


#: The canonical, ordered Valhalla section list. Order is contractually stable;
#: appending is allowed, reordering/removing is a breaking change.
SECTION_ORDER: tuple[SectionSpec, ...] = (
    SectionSpec("passport", "Report Passport", lambda _d: True, "present"),
    SectionSpec(
        "executive_summary",
        "Executive Summary",
        lambda d: bool(d.conclusions and d.conclusions.executive_summary),
        "llm_not_generated",
    ),
    SectionSpec(
        "engagement", "Engagement Parameters", lambda d: d.engagement is not None, "not_recorded"
    ),
    SectionSpec("methodology", "Methodology", lambda d: _has(d.methodology), "not_recorded"),
    SectionSpec(
        "surface_inventory",
        "Attack Surface Inventory",
        lambda d: _has(d.surface_inventory),
        "not_assessed",
    ),
    SectionSpec(
        "priority_findings", "Priority Findings", lambda d: _has(d.findings), "no_findings"
    ),
    SectionSpec(
        "findings_by_asset", "Findings by Asset", lambda d: _has(d.findings), "no_findings"
    ),
    SectionSpec("findings", "Findings", lambda d: _has(d.findings), "no_findings"),
    SectionSpec(
        "unconfirmed_observations",
        "Unconfirmed Observations",
        lambda d: _has(d.unconfirmed_observations),
        "none",
    ),
    SectionSpec(
        "test_executions",
        "Executed Checks Without Findings",
        lambda d: _has(d.test_executions),
        "not_recorded",
    ),
    SectionSpec("attack_narrative", "Attack Narrative", lambda d: _has(d.attack_narrative), "none"),
    SectionSpec("exploit_chains", "Impact Chains", lambda d: _has(d.exploit_chains), "none_proven"),
    SectionSpec(
        "business_risk",
        "Business Risk",
        lambda d: bool(d.conclusions and d.conclusions.business_risk),
        "llm_not_generated",
    ),
    SectionSpec(
        "priority_plan",
        "Prioritised Remediation Plan",
        lambda d: bool(d.conclusions and d.conclusions.priority_plan),
        "llm_not_generated",
    ),
    SectionSpec(
        "retest_closure",
        "Retest & Closure",
        lambda d: any(f.closure is not None for f in d.findings),
        "not_retested",
    ),
    SectionSpec(
        "evidence_inventory",
        "Evidence Inventory",
        lambda d: _has(d.evidence_references),
        "no_evidence",
    ),
    SectionSpec("coverage", "Coverage", lambda d: _has(d.coverage), "not_assessed"),
    SectionSpec("wstg", "WSTG v4.2 Coverage", lambda d: d.wstg is not None, "disabled"),
    SectionSpec("tool_runs", "Execution Log", lambda d: _has(d.tool_runs), "not_assessed"),
    SectionSpec(
        "client_impact",
        "Impact on Client Environment",
        lambda d: d.client_impact is not None,
        "nothing_created",
    ),
    SectionSpec("limitations", "Limitations", lambda d: _has(d.limitations), "none"),
    SectionSpec("claims", "Claims Ledger", lambda d: _has(d.claims), "none"),
    SectionSpec(
        "appendix_all_findings",
        "Appendix A — All Findings",
        lambda d: _has(d.findings),
        "no_findings",
    ),
    SectionSpec(
        "appendix_assets", "Appendix B — Assets & Subdomains", lambda _d: True, "not_assessed"
    ),
    SectionSpec(
        "appendix_tool_runs",
        "Appendix C — Tool Runs & Artifacts",
        lambda d: _has(d.tool_runs),
        "not_assessed",
    ),
    SectionSpec(
        "appendix_verification_kit",
        "Appendix D — Independent Verification Kit",
        lambda d: bool(d.verification_kit_ref),
        "not_generated",
    ),
    SectionSpec(
        "validation_errors",
        "Validation Notes",
        lambda d: _has(d.validation_errors),
        "none",
    ),
    SectionSpec(
        "disclaimer",
        "Methodology, Limits of Conclusions & Disclaimer",
        lambda _d: True,
        "present",
    ),
)


@dataclass(frozen=True)
class SectionState:
    section_id: str
    title: str
    present: bool
    status: str


def iter_sections(doc: ReportDocumentV1) -> list[SectionState]:
    """Return the ordered section states for ``doc`` (present + status note)."""
    out: list[SectionState] = []
    for spec in SECTION_ORDER:
        present = bool(spec.present(doc))
        out.append(
            SectionState(
                section_id=spec.section_id,
                title=spec.title,
                present=present,
                status="present" if present else spec.empty_status,
            )
        )
    return out


def section_ids() -> tuple[str, ...]:
    return tuple(s.section_id for s in SECTION_ORDER)


__all__ = [
    "SECTION_ORDER",
    "SectionSpec",
    "SectionState",
    "iter_sections",
    "section_ids",
]
