"""Valhalla completeness registry + quality validators (Phase 16).

The user's core requirement: *everything collected during the pentest reaches the
report*. This module makes that a declarative, testable contract rather than ad-hoc
template inserts.

Two building blocks:

* ``VALHALLA_REQUIRED_SOURCES`` — a declarative table of data sources, where each
  comes from, which report section it feeds, and what to do when it is absent.
* ``validate_valhalla_completeness`` — the release rule that catches **VP-04**:
  *"a source is non-empty but its section is empty"* is a release error, not a
  silent omission. Plus stop-list (VP-02) and unclassified-in-registry (VP-05)
  checks used by the quality gate.

Pure and additive — no changes to the report pipeline; the pipeline/quality gate
calls these to block a bad release.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RequiredSource:
    key: str
    origin: str
    section: str
    required: bool
    on_absent: str


#: Declarative registry (§20.5). ``key`` is the snapshot field; ``section`` the report
#: section it must populate. ``required`` sources must be represented even when empty
#: (with an explicit "not tested / none found" note per ``on_absent``).
VALHALLA_REQUIRED_SOURCES: tuple[RequiredSource, ...] = (
    RequiredSource(
        "findings",
        "Finding/ScanReportData.findings",
        "findings_registry",
        True,
        "explicit_none_plus_coverage",
    ),
    RequiredSource("evidence", "Evidence", "finding_cards", True, "cap_at_suspected"),
    RequiredSource("tool_runs", "ToolRun", "execution_log", True, "not_run_is_not_not_found"),
    RequiredSource(
        "raw_artifacts", "MinIO/raw_artifacts", "appendix_grouped", True, "grouped_by_finding"
    ),
    RequiredSource(
        "ports_services",
        "nmap/naabu artifacts",
        "surface_inventory",
        True,
        "consistency_error_if_artifact",
    ),
    RequiredSource(
        "tech_stack",
        "whatweb/wafw00f/nuclei-tech",
        "surface_inventory",
        True,
        "consistency_error_if_artifact",
    ),
    RequiredSource(
        "wstg_coverage", "wstg_*", "methodology_completeness", True, "percent_plus_untested_list"
    ),
    RequiredSource(
        "exploitation",
        "ExploitationOutput",
        "confirmed_chains",
        True,
        "no_attempt_is_not_not_exploitable",
    ),
    RequiredSource("scope_roe", "Scan.execution_mode/ScopeEngine", "passport", True, "mandatory"),
    RequiredSource("quality_gate", "report_quality_gate", "completeness_limits", True, "mandatory"),
    RequiredSource("llm_degraded", "llm_degraded flag", "passport_limits", True, "mandatory"),
    RequiredSource(
        "cairn_graph",
        "cairn_facts/cairn_intents",
        "search_graph",
        False,
        "not_applicable_if_unused",
    ),
    RequiredSource(
        "cairn_directives", "cairn_directives", "next_steps", False, "not_applicable_if_unused"
    ),
)

#: Placeholder / stop-list phrases that must never appear in a Valhalla report (VP-02).
STOP_LIST_PHRASES: tuple[str, ...] = (
    "poc details are available in asgard",
    "poc details are available in valhalla",
    "poc details are available in asgard / valhalla reports",
    "details are available in asgard / valhalla reports",
)


@dataclass
class CompletenessViolation:
    source_key: str
    section: str
    reason: str


@dataclass
class CompletenessReport:
    violations: list[CompletenessViolation] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.violations


def _is_nonempty(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (list, tuple, set, dict, str)):
        return len(value) > 0
    return bool(value)


def validate_valhalla_completeness(
    snapshot: dict[str, Any],
    sections: dict[str, Any],
) -> CompletenessReport:
    """Catch VP-04: a non-empty source whose target section is empty is an error.

    ``snapshot`` maps source keys to collected data; ``sections`` maps section names
    to their rendered content. A required source that is non-empty while its section
    is empty is a release-blocking violation.
    """
    report = CompletenessReport()
    for src in VALHALLA_REQUIRED_SOURCES:
        source_value = snapshot.get(src.key)
        section_value = sections.get(src.section)
        if _is_nonempty(source_value) and not _is_nonempty(section_value):
            report.violations.append(
                CompletenessViolation(
                    source_key=src.key,
                    section=src.section,
                    reason=f"source '{src.key}' is non-empty but section '{src.section}' is empty",
                )
            )
    return report


def find_stop_list_violations(text: str) -> list[str]:
    """Return any stop-list placeholder phrases present in ``text`` (VP-02)."""
    lowered = text.lower()
    return [phrase for phrase in STOP_LIST_PHRASES if phrase in lowered]


_UNCLASSIFIED_RE = re.compile(r"unclassified|not[_ ]assessed|cannot be interpreted", re.IGNORECASE)


def unclassified_findings_in_registry(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return findings that are really unclassified observations (VP-05).

    A finding with no category/CWE and an 'unclassified'/'not_assessed' marker must
    NOT sit in the findings registry — it belongs in the appendix.
    """
    offenders: list[dict[str, Any]] = []
    for finding in findings:
        cwe = str(finding.get("cwe") or "").strip().lower()
        category = str(finding.get("category") or finding.get("owasp_category") or "").strip()
        title = str(finding.get("title") or "")
        description = str(finding.get("description") or "")
        has_category = bool(category) and category.lower() not in (
            "",
            "not_assessed",
            "unclassified",
        )
        marker = _UNCLASSIFIED_RE.search(title) or _UNCLASSIFIED_RE.search(description)
        if not has_category and (cwe in ("", "not_assessed", "unclassified")) and marker:
            offenders.append(finding)
    return offenders


def valhalla_release_blockers(
    *,
    snapshot: dict[str, Any],
    sections: dict[str, Any],
    report_text: str,
    findings: list[dict[str, Any]],
    requested_tier: str,
    actual_tier: str,
    llm_analysis_status: str,
) -> list[str]:
    """Aggregate the blocking rules that must prevent a Valhalla release (§20.11).

    Returns a list of human-readable blocking reasons (empty == releasable). This is
    additive: the pipeline/quality gate calls it to fail-closed instead of shipping a
    defective report. Covers VP-01 (tier swap), VP-02 (placeholder), VP-04
    (source/section mismatch), VP-05 (unclassified in registry) and §9 (LLM analysis
    incomplete but release marked ready).
    """
    blockers: list[str] = []

    # VP-01 — requested tier must equal the rendered tier.
    if requested_tier.strip().lower() != actual_tier.strip().lower():
        blockers.append(f"VP-01: requested tier '{requested_tier}' but report is '{actual_tier}'")

    # VP-02 — placeholder / stop-list phrases.
    for phrase in find_stop_list_violations(report_text):
        blockers.append(f"VP-02: stop-list phrase present: '{phrase}'")

    # VP-04 — a non-empty source with an empty section.
    completeness = validate_valhalla_completeness(snapshot, sections)
    for violation in completeness.violations:
        blockers.append(f"VP-04: {violation.reason}")

    # VP-05 — unclassified observations must not sit in the findings registry.
    offenders = unclassified_findings_in_registry(findings)
    if offenders:
        blockers.append(
            f"VP-05: {len(offenders)} unclassified observation(s) in the findings registry"
        )

    # §9 — LLM analysis must be complete for a ready release.
    if llm_analysis_status.strip().lower() != "completed":
        blockers.append(
            f"LLM analysis not complete (status='{llm_analysis_status}') — release cannot be final"
        )

    return blockers


__all__ = [
    "STOP_LIST_PHRASES",
    "VALHALLA_REQUIRED_SOURCES",
    "CompletenessReport",
    "CompletenessViolation",
    "RequiredSource",
    "find_stop_list_violations",
    "unclassified_findings_in_registry",
    "validate_valhalla_completeness",
    "valhalla_release_blockers",
]
