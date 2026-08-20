"""Transform an adaptive-loop :class:`LoopReport` into the scan artifact contract.

This is the bridge that lets the adaptive driver (Step 3) *produce the same
artifacts as the linear FSM* rather than replacing the whole persistence stack:
by emitting a :class:`~src.orchestration.phases.VulnAnalysisOutput` (findings +
coverage), the loop's results flow through the existing
``_persist_report_and_findings`` path into ``Finding`` rows, ``ScanState`` and the
report tiers unchanged. The loop never touches the DB; it only yields a typed
phase output that the FSM already knows how to persist.

Evidence discipline (never over-claim): the production
:class:`~src.orchestration.adaptive_integration.HeuristicVerifier` returns
``CONFIRMED`` merely on *exit 0 + output* — a signal, not a proven exploit. So a
confirmed action maps to :class:`~src.orchestration.evidence_tier.EvidenceTier.SUSPECTED`
(tier 2), keeping it out of the "provable" Valhalla tier until a real
LLM/PoC verifier upgrades it. ``INCONCLUSIVE`` / ``REJECTED`` actions produce no
finding at all.
"""

from __future__ import annotations

from typing import Any

from src.orchestration.adaptive_loop import ActionRecord, LoopReport, VerifyOutcome
from src.orchestration.evidence_tier import EvidenceTier
from src.orchestration.phases import VulnAnalysisOutput

# tool_id -> (finding label, CWE, severity). Conservative; unknown tools fall back
# to a generic low-signal finding. Callers can enrich via node ``vuln_type`` metadata.
_TOOL_VULN: dict[str, tuple[str, str, str]] = {
    "sqlmap": ("SQL Injection", "CWE-89", "high"),
    "dalfox": ("Cross-Site Scripting (XSS)", "CWE-79", "medium"),
    "xsstrike": ("Cross-Site Scripting (XSS)", "CWE-79", "medium"),
    "commix": ("OS Command Injection", "CWE-78", "critical"),
    "tplmap": ("Server-Side Template Injection (SSTI)", "CWE-1336", "high"),
    "crlfuzz": ("CRLF Injection", "CWE-93", "medium"),
    "nuclei": ("Template-detected issue (nuclei)", "", "medium"),
    "ffuf": ("Exposed / force-browsed resource", "CWE-538", "low"),
}
_DEFAULT_VULN: tuple[str, str, str] = ("Potential vulnerability", "", "info")

# Heuristic "confirmed" (tool produced output) is a lead, not a proven exploit.
_CONFIRMED_TIER: int = int(EvidenceTier.SUSPECTED)


def _vuln_for(record: ActionRecord) -> tuple[str, str, str]:
    """Resolve ``(label, cwe, severity)`` for a record from its tool + node metadata."""
    metadata = record.proposal.metadata or {}
    explicit = str(
        metadata.get("vuln_type") or metadata.get("vuln_class") or metadata.get("family") or ""
    ).strip()
    tool = (record.proposal.tool or "").strip().lower()
    if tool in _TOOL_VULN:
        return _TOOL_VULN[tool]
    if explicit:
        return (explicit, "", "medium")
    return _DEFAULT_VULN


def action_record_to_finding(record: ActionRecord) -> dict[str, Any] | None:
    """Map a single ``CONFIRMED`` action record to a finding dict, else ``None``.

    Only confirmed actions become findings; inconclusive/rejected ones carry no
    evidence worth persisting. The dict uses the same keys the FSM's
    ``_persist_report_and_findings`` consumes, so it lands as a normal ``Finding``.
    """
    if record.outcome != VerifyOutcome.CONFIRMED:
        return None

    metadata = record.proposal.metadata or {}
    label, cwe, severity = _vuln_for(record)
    tool = record.proposal.tool
    url = (record.proposal.target or str(metadata.get("url", ""))).strip()
    param = str(metadata.get("param_name", "")).strip()
    input_location = str(metadata.get("location", "")).strip()
    surface_id = str(metadata.get("surface_id", "")).strip()

    title = f"{label} via {tool}" + (f" on parameter '{param}'" if param else "")
    description = (
        f"Adaptive loop executed '{tool}' against {url or 'the target'}"
        + (
            f" (parameter '{param}'" + (f", {input_location}" if input_location else "") + ")"
            if param
            else ""
        )
        + f"; the tool produced a signal (exit {record.exit_code})."
    )

    finding: dict[str, Any] = {
        "title": title[:500],
        "severity": severity,
        "description": description,
        "confidence": "likely",
        "evidence_type": "dynamic",
        "evidence_tier": _CONFIRMED_TIER,
        "exploit_demonstrated": False,
        "dedup_status": "unchecked",
        "source": "adaptive_loop",
        "adaptive": True,
        "tool": tool,
        "url": url,
        "node_id": record.proposal.node_id,
        "proof_of_concept": {
            "tool": tool,
            "target": url,
            "exit_code": record.exit_code,
            "evidence": record.evidence,
        },
    }
    if cwe:
        finding["cwe"] = cwe
    if param:
        finding["parameter"] = param
    if input_location:
        finding["input_location"] = input_location
    if surface_id:
        finding["evidence_refs"] = [surface_id]
    if url:
        finding["reproducible_steps"] = f"Run `{tool}` against {url}; observe the tool output."
    return finding


def loop_report_to_findings(report: LoopReport) -> list[dict[str, Any]]:
    """All confirmed findings from a loop report (order-preserving)."""
    findings: list[dict[str, Any]] = []
    for record in report.trace:
        finding = action_record_to_finding(record)
        if finding is not None:
            findings.append(finding)
    return findings


def adaptive_coverage_result(report: LoopReport) -> dict[str, Any]:
    """One ``coverage_results`` entry summarizing the adaptive run (free-form dict)."""
    return {
        "kind": "adaptive_loop",
        "actions_run": report.actions_run,
        "confirmed": report.confirmed,
        "rejected": report.rejected,
        "inconclusive": report.inconclusive,
        "stopped_reason": report.stopped_reason,
        **report.coverage,
    }


def loop_report_to_vuln_output(report: LoopReport) -> VulnAnalysisOutput:
    """Typed :class:`VulnAnalysisOutput` from a loop report (findings + coverage).

    Plugging this into the VULN_ANALYSIS phase output makes the loop's findings
    flow through the unchanged FSM persistence into ``Finding`` rows and reports.
    """
    return VulnAnalysisOutput(
        findings=loop_report_to_findings(report),
        coverage_results=[adaptive_coverage_result(report)],
    )


def loop_report_timeline_entries(report: LoopReport) -> list[dict[str, Any]]:
    """Per-action append-only timeline entries (one per executed action)."""
    return [
        {
            "kind": "adaptive_action",
            "node_id": record.proposal.node_id,
            "tool": record.proposal.tool,
            "target": record.proposal.target,
            "outcome": record.outcome.value,
            "exit_code": record.exit_code,
        }
        for record in report.trace
    ]


__all__ = [
    "action_record_to_finding",
    "adaptive_coverage_result",
    "loop_report_timeline_entries",
    "loop_report_to_findings",
    "loop_report_to_vuln_output",
]
