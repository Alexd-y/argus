"""Snapshot completeness / evidence-chain gate (Part III, Phase U — prompt §30).

Blocking rules derived from the shipped-bundle defects R-13…R-18. Pure functions
over a :class:`ReportDocumentV1`; the aggregator feeds the Valhalla release gate.

* R-13 — the snapshot passport (execution_mode / scan_profile / … and the version
  dicts) must be filled; an empty dict in a mandatory field is an error, not a norm.
* R-14 — ``limitations`` must be non-empty when the WSTG coverage gate failed.
* R-15 — every ``tool_run`` needs timing + a parser status / artifact; ``success``
  with no output and no artifact is undefined and must be ``completed_no_output``.
* R-16 — every ``evidence_reference`` needs a sha256 and a collection timestamp.
* R-17 — ``tool:*`` / ``recon:*`` pseudo-ids are not evidence; a finding whose only
  evidence is pseudo cannot be presented above ``suspected``.
* R-18 — a tool-derived finding needs a ``tool_run_id``; a broken chain blocks a
  finding of severity ``medium`` or higher.
"""

from __future__ import annotations

import re

from src.reports.report_document import ReportDocumentV1, ReportFinding

_PROVABLE = frozenset({"confirmed", "exploitable"})
_MEDIUM_PLUS = frozenset({"critical", "high", "medium"})
_PSEUDO_EVIDENCE_RE = re.compile(r"^(tool|recon):", re.IGNORECASE)

#: Passport scalar fields that must be present (R-13, §30.1 item 2).
_REQUIRED_SCALARS: tuple[str, ...] = (
    "execution_mode",
    "scan_profile",
    "resolved_scan_mode",
    "started_at",
)
#: Passport dict fields that must be non-empty (R-13).
_REQUIRED_DICTS: tuple[str, ...] = (
    "registry_versions",
    "scope_summary",
)


def is_pseudo_evidence(evidence_id: str) -> bool:
    return bool(_PSEUDO_EVIDENCE_RE.match((evidence_id or "").strip()))


def finding_has_only_pseudo_evidence(finding: ReportFinding) -> bool:
    ids = [e for e in finding.evidence_ids if str(e).strip()]
    if not ids:
        return False
    return all(is_pseudo_evidence(e) for e in ids) and not finding.raw_artifact_ref


def passport_blockers(doc: ReportDocumentV1) -> list[str]:
    out: list[str] = []
    for field in _REQUIRED_SCALARS:
        if not getattr(doc, field, None):
            out.append(f"R-13: snapshot passport field '{field}' is empty")
    for field in _REQUIRED_DICTS:
        if not getattr(doc, field, None):
            out.append(f"R-13: snapshot passport dict '{field}' is empty")
    return out


def limitations_blockers(doc: ReportDocumentV1) -> list[str]:
    wstg = doc.wstg if isinstance(doc.wstg, dict) else {}
    gate_passed = wstg.get("coverage_gate_passed")
    if gate_passed is False and not doc.limitations:
        return ["R-14: WSTG coverage gate failed but limitations is empty"]
    return []


def tool_run_blockers(doc: ReportDocumentV1) -> list[str]:
    out: list[str] = []
    for t in doc.tool_runs:
        if not t.started_at or not t.finished_at:
            out.append(f"R-15: tool_run '{t.tool_run_id}' missing start/finish timing")
        if str(t.status).lower() == "success" and not t.raw_artifact_ref and not t.parser_status:
            out.append(
                f"R-15: tool_run '{t.tool_run_id}' is 'success' with no artifact/parser output "
                "(should be 'completed_no_output')"
            )
    return out


def evidence_blockers(doc: ReportDocumentV1) -> list[str]:
    out: list[str] = []
    for e in doc.evidence_references:
        if not e.sha256:
            out.append(f"R-16: evidence '{e.evidence_id}' has no sha256")
        if not e.collected_at_utc:
            out.append(f"R-16: evidence '{e.evidence_id}' has no collected_at_utc")
    return out


def finding_chain_blockers(doc: ReportDocumentV1) -> list[str]:
    out: list[str] = []
    for f in doc.findings:
        # R-17 — pseudo-evidence cannot support a provable status.
        if f.verification_status in _PROVABLE and finding_has_only_pseudo_evidence(f):
            out.append(
                f"R-17: finding '{f.finding_id}' is {f.verification_status} but its only evidence "
                "is pseudo (tool:*/recon:*)"
            )
        # R-18 — a medium+ finding must trace to a tool run or a validator.
        if (f.severity or "").lower() in _MEDIUM_PLUS and not (f.tool_run_id or f.validator_id):
            out.append(
                f"R-18: finding '{f.finding_id}' (severity {f.severity}) has no tool_run_id/"
                "validator_id — evidence chain broken"
            )
    return out


def snapshot_release_blockers(doc: ReportDocumentV1) -> list[str]:
    """Aggregate all Phase-U snapshot-completeness blockers (R-13…R-18)."""
    return [
        *passport_blockers(doc),
        *limitations_blockers(doc),
        *tool_run_blockers(doc),
        *evidence_blockers(doc),
        *finding_chain_blockers(doc),
    ]


__all__ = [
    "evidence_blockers",
    "finding_chain_blockers",
    "finding_has_only_pseudo_evidence",
    "is_pseudo_evidence",
    "limitations_blockers",
    "passport_blockers",
    "snapshot_release_blockers",
    "tool_run_blockers",
]
