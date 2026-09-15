"""End-to-end call point wiring the Valhalla LLM analysis into report generation.

This is the single orchestration entry the report pipeline invokes for the
VALHALLA tier: it maps normalised report findings into closure-computation
inputs, runs the per-finding remediation/closure analysis, freezes the document
tree and builds the atomic multi-format release. It is deliberately I/O-free
(no MinIO, no DB) and takes an injected ``llm_callable`` so it is fully testable
with a mock and reusable from the pipeline with the real facade binding.
"""

from __future__ import annotations

from typing import Any

from src.reports.llm_remediation.builder import build_valhalla_llm_document
from src.reports.llm_remediation.bundle import ValhallaRelease, build_valhalla_release
from src.reports.llm_remediation.closure_status import ClosureComputationInput
from src.reports.llm_remediation.document import ValhallaLlmDocument
from src.reports.llm_remediation.runner import LlmCallable, RemediationRunner

_FALSE_POSITIVE_STATUSES = {"false_positive"}
_RISK_ACCEPTED_STATUSES = {"accepted_risk", "risk_accepted", "accepted"}


def _finding_id(finding: dict[str, Any]) -> str:
    return str(finding.get("finding_id") or finding.get("id") or "")


def _finding_status(finding: dict[str, Any]) -> str:
    return str(finding.get("validation_status") or finding.get("verification_status") or "").lower()


def finding_to_closure_input(finding: dict[str, Any]) -> ClosureComputationInput:
    """Map a report finding to the deterministic closure-status inputs.

    A first-pass assessment has no retest, so the computed status defaults to
    ``not_retested`` (never a fabricated ``fixed_verified``). Explicit
    false-positive / accepted-risk classifications are honoured. Structured
    retest data, when present in a future data model, can be threaded in here.
    """

    status = _finding_status(finding)
    return ClosureComputationInput(
        finding_id=_finding_id(finding),
        acceptance_criteria_ids=(),
        retests=(),
        is_false_positive=status in _FALSE_POSITIVE_STATUSES,
        risk_accepted=status in _RISK_ACCEPTED_STATUSES,
    )


def _evidence_ids(finding: dict[str, Any]) -> list[str]:
    raw = finding.get("evidence_refs") or finding.get("evidence_ids") or []
    if isinstance(raw, (list, tuple)):
        return [str(v) for v in raw]
    return [str(raw)]


def _finding_meta(findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    meta: dict[str, dict[str, Any]] = {}
    for finding in findings:
        fid = _finding_id(finding)
        if not fid:
            continue
        meta[fid] = {
            "title": finding.get("title", ""),
            "severity": finding.get("severity", "unknown"),
            "verification_status": finding.get("validation_status")
            or finding.get("verification_status")
            or "not_assessed",
        }
    return meta


def generate_valhalla_llm_release(
    findings: list[dict[str, Any]],
    *,
    report_meta: dict[str, Any],
    llm_callable: LlmCallable,
    formats: list[str] | None = None,
    canonical_snapshot_hash: str = "",
    allow_incomplete_draft: bool = True,
    provider: str = "unknown",
    model: str = "unknown",
    cache: dict[str, Any] | None = None,
    locale: str = "ru",
) -> tuple[ValhallaLlmDocument, ValhallaRelease]:
    """Run the analysis and build the multi-format release for a report.

    Returns the frozen document and the atomic release (artifacts + manifest).
    ``allow_incomplete_draft`` defaults to True so a partial/failed LLM run
    still yields an honest, clearly-marked draft instead of nothing — the
    manifest ``generation_status`` distinguishes ``ready`` from ``draft``.
    """

    runner = RemediationRunner(llm_callable, provider=provider, model=model, cache=cache)
    valid = [f for f in findings if _finding_id(f)]
    closure_inputs = {_finding_id(f): finding_to_closure_input(f) for f in valid}
    allowed_evidence = {_finding_id(f): _evidence_ids(f) for f in valid}

    run_result = runner.run(
        valid,
        report_meta=report_meta,
        closure_inputs=closure_inputs,
        allowed_evidence_ids=allowed_evidence,
        locale=locale,
    )
    document = build_valhalla_llm_document(
        run_result,
        report_meta=report_meta,
        finding_meta=_finding_meta(valid),
        canonical_snapshot_hash=canonical_snapshot_hash,
        locale=locale,
    )
    release = build_valhalla_release(
        document, formats=formats, allow_incomplete_draft=allow_incomplete_draft
    )
    return document, release


__all__ = [
    "finding_to_closure_input",
    "generate_valhalla_llm_release",
]
