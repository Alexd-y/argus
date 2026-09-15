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
from src.reports.llm_remediation.closure_status import (
    ClosureComputationInput,
    RetestExecution,
    RetestOutcome,
)
from src.reports.llm_remediation.document import ValhallaLlmDocument
from src.reports.llm_remediation.runner import LlmCallable, RemediationRunner

_FALSE_POSITIVE_STATUSES = {"false_positive"}
_RISK_ACCEPTED_STATUSES = {"accepted_risk", "risk_accepted", "accepted"}

# Structured retest outcome vocabulary. Free-text ``retest_result`` is
# deliberately NOT auto-mapped to a passing outcome: inferring a fix from vague
# prose would risk a false ``fixed_verified`` (prompt L02/L03). Only an explicit
# structured retest record contributes evidence to the closure computation.
_RETEST_OUTCOME_MAP: dict[str, RetestOutcome] = {
    "pass_secure": RetestOutcome.PASS_SECURE,
    "pass": RetestOutcome.PASS_SECURE,
    "secure": RetestOutcome.PASS_SECURE,
    "fixed": RetestOutcome.PASS_SECURE,
    "fail_vulnerable": RetestOutcome.FAIL_VULNERABLE,
    "fail": RetestOutcome.FAIL_VULNERABLE,
    "vulnerable": RetestOutcome.FAIL_VULNERABLE,
    "inconclusive": RetestOutcome.INCONCLUSIVE,
    "unreachable": RetestOutcome.UNREACHABLE,
    "error": RetestOutcome.ERROR,
}


def _finding_id(finding: dict[str, Any]) -> str:
    return str(finding.get("finding_id") or finding.get("id") or "")


def _finding_status(finding: dict[str, Any]) -> str:
    return str(finding.get("validation_status") or finding.get("verification_status") or "").lower()


def parse_finding_retests(finding: dict[str, Any]) -> tuple[RetestExecution, ...]:
    """Build typed retest executions from a finding's structured ``retests``.

    Expects ``finding["retests"]`` to be a list of dicts with ``outcome`` (one
    of the :class:`RetestOutcome` vocabulary) and optional ``test_id``,
    ``criteria_ids`` and ``evidence_ids``. Entries with an unknown/absent
    outcome are skipped (conservative: unknown never counts as a pass). Free-text
    fields are intentionally ignored here to avoid fabricating a fix.
    """

    raw = finding.get("retests")
    if not isinstance(raw, (list, tuple)):
        return ()
    executions: list[RetestExecution] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        outcome = _RETEST_OUTCOME_MAP.get(str(item.get("outcome", "")).strip().lower())
        if outcome is None:
            continue
        executions.append(
            RetestExecution(
                test_id=str(item.get("test_id") or f"retest-{len(executions) + 1}"),
                outcome=outcome,
                criteria_ids=tuple(str(c) for c in (item.get("criteria_ids") or [])),
                evidence_ids=tuple(str(e) for e in (item.get("evidence_ids") or [])),
            )
        )
    return tuple(executions)


def finding_to_closure_input(finding: dict[str, Any]) -> ClosureComputationInput:
    """Map a report finding to the deterministic closure-status inputs.

    Consumes structured retest data (``retests``) and known acceptance-criteria
    ids (``acceptance_criteria_ids``) when present, so the computed status
    reflects real retest evidence. Without retest data the status is
    ``not_retested`` (never a fabricated ``fixed_verified``). Explicit
    false-positive / accepted-risk classifications are honoured.
    """

    status = _finding_status(finding)
    criteria = tuple(str(c) for c in (finding.get("acceptance_criteria_ids") or []))
    return ClosureComputationInput(
        finding_id=_finding_id(finding),
        acceptance_criteria_ids=criteria,
        retests=parse_finding_retests(finding),
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
    "parse_finding_retests",
]
