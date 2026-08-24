"""Runtime glue for the typed LLM-intent compiler (R8).

Two entry points:

* :func:`run_typed_intent` — the Evidence/context → typed intent → deterministic
  compiler → tool job chain, wiring the profile + signed registries into a
  :class:`CompilerContext`.
* :func:`enforce_finding_evidence` — a defensive gate that drops fabricated LLM
  findings (a ``confirmed``/``exploitable`` claim with no evidence, or a CVE
  asserted with no evidence) from a phase's finding list (R6/R8 defense-in-depth).

Both are pure/testable and emit structured events.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from src.core.structured_events import (
    EVENT_EVIDENCE_CONTRACT_FAILED,
    EVENT_EVIDENCE_CONTRACT_SATISFIED,
    emit_event,
)
from src.llm_orchestrator.intent_compiler import (
    AbstainResult,
    CompiledToolJob,
    compile_intent,
)
from src.orchestration.scan_policy import build_compiler_context
from src.payloads.taxonomy import FamilyLike
from src.profiles.resolver import ResolvedScanProfile
from src.sandbox.tool_registrability import DescriptorLike

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_PROVABLE = frozenset({"confirmed", "exploitable"})
_EVIDENCE_KEYS = (
    "evidence_ids",
    "evidence_refs",
    "evidence",
    "proof_of_concept",
    "reproducible_steps",
    "reproducer",
)


def run_typed_intent(
    raw_intent: dict[str, Any],
    *,
    resolved_profile: ResolvedScanProfile,
    tool_descriptors: list[DescriptorLike],
    payload_families: list[FamilyLike],
    parser_tool_ids: frozenset[str],
    known_executables: frozenset[str] | None = None,
    allowed_scope_refs: frozenset[str] = frozenset(),
    lab_lease_active: bool = False,
    granted_approvals: frozenset[str] = frozenset(),
    budget_remaining: bool = True,
    scan_id: str | None = None,
    tenant_id: str | None = None,
) -> CompiledToolJob | AbstainResult:
    """Compile a raw LLM intent into a safe tool job (or abstain) — R8 chain."""
    ctx = build_compiler_context(
        resolved_profile,
        tool_descriptors=tool_descriptors,
        payload_families=payload_families,
        parser_tool_ids=parser_tool_ids,
        known_executables=known_executables,
        allowed_scope_refs=allowed_scope_refs,
        lab_lease_active=lab_lease_active,
        granted_approvals=granted_approvals,
        budget_remaining=budget_remaining,
        scan_id=scan_id,
        tenant_id=tenant_id,
    )
    return compile_intent(raw_intent, ctx)


def _has_evidence(finding: dict[str, Any]) -> bool:
    for key in _EVIDENCE_KEYS:
        value = finding.get(key)
        if value:
            return True
    return False


def _claims_provable(finding: dict[str, Any]) -> bool:
    for key in ("verification_status", "validation_status", "status", "confidence"):
        val = str(finding.get(key, "") or "").strip().lower()
        if val in _PROVABLE or val == "validated":
            return True
    return False


def _asserts_cve(finding: dict[str, Any]) -> bool:
    blob = " ".join(
        str(finding.get(k, "")) for k in ("title", "description", "cve", "summary")
    )
    return bool(_CVE_RE.search(blob))


def _has_evidence_ext(finding: dict[str, Any], extra_keys: tuple[str, ...]) -> bool:
    for key in (*_EVIDENCE_KEYS, *extra_keys):
        if finding.get(key):
            return True
    return False


def enforce_finding_evidence(
    findings: list[dict[str, Any]],
    *,
    scan_id: str | None = None,
    tenant_id: str | None = None,
    scan_profile: str | None = None,
    phase: str | None = None,
    extra_evidence_keys: tuple[str, ...] = (),
    treat_as_provable: bool = False,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Drop fabricated findings (provable/CVE claim without evidence). Returns (kept, dropped).

    Conservative: only drops a finding when it *claims* confirmed/exploitable (or
    asserts a CVE) AND carries no evidence of any recognized kind. Callers may pass
    ``extra_evidence_keys`` (e.g. exploit PoC keys) and ``treat_as_provable`` for
    phases whose entries inherently assert exploitability.
    """
    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    for finding in findings:
        provable = treat_as_provable or _claims_provable(finding)
        cve = _asserts_cve(finding)
        if (provable or cve) and not _has_evidence_ext(finding, extra_evidence_keys):
            dropped.append(finding)
            emit_event(
                EVENT_EVIDENCE_CONTRACT_FAILED,
                tenant_id=tenant_id,
                scan_id=scan_id,
                scan_profile=scan_profile,
                phase=phase,
                reason_code="cve_without_evidence" if cve else "provable_without_evidence",
                finding_id=finding.get("finding_id"),
            )
            continue
        kept.append(finding)
    if dropped:
        emit_event(
            EVENT_EVIDENCE_CONTRACT_SATISFIED,
            tenant_id=tenant_id,
            scan_id=scan_id,
            scan_profile=scan_profile,
            phase=phase,
            kept=len(kept),
            dropped=len(dropped),
        )
    return kept, dropped


__all__ = ["enforce_finding_evidence", "run_typed_intent"]
