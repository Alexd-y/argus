"""Typed-intent runtime glue + defensive finding-evidence gate (R8)."""

from __future__ import annotations

from dataclasses import dataclass

from src.llm_orchestrator.intent_compiler import AbstainResult, CompiledToolJob
from src.orchestration.typed_intent_runner import (
    enforce_finding_evidence,
    run_typed_intent,
)
from src.profiles.resolver import resolve_scan_profile


@dataclass
class FakeDescriptor:
    tool_id: str
    command_template: list[str]
    risk_level: str = "low"
    requires_approval: bool = False


@dataclass
class FakeFamily:
    family_id: str
    cwe_ids: list[int]
    risk_level: str = "low"
    requires_approval: bool = False
    oast_required: bool = False


DESCRIPTORS = [FakeDescriptor("nuclei", ["nuclei"]), FakeDescriptor("ffuf", ["ffuf"])]
FAMILIES = [FakeFamily("xss_safe", [79])]
PARSERS = frozenset({"nuclei", "ffuf"})
EXECS = frozenset({"nuclei", "ffuf"})


def test_run_typed_intent_compiles_valid_intent():
    job = run_typed_intent(
        {
            "phase": "vuln_analysis",
            "scope_refs": ["scope-1"],
            "tool_id": "nuclei",
            "typed_args": {"severity": "high"},
            "payload_family_id": "xss_safe",
        },
        resolved_profile=resolve_scan_profile("light"),
        tool_descriptors=DESCRIPTORS,
        payload_families=FAMILIES,
        parser_tool_ids=PARSERS,
        known_executables=EXECS,
        allowed_scope_refs=frozenset({"scope-1"}),
    )
    assert isinstance(job, CompiledToolJob)
    assert job.tool_id == "nuclei"


def test_run_typed_intent_abstains():
    result = run_typed_intent(
        {"phase": "vuln_analysis", "abstain_reason": "insufficient_evidence"},
        resolved_profile=resolve_scan_profile("light"),
        tool_descriptors=DESCRIPTORS,
        payload_families=FAMILIES,
        parser_tool_ids=PARSERS,
        known_executables=EXECS,
    )
    assert isinstance(result, AbstainResult)


class TestEnforceFindingEvidence:
    def test_drops_confirmed_without_evidence(self):
        findings = [
            {"finding_id": "F-1", "title": "SQLi", "verification_status": "confirmed", "evidence_ids": ["E-1"]},
            {"finding_id": "F-2", "title": "RCE", "verification_status": "confirmed"},
        ]
        kept, dropped = enforce_finding_evidence(findings)
        assert [f["finding_id"] for f in kept] == ["F-1"]
        assert [f["finding_id"] for f in dropped] == ["F-2"]

    def test_drops_cve_without_evidence(self):
        findings = [
            {"finding_id": "F-1", "title": "Affected by CVE-2021-44228"},
        ]
        kept, dropped = enforce_finding_evidence(findings)
        assert kept == []
        assert len(dropped) == 1

    def test_keeps_cve_with_evidence(self):
        findings = [
            {"finding_id": "F-1", "title": "CVE-2021-44228", "evidence_refs": ["E-1"]},
        ]
        kept, dropped = enforce_finding_evidence(findings)
        assert len(kept) == 1
        assert dropped == []

    def test_keeps_suspected_without_evidence(self):
        findings = [
            {"finding_id": "F-1", "title": "maybe", "confidence": "possible"},
        ]
        kept, dropped = enforce_finding_evidence(findings)
        assert len(kept) == 1
        assert dropped == []

    def test_validated_status_requires_evidence(self):
        findings = [
            {"finding_id": "F-1", "title": "x", "validation_status": "validated"},
        ]
        kept, dropped = enforce_finding_evidence(findings)
        assert dropped and dropped[0]["finding_id"] == "F-1"

    def test_reproducible_steps_counts_as_evidence(self):
        findings = [
            {"finding_id": "F-1", "title": "x", "verification_status": "confirmed",
             "reproducible_steps": ["step 1"]},
        ]
        kept, dropped = enforce_finding_evidence(findings)
        assert len(kept) == 1


class TestExploitEvidenceGate:
    """Exploitation output: every exploit inherently claims exploitability."""

    def test_exploit_without_poc_dropped(self):
        exploits = [{"vuln_type": "xss", "severity": "high"}]
        kept, dropped = enforce_finding_evidence(
            exploits,
            treat_as_provable=True,
            extra_evidence_keys=("poc_url", "browser_evidence", "screenshot_base64"),
        )
        assert kept == []
        assert len(dropped) == 1

    def test_exploit_with_poc_url_kept(self):
        exploits = [{"vuln_type": "xss", "severity": "high", "poc_url": "http://x/?q=<script>"}]
        kept, dropped = enforce_finding_evidence(
            exploits,
            treat_as_provable=True,
            extra_evidence_keys=("poc_url", "browser_evidence", "screenshot_base64"),
        )
        assert len(kept) == 1
        assert dropped == []

    def test_exploit_with_symbolic_proof_kept(self):
        exploits = [{"vuln_type": "rce", "severity": "critical", "symbolic_execution_proven": True}]
        kept, dropped = enforce_finding_evidence(
            exploits,
            treat_as_provable=True,
            extra_evidence_keys=("symbolic_execution_proven",),
        )
        assert len(kept) == 1
