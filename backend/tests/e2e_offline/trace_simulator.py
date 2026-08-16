"""Offline E2E traces — Production + LAB (DoD §22), no Docker."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from src.execution_mode import ExecutionMode, evaluate_with_execution_mode
from src.execution_mode.boundary_verifier import LabBoundaryVerifier
from src.execution_mode.lab_lease import LabLeaseService
from src.execution_mode.lab_scope import LabScopeManifest


@dataclass
class TraceEvent:
    stage: str
    detail: dict[str, Any] = field(default_factory=dict)


class TraceSimulator:
    """Deterministic in-memory pipeline simulator with DI stubs."""

    def __init__(self) -> None:
        self.events: list[TraceEvent] = []

    def _emit(self, stage: str, **detail: Any) -> None:
        self.events.append(TraceEvent(stage=stage, detail=detail))

    def run_production(self, *, tenant_id: str = "t-prod") -> list[str]:
        self._emit("phase_input", phase="vuln_analysis")
        self._emit("policy_content_classification", content_class="internal")
        self._emit("tenant_filtered_rag", tenant_id=tenant_id)
        self._emit("typed_analysis", alias="security_reasoner")
        self._emit("deterministic_candidate_set", count=3)
        self._emit("production_policy_approval", requires_approval=True, allowed=False)
        # Approval granted stub
        self._emit("production_policy_approval", requires_approval=False, allowed=True)
        self._emit("sandbox_execution_stub", tool="nuclei")
        self._emit("evidence_finding_coverage_report", findings=1)
        return [e.stage for e in self.events]

    def run_lab_unrestricted(self, *, tenant_id: str = "t-lab") -> list[str]:
        manifest = LabScopeManifest(
            tenant_id=tenant_id,
            engagement_id="e-lab",
            cidrs=("10.90.0.0/16",),
            dns_suffixes=("lab.argus",),
            k8s_namespace="argus-lab-42",
            vm_network_ids=("labnet-42",),
            capture_full=True,
            expires_at=datetime.now(tz=timezone.utc) + timedelta(hours=2),
            created_by="sim",
        )
        self._emit("lab_scope_manifest", manifest_id=manifest.manifest_id)
        verdict = LabBoundaryVerifier().verify(
            "10.90.3.3",
            manifest,
            tenant_id=tenant_id,
            engagement_id="e-lab",
            k8s_namespace="argus-lab-42",
            vm_network_id="labnet-42",
        )
        self._emit("boundary_verification", allowed=verdict.allowed, proof=verdict.proof)
        lease = LabLeaseService().issue(manifest, boundary_proof=verdict.proof)
        self._emit("unrestricted_lease", lease_id=lease.lease_id, requires_approval=False)
        self._emit("tenant_filtered_rag", collections=["lab_research"], tenant_id=tenant_id)
        self._emit("complete_requested_plan", steps=["nuclei", "custom_script", "sqlmap"])
        decision = evaluate_with_execution_mode(
            mode=ExecutionMode.LAB_UNRESTRICTED,
            target="10.90.3.3",
            lease=lease,
            tenant_id=tenant_id,
            engagement_id="e-lab",
        )
        assert decision.requires_approval is False
        self._emit(
            "arbitrary_tool_selection",
            tools=["nuclei", "custom_script", "sqlmap"],
            approval_steps=0,
            rate_caps=None,
        )
        self._emit("sandbox_lab_exec_stub", tool="nuclei")
        self._emit("full_evidence_oast_session_trace", capture_full=True)
        self._emit("findings_diff_retest_coverage_report")
        return [e.stage for e in self.events]
