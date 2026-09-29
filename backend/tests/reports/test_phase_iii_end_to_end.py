"""Part III end-to-end (§33) — the shipped-bundle scenario must NOT release ready.

Reproduces the diagnosed bundle (9 findings, tool_runs without timing, evidence
without hashes, pseudo-evidence, 2% WSTG coverage, LLM unavailable) and asserts the
release is an honest draft listing exactly the R-01…R-19 class of violations, never a
ready release.
"""

from __future__ import annotations

from types import SimpleNamespace

from src.reports.llm_remediation.bundle import GenerationStatus
from src.reports.llm_remediation.integration import generate_valhalla_llm_release
from src.reports.llm_remediation.runner import LlmNotInvokedError
from src.reports.snapshot_builder import build_snapshot_from_report_data
from src.reports.snapshot_completeness_gate import snapshot_release_blockers


def _bundle_like_report_data():
    findings = []
    for i in range(1, 10):  # 9 findings, like the shipped bundle
        findings.append(
            SimpleNamespace(
                finding_id=f"f{i:03d}",
                title="TLS/SSL configuration observation" if i == 1 else f"Observation {i}",
                severity="medium" if i == 1 else "info",
                cwe=None,
                description="d",
                validation_status="validated" if i == 1 else "unverified",
                confidence="confirmed" if i == 1 else "possible",
                # Pseudo-evidence only (R-17); no tool_run link (R-18).
                evidence_refs=["tool:testssl"] if i == 1 else ["recon:asnmap"],
                proof_of_concept=None,
                tool_run_id=None,
                source_tool="testssl" if i == 1 else "asnmap",
            )
        )
    tool_runs = [
        {"id": f"tr{i}", "tool_name": t, "status": "success"}  # no timing/artifact (R-15)
        for i, t in enumerate(["testssl", "whatweb", "asnmap", "gau", "ffuf"], 1)
    ]
    evidence = [
        {"finding_id": "f002", "object_key": "argus/poc/f002.json", "kind": "artifact"}
        # no sha256 / collected_at (R-16); f001 keeps only pseudo-evidence (R-17)
    ]
    return SimpleNamespace(
        findings=findings,
        evidence=evidence,
        technologies=["nginx"],
        target="https://alleksy.com",
        scan_id="135f8c21",
        tenant_id="00000000-0000-0000-0000-000000000001",
        tool_runs=tool_runs,
    )


def test_bundle_scenario_snapshot_blockers_are_honest_draft():
    rd = _bundle_like_report_data()
    scan = SimpleNamespace(tool_runs=rd.tool_runs)
    doc = build_snapshot_from_report_data(
        rd,
        scan_meta={"scan_id": "135f8c21", "tier": "valhalla"},
        scan_report_data=scan,
    )
    blockers = snapshot_release_blockers(doc)
    codes = " ".join(blockers)
    # Passport empty, tool_runs no timing, evidence no hash, pseudo-evidence, broken chain.
    assert "R-13" in codes
    assert "R-15" in codes
    assert "R-16" in codes
    # The confirmed TLS finding is capped away from a provable status (R-17 cap).
    tls = next(f for f in doc.findings if f.finding_id == "f001")
    assert tls.verification_status != "confirmed"


def test_bundle_scenario_llm_unavailable_is_draft_not_ready():
    rd = _bundle_like_report_data()
    findings = [
        {
            "finding_id": f.finding_id,
            "title": f.title,
            "severity": f.severity,
            "verification_status": "suspected",
        }
        for f in rd.findings
    ]

    def unavailable(system_prompt: str, user_prompt: str, kind: str) -> str:
        raise LlmNotInvokedError("budget ledger unavailable — denying paid cloud call")

    _doc, release = generate_valhalla_llm_release(
        findings,
        report_meta={"report_id": "R", "report_version": "v", "target": "alleksy.com"},
        llm_callable=unavailable,
        provider="cloud_deepseek",
        model="deepseek-chat",
        health_probe=True,
    )
    # Honest draft: never ready, cause recorded (R-01/R-02), real model, failure kind.
    assert release.manifest.generation_status is not GenerationStatus.READY
    assert release.manifest.errors
    assert release.manifest.llm_model == "deepseek-chat"
    assert release.manifest.failure_kinds.get("llm_not_invoked", 0) >= 1
