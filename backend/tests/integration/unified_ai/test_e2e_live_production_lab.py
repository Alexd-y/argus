"""Live production + LAB e2e: scan policy, lease, runner, findings, report.

Not a Juice Shop HTTP ping. Uses the real LAB runner (local subprocess fallback),
findings repository, coverage sink, Nuclei compiler, and JSON report generator.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient
from src.api.routers import execution_mode as em_api
from src.api.routers import unified_ai_lab as lab_api
from src.api.schemas import Finding, ReportSummary
from src.findings.lifecycle import FindingOccurrence, LogicalFinding
from src.findings.repository import get_findings_repository
from src.nuclei.profile_compiler import NucleiProfileCompiler
from src.orchestration.coverage_phase_sink import (
    ToolRunSignal,
    attach_phase_coverage,
    get_coverage_store,
)
from src.orchestration.execution_mode_context import resolve_tool_policy_from_options
from src.reports.generators import ReportData, generate_json


def _app() -> FastAPI:
    app = FastAPI()
    app.include_router(em_api.router, prefix="/api/v1")
    app.include_router(lab_api.nuclei_router, prefix="/api/v1")
    app.include_router(lab_api.lab_router, prefix="/api/v1")
    app.include_router(lab_api.findings_ext_router, prefix="/api/v1")
    app.include_router(lab_api.coverage_router, prefix="/api/v1")
    return app


def _client() -> TestClient:
    em_api._reset_stores_for_tests()
    lab_api._reset_stores_for_tests()
    get_coverage_store().clear()
    return TestClient(_app())


def _headers() -> dict[str, str]:
    return {"X-Tenant-Id": "t-1", "X-User-Id": "u-1"}


def test_live_production_path_blocks_unapproved_sqlmap_and_emits_report() -> None:
    client = _client()
    headers = _headers()
    mode = client.post(
        "/api/v1/engagements/e-prod/execution-mode",
        headers=headers,
        json={"mode": "production"},
    )
    assert mode.status_code == 200
    assert mode.json()["mode"] == "production"

    policy = resolve_tool_policy_from_options(
        "sqlmap",
        {"execution_mode": "production", "tenant_id": "t-1", "engagement_id": "e-prod"},
        target="https://prod.example/app",
        tenant_id="t-1",
        engagement_id="e-prod",
        as_dict=True,
    )
    assert policy.get("requires_approval") is True
    assert policy.get("allowed") is False

    argv = NucleiProfileCompiler.compile(
        "vuln_default",
        "production",
        "https://prod.example/app",
    )
    assert argv
    assert argv[0] == "nuclei"

    finding_key = "c" * 64
    repo = get_findings_repository()

    async def _seed() -> None:
        await repo.upsert_logical_finding(
            LogicalFinding(
                finding_key=finding_key,
                tenant_id="t-1",
                engagement_id="e-prod",
                title="SQL injection candidate",
                category="sqli",
            ),
            scan_id="scan-prod-live",
        )

    asyncio.run(_seed())
    report = generate_json(
        ReportData(
            report_id=str(uuid4()),
            target="https://prod.example/app",
            summary=ReportSummary(high=1),
            findings=[
                Finding(
                    finding_id=finding_key,
                    severity="high",
                    title="SQL injection candidate",
                    description="Production candidate blocked pending approval",
                    evidence_refs=["policy:sqlmap:requires_approval"],
                )
            ],
            technologies=["nginx"],
            scan_id="scan-prod-live",
            tenant_id="t-1",
            created_at="2026-08-16T00:00:00Z",
        )
    )
    payload = json.loads(report.decode("utf-8"))
    assert payload["metadata"]["scan_id"] == "scan-prod-live"
    assert any(item.get("title") == "SQL injection candidate" for item in payload["findings"])


def test_live_lab_path_lease_execute_findings_diff_report() -> None:
    client = _client()
    headers = _headers()
    client.post(
        "/api/v1/engagements/e-lab/execution-mode",
        headers=headers,
        json={"mode": "lab_unrestricted"},
    )
    scope = client.post(
        "/api/v1/engagements/e-lab/lab-scope",
        headers=headers,
        json={
            "cidrs": ["10.90.0.0/16"],
            "dns_suffixes": ["lab.argus"],
            "k8s_namespace": "argus-lab-42",
            "vm_network_ids": ["labnet-42"],
            "capture_full": True,
        },
    )
    assert scope.status_code == 201
    lease = client.post(
        "/api/v1/engagements/e-lab/lab-lease",
        headers=headers,
        json={
            "target": "https://app.lab.argus/login",
            "k8s_namespace": "argus-lab-42",
            "vm_network_id": "labnet-42",
        },
    )
    assert lease.status_code == 201
    lease_id = lease.json()["lease_id"]
    assert lease.json()["policy"]["requires_approval"] is False

    created = client.post(
        "/api/v1/lab/scripts",
        headers=headers,
        json={"language": "python", "source": "print('lab-live-ok')", "lease_id": lease_id},
    )
    assert created.status_code == 201
    executed = client.post(f"/api/v1/lab/scripts/{created.json()['script_id']}/execute")
    assert executed.status_code == 200
    assert executed.json()["requires_approval"] is False
    assert executed.json()["status"] == "completed"
    assert "lab-live-ok" in executed.json()["stdout"]
    assert executed.json()["runner"] != "argus-sandbox"

    nuclei_argv = NucleiProfileCompiler.compile(
        "lab_unrestricted",
        "lab_unrestricted",
        "https://app.lab.argus/login",
        allow_code=True,
        allow_headless=True,
        allow_javascript=True,
    )
    assert "-ni" not in nuclei_argv
    assert "-rate-limit" not in nuclei_argv

    finding_key = "d" * 64
    occurrence_key = "e" * 64
    seen = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
    repo = get_findings_repository()

    async def _seed() -> None:
        await repo.upsert_logical_finding(
            LogicalFinding(
                finding_key=finding_key,
                tenant_id="t-1",
                engagement_id="e-lab",
                title="LAB XSS",
                category="xss",
            ),
            scan_id="scan-lab-base",
        )
        await repo.save_occurrence(
            FindingOccurrence(
                occurrence_key=occurrence_key,
                finding_key=finding_key,
                tenant_id="t-1",
                scan_id="scan-lab-live",
                scanner="nuclei",
                detector_id="xss-reflected",
                detector_version="1.0.0",
                evidence_refs=("ev-lab-1",),
                first_seen_at=seen,
                last_seen_at=seen,
            )
        )
        await repo.upsert_logical_finding(
            LogicalFinding(
                finding_key=finding_key,
                tenant_id="t-1",
                engagement_id="e-lab",
                title="LAB XSS",
                category="xss",
            ),
            scan_id="scan-lab-live",
        )

    asyncio.run(_seed())

    occ = client.get("/api/v1/scans/scan-lab-live/occurrences", headers=headers)
    assert occ.status_code == 200
    assert occ.json()["occurrences"][0]["detector_id"] == "xss-reflected"

    retest = client.post(
        f"/api/v1/findings/{finding_key}/retest?scan_id=scan-lab-live&outcome=still_present",
        headers=headers,
    )
    assert retest.status_code == 200

    diff = client.get("/api/v1/scans/scan-lab-live/diff/scan-lab-base", headers=headers)
    assert diff.status_code == 200
    assert "entries" in diff.json()

    attach_phase_coverage(
        phase="vuln_analysis",
        tenant_id="t-1",
        scan_id="scan-lab-live",
        asset_id="asset-lab-live",
        signals=[
            ToolRunSignal(
                tool_id="nuclei",
                capability_id="web.application.xss",
                tool_executed=True,
                execution_evidence_id="ev-lab-1",
                finding_id=finding_key,
            )
        ],
        scan_options={"execution_mode": "lab_unrestricted"},
    )
    coverage = client.get("/api/v1/scans/scan-lab-live/coverage")
    assert coverage.status_code == 200
    assert coverage.json()["results"]

    report = generate_json(
        ReportData(
            report_id=str(uuid4()),
            target="https://app.lab.argus/login",
            summary=ReportSummary(high=1),
            findings=[
                Finding(
                    finding_id=finding_key,
                    severity="high",
                    title="LAB XSS",
                    description="Live LAB occurrence with capture_full evidence",
                    evidence_refs=["ev-lab-1"],
                    tool_name="nuclei",
                    tool_command=" ".join(nuclei_argv[:6]),
                )
            ],
            technologies=["lab-runner"],
            scan_id="scan-lab-live",
            tenant_id="t-1",
            created_at="2026-08-16T12:00:00Z",
            raw_artifacts=[{"execution_id": executed.json()["execution_id"], "stdout": "lab-live-ok"}],
        )
    )
    payload = json.loads(report.decode("utf-8"))
    assert payload["metadata"]["scan_id"] == "scan-lab-live"
    assert any(item.get("title") == "LAB XSS" for item in payload["findings"])
