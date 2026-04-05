"""Verify ArgusClient exposes recon, pipeline, admin, and report-download APIs.

Follow-up 3 maps backend routes to ArgusClient methods (names match ``argus_mcp.py``,
not the older alias names from draft docs).
"""

from __future__ import annotations

import sys
from pathlib import Path

_MCP_SERVER_ROOT = Path(__file__).resolve().parent.parent
if str(_MCP_SERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(_MCP_SERVER_ROOT))

from argus_mcp import ArgusClient  # noqa: E402


def test_client_has_recon_methods() -> None:
    """Engagements, targets, jobs, artifacts, normalized findings."""
    methods = [
        "list_engagements",
        "create_engagement",
        "get_engagement",
        "patch_engagement",
        "activate_engagement",
        "complete_engagement",
        "create_engagement_target",
        "list_engagement_targets",
        "get_recon_target",
        "delete_recon_target",
        "create_engagement_job",
        "list_engagement_jobs",
        "get_recon_job",
        "cancel_recon_job",
        "list_engagement_artifacts",
        "get_recon_artifact_metadata",
        "get_recon_artifact_download_url",
        "list_normalized_findings",
        "get_normalized_finding",
    ]
    for name in methods:
        assert hasattr(ArgusClient, name), f"ArgusClient missing method: {name}"


def test_client_has_pipeline_methods() -> None:
    """Threat modeling, vulnerability analysis, exploitation."""
    methods = [
        "create_threat_model_run",
        "execute_threat_model_run",
        "trigger_threat_modeling",
        "get_threat_model_input_bundle",
        "get_threat_model_ai_traces",
        "get_threat_model_mcp_traces",
        "download_threat_model_run_artifact",
        "trigger_vulnerability_analysis",
        "create_vulnerability_analysis_run",
        "execute_vulnerability_analysis_run",
        "get_va_next_phase_gate",
        "get_va_evidence_bundles",
        "get_va_evidence_sufficiency",
        "download_va_finding_confirmation_matrix",
        "get_va_confirmed_findings",
        "download_va_run_artifact",
        "get_vulnerability_analysis_readiness",
        "start_exploitation_run",
        "get_exploitation_status",
        "get_exploitation_results",
        "list_exploitation_approvals",
        "approve_exploitation_approval",
        "reject_exploitation_approval",
        "download_exploitation_artifact",
    ]
    for name in methods:
        assert hasattr(ArgusClient, name), f"ArgusClient missing method: {name}"


def test_client_has_download_report() -> None:
    """Report file download via GET /api/v1/reports/{id}/download."""
    assert hasattr(ArgusClient, "download_report"), "ArgusClient missing method: download_report"


def test_client_has_admin_methods() -> None:
    """Admin routes (X-Admin-Key / ARGUS_ADMIN_KEY)."""
    methods = [
        "admin_list_tenants",
        "admin_create_tenant",
        "admin_get_tenant",
        "admin_list_users",
        "admin_list_subscriptions",
        "admin_list_providers",
        "admin_patch_provider",
        "admin_list_policies",
        "admin_list_audit_logs",
        "admin_list_usage",
        "admin_health_dashboard",
    ]
    for name in methods:
        assert hasattr(ArgusClient, name), f"ArgusClient missing method: {name}"
