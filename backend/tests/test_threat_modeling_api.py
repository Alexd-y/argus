"""API contract tests for TM-008 (Threat Modeling API/CLI).

TestClient: POST trigger 400 when Stage 1 not ready, 201/200 when recon exists.
GET input-bundle, ai-traces, mcp-traces structure. GET artifacts download 404 for unknown type.
Uses mocks for dependency_check, pipeline, artifact_service.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from src.recon.threat_modeling.dependency_check import BLOCKED_MISSING_RECON
from src.recon.threat_modeling.pipeline import ThreatModelPipelineError
from starlette.testclient import TestClient

API_BASE = "/api/v1/recon/engagements"


def _mock_engagement(engagement_id: str, scope_config: dict | None = None) -> MagicMock:
    eng = MagicMock()
    eng.id = engagement_id
    eng.scope_config = scope_config
    return eng


def _mock_threat_model_run(
    run_id: str = "run-123",
    job_id: str = "job-456",
    engagement_id: str = "eng-1",
    target_id: str | None = None,
) -> MagicMock:
    run = MagicMock()
    run.id = "db-id-1"
    run.run_id = run_id
    run.job_id = job_id
    run.engagement_id = engagement_id
    run.target_id = target_id
    run.status = "completed"
    run.created_at = datetime.now(UTC)
    run.completed_at = datetime.now(UTC)
    run.artifact_refs = ["threat_model.md", "ai_reasoning_traces.json"]
    return run


def _mock_pipeline_result(
    run_id: str = "run-123",
    job_id: str = "job-456",
    status: str = "completed",
) -> MagicMock:
    result = MagicMock()
    result.run_id = run_id
    result.job_id = job_id
    result.status = status
    result.artifact_refs = ["threat_model.md", "ai_reasoning_traces.json"]
    result.completed_at = datetime.now(UTC)
    return result


@pytest.fixture
def mock_db_session():
    """Mock AsyncSession for get_db dependency."""
    session = AsyncMock()
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.flush = AsyncMock()
    session.rollback = AsyncMock()
    session.close = MagicMock()
    session.execute = AsyncMock(return_value=MagicMock())
    return session


@pytest.fixture
def client_with_db(app, mock_db_session):
    """TestClient with mocked get_db."""
    from src.db.session import get_db

    async def _mock_get_db():
        try:
            yield mock_db_session
        finally:
            pass

    app.dependency_overrides[get_db] = _mock_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.pop(get_db, None)


class TestTriggerEndpoint:
    """POST /recon/engagements/{id}/threat-modeling/trigger."""

    def test_trigger_returns_400_when_stage1_not_ready(
        self, client_with_db: TestClient
    ) -> None:
        """POST trigger returns 400 with blocked_missing_recon when Stage 1 not ready."""
        engagement_id = "eng-001"
        url = f"{API_BASE}/{engagement_id}/threat-modeling/trigger"

        mock_eng = _mock_engagement(engagement_id, scope_config=None)
        mock_run = _mock_threat_model_run(engagement_id=engagement_id)

        with (
            patch(
                "src.api.routers.recon.threat_modeling.get_engagement",
                new_callable=AsyncMock,
                return_value=mock_eng,
            ),
            patch(
                "src.api.routers.recon.threat_modeling.create_threat_model_run",
                new_callable=AsyncMock,
                return_value=mock_run,
            ),
            patch(
                "src.api.routers.recon.threat_modeling.execute_threat_modeling_run",
                new_callable=AsyncMock,
                side_effect=ThreatModelPipelineError(
                    "Stage 1 not ready", blocking_reason=BLOCKED_MISSING_RECON
                ),
            ),
        ):
            response = client_with_db.post(url, json={})

        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert BLOCKED_MISSING_RECON in data["detail"]

    def test_trigger_returns_201_when_recon_dir_exists(
        self, client_with_db: TestClient, tmp_path: Path
    ) -> None:
        """POST trigger returns 201 when recon dir exists (mocked pipeline success)."""
        engagement_id = "eng-002"
        url = f"{API_BASE}/{engagement_id}/threat-modeling/trigger"

        mock_eng = _mock_engagement(
            engagement_id,
            scope_config={"recon_dir": str(tmp_path)},
        )
        mock_run = _mock_threat_model_run(engagement_id=engagement_id)
        mock_result = _mock_pipeline_result()

        with (
            patch(
                "src.api.routers.recon.threat_modeling.get_engagement",
                new_callable=AsyncMock,
                return_value=mock_eng,
            ),
            patch(
                "src.api.routers.recon.threat_modeling.create_threat_model_run",
                new_callable=AsyncMock,
                return_value=mock_run,
            ),
            patch(
                "src.api.routers.recon.threat_modeling.execute_threat_modeling_run",
                new_callable=AsyncMock,
                return_value=mock_result,
            ),
        ):
            response = client_with_db.post(url, json={})

        assert response.status_code in (200, 201)
        data = response.json()
        assert "run_id" in data or "status" in data
        assert data.get("status") == "completed"

    def test_trigger_returns_404_when_engagement_not_found(
        self, client_with_db: TestClient
    ) -> None:
        """POST trigger returns 404 when engagement does not exist."""
        engagement_id = "eng-nonexistent"
        url = f"{API_BASE}/{engagement_id}/threat-modeling/trigger"

        with patch(
            "src.api.routers.recon.threat_modeling.get_engagement",
            new_callable=AsyncMock,
            return_value=None,
        ):
            response = client_with_db.post(url, json={})

        assert response.status_code == 404
        assert "detail" in response.json()


class TestInputBundleEndpoint:
    """GET /recon/engagements/{id}/threat-modeling/runs/{run_id}/input-bundle."""

    def test_get_input_bundle_returns_appropriate_structure(
        self, client_with_db: TestClient
    ) -> None:
        """GET input-bundle returns ThreatModelInputBundle structure."""
        engagement_id = "eng-003"
        run_id = "run-789"
        url = f"{API_BASE}/{engagement_id}/threat-modeling/runs/{run_id}/input-bundle"

        mock_run = _mock_threat_model_run(run_id=run_id, engagement_id=engagement_id)
        mock_eng = _mock_engagement(engagement_id, scope_config=None)

        bundle_dict = {
            "engagement_id": engagement_id,
            "target_id": None,
            "critical_assets": [],
            "trust_boundaries": [],
            "entry_points": [],
            "priority_hypotheses": [],
            "anomalies": [],
            "intel_findings": [],
            "api_surface": [],
            "live_hosts": [],
            "tech_profile": [],
        }

        with (
            patch(
                "src.api.routers.recon.threat_modeling.get_threat_model_run",
                new_callable=AsyncMock,
                return_value=mock_run,
            ),
            patch(
                "src.api.routers.recon.threat_modeling.get_engagement",
                new_callable=AsyncMock,
                return_value=mock_eng,
            ),
            patch(
                "src.api.routers.recon.threat_modeling.load_threat_model_input_bundle_from_artifacts",
                new_callable=AsyncMock,
                return_value=MagicMock(model_dump=MagicMock(return_value=bundle_dict)),
            ),
        ):
            response = client_with_db.get(url)

        assert response.status_code == 200
        data = response.json()
        assert data["engagement_id"] == engagement_id
        assert "critical_assets" in data
        assert "trust_boundaries" in data
        assert "entry_points" in data


class TestTraceEndpoints:
    """GET ai-traces, mcp-traces."""

    def test_get_ai_traces_returns_json_structure(
        self, client_with_db: TestClient
    ) -> None:
        """GET ai-traces returns AI reasoning traces structure."""
        engagement_id = "eng-004"
        run_id = "run-ai"
        url = f"{API_BASE}/{engagement_id}/threat-modeling/runs/{run_id}/ai-traces"

        mock_run = _mock_threat_model_run(run_id=run_id, engagement_id=engagement_id)
        mock_artifact = MagicMock()
        mock_artifact.object_key = "eng-004/job-456/ai_reasoning_traces.json"
        mock_artifact.filename = "ai_reasoning_traces.json"
        mock_artifact.content_type = "application/json"

        with (
            patch(
                "src.api.routers.recon.threat_modeling.get_threat_model_run",
                new_callable=AsyncMock,
                return_value=mock_run,
            ),
            patch(
                "src.api.routers.recon.threat_modeling.get_artifact_by_engagement_job_filename",
                new_callable=AsyncMock,
                return_value=mock_artifact,
            ),
            patch(
                "src.recon.storage.download_artifact",
                return_value=b'{"traces": [{"step_id": "step1", "description": "Test"}]}',
            ),
        ):
            response = client_with_db.get(url)

        assert response.status_code == 200
        data = response.json()
        assert "traces" in data
        assert len(data["traces"]) == 1
        assert data["traces"][0]["step_id"] == "step1"

    def test_get_mcp_traces_returns_json_structure(
        self, client_with_db: TestClient
    ) -> None:
        """GET mcp-traces returns MCP trace structure."""
        engagement_id = "eng-005"
        run_id = "run-mcp"
        url = f"{API_BASE}/{engagement_id}/threat-modeling/runs/{run_id}/mcp-traces"

        mock_run = _mock_threat_model_run(run_id=run_id, engagement_id=engagement_id)
        mock_artifact = MagicMock()
        mock_artifact.object_key = "eng-005/job-456/mcp_trace.json"
        mock_artifact.filename = "mcp_trace.json"

        with (
            patch(
                "src.api.routers.recon.threat_modeling.get_threat_model_run",
                new_callable=AsyncMock,
                return_value=mock_run,
            ),
            patch(
                "src.api.routers.recon.threat_modeling.get_artifact_by_engagement_job_filename",
                new_callable=AsyncMock,
                return_value=mock_artifact,
            ),
            patch(
                "src.recon.storage.download_artifact",
                return_value=b'{"invocations": [{"tool_name": "fetch", "invocation_id": "inv1"}]}',
            ),
        ):
            response = client_with_db.get(url)

        assert response.status_code == 200
        data = response.json()
        assert "invocations" in data
        assert len(data["invocations"]) == 1
        assert data["invocations"][0]["tool_name"] == "fetch"


class TestArtifactDownloadEndpoint:
    """GET artifacts/{type}/download."""

    def test_download_returns_404_for_unknown_type(
        self, client_with_db: TestClient
    ) -> None:
        """GET artifacts/{type}/download returns 404 for unknown artifact type."""
        engagement_id = "eng-006"
        run_id = "run-art"
        url = f"{API_BASE}/{engagement_id}/threat-modeling/runs/{run_id}/artifacts/unknown_type/download"

        mock_run = _mock_threat_model_run(run_id=run_id, engagement_id=engagement_id)

        with (
            patch(
                "src.api.routers.recon.threat_modeling.get_threat_model_run",
                new_callable=AsyncMock,
                return_value=mock_run,
            ),
            patch(
                "src.api.routers.recon.threat_modeling.get_artifact_by_engagement_job_filename",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            response = client_with_db.get(url)

        assert response.status_code == 404
        data = response.json()
        assert "detail" in data
        assert "not found" in data["detail"].lower() or "unknown" in data["detail"].lower()
