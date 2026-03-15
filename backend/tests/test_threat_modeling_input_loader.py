"""Tests for threat model input loader."""

from pathlib import Path

import pytest
from app.schemas.threat_modeling.schemas import ThreatModelInputBundle
from src.recon.threat_modeling.input_loader import (
    load_threat_model_input_bundle,
    load_threat_model_input_bundle_from_artifacts,
)


class TestLoadThreatModelInputBundle:
    """load_threat_model_input_bundle file-based."""

    def test_empty_recon_dir_returns_minimal_bundle(self, tmp_path: Path) -> None:
        """Empty recon dir returns bundle with empty lists."""
        bundle = load_threat_model_input_bundle(tmp_path, "e1", None)
        assert isinstance(bundle, ThreatModelInputBundle)
        assert bundle.engagement_id == "e1"
        assert bundle.target_id is None
        assert bundle.critical_assets == []
        assert bundle.trust_boundaries == []
        assert bundle.entry_points == []
        assert bundle.priority_hypotheses == []
        assert bundle.anomalies == []
        assert bundle.intel_findings == []
        assert bundle.api_surface == []
        assert bundle.live_hosts == []
        assert bundle.tech_profile == []

    def test_nonexistent_recon_dir_returns_minimal_bundle(self) -> None:
        """Nonexistent recon dir returns minimal bundle."""
        bundle = load_threat_model_input_bundle(
            Path("/nonexistent/recon/dir"),
            "e1",
            "t1",
        )
        assert bundle.engagement_id == "e1"
        assert bundle.target_id == "t1"
        assert bundle.critical_assets == []

    def test_stage2_structured_maps_to_assets_boundaries_entry_points(
        self, tmp_path: Path
    ) -> None:
        """stage2_structured.json maps to CriticalAsset, TrustBoundary, EntryPoint."""
        stage2 = {
            "priority_hypotheses": [
                {"type": "hypothesis", "source": "x", "text": "H1", "priority": "high"},
            ],
            "critical_assets": [
                {"type": "observation", "source": "tech", "text": "https://api.example.com"},
            ],
            "trust_boundaries": [
                {"type": "inference", "source": "live", "text": "Public web tier"},
            ],
            "entry_points": [
                {"type": "hypothesis", "source": "ep", "text": "https://app.example.com/login"},
            ],
        }
        (tmp_path / "stage2_structured.json").write_text(
            __import__("json").dumps(stage2),
            encoding="utf-8",
        )
        bundle = load_threat_model_input_bundle(tmp_path, "e1", None)
        assert len(bundle.priority_hypotheses) == 1
        assert bundle.priority_hypotheses[0]["text"] == "H1"
        assert len(bundle.critical_assets) == 1
        assert "api.example.com" in bundle.critical_assets[0].name
        assert len(bundle.trust_boundaries) == 1
        assert "Public web tier" in bundle.trust_boundaries[0].name
        assert len(bundle.entry_points) == 1
        assert "app.example.com" in bundle.entry_points[0].name

    def test_anomalies_structured_list(self, tmp_path: Path) -> None:
        """anomalies_structured.json as list is stored."""
        anomalies = [{"id": "a1", "text": "Anomaly 1"}]
        (tmp_path / "anomalies_structured.json").write_text(
            __import__("json").dumps(anomalies),
            encoding="utf-8",
        )
        bundle = load_threat_model_input_bundle(tmp_path, "e1", None)
        assert bundle.anomalies == anomalies

    def test_anomalies_structured_dict(self, tmp_path: Path) -> None:
        """anomalies_structured.json as dict is stored."""
        anomalies = {"items": [{"id": "a1"}], "count": 1}
        (tmp_path / "anomalies_structured.json").write_text(
            __import__("json").dumps(anomalies),
            encoding="utf-8",
        )
        bundle = load_threat_model_input_bundle(tmp_path, "e1", None)
        assert bundle.anomalies == anomalies

    def test_csv_artifacts_loaded(self, tmp_path: Path) -> None:
        """CSV artifacts are parsed into list of dicts."""
        (tmp_path / "api_surface.csv").write_text(
            "url,method,source\n/api/v1,GET,route\n",
            encoding="utf-8",
            newline="",
        )
        (tmp_path / "live_hosts_detailed.csv").write_text(
            "host,url,status,server\napp.example.com,https://app.example.com/,200,nginx\n",
            encoding="utf-8",
            newline="",
        )
        (tmp_path / "tech_profile.csv").write_text(
            "technology,evidence\nnginx,Server header\n",
            encoding="utf-8",
            newline="",
        )
        bundle = load_threat_model_input_bundle(tmp_path, "e1", None)
        assert len(bundle.api_surface) == 1
        assert bundle.api_surface[0]["url"] == "/api/v1"
        assert len(bundle.live_hosts) == 1
        assert bundle.live_hosts[0]["host"] == "app.example.com"
        assert len(bundle.tech_profile) == 1
        assert bundle.tech_profile[0]["technology"] == "nginx"

    def test_missing_files_graceful(self, tmp_path: Path) -> None:
        """Missing files result in empty lists, no exception."""
        (tmp_path / "stage2_structured.json").write_text("{}", encoding="utf-8")
        bundle = load_threat_model_input_bundle(tmp_path, "e1", None)
        assert bundle.engagement_id == "e1"
        assert bundle.intel_findings == []
        assert bundle.dns_summary is None


@pytest.mark.asyncio
async def test_load_threat_model_input_bundle_from_artifacts_empty() -> None:
    """load_threat_model_input_bundle_from_artifacts with no artifacts returns minimal."""
    from unittest.mock import AsyncMock, patch

    mock_db = AsyncMock()
    with patch(
        "src.recon.services.artifact_service.get_artifacts_for_engagement",
        new_callable=AsyncMock,
        return_value=[],
    ):
        bundle = await load_threat_model_input_bundle_from_artifacts(
            mock_db, "e1", "t1"
        )
    assert bundle.engagement_id == "e1"
    assert bundle.target_id == "t1"
    assert bundle.critical_assets == []
