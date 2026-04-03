"""Block 9 — timeline, false-positive, remediation, findings statistics (TestClient + DB mocks, no network)."""

import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.testclient import TestClient

from src.core.config import settings


def _async_session_factory(session: AsyncMock):
    @asynccontextmanager
    async def _cm():
        yield session

    def factory():
        return _cm()

    return factory


class TestScanTimelineEndpoint:
    def test_timeline_returns_events_and_gaps(self, client: TestClient) -> None:
        scan_id = str(uuid.uuid4())
        r_scan = MagicMock()
        r_scan.scalar_one_or_none.return_value = MagicMock()

        t0 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=UTC)
        t1 = datetime(2026, 1, 1, 10, 0, 10, tzinfo=UTC)
        ev0 = MagicMock()
        ev0.id = "ev-0"
        ev0.event = "start"
        ev0.phase = "recon"
        ev0.progress = 0
        ev0.message = "m0"
        ev0.created_at = t0
        ev0.duration_sec = 2.5
        ev1 = MagicMock()
        ev1.id = "ev-1"
        ev1.event = "progress"
        ev1.phase = "recon"
        ev1.progress = 50
        ev1.message = "m1"
        ev1.created_at = t1
        ev1.duration_sec = None

        r_ev = MagicMock()
        scalars = MagicMock()
        scalars.all.return_value = [ev0, ev1]
        r_ev.scalars.return_value = scalars

        r_set = MagicMock()
        session = AsyncMock()
        # First execute: SET LOCAL app.current_tenant_id (set_session_tenant)
        session.execute = AsyncMock(side_effect=[r_set, r_scan, r_ev])
        factory = _async_session_factory(session)

        with patch("src.api.routers.scans.async_session_factory", factory):
            r = client.get(f"/api/v1/scans/{scan_id}/timeline")
        assert r.status_code == 200
        body = r.json()
        assert body["scan_id"] == scan_id
        assert len(body["events"]) == 2
        assert body["events"][0]["gap_from_previous_sec"] is None
        assert body["events"][1]["gap_from_previous_sec"] == pytest.approx(10.0)
        assert body["total_duration_sec"] == pytest.approx(10.0)

    def test_timeline_scan_missing_404(self, client: TestClient) -> None:
        scan_id = str(uuid.uuid4())
        r_scan = MagicMock()
        r_scan.scalar_one_or_none.return_value = None
        r_set = MagicMock()
        session = AsyncMock()
        session.execute = AsyncMock(side_effect=[r_set, r_scan])
        factory = _async_session_factory(session)
        with patch("src.api.routers.scans.async_session_factory", factory):
            r = client.get(f"/api/v1/scans/{scan_id}/timeline")
        assert r.status_code == 404


class TestFindingFalsePositiveEndpoint:
    def test_false_positive_post_updates_via_mock_session(
        self, client: TestClient
    ) -> None:
        fid = str(uuid.uuid4())
        finding = MagicMock()
        finding.tenant_id = settings.default_tenant_id

        session = AsyncMock()
        session.execute = AsyncMock()
        session.commit = AsyncMock()
        factory = _async_session_factory(session)

        with (
            patch(
                "src.api.routers.findings._load_finding_for_tenant",
                new_callable=AsyncMock,
                return_value=(finding, "https://target.example/"),
            ),
            patch("src.api.routers.findings.async_session_factory", factory),
        ):
            r = client.post(
                f"/api/v1/findings/{fid}/false-positive",
                json={"reason": "Expected WAF behavior in staging"},
            )
        assert r.status_code == 200
        data = r.json()
        assert data["finding_id"] == fid
        assert data["false_positive"] is True
        assert data["dedup_status"] == "false_positive"
        session.commit.assert_awaited()


class TestFindingRemediationEndpoint:
    def test_remediation_loads_skill_sections(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fid = str(uuid.uuid4())
        finding = MagicMock()
        finding.tenant_id = settings.default_tenant_id
        finding.owasp_category = "A03"
        finding.cwe = "CWE-79"
        finding.title = "Reflected XSS"
        finding.severity = "high"
        finding.description = "PoC in query string"

        kb = MagicMock()
        kb.get_scan_strategy.return_value = {"skills": ["xss-skill"]}

        def _fake_load(skill_id: str) -> str:
            if skill_id == "xss-skill":
                return "## Remediation\n- Encode output\n- Use CSP"
            return ""

        monkeypatch.setattr(
            "src.api.routers.findings.is_llm_available", lambda: False
        )
        with (
            patch(
                "src.api.routers.findings._load_finding_for_tenant",
                new_callable=AsyncMock,
                return_value=(finding, "https://app.example/"),
            ),
            patch(
                "src.api.routers.findings.get_knowledge_base",
                return_value=kb,
            ),
            patch("src.api.routers.findings.load_skill", side_effect=_fake_load),
        ):
            r = client.get(f"/api/v1/findings/{fid}/remediation")
        assert r.status_code == 200
        payload = r.json()
        assert payload["finding_id"] == fid
        assert "xss-skill" in payload["skills_considered"]
        assert len(payload["sections"]) >= 1
        assert payload["sections"][0]["skill_id"] == "xss-skill"
        assert "CSP" in payload["sections"][0]["body"] or "Encode" in payload["sections"][0]["body"]


class TestScanFindingsStatisticsEndpoint:
    def test_statistics_aggregates_mock_rows(self, client: TestClient) -> None:
        scan_id = str(uuid.uuid4())

        r_scan = MagicMock()
        r_scan.scalar_one_or_none.return_value = MagicMock()

        r_sev = MagicMock()
        r_sev.all.return_value = [("high", 2), ("medium", 1)]

        r_owasp = MagicMock()
        r_owasp.all.return_value = [("A01", 1)]

        r_conf = MagicMock()
        r_conf.all.return_value = [("likely", 3)]

        r_cwe = MagicMock()
        r_cwe.all.return_value = [("CWE-79",), ("CWE-89",)]

        r_val = MagicMock()
        r_val.scalar_one.return_value = 1

        r_fp = MagicMock()
        r_fp.scalar_one.return_value = 2

        r_risk = MagicMock()
        r_risk.all.return_value = [("critical", 1), ("high", 1)]

        r_set = MagicMock()
        session = AsyncMock()
        session.execute = AsyncMock(
            side_effect=[
                r_set,
                r_scan,
                r_sev,
                r_owasp,
                r_conf,
                r_cwe,
                r_val,
                r_fp,
                r_risk,
            ]
        )
        factory = _async_session_factory(session)

        with patch("src.api.routers.scans.async_session_factory", factory):
            r = client.get(f"/api/v1/scans/{scan_id}/findings/statistics")
        assert r.status_code == 200
        out = r.json()
        assert out["scan_id"] == scan_id
        assert out["by_severity"]["high"] == 2
        assert out["by_owasp"]["A01"] == 1
        assert set(out["unique_cwes"]) == {"CWE-79", "CWE-89"}
        assert out["validated"] == 1
        assert out["false_positives"] == 2
        assert isinstance(out["risk_score"], (int, float))
        assert out["risk_score"] > 0

    def test_statistics_scan_not_found(self, client: TestClient) -> None:
        scan_id = str(uuid.uuid4())
        r_scan = MagicMock()
        r_scan.scalar_one_or_none.return_value = None
        r_set = MagicMock()
        session = AsyncMock()
        session.execute = AsyncMock(side_effect=[r_set, r_scan])
        factory = _async_session_factory(session)
        with patch("src.api.routers.scans.async_session_factory", factory):
            r = client.get(f"/api/v1/scans/{scan_id}/findings/statistics")
        assert r.status_code == 404
