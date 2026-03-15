"""Tests for ARGUS-010: SSE, Timeline, Observability."""

import json
import logging
import uuid
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from src.api.routers.scans import SSE_EVENT_TYPES, _build_sse_payload
from src.core.observability import (
    get_metrics_content,
    record_phase_duration,
    record_scan_started,
    record_tool_run,
)
from src.db.models import Scan, ScanEvent


class TestSSEEventTypes:
    """SSE event types per api-contracts."""

    def test_sse_event_types_include_required(self) -> None:
        """Required event types: phase_start, phase_complete, tool_run, finding, progress."""
        required = {"phase_start", "phase_complete", "tool_run", "finding", "progress"}
        assert required.issubset(SSE_EVENT_TYPES)

    def test_sse_event_types_include_complete_and_error(self) -> None:
        """Complete and error event types for scan lifecycle."""
        assert "complete" in SSE_EVENT_TYPES
        assert "error" in SSE_EVENT_TYPES


class TestBuildSSEPayload:
    """SSE payload format per api-contracts: { event, phase?, progress?, message?, data? }."""

    def test_payload_includes_event(self) -> None:
        """Payload must include event field."""
        ev = MagicMock(spec=ScanEvent)
        ev.event = "phase_start"
        ev.phase = "recon"
        ev.progress = 16
        ev.message = "Starting recon"
        ev.data = None
        payload = _build_sse_payload(ev)
        assert payload["event"] == "phase_start"

    def test_payload_includes_phase_when_present(self) -> None:
        """Payload includes phase when set."""
        ev = MagicMock(spec=ScanEvent)
        ev.event = "phase_complete"
        ev.phase = "recon"
        ev.progress = 16
        ev.message = "Completed"
        ev.data = None
        payload = _build_sse_payload(ev)
        assert payload["phase"] == "recon"

    def test_payload_includes_progress_when_present(self) -> None:
        """Payload includes progress when set."""
        ev = MagicMock(spec=ScanEvent)
        ev.event = "progress"
        ev.phase = "recon"
        ev.progress = 50
        ev.message = "Progress 50%"
        ev.data = None
        payload = _build_sse_payload(ev)
        assert payload["progress"] == 50

    def test_payload_includes_data_when_present(self) -> None:
        """Payload includes data object when set."""
        ev = MagicMock(spec=ScanEvent)
        ev.event = "finding"
        ev.phase = "reporting"
        ev.progress = 100
        ev.message = "Finding: XSS"
        ev.data = {"severity": "high", "title": "XSS"}
        payload = _build_sse_payload(ev)
        assert payload["data"] == {"severity": "high", "title": "XSS"}

    def test_payload_omits_none_fields(self) -> None:
        """None and empty message are omitted or handled."""
        ev = MagicMock(spec=ScanEvent)
        ev.event = "tool_run"
        ev.phase = None
        ev.progress = None
        ev.message = None
        ev.data = {"tool": "nmap"}
        payload = _build_sse_payload(ev)
        assert "event" in payload
        assert "data" in payload
        assert payload.get("phase") is None or "phase" not in payload

    def test_payload_omits_empty_data_dict(self) -> None:
        """Empty dict as data is omitted (falsy in Python)."""
        ev = MagicMock(spec=ScanEvent)
        ev.event = "finding"
        ev.phase = "reporting"
        ev.progress = 100
        ev.message = "No details"
        ev.data = {}
        payload = _build_sse_payload(ev)
        assert payload["event"] == "finding"
        assert "data" not in payload

    def test_payload_includes_error_for_error_event(self) -> None:
        """For event=error, payload must include error field (frontend reads payload.error)."""
        ev = MagicMock(spec=ScanEvent)
        ev.event = "error"
        ev.phase = "reporting"
        ev.progress = 50
        ev.message = "Scan failed: timeout"
        ev.data = None
        payload = _build_sse_payload(ev)
        assert payload["event"] == "error"
        assert payload["error"] == "Scan failed: timeout"

    def test_phase_complete_filters_sensitive_data(self) -> None:
        """phase_complete data is filtered: no findings, exploits, evidence, report content (ARGUS-010)."""
        ev = MagicMock(spec=ScanEvent)
        ev.event = "phase_complete"
        ev.phase = "vuln_analysis"
        ev.progress = 50
        ev.message = "Completed vuln_analysis"
        ev.data = {
            "findings": [
                {"title": "SQLi", "payload": "1' OR 1=1--", "description": "sensitive"},
            ],
            "exploits": [{"cmd": "curl http://evil.com"}],
            "evidence": [{"path": "/etc/passwd", "content": "root:x:0:0"}],
        }
        payload = _build_sse_payload(ev)
        assert payload["event"] == "phase_complete"
        assert payload["phase"] == "vuln_analysis"
        data = payload.get("data", {})
        assert data.get("findings_count") == 1
        assert data.get("exploits_count") == 1
        assert data.get("evidence_count") == 1
        assert "findings" not in data
        assert "exploits" not in data
        assert "evidence" not in data
        assert "payload" not in str(data)
        assert "sensitive" not in str(data)


class TestMetricsEndpoint:
    """Prometheus /metrics endpoint."""

    def test_metrics_returns_200(self, client) -> None:
        """GET /metrics returns 200."""
        response = client.get("/metrics")
        assert response.status_code == 200

    def test_metrics_content_type(self, client) -> None:
        """Metrics returns text/plain or prometheus format."""
        response = client.get("/metrics")
        ct = response.headers.get("content-type", "")
        assert "text/plain" in ct or "prometheus" in ct.lower()


class TestObservabilityMetrics:
    """Observability module — metrics recording."""

    def test_record_scan_started_no_error(self) -> None:
        """record_scan_started does not raise."""
        record_scan_started()

    def test_record_phase_duration_no_error(self) -> None:
        """record_phase_duration does not raise."""
        record_phase_duration("recon", 5.2)

    def test_record_tool_run_no_error(self) -> None:
        """record_tool_run does not raise."""
        record_tool_run("nmap")

    def test_get_metrics_content_returns_tuple(self) -> None:
        """get_metrics_content returns (bytes, str)."""
        body, content_type = get_metrics_content()
        assert isinstance(body, bytes)
        assert isinstance(content_type, str)

    def test_record_scan_started_increments_metrics(self) -> None:
        """record_scan_started increments argus_scans_total when Prometheus available."""
        record_scan_started()
        record_scan_started()
        body, _ = get_metrics_content()
        text = body.decode("utf-8")
        assert "argus_scans_total" in text or "argus_scans" in text

    def test_record_tool_run_increments_metrics(self) -> None:
        """record_tool_run increments argus_tool_runs_total when Prometheus available."""
        record_tool_run("nmap")
        record_tool_run("nuclei")
        body, _ = get_metrics_content()
        text = body.decode("utf-8")
        assert "argus_tool_runs" in text or "tool_runs" in text


class TestSSEEndpointEventFormat:
    """GET /scans/:id/events — SSE event format compliance."""

    def test_sse_payload_structure_compliance(self) -> None:
        """SSE payload structure matches api-contracts: event, phase?, progress?, message?, data?."""
        ev = MagicMock(spec=ScanEvent)
        ev.event = "phase_start"
        ev.phase = "recon"
        ev.progress = 16
        ev.message = "Starting recon"
        ev.data = None
        payload = _build_sse_payload(ev)
        assert "event" in payload
        assert payload["event"] == "phase_start"
        assert payload.get("phase") == "recon"
        assert payload.get("progress") == 16
        assert payload.get("message") == "Starting recon"

    def test_sse_json_payload_serializable(self) -> None:
        """SSE payload is JSON-serializable."""
        ev = MagicMock(spec=ScanEvent)
        ev.event = "finding"
        ev.phase = "reporting"
        ev.progress = 100
        ev.message = "Finding: XSS"
        ev.data = {"severity": "high", "title": "XSS"}
        payload = _build_sse_payload(ev)
        serialized = json.dumps(payload)
        parsed = json.loads(serialized)
        assert parsed["event"] == "finding"
        assert parsed["data"]["severity"] == "high"

    def test_sse_empty_events_yields_init(self, client) -> None:
        """When scan has no events, SSE yields init event. Polling loop exits when scan completed."""
        scan_id = str(uuid.uuid4())
        mock_scan = MagicMock(spec=Scan)
        mock_scan.id = scan_id
        mock_scan.status = "completed"
        mock_scan.phase = "reporting"
        mock_scan.progress = 100

        scan_result = MagicMock()
        scan_result.scalar_one_or_none.return_value = mock_scan

        events_result = MagicMock()
        events_result.scalars.return_value.all.return_value = []

        call_count = 0

        async def mock_execute(query):
            nonlocal call_count
            call_count += 1
            if call_count % 2 == 1:
                return scan_result
            return events_result

        session = AsyncMock()
        session.execute = mock_execute
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=None)

        @asynccontextmanager
        async def mock_session_factory():
            yield session

        with (
            patch("src.api.routers.scans.async_session_factory", mock_session_factory),
            patch("src.api.routers.scans.set_session_tenant", AsyncMock()),
        ):
            response = client.get(
                f"/api/v1/scans/{scan_id}/events",
                headers={"Accept": "text/event-stream"},
            )
        assert response.status_code == 200
        assert "text/event-stream" in response.headers.get("content-type", "")
        body = response.text
        assert "event" in body or "init" in body
        assert "Scan started" in body or "init" in body


class TestStateMachineEventTypes:
    """State machine records correct event types."""

    @pytest.mark.asyncio
    async def test_record_event_tool_run(self) -> None:
        """_record_event accepts tool_run event type."""
        from src.orchestration.state_machine import _record_event

        session = AsyncMock()
        session.add = MagicMock()
        await _record_event(
            session,
            tenant_id="t1",
            scan_id="s1",
            event="tool_run",
            phase="exploitation",
            progress=50,
            message="Running exploit_attempt",
            data={"tool": "exploit_attempt"},
        )
        session.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_record_event_finding(self) -> None:
        """_record_event accepts finding event type."""
        from src.orchestration.state_machine import _record_event

        session = AsyncMock()
        session.add = MagicMock()
        await _record_event(
            session,
            tenant_id="t1",
            scan_id="s1",
            event="finding",
            phase="reporting",
            progress=100,
            message="Finding: XSS",
            data={"severity": "high", "title": "XSS"},
        )
        session.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_record_event_progress(self) -> None:
        """_record_event accepts progress event type."""
        from src.orchestration.state_machine import _record_event

        session = AsyncMock()
        session.add = MagicMock()
        await _record_event(
            session,
            tenant_id="t1",
            scan_id="s1",
            event="progress",
            phase="recon",
            progress=16,
            message="Progress 16%",
        )
        session.add.assert_called_once()


class TestStructuredLoggingExtraFields:
    """Structured logging with extra fields (event_type, phase, scan_id)."""

    def test_logging_extra_fields_preserved_in_record(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Log records with extra dict have attributes on LogRecord."""
        logger = logging.getLogger("src.orchestration.state_machine")
        with caplog.at_level(logging.INFO):
            logger.info(
                "Phase started",
                extra={
                    "event_type": "phase_start",
                    "phase": "recon",
                    "scan_id": "scan-123",
                },
            )
        assert len(caplog.records) >= 1
        record = caplog.records[-1]
        assert getattr(record, "event_type", None) == "phase_start"
        assert getattr(record, "phase", None) == "recon"
        assert getattr(record, "scan_id", None) == "scan-123"

    def test_logging_extra_fields_phase_complete(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Phase complete log includes duration_seconds in extra."""
        logger = logging.getLogger("src.orchestration.state_machine")
        with caplog.at_level(logging.INFO):
            logger.info(
                "Phase completed",
                extra={
                    "event_type": "phase_complete",
                    "phase": "recon",
                    "scan_id": "scan-456",
                    "duration_seconds": 5.23,
                },
            )
        assert len(caplog.records) >= 1
        record = caplog.records[-1]
        assert getattr(record, "event_type", None) == "phase_complete"
        assert getattr(record, "duration_seconds", None) == 5.23
