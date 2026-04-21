"""FIX-009: Evidence/Screenshot schemas exist, ToolRun recording function exists."""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest


BACKEND_SRC = Path(__file__).resolve().parent.parent / "src"


class TestEvidenceResponseSchema:
    """EvidenceResponse schema must exist and have expected fields."""

    def test_schema_importable(self) -> None:
        from src.api.schemas import EvidenceResponse

        assert EvidenceResponse is not None

    def test_has_required_fields(self) -> None:
        from src.api.schemas import EvidenceResponse

        fields = set(EvidenceResponse.model_fields.keys())
        assert "id" in fields
        assert "scan_id" in fields
        assert "finding_id" in fields
        assert "object_key" in fields

    def test_serialization(self) -> None:
        from src.api.schemas import EvidenceResponse

        obj = EvidenceResponse(
            id="ev-1",
            scan_id="s-1",
            finding_id="f-1",
            object_key="bucket/key.png",
        )
        data = obj.model_dump()
        assert data["id"] == "ev-1"
        assert data["object_key"] == "bucket/key.png"


class TestScreenshotResponseSchema:
    """ScreenshotResponse schema must exist and have expected fields."""

    def test_schema_importable(self) -> None:
        from src.api.schemas import ScreenshotResponse

        assert ScreenshotResponse is not None

    def test_has_required_fields(self) -> None:
        from src.api.schemas import ScreenshotResponse

        fields = set(ScreenshotResponse.model_fields.keys())
        assert "id" in fields
        assert "scan_id" in fields
        assert "object_key" in fields

    def test_serialization(self) -> None:
        from src.api.schemas import ScreenshotResponse

        obj = ScreenshotResponse(
            id="ss-1",
            scan_id="s-1",
            object_key="bucket/screenshot.png",
        )
        data = obj.model_dump()
        assert data["id"] == "ss-1"


class TestToolRunRecordingExists:
    """executor.py must have _persist_tool_run function for ToolRun recording."""

    def test_persist_tool_run_exists(self) -> None:
        path = BACKEND_SRC / "tools" / "executor.py"
        assert path.exists(), "executor.py not found"
        source = path.read_text(encoding="utf-8")
        assert "_persist_tool_run" in source, (
            "_persist_tool_run function must exist in executor.py"
        )

    def test_persist_tool_run_is_async(self) -> None:
        path = BACKEND_SRC / "tools" / "executor.py"
        source = path.read_text(encoding="utf-8")
        assert "async def _persist_tool_run" in source

    def test_tool_run_model_imported(self) -> None:
        path = BACKEND_SRC / "tools" / "executor.py"
        source = path.read_text(encoding="utf-8")
        assert "ToolRun" in source

    def test_schedule_tool_run_record_exists(self) -> None:
        path = BACKEND_SRC / "tools" / "executor.py"
        source = path.read_text(encoding="utf-8")
        assert "_schedule_tool_run_record" in source


class TestFindingsRouterEvidenceEndpoints:
    """findings.py must have evidence and screenshot endpoints."""

    def test_evidence_endpoint_exists(self) -> None:
        from src.api.routers import findings

        source = inspect.getsource(findings)
        assert "list_finding_evidence" in source
        assert "/evidence" in source

    def test_screenshot_endpoint_exists(self) -> None:
        from src.api.routers import findings

        source = inspect.getsource(findings)
        assert "list_finding_screenshots" in source
        assert "/screenshots" in source
